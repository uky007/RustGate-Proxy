use crate::handler::{
    extract_body_bytes, extract_response_body_bytes, put_body_back, put_response_body_back,
    BoxBody, Buffered, Dropped, RequestHandler,
};
use bytes::Bytes;
use hyper::header::HeaderMap;
use hyper::{Method, Request, Response, StatusCode, Uri, Version};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use tracing::info;

pub type InterceptId = u64;

/// Sent from handler to TUI.
pub enum InterceptedItem {
    Request {
        id: InterceptId,
        method: Method,
        uri: Uri,
        version: Version,
        headers: HeaderMap,
        body: Bytes,
        reply: mpsc::Sender<Verdict>,
    },
    Response {
        id: InterceptId,
        status: StatusCode,
        version: Version,
        headers: HeaderMap,
        body: Bytes,
        reply: mpsc::Sender<Verdict>,
    },
}

/// Sent from TUI back to handler.
pub enum Verdict {
    Forward {
        headers: Box<HeaderMap>,
        body: Bytes,
        method: Option<Method>,
        uri: Option<Uri>,
        status: Option<StatusCode>,
    },
    Drop,
}

/// RequestHandler that intercepts requests/responses and sends them to the TUI.
pub struct InterceptHandler {
    tx: mpsc::SyncSender<InterceptedItem>,
    active: Arc<AtomicBool>,
    next_id: AtomicU64,
}

impl InterceptHandler {
    pub fn new(tx: mpsc::SyncSender<InterceptedItem>, active: Arc<AtomicBool>) -> Self {
        Self {
            tx,
            active,
            next_id: AtomicU64::new(1),
        }
    }
}

impl RequestHandler for InterceptHandler {
    fn handle_request(&self, req: &mut Request<BoxBody>) {
        let path = req.uri().path();
        let display_uri = if req.uri().query().is_some() {
            format!("{path}?...")
        } else {
            path.to_string()
        };
        info!(">> {} {} {:?}", req.method(), display_uri, req.version());

        // Only intercept if body was pre-buffered and interception is active
        if !self.active.load(Ordering::Relaxed)
            || req.extensions().get::<Buffered>().is_none()
        {
            return;
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let body_bytes = extract_body_bytes(req);
        let (reply_tx, reply_rx) = mpsc::channel();

        let item = InterceptedItem::Request {
            id,
            method: req.method().clone(),
            uri: req.uri().clone(),
            version: req.version(),
            headers: req.headers().clone(),
            body: body_bytes.clone(),
            reply: reply_tx,
        };

        // Backpressure: block until queue has space (bounded channel)
        let send_result = tokio::task::block_in_place(|| self.tx.send(item));
        match send_result {
            Ok(()) => {}
            Err(_) => {
                // Disconnected — TUI exited
                tracing::warn!("TUI disconnected, disabling interception");
                self.active.store(false, Ordering::Relaxed);
                put_body_back(req, body_bytes);
                return;
            }
        }

        // Use block_in_place so the tokio worker thread is released while waiting
        match tokio::task::block_in_place(|| reply_rx.recv()) {
            Ok(Verdict::Forward {
                headers,
                body,
                ..
            }) => {
                // Apply header and body edits only.
                // Method/URI changes are ignored because the upstream connection
                // is already resolved from the original request — changing the URI
                // in the TUI would not retarget the connection.
                *req.headers_mut() = *headers;
                let changed = body != body_bytes;
                put_body_back(req, body.clone());
                fix_headers_after_edit(req.headers_mut(), body.len(), changed);
            }
            Ok(Verdict::Drop) => {
                req.extensions_mut().insert(Dropped);
                put_body_back(req, Bytes::new());
                fix_headers_after_edit(req.headers_mut(), 0, true);
            }
            Err(_) => {
                put_body_back(req, body_bytes);
            }
        }
    }

    fn handle_response(&self, res: &mut Response<BoxBody>) {
        info!("<< {}", res.status());

        // Only intercept if body was pre-buffered and interception is active
        if !self.active.load(Ordering::Relaxed)
            || res.extensions().get::<Buffered>().is_none()
        {
            return;
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let body_bytes = extract_response_body_bytes(res);
        let (reply_tx, reply_rx) = mpsc::channel();

        let item = InterceptedItem::Response {
            id,
            status: res.status(),
            version: res.version(),
            headers: res.headers().clone(),
            body: body_bytes.clone(),
            reply: reply_tx,
        };

        let send_result = tokio::task::block_in_place(|| self.tx.send(item));
        match send_result {
            Ok(()) => {}
            Err(_) => {
                tracing::warn!("TUI disconnected, disabling interception");
                self.active.store(false, Ordering::Relaxed);
                put_response_body_back(res, body_bytes);
                return;
            }
        }

        match tokio::task::block_in_place(|| reply_rx.recv()) {
            Ok(Verdict::Forward {
                headers,
                body,
                status,
                ..
            }) => {
                *res.headers_mut() = *headers;
                if let Some(s) = status {
                    *res.status_mut() = s;
                }
                let changed = body != body_bytes;
                put_response_body_back(res, body.clone());
                fix_headers_after_edit(res.headers_mut(), body.len(), changed);
            }
            Ok(Verdict::Drop) => {
                res.extensions_mut().insert(Dropped);
                put_response_body_back(res, Bytes::new());
                fix_headers_after_edit(res.headers_mut(), 0, true);
            }
            Err(_) => {
                put_response_body_back(res, body_bytes);
            }
        }
    }
}

/// Recompute framing headers after body mutation to prevent corrupt HTTP.
/// If `body_changed` is false, preserve all original headers (no-op).
/// Sanitize headers after interception edit.
/// Always strips hop-by-hop headers (edit may have reintroduced them).
/// Recomputes framing headers only if body was actually changed.
fn fix_headers_after_edit(headers: &mut HeaderMap, body_len: usize, body_changed: bool) {
    // Always strip hop-by-hop headers that should not be forwarded
    for name in &[
        hyper::header::CONNECTION,
        hyper::header::PROXY_AUTHORIZATION,
        hyper::header::PROXY_AUTHENTICATE,
        hyper::header::TE,
        hyper::header::TRAILER,
        hyper::header::UPGRADE,
    ] {
        headers.remove(name);
    }
    // Also strip Keep-Alive (not in hyper constants)
    headers.remove("keep-alive");

    if !body_changed {
        return; // Preserve original framing headers
    }
    headers.remove(hyper::header::TRANSFER_ENCODING);
    headers.remove(hyper::header::CONTENT_ENCODING);
    if body_len > 0 {
        headers.insert(
            hyper::header::CONTENT_LENGTH,
            hyper::header::HeaderValue::from(body_len),
        );
    } else {
        headers.remove(hyper::header::CONTENT_LENGTH);
    }
}

/// Check if body is valid UTF-8 (safe for text editing).
pub fn is_text_body(body: &Bytes) -> bool {
    body.is_empty() || std::str::from_utf8(body).is_ok()
}

/// Serialize an HTTP request to raw text for display/editing.
pub fn serialize_request(
    method: &Method,
    uri: &Uri,
    version: Version,
    headers: &HeaderMap,
    body: &Bytes,
) -> String {
    let mut s = format!("{method} {uri} {version:?}\r\n");
    for (name, value) in headers.iter() {
        s.push_str(&format!(
            "{}: {}\r\n",
            name,
            value.to_str().unwrap_or("<binary>")
        ));
    }
    s.push_str("\r\n");
    if !body.is_empty() {
        match std::str::from_utf8(body) {
            Ok(text) => s.push_str(text),
            Err(_) => s.push_str(&format!("<binary {} bytes>", body.len())),
        }
    }
    s
}

/// Serialize an HTTP response to raw text for display/editing.
pub fn serialize_response(
    status: StatusCode,
    version: Version,
    headers: &HeaderMap,
    body: &Bytes,
) -> String {
    let mut s = format!("{version:?} {status}\r\n");
    for (name, value) in headers.iter() {
        s.push_str(&format!(
            "{}: {}\r\n",
            name,
            value.to_str().unwrap_or("<binary>")
        ));
    }
    s.push_str("\r\n");
    if !body.is_empty() {
        match std::str::from_utf8(body) {
            Ok(text) => s.push_str(text),
            Err(_) => s.push_str(&format!("<binary {} bytes>", body.len())),
        }
    }
    s
}

/// Parse raw HTTP request text back into parts.
pub fn parse_request_text(text: &str) -> Option<(Method, Uri, HeaderMap, Bytes)> {
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text, ""));

    let mut lines = head.lines();
    let request_line = lines.next()?;
    let mut parts = request_line.splitn(3, ' ');
    let method: Method = parts.next()?.parse().ok()?;
    let uri: Uri = parts.next()?.parse().ok()?;

    let mut headers = HeaderMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(": ") {
            if let (Ok(n), Ok(v)) = (
                name.parse::<hyper::header::HeaderName>(),
                value.parse::<hyper::header::HeaderValue>(),
            ) {
                headers.append(n, v);
            }
        }
    }

    Some((method, uri, headers, Bytes::from(body.to_string())))
}

/// Parse raw HTTP response text back into parts.
pub fn parse_response_text(text: &str) -> Option<(StatusCode, HeaderMap, Bytes)> {
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text, ""));

    let mut lines = head.lines();
    let status_line = lines.next()?;
    let status_str = status_line.split_once(' ')?.1;
    let status_code: u16 = status_str.split_whitespace().next()?.parse().ok()?;
    let status = StatusCode::from_u16(status_code).ok()?;

    let mut headers = HeaderMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(": ") {
            if let (Ok(n), Ok(v)) = (
                name.parse::<hyper::header::HeaderName>(),
                value.parse::<hyper::header::HeaderValue>(),
            ) {
                headers.append(n, v);
            }
        }
    }

    Some((status, headers, Bytes::from(body.to_string())))
}
