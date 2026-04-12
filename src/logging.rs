use crate::handler::{
    extract_body_bytes, extract_response_body_bytes, put_body_back, put_response_body_back,
    BoxBody, Buffered, Dropped, RequestHandler,
};
use base64::Engine;
use bytes::Bytes;
use hyper::{Request, Response};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use tracing::info;

/// Unique ID for pairing request and response in the log.
#[derive(Clone, Debug)]
pub struct LogId(pub u64);

/// Upstream target info stored in request extensions for logging.
#[derive(Clone, Debug)]
pub struct UpstreamTarget {
    pub scheme: String,
    pub host: String,
    pub port: u16,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LogEntry {
    pub id: u64,
    pub timestamp_req: String,
    pub timestamp_res: String,
    pub request: LoggedRequest,
    pub response: LoggedResponse,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LoggedRequest {
    pub method: String,
    pub uri: String,
    pub version: String,
    #[serde(default)]
    pub target_scheme: String,
    #[serde(default)]
    pub target_host: String,
    #[serde(default)]
    pub target_port: u16,
    pub headers: Vec<(String, String)>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_base64: Option<String>,
    pub body_truncated: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LoggedResponse {
    pub status: u16,
    pub version: String,
    pub headers: Vec<(String, String)>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_base64: Option<String>,
    pub body_truncated: bool,
}

struct PendingLogEntry {
    timestamp_req: String,
    request: LoggedRequest,
}

/// Format SystemTime as ISO 8601 UTC string.
fn format_timestamp() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs();
    let millis = d.subsec_millis();

    // Simple UTC datetime formatting
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;

    // Days since epoch to Y-M-D (simplified leap year calculation)
    let (year, month, day) = days_to_ymd(days);

    format!(
        "{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}.{millis:03}Z"
    )
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let mut year = 1970;
    loop {
        let days_in_year = if is_leap(year) { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }
    let month_days = if is_leap(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 1;
    for &md in &month_days {
        if days < md {
            break;
        }
        days -= md;
        month += 1;
    }
    (year, month, days + 1)
}

fn is_leap(y: u64) -> bool {
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
}

/// Encode body bytes for logging.
/// Returns (body_text, body_base64, body_truncated).
/// `may_have_body` is true if the message had Content-Length or Transfer-Encoding,
/// indicating a body was expected but may not have been captured.
fn encode_body(
    bytes: &Bytes,
    is_buffered: bool,
    may_have_body: bool,
) -> (Option<String>, Option<String>, bool) {
    if !is_buffered || bytes.is_empty() {
        // truncated if body was expected but we couldn't buffer it
        let truncated = !is_buffered && may_have_body;
        return (None, None, truncated);
    }
    match std::str::from_utf8(bytes) {
        Ok(text) => (Some(text.to_string()), None, false),
        Err(_) => {
            let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
            (None, Some(b64), false)
        }
    }
}

/// Safe headers that are logged verbatim. All others are redacted to prevent
/// credential persistence (Authorization, Cookie, vendor API keys, etc.).
const SAFE_LOG_HEADERS: &[&str] = &[
    "accept", "accept-encoding", "accept-language", "cache-control",
    "connection", "content-encoding", "content-language", "content-length",
    "content-type", "date", "etag", "expires", "host", "if-match",
    "if-modified-since", "if-none-match", "if-unmodified-since",
    "last-modified", "location", "pragma", "range", "server",
    "transfer-encoding", "user-agent", "vary", "via",
    "access-control-allow-origin", "access-control-allow-methods",
    "access-control-allow-headers", "access-control-max-age",
    "x-content-type-options", "x-frame-options", "x-request-id",
    "strict-transport-security", "content-security-policy",
];

fn capture_headers(headers: &hyper::HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            let val = if SAFE_LOG_HEADERS.iter().any(|h| name.as_str().eq_ignore_ascii_case(h)) {
                value.to_str().unwrap_or("<binary>").to_string()
            } else {
                "<redacted>".to_string()
            };
            (name.to_string(), val)
        })
        .collect()
}

/// Background writer thread that receives LogEntry values and writes JSON Lines.
struct LogWriter {
    rx: mpsc::Receiver<LogEntry>,
    file: std::io::BufWriter<std::fs::File>,
}

impl LogWriter {
    fn run(mut self) {
        while let Ok(entry) = self.rx.recv() {
            if let Ok(json) = serde_json::to_string(&entry) {
                let _ = writeln!(self.file, "{json}");
                let _ = self.file.flush();
            }
        }
    }
}

/// Decorator handler that logs traffic to a JSON Lines file.
/// Wraps any inner RequestHandler.
pub struct TrafficLogHandler {
    inner: Arc<dyn RequestHandler>,
    tx: mpsc::SyncSender<LogEntry>,
    next_id: AtomicU64,
    pending: Mutex<HashMap<u64, PendingLogEntry>>,
}

impl TrafficLogHandler {
    pub fn new(
        inner: Arc<dyn RequestHandler>,
        path: &Path,
    ) -> std::io::Result<Self> {
        // Reject symlinks to prevent writing to unintended locations
        #[cfg(unix)]
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            if meta.file_type().is_symlink() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Refusing to write log to symlink: {}", path.display()),
                ));
            }
        }

        // Create with restricted permissions (owner-only on Unix)
        #[cfg(unix)]
        let file = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(path)?
        };
        #[cfg(not(unix))]
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        let writer = std::io::BufWriter::new(file);
        let (tx, rx) = mpsc::sync_channel(256);

        std::thread::spawn(move || {
            LogWriter { rx, file: writer }.run();
        });

        info!("Traffic logging to {}", path.display());

        Ok(Self {
            inner,
            tx,
            next_id: AtomicU64::new(1),
            pending: Mutex::new(HashMap::new()),
        })
    }
}

impl RequestHandler for TrafficLogHandler {
    fn handle_request(&self, req: &mut Request<BoxBody>) {
        // Let inner handler process first (e.g., InterceptHandler may modify/drop)
        self.inner.handle_request(req);

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let is_buffered = req.extensions().get::<Buffered>().is_some();
        let is_dropped = req.extensions().get::<Dropped>().is_some();

        // Capture request data (after inner handler's modifications)
        let body_bytes = if is_buffered && !is_dropped {
            let b = extract_body_bytes(req);
            put_body_back(req, b.clone());
            b
        } else {
            Bytes::new()
        };

        let may_have_body = req.headers().contains_key(hyper::header::CONTENT_LENGTH)
            || req.headers().contains_key(hyper::header::TRANSFER_ENCODING);
        let (body, body_base64, body_truncated) = encode_body(&body_bytes, is_buffered, may_have_body);

        let upstream = req.extensions().get::<UpstreamTarget>().cloned();
        let logged_req = LoggedRequest {
            method: req.method().to_string(),
            uri: req.uri().to_string(),
            version: format!("{:?}", req.version()),
            target_scheme: upstream.as_ref().map(|t| t.scheme.clone()).unwrap_or_default(),
            target_host: upstream.as_ref().map(|t| t.host.clone()).unwrap_or_default(),
            target_port: upstream.as_ref().map(|t| t.port).unwrap_or(0),
            headers: capture_headers(req.headers()),
            body,
            body_base64,
            body_truncated,
        };

        // If dropped, emit log entry immediately with synthetic response
        if is_dropped {
            let entry = LogEntry {
                id,
                timestamp_req: format_timestamp(),
                timestamp_res: format_timestamp(),
                request: logged_req,
                response: LoggedResponse {
                    status: 0,
                    version: String::new(),
                    headers: Vec::new(),
                    body: None,
                    body_base64: None,
                    body_truncated: true,
                },
            };
            if self.tx.try_send(entry).is_err() {
                tracing::warn!("Traffic log queue full, entry dropped");
            }
            return;
        }

        // Store pending for pairing with response
        req.extensions_mut().insert(LogId(id));
        if let Ok(mut pending) = self.pending.lock() {
            // Prevent unbounded growth from failed upstream requests
            if pending.len() > 1000 {
                let oldest = *pending.keys().min().unwrap();
                pending.remove(&oldest);
                tracing::warn!("Evicted unpaired log entry {oldest} (pending overflow)");
            }
            pending.insert(id, PendingLogEntry {
                timestamp_req: format_timestamp(),
                request: logged_req,
            });
        }
    }

    fn handle_response(&self, res: &mut Response<BoxBody>) {
        let log_id = res.extensions().get::<LogId>().cloned();

        // Let inner handler process response FIRST (e.g., interceptor may edit/drop)
        self.inner.handle_response(res);

        // Now capture the final post-interception state for logging
        let is_buffered = res.extensions().get::<Buffered>().is_some();
        let is_dropped = res.extensions().get::<Dropped>().is_some();

        let body_bytes = if is_buffered && !is_dropped {
            let b = extract_response_body_bytes(res);
            put_response_body_back(res, b.clone());
            b
        } else {
            Bytes::new()
        };

        let may_have_body = res.headers().contains_key(hyper::header::CONTENT_LENGTH)
            || res.headers().contains_key(hyper::header::TRANSFER_ENCODING);
        let (body, body_base64, body_truncated) = encode_body(&body_bytes, is_buffered, may_have_body);

        let logged_res = LoggedResponse {
            status: if is_dropped { 0 } else { res.status().as_u16() },
            version: format!("{:?}", res.version()),
            headers: if is_dropped { Vec::new() } else { capture_headers(res.headers()) },
            body,
            body_base64,
            body_truncated: body_truncated || is_dropped,
        };

        // Pair with pending request
        if let Some(LogId(id)) = log_id {
            let pending_entry = self.pending.lock().ok().and_then(|mut p| p.remove(&id));
            if let Some(pending) = pending_entry {
                let entry = LogEntry {
                    id,
                    timestamp_req: pending.timestamp_req,
                    timestamp_res: format_timestamp(),
                    request: pending.request,
                    response: logged_res,
                };
                if self.tx.try_send(entry).is_err() {
                tracing::warn!("Traffic log queue full, entry dropped");
            }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_entry_serde_roundtrip() {
        let entry = LogEntry {
            id: 1,
            timestamp_req: "2026-04-11T12:00:00.000Z".into(),
            timestamp_res: "2026-04-11T12:00:00.123Z".into(),
            request: LoggedRequest {
                method: "GET".into(),
                uri: "/api".into(),
                version: "HTTP/1.1".into(),
                target_scheme: "https".into(),
                target_host: "example.com".into(),
                target_port: 443,
                headers: vec![("host".into(), "example.com".into())],
                body: None,
                body_base64: None,
                body_truncated: false,
            },
            response: LoggedResponse {
                status: 200,
                version: "HTTP/1.1".into(),
                headers: vec![("content-type".into(), "application/json".into())],
                body: Some("{\"ok\":true}".into()),
                body_base64: None,
                body_truncated: false,
            },
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: LogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, 1);
        assert_eq!(parsed.request.method, "GET");
        assert_eq!(parsed.response.status, 200);
    }

    #[test]
    fn test_encode_body_utf8() {
        let bytes = Bytes::from("hello world");
        let (body, b64, trunc) = encode_body(&bytes, true, true);
        assert_eq!(body.unwrap(), "hello world");
        assert!(b64.is_none());
        assert!(!trunc);
    }

    #[test]
    fn test_encode_body_binary() {
        let bytes = Bytes::from(vec![0xFF, 0xFE, 0x00, 0x01]);
        let (body, b64, trunc) = encode_body(&bytes, true, true);
        assert!(body.is_none());
        assert!(b64.is_some());
        assert!(!trunc);
    }

    #[test]
    fn test_encode_body_not_buffered_with_cl() {
        // Has Content-Length but wasn't buffered → truncated
        let bytes = Bytes::new();
        let (body, b64, trunc) = encode_body(&bytes, false, true);
        assert!(body.is_none());
        assert!(b64.is_none());
        assert!(trunc);
    }

    #[test]
    fn test_encode_body_not_buffered_no_cl() {
        // No Content-Length, not buffered → NOT truncated (bodyless request)
        let bytes = Bytes::new();
        let (body, b64, trunc) = encode_body(&bytes, false, false);
        assert!(body.is_none());
        assert!(b64.is_none());
        assert!(!trunc);
    }

    #[test]
    fn test_format_timestamp() {
        let ts = format_timestamp();
        assert!(ts.ends_with('Z'));
        assert!(ts.contains('T'));
    }
}
