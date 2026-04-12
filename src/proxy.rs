use crate::cert::CertificateAuthority;
use crate::error::ProxyError;
use crate::handler::{boxed_body, full_boxed_body, Buffered, BoxBody, Dropped, RequestHandler};
use crate::logging::{LogId, UpstreamTarget};
use crate::tls;
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::client::conn::http1 as client_http1;
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{Method, Request, Response};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tracing::{debug, error, info, warn};

/// Maximum body size for interception (10 MB).
const MAX_INTERCEPT_BODY: usize = 10 * 1024 * 1024;

/// Check if a body should be intercepted based on Content-Length header.
/// Returns true ONLY if Content-Length is explicitly present and within the limit.
/// All other cases (chunked, close-delimited, unknown-length) skip interception
/// to avoid consuming streaming bodies.
fn should_intercept_body(headers: &hyper::HeaderMap) -> bool {
    if let Some(cl) = headers.get(hyper::header::CONTENT_LENGTH) {
        if let Ok(s) = cl.to_str() {
            if let Ok(len) = s.parse::<usize>() {
                return len <= MAX_INTERCEPT_BODY;
            }
        }
    }
    false
}

/// Collect a body into Bytes. Returns None on failure or size exceeded.
async fn try_collect_body<B>(body: B) -> Option<Bytes>
where
    B: hyper::body::Body<Data = Bytes, Error = hyper::Error>,
{
    use http_body_util::Limited;
    let limited = Limited::new(body, MAX_INTERCEPT_BODY);
    BodyExt::collect(limited)
        .await
        .ok()
        .map(|c| c.to_bytes())
}

/// Shared state passed to each connection handler.
pub struct ProxyState {
    pub ca: Arc<CertificateAuthority>,
    pub mitm: bool,
    pub intercept: bool,
    pub log_traffic: bool,
    pub handler: Arc<dyn RequestHandler>,
}

/// Handle a single accepted TCP connection.
pub async fn handle_connection(
    stream: TcpStream,
    addr: SocketAddr,
    state: Arc<ProxyState>,
) {
    debug!("New connection from {addr}");

    let io = TokioIo::new(stream);
    let state = state.clone();

    let service = service_fn(move |req: Request<hyper::body::Incoming>| {
        let state = state.clone();
        async move { handle_request(req, state).await }
    });

    if let Err(e) = server_http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(io, service)
        .with_upgrades()
        .await
    {
        if !e.to_string().contains("early eof")
            && !e.to_string().contains("connection closed")
        {
            error!("Connection error from {addr}: {e}");
        }
    }
}

/// Route a request: CONNECT goes to tunnel/MITM, everything else gets forwarded.
async fn handle_request(
    req: Request<hyper::body::Incoming>,
    state: Arc<ProxyState>,
) -> Result<Response<BoxBody>, hyper::Error> {
    if req.method() == Method::CONNECT {
        handle_connect(req, state).await
    } else {
        handle_forward(req, state).await
    }
}

// ─── HTTP Forwarding ───────────────────────────────────────────────────────────

/// Forward a plain HTTP request to the upstream server.
async fn handle_forward(
    req: Request<hyper::body::Incoming>,
    state: Arc<ProxyState>,
) -> Result<Response<BoxBody>, hyper::Error> {
    let uri = req.uri().clone();
    let host = match uri.host() {
        Some(h) => h.to_string(),
        None => {
            warn!("Request with no host: {uri}");
            return Ok(bad_request("Missing host in URI"));
        }
    };
    let port = uri.port_u16().unwrap_or(80);
    let addr = format!("{host}:{port}");

    // Build the request to forward
    let (mut parts, body) = req.into_parts();
    let path = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    parts.uri = match path.parse() {
        Ok(uri) => uri,
        Err(_) => {
            warn!("Invalid path: {path}");
            return Ok(bad_request("Invalid request URI"));
        }
    };

    // Store upstream target for logging
    parts.extensions.insert(UpstreamTarget {
        scheme: "http".into(),
        host: host.to_string(),
        port,
    });

    // Check intercept eligibility BEFORE stripping hop-by-hop headers
    let do_buffer = (state.intercept || state.log_traffic) && should_intercept_body(&parts.headers);

    strip_hop_by_hop_headers(&mut parts.headers);

    let mut forwarded_req = if do_buffer {
        match try_collect_body(body).await {
            Some(bytes) => {
                let mut req = Request::from_parts(parts, full_boxed_body(bytes));
                req.extensions_mut().insert(Buffered);
                req
            }
            None if state.intercept => {
                error!("Request body collection failed");
                return Ok(bad_gateway("Request body read error"));
            }
            None => {
                // Logging-only: body consumed but forward with empty body (best-effort)
                warn!("Request body collection failed, forwarding with empty body");
                Request::from_parts(parts, full_boxed_body(Bytes::new()))
            }
        }
    } else {
        Request::from_parts(parts, boxed_body(body))
    };

    state.handler.handle_request(&mut forwarded_req);
    let log_id = forwarded_req.extensions().get::<LogId>().cloned();

    if forwarded_req.extensions().get::<Dropped>().is_some() {
        return Ok(bad_gateway("Request dropped by interceptor"));
    }

    // Connect to upstream
    let upstream = match TcpStream::connect(&addr).await {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to connect to {addr}: {e}");
            return Ok(bad_gateway(&format!("Failed to connect to {addr}")));
        }
    };

    let io = TokioIo::new(upstream);
    let (mut sender, conn) = match client_http1::handshake(io).await {
        Ok(r) => r,
        Err(e) => {
            error!("Handshake with {addr} failed: {e}");
            return Ok(bad_gateway("Upstream handshake failed"));
        }
    };

    tokio::spawn(async move {
        if let Err(e) = conn.await {
            error!("Upstream connection error: {e}");
        }
    });

    match sender.send_request(forwarded_req).await {
        Ok(res) => {
            let (parts, body) = res.into_parts();
            let mut response = if (state.intercept || state.log_traffic) && should_intercept_body(&parts.headers) {
                match try_collect_body(body).await {
                    Some(bytes) => {
                        let mut res = Response::from_parts(parts, full_boxed_body(bytes));
                        res.extensions_mut().insert(Buffered);
                        res
                    }
                    None if state.intercept => {
                        error!("Response body collection failed");
                        return Ok(bad_gateway("Response body collection failed"));
                    }
                    None => {
                        // Logging-only: pass through empty body (best-effort)
                        warn!("Response body collection failed, forwarding empty");
                        Response::from_parts(parts, full_boxed_body(Bytes::new()))
                    }
                }
            } else {
                Response::from_parts(parts, boxed_body(body))
            };
            if let Some(id) = log_id { response.extensions_mut().insert(id); }
            state.handler.handle_response(&mut response);
            if response.extensions().get::<Dropped>().is_some() {
                return Ok(interceptor_dropped_response());
            }
            Ok(response)
        }
        Err(e) => {
            error!("Upstream request failed: {e}");
            Ok(bad_gateway("Upstream request failed"))
        }
    }
}

// ─── CONNECT Handling ──────────────────────────────────────────────────────────

/// Handle a CONNECT request: either tunnel (passthrough) or MITM.
async fn handle_connect(
    req: Request<hyper::body::Incoming>,
    state: Arc<ProxyState>,
) -> Result<Response<BoxBody>, hyper::Error> {
    let target = match req.uri().authority() {
        Some(auth) => auth.to_string(),
        None => {
            warn!("CONNECT without authority");
            return Ok(bad_request("CONNECT target missing"));
        }
    };

    let (host, port) = parse_host_port(&target);
    let addr = format!("{host}:{port}");

    info!("CONNECT {target}");

    if state.mitm {
        // MITM mode: intercept the TLS connection
        handle_mitm(req, host, addr, state).await
    } else {
        // Passthrough mode: just tunnel bytes
        handle_tunnel(req, addr).await
    }
}

/// Passthrough tunneling: bidirectional copy between client and upstream.
async fn handle_tunnel(
    req: Request<hyper::body::Incoming>,
    addr: String,
) -> Result<Response<BoxBody>, hyper::Error> {
    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                if let Err(e) = tunnel_bidirectional(upgraded, &addr).await {
                    error!("Tunnel error to {addr}: {e}");
                }
            }
            Err(e) => {
                error!("Upgrade failed: {e}");
            }
        }
    });

    // Respond with 200 to tell the client the tunnel is established
    Ok(Response::new(empty_body()))
}

/// Copy data bidirectionally between the upgraded client connection and upstream.
async fn tunnel_bidirectional(
    upgraded: Upgraded,
    addr: &str,
) -> crate::error::Result<()> {
    let mut upstream = TcpStream::connect(addr).await?;

    let mut client = TokioIo::new(upgraded);

    let (client_to_server, server_to_client) =
        tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;

    debug!(
        "Tunnel closed: {addr} (client→server: {client_to_server}B, server→client: {server_to_client}B)"
    );
    Ok(())
}

/// MITM mode: terminate TLS with both ends, intercept HTTP traffic.
async fn handle_mitm(
    req: Request<hyper::body::Incoming>,
    host: String,
    addr: String,
    state: Arc<ProxyState>,
) -> Result<Response<BoxBody>, hyper::Error> {
    let state = state.clone();

    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                if let Err(e) =
                    mitm_intercept(upgraded, &host, &addr, state).await
                {
                    error!("MITM error for {host}: {e}");
                }
            }
            Err(e) => {
                error!("MITM upgrade failed: {e}");
            }
        }
    });

    Ok(Response::new(empty_body()))
}

/// Perform MITM interception on an upgraded connection.
async fn mitm_intercept(
    upgraded: Upgraded,
    host: &str,
    addr: &str,
    state: Arc<ProxyState>,
) -> crate::error::Result<()> {
    // Create a TLS acceptor with a fake cert for this domain
    let acceptor = tls::make_tls_acceptor(&state.ca, host).await?;

    // Accept TLS from the client side
    let client_io = TokioIo::new(upgraded);
    let client_tls = acceptor
        .accept(client_io)
        .await
        .map_err(|e| ProxyError::Other(format!("Client TLS accept failed: {e}")))?;

    let client_tls = TokioIo::new(client_tls);

    // Serve HTTP on the decrypted client stream
    let host = host.to_string();
    let addr = addr.to_string();

    let service = service_fn(move |req: Request<hyper::body::Incoming>| {
        let host = host.clone();
        let addr = addr.clone();
        let state = state.clone();
        async move {
            mitm_forward_request(req, &host, &addr, state).await
        }
    });

    if let Err(e) = server_http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(client_tls, service)
        .await
    {
        if !e.to_string().contains("early eof")
            && !e.to_string().contains("connection closed")
        {
            debug!("MITM connection closed: {e}");
        }
    }

    Ok(())
}

/// Forward a request from the MITM-decrypted stream to the real upstream over TLS.
async fn mitm_forward_request(
    req: Request<hyper::body::Incoming>,
    host: &str,
    addr: &str,
    state: Arc<ProxyState>,
) -> Result<Response<BoxBody>, hyper::Error> {
    let (mut parts, body) = req.into_parts();

    parts.extensions.insert(UpstreamTarget {
        scheme: "https".into(),
        host: host.to_string(),
        port: addr.rsplit_once(':').and_then(|(_, p)| p.parse().ok()).unwrap_or(443),
    });

    let do_buffer = (state.intercept || state.log_traffic) && should_intercept_body(&parts.headers);
    strip_hop_by_hop_headers(&mut parts.headers);

    let mut forwarded_req = if do_buffer {
        match try_collect_body(body).await {
            Some(bytes) => {
                let mut req = Request::from_parts(parts, full_boxed_body(bytes));
                req.extensions_mut().insert(Buffered);
                req
            }
            None if state.intercept => {
                error!("MITM request body collection failed");
                return Ok(bad_gateway("Request body read error"));
            }
            None => {
                warn!("MITM request body collection failed, forwarding with empty body");
                Request::from_parts(parts, full_boxed_body(Bytes::new()))
            }
        }
    } else {
        Request::from_parts(parts, boxed_body(body))
    };

    state.handler.handle_request(&mut forwarded_req);
    let log_id = forwarded_req.extensions().get::<LogId>().cloned();

    if forwarded_req.extensions().get::<Dropped>().is_some() {
        return Ok(bad_gateway("Request dropped by interceptor"));
    }

    // Connect to upstream over TLS
    let upstream_tls = match tls::connect_tls_upstream(host, addr).await {
        Ok(s) => s,
        Err(e) => {
            error!("Failed TLS connect to {addr}: {e}");
            return Ok(bad_gateway(&format!(
                "Failed to connect to upstream: {e}"
            )));
        }
    };

    let io = TokioIo::new(upstream_tls);
    let (mut sender, conn) = match client_http1::handshake(io).await {
        Ok(r) => r,
        Err(e) => {
            error!("Upstream TLS handshake failed: {e}");
            return Ok(bad_gateway("Upstream TLS handshake failed"));
        }
    };

    tokio::spawn(async move {
        if let Err(e) = conn.await {
            debug!("Upstream TLS connection closed: {e}");
        }
    });

    match sender.send_request(forwarded_req).await {
        Ok(res) => {
            let (parts, body) = res.into_parts();
            let mut response = if (state.intercept || state.log_traffic) && should_intercept_body(&parts.headers) {
                match try_collect_body(body).await {
                    Some(bytes) => {
                        let mut res = Response::from_parts(parts, full_boxed_body(bytes));
                        res.extensions_mut().insert(Buffered);
                        res
                    }
                    None if state.intercept => {
                        error!("MITM response body collection failed");
                        return Ok(bad_gateway("Response body collection failed"));
                    }
                    None => {
                        warn!("MITM response body collection failed, forwarding empty");
                        Response::from_parts(parts, full_boxed_body(Bytes::new()))
                    }
                }
            } else {
                Response::from_parts(parts, boxed_body(body))
            };
            if let Some(id) = log_id { response.extensions_mut().insert(id); }
            state.handler.handle_response(&mut response);
            if response.extensions().get::<Dropped>().is_some() {
                return Ok(interceptor_dropped_response());
            }
            Ok(response)
        }
        Err(e) => {
            error!("Upstream TLS request failed: {e}");
            Ok(bad_gateway("Upstream request failed"))
        }
    }
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

/// Hop-by-hop headers that should not be forwarded.
const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

/// Parse host and port from a CONNECT target, handling IPv6 bracket notation.
/// e.g. "example.com:443", "[::1]:443", "example.com"
pub fn parse_host_port(target: &str) -> (String, u16) {
    if let Some(bracketed) = target.strip_prefix('[') {
        // IPv6: [::1]:port
        if let Some((ip6, rest)) = bracketed.split_once(']') {
            let port = rest
                .strip_prefix(':')
                .and_then(|p| p.parse().ok())
                .unwrap_or(443);
            return (ip6.to_string(), port);
        }
    }
    // IPv4 / hostname: host:port
    if let Some((host, port_str)) = target.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            return (host.to_string(), port);
        }
    }
    (target.to_string(), 443)
}

fn strip_hop_by_hop_headers(headers: &mut hyper::HeaderMap) {
    // Also remove headers listed in the Connection header value
    if let Some(conn_val) = headers.get("connection").cloned() {
        if let Ok(val) = conn_val.to_str() {
            for name in val.split(',') {
                let name = name.trim();
                if !name.is_empty() {
                    headers.remove(name);
                }
            }
        }
    }

    for name in HOP_BY_HOP_HEADERS {
        headers.remove(*name);
    }
}

fn empty_body() -> BoxBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn bad_request(msg: &str) -> Response<BoxBody> {
    Response::builder()
        .status(400)
        .body(full_body(msg))
        .unwrap()
}

fn bad_gateway(msg: &str) -> Response<BoxBody> {
    Response::builder()
        .status(502)
        .body(full_body(msg))
        .unwrap()
}

/// Non-retryable response for interceptor-dropped responses.
/// Uses 444 (No Response, nginx convention) + Connection: close to signal
/// that the response was locally suppressed and the client should NOT retry.
/// The upstream request was already executed.
fn interceptor_dropped_response() -> Response<BoxBody> {
    Response::builder()
        .status(444)
        .header("Connection", "close")
        .header("X-RustGate-Interceptor", "response-dropped")
        .body(full_body(
            "Response dropped by interceptor. The upstream request was already executed. Do not retry.",
        ))
        .unwrap()
}

fn full_body(msg: &str) -> BoxBody {
    Full::new(Bytes::from(msg.to_string()))
        .map_err(|never| match never {})
        .boxed()
}
