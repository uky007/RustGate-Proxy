use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::{Request, Response};
use tracing::info;

pub type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

/// Trait for intercepting and modifying HTTP requests and responses.
pub trait RequestHandler: Send + Sync {
    /// Called before forwarding the request to upstream.
    /// Modify the request in place to alter what gets sent.
    fn handle_request(&self, req: &mut Request<BoxBody>);

    /// Called before sending the response back to the client.
    /// Modify the response in place to alter what the client receives.
    fn handle_response(&self, res: &mut Response<BoxBody>);
}

/// Default handler that logs requests and responses without modification.
pub struct LoggingHandler;

impl RequestHandler for LoggingHandler {
    fn handle_request(&self, req: &mut Request<BoxBody>) {
        let path = req.uri().path();
        let display_uri = if req.uri().query().is_some() {
            format!("{path}?<redacted>")
        } else {
            path.to_string()
        };
        info!(">> {} {} {:?}", req.method(), display_uri, req.version());
    }

    fn handle_response(&self, res: &mut Response<BoxBody>) {
        info!("<< {}", res.status());
    }
}

/// Convert an incoming body to our BoxBody type.
pub fn boxed_body<B>(body: B) -> BoxBody
where
    B: hyper::body::Body<Data = Bytes, Error = hyper::Error> + Send + Sync + 'static,
{
    body.boxed()
}

/// Create a BoxBody from Bytes (fully buffered).
pub fn full_boxed_body(bytes: Bytes) -> BoxBody {
    http_body_util::Full::new(bytes)
        .map_err(|never| match never {})
        .boxed()
}

/// Extract body bytes from a request, replacing with empty body.
pub fn extract_body_bytes(req: &mut Request<BoxBody>) -> Bytes {
    let body = std::mem::replace(req.body_mut(), empty_boxed_body());
    // The body should already be a Full<Bytes> after pre-collection in proxy.rs.
    // We try to extract it synchronously via a blocking poll.
    // Since we pre-collect in proxy, the body is always ready.
    futures_util::FutureExt::now_or_never(async {
        body.collect().await.map(|c| c.to_bytes()).unwrap_or_default()
    })
    .unwrap_or_default()
}

/// Extract body bytes from a response, replacing with empty body.
pub fn extract_response_body_bytes(res: &mut Response<BoxBody>) -> Bytes {
    let body = std::mem::replace(res.body_mut(), empty_boxed_body());
    futures_util::FutureExt::now_or_never(async {
        body.collect().await.map(|c| c.to_bytes()).unwrap_or_default()
    })
    .unwrap_or_default()
}

/// Put bytes back as the request body.
pub fn put_body_back(req: &mut Request<BoxBody>, bytes: Bytes) {
    *req.body_mut() = full_boxed_body(bytes);
}

/// Put bytes back as the response body.
pub fn put_response_body_back(res: &mut Response<BoxBody>, bytes: Bytes) {
    *res.body_mut() = full_boxed_body(bytes);
}

/// Create an empty BoxBody.
pub fn empty_boxed_body() -> BoxBody {
    http_body_util::Empty::new()
        .map_err(|never| match never {})
        .boxed()
}

/// Marker type: when present in request extensions, the request was dropped by the interceptor.
#[derive(Clone)]
pub struct Dropped;

/// Marker type: when present in extensions, the body has been pre-buffered for interception.
#[derive(Clone)]
pub struct Buffered;
