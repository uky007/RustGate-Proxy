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
