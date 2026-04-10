use std::fmt;

#[derive(Debug)]
pub enum ProxyError {
    Io(std::io::Error),
    Hyper(hyper::Error),
    Http(http::Error),
    Tls(rustls::Error),
    Rcgen(rcgen::Error),
    AddrParse(std::net::AddrParseError),
    WebSocket(String),
    Serde(serde_json::Error),
    Protocol(String),
    Other(String),
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProxyError::Io(e) => write!(f, "IO error: {e}"),
            ProxyError::Hyper(e) => write!(f, "Hyper error: {e}"),
            ProxyError::Http(e) => write!(f, "HTTP error: {e}"),
            ProxyError::Tls(e) => write!(f, "TLS error: {e}"),
            ProxyError::Rcgen(e) => write!(f, "Certificate error: {e}"),
            ProxyError::AddrParse(e) => write!(f, "Address parse error: {e}"),
            ProxyError::WebSocket(e) => write!(f, "WebSocket error: {e}"),
            ProxyError::Serde(e) => write!(f, "Serialization error: {e}"),
            ProxyError::Protocol(e) => write!(f, "Protocol error: {e}"),
            ProxyError::Other(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ProxyError {}

impl From<std::io::Error> for ProxyError {
    fn from(e: std::io::Error) -> Self {
        ProxyError::Io(e)
    }
}

impl From<hyper::Error> for ProxyError {
    fn from(e: hyper::Error) -> Self {
        ProxyError::Hyper(e)
    }
}

impl From<http::Error> for ProxyError {
    fn from(e: http::Error) -> Self {
        ProxyError::Http(e)
    }
}

impl From<rustls::Error> for ProxyError {
    fn from(e: rustls::Error) -> Self {
        ProxyError::Tls(e)
    }
}

impl From<rcgen::Error> for ProxyError {
    fn from(e: rcgen::Error) -> Self {
        ProxyError::Rcgen(e)
    }
}

impl From<std::net::AddrParseError> for ProxyError {
    fn from(e: std::net::AddrParseError) -> Self {
        ProxyError::AddrParse(e)
    }
}

impl From<serde_json::Error> for ProxyError {
    fn from(e: serde_json::Error) -> Self {
        ProxyError::Serde(e)
    }
}

impl From<tokio_tungstenite::tungstenite::Error> for ProxyError {
    fn from(e: tokio_tungstenite::tungstenite::Error) -> Self {
        ProxyError::WebSocket(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, ProxyError>;
