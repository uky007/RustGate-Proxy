use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use rustgate::cert::CertificateAuthority;
use rustgate::handler::LoggingHandler;
use rustgate::proxy::{handle_connection, ProxyState};
use std::sync::Arc;
use tempfile::TempDir;
use tokio::net::TcpListener;

type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

fn full_body(data: &'static str) -> BoxBody {
    Full::new(Bytes::from(data))
        .map_err(|_| unreachable!())
        .boxed()
}

fn empty_body() -> BoxBody {
    http_body_util::Empty::<Bytes>::new()
        .map_err(|_| unreachable!())
        .boxed()
}

/// Spawn a simple upstream HTTP server that returns a fixed response.
async fn spawn_upstream(body: &'static str) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let io = TokioIo::new(stream);
        let svc = service_fn(move |_req: Request<hyper::body::Incoming>| {
            let body = body;
            async move {
                let resp = Response::builder()
                    .status(200)
                    .body(full_body(body))
                    .unwrap();
                Ok::<_, hyper::Error>(resp)
            }
        });
        let _ = server_http1::Builder::new()
            .serve_connection(io, svc)
            .await;
    });
    (format!("127.0.0.1:{}", addr.port()), handle)
}

/// Spawn the proxy and return its address.
/// Returns (addr, handle, _tempdir) — keep _tempdir alive to prevent cleanup.
async fn spawn_proxy(mitm: bool) -> (String, tokio::task::JoinHandle<()>, TempDir) {
    let tmp = TempDir::new().unwrap();
    let ca = Arc::new(CertificateAuthority::with_dir(tmp.path().to_path_buf()).await.unwrap());
    let state = Arc::new(ProxyState {
        ca,
        mitm,
        handler: Arc::new(LoggingHandler),
    });

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        handle_connection(stream, peer, state).await;
    });
    (format!("127.0.0.1:{}", addr.port()), handle, tmp)
}

#[tokio::test]
async fn test_http_forward() {
    let (upstream_addr, _upstream) = spawn_upstream("hello from upstream").await;
    let (proxy_addr, _proxy, _tmp) = spawn_proxy(false).await;

    let stream = tokio::net::TcpStream::connect(&proxy_addr).await.unwrap();
    let io = TokioIo::new(stream);
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::builder()
        .method("GET")
        .uri(format!("http://{upstream_addr}/test"))
        .body(empty_body())
        .unwrap();

    let res = sender.send_request(req).await.unwrap();
    assert_eq!(res.status(), 200);

    let body = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"hello from upstream");
}

#[tokio::test]
async fn test_connect_tunnel_returns_200() {
    let (proxy_addr, _proxy, _tmp) = spawn_proxy(false).await;

    let stream = tokio::net::TcpStream::connect(&proxy_addr).await.unwrap();
    let io = TokioIo::new(stream);
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::builder()
        .method("CONNECT")
        .uri("example.com:443")
        .body(empty_body())
        .unwrap();

    let res = sender.send_request(req).await.unwrap();
    assert_eq!(res.status(), 200);
}

#[tokio::test]
async fn test_ca_reload_preserves_identity() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().to_path_buf();

    // First load: generates CA and saves to disk
    let _ca1 = CertificateAuthority::with_dir(dir.clone()).await.unwrap();
    let pem_after_create = std::fs::read_to_string(dir.join("ca.pem")).unwrap();

    // Second load: should reload the same CA from disk
    let _ca2 = CertificateAuthority::with_dir(dir.clone()).await.unwrap();
    let pem_after_reload = std::fs::read_to_string(dir.join("ca.pem")).unwrap();

    // CA cert on disk must not change between loads
    assert_eq!(pem_after_create, pem_after_reload);
}

#[test]
fn test_parse_host_port_ipv4() {
    let (host, port) = rustgate::proxy::parse_host_port("example.com:8080");
    assert_eq!(host, "example.com");
    assert_eq!(port, 8080);
}

#[test]
fn test_parse_host_port_default() {
    let (host, port) = rustgate::proxy::parse_host_port("example.com");
    assert_eq!(host, "example.com");
    assert_eq!(port, 443);
}

#[test]
fn test_parse_host_port_ipv6() {
    let (host, port) = rustgate::proxy::parse_host_port("[::1]:443");
    assert_eq!(host, "::1");
    assert_eq!(port, 443);
}

#[test]
fn test_parse_host_port_ipv6_custom_port() {
    let (host, port) = rustgate::proxy::parse_host_port("[2001:db8::1]:8080");
    assert_eq!(host, "2001:db8::1");
    assert_eq!(port, 8080);
}
