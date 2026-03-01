# RustGate

[![Crates.io](https://img.shields.io/crates/v/rustgate-proxy.svg)](https://crates.io/crates/rustgate-proxy)
[![docs.rs](https://docs.rs/rustgate-proxy/badge.svg)](https://docs.rs/rustgate-proxy)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

MITM-capable HTTP/HTTPS proxy written in Rust. It can be used both as a CLI tool and as a library (crate: `rustgate-proxy`, lib: `rustgate`).

## Features

- **HTTP Proxy** - Forwards plain HTTP requests (with hop-by-hop header stripping)
- **CONNECT Tunneling** - HTTPS passthrough via bidirectional byte relay
- **MITM Mode** - TLS termination for HTTPS interception and inspection
- **Dynamic Certificate Generation** - Per-domain CA-signed cert generation with caching
- **CA Certificate Management** - Auto-generates and stores root CA in `~/.rustgate/` on first run (private key set to `0600`)
- **Request/Response Rewriting** - Hook mechanism via the `RequestHandler` trait
- **IPv6 Support** - Correctly handles CONNECT targets like `[::1]:443`
- **Security Considerations** - Masks query parameters in logs and warns on non-loopback bind

## Architecture

```
Client ──TCP──> RustGate Proxy ──TCP/TLS──> Upstream Server
                    |
              +-----+-----+
              | HTTP Router |
              +-----+------+
           +--------+--------+
           v        v        v
      HTTP Forward CONNECT   CONNECT
        (Plain)   (Tunnel)   (MITM)
                 Passthrough TLS Termination
```

## Installation

### From crates.io

```bash
cargo install rustgate-proxy
```

### Build from source

```bash
git clone https://github.com/uky007/RustGate-Proxy.git
cd RustGate-Proxy
cargo build --release
```

## Usage

### Basic (passthrough mode)

```bash
# Default: starts on 127.0.0.1:8080
rustgate

# Custom port
rustgate --port 9090
```

### MITM mode (TLS interception)

```bash
rustgate --mitm
```

On first startup, a CA certificate is generated at `~/.rustgate/ca.pem`.

### CLI options

```
Usage: rustgate [OPTIONS]

Options:
      --host <HOST>  Listen address [default: 127.0.0.1]
  -p, --port <PORT>  Listen port [default: 8080]
      --mitm         Enable MITM mode (TLS interception)
  -h, --help         Print help
```

### Log level

Controlled with the `RUST_LOG` environment variable:

```bash
RUST_LOG=rustgate=debug rustgate --mitm
RUST_LOG=rustgate=trace rustgate --mitm
```

## Quick verification

### HTTP proxy

```bash
curl -x http://localhost:8080 http://httpbin.org/get
```

### HTTPS passthrough

```bash
curl -x http://localhost:8080 https://httpbin.org/get
```

### MITM (TLS interception)

Send an HTTPS request with the CA certificate:

```bash
curl --cacert ~/.rustgate/ca.pem -x http://localhost:8080 https://httpbin.org/get
```

If you install the CA certificate into your OS trust store, `--cacert` is no longer needed:

```bash
# macOS
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain ~/.rustgate/ca.pem

# Ubuntu/Debian
sudo cp ~/.rustgate/ca.pem /usr/local/share/ca-certificates/rustgate.crt
sudo update-ca-certificates
```

## Use as a library

Crate name is `rustgate-proxy`; library name is `rustgate`.

```toml
[dependencies]
rustgate-proxy = "0.1"
```

### Custom handler

Implement `RequestHandler` to inspect or modify requests and responses passing through the proxy:

```rust
use rustgate::handler::{BoxBody, RequestHandler};
use hyper::{Request, Response};

struct MyHandler;

impl RequestHandler for MyHandler {
    fn handle_request(&self, req: &mut Request<BoxBody>) {
        req.headers_mut()
            .insert("X-Proxied-By", "RustGate".parse().unwrap());
    }

    fn handle_response(&self, res: &mut Response<BoxBody>) {
        res.headers_mut()
            .insert("X-Proxy", "RustGate".parse().unwrap());
    }
}
```

### Embed the proxy server

```rust
use rustgate::cert::CertificateAuthority;
use rustgate::handler::LoggingHandler;
use rustgate::proxy::{handle_connection, ProxyState};
use std::sync::Arc;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ca = Arc::new(CertificateAuthority::new().await?);
    let state = Arc::new(ProxyState {
        ca,
        mitm: true,
        handler: Arc::new(LoggingHandler),
    });

    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    loop {
        let (stream, addr) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(handle_connection(stream, addr, state));
    }
}
```

### Public modules

| Module | Description |
|-----------|------|
| `rustgate::proxy` | `ProxyState`, `handle_connection`, `parse_host_port` |
| `rustgate::cert` | `CertificateAuthority`, `CertifiedKey` |
| `rustgate::tls` | `make_tls_acceptor`, `connect_tls_upstream` |
| `rustgate::handler` | `RequestHandler` trait, `LoggingHandler`, `BoxBody` |
| `rustgate::error` | `ProxyError`, `Result` |

## File layout

```
src/
├── lib.rs        # Library entry point (exports modules)
├── main.rs       # CLI entry point
├── proxy.rs      # Proxy handlers (HTTP forward + CONNECT + MITM)
├── cert.rs       # CA management and dynamic certificate generation
├── tls.rs        # TLS termination and upstream TLS connection
├── handler.rs    # RequestHandler trait definition
└── error.rs      # Error type definitions
tests/
└── integration_test.rs  # Integration tests
```

## Notes

- **Use MITM features only with consent from all parties involved.** Unauthorized interception may violate laws.
- **Authentication and access control are not implemented.** Binding to non-loopback addresses (`0.0.0.0`, `::`, LAN IP, public IP, etc.) can expose the proxy on your network. RustGate warns at startup when binding to non-loopback addresses. Use trusted networks only, or restrict access with firewalls.
- This tool is intended for security testing, debugging, and educational use.

## License

[MIT](LICENSE)

