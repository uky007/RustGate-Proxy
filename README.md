# RustGate

[![Crates.io](https://img.shields.io/crates/v/rustgate-proxy.svg)](https://crates.io/crates/rustgate-proxy)
[![docs.rs](https://docs.rs/rustgate-proxy/badge.svg)](https://docs.rs/rustgate-proxy)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

MITM-capable HTTP/HTTPS proxy with WebSocket-based C2 tunneling, written in Rust. It can be used as a CLI tool and as a library (crate: `rustgate-proxy`, lib: `rustgate`).

> **WARNING:** This tool is for authorized security research only. Unauthorized use may violate applicable laws. Use responsibly.

## Features

### Proxy Mode

- **HTTP Proxy** - Forwards plain HTTP requests (with hop-by-hop header stripping)
- **CONNECT Tunneling** - HTTPS passthrough via bidirectional byte relay
- **MITM Mode** - TLS termination for HTTPS interception and inspection
- **Dynamic Certificate Generation** - Per-domain CA-signed cert generation with caching
- **CA Certificate Management** - Auto-generates and stores root CA in `~/.rustgate/`
- **Request/Response Rewriting** - Hook mechanism via the `RequestHandler` trait
- **TUI Interceptor** (v0.3.0) - Interactive Burp-style request/response inspection, editing, and drop
- **Traffic Logging** (v0.4.0) - JSON Lines traffic capture with automatic credential redaction
- **Request Replay** (v0.4.0) - Resend captured traffic with HTTPS support and target override

### C2 Mode (v0.2.0)

- **WebSocket C2 Server** - Accepts client connections over mTLS-authenticated WebSocket
- **WebSocket C2 Client** - Connects to server, receives commands, creates tunnels
- **SOCKS5 Proxy Tunneling** - Operator-initiated SOCKS5 listener on client, traffic relayed through server
- **Reverse TCP Tunneling** - Server binds a port, forwards connections back to client's local service
- **mTLS Authentication** - Mutual TLS with separate CA for C2 (SHA-256 certificate fingerprint identity)
- **Client Certificate Generation** - `gen-client-cert` subcommand for mTLS credential provisioning

### Security Guardrails

- Tunnel creation commands only (no shell execution)
- Operator-authorized tunnel IDs with command-specific acknowledgements (`SocksReady`, `ReverseTunnelReady`)
- Channel ID parity validation (client=odd, server=even) with duplicate rejection
- Handshake timeouts (15s TLS + 10s WS) with concurrency limiting
- Session eviction with shutdown signaling for stale/reconnecting clients
- Per-tunnel lifecycle management (stop closes listeners, channels, and relays)
- Bounded connect/readiness timeouts on all async paths
- Reverse tunnel listeners bound to loopback only
- Partial CA state detection (fail-closed)
- Separate CA for C2 mode (`--ca-dir` required)

## Installation

```bash
cargo install rustgate-proxy
```

## Usage

### Proxy Mode

```bash
# Default: starts on 127.0.0.1:8080
rustgate

# MITM mode
rustgate --mitm

# Custom host/port
rustgate --host 0.0.0.0 --port 9090 --mitm
```

### Intercept Mode (new in v0.3.0)

```bash
rustgate --mitm --intercept
```

Opens a TUI for interactive request/response inspection and editing:

```
┌─ RustGate Interceptor ─────────────────────────────────┐
│ [INTERCEPT ON]  Pending: 1  History: 23                │
├─────────────────────────┬──────────────────────────────┤
│  # │ Method │ Path      │  ▶ PENDING REQUEST           │
│  1 │ GET    │ /api/user │  GET /api/data HTTP/1.1      │
│▸ 2 │ POST   │ /api/data │  Host: example.com           │
│    │        │           │  Authorization: Bearer xxx   │
│    │ History list       │  Detail / pending view       │
├─────────────────────────┴──────────────────────────────┤
│ [f]orward  [d]rop  [e]dit  [space] toggle  [q]uit     │
└────────────────────────────────────────────────────────┘
```

- **f** — Forward request/response as-is
- **d** — Drop (block the request or suppress the response)
- **e** — Edit headers and body in an inline text editor (Ctrl+S to save)
- **space** — Toggle interception on/off at runtime
- **q** — Quit TUI (proxy continues in passthrough mode)

### C2 Server

```bash
rustgate server --server-name myserver.example.com --ca-dir ./my-ca --port 4443
```

The server generates a CA on first run (if `--ca-dir` is empty), listens for mTLS WebSocket clients, and provides an interactive stdin console:

```
list                                  - List connected clients
socks <client> <port>                 - Start SOCKS5 on client
reverse <client> <remote_port> <target> - Reverse tunnel
stop <client> <tunnel_id>             - Stop a tunnel
```

### C2 Client

```bash
rustgate client \
  --server-url wss://myserver.example.com:4443 \
  --cert ./certs/client.pem \
  --key ./certs/client-key.pem \
  --ca-cert ./my-ca/ca.pem
```

### Generate Client Certificate

```bash
rustgate gen-client-cert --cn my-client --out-dir ./certs --ca-dir ./my-ca
```

### Traffic Logging (new in v0.4.0)

```bash
# Log all traffic to JSON Lines file
rustgate --mitm --log-file /tmp/traffic.jsonl

# Combined with intercept
rustgate --mitm --intercept --log-file /tmp/traffic.jsonl
```

Logs request/response pairs with timestamps, headers, and bodies. Sensitive headers and query parameter values are automatically redacted. Log files are created with `0o600` permissions.

### Replay

```bash
# Replay captured traffic to the original targets
rustgate replay --log-file /tmp/traffic.jsonl

# Replay to a different target (strips non-safe headers)
rustgate replay --log-file /tmp/traffic.jsonl --target https://staging.example.com

# Rate-limited replay
rustgate replay --log-file /tmp/traffic.jsonl --delay 100
```

### Log level

```bash
RUST_LOG=rustgate=debug rustgate --mitm
```

## Quick Verification (Proxy)

```bash
# HTTP proxy
curl -x http://localhost:8080 http://httpbin.org/get

# HTTPS passthrough
curl -x http://localhost:8080 https://httpbin.org/get

# MITM
curl --cacert ~/.rustgate/ca.pem -x http://localhost:8080 https://httpbin.org/get
```

## Use as a Library

```toml
[dependencies]
rustgate-proxy = "0.4"
```

### Custom handler

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

### Public modules

| Module | Description |
|-----------|------|
| `rustgate::proxy` | `ProxyState`, `handle_connection`, `parse_host_port` |
| `rustgate::cert` | `CertificateAuthority`, `CertifiedKey` |
| `rustgate::tls` | `make_tls_acceptor`, `connect_tls_upstream`, mTLS config |
| `rustgate::handler` | `RequestHandler` trait, `LoggingHandler`, `BoxBody` |
| `rustgate::error` | `ProxyError`, `Result` |
| `rustgate::c2` | C2 server and client modules |
| `rustgate::protocol` | WebSocket command/response protocol |
| `rustgate::ws` | WebSocket helpers and channel multiplexing |
| `rustgate::socks5` | Minimal SOCKS5 server (CONNECT only) |

## Notes

- **Use MITM and C2 features only with proper authorization.** Unauthorized interception or tunneling may violate laws.
- **Proxy mode has no authentication.** Binding to non-loopback addresses can expose it on your network.
- **C2 mode requires mTLS.** Both server and client must present certificates signed by the same CA.
- This tool is intended for security research, testing, and educational use.

## License

[MIT](LICENSE)
