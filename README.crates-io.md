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

### C2 Mode (v0.2.0)

- **WebSocket C2 Server** - Accepts client connections over mTLS-authenticated WebSocket
- **WebSocket C2 Client** - Connects to server, receives commands, creates tunnels
- **SOCKS5 Proxy Tunneling** - Operator-initiated SOCKS5 listener on client, traffic relayed through server
- **Reverse TCP Tunneling** - Server binds a port, forwards connections back to client's local service
- **mTLS Authentication** - Mutual TLS with separate CA for C2 (SHA-256 certificate fingerprint identity)
- **Client Certificate Generation** - `gen-client-cert` subcommand for mTLS credential provisioning

## Installation

```bash
cargo install rustgate-proxy
```

## Usage

### Proxy Mode

```bash
rustgate              # Default: 127.0.0.1:8080
rustgate --mitm       # MITM mode
```

### C2 Server

```bash
rustgate server --server-name myserver.example.com --ca-dir ./my-ca --port 4443
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

## Use as a Library

```toml
[dependencies]
rustgate-proxy = "0.3"
```

## Notes

- **Use MITM and C2 features only with proper authorization.** Unauthorized interception or tunneling may violate laws.
- **C2 mode requires mTLS.** Both server and client must present certificates signed by the same CA.
- This tool is intended for security research, testing, and educational use.

## License

[MIT](LICENSE)
