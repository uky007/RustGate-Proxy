# Changelog

All notable changes to this project are documented in this file.

The format is based on Keep a Changelog, and this project follows Semantic Versioning.

## [0.1.1] - 2026-03-01

### Added
- Added `README.crates-io.md` as an English-only README for crates.io.
- Added Japanese section to repository `README.md` while keeping English-first structure.

### Changed
- Switched package README in `Cargo.toml` from `README.md` to `README.crates-io.md`.

## [0.1.0] - 2026-03-01

### Added
- Initial public release of RustGate-Proxy.
- HTTP proxy forwarding with hop-by-hop header stripping.
- CONNECT tunneling for HTTPS passthrough mode.
- MITM mode with dynamic per-domain certificate generation.
- Root CA generation/loading under `~/.rustgate/`.
- Request/response interception hooks via `RequestHandler`.
- IPv6 CONNECT target parsing support.
- CLI binary (`rustgate`) and library crate (`rustgate`).
- CI workflow for build, clippy, and test.

### Security
- Mask query parameters in request logs.
- Warn when binding proxy on non-loopback addresses.
