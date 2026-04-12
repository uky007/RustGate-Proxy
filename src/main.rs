use clap::{Parser, Subcommand};
use rustgate::cert::CertificateAuthority;
use rustgate::handler::LoggingHandler;
use rustgate::proxy::ProxyState;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{info, warn};

const BANNER: &str = "\
WARNING: This tool is for authorized security research only.
Unauthorized use may violate applicable laws. Use responsibly.
";

#[derive(Parser, Debug)]
#[command(name = "rustgate", about = "MITM proxy and C2 tunnel toolkit")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Address to listen on (proxy mode)
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// Port to listen on (proxy mode)
    #[arg(short, long, default_value_t = 8080)]
    port: u16,

    /// Enable MITM mode (TLS interception)
    #[arg(long)]
    mitm: bool,

    /// Enable request/response interception TUI (use with --mitm)
    #[arg(long)]
    intercept: bool,

    /// Log traffic to JSON Lines file
    #[arg(long)]
    log_file: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run as C2 server (accept WebSocket clients via mTLS)
    Server {
        #[arg(long, default_value = "0.0.0.0")]
        host: String,
        #[arg(short, long, default_value_t = 4443)]
        port: u16,
        /// Hostname/IP for the server certificate (clients connect to this name)
        #[arg(long)]
        server_name: String,
        /// Path to CA directory (required — each deployment should use its own CA)
        #[arg(long)]
        ca_dir: PathBuf,
    },
    /// Run as C2 client (connect to server via mTLS)
    Client {
        /// Server WebSocket URL (e.g. wss://server.example.com:4443)
        #[arg(long)]
        server_url: String,
        /// Path to client certificate PEM
        #[arg(long)]
        cert: PathBuf,
        /// Path to client private key PEM
        #[arg(long)]
        key: PathBuf,
        /// Path to CA cert PEM for verifying server
        #[arg(long)]
        ca_cert: PathBuf,
    },
    /// Generate a client certificate signed by the CA
    GenClientCert {
        /// Common name for the client certificate
        #[arg(long, default_value = "rustgate-client")]
        cn: String,
        /// Output directory for cert and key PEM files
        #[arg(long, default_value = ".")]
        out_dir: PathBuf,
        /// Path to CA directory (required — must match the server's CA)
        #[arg(long)]
        ca_dir: PathBuf,
    },
    /// Replay requests from a traffic log file
    Replay {
        /// Path to JSON Lines log file
        #[arg(long)]
        log_file: PathBuf,
        /// Override target URL (scheme://host:port) for all requests
        #[arg(long)]
        target: Option<String>,
        /// Delay between requests in milliseconds
        #[arg(long, default_value_t = 0)]
        delay: u64,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("rustgate=info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();

    eprintln!("{BANNER}");

    match cli.command {
        None => run_proxy(cli.host, cli.port, cli.mitm, cli.intercept, cli.log_file).await,
        Some(Commands::Server {
            host,
            port,
            server_name,
            ca_dir,
        }) => run_server(host, port, server_name, ca_dir).await,
        Some(Commands::Client {
            server_url,
            cert,
            key,
            ca_cert,
        }) => run_client(server_url, cert, key, ca_cert).await,
        Some(Commands::GenClientCert {
            cn,
            out_dir,
            ca_dir,
        }) => run_gen_client_cert(cn, out_dir, ca_dir).await,
        Some(Commands::Replay {
            log_file,
            target,
            delay,
        }) => run_replay(log_file, target, delay).await,
    }
}

async fn run_proxy(
    host: String,
    port: u16,
    mitm: bool,
    intercept: bool,
    log_file: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let listen_addr = format!("{host}:{port}");

    let ca = Arc::new(CertificateAuthority::new().await?);

    if mitm {
        let ca_path = CertificateAuthority::ca_cert_path()?;
        info!(
            "MITM mode enabled. Install CA cert: {}",
            ca_path.display()
        );
    }

    let base_handler: Arc<dyn rustgate::handler::RequestHandler> = if intercept {
        let (tx, rx) = std::sync::mpsc::sync_channel(16);
        let active = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let active_clone = active.clone();

        std::thread::spawn(move || {
            if let Err(e) = rustgate::tui::run_tui(rx, active_clone) {
                eprintln!("TUI error: {e}");
            }
        });

        Arc::new(rustgate::intercept::InterceptHandler::new(tx, active))
    } else {
        Arc::new(LoggingHandler)
    };

    let log_traffic = log_file.is_some();
    let handler: Arc<dyn rustgate::handler::RequestHandler> = if let Some(ref path) = log_file {
        Arc::new(rustgate::logging::TrafficLogHandler::new(base_handler, path)?)
    } else {
        base_handler
    };

    let state = Arc::new(ProxyState {
        ca,
        mitm,
        intercept,
        log_traffic,
        handler,
    });

    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if !ip.is_loopback() {
            warn!(
                "Binding to non-loopback address ({host}). \
                 No authentication is configured — this proxy may be accessible from the network."
            );
        }
    }

    let listener = TcpListener::bind(&listen_addr).await?;
    info!("RustGate proxy listening on {listen_addr}");

    loop {
        let (stream, addr) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            rustgate::proxy::handle_connection(stream, addr, state).await;
        });
    }
}

async fn run_server(
    host: String,
    port: u16,
    server_name: String,
    ca_dir: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let ca = Arc::new(CertificateAuthority::with_dir(ca_dir).await?);
    rustgate::c2::server::run(&host, port, &server_name, ca).await?;
    Ok(())
}

async fn run_client(
    server_url: String,
    cert: PathBuf,
    key: PathBuf,
    ca_cert: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    rustgate::c2::client::run(
        &server_url,
        cert.to_str().unwrap_or_default(),
        key.to_str().unwrap_or_default(),
        ca_cert.to_str().unwrap_or_default(),
    )
    .await?;
    Ok(())
}

async fn run_gen_client_cert(
    cn: String,
    out_dir: PathBuf,
    ca_dir: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let ca = CertificateAuthority::with_dir(ca_dir).await?;

    // Sanitize CN for use as a filename — reject path separators and traversals
    if cn.contains('/') || cn.contains('\\') || cn.contains('\0') || cn.starts_with('.') {
        return Err("CN must not contain path separators or start with '.'".into());
    }

    let (cert_pem, key_pem) = ca.generate_client_cert(&cn)?;

    tokio::fs::create_dir_all(&out_dir).await?;
    let cert_path = out_dir.join(format!("{cn}.pem"));
    let key_path = out_dir.join(format!("{cn}-key.pem"));

    // Reject symlinks to prevent arbitrary file clobber
    #[cfg(unix)]
    {
        for path in [&cert_path, &key_path] {
            if let Ok(meta) = tokio::fs::symlink_metadata(path).await {
                if meta.file_type().is_symlink() {
                    return Err(format!("Refusing to overwrite symlink: {}", path.display()).into());
                }
            }
        }
    }

    tokio::fs::write(&cert_path, &cert_pem).await?;

    // Write private key with restricted permissions
    #[cfg(unix)]
    {
        use tokio::io::AsyncWriteExt;
        // Try create_new first (no overwrite, 0600 from creation)
        let new_file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&key_path)
            .await;
        if let Ok(f) = new_file {
            let mut writer = tokio::io::BufWriter::new(f);
            writer.write_all(key_pem.as_bytes()).await?;
            writer.flush().await?;
        } else {
            // File already exists — overwrite and force-set permissions
            tokio::fs::write(&key_path, &key_pem).await?;
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).await?;
        }
    }
    #[cfg(not(unix))]
    {
        tokio::fs::write(&key_path, &key_pem).await?;
    }

    info!("Client certificate generated:");
    info!("  Cert: {}", cert_path.display());
    info!("  Key:  {}", key_path.display());
    info!("  CN:   {cn}");

    Ok(())
}

async fn run_replay(
    log_file: PathBuf,
    target: Option<String>,
    delay: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    use base64::Engine;
    use bytes::Bytes;
    use hyper::client::conn::http1 as client_http1;
    use hyper_util::rt::TokioIo;
    use std::io::BufRead;
    use tokio::net::TcpStream;

    let file = std::fs::File::open(&log_file)?;
    let reader = std::io::BufReader::new(file);

    let mut count = 0u64;
    for line_result in reader.lines() {
        let line = line_result?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: rustgate::logging::LogEntry = serde_json::from_str(&line)?;

        // Determine target
        let (scheme, host, port) = if let Some(ref t) = target {
            let parsed: http::Uri = t.parse()?;
            let s = parsed.scheme_str().ok_or_else(|| {
                format!("--target must include scheme (http:// or https://): {t}")
            })?.to_string();
            let h = parsed.host().ok_or_else(|| {
                format!("--target must include host: {t}")
            })?.to_string();
            let p = parsed.port_u16().unwrap_or(if s == "https" { 443 } else { 80 });
            (s, h, p)
        } else if !entry.request.target_host.is_empty() {
            (
                entry.request.target_scheme.clone(),
                entry.request.target_host.clone(),
                entry.request.target_port,
            )
        } else {
            warn!("Skipping entry {}: no target info", entry.id);
            continue;
        };

        let addr = format!("{host}:{port}");

        // Skip entries with truncated bodies (would send wrong payload)
        if entry.request.body_truncated {
            warn!("Skipping entry {}: body was not captured", entry.id);
            continue;
        }

        // Reconstruct body
        let body_bytes = if let Some(ref text) = entry.request.body {
            Bytes::from(text.clone())
        } else if let Some(ref b64) = entry.request.body_base64 {
            Bytes::from(base64::engine::general_purpose::STANDARD.decode(b64)?)
        } else {
            Bytes::new()
        };

        // Build request with path-only URI
        let path = {
            let parsed: http::Uri = entry.request.uri.parse().unwrap_or_default();
            parsed
                .path_and_query()
                .map(|pq| pq.to_string())
                .unwrap_or_else(|| "/".into())
        };
        let mut builder = hyper::Request::builder()
            .method(entry.request.method.as_str())
            .uri(&path);
        // Safe headers to forward when retargeting to a different host.
        // All other headers (including auth, cookies, vendor tokens) are dropped.
        const SAFE_HEADERS: &[&str] = &[
            "accept", "accept-encoding", "accept-language", "cache-control",
            "content-type", "user-agent", "if-match", "if-none-match",
            "if-modified-since", "if-unmodified-since", "range",
        ];
        for (name, value) in &entry.request.headers {
            if value == "<redacted>" {
                continue; // never replay redacted placeholder values
            } else if name.eq_ignore_ascii_case("host") {
                builder = builder.header("host", &host);
            } else if name.eq_ignore_ascii_case("content-length")
                || name.eq_ignore_ascii_case("transfer-encoding")
            {
                continue; // recomputed below
            } else if target.is_some()
                && !SAFE_HEADERS.iter().any(|h| name.eq_ignore_ascii_case(h))
            {
                continue; // drop non-safe headers when retargeting
            } else {
                builder = builder.header(name.as_str(), value.as_str());
            }
        }
        // Set correct Content-Length for the reconstructed body
        if !body_bytes.is_empty() {
            builder = builder.header("content-length", body_bytes.len().to_string());
        }
        let req = builder.body(rustgate::handler::full_boxed_body(body_bytes))?;

        // Connect and send (HTTP or HTTPS)
        let send_result = if scheme == "https" {
            // TLS connection
            match rustgate::tls::connect_tls_upstream(&host, &addr).await {
                Ok(tls_stream) => {
                    let io = TokioIo::new(tls_stream);
                    match client_http1::handshake(io).await {
                        Ok((mut sender, conn)) => {
                            tokio::spawn(async move { let _ = conn.await; });
                            sender.send_request(req).await.map_err(|e| e.to_string())
                        }
                        Err(e) => Err(format!("TLS handshake: {e}")),
                    }
                }
                Err(e) => Err(format!("TLS connect: {e}")),
            }
        } else {
            match TcpStream::connect(&addr).await {
                Ok(tcp) => {
                    let io = TokioIo::new(tcp);
                    match client_http1::handshake(io).await {
                        Ok((mut sender, conn)) => {
                            tokio::spawn(async move { let _ = conn.await; });
                            sender.send_request(req).await.map_err(|e| e.to_string())
                        }
                        Err(e) => Err(format!("Handshake: {e}")),
                    }
                }
                Err(e) => Err(format!("Connect: {e}")),
            }
        };

        match send_result {
            Ok(res) => {
                count += 1;
                info!(
                    "[{count}] {} {}://{}{} -> {}",
                    entry.request.method, scheme, host, entry.request.uri, res.status()
                );
            }
            Err(e) => {
                warn!("[{}] Failed: {e}", entry.request.uri);
            }
        }

        if delay > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
        }
    }

    info!("Replay complete: {count} requests sent");
    Ok(())
}
