use clap::Parser;
use rustgate::cert::CertificateAuthority;
use rustgate::handler::LoggingHandler;
use rustgate::proxy::ProxyState;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(name = "rustgate", about = "MITM HTTP/HTTPS proxy")]
struct Args {
    /// Address to listen on
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// Port to listen on
    #[arg(short, long, default_value_t = 8080)]
    port: u16,

    /// Enable MITM mode (TLS interception)
    #[arg(long)]
    mitm: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("rustgate=info".parse().unwrap()),
        )
        .init();

    let args = Args::parse();
    let listen_addr = format!("{}:{}", args.host, args.port);

    let ca = Arc::new(CertificateAuthority::new().await?);

    if args.mitm {
        let ca_path = CertificateAuthority::ca_cert_path()?;
        info!(
            "MITM mode enabled. Install CA cert: {}",
            ca_path.display()
        );
    }

    let state = Arc::new(ProxyState {
        ca,
        mitm: args.mitm,
        handler: Arc::new(LoggingHandler),
    });

    if let Ok(ip) = args.host.parse::<std::net::IpAddr>() {
        if !ip.is_loopback() {
            warn!(
                "Binding to non-loopback address ({}). No authentication is configured — this proxy may be accessible from the network.",
                args.host
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
