use crate::error::{ProxyError, Result};
use crate::protocol::{
    frame_tunnel_data, parse_tunnel_data, Command, CommandResponse, ControlMessage, WsTextMessage,
};
use crate::socks5::Socks5Listener;
use crate::ws::{self, ChannelMap};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, RwLock};
use tokio_tungstenite::tungstenite::Message;
use tracing::{info, warn};

/// Run the C2 client with automatic reconnect.
pub async fn run(
    server_url: &str,
    cert_pem_path: &str,
    key_pem_path: &str,
    ca_cert_pem_path: &str,
) -> Result<()> {
    // Load client cert and key
    let cert_pem = tokio::fs::read_to_string(cert_pem_path).await?;
    let key_pem = tokio::fs::read_to_string(key_pem_path).await?;
    let ca_pem = tokio::fs::read_to_string(ca_cert_pem_path).await?;

    let client_cert_der = pem_to_cert_der(&cert_pem)?;
    let client_key_der = pem_to_key_der(&key_pem)?;
    let ca_cert_der = pem_to_cert_der(&ca_pem)?;

    let tls_config = crate::tls::make_mtls_client_config(
        client_cert_der,
        client_key_der,
        ca_cert_der,
    )?;

    // Parse host:port from server URL (wss://host:port)
    let (host, port) = parse_wss_url(server_url)?;

    let mut backoff = 1u64;
    loop {
        info!("Connecting to {server_url}...");
        match connect_and_run(&host, port, server_url, tls_config.clone()).await {
            Ok(()) => {
                info!("Disconnected from server");
                backoff = 1;
            }
            Err(e) => {
                warn!("Connection error: {e}");
            }
        }

        info!("Reconnecting in {backoff}s...");
        tokio::time::sleep(std::time::Duration::from_secs(backoff)).await;
        backoff = (backoff * 2).min(60);
    }
}

async fn connect_and_run(
    host: &str,
    port: u16,
    server_url: &str,
    tls_config: Arc<rustls::ClientConfig>,
) -> Result<()> {
    let addr = format!("{host}:{port}");
    let tcp = TcpStream::connect(&addr).await?;

    let connector = tokio_rustls::TlsConnector::from(tls_config);
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| ProxyError::Other(e.to_string()))?;
    let tls_stream = connector.connect(server_name, tcp).await?;

    info!("TLS handshake complete, upgrading to WebSocket...");
    let ws_stream = ws::connect_ws(tls_stream, server_url).await?;
    let (mut ws_sink, mut ws_source) = ws_stream.split();

    let channels = Arc::new(ChannelMap::new(1)); // Client uses odd IDs
    let tunnel_targets: Arc<RwLock<HashMap<u32, String>>> = Arc::new(RwLock::new(HashMap::new()));
    // Track spawned tunnel tasks for lifecycle management (StopTunnel)
    let tunnel_handles: Arc<RwLock<HashMap<u32, tokio::task::AbortHandle>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let (ws_tx, mut ws_rx) = mpsc::channel::<Message>(256);

    info!("Connected to C2 server");

    // Writer task
    let writer_handle = tokio::spawn(async move {
        while let Some(msg) = ws_rx.recv().await {
            if ws_sink.send(msg).await.is_err() {
                break;
            }
        }
    });

    // Reader loop
    while let Some(msg_result) = ws_source.next().await {
        let msg = match msg_result {
            Ok(m) => m,
            Err(e) => {
                warn!("WebSocket read error: {e}");
                break;
            }
        };

        match msg {
            Message::Text(text) => {
                match serde_json::from_str::<WsTextMessage>(&text) {
                    Ok(WsTextMessage::Command(cmd)) => {
                        handle_command(
                            cmd,
                            &channels,
                            &tunnel_targets,
                            &tunnel_handles,
                            ws_tx.clone(),
                        )
                        .await;
                    }
                    Ok(WsTextMessage::Control(ctrl)) => {
                        handle_client_control(
                            ctrl,
                            &channels,
                            &tunnel_targets,
                            ws_tx.clone(),
                        )
                        .await;
                    }
                    Ok(WsTextMessage::Response(_)) => {
                        warn!("Unexpected response from server");
                    }
                    Err(e) => {
                        warn!("Failed to parse message: {e}");
                    }
                }
            }
            Message::Binary(data) => {
                if let Some((channel_id, payload)) = parse_tunnel_data(&data) {
                    if !channels.send(channel_id, Bytes::copy_from_slice(payload)).await {
                        warn!("Data for unknown channel {channel_id}");
                    }
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }

    writer_handle.abort();

    // Close all channels — drops senders so relay tasks exit immediately
    channels.close_all().await;

    // Clean up all tunnel tasks so ports are freed for reconnect
    {
        let mut handles = tunnel_handles.write().await;
        for (tid, handle) in handles.drain() {
            handle.abort();
            info!("Aborted tunnel {tid} on disconnect");
        }
    }
    tunnel_targets.write().await.clear();

    Ok(())
}

/// Handle a command from the server.
async fn handle_command(
    cmd: Command,
    channels: &Arc<ChannelMap>,
    tunnel_targets: &Arc<RwLock<HashMap<u32, String>>>,
    tunnel_handles: &Arc<RwLock<HashMap<u32, tokio::task::AbortHandle>>>,
    ws_tx: mpsc::Sender<Message>,
) {
    match cmd {
        Command::Socks { tunnel_id, port } => {
            let addr = format!("127.0.0.1:{port}");
            info!("Starting SOCKS5 listener on {addr} (tunnel {tunnel_id})");

            match Socks5Listener::bind(&addr, tunnel_id).await {
                Ok(socks_listener) => {
                    send_response(
                        &ws_tx,
                        CommandResponse::SocksReady { tunnel_id },
                    )
                    .await;

                    let channels = channels.clone();
                    let ws_tx = ws_tx.clone();
                    let handle = tokio::spawn(async move {
                        socks_accept_loop(socks_listener, channels, ws_tx).await;
                    });
                    tunnel_handles
                        .write()
                        .await
                        .insert(tunnel_id, handle.abort_handle());
                }
                Err(e) => {
                    warn!("Failed to bind SOCKS5: {e}");
                    send_response(
                        &ws_tx,
                        CommandResponse::Error {
                            tunnel_id: Some(tunnel_id),
                            message: format!("Failed to bind: {e}"),
                        },
                    )
                    .await;
                }
            }
        }
        Command::ReverseTunnel {
            tunnel_id,
            remote_port,
            local_target,
        } => {
            info!(
                "Reverse tunnel {tunnel_id}: validating {local_target} \
                 (remote_port={remote_port})"
            );

            // Validate target is reachable before acknowledging
            match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                TcpStream::connect(&local_target),
            )
            .await
            {
                Ok(Ok(_tcp)) => {
                    // Target reachable — register and confirm
                    tunnel_targets
                        .write()
                        .await
                        .insert(tunnel_id, local_target);
                    send_response(
                        &ws_tx,
                        CommandResponse::ReverseTunnelReady { tunnel_id },
                    )
                    .await;
                }
                Ok(Err(e)) => {
                    warn!("Reverse tunnel {tunnel_id}: target {local_target} unreachable: {e}");
                    send_response(
                        &ws_tx,
                        CommandResponse::Error {
                            tunnel_id: Some(tunnel_id),
                            message: format!("Target unreachable: {e}"),
                        },
                    )
                    .await;
                }
                Err(_) => {
                    warn!("Reverse tunnel {tunnel_id}: target {local_target} connect timed out");
                    send_response(
                        &ws_tx,
                        CommandResponse::Error {
                            tunnel_id: Some(tunnel_id),
                            message: "Target connect timed out".into(),
                        },
                    )
                    .await;
                }
            }
        }
        Command::Ping { seq } => {
            send_response(&ws_tx, CommandResponse::Pong { seq }).await;
        }
        Command::StopTunnel { tunnel_id } => {
            tunnel_targets.write().await.remove(&tunnel_id);
            // Abort the spawned listener/task for this tunnel
            if let Some(handle) = tunnel_handles.write().await.remove(&tunnel_id) {
                handle.abort();
            }
            // Close all active channels belonging to this tunnel
            let closed = channels.close_tunnel(tunnel_id).await;
            if !closed.is_empty() {
                info!("Closed {} active channels for tunnel {tunnel_id}", closed.len());
            }
            info!("Tunnel {tunnel_id} stopped");
            send_response(
                &ws_tx,
                CommandResponse::Ok {
                    tunnel_id: Some(tunnel_id),
                    message: Some("Tunnel stopped".into()),
                },
            )
            .await;
        }
    }
}

/// Handle control messages from server on the client side.
async fn handle_client_control(
    ctrl: ControlMessage,
    channels: &Arc<ChannelMap>,
    tunnel_targets: &Arc<RwLock<HashMap<u32, String>>>,
    ws_tx: mpsc::Sender<Message>,
) {
    match ctrl {
        ControlMessage::ChannelOpen {
            channel_id,
            tunnel_id,
            target: _,
        } => {
            // Validate: server-originated channel_id must be even and not already in use
            if channel_id % 2 != 0 {
                warn!("Rejected ChannelOpen with odd channel_id {channel_id} from server");
                return;
            }
            if channels.has(channel_id).await {
                warn!("Rejected ChannelOpen with duplicate channel_id {channel_id}");
                let close = WsTextMessage::Control(ControlMessage::ChannelClose { channel_id });
                if let Ok(json) = serde_json::to_string(&close) {
                    let _ = ws_tx.send(Message::Text(json)).await;
                }
                return;
            }

            // Server opened a channel for a reverse tunnel — connect to local target
            let targets = tunnel_targets.read().await;
            let local_target = match targets.get(&tunnel_id) {
                Some(t) => t.clone(),
                None => {
                    warn!("ChannelOpen for unknown tunnel {tunnel_id}");
                    return;
                }
            };
            drop(targets);

            info!("Reverse channel {channel_id} -> connecting to {local_target}");

            // Reserve channel BEFORE async connect so ChannelClose can cancel it
            let (data_tx, data_rx) = mpsc::channel::<Bytes>(256);
            channels.insert_with_tunnel(channel_id, tunnel_id, data_tx).await;

            let channels = channels.clone();
            tokio::spawn(async move {
                // Timeout connect at 8s (< server's 10s readiness timeout)
                let connect_result = tokio::time::timeout(
                    std::time::Duration::from_secs(8),
                    TcpStream::connect(&local_target),
                )
                .await;
                match connect_result {
                    Ok(Ok(tcp)) => {
                        // Re-check channel still exists (not revoked during connect)
                        if !channels.has(channel_id).await {
                            warn!("Channel {channel_id} revoked during reverse connect, dropping");
                            drop(tcp);
                            return;
                        }

                        let ready = WsTextMessage::Control(ControlMessage::ChannelReady {
                            channel_id,
                        });
                        if let Ok(json) = serde_json::to_string(&ready) {
                            let _ = ws_tx.send(Message::Text(json)).await;
                        }

                        relay_tcp_ws(tcp, channel_id, data_rx, channels, ws_tx).await;
                    }
                    Ok(Err(e)) => {
                        warn!("Failed to connect to {local_target}: {e}");
                        channels.remove(channel_id).await;
                        let close = WsTextMessage::Control(ControlMessage::ChannelClose {
                            channel_id,
                        });
                        if let Ok(json) = serde_json::to_string(&close) {
                            let _ = ws_tx.send(Message::Text(json)).await;
                        }
                    }
                    Err(_) => {
                        warn!("Connect to {local_target} timed out for channel {channel_id}");
                        channels.remove(channel_id).await;
                        let close = WsTextMessage::Control(ControlMessage::ChannelClose {
                            channel_id,
                        });
                        if let Ok(json) = serde_json::to_string(&close) {
                            let _ = ws_tx.send(Message::Text(json)).await;
                        }
                    }
                }
            });
        }
        ControlMessage::ChannelReady { channel_id } => {
            channels.signal_ready(channel_id).await;
            info!("Channel {channel_id} ready");
        }
        ControlMessage::ChannelClose { channel_id } => {
            channels.remove(channel_id).await;
            info!("Channel {channel_id} closed by server");
        }
    }
}

/// SOCKS5 accept loop: accepts raw TCP connections concurrently, then performs
/// handshake per-connection with a timeout so one stalled client cannot block others.
async fn socks_accept_loop(
    listener: Socks5Listener,
    channels: Arc<ChannelMap>,
    ws_tx: mpsc::Sender<Message>,
) {
    let tunnel_id = listener.tunnel_id;
    loop {
        match listener.accept_raw().await {
            Ok(raw_stream) => {
                let channels = channels.clone();
                let ws_tx = ws_tx.clone();
                tokio::spawn(async move {
                    handle_socks_connection(raw_stream, tunnel_id, channels, ws_tx).await;
                });
            }
            Err(e) => {
                warn!("SOCKS5 accept error: {e}");
            }
        }
    }
}

/// Handle a single SOCKS5 connection: handshake (with timeout) -> ChannelOpen -> relay.
async fn handle_socks_connection(
    raw_stream: TcpStream,
    tunnel_id: u32,
    channels: Arc<ChannelMap>,
    ws_tx: mpsc::Sender<Message>,
) {
    // SOCKS handshake with 5s timeout to prevent one stalled client from blocking
    let handshake = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        crate::socks5::socks5_handshake(raw_stream),
    )
    .await;
    let (mut tcp_stream, req) = match handshake {
        Ok(Ok(result)) => result,
        Ok(Err(e)) => {
            warn!("SOCKS5 handshake failed: {e}");
            return;
        }
        Err(_) => {
            warn!("SOCKS5 handshake timed out");
            return;
        }
    };

    let channel_id = channels.alloc_id();
    info!(
        "SOCKS5 connection -> {}, channel {channel_id}",
        req.target_addr
    );

    let (data_tx, data_rx) = mpsc::channel::<Bytes>(256);
    channels
        .insert_with_tunnel(channel_id, tunnel_id, data_tx)
        .await;

    let ready_rx = channels.wait_ready(channel_id).await;

    let open = WsTextMessage::Control(ControlMessage::ChannelOpen {
        channel_id,
        tunnel_id,
        target: Some(req.target_addr),
    });
    if let Ok(json) = serde_json::to_string(&open) {
        if ws_tx.send(Message::Text(json)).await.is_err() {
            channels.remove(channel_id).await;
            return;
        }
    }

    // Wait for server to confirm the remote connection is ready (bounded timeout)
    let ready_result = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        ready_rx,
    )
    .await;
    if ready_result.is_err() || ready_result.unwrap().is_err() {
        warn!("Channel {channel_id} ready timeout or signal dropped");
        channels.remove(channel_id).await;
        let close = WsTextMessage::Control(ControlMessage::ChannelClose { channel_id });
        if let Ok(json) = serde_json::to_string(&close) {
            let _ = ws_tx.send(Message::Text(json)).await;
        }
        return;
    }

    if crate::socks5::send_socks5_success(&mut tcp_stream)
        .await
        .is_err()
    {
        warn!("Failed to send SOCKS5 success for channel {channel_id}");
        channels.remove(channel_id).await;
        let close = WsTextMessage::Control(ControlMessage::ChannelClose { channel_id });
        if let Ok(json) = serde_json::to_string(&close) {
            let _ = ws_tx.send(Message::Text(json)).await;
        }
        return;
    }

    relay_tcp_ws(tcp_stream, channel_id, data_rx, channels, ws_tx).await;
}

/// Bidirectional relay between a TCP stream and a WS channel.
/// `data_rx` must already be registered in `channels` before calling this.
async fn relay_tcp_ws(
    tcp: TcpStream,
    channel_id: u32,
    mut data_rx: mpsc::Receiver<Bytes>,
    channels: Arc<ChannelMap>,
    ws_tx: mpsc::Sender<Message>,
) {
    let (mut tcp_read, mut tcp_write) = tcp.into_split();

    // WS -> TCP
    let ws2tcp = tokio::spawn(async move {
        while let Some(data) = data_rx.recv().await {
            if tcp_write.write_all(&data).await.is_err() {
                break;
            }
        }
        let _ = tcp_write.shutdown().await;
    });

    // TCP -> WS
    let ws_tx_data = ws_tx.clone();
    let tcp2ws = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        loop {
            match tcp_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let frame = frame_tunnel_data(channel_id, &buf[..n]);
                    if ws_tx_data.send(Message::Binary(frame)).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // When first direction finishes: notify peer, give grace period to drain,
    // then remove channel routing and force-abort.
    let ws2tcp_abort = ws2tcp.abort_handle();
    let tcp2ws_abort = tcp2ws.abort_handle();

    tokio::select! {
        _ = ws2tcp => {}
        _ = tcp2ws => {}
    }

    // Notify peer (channel stays registered for drain)
    let close = WsTextMessage::Control(ControlMessage::ChannelClose { channel_id });
    if let Ok(json) = serde_json::to_string(&close) {
        let _ = ws_tx.send(Message::Text(json)).await;
    }

    // Grace period: channel stays registered so in-flight frames are delivered
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    // Now remove and force-abort
    channels.remove(channel_id).await;
    ws2tcp_abort.abort();
    tcp2ws_abort.abort();
}

async fn send_response(ws_tx: &mpsc::Sender<Message>, resp: CommandResponse) {
    let msg = WsTextMessage::Response(resp);
    if let Ok(json) = serde_json::to_string(&msg) {
        let _ = ws_tx.send(Message::Text(json)).await;
    }
}

fn parse_wss_url(url: &str) -> Result<(String, u16)> {
    let stripped = url
        .strip_prefix("wss://")
        .ok_or_else(|| ProxyError::Other("Server URL must start with wss://".into()))?;
    let (host, port) = if let Some((h, p)) = stripped.rsplit_once(':') {
        let port: u16 = p
            .parse()
            .map_err(|_| ProxyError::Other(format!("Invalid port in URL: {p}")))?;
        (h.to_string(), port)
    } else {
        (stripped.to_string(), 443)
    };
    Ok((host, port))
}

fn pem_to_cert_der(pem: &str) -> Result<CertificateDer<'static>> {
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    certs
        .into_iter()
        .next()
        .ok_or_else(|| ProxyError::Other("No certificate found in PEM".into()))
}

fn pem_to_key_der(pem: &str) -> Result<PrivatePkcs8KeyDer<'static>> {
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    let keys = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    keys.into_iter()
        .next()
        .ok_or_else(|| ProxyError::Other("No PKCS8 private key found in PEM".into()))
}
