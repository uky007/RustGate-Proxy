use crate::cert::CertificateAuthority;
use crate::error::{ProxyError, Result};
use crate::protocol::{
    frame_tunnel_data, parse_tunnel_data, Command, CommandResponse, ControlMessage, WsTextMessage,
};
use crate::ws::{self, ChannelMap};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::Message;
use tracing::{error, info, warn};

struct ClientHandle {
    cn: String,
    session_id: u64,
    ws_tx: mpsc::Sender<Message>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    channels: Arc<ChannelMap>,
    /// Pending reverse tunnels: tunnel_id -> remote_port (waiting for client Ok)
    pending_reverse: Arc<tokio::sync::RwLock<HashMap<u32, u16>>>,
    /// Pending SOCKS tunnels: tunnel_ids waiting for client Ok before authorization
    pending_socks: Arc<tokio::sync::RwLock<std::collections::HashSet<u32>>>,
    /// Tunnel IDs authorized by the operator (SOCKS commands, granted on client Ok)
    authorized_tunnels: Arc<tokio::sync::RwLock<std::collections::HashSet<u32>>>,
    /// Active reverse tunnel listeners: tunnel_id -> abort handle
    reverse_listeners: Arc<tokio::sync::RwLock<HashMap<u32, tokio::task::AbortHandle>>>,
}

struct ServerState {
    clients: Arc<tokio::sync::RwLock<HashMap<String, ClientHandle>>>,
    next_tunnel_id: AtomicU32,
    next_session_id: std::sync::atomic::AtomicU64,
}

impl ServerState {
    fn alloc_tunnel_id(&self) -> u32 {
        self.next_tunnel_id.fetch_add(1, Ordering::Relaxed)
    }
}

/// Run the C2 server.
pub async fn run(
    host: &str,
    port: u16,
    server_name: &str,
    ca: Arc<CertificateAuthority>,
) -> Result<()> {
    let listen_addr = format!("{host}:{port}");

    // Generate server cert using the advertised server_name, not the bind address
    let server_ck = ca.generate_server_cert(server_name)?;
    let ca_cert_der = ca.ca_cert_der();
    let tls_config =
        crate::tls::make_mtls_server_config(server_ck.cert_der, server_ck.key_der, ca_cert_der)?;
    let acceptor = TlsAcceptor::from(tls_config);

    let state = Arc::new(ServerState {
        clients: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        next_session_id: std::sync::atomic::AtomicU64::new(1),
        next_tunnel_id: AtomicU32::new(1),
    });

    let listener = TcpListener::bind(&listen_addr).await?;
    info!(
        "C2 server listening on {listen_addr} (cert name: {server_name}, mTLS required)"
    );

    let state_stdin = state.clone();
    tokio::spawn(async move {
        if let Err(e) = stdin_command_loop(state_stdin).await {
            error!("Stdin command loop error: {e}");
        }
    });

    // Limit concurrent handshakes to prevent pre-auth exhaustion
    let handshake_semaphore = Arc::new(tokio::sync::Semaphore::new(64));

    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let state = state.clone();
        let sem = handshake_semaphore.clone();

        tokio::spawn(async move {
            // Acquire permit for handshake only
            let permit = match sem.try_acquire() {
                Ok(p) => p,
                Err(_) => {
                    warn!("Rejecting {peer}: too many concurrent handshakes");
                    return;
                }
            };

            // Perform TLS + WS handshake under the permit
            let handshake_result = perform_handshake(stream, peer, &acceptor).await;
            drop(permit); // Release immediately after handshake

            match handshake_result {
                Ok((ws_stream, fingerprint, cn)) => {
                    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
                    match run_session(ws_stream, peer, fingerprint, cn, state, shutdown_tx, shutdown_rx).await {
                        Ok(()) => info!("Client {peer} disconnected"),
                        Err(e) => warn!("Client {peer} error: {e}"),
                    }
                }
                Err(e) => warn!("Client {peer} handshake error: {e}"),
            }
        });
    }
}

/// Perform TLS + WebSocket handshake with timeouts. Returns (ws_stream, fingerprint, cn).
async fn perform_handshake(
    stream: TcpStream,
    peer: std::net::SocketAddr,
    acceptor: &TlsAcceptor,
) -> Result<(ws::ServerWsStream, String, String)> {
    let tls_stream = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        acceptor.accept(stream),
    )
    .await
    .map_err(|_| ProxyError::Other(format!("TLS handshake timed out for {peer}")))?
    .map_err(|e| ProxyError::Other(format!("TLS handshake failed for {peer}: {e}")))?;

    let (fingerprint, cn) = extract_client_identity(&tls_stream);
    info!("Client authenticated: {cn} [{fingerprint}] ({peer})");

    let ws_stream = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        ws::accept_ws(tls_stream),
    )
    .await
    .map_err(|_| ProxyError::Other(format!("WebSocket upgrade timed out for {peer}")))?
    ?;

    Ok((ws_stream, fingerprint, cn))
}

/// Run the authenticated C2 session after handshake.
async fn run_session(
    ws_stream: ws::ServerWsStream,
    _peer: std::net::SocketAddr,
    fingerprint: String,
    cn: String,
    state: Arc<ServerState>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let client_label = format!("{cn} [{fingerprint}]");
    let (mut ws_sink, mut ws_source) = ws_stream.split();

    let channels = Arc::new(ChannelMap::new(2)); // Server uses even IDs
    let (ws_tx, mut ws_rx) = mpsc::channel::<Message>(256);

    let reverse_listeners: Arc<tokio::sync::RwLock<HashMap<u32, tokio::task::AbortHandle>>> =
        Arc::new(tokio::sync::RwLock::new(HashMap::new()));
    let pending_reverse: Arc<tokio::sync::RwLock<HashMap<u32, u16>>> =
        Arc::new(tokio::sync::RwLock::new(HashMap::new()));
    let authorized_tunnels: Arc<tokio::sync::RwLock<std::collections::HashSet<u32>>> =
        Arc::new(tokio::sync::RwLock::new(std::collections::HashSet::new()));
    let pending_socks: Arc<tokio::sync::RwLock<std::collections::HashSet<u32>>> =
        Arc::new(tokio::sync::RwLock::new(std::collections::HashSet::new()));

    let session_id = state
        .next_session_id
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    // If a session with the same fingerprint exists, evict it (stale/half-open).
    {
        let mut clients = state.clients.write().await;
        if let Some(old) = clients.remove(&fingerprint) {
            warn!("[{client_label}] Evicting stale session for reconnect");
            // Wipe all authorization/pending state so the old task cannot act
            old.authorized_tunnels.write().await.clear();
            old.pending_socks.write().await.clear();
            old.pending_reverse.write().await.clear();
            // Close all channels — drops senders, unblocking relay tasks
            old.channels.close_all().await;
            // Abort reverse listeners so ports are freed
            for handle in old.reverse_listeners.write().await.drain() {
                handle.1.abort();
            }
            // Signal the old session to shut down
            let _ = old.shutdown_tx.send(true);
            drop(old);
        }
        clients.insert(
            fingerprint.clone(),
            ClientHandle {
                cn: cn.clone(),
                session_id,
                ws_tx: ws_tx.clone(),
                shutdown_tx,
                channels: channels.clone(),
                pending_reverse: pending_reverse.clone(),
                pending_socks: pending_socks.clone(),
                authorized_tunnels: authorized_tunnels.clone(),
                reverse_listeners: reverse_listeners.clone(),
            },
        );
    }

    // Writer task
    let label_writer = client_label.clone();
    let writer_handle = tokio::spawn(async move {
        while let Some(msg) = ws_rx.recv().await {
            if ws_sink.send(msg).await.is_err() {
                info!("[{label_writer}] WS write closed");
                break;
            }
        }
    });

    // Reader loop
    let channels_reader = channels.clone();
    let ws_tx_reader = ws_tx.clone();
    let label_reader = client_label.clone();
    let tunnel_state = ClientTunnelState {
        pending_reverse: pending_reverse.clone(),
        pending_socks: pending_socks.clone(),
        authorized_tunnels: authorized_tunnels.clone(),
        reverse_listeners: reverse_listeners.clone(),
    };
    loop {
        let msg_result = tokio::select! {
            msg = ws_source.next() => msg,
            _ = shutdown_rx.changed() => {
                info!("[{label_reader}] Session shutdown signal received");
                break;
            }
        };
        let msg = match msg_result {
            Some(Ok(m)) => m,
            Some(Err(e)) => {
                warn!("[{label_reader}] WebSocket read error: {e}");
                break;
            }
            None => break,
        };

        match msg {
            Message::Text(text) => match serde_json::from_str::<WsTextMessage>(&text) {
                Ok(WsTextMessage::Response(resp)) => {
                    handle_response(
                        &label_reader,
                        &resp,
                        &tunnel_state,
                        &channels_reader,
                        ws_tx_reader.clone(),
                    )
                    .await;
                }
                Ok(WsTextMessage::Control(ctrl)) => {
                    handle_server_control(
                        &label_reader,
                        ctrl,
                        channels_reader.clone(),
                        &tunnel_state.authorized_tunnels,
                        ws_tx_reader.clone(),
                    )
                    .await;
                }
                Ok(WsTextMessage::Command(_)) => {
                    warn!("[{label_reader}] Unexpected command from client");
                }
                Err(e) => {
                    warn!("[{label_reader}] Failed to parse message: {e}");
                }
            },
            Message::Binary(data) => {
                if let Some((channel_id, payload)) = parse_tunnel_data(&data) {
                    if !channels_reader
                        .send(channel_id, Bytes::copy_from_slice(payload))
                        .await
                    {
                        warn!("[{label_reader}] Data for unknown channel {channel_id}");
                    }
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }

    // Cleanup: abort writer, close channels, abort reverse listeners
    writer_handle.abort();
    channels.close_all().await;
    {
        let listeners = reverse_listeners.read().await;
        for handle in listeners.values() {
            handle.abort();
        }
    }
    // Only remove from clients map if this session is still the current one (generation check)
    {
        let mut clients = state.clients.write().await;
        if let Some(existing) = clients.get(&fingerprint) {
            if existing.session_id == session_id {
                clients.remove(&fingerprint);
            }
        }
    }
    info!("[{client_label}] Client removed");

    Ok(())
}

/// Per-client tunnel state used by handle_response.
struct ClientTunnelState {
    pending_reverse: Arc<tokio::sync::RwLock<HashMap<u32, u16>>>,
    pending_socks: Arc<tokio::sync::RwLock<std::collections::HashSet<u32>>>,
    authorized_tunnels: Arc<tokio::sync::RwLock<std::collections::HashSet<u32>>>,
    reverse_listeners: Arc<tokio::sync::RwLock<HashMap<u32, tokio::task::AbortHandle>>>,
}

/// Handle client responses — authorize tunnels on Ok, revoke on Error.
async fn handle_response(
    label: &str,
    resp: &CommandResponse,
    ts: &ClientTunnelState,
    channels: &Arc<ChannelMap>,
    ws_tx: mpsc::Sender<Message>,
) {
    match resp {
        CommandResponse::SocksReady { tunnel_id: tid } => {
            if ts.pending_socks.write().await.remove(tid) {
                ts.authorized_tunnels.write().await.insert(*tid);
                info!("[{label}] SOCKS tunnel {tid} authorized via SocksReady");
            } else {
                warn!("[{label}] Unexpected SocksReady for tunnel {tid}");
            }
        }
        CommandResponse::ReverseTunnelReady { tunnel_id: tid } => {
            // Client validated the target — now start the reverse listener
            let remote_port = ts.pending_reverse.write().await.remove(tid);
            if let Some(port) = remote_port {
                info!("[{label}] Starting reverse listener on 127.0.0.1:{port} (tunnel {tid})");
                let channels = channels.clone();
                let tid = *tid;
                let label = label.to_string();
                let handle = tokio::spawn(async move {
                    if let Err(e) =
                        reverse_listen_loop(port, tid, channels, ws_tx, &label).await
                    {
                        warn!("[{label}] Reverse listener error: {e}");
                    }
                });
                ts.reverse_listeners
                    .write()
                    .await
                    .insert(tid, handle.abort_handle());
            } else {
                info!("[{label}] Ok response: tunnel_id={tid}");
            }
        }
        CommandResponse::Ok { .. } => {
            info!("[{label}] Ok response");
        }
        CommandResponse::Error { tunnel_id, message } => {
            // Revoke the specific failed tunnel, not all pending
            if let Some(tid) = tunnel_id {
                if ts.pending_socks.write().await.remove(tid) {
                    ts.authorized_tunnels.write().await.remove(tid);
                    info!("[{label}] Revoked failed SOCKS tunnel {tid}");
                }
                ts.pending_reverse.write().await.remove(tid);
            }
            warn!("[{label}] Error response: {message}");
        }
        CommandResponse::Pong { seq } => {
            info!("[{label}] Pong seq={seq}");
        }
    }
}

/// Accept loop for reverse tunnel: binds remote_port, sends ChannelOpen for each connection.
async fn reverse_listen_loop(
    port: u16,
    tunnel_id: u32,
    channels: Arc<ChannelMap>,
    ws_tx: mpsc::Sender<Message>,
    label: &str,
) -> Result<()> {
    let listener = TcpListener::bind(format!("127.0.0.1:{port}")).await?;
    info!("[{label}] Reverse tunnel {tunnel_id} listening on 127.0.0.1:{port}");

    loop {
        let (tcp, peer) = listener.accept().await?;
        let channel_id = channels.alloc_id();
        info!("[{label}] Reverse connection from {peer}, channel {channel_id}");

        // Register data channel and readiness waiter BEFORE sending ChannelOpen
        // so inbound data frames are buffered even if peer responds instantly.
        let (data_tx, data_rx) = mpsc::channel::<Bytes>(256);
        channels.insert_with_tunnel(channel_id, tunnel_id, data_tx).await;
        let ready_rx = channels.wait_ready(channel_id).await;

        let open = WsTextMessage::Control(ControlMessage::ChannelOpen {
            channel_id,
            tunnel_id,
            target: None,
        });
        if let Ok(json) = serde_json::to_string(&open) {
            if ws_tx.send(Message::Text(json)).await.is_err() {
                break Ok(());
            }
        }

        let channels = channels.clone();
        let ws_tx = ws_tx.clone();
        let label = label.to_string();
        tokio::spawn(async move {
            // Timeout readiness wait to prevent indefinite hangs from non-responsive clients
            let ready_result = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                ready_rx,
            )
            .await;
            if ready_result.is_err() || ready_result.unwrap().is_err() {
                warn!("[{label}] Channel {channel_id} ready timeout or signal dropped");
                channels.remove(channel_id).await;
                let close = WsTextMessage::Control(ControlMessage::ChannelClose { channel_id });
                if let Ok(json) = serde_json::to_string(&close) {
                    let _ = ws_tx.send(Message::Text(json)).await;
                }
                return;
            }
            relay_tcp_ws(tcp, channel_id, data_rx, channels, ws_tx, &label).await;
        });
    }
}

/// Handle control messages from client on the server side.
async fn handle_server_control(
    label: &str,
    ctrl: ControlMessage,
    channels: Arc<ChannelMap>,
    authorized_tunnels: &tokio::sync::RwLock<std::collections::HashSet<u32>>,
    ws_tx: mpsc::Sender<Message>,
) {
    match ctrl {
        ControlMessage::ChannelOpen {
            channel_id,
            tunnel_id,
            target,
        } => {
            // Validate channel_id: must be odd (client-originated) and not already in use
            if channel_id % 2 == 0 {
                warn!("[{label}] Rejected ChannelOpen with even channel_id {channel_id}");
                return;
            }
            if channels.has(channel_id).await {
                warn!("[{label}] Rejected ChannelOpen with duplicate channel_id {channel_id}");
                let close =
                    WsTextMessage::Control(ControlMessage::ChannelClose { channel_id });
                if let Ok(json) = serde_json::to_string(&close) {
                    let _ = ws_tx.send(Message::Text(json)).await;
                }
                return;
            }

            // Validate: only allow ChannelOpen for operator-authorized tunnels
            if !authorized_tunnels.read().await.contains(&tunnel_id) {
                warn!(
                    "[{label}] Rejected unsolicited ChannelOpen for tunnel {tunnel_id}, channel {channel_id}"
                );
                let close =
                    WsTextMessage::Control(ControlMessage::ChannelClose { channel_id });
                if let Ok(json) = serde_json::to_string(&close) {
                    let _ = ws_tx.send(Message::Text(json)).await;
                }
                return;
            }

            let target = match target {
                Some(t) => t,
                None => {
                    warn!("[{label}] ChannelOpen without target");
                    return;
                }
            };

            // Reserve the channel_id atomically BEFORE async connect
            // to prevent duplicate ChannelOpen from creating parallel connections.
            let (data_tx, data_rx) = mpsc::channel::<Bytes>(256);
            channels
                .insert_with_tunnel(channel_id, tunnel_id, data_tx)
                .await;

            info!("[{label}] Channel {channel_id} -> connecting to {target}");

            let channels = channels.clone();
            let label = label.to_string();
            tokio::spawn(async move {
                // Bounded connect timeout to prevent indefinite hangs on blackholed targets
                let connect_result = tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    TcpStream::connect(&target),
                )
                .await;
                match connect_result {
                    Ok(Ok(tcp)) => {
                        // Re-check channel is still registered (not revoked during connect)
                        if !channels.has(channel_id).await {
                            warn!("[{label}] Channel {channel_id} revoked during connect, dropping");
                            drop(tcp);
                            return;
                        }

                        info!("[{label}] Channel {channel_id} connected to {target}");

                        let ready = WsTextMessage::Control(ControlMessage::ChannelReady {
                            channel_id,
                        });
                        if let Ok(json) = serde_json::to_string(&ready) {
                            let _ = ws_tx.send(Message::Text(json)).await;
                        }

                        relay_tcp_ws(tcp, channel_id, data_rx, channels, ws_tx.clone(), &label)
                            .await;
                    }
                    Ok(Err(e)) => {
                        warn!("[{label}] Failed to connect to {target}: {e}");
                        channels.remove(channel_id).await;
                        let close =
                            WsTextMessage::Control(ControlMessage::ChannelClose { channel_id });
                        if let Ok(json) = serde_json::to_string(&close) {
                            let _ = ws_tx.send(Message::Text(json)).await;
                        }
                    }
                    Err(_) => {
                        warn!("[{label}] Connect to {target} timed out for channel {channel_id}");
                        channels.remove(channel_id).await;
                        let close =
                            WsTextMessage::Control(ControlMessage::ChannelClose { channel_id });
                        if let Ok(json) = serde_json::to_string(&close) {
                            let _ = ws_tx.send(Message::Text(json)).await;
                        }
                    }
                }
            });
        }
        ControlMessage::ChannelReady { channel_id } => {
            channels.signal_ready(channel_id).await;
            info!("[{label}] Channel {channel_id} ready");
        }
        ControlMessage::ChannelClose { channel_id } => {
            channels.remove(channel_id).await;
            info!("[{label}] Channel {channel_id} closed");
        }
    }
}

/// Bidirectional relay between a TCP stream and a WS channel.
/// `data_rx` must already be registered in `channels` before calling this.
async fn relay_tcp_ws(
    tcp: TcpStream,
    channel_id: u32,
    mut data_rx: mpsc::Receiver<Bytes>,
    channels: Arc<ChannelMap>,
    ws_tx: mpsc::Sender<Message>,
    label: &str,
) {
    let (mut tcp_read, mut tcp_write) = tcp.into_split();

    let ws2tcp = tokio::spawn(async move {
        while let Some(data) = data_rx.recv().await {
            if tcp_write.write_all(&data).await.is_err() {
                break;
            }
        }
        let _ = tcp_write.shutdown().await;
    });

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

    // Notify peer that we're closing (channel stays registered for drain)
    let close = WsTextMessage::Control(ControlMessage::ChannelClose { channel_id });
    if let Ok(json) = serde_json::to_string(&close) {
        let _ = ws_tx.send(Message::Text(json)).await;
    }

    // Grace period: channel stays registered so in-flight frames can still be delivered
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    // Now remove channel routing and force-abort any remaining task
    channels.remove(channel_id).await;
    ws2tcp_abort.abort();
    tcp2ws_abort.abort();
    info!("[{label}] Channel {channel_id} closed");
}

/// Extract (fingerprint, CN) from a client's peer certificate.
/// Fingerprint is hex-encoded SHA-256 of the raw DER certificate (first 16 hex chars).
fn extract_client_identity(
    tls_stream: &tokio_rustls::server::TlsStream<TcpStream>,
) -> (String, String) {
    let (_, server_conn) = tls_stream.get_ref();
    let certs = server_conn.peer_certificates().unwrap_or_default();
    let cert_der = match certs.first() {
        Some(c) => c.as_ref(),
        None => return ("unknown".into(), "unknown".into()),
    };

    // SHA-256 fingerprint of the raw DER certificate
    let digest = ring::digest::digest(&ring::digest::SHA256, cert_der);
    let fingerprint: String = digest.as_ref().iter().map(|b| format!("{b:02x}")).collect();

    let cn = extract_cn_from_der(cert_der).unwrap_or_else(|| "unknown".into());
    (fingerprint, cn)
}

/// Extract the LAST CN from a DER-encoded certificate (minimal ASN.1 parsing).
/// In X.509, issuer DN appears before subject DN, so the last CN OID match
/// corresponds to the subject (leaf) CN, not the issuer (CA) CN.
fn extract_cn_from_der(der: &[u8]) -> Option<String> {
    let cn_oid = [0x55, 0x04, 0x03];
    let mut last_cn: Option<String> = None;
    for i in 0..der.len().saturating_sub(3) {
        if der[i..i + 3] == cn_oid {
            let val_start = i + 3;
            if val_start + 2 <= der.len() {
                let _tag = der[val_start];
                let len = der[val_start + 1] as usize;
                let str_start = val_start + 2;
                if str_start + len <= der.len() {
                    if let Ok(s) = String::from_utf8(der[str_start..str_start + len].to_vec()) {
                        last_cn = Some(s);
                    }
                }
            }
        }
    }
    last_cn
}

/// Read commands from stdin and dispatch to connected clients.
async fn stdin_command_loop(state: Arc<ServerState>) -> Result<()> {
    let stdin = tokio::io::stdin();
    let reader = BufReader::new(stdin);
    let mut lines = reader.lines();

    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        match parts.first().copied() {
            Some("list") => {
                let clients = state.clients.read().await;
                if clients.is_empty() {
                    info!("No connected clients");
                } else {
                    for (fp, handle) in clients.iter() {
                        info!("  - {} [{}]", handle.cn, fp);
                    }
                }
            }
            Some("socks") if parts.len() == 3 => {
                let cn = parts[1];
                let port: u16 = match parts[2].parse() {
                    Ok(p) => p,
                    Err(_) => {
                        warn!("Invalid port: {}", parts[2]);
                        continue;
                    }
                };
                let tunnel_id = state.alloc_tunnel_id();
                // Do NOT authorize yet — wait for client Ok response.
                // Authorization happens in handle_response on success.
                {
                    let clients = state.clients.read().await;
                    if let Some(client) = find_client_in_map(&clients, cn) {
                        // Track as pending so handle_response knows to authorize on Ok
                        client
                            .pending_socks
                            .write()
                            .await
                            .insert(tunnel_id);
                    }
                }
                send_command_to_client(
                    &state,
                    cn,
                    WsTextMessage::Command(Command::Socks { tunnel_id, port }),
                )
                .await;
            }
            Some("reverse") if parts.len() == 4 => {
                let cn = parts[1];
                let remote_port: u16 = match parts[2].parse() {
                    Ok(p) => p,
                    Err(_) => {
                        warn!("Invalid port: {}", parts[2]);
                        continue;
                    }
                };
                let local_target = parts[3].to_string();
                let tunnel_id = state.alloc_tunnel_id();

                // Store pending reverse tunnel so we start the listener on Ok response
                // We need access to the per-client pending_reverse map, but it's inside handle_client.
                // Instead, we use a shared state approach: store in ServerState.
                // For simplicity, we broadcast the reverse command and track the tunnel_id
                // globally. The handle_response for the specific client will pick it up.
                send_command_to_client_with_reverse(
                    &state,
                    cn,
                    tunnel_id,
                    remote_port,
                    local_target,
                )
                .await;
            }
            Some("stop") if parts.len() == 3 => {
                let cn = parts[1];
                let tunnel_id: u32 = match parts[2].parse() {
                    Ok(id) => id,
                    Err(_) => {
                        warn!("Invalid tunnel ID: {}", parts[2]);
                        continue;
                    }
                };
                // Fully revoke: clear all pending + active state for this tunnel
                {
                    let clients = state.clients.read().await;
                    if let Some(client) = find_client_in_map(&clients, cn) {
                        // Clear pending state so late acks cannot resurrect the tunnel
                        client.pending_socks.write().await.remove(&tunnel_id);
                        client.pending_reverse.write().await.remove(&tunnel_id);
                        client.authorized_tunnels.write().await.remove(&tunnel_id);
                        if let Some(handle) =
                            client.reverse_listeners.write().await.remove(&tunnel_id)
                        {
                            handle.abort();
                            info!("Aborted reverse listener for tunnel {tunnel_id}");
                        }
                        let closed = client.channels.close_tunnel(tunnel_id).await;
                        if !closed.is_empty() {
                            info!("Closed {} server-side channels for tunnel {tunnel_id}", closed.len());
                        }
                    }
                }
                send_command_to_client(
                    &state,
                    cn,
                    WsTextMessage::Command(Command::StopTunnel { tunnel_id }),
                )
                .await;
            }
            Some("help") | Some("?") => {
                info!("Commands:");
                info!("  list                                              - List connected clients");
                info!("  socks <client_cn> <port>                          - Start SOCKS5 on client");
                info!("  reverse <client_cn> <remote_port> <local_target>  - Reverse tunnel");
                info!("  stop <client_cn> <tunnel_id>                      - Stop a tunnel");
            }
            _ => {
                warn!("Unknown command. Type 'help' for usage.");
            }
        }
    }

    Ok(())
}

/// Find a client by CN or fingerprint and send a command.
async fn send_command_to_client(state: &ServerState, id: &str, msg: WsTextMessage) {
    let ws_tx = {
        let clients = state.clients.read().await;
        match find_client_in_map(&clients, id) {
            Some(client) => client.ws_tx.clone(),
            None => return,
        }
    };
    if let Ok(json) = serde_json::to_string(&msg) {
        if ws_tx.send(Message::Text(json)).await.is_err() {
            warn!("Failed to send to {id}");
        } else {
            info!("Sent command to {id}");
        }
    }
}

/// Send a ReverseTunnel command and register the pending tunnel_id -> remote_port.
async fn send_command_to_client_with_reverse(
    state: &ServerState,
    id: &str,
    tunnel_id: u32,
    remote_port: u16,
    local_target: String,
) {
    let msg = WsTextMessage::Command(Command::ReverseTunnel {
        tunnel_id,
        remote_port,
        local_target,
    });
    let (ws_tx, pending_reverse) = {
        let clients = state.clients.read().await;
        match find_client_in_map(&clients, id) {
            Some(client) => (client.ws_tx.clone(), client.pending_reverse.clone()),
            None => return,
        }
    };
    pending_reverse.write().await.insert(tunnel_id, remote_port);
    if let Ok(json) = serde_json::to_string(&msg) {
        if ws_tx.send(Message::Text(json)).await.is_err() {
            warn!("Failed to send to {id}");
            pending_reverse.write().await.remove(&tunnel_id);
        } else {
            info!("Sent reverse tunnel command to {id} (tunnel {tunnel_id}, port {remote_port})");
        }
    }
}

/// Look up a client by fingerprint (prefix) or CN. Returns None on ambiguity.
fn find_client_in_map<'a>(
    clients: &'a HashMap<String, ClientHandle>,
    id: &str,
) -> Option<&'a ClientHandle> {
    // Exact fingerprint
    if let Some(handle) = clients.get(id) {
        return Some(handle);
    }
    // Fingerprint prefix
    let fp_matches: Vec<_> = clients
        .iter()
        .filter(|(fp, _)| fp.starts_with(id))
        .collect();
    if fp_matches.len() == 1 {
        return Some(fp_matches[0].1);
    }
    // CN match (reject ambiguous)
    let cn_matches: Vec<_> = clients.values().filter(|h| h.cn == id).collect();
    match cn_matches.len() {
        1 => Some(cn_matches[0]),
        0 => {
            warn!("Client not found: {id}");
            None
        }
        n => {
            warn!("Ambiguous CN '{id}' matches {n} clients. Use fingerprint instead.");
            None
        }
    }
}
