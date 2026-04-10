use crate::error::Result;
use bytes::Bytes;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;
use tokio_tungstenite::WebSocketStream;

pub type ServerWsStream = WebSocketStream<ServerTlsStream<TcpStream>>;
pub type ClientWsStream = WebSocketStream<ClientTlsStream<TcpStream>>;

/// Accept a WebSocket connection over an already-established mTLS server stream.
pub async fn accept_ws(tls_stream: ServerTlsStream<TcpStream>) -> Result<ServerWsStream> {
    let ws = tokio_tungstenite::accept_async(tls_stream).await?;
    Ok(ws)
}

/// Connect as a WebSocket client over an already-established mTLS client stream.
pub async fn connect_ws(
    tls_stream: ClientTlsStream<TcpStream>,
    url: &str,
) -> Result<ClientWsStream> {
    let (ws, _response) = tokio_tungstenite::client_async(url, tls_stream).await?;
    Ok(ws)
}

/// Internal state protected by a single Mutex to prevent lock-order deadlocks.
struct ChannelState {
    channels: HashMap<u32, mpsc::Sender<Bytes>>,
    ready_signals: HashMap<u32, oneshot::Sender<()>>,
    tunnel_channels: HashMap<u32, HashSet<u32>>,
}

/// Manages multiplexed data channels over a single WebSocket connection.
///
/// Each channel has a unique u32 ID. Client-originated channels use odd IDs,
/// server-originated channels use even IDs to avoid collisions.
pub struct ChannelMap {
    state: Mutex<ChannelState>,
    next_id: AtomicU32,
}

impl ChannelMap {
    /// Create a new ChannelMap. `start_id` should be 1 for clients (odd), 2 for servers (even).
    pub fn new(start_id: u32) -> Self {
        Self {
            state: Mutex::new(ChannelState {
                channels: HashMap::new(),
                ready_signals: HashMap::new(),
                tunnel_channels: HashMap::new(),
            }),
            next_id: AtomicU32::new(start_id),
        }
    }

    /// Allocate the next channel ID (increments by 2 to maintain odd/even parity).
    pub fn alloc_id(&self) -> u32 {
        self.next_id.fetch_add(2, Ordering::Relaxed)
    }

    /// Check if a channel_id is already registered.
    pub async fn has(&self, channel_id: u32) -> bool {
        self.state.lock().await.channels.contains_key(&channel_id)
    }

    /// Register a channel with its sender.
    pub async fn insert(&self, channel_id: u32, sender: mpsc::Sender<Bytes>) {
        self.state.lock().await.channels.insert(channel_id, sender);
    }

    /// Register a channel and associate it with a tunnel_id for lifecycle tracking.
    pub async fn insert_with_tunnel(
        &self,
        channel_id: u32,
        tunnel_id: u32,
        sender: mpsc::Sender<Bytes>,
    ) {
        let mut s = self.state.lock().await;
        s.channels.insert(channel_id, sender);
        s.tunnel_channels
            .entry(tunnel_id)
            .or_default()
            .insert(channel_id);
    }

    /// Route data to a channel. Returns false if channel not found or closed.
    /// Uses try_send so the shared WS reader never blocks on one slow channel.
    /// If the buffer is full, the channel is closed cleanly (removed + returns false).
    pub async fn send(&self, channel_id: u32, data: Bytes) -> bool {
        let tx = {
            let s = self.state.lock().await;
            s.channels.get(&channel_id).cloned()
        };
        if let Some(tx) = tx {
            match tx.try_send(data) {
                Ok(()) => true,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    // Channel congested — close it to preserve session liveness.
                    // The relay task will see the sender drop and clean up.
                    self.remove(channel_id).await;
                    false
                }
                Err(mpsc::error::TrySendError::Closed(_)) => false,
            }
        } else {
            false
        }
    }

    /// Remove a channel and cancel any pending readiness waiter.
    pub async fn remove(&self, channel_id: u32) {
        let mut s = self.state.lock().await;
        s.channels.remove(&channel_id);
        s.ready_signals.remove(&channel_id);
        for set in s.tunnel_channels.values_mut() {
            set.remove(&channel_id);
        }
    }

    /// Close ALL channels — used on session disconnect.
    pub async fn close_all(&self) {
        let mut s = self.state.lock().await;
        s.channels.clear();
        s.ready_signals.clear();
        s.tunnel_channels.clear();
    }

    /// Close all channels belonging to a tunnel. Returns the channel IDs that were removed.
    pub async fn close_tunnel(&self, tunnel_id: u32) -> Vec<u32> {
        let mut s = self.state.lock().await;
        let channel_ids: Vec<u32> = s
            .tunnel_channels
            .remove(&tunnel_id)
            .unwrap_or_default()
            .into_iter()
            .collect();
        for &id in &channel_ids {
            s.channels.remove(&id);
            s.ready_signals.remove(&id);
        }
        channel_ids
    }

    /// Register a readiness waiter for a channel.
    pub async fn wait_ready(&self, channel_id: u32) -> oneshot::Receiver<()> {
        let (tx, rx) = oneshot::channel();
        self.state
            .lock()
            .await
            .ready_signals
            .insert(channel_id, tx);
        rx
    }

    /// Signal that a channel is ready. Returns true if a waiter was notified.
    pub async fn signal_ready(&self, channel_id: u32) -> bool {
        if let Some(tx) = self.state.lock().await.ready_signals.remove(&channel_id) {
            tx.send(()).is_ok()
        } else {
            false
        }
    }
}
