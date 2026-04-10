use serde::{Deserialize, Serialize};

/// Top-level WebSocket text message envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WsTextMessage {
    Command(Command),
    Response(CommandResponse),
    Control(ControlMessage),
}

/// Command sent from server to client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Command {
    /// Start a SOCKS5 proxy listener on the client.
    Socks { tunnel_id: u32, port: u16 },
    /// Create a reverse TCP tunnel: server binds remote_port,
    /// forwards connections back to client's local_target.
    ReverseTunnel {
        tunnel_id: u32,
        remote_port: u16,
        local_target: String,
    },
    /// Ping/keepalive.
    Ping { seq: u64 },
    /// Request client to shut down a specific tunnel.
    StopTunnel { tunnel_id: u32 },
}

/// Response from client to server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CommandResponse {
    Ok {
        tunnel_id: Option<u32>,
        message: Option<String>,
    },
    /// SOCKS listener successfully bound — authorizes the tunnel on the server.
    SocksReady {
        tunnel_id: u32,
    },
    /// Reverse tunnel target validated (client confirmed local_target is reachable).
    ReverseTunnelReady {
        tunnel_id: u32,
    },
    Error {
        tunnel_id: Option<u32>,
        message: String,
    },
    Pong {
        seq: u64,
    },
}

/// Control messages for channel lifecycle (sent by both sides).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlMessage {
    /// A new data channel has been opened.
    ChannelOpen {
        channel_id: u32,
        tunnel_id: u32,
        /// For SOCKS: the destination the remote side should connect to.
        target: Option<String>,
    },
    /// The channel is ready for data transfer.
    ChannelReady { channel_id: u32 },
    /// The channel has been closed.
    ChannelClose { channel_id: u32 },
}

/// Frame tunnel data with a 4-byte channel ID header for binary WS messages.
pub fn frame_tunnel_data(channel_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&channel_id.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// Parse a binary WS message into (channel_id, payload).
pub fn parse_tunnel_data(data: &[u8]) -> Option<(u32, &[u8])> {
    if data.len() < 4 {
        return None;
    }
    let channel_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    Some((channel_id, &data[4..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_serde_roundtrip() {
        let msg = WsTextMessage::Command(Command::Socks { tunnel_id: 1, port: 1080 });
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: WsTextMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            WsTextMessage::Command(Command::Socks { tunnel_id, port }) => {
                assert_eq!(tunnel_id, 1);
                assert_eq!(port, 1080);
            }
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn test_response_serde_roundtrip() {
        let msg = WsTextMessage::Response(CommandResponse::Ok {
            tunnel_id: Some(1),
            message: None,
        });
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: WsTextMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            WsTextMessage::Response(CommandResponse::Ok { tunnel_id, .. }) => {
                assert_eq!(tunnel_id, Some(1));
            }
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn test_control_serde_roundtrip() {
        let msg = WsTextMessage::Control(ControlMessage::ChannelOpen {
            channel_id: 3,
            tunnel_id: 1,
            target: Some("example.com:443".into()),
        });
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: WsTextMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            WsTextMessage::Control(ControlMessage::ChannelOpen {
                channel_id,
                tunnel_id,
                target,
            }) => {
                assert_eq!(channel_id, 3);
                assert_eq!(tunnel_id, 1);
                assert_eq!(target.as_deref(), Some("example.com:443"));
            }
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn test_frame_parse_roundtrip() {
        let data = b"hello world";
        let framed = frame_tunnel_data(42, data);
        let (channel_id, payload) = parse_tunnel_data(&framed).unwrap();
        assert_eq!(channel_id, 42);
        assert_eq!(payload, data);
    }

    #[test]
    fn test_parse_tunnel_data_too_short() {
        assert!(parse_tunnel_data(&[0, 1, 2]).is_none());
        assert!(parse_tunnel_data(&[]).is_none());
    }
}
