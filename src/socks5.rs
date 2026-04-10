use crate::error::{ProxyError, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::debug;

const SOCKS5_VERSION: u8 = 0x05;
const AUTH_NONE: u8 = 0x00;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const REPLY_SUCCESS: u8 = 0x00;
const REPLY_GENERAL_FAILURE: u8 = 0x01;
const REPLY_CMD_NOT_SUPPORTED: u8 = 0x07;

/// Parsed SOCKS5 CONNECT request.
pub struct Socks5Request {
    pub target_addr: String,
}

/// A minimal SOCKS5 listener that only supports the CONNECT command.
pub struct Socks5Listener {
    listener: TcpListener,
    pub tunnel_id: u32,
}

impl Socks5Listener {
    pub async fn bind(addr: &str, tunnel_id: u32) -> Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self {
            listener,
            tunnel_id,
        })
    }

    /// Accept a raw TCP connection (no handshake — caller handles it per-connection).
    pub async fn accept_raw(&self) -> Result<TcpStream> {
        let (stream, peer) = self.listener.accept().await?;
        debug!("SOCKS5 connection from {peer}");
        Ok(stream)
    }

    /// Accept one SOCKS5 connection, perform handshake, return the stream and target.
    pub async fn accept(&self) -> Result<(TcpStream, Socks5Request)> {
        let (stream, peer) = self.listener.accept().await?;
        debug!("SOCKS5 connection from {peer}");
        socks5_handshake(stream).await
    }
}

/// Perform SOCKS5 server-side handshake. Returns the TCP stream and CONNECT target.
pub async fn socks5_handshake(mut stream: TcpStream) -> Result<(TcpStream, Socks5Request)> {
    // 1. Method selection: [VER][NMETHODS][METHODS...]
    let ver = stream.read_u8().await?;
    if ver != SOCKS5_VERSION {
        return Err(ProxyError::Protocol(format!(
            "SOCKS: expected version 5, got {ver}"
        )));
    }
    let nmethods = stream.read_u8().await? as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    if !methods.contains(&AUTH_NONE) {
        // No acceptable auth method
        stream.write_all(&[SOCKS5_VERSION, 0xFF]).await?;
        return Err(ProxyError::Protocol(
            "SOCKS: no acceptable auth method".into(),
        ));
    }
    // Reply: no auth required
    stream.write_all(&[SOCKS5_VERSION, AUTH_NONE]).await?;

    // 2. Request: [VER][CMD][RSV][ATYP][ADDR][PORT]
    let ver = stream.read_u8().await?;
    if ver != SOCKS5_VERSION {
        return Err(ProxyError::Protocol(format!(
            "SOCKS: expected version 5 in request, got {ver}"
        )));
    }
    let cmd = stream.read_u8().await?;
    let _rsv = stream.read_u8().await?;

    if cmd != CMD_CONNECT {
        // Reply with "command not supported"
        stream
            .write_all(&[SOCKS5_VERSION, REPLY_CMD_NOT_SUPPORTED, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
            .await?;
        return Err(ProxyError::Protocol(format!(
            "SOCKS: unsupported command {cmd}"
        )));
    }

    let atyp = stream.read_u8().await?;
    let host = match atyp {
        ATYP_IPV4 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
        }
        ATYP_DOMAIN => {
            let len = stream.read_u8().await? as usize;
            let mut domain = vec![0u8; len];
            stream.read_exact(&mut domain).await?;
            String::from_utf8(domain)
                .map_err(|e| ProxyError::Protocol(format!("SOCKS: invalid domain: {e}")))?
        }
        ATYP_IPV6 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            let segments: Vec<String> = addr
                .chunks(2)
                .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
                .collect();
            format!("[{}]", segments.join(":"))
        }
        _ => {
            stream
                .write_all(&[SOCKS5_VERSION, REPLY_GENERAL_FAILURE, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
                .await?;
            return Err(ProxyError::Protocol(format!(
                "SOCKS: unsupported address type {atyp}"
            )));
        }
    };

    let port = stream.read_u16().await?;
    let target_addr = format!("{host}:{port}");
    debug!("SOCKS5 CONNECT to {target_addr}");

    Ok((stream, Socks5Request { target_addr }))
}

/// Send the SOCKS5 success reply after the remote side is ready.
pub async fn send_socks5_success(stream: &mut TcpStream) -> Result<()> {
    stream
        .write_all(&[SOCKS5_VERSION, REPLY_SUCCESS, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

    #[tokio::test]
    async fn test_socks5_connect_ipv4() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            // Method selection: version 5, 1 method, no auth
            stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut resp = [0u8; 2];
            stream.read_exact(&mut resp).await.unwrap();
            assert_eq!(resp, [0x05, 0x00]);

            // CONNECT to 93.184.216.34:80 (example.com)
            stream
                .write_all(&[0x05, 0x01, 0x00, 0x01, 93, 184, 216, 34, 0x00, 0x50])
                .await
                .unwrap();
            let mut resp = [0u8; 10];
            stream.read_exact(&mut resp).await.unwrap();
            assert_eq!(resp[0], 0x05); // version
            assert_eq!(resp[1], 0x00); // success
        });

        let (stream, _peer) = listener.accept().await.unwrap();
        let (mut stream, req) = socks5_handshake(stream).await.unwrap();
        assert_eq!(req.target_addr, "93.184.216.34:80");
        send_socks5_success(&mut stream).await.unwrap();

        client.await.unwrap();
    }

    #[tokio::test]
    async fn test_socks5_connect_domain() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut resp = [0u8; 2];
            stream.read_exact(&mut resp).await.unwrap();

            // CONNECT to example.com:443 (domain)
            let domain = b"example.com";
            let mut req = vec![0x05, 0x01, 0x00, 0x03, domain.len() as u8];
            req.extend_from_slice(domain);
            req.extend_from_slice(&443u16.to_be_bytes());
            stream.write_all(&req).await.unwrap();

            let mut resp = [0u8; 10];
            stream.read_exact(&mut resp).await.unwrap();
            assert_eq!(resp[1], 0x00);
        });

        let (stream, _peer) = listener.accept().await.unwrap();
        let (mut stream, req) = socks5_handshake(stream).await.unwrap();
        assert_eq!(req.target_addr, "example.com:443");
        send_socks5_success(&mut stream).await.unwrap();

        client.await.unwrap();
    }
}
