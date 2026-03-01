use crate::cert::CertificateAuthority;
use crate::error::Result;
use rustls::ServerConfig;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

/// Create a `TlsAcceptor` for the given domain using a dynamically generated certificate.
pub async fn make_tls_acceptor(
    ca: &CertificateAuthority,
    domain: &str,
) -> Result<TlsAcceptor> {
    let ck = ca.get_or_create_cert(domain).await?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![ck.cert_der.clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(ck.key_der.clone_key()),
        )?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Connect to an upstream server over TLS and return the stream.
pub async fn connect_tls_upstream(
    host: &str,
    addr: &str,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(addr).await?;

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| crate::error::ProxyError::Other(e.to_string()))?;

    let tls_stream = connector.connect(server_name, tcp).await?;
    Ok(tls_stream)
}
