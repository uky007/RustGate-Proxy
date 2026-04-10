use crate::cert::CertificateAuthority;
use crate::error::{ProxyError, Result};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
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

/// Create a server TLS config that requires mTLS (client certificate verification).
pub fn make_mtls_server_config(
    server_cert_der: CertificateDer<'static>,
    server_key_der: PrivatePkcs8KeyDer<'static>,
    ca_cert_der: CertificateDer<'static>,
) -> Result<Arc<ServerConfig>> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store
        .add(ca_cert_der)
        .map_err(|e| ProxyError::Other(format!("Failed to add CA cert to root store: {e}")))?;

    let client_verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
        .build()
        .map_err(|e| ProxyError::Other(format!("Failed to build client verifier: {e}")))?;

    let config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(
            vec![server_cert_der],
            rustls::pki_types::PrivateKeyDer::Pkcs8(server_key_der),
        )?;

    Ok(Arc::new(config))
}

/// Create a client TLS config for mTLS (presents client cert, verifies server against CA).
pub fn make_mtls_client_config(
    client_cert_der: CertificateDer<'static>,
    client_key_der: PrivatePkcs8KeyDer<'static>,
    ca_cert_der: CertificateDer<'static>,
) -> Result<Arc<rustls::ClientConfig>> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store
        .add(ca_cert_der)
        .map_err(|e| ProxyError::Other(format!("Failed to add CA cert to root store: {e}")))?;

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(
            vec![client_cert_der],
            rustls::pki_types::PrivateKeyDer::Pkcs8(client_key_der),
        )
        .map_err(ProxyError::Tls)?;

    Ok(Arc::new(config))
}
