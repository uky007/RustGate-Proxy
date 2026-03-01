use crate::error::{ProxyError, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
    SanType,
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info};

/// Holds a certificate and its private key for TLS.
pub struct CertifiedKey {
    pub cert_der: CertificateDer<'static>,
    pub key_der: PrivatePkcs8KeyDer<'static>,
}

/// Manages the root CA and generates per-domain certificates.
pub struct CertificateAuthority {
    ca_cert: rcgen::Certificate,
    ca_key: KeyPair,
    cache: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

impl CertificateAuthority {
    /// Load or create a CA certificate. Stores files under `~/.rustgate/`.
    pub async fn new() -> Result<Self> {
        Self::with_dir(Self::ca_dir()?).await
    }

    /// Load or create a CA certificate in the specified directory.
    pub async fn with_dir(dir: PathBuf) -> Result<Self> {
        tokio::fs::create_dir_all(&dir).await?;

        let cert_path = dir.join("ca.pem");
        let key_path = dir.join("ca-key.pem");

        let (ca_cert, ca_key) = if cert_path.exists() && key_path.exists() {
            info!("Loading existing CA certificate from {}", dir.display());
            Self::load_ca(&cert_path, &key_path).await?
        } else {
            info!("Generating new CA certificate in {}", dir.display());
            let (cert, key) = Self::generate_ca()?;
            Self::save_ca(&cert, &key, &cert_path, &key_path).await?;
            (cert, key)
        };

        Ok(Self {
            ca_cert,
            ca_key,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// Return the path to the CA PEM file for users to install.
    pub fn ca_cert_path() -> Result<PathBuf> {
        Ok(Self::ca_dir()?.join("ca.pem"))
    }

    /// Generate a fake certificate for the given domain, signed by the CA.
    pub async fn get_or_create_cert(&self, domain: &str) -> Result<Arc<CertifiedKey>> {
        {
            let cache = self.cache.lock().await;
            if let Some(ck) = cache.get(domain) {
                debug!("Using cached certificate for {domain}");
                return Ok(ck.clone());
            }
        }

        debug!("Generating certificate for {domain}");
        let ck = self.generate_domain_cert(domain)?;
        let ck = Arc::new(ck);

        {
            let mut cache = self.cache.lock().await;
            cache.insert(domain.to_string(), ck.clone());
        }

        Ok(ck)
    }

    fn ca_dir() -> Result<PathBuf> {
        let home = std::env::var("HOME")
            .map_err(|_| ProxyError::Other("HOME environment variable not set".into()))?;
        Ok(PathBuf::from(home).join(".rustgate"))
    }

    fn generate_ca() -> Result<(rcgen::Certificate, KeyPair)> {
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "RustGate CA");
        dn.push(DnType::OrganizationName, "RustGate");
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];

        let key = KeyPair::generate()?;
        let cert = params.self_signed(&key)?;
        Ok((cert, key))
    }

    async fn save_ca(
        cert: &rcgen::Certificate,
        key: &KeyPair,
        cert_path: &PathBuf,
        key_path: &PathBuf,
    ) -> Result<()> {
        tokio::fs::write(cert_path, cert.pem()).await?;
        tokio::fs::write(key_path, key.serialize_pem()).await?;

        // Restrict private key to owner-only access (0600)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            tokio::fs::set_permissions(key_path, perms).await?;
        }

        Ok(())
    }

    async fn load_ca(
        cert_path: &PathBuf,
        key_path: &PathBuf,
    ) -> Result<(rcgen::Certificate, KeyPair)> {
        let key_pem = tokio::fs::read_to_string(key_path).await?;
        let key = KeyPair::from_pem(&key_pem)?;

        let cert_pem = tokio::fs::read_to_string(cert_path).await?;
        let params = CertificateParams::from_ca_cert_pem(&cert_pem)?;
        let cert = params.self_signed(&key)?;

        Ok((cert, key))
    }

    fn generate_domain_cert(&self, domain: &str) -> Result<CertifiedKey> {
        let mut params = CertificateParams::new(vec![domain.to_string()])?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, domain);
        params.distinguished_name = dn;

        // SAN is already set by CertificateParams::new
        // Override for IP addresses
        if let Ok(ip) = domain.parse::<std::net::IpAddr>() {
            params.subject_alt_names = vec![SanType::IpAddress(ip)];
        }

        let key = KeyPair::generate()?;
        let cert = params.signed_by(&key, &self.ca_cert, &self.ca_key)?;

        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivatePkcs8KeyDer::from(key.serialize_der());

        Ok(CertifiedKey { cert_der, key_der })
    }
}
