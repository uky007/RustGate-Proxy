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

        let cert_exists = cert_path.exists();
        let key_exists = key_path.exists();

        // Partial CA state is fatal — prevent silent rekey
        if cert_exists != key_exists {
            return Err(ProxyError::Other(format!(
                "Partial CA state in {}: {} exists but {} is missing. \
                 Restore the missing file or remove both to reinitialize.",
                dir.display(),
                if cert_exists { "ca.pem" } else { "ca-key.pem" },
                if cert_exists { "ca-key.pem" } else { "ca.pem" },
            )));
        }

        let (ca_cert, ca_key) = if cert_exists {
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

        // Verify the private key matches the certificate's public key.
        // Re-sign with the loaded key and check that the public key in
        // the resulting cert matches the original.
        let cert = params.self_signed(&key)?;

        let original_der = Self::pem_to_der(&cert_pem)?;
        let regenerated_der = cert.der().to_vec();
        let original_spki = Self::extract_spki(&original_der)?;
        let regenerated_spki = Self::extract_spki(&regenerated_der)?;
        if original_spki != regenerated_spki {
            return Err(ProxyError::Other(
                "CA certificate and private key do not match: \
                 public key in ca.pem differs from ca-key.pem"
                    .into(),
            ));
        }

        Ok((cert, key))
    }

    /// Extract the raw PEM body into DER bytes.
    fn pem_to_der(pem_str: &str) -> Result<Vec<u8>> {
        let mut reader = std::io::BufReader::new(pem_str.as_bytes());
        let certs = rustls_pemfile::certs(&mut reader)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        certs
            .into_iter()
            .next()
            .map(|c| c.to_vec())
            .ok_or_else(|| ProxyError::Other("No certificate found in PEM".into()))
    }

    /// Extract SubjectPublicKeyInfo bytes from a DER-encoded X.509 certificate.
    /// Uses minimal ASN.1 parsing: Certificate -> TBSCertificate -> SPKI (7th field).
    fn extract_spki(der: &[u8]) -> Result<Vec<u8>> {
        // Certificate is a SEQUENCE containing TBSCertificate, signatureAlgorithm, signature
        let tbs = Self::asn1_sequence_contents(der)?;
        // TBSCertificate is a SEQUENCE: version, serialNumber, signature, issuer,
        //   validity, subject, subjectPublicKeyInfo, ...
        let tbs_inner = Self::asn1_sequence_contents(tbs)?;

        let mut pos = 0;
        // Skip 6 fields: version (explicit tag [0]), serial, sigAlg, issuer, validity, subject
        for i in 0..6 {
            if pos >= tbs_inner.len() {
                return Err(ProxyError::Other(
                    format!("Unexpected end of TBSCertificate at field {i}"),
                ));
            }
            let (_, field_len) = Self::asn1_read_tag_and_length(&tbs_inner[pos..])?;
            pos += field_len;
        }

        // The 7th field is SubjectPublicKeyInfo
        if pos >= tbs_inner.len() {
            return Err(ProxyError::Other(
                "SubjectPublicKeyInfo not found in certificate".into(),
            ));
        }
        let (_, spki_len) = Self::asn1_read_tag_and_length(&tbs_inner[pos..])?;
        Ok(tbs_inner[pos..pos + spki_len].to_vec())
    }

    /// Parse the contents (value bytes) of an ASN.1 SEQUENCE.
    fn asn1_sequence_contents(data: &[u8]) -> Result<&[u8]> {
        if data.is_empty() || (data[0] & 0x1f) != 0x10 {
            return Err(ProxyError::Other("Expected ASN.1 SEQUENCE".into()));
        }
        let (header_len, total_len) = Self::asn1_read_tag_and_length(data)?;
        let content_len = total_len - header_len;
        Ok(&data[header_len..header_len + content_len])
    }

    /// Read ASN.1 tag and length, returning (header_size, total_element_size).
    fn asn1_read_tag_and_length(data: &[u8]) -> Result<(usize, usize)> {
        if data.len() < 2 {
            return Err(ProxyError::Other("ASN.1 data too short".into()));
        }
        let mut pos = 1; // skip tag byte
        let length_byte = data[pos];
        pos += 1;

        let content_len = if length_byte & 0x80 == 0 {
            length_byte as usize
        } else {
            let num_bytes = (length_byte & 0x7f) as usize;
            if pos + num_bytes > data.len() {
                return Err(ProxyError::Other("ASN.1 length overflow".into()));
            }
            let mut len = 0usize;
            for &b in &data[pos..pos + num_bytes] {
                len = (len << 8) | b as usize;
            }
            pos += num_bytes;
            len
        };

        let total_len = pos + content_len;
        if total_len > data.len() {
            return Err(ProxyError::Other(
                "ASN.1 element extends beyond input data".into(),
            ));
        }

        Ok((pos, total_len))
    }

    /// Generate a client certificate signed by this CA (EKU: ClientAuth).
    /// Returns (cert_pem, key_pem) as Strings.
    pub fn generate_client_cert(&self, cn: &str) -> Result<(String, String)> {
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        dn.push(DnType::OrganizationName, "RustGate");
        params.distinguished_name = dn;
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];

        let key = KeyPair::generate()?;
        let cert = params.signed_by(&key, &self.ca_cert, &self.ca_key)?;

        Ok((cert.pem(), key.serialize_pem()))
    }

    /// Generate a server certificate signed by this CA (EKU: ServerAuth).
    pub fn generate_server_cert(&self, host: &str) -> Result<CertifiedKey> {
        let mut params = CertificateParams::new(vec![host.to_string()])?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        params.distinguished_name = dn;
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];

        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            params.subject_alt_names = vec![SanType::IpAddress(ip)];
        }

        let key = KeyPair::generate()?;
        let cert = params.signed_by(&key, &self.ca_cert, &self.ca_key)?;

        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivatePkcs8KeyDer::from(key.serialize_der());
        Ok(CertifiedKey { cert_der, key_der })
    }

    /// Return the CA certificate in DER format (for building RootCertStore).
    pub fn ca_cert_der(&self) -> CertificateDer<'static> {
        CertificateDer::from(self.ca_cert.der().to_vec())
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
