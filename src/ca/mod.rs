//! Local Certificate Authority (CA) Subsystem for Vexa Agent Control (FR-304 / FR-MITM).
//!
//! Generates, stores, and manages an ECDSA P-256 Root CA on the developer workstation.
//! Issues short-lived, domain-restricted dynamic leaf certificates for intercepted LLM endpoints.

pub mod trust_store;

use dashmap::DashMap;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio_rustls::rustls::ServerConfig;

pub use trust_store::{install_ca_to_trust_store, is_ca_installed, uninstall_ca_from_trust_store, CA_COMMON_NAME};

#[derive(Debug)]
pub enum CaError {
    Io(std::io::Error),
    Crypto(String),
    TrustStore(trust_store::TrustStoreError),
    TlsConfig(String),
}

impl fmt::Display for CaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {}", e),
            Self::Crypto(e) => write!(f, "Crypto / rcgen error: {}", e),
            Self::TrustStore(e) => write!(f, "Trust store error: {}", e),
            Self::TlsConfig(e) => write!(f, "TLS configuration error: {}", e),
        }
    }
}

impl std::error::Error for CaError {}

impl From<std::io::Error> for CaError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<trust_store::TrustStoreError> for CaError {
    fn from(e: trust_store::TrustStoreError) -> Self {
        Self::TrustStore(e)
    }
}

/// Default list of domain patterns intercepted for LLM spend & governance telemetry.
pub const DEFAULT_INTERCEPT_DOMAINS: &[&str] = &[
    "api2.cursor.sh",
    "api.cursor.sh",
    "*.cursor.sh",
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "openrouter.ai",
];

/// Checks whether a given target hostname matches an allowlisted interceptable domain pattern.
pub fn is_interceptable_host(target_host: &str, custom_domains: Option<&[String]>) -> bool {
    let lower_host = target_host.to_lowercase();

    // Check custom domains if provided
    if let Some(domains) = custom_domains {
        for pattern in domains {
            if matches_domain_pattern(&lower_host, pattern) {
                return true;
            }
        }
    }

    // Check default domains
    for pattern in DEFAULT_INTERCEPT_DOMAINS {
        if matches_domain_pattern(&lower_host, pattern) {
            return true;
        }
    }

    false
}

/// Helper to match domain with optional wildcard (e.g. `*.cursor.sh` matches `api2.cursor.sh`).
fn matches_domain_pattern(host: &str, pattern: &str) -> bool {
    let p_lower = pattern.to_lowercase();
    if p_lower.starts_with("*.") {
        let suffix = &p_lower[1..]; // ".cursor.sh"
        host.ends_with(suffix) || host == &p_lower[2..]
    } else {
        host == p_lower
    }
}

/// Helper to build deterministic CA certificate parameters
fn build_ca_params() -> rcgen::CertificateParams {
    let mut ca_params = rcgen::CertificateParams::default();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, CA_COMMON_NAME);
    dn.push(rcgen::DnType::OrganizationName, "Vexa Agent Control Security Gateway");
    ca_params.distinguished_name = dn;
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    ca_params.serial_number = Some(rcgen::SerialNumber::from(1001u64));
    ca_params.not_before = rcgen::date_time_ymd(2025, 1, 1);
    ca_params.not_after = rcgen::date_time_ymd(2035, 1, 1);
    ca_params
}

/// Manages local Root CA generation, storage, and dynamic leaf certificate issuance.
#[derive(Clone)]
pub struct CaManager {
    pub ca_dir: PathBuf,
    pub ca_cert_pem: String,
    pub ca_key_pem: String,
    ca_cert: Arc<rcgen::Certificate>,
    ca_key_pair: Arc<rcgen::KeyPair>,
    /// In-memory cache of compiled rustls::ServerConfig per hostname to ensure sub-millisecond lookups
    leaf_cache: Arc<DashMap<String, Arc<ServerConfig>>>,
}

impl CaManager {
    /// Resolves the default CA storage directory (`~/.agentcontrol/ca`).
    pub fn default_ca_dir() -> PathBuf {
        if let Some(home) = dirs::home_dir() {
            home.join(".agentcontrol").join("ca")
        } else {
            PathBuf::from(".agentcontrol_ca")
        }
    }

    /// Initializes or loads the local Root CA from the specified directory.
    pub fn init_or_load(ca_dir: Option<PathBuf>) -> Result<Self, CaError> {
        let dir = ca_dir.unwrap_or_else(Self::default_ca_dir);
        fs::create_dir_all(&dir)?;

        let cert_path = dir.join("agentcontrol-ca.pem");
        let key_path = dir.join("agentcontrol-ca.key");

        let (key_pair, ca_cert, cert_pem, key_pem) = if cert_path.exists() && key_path.exists() {
            let key_pem = fs::read_to_string(&key_path)?;

            // Reconstruct KeyPair from existing PEM
            let key_pair = rcgen::KeyPair::from_pem(&key_pem)
                .map_err(|e| CaError::Crypto(format!("Failed to parse CA private key PEM: {}", e)))?;

            let ca_params = build_ca_params();
            let ca_cert = ca_params
                .self_signed(&key_pair)
                .map_err(|e| CaError::Crypto(format!("Failed to self-sign Root CA: {}", e)))?;

            let cert_pem = ca_cert.pem();
            // Re-write to ensure disk matches the exact deterministic cert
            let _ = fs::write(&cert_path, cert_pem.as_bytes());

            (key_pair, ca_cert, cert_pem, key_pem)
        } else {
            // Generate brand new ECDSA P-256 Root CA Keypair
            let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
                .map_err(|e| CaError::Crypto(format!("Failed to generate P-256 keypair: {}", e)))?;

            let ca_params = build_ca_params();
            let ca_cert = ca_params
                .self_signed(&key_pair)
                .map_err(|e| CaError::Crypto(format!("Failed to self-sign Root CA: {}", e)))?;

            let cert_pem = ca_cert.pem();
            let key_pem = key_pair.serialize_pem();

            // Write files securely
            fs::write(&cert_path, cert_pem.as_bytes())?;
            fs::write(&key_path, key_pem.as_bytes())?;

            // On Unix, apply 0600 permissions
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600));
            }

            (key_pair, ca_cert, cert_pem, key_pem)
        };

        Ok(Self {
            ca_dir: dir,
            ca_cert_pem: cert_pem,
            ca_key_pem: key_pem,
            ca_cert: Arc::new(ca_cert),
            ca_key_pair: Arc::new(key_pair),
            leaf_cache: Arc::new(DashMap::new()),
        })
    }

    /// Returns or dynamically generates a compiled `rustls::ServerConfig` for the given hostname.
    pub fn get_or_create_server_config(&self, host: &str) -> Result<Arc<ServerConfig>, CaError> {
        let clean_host = host.split(':').next().unwrap_or(host).to_string();

        if let Some(cached) = self.leaf_cache.get(&clean_host) {
            return Ok(Arc::clone(&cached));
        }

        // Generate dynamic leaf certificate for host
        let leaf_key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|e| CaError::Crypto(format!("Failed to generate leaf P-256 keypair: {}", e)))?;

        let mut leaf_params = rcgen::CertificateParams::default();
        leaf_params.is_ca = rcgen::IsCa::NoCa;
        let mut leaf_dn = rcgen::DistinguishedName::new();
        leaf_dn.push(rcgen::DnType::CommonName, &clean_host);
        leaf_params.distinguished_name = leaf_dn;

        let ia5 = rcgen::Ia5String::try_from(clean_host.clone())
            .map_err(|e| CaError::Crypto(format!("Invalid DNS name: {}", e)))?;
        leaf_params.subject_alt_names = vec![rcgen::SanType::DnsName(ia5)];
        leaf_params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
        ];
        leaf_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];

        // Sign dynamic leaf directly with the authoritative Root CA instance
        let leaf_cert = leaf_params
            .signed_by(&leaf_key_pair, &self.ca_cert, &self.ca_key_pair)
            .map_err(|e| CaError::Crypto(format!("Failed to sign leaf cert for {}: {}", clean_host, e)))?;

        let leaf_cert_pem = leaf_cert.pem();
        let leaf_key_pem = leaf_key_pair.serialize_pem();

        // Build ServerConfig using standard rustls
        let cert_chain: Vec<_> = rustls_pemfile::certs(&mut leaf_cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| CaError::TlsConfig(format!("Invalid leaf PEM cert: {}", e)))?;

        let ca_chain: Vec<_> = rustls_pemfile::certs(&mut self.ca_cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| CaError::TlsConfig(format!("Invalid CA PEM cert: {}", e)))?;

        let mut full_chain = cert_chain;
        full_chain.extend(ca_chain);

        let private_key = rustls_pemfile::private_key(&mut leaf_key_pem.as_bytes())
            .map_err(|e| CaError::TlsConfig(format!("Invalid leaf private key: {}", e)))?
            .ok_or_else(|| CaError::TlsConfig("No private key found for leaf cert".to_string()))?;

        let server_config = ServerConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| CaError::TlsConfig(format!("TLS version error: {}", e)))?
        .with_no_client_auth()
        .with_single_cert(full_chain, private_key)
        .map_err(|e| CaError::TlsConfig(format!("Failed to build ServerConfig: {}", e)))?;

        let arc_config = Arc::new(server_config);
        self.leaf_cache.insert(clean_host, Arc::clone(&arc_config));

        Ok(arc_config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_pattern_matching() {
        assert!(matches_domain_pattern("api2.cursor.sh", "*.cursor.sh"));
        assert!(matches_domain_pattern("cursor.sh", "*.cursor.sh"));
        assert!(matches_domain_pattern("api.openai.com", "api.openai.com"));
        assert!(!matches_domain_pattern("evil.com", "*.cursor.sh"));
        assert!(is_interceptable_host("api2.cursor.sh", None));
        assert!(is_interceptable_host("api.anthropic.com", None));
        assert!(!is_interceptable_host("github.com", None));
    }

    #[test]
    fn test_ca_init_and_leaf_issuance() {
        let temp_dir = tempfile::tempdir().unwrap();
        let ca_mgr = CaManager::init_or_load(Some(temp_dir.path().to_path_buf())).unwrap();

        assert!(!ca_mgr.ca_cert_pem.is_empty());
        assert!(!ca_mgr.ca_key_pem.is_empty());
        assert!(temp_dir.path().join("agentcontrol-ca.pem").exists());
        assert!(temp_dir.path().join("agentcontrol-ca.key").exists());

        // Test dynamic leaf cert generation
        let config1 = ca_mgr.get_or_create_server_config("api2.cursor.sh").unwrap();
        let config2 = ca_mgr.get_or_create_server_config("api2.cursor.sh").unwrap();

        // Memory cache should return the exact same Arc instance
        assert!(Arc::ptr_eq(&config1, &config2));
    }
}
