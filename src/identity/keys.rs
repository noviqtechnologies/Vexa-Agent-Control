//! Cryptographic identity keys and secure OS storage.
//! Manages dual-key generation: Ed25519 (Identity/Proof) + ECDSA P-256 (GCP mTLS CSR).

use ed25519_dalek::{SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum KeyError {
    Io(std::io::Error),
    Crypto(String),
    AccessDenied(String),
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyError::Io(e) => write!(f, "IO error: {}", e),
            KeyError::Crypto(msg) => write!(f, "Crypto error: {}", msg),
            KeyError::AccessDenied(msg) => write!(f, "Storage access denied: {}", msg),
        }
    }
}

impl std::error::Error for KeyError {}

impl From<std::io::Error> for KeyError {
    fn from(err: std::io::Error) -> Self {
        KeyError::Io(err)
    }
}

pub struct KeyPairBundle {
    pub ed25519_signing_key: Ed25519SigningKey,
    pub ed25519_public_bytes: [u8; 32],
    pub ed25519_fingerprint: String,
    pub p256_raw_key_bytes: Vec<u8>,
    pub p256_key_pem: String,
    pub csr_pem: String,
    pub csr_sha256: String,
}

pub struct IdentityKeyManager {
    state_dir: PathBuf,
}

impl IdentityKeyManager {
    pub fn new(state_dir: impl AsRef<Path>) -> Self {
        Self {
            state_dir: state_dir.as_ref().to_path_buf(),
        }
    }

    /// Generate new Ed25519 and ECDSA P-256 keypairs and export a standard CSR
    pub fn generate_bundle(&self, stable_device_id: &str) -> Result<KeyPairBundle, KeyError> {
        let ed_signing = Ed25519SigningKey::generate(&mut OsRng);
        self.generate_bundle_with_key(stable_device_id, ed_signing)
    }

    /// Generate cryptographic bundle using an existing Ed25519 signing key
    pub fn generate_bundle_with_key(&self, stable_device_id: &str, ed_signing: Ed25519SigningKey) -> Result<KeyPairBundle, KeyError> {
        let ed_verifying: Ed25519VerifyingKey = ed_signing.verifying_key();
        let ed_pub_bytes = ed_verifying.to_bytes();
        let ed_fp = hex::encode(Sha256::digest(&ed_pub_bytes));

        // 2. Generate standard ECDSA P-256 Keypair using rcgen
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|e| KeyError::Crypto(format!("Failed to generate P-256 keypair: {}", e)))?;
        let p256_raw = key_pair.serialize_der();
        let p256_key_pem = key_pair.serialize_pem();

        // 3. Construct standard PKCS#10 Certificate Signing Request (CSR)
        let mut params = rcgen::CertificateParams::default();
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, format!("vexa-device-{}", stable_device_id));
        dn.push(rcgen::DnType::OrganizationName, "Vexa Agent Control Enrolled Device");
        params.distinguished_name = dn;

        let csr = params.serialize_request(&key_pair)
            .map_err(|e| KeyError::Crypto(format!("Failed to serialize CSR: {}", e)))?;
        let csr_pem = csr.pem()
            .map_err(|e| KeyError::Crypto(format!("Failed to encode CSR PEM: {}", e)))?;
        let csr_sha256 = hex::encode(Sha256::digest(csr_pem.as_bytes()));

        Ok(KeyPairBundle {
            ed25519_signing_key: ed_signing,
            ed25519_public_bytes: ed_pub_bytes,
            ed25519_fingerprint: ed_fp,
            p256_raw_key_bytes: p256_raw,
            p256_key_pem,
            csr_pem,
            csr_sha256,
        })
    }

    /// Save the private keys securely to disk using OS-restricted ACLs (0600 on Unix)
    pub fn persist_bundle_securely(&self, bundle: &KeyPairBundle) -> Result<(), KeyError> {
        fs::create_dir_all(&self.state_dir)?;

        let ed_path = self.state_dir.join("identity_ed25519.key");
        let p256_path = self.state_dir.join("mtls_p256.key");
        let p256_pem_path = self.state_dir.join("device_key.pem");

        Self::write_protected_file(&ed_path, bundle.ed25519_signing_key.as_bytes())?;
        Self::write_protected_file(&p256_path, &bundle.p256_raw_key_bytes)?;
        Self::write_protected_file(&p256_pem_path, bundle.p256_key_pem.as_bytes())?;

        Ok(())
    }

    fn write_protected_file(path: &Path, content: &[u8]) -> Result<(), KeyError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .mode(0o600)
                .open(path)?;
            file.write_all(content)?;
        }

        #[cfg(not(unix))]
        {
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(path)?;
            file.write_all(content)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_bundle_valid_p256_csr() {
        let temp_dir = tempfile::tempdir().unwrap();
        let key_mgr = IdentityKeyManager::new(temp_dir.path());
        let bundle = key_mgr.generate_bundle("test-device-01").unwrap();

        assert!(!bundle.ed25519_fingerprint.is_empty());
        assert!(!bundle.csr_sha256.is_empty());
        assert!(bundle.csr_pem.contains("-----BEGIN CERTIFICATE REQUEST-----"));
        assert!(bundle.csr_pem.contains("-----END CERTIFICATE REQUEST-----"));
        assert!(!bundle.p256_raw_key_bytes.is_empty());

        // Verify persisting bundle securely
        assert!(key_mgr.persist_bundle_securely(&bundle).is_ok());
        assert!(temp_dir.path().join("identity_ed25519.key").exists());
        assert!(temp_dir.path().join("mtls_p256.key").exists());
    }
}
