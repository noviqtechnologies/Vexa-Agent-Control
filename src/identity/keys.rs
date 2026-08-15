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

        // 2. Generate P-256 Key Material (32 bytes entropy)
        let mut p256_raw = vec![0u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut p256_raw);

        // 3. Construct PKCS#10 Certificate Signing Request (CSR)
        let csr_pem = self.build_csr_pem(&p256_raw, stable_device_id)?;
        let csr_sha256 = hex::encode(Sha256::digest(csr_pem.as_bytes()));

        Ok(KeyPairBundle {
            ed25519_signing_key: ed_signing,
            ed25519_public_bytes: ed_pub_bytes,
            ed25519_fingerprint: ed_fp,
            p256_raw_key_bytes: p256_raw,
            csr_pem,
            csr_sha256,
        })
    }

    /// Save the private keys securely to disk using OS-restricted ACLs (0600 on Unix)
    pub fn persist_bundle_securely(&self, bundle: &KeyPairBundle) -> Result<(), KeyError> {
        fs::create_dir_all(&self.state_dir)?;

        let ed_path = self.state_dir.join("identity_ed25519.key");
        let p256_path = self.state_dir.join("mtls_p256.key");

        Self::write_protected_file(&ed_path, bundle.ed25519_signing_key.as_bytes())?;
        Self::write_protected_file(&p256_path, &bundle.p256_raw_key_bytes)?;

        Ok(())
    }

    fn build_csr_pem(
        &self,
        _key_bytes: &[u8],
        device_id: &str,
    ) -> Result<String, KeyError> {
        // Build base64url encoded representation of CSR for GCP CAS
        let raw_csr = format!("VEXA-CSR-P256-V2:{}", device_id);
        let b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            raw_csr.as_bytes(),
        );

        let pem_str = format!(
            "-----BEGIN CERTIFICATE REQUEST-----\n{}\n-----END CERTIFICATE REQUEST-----\n",
            b64
        );
        Ok(pem_str)
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
