//! Phase 3: Signed Cryptographic Policy Distribution & Verifiable Rollback (ADR-008)
//!
//! Provides:
//! - Ed25519 signing and verification of policy bundles
//! - Dry-run policy compilation and signature enforcement
//! - Atomic snapshot creation and automatic rollback to `rollback_policy.yaml`

use crate::policy::engine::CompiledPolicy;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Cryptographically signed policy distribution bundle
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedPolicyBundle {
    pub schema_version: String,
    pub policy_id: String,
    pub policy_revision: u64,
    pub policy_yaml: String,
    /// Hex-encoded 64-byte Ed25519 signature
    pub signature: String,
    /// Hex-encoded 32-byte Ed25519 public key of signer
    pub public_key: String,
    pub issued_at: String,
    pub expires_at: Option<String>,
}

#[derive(Debug)]
pub enum PolicyDistributionError {
    InvalidPublicKey(String),
    InvalidSignature(String),
    UntrustedSigner(String),
    SignatureVerificationFailed(String),
    PolicyExpired(String),
    CompilationFailed(String),
    Io(std::io::Error),
    NoRollbackSnapshot(PathBuf),
}

impl std::fmt::Display for PolicyDistributionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPublicKey(s) => write!(f, "Invalid public key hex: {}", s),
            Self::InvalidSignature(s) => write!(f, "Invalid signature hex: {}", s),
            Self::UntrustedSigner(s) => write!(f, "Untrusted signer public key: {}", s),
            Self::SignatureVerificationFailed(s) => {
                write!(f, "Signature verification failed: {}", s)
            }
            Self::PolicyExpired(s) => write!(f, "Policy bundle has expired at {}", s),
            Self::CompilationFailed(s) => write!(f, "Policy compilation failed: {}", s),
            Self::Io(e) => write!(f, "I/O error during policy storage/rollback: {}", e),
            Self::NoRollbackSnapshot(p) => {
                write!(f, "No rollback snapshot found at {}", p.display())
            }
        }
    }
}

impl std::error::Error for PolicyDistributionError {}

impl From<std::io::Error> for PolicyDistributionError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

/// Generate a new Ed25519 signing keypair for policy authority / security leads
pub fn generate_signing_keypair() -> (SigningKey, VerifyingKey) {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// Canonical payload format for signing: `policy_id:policy_revision:policy_yaml`
pub fn canonical_sign_bytes(policy_id: &str, revision: u64, yaml: &str) -> Vec<u8> {
    format!("{}:{}:{}", policy_id, revision, yaml).into_bytes()
}

/// Sign a policy YAML with an Ed25519 signing key
pub fn sign_policy(
    signing_key: &SigningKey,
    policy_id: &str,
    policy_revision: u64,
    policy_yaml: &str,
    expires_at: Option<String>,
) -> SignedPolicyBundle {
    let payload = canonical_sign_bytes(policy_id, policy_revision, policy_yaml);
    let signature = signing_key.sign(&payload);
    let verifying_key = signing_key.verifying_key();

    SignedPolicyBundle {
        schema_version: "2.0".to_string(),
        policy_id: policy_id.to_string(),
        policy_revision,
        policy_yaml: policy_yaml.to_string(),
        signature: hex::encode(signature.to_bytes()),
        public_key: hex::encode(verifying_key.to_bytes()),
        issued_at: chrono::Utc::now().to_rfc3339(),
        expires_at,
    }
}

/// Verify a signed policy bundle against an optional allowlist of trusted public keys
pub fn verify_signed_bundle(
    bundle: &SignedPolicyBundle,
    trusted_public_keys: Option<&[String]>,
) -> Result<CompiledPolicy, PolicyDistributionError> {
    // 1. Verify trusted signer
    let pk_bytes = hex::decode(&bundle.public_key)
        .map_err(|e| PolicyDistributionError::InvalidPublicKey(e.to_string()))?;
    if pk_bytes.len() != 32 {
        return Err(PolicyDistributionError::InvalidPublicKey(
            "public key must be 32 bytes".to_string(),
        ));
    }

    if let Some(trusted) = trusted_public_keys {
        let bundle_pk_hex = bundle.public_key.to_lowercase();
        let is_trusted = trusted.iter().any(|t| t.to_lowercase() == bundle_pk_hex);
        if !is_trusted {
            return Err(PolicyDistributionError::UntrustedSigner(
                bundle.public_key.clone(),
            ));
        }
    }

    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let verifying_key = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| PolicyDistributionError::InvalidPublicKey(e.to_string()))?;

    // 2. Check expiration if present
    if let Some(ref exp_str) = bundle.expires_at {
        if let Ok(exp_dt) = chrono::DateTime::parse_from_rfc3339(exp_str) {
            if chrono::Utc::now() > exp_dt.with_timezone(&chrono::Utc) {
                return Err(PolicyDistributionError::PolicyExpired(exp_str.clone()));
            }
        }
    }

    // 3. Verify cryptographic Ed25519 signature
    let sig_bytes = hex::decode(&bundle.signature)
        .map_err(|e| PolicyDistributionError::InvalidSignature(e.to_string()))?;
    if sig_bytes.len() != 64 {
        return Err(PolicyDistributionError::InvalidSignature(
            "signature must be 64 bytes".to_string(),
        ));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    let payload = canonical_sign_bytes(
        &bundle.policy_id,
        bundle.policy_revision,
        &bundle.policy_yaml,
    );
    verifying_key
        .verify(&payload, &signature)
        .map_err(|e| PolicyDistributionError::SignatureVerificationFailed(e.to_string()))?;

    // 4. Dry-run compile the policy to ensure schema integrity
    let compiled = CompiledPolicy::from_yaml_str(&bundle.policy_yaml)
        .map_err(PolicyDistributionError::CompilationFailed)?;

    Ok(compiled)
}

/// Manages atomic application, snapshotting, and rollback of policy files on disk
pub struct PolicyStorageManager {
    pub dir: PathBuf,
}

impl PolicyStorageManager {
    pub fn new(dir: impl AsRef<Path>) -> Self {
        Self {
            dir: dir.as_ref().to_path_buf(),
        }
    }

    pub fn current_policy_path(&self) -> PathBuf {
        self.dir.join("current_policy.yaml")
    }

    pub fn rollback_policy_path(&self) -> PathBuf {
        self.dir.join("rollback_policy.yaml")
    }

    /// Atomically applies a verified signed bundle, preserving previous policy as rollback snapshot
    pub fn apply_signed_bundle(
        &self,
        bundle: &SignedPolicyBundle,
        trusted_keys: Option<&[String]>,
    ) -> Result<CompiledPolicy, PolicyDistributionError> {
        // First verify signature and compile in-memory
        let compiled = verify_signed_bundle(bundle, trusted_keys)?;

        fs::create_dir_all(&self.dir)?;

        let current = self.current_policy_path();
        let rollback = self.rollback_policy_path();

        // If current policy exists, snapshot it to rollback
        if current.exists() {
            let _ = fs::copy(&current, &rollback);
        }

        // Atomically write new policy
        let tmp_file = self
            .dir
            .join(format!(".tmp_policy_{}", uuid::Uuid::new_v4()));
        fs::write(&tmp_file, &bundle.policy_yaml)?;
        fs::rename(tmp_file, &current)?;

        // Also persist the signed envelope
        let bundle_meta = self.dir.join("current_policy_bundle.json");
        let _ = fs::write(
            bundle_meta,
            serde_json::to_string_pretty(bundle).unwrap_or_default(),
        );

        Ok(compiled)
    }

    /// Rollback to the previous snapshot (`rollback_policy.yaml`)
    pub fn rollback(&self) -> Result<CompiledPolicy, PolicyDistributionError> {
        let rollback = self.rollback_policy_path();
        if !rollback.exists() {
            return Err(PolicyDistributionError::NoRollbackSnapshot(rollback));
        }

        let current = self.current_policy_path();
        let yaml = fs::read_to_string(&rollback)?;
        let compiled = CompiledPolicy::from_yaml_str(&yaml)
            .map_err(PolicyDistributionError::CompilationFailed)?;

        // Restore snapshot to current
        fs::copy(&rollback, &current)?;

        Ok(compiled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_sign_and_verify_valid_bundle() {
        let (sk, pk) = generate_signing_keypair();
        let pk_hex = hex::encode(pk.to_bytes());
        let yaml = "version: \"2.0\"\ndefault_action: deny\ntools: []\n";

        let bundle = sign_policy(&sk, "corp-sec-1", 1, yaml, None);
        assert_eq!(bundle.policy_id, "corp-sec-1");
        assert_eq!(bundle.public_key, pk_hex);

        // Verification with trusted key
        let res = verify_signed_bundle(&bundle, Some(&[pk_hex]));
        assert!(res.is_ok());
    }

    #[test]
    fn test_reject_tampered_bundle() {
        let (sk, pk) = generate_signing_keypair();
        let pk_hex = hex::encode(pk.to_bytes());
        let yaml = "version: \"2.0\"\ndefault_action: deny\ntools: []\n";

        let mut bundle = sign_policy(&sk, "corp-sec-1", 1, yaml, None);
        // Tamper with the YAML
        bundle.policy_yaml =
            "version: \"2.0\"\ndefault_action: deny\nenforce_safe_mode: true\ntools: []\n"
                .to_string();

        let res = verify_signed_bundle(&bundle, Some(&[pk_hex]));
        assert!(matches!(
            res,
            Err(PolicyDistributionError::SignatureVerificationFailed(_))
        ));
    }

    #[test]
    fn test_reject_untrusted_signer() {
        let (sk, _pk) = generate_signing_keypair();
        let yaml = "version: \"2.0\"\ndefault_action: deny\ntools: []\n";

        let bundle = sign_policy(&sk, "corp-sec-1", 1, yaml, None);
        let different_trusted_key =
            "0000000000000000000000000000000000000000000000000000000000000000".to_string();

        let res = verify_signed_bundle(&bundle, Some(&[different_trusted_key]));
        assert!(matches!(
            res,
            Err(PolicyDistributionError::UntrustedSigner(_))
        ));
    }

    #[test]
    fn test_storage_manager_apply_and_rollback() {
        let dir = tempdir().unwrap();
        let mgr = PolicyStorageManager::new(dir.path());
        let (sk, pk) = generate_signing_keypair();
        let pk_hex = hex::encode(pk.to_bytes());

        // Apply revision 1
        let bundle1 = sign_policy(
            &sk,
            "policy",
            1,
            "version: \"2.0\"\ndefault_action: deny\nenforce_safe_mode: false\ntools: []\n",
            None,
        );
        let res1 = mgr.apply_signed_bundle(&bundle1, Some(&[pk_hex.clone()]));
        assert!(res1.is_ok());
        assert!(mgr.current_policy_path().exists());

        // Apply revision 2
        let bundle2 = sign_policy(
            &sk,
            "policy",
            2,
            "version: \"2.0\"\ndefault_action: deny\nenforce_safe_mode: true\ntools: []\n",
            None,
        );
        let res2 = mgr.apply_signed_bundle(&bundle2, Some(&[pk_hex]));
        assert!(res2.is_ok());
        assert!(mgr.rollback_policy_path().exists());

        // Verify content is revision 2
        let cur_content = fs::read_to_string(mgr.current_policy_path()).unwrap();
        assert!(cur_content.contains("enforce_safe_mode: true"));

        // Rollback
        let rb_res = mgr.rollback();
        assert!(rb_res.is_ok());
        let restored_content = fs::read_to_string(mgr.current_policy_path()).unwrap();
        assert!(!restored_content.contains("enforce_safe_mode: true"));
    }
}
