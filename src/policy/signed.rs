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

/// Canonical payload format for signing: length-framed, domain-separated binary format
pub fn canonical_sign_payload(
    schema_version: &str,
    policy_id: &str,
    revision: u64,
    yaml: &str,
    issued_at: &str,
    expires_at: Option<&str>,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"vexa-policy-bundle-v1\0");
    write_length_prefixed(&mut payload, schema_version.as_bytes());
    write_length_prefixed(&mut payload, policy_id.as_bytes());
    payload.extend_from_slice(&revision.to_be_bytes());
    write_length_prefixed(&mut payload, yaml.as_bytes());
    write_length_prefixed(&mut payload, issued_at.as_bytes());
    if let Some(exp) = expires_at {
        payload.push(1);
        write_length_prefixed(&mut payload, exp.as_bytes());
    } else {
        payload.push(0);
    }
    payload
}

fn write_length_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

/// Helper for backwards-compatibility
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
    let schema_version = "2.0".to_string();
    let issued_at = chrono::Utc::now().to_rfc3339();
    let payload = canonical_sign_payload(
        &schema_version,
        policy_id,
        policy_revision,
        policy_yaml,
        &issued_at,
        expires_at.as_deref(),
    );
    let signature = signing_key.sign(&payload);
    let verifying_key = signing_key.verifying_key();

    SignedPolicyBundle {
        schema_version,
        policy_id: policy_id.to_string(),
        policy_revision,
        policy_yaml: policy_yaml.to_string(),
        signature: hex::encode(signature.to_bytes()),
        public_key: hex::encode(verifying_key.to_bytes()),
        issued_at,
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

    // 2. Check expiration if present (hard error on malformed timestamp)
    if let Some(ref exp_str) = bundle.expires_at {
        match chrono::DateTime::parse_from_rfc3339(exp_str) {
            Ok(exp_dt) => {
                if chrono::Utc::now() > exp_dt.with_timezone(&chrono::Utc) {
                    return Err(PolicyDistributionError::PolicyExpired(exp_str.clone()));
                }
            }
            Err(e) => {
                return Err(PolicyDistributionError::InvalidSignature(format!(
                    "Malformed expires_at timestamp '{}': {}",
                    exp_str, e
                )));
            }
        }
    }

    // 3. Verify cryptographic Ed25519 signature over canonical length-prefixed payload
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

    let payload = canonical_sign_payload(
        &bundle.schema_version,
        &bundle.policy_id,
        bundle.policy_revision,
        &bundle.policy_yaml,
        &bundle.issued_at,
        bundle.expires_at.as_deref(),
    );
    verifying_key
        .verify(&payload, &signature)
        .map_err(|e| PolicyDistributionError::SignatureVerificationFailed(e.to_string()))?;

    // 4. Dry-run compile the policy to ensure schema integrity
    let mut compiled = CompiledPolicy::from_yaml_str(&bundle.policy_yaml)
        .map_err(PolicyDistributionError::CompilationFailed)?;
    compiled.policy_revision = Some(bundle.policy_revision);
    compiled.policy_hash = Some(format!("rev:{}", bundle.policy_revision));

    Ok(compiled)
}

/// Durable cross-platform atomic replace helper.
///
/// On Windows, `fs::rename` fails if target exists.
/// This helper writes to a sibling temp file, flushes/syncs to disk,
/// and performs a resilient atomic replace with retry backoff for Windows file locks,
/// followed by a parent directory fsync.
pub fn durable_atomic_replace(target: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let tmp_file = parent.join(format!(
        ".tmp_{}_{}",
        uuid::Uuid::new_v4(),
        target
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file")
    ));
    {
        let mut f = fs::File::create(&tmp_file)?;
        use std::io::Write;
        f.write_all(bytes)?;
        f.sync_all()?;
    }

    let mut success = false;
    let mut last_err = None;
    for attempt in 0..5 {
        if target.exists() {
            let _ = fs::remove_file(target);
        }
        match fs::rename(&tmp_file, target) {
            Ok(()) => {
                success = true;
                break;
            }
            Err(e) => {
                last_err = Some(e);
                std::thread::sleep(std::time::Duration::from_millis(10 * (attempt + 1)));
            }
        }
    }

    if !success {
        let _ = fs::remove_file(&tmp_file);
        return Err(last_err.unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                "Failed to replace file atomically across OS boundary",
            )
        }));
    }

    if let Ok(dir) = fs::File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
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

    pub fn current_bundle_path(&self) -> PathBuf {
        self.dir.join("current_policy_bundle.json")
    }

    pub fn rollback_bundle_path(&self) -> PathBuf {
        self.dir.join("rollback_policy_bundle.json")
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
        let current_bundle = self.current_bundle_path();
        let rollback_bundle = self.rollback_bundle_path();

        // If current policy exists, snapshot both YAML and envelope
        if current.exists() {
            let _ = fs::copy(&current, &rollback);
            if current_bundle.exists() {
                let _ = fs::copy(&current_bundle, &rollback_bundle);
            }
        }

        // Atomically write new policy (with cross-OS safe rename)
        durable_atomic_replace(&current, bundle.policy_yaml.as_bytes())?;

        // Also persist the signed envelope - propagate error instead of ignoring
        let bundle_json = serde_json::to_string_pretty(bundle)
            .map_err(|e| PolicyDistributionError::CompilationFailed(e.to_string()))?;
        durable_atomic_replace(&current_bundle, bundle_json.as_bytes())?;

        Ok(compiled)
    }

    /// Rollback to the previous snapshot, re-verifying the signed envelope if present
    pub fn rollback(&self) -> Result<CompiledPolicy, PolicyDistributionError> {
        self.rollback_with_keys(None)
    }

    /// Rollback with trusted keys verification
    pub fn rollback_with_keys(
        &self,
        trusted_keys: Option<&[String]>,
    ) -> Result<CompiledPolicy, PolicyDistributionError> {
        let rollback = self.rollback_policy_path();
        let rollback_bundle = self.rollback_bundle_path();

        // If signed rollback bundle exists, re-verify it
        if rollback_bundle.exists() {
            if let Ok(bundle_data) = fs::read_to_string(&rollback_bundle) {
                if let Ok(bundle) = serde_json::from_str::<SignedPolicyBundle>(&bundle_data) {
                    let compiled = verify_signed_bundle(&bundle, trusted_keys)?;
                    let current = self.current_policy_path();
                    let current_bundle = self.current_bundle_path();
                    durable_atomic_replace(&current, bundle.policy_yaml.as_bytes())?;
                    durable_atomic_replace(&current_bundle, bundle_data.as_bytes())?;
                    return Ok(compiled);
                }
            }
        }

        if !rollback.exists() {
            return Err(PolicyDistributionError::NoRollbackSnapshot(rollback));
        }

        let current = self.current_policy_path();
        let yaml = fs::read_to_string(&rollback)?;
        let compiled = CompiledPolicy::from_yaml_str(&yaml)
            .map_err(PolicyDistributionError::CompilationFailed)?;

        durable_atomic_replace(&current, yaml.as_bytes())?;

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

    #[test]
    fn test_tamper_metadata_detected() {
        let (sk, pk) = generate_signing_keypair();
        let pk_hex = hex::encode(pk.to_bytes());
        let yaml = "version: \"2.0\"\ndefault_action: deny\ntools: []\n";

        let mut bundle = sign_policy(&sk, "corp-sec-1", 1, yaml, None);
        // Tamper with unsigned field issued_at
        bundle.issued_at = "2020-01-01T00:00:00Z".to_string();

        let res = verify_signed_bundle(&bundle, Some(&[pk_hex.clone()]));
        assert!(matches!(
            res,
            Err(PolicyDistributionError::SignatureVerificationFailed(_))
        ));

        // Tamper with expires_at
        let mut bundle2 = sign_policy(&sk, "corp-sec-1", 1, yaml, None);
        bundle2.expires_at = Some("2099-01-01T00:00:00Z".to_string());
        let res2 = verify_signed_bundle(&bundle2, Some(&[pk_hex]));
        assert!(matches!(
            res2,
            Err(PolicyDistributionError::SignatureVerificationFailed(_))
        ));
    }

    #[test]
    fn test_malformed_expiry_timestamp() {
        let (sk, pk) = generate_signing_keypair();
        let pk_hex = hex::encode(pk.to_bytes());
        let yaml = "version: \"2.0\"\ndefault_action: deny\ntools: []\n";

        let bundle = sign_policy(
            &sk,
            "corp-sec-1",
            1,
            yaml,
            Some("not-a-timestamp".to_string()),
        );
        let res = verify_signed_bundle(&bundle, Some(&[pk_hex]));
        assert!(matches!(
            res,
            Err(PolicyDistributionError::InvalidSignature(_))
        ));
    }

    #[test]
    fn test_delimiter_ambiguity_eliminated() {
        let (sk, pk) = generate_signing_keypair();
        let pk_hex = hex::encode(pk.to_bytes());
        let yaml = "version: \"2.0\"\ndefault_action: deny\ntools: []\n";

        // policy_id with colons should verify cleanly and not collide
        let bundle = sign_policy(&sk, "corp:sec:1", 1, yaml, None);
        let res = verify_signed_bundle(&bundle, Some(&[pk_hex]));
        assert!(res.is_ok());
    }
}
