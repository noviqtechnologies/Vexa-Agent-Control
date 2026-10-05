//! Phase 3: Automated Disaster Recovery (Backup & Restore Engine)
//!
//! Provides verifiable, automated backup and recovery of team policy databases,
//! trace stores, and HMAC audit chains, with end-to-end cryptographic integrity verification.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupFileEntry {
    pub relative_path: String,
    pub content_hex: String,
    pub sha256: String,
    pub size_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupArchive {
    pub manifest_version: String,
    pub created_at: String,
    pub generator_version: String,
    pub files: Vec<BackupFileEntry>,
    pub overall_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreReport {
    pub restored_files_count: usize,
    pub restored_bytes: usize,
    pub audit_chain_verified: bool,
    pub restored_paths: Vec<String>,
}

#[derive(Debug)]
pub enum DisasterRecoveryError {
    Io(std::io::Error),
    Serialization(serde_json::Error),
    ManifestCorrupted { stored: String, computed: String },
    FileIntegrityFailure { path: String, stored: String, computed: String },
    AuditVerificationFailed(String),
}

impl std::fmt::Display for DisasterRecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {}", e),
            Self::Serialization(e) => write!(f, "Serialization error: {}", e),
            Self::ManifestCorrupted { stored, computed } => {
                write!(f, "Corrupted backup: manifest hash mismatch (stored={}, computed={})", stored, computed)
            }
            Self::FileIntegrityFailure { path, stored, computed } => {
                write!(f, "File integrity failure for '{}': stored={}, computed={}", path, stored, computed)
            }
            Self::AuditVerificationFailed(e) => write!(f, "Audit chain verification failed on restored logs: {}", e),
        }
    }
}

impl std::error::Error for DisasterRecoveryError {}

impl From<std::io::Error> for DisasterRecoveryError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<serde_json::Error> for DisasterRecoveryError {
    fn from(err: serde_json::Error) -> Self {
        Self::Serialization(err)
    }
}

fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Create a verified backup archive from target files in a source directory
pub fn create_backup(
    source_dir: &Path,
    target_rel_paths: &[&str],
    output_archive_path: &Path,
) -> Result<BackupArchive, DisasterRecoveryError> {
    let mut files = Vec::new();
    let mut manifest_hasher = Sha256::new();

    for rel_path in target_rel_paths {
        let full_path = source_dir.join(rel_path);
        if full_path.exists() && full_path.is_file() {
            let data = fs::read(&full_path)?;
            let file_hash = compute_sha256(&data);

            manifest_hasher.update(rel_path.as_bytes());
            manifest_hasher.update(file_hash.as_bytes());

            files.push(BackupFileEntry {
                relative_path: rel_path.to_string(),
                content_hex: hex::encode(&data),
                sha256: file_hash,
                size_bytes: data.len(),
            });
        }
    }

    let overall_sha256 = hex::encode(manifest_hasher.finalize());

    let archive = BackupArchive {
        manifest_version: "1.0.0".to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        generator_version: env!("CARGO_PKG_VERSION").to_string(),
        files,
        overall_sha256,
    };

    if let Some(parent) = output_archive_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    let serialized = serde_json::to_string_pretty(&archive)?;
    fs::write(output_archive_path, serialized)?;

    Ok(archive)
}

/// Restore a backup archive into target directory with integrity and HMAC audit chain verification
pub fn restore_backup(
    archive_path: &Path,
    target_dir: &Path,
    audit_session_secret: Option<&[u8]>,
) -> Result<RestoreReport, DisasterRecoveryError> {
    let data = fs::read_to_string(archive_path)?;
    let archive: BackupArchive = serde_json::from_str(&data)?;

    // 1. Verify overall manifest hash
    let mut manifest_hasher = Sha256::new();
    for entry in &archive.files {
        manifest_hasher.update(entry.relative_path.as_bytes());
        manifest_hasher.update(entry.sha256.as_bytes());
    }
    let computed_overall = hex::encode(manifest_hasher.finalize());
    if computed_overall != archive.overall_sha256 {
        return Err(DisasterRecoveryError::ManifestCorrupted {
            stored: archive.overall_sha256,
            computed: computed_overall,
        });
    }

    // 2. Validate and restore files
    fs::create_dir_all(target_dir)?;
    let mut restored_bytes = 0;
    let mut restored_paths = Vec::new();
    let mut audit_log_restored: Option<PathBuf> = None;

    for entry in &archive.files {
        let content_bytes = hex::decode(&entry.content_hex)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let computed_hash = compute_sha256(&content_bytes);
        if computed_hash != entry.sha256 {
            return Err(DisasterRecoveryError::FileIntegrityFailure {
                path: entry.relative_path.clone(),
                stored: entry.sha256.clone(),
                computed: computed_hash,
            });
        }

        let out_file_path = target_dir.join(&entry.relative_path);
        if let Some(parent) = out_file_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&out_file_path, &content_bytes)?;

        restored_bytes += content_bytes.len();
        restored_paths.push(entry.relative_path.clone());

        if entry.relative_path.ends_with(".jsonl") || entry.relative_path.contains("audit") {
            audit_log_restored = Some(out_file_path);
        }
    }

    // 3. Verify HMAC audit chain continuity if audit log restored
    let mut audit_chain_verified = false;
    if let Some(audit_path) = audit_log_restored {
        let ver_res = if let Some(secret) = audit_session_secret {
            crate::audit::verifier::verify_chain_with_secret(&audit_path, secret)
        } else {
            crate::audit::verifier::verify_chain(&audit_path)
        };
        match ver_res {
            crate::audit::verifier::VerifyResult::Valid { .. } => {
                audit_chain_verified = true;
            }
            crate::audit::verifier::VerifyResult::Invalid { entry_index, reason } => {
                return Err(DisasterRecoveryError::AuditVerificationFailed(format!(
                    "Invalid HMAC chain at index {}: {}",
                    entry_index, reason
                )));
            }
            crate::audit::verifier::VerifyResult::Error(err) => {
                return Err(DisasterRecoveryError::AuditVerificationFailed(err));
            }
        }
    }

    Ok(RestoreReport {
        restored_files_count: archive.files.len(),
        restored_bytes,
        audit_chain_verified,
        restored_paths,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_backup_and_restore_roundtrip() {
        let src = tempdir().unwrap();
        let dst = tempdir().unwrap();
        let archive_dir = tempdir().unwrap();
        let archive_path = archive_dir.path().join("backup.json");

        // Create sample files
        let policy_content = "version: \"2.0\"\ndefault_action: deny\ntools: []\n";
        let entry = crate::audit::logger::AuditEntry {
            ts: chrono::Utc::now().to_rfc3339(),
            session_id: "dr-sess".to_string(),
            event: "backup_test".to_string(),
            tool_name: None,
            params_hash: None,
            params: None,
            reason: None,
            latency_ms: None,
            identity_sub: None,
            identity_email: None,
            policy_hash: None,
            request_ip: None,
            matched_group_id: None,
            entry_index: 0,
            prev_hmac: crate::audit::logger::ZERO_HMAC.to_string(),
            hmac: Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string()),
        };
        let audit_content = serde_json::to_string(&entry).unwrap();
        fs::write(src.path().join("policy.yaml"), policy_content).unwrap();
        fs::write(src.path().join("audit.jsonl"), &audit_content).unwrap();

        // Backup
        let bkp = create_backup(
            src.path(),
            &["policy.yaml", "audit.jsonl"],
            &archive_path,
        ).unwrap();
        assert_eq!(bkp.files.len(), 2);

        // Restore
        let report = restore_backup(&archive_path, dst.path(), None).unwrap();
        assert_eq!(report.restored_files_count, 2);
        assert_eq!(fs::read_to_string(dst.path().join("policy.yaml")).unwrap(), policy_content);
        assert_eq!(fs::read_to_string(dst.path().join("audit.jsonl")).unwrap(), audit_content);
    }
}
