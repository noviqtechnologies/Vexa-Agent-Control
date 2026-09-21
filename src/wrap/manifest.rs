//! Complete Ownership Manifest Schema (v1.1) (REQ-ONB-002, REQ-OPS-001, PRD §FR-3.2)
//!
//! Tracks exact written values, previous values, and cryptographic pre/post file hashes
//! to ensure safe, non-destructive configuration reversal that preserves all user customizations.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OwnershipManifest {
    pub manifest_version: String,
    pub target: String,
    pub config_path: PathBuf,
    pub pre_mutation_hash_sha256: String,
    pub post_mutation_hash_sha256: String,
    pub managed_keys: Vec<String>,
    pub previous_values: HashMap<String, serde_json::Value>,
    pub written_values: HashMap<String, serde_json::Value>,
    pub agentcontrol_version: String,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_mode: Option<String>,
}

impl OwnershipManifest {
    pub fn new(
        target: impl Into<String>,
        config_path: PathBuf,
        pre_hash: impl Into<String>,
        post_hash: impl Into<String>,
        managed_keys: Vec<String>,
        previous_values: HashMap<String, serde_json::Value>,
        written_values: HashMap<String, serde_json::Value>,
    ) -> Self {
        Self {
            manifest_version: "1.1".to_string(),
            target: target.into(),
            config_path,
            pre_mutation_hash_sha256: pre_hash.into(),
            post_mutation_hash_sha256: post_hash.into(),
            managed_keys,
            previous_values,
            written_values,
            agentcontrol_version: env!("CARGO_PKG_VERSION").to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            connect_mode: None,
        }
    }

    pub fn with_connect_mode(mut self, mode: impl Into<String>) -> Self {
        self.connect_mode = Some(mode.into());
        self
    }

    /// Compute SHA-256 hex digest of a file.
    pub fn compute_sha256(path: &Path) -> io::Result<String> {
        let content = fs::read(path)?;
        let mut hasher = Sha256::new();
        hasher.update(&content);
        Ok(hex::encode(hasher.finalize()))
    }

    /// Get default manifests directory (`~/.agentcontrol/manifests`).
    pub fn manifests_dir() -> io::Result<PathBuf> {
        let home = dirs::home_dir()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Home directory not found"))?;
        let dir = home.join(".agentcontrol").join("manifests");
        fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    /// Path to manifest file for a given target.
    pub fn path_for_target(target: &str) -> io::Result<PathBuf> {
        let dir = Self::manifests_dir()?;
        Ok(dir.join(format!("{}.manifest.json", target)))
    }

    /// Save manifest atomically to disk.
    pub fn save(&self) -> io::Result<PathBuf> {
        let path = Self::path_for_target(&self.target)?;
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let tmp_path = path.with_extension(format!("tmp.{}", uuid::Uuid::new_v4()));
        fs::write(&tmp_path, json)?;
        fs::rename(&tmp_path, &path)?;
        Ok(path)
    }

    /// Load manifest for a target from disk.
    pub fn load(target: &str) -> io::Result<Option<Self>> {
        let path = Self::path_for_target(target)?;
        if !path.exists() {
            return Ok(None);
        }
        let content = fs::read_to_string(&path)?;
        let manifest: Self = serde_json::from_str(&content)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(Some(manifest))
    }

    /// Delete manifest file for a target.
    pub fn delete(target: &str) -> io::Result<()> {
        let path = Self::path_for_target(target)?;
        if path.exists() {
            fs::remove_file(path)?;
        }
        Ok(())
    }

    /// List all active ownership manifests.
    pub fn list_all() -> io::Result<Vec<Self>> {
        let dir = Self::manifests_dir()?;
        let mut list = Vec::new();
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.extension().and_then(|e| e.to_str()) == Some("json")
                    && p.file_name()
                        .and_then(|n| n.to_str())
                        .map(|n| n.ends_with(".manifest.json"))
                        .unwrap_or(false)
                {
                    if let Ok(content) = fs::read_to_string(&p) {
                        if let Ok(m) = serde_json::from_str::<Self>(&content) {
                            list.push(m);
                        }
                    }
                }
            }
        }
        Ok(list)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_manifest_roundtrip() {
        let dir = tempdir().unwrap();
        let config_file = dir.path().join("config.json");
        fs::write(&config_file, r#"{"custom": true}"#).unwrap();

        let pre_hash = OwnershipManifest::compute_sha256(&config_file).unwrap();
        fs::write(
            &config_file,
            r#"{"custom": true, "openai_base_url": "http://127.0.0.1:18080"}"#,
        )
        .unwrap();
        let post_hash = OwnershipManifest::compute_sha256(&config_file).unwrap();

        assert_ne!(pre_hash, post_hash);

        let mut previous = HashMap::new();
        previous.insert("openai_base_url".to_string(), serde_json::Value::Null);

        let mut written = HashMap::new();
        written.insert(
            "openai_base_url".to_string(),
            serde_json::Value::String("http://127.0.0.1:18080".to_string()),
        );

        let manifest = OwnershipManifest::new(
            "test_client",
            config_file.clone(),
            pre_hash.clone(),
            post_hash.clone(),
            vec!["openai_base_url".to_string()],
            previous,
            written.clone(),
        );

        assert_eq!(manifest.manifest_version, "1.1");
        assert_eq!(manifest.pre_mutation_hash_sha256, pre_hash);
        assert_eq!(manifest.post_mutation_hash_sha256, post_hash);
        assert_eq!(
            manifest.written_values.get("openai_base_url"),
            written.get("openai_base_url")
        );
    }
}
