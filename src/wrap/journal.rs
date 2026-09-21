//! Transaction Journal for Workstation Protection (P0, REQ-OPS-001).
//!
//! Tracks in-flight workstation configuration mutations during `agentcontrol protect`.
//! Provides fail-closed atomicity across multiple IDE targets: if any target fails
//! during injection, all already-modified targets are rolled back to their exact
//! pre-mutation state, and uncommitted manifests are pruned.
//!
//! Also provides stale transaction recovery on startup: if an interrupted or crashed
//! protect run left an uncommitted `protect_journal.json`, it is automatically detected
//! and rolled back before new operations proceed.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use colored::*;

use crate::wrap::manifest::OwnershipManifest;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JournalTargetEntry {
    pub target: String,
    pub config_path: PathBuf,
    pub existed_before: bool,
    pub pre_mutation_content: Option<String>,
    pub manifest_target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProtectJournal {
    pub transaction_id: String,
    pub started_at: String,
    pub profile: String,
    pub targets_attempted: Vec<String>,
    pub targets_completed: Vec<String>,
    pub entries: HashMap<String, JournalTargetEntry>,
}

impl ProtectJournal {
    pub fn new(profile: impl Into<String>) -> Self {
        Self {
            transaction_id: uuid::Uuid::new_v4().to_string(),
            started_at: chrono::Utc::now().to_rfc3339(),
            profile: profile.into(),
            targets_attempted: Vec::new(),
            targets_completed: Vec::new(),
            entries: HashMap::new(),
        }
    }

    /// Default journal path: `~/.agentcontrol/protect_journal.json`
    pub fn journal_path() -> io::Result<PathBuf> {
        let home = dirs::home_dir()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Home directory not found"))?;
        let dir = home.join(".agentcontrol");
        fs::create_dir_all(&dir)?;
        Ok(dir.join("protect_journal.json"))
    }

    /// Record target before modification
    pub fn record_target_start(&mut self, target: &str, config_path: &Path, manifest_target: &str) {
        let existed = config_path.exists();
        let content = if existed {
            fs::read_to_string(config_path).ok()
        } else {
            None
        };

        self.targets_attempted.push(target.to_string());
        self.entries.insert(
            target.to_string(),
            JournalTargetEntry {
                target: target.to_string(),
                config_path: config_path.to_path_buf(),
                existed_before: existed,
                pre_mutation_content: content,
                manifest_target: manifest_target.to_string(),
            },
        );
    }

    /// Record target successfully modified
    pub fn record_target_success(&mut self, target: &str) {
        if !self.targets_completed.contains(&target.to_string()) {
            self.targets_completed.push(target.to_string());
        }
    }

    /// Save journal atomically to disk
    pub fn save(&self) -> io::Result<()> {
        let path = Self::journal_path()?;
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let tmp_path = path.with_extension(format!("tmp.{}", uuid::Uuid::new_v4()));
        fs::write(&tmp_path, json)?;
        fs::rename(&tmp_path, &path)?;
        Ok(())
    }

    /// Load existing journal from disk
    pub fn load() -> io::Result<Option<Self>> {
        let path = Self::journal_path()?;
        if !path.exists() {
            return Ok(None);
        }
        let content = fs::read_to_string(&path)?;
        let journal: Self = serde_json::from_str(&content)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(Some(journal))
    }

    /// Delete journal file from disk upon successful commit
    pub fn delete_file() -> io::Result<()> {
        let path = Self::journal_path()?;
        if path.exists() {
            fs::remove_file(path)?;
        }
        Ok(())
    }

    /// Delete journal file from disk upon successful commit (method form)
    pub fn delete(&self) -> io::Result<()> {
        Self::delete_file()
    }


    /// Roll back all completed targets in reverse order
    pub fn rollback(&self) -> Result<Vec<String>, String> {
        let mut rolled_back = Vec::new();
        for target in self.targets_completed.iter().rev() {
            if let Some(entry) = self.entries.get(target) {
                if entry.existed_before {
                    if let Some(ref content) = entry.pre_mutation_content {
                        fs::write(&entry.config_path, content)
                            .map_err(|e| format!("Failed to restore {}: {}", entry.config_path.display(), e))?;
                    }
                } else if entry.config_path.exists() {
                    let _ = fs::remove_file(&entry.config_path);
                }
                // Also remove ownership manifest if created
                let _ = OwnershipManifest::delete(&entry.manifest_target);
                rolled_back.push(target.clone());
            }
        }
        let _ = Self::delete_file();
        Ok(rolled_back)
    }

    /// Recover from stale journal if present on startup
    pub fn recover_if_stale() -> Result<bool, String> {
        match Self::load() {
            Ok(Some(journal)) => {
                eprintln!(
                    "{} Stale or uncommitted protect transaction detected (tx: {}).",
                    "⚠".yellow().bold(),
                    journal.transaction_id.cyan()
                );
                eprintln!("  Rolling back partially applied workstation modifications to ensure clean state...");
                match journal.rollback() {
                    Ok(reverted) => {
                        eprintln!(
                            "  {} Rolled back targets: {}",
                            "✔".green(),
                            if reverted.is_empty() { "none".to_string() } else { reverted.join(", ") }
                        );
                        Ok(true)
                    }
                    Err(e) => {
                        eprintln!("  {} Rollback error: {}", "✖".red(), e);
                        Err(e)
                    }
                }
            }
            Ok(None) => Ok(false),
            Err(e) => {
                eprintln!("{} Warning: failed to parse protect journal: {}", "⚠".yellow(), e);
                let _ = Self::delete_file();
                Ok(false)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_protect_journal_rollback() {
        let dir = tempdir().unwrap();
        let config_file = dir.path().join("test_config.json");
        fs::write(&config_file, r#"{"original": true}"#).unwrap();

        let mut journal = ProtectJournal::new("local-gateway");
        journal.record_target_start("test_target", &config_file, "test_manifest");
        journal.record_target_success("test_target");

        // Simulate modification
        fs::write(&config_file, r#"{"modified": true}"#).unwrap();

        // Rollback
        let rolled_back = journal.rollback().unwrap();
        assert_eq!(rolled_back, vec!["test_target"]);

        let restored = fs::read_to_string(&config_file).unwrap();
        assert_eq!(restored, r#"{"original": true}"#);
    }
}
