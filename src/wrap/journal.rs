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

use colored::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::wrap::manifest::OwnershipManifest;

/// Durable atomic file writing helper with sync_all and rename.
pub fn write_file_durable(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp_path = path.with_extension(format!("tmp.{}", uuid::Uuid::new_v4()));
    {
        let mut file = fs::File::create(&tmp_path)?;
        use std::io::Write;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&tmp_path, path)?;
    Ok(())
}

/// Pre-mutation preimage for an individual configuration or auxiliary file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JournalFilePreimage {
    pub path: PathBuf,
    pub existed_before: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pre_mutation_bytes: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JournalTargetEntry {
    pub target: String,
    pub files: Vec<JournalFilePreimage>,
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

    /// Record target and capture byte preimages for all its files before modification
    pub fn record_target_start(
        &mut self,
        target: &str,
        files_to_record: &[&Path],
        manifest_target: &str,
    ) {
        let mut file_entries = Vec::new();
        for file_path in files_to_record {
            let existed = file_path.exists();
            let bytes = if existed {
                fs::read(file_path).ok()
            } else {
                None
            };
            file_entries.push(JournalFilePreimage {
                path: file_path.to_path_buf(),
                existed_before: existed,
                pre_mutation_bytes: bytes,
            });
        }

        if !self.targets_attempted.contains(&target.to_string()) {
            self.targets_attempted.push(target.to_string());
        }
        self.entries.insert(
            target.to_string(),
            JournalTargetEntry {
                target: target.to_string(),
                files: file_entries,
                manifest_target: manifest_target.to_string(),
            },
        );
    }

    /// Add an auxiliary file (e.g. auth.json) to an already started target entry
    pub fn record_auxiliary_file(&mut self, target: &str, file_path: &Path) {
        if let Some(entry) = self.entries.get_mut(target) {
            if !entry.files.iter().any(|f| f.path == file_path) {
                let existed = file_path.exists();
                let bytes = if existed {
                    fs::read(file_path).ok()
                } else {
                    None
                };
                entry.files.push(JournalFilePreimage {
                    path: file_path.to_path_buf(),
                    existed_before: existed,
                    pre_mutation_bytes: bytes,
                });
            }
        }
    }

    /// Record target successfully modified
    pub fn record_target_success(&mut self, target: &str) {
        if !self.targets_completed.contains(&target.to_string()) {
            self.targets_completed.push(target.to_string());
        }
    }

    /// Save journal atomically and durably to disk
    pub fn save(&self) -> io::Result<()> {
        let path = Self::journal_path()?;
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        write_file_durable(&path, &json)
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

    /// Quarantine corrupted journal file by renaming it with a timestamp
    pub fn quarantine_corrupted_journal() -> io::Result<Option<PathBuf>> {
        let path = Self::journal_path()?;
        if path.exists() {
            let ts = chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string();
            let quarantine_path = path.with_extension(format!("corrupt.{}", ts));
            fs::rename(&path, &quarantine_path)?;
            Ok(Some(quarantine_path))
        } else {
            Ok(None)
        }
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

    /// Roll back all attempted and in-progress targets in reverse order
    pub fn rollback(&self) -> Result<Vec<String>, String> {
        let mut rolled_back = Vec::new();
        let mut attempted_rev = self.targets_attempted.clone();
        attempted_rev.reverse();

        for target in &attempted_rev {
            if let Some(entry) = self.entries.get(target) {
                for file_entry in entry.files.iter().rev() {
                    if file_entry.existed_before {
                        if let Some(ref bytes) = file_entry.pre_mutation_bytes {
                            let _ = write_file_durable(&file_entry.path, bytes);
                        }
                    } else if file_entry.path.exists() {
                        let _ = fs::remove_file(&file_entry.path);
                    }
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
                            if reverted.is_empty() {
                                "none".to_string()
                            } else {
                                reverted.join(", ")
                            }
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
                eprintln!("{} Warning: failed to parse protect journal: {}. Quarantining corrupted journal...", "⚠".yellow(), e);
                if let Ok(Some(qpath)) = Self::quarantine_corrupted_journal() {
                    eprintln!(
                        "  {} Quarantined unreadable journal to: {}",
                        "✔".green(),
                        qpath.display().to_string().cyan()
                    );
                }
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
        journal.record_target_start("test_target", &[&config_file], "test_manifest");
        journal.record_target_success("test_target");

        // Simulate modification
        fs::write(&config_file, r#"{"modified": true}"#).unwrap();
        assert_eq!(
            fs::read_to_string(&config_file).unwrap(),
            r#"{"modified": true}"#
        );

        // Roll back
        let reverted = journal.rollback().unwrap();
        assert_eq!(reverted, vec!["test_target"]);
        assert_eq!(
            fs::read_to_string(&config_file).unwrap(),
            r#"{"original": true}"#
        );
    }

    #[test]
    fn test_protect_journal_in_progress_rollback() {
        let dir = tempdir().unwrap();
        let config_file = dir.path().join("in_flight_config.json");
        fs::write(&config_file, r#"{"clean": true}"#).unwrap();

        let mut journal = ProtectJournal::new("local-gateway");
        // Target is started (in attempted list) but NEVER marked success
        journal.record_target_start("in_flight_target", &[&config_file], "in_flight_manifest");

        // Interrupted midway after mutating file
        fs::write(&config_file, r#"{"corrupt_partial": true}"#).unwrap();

        // Roll back must restore in-progress target too
        let reverted = journal.rollback().unwrap();
        assert_eq!(reverted, vec!["in_flight_target"]);
        assert_eq!(
            fs::read_to_string(&config_file).unwrap(),
            r#"{"clean": true}"#
        );
    }
}
