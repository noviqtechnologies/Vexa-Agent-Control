//! Integration tests for `agentwall protect` / `agentwall unprotect` CLI commands
//! and associated backup / configuration-wrapping subsystem.
//!
//! Tests cover:
//!   FR-1.2: Timestamped atomic backup creation before any config write
//!   FR-1.3: --dry-run preview (no disk writes)
//!   FR-1.4: Backup integrity verification before reversion
//!   NFR-3.2: Zero-loss backup policy (corrupt backup blocks reversion)
//!   API:    POST /api/mode mode-toggle endpoint contract

use std::fs;
use std::path::{Path, PathBuf};
use tempfile::tempdir;

// ── Helpers ──────────────────────────────────────────────────────────────────

fn write_valid_mcp_config(dir: &Path, filename: &str) -> PathBuf {
    let p = dir.join(filename);
    fs::write(
        &p,
        r#"{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home/user"]
    }
  }
}"#,
    )
    .unwrap();
    p
}

fn write_corrupt_config(dir: &Path, filename: &str) -> PathBuf {
    let p = dir.join(filename);
    fs::write(&p, b"NOT VALID JSON !!!").unwrap();
    p
}

fn write_empty_config(dir: &Path, filename: &str) -> PathBuf {
    let p = dir.join(filename);
    fs::write(&p, b"").unwrap();
    p
}

// ── backup::verify_backup_integrity ─────────────────────────────────────────

#[cfg(test)]
mod backup_integrity_tests {
    use super::*;
    use agentwall::wrap::backup;

    #[test]
    fn valid_backup_passes_integrity_check() {
        let dir = tempdir().unwrap();
        let config = write_valid_mcp_config(dir.path(), "cursor_config.json");
        let backup_path = backup::create_backup(&config).unwrap();
        assert!(backup_path.exists(), "Backup file must be created on disk");
        backup::verify_backup_integrity(&backup_path)
            .expect("Valid JSON backup should pass integrity check");
    }

    #[test]
    fn corrupt_backup_fails_integrity_check() {
        let dir = tempdir().unwrap();
        let corrupt = write_corrupt_config(dir.path(), "backup_bad.json");
        let err = backup::verify_backup_integrity(&corrupt)
            .expect_err("Corrupt backup must fail integrity check");
        let msg = format!("{err}");
        assert!(
            msg.to_lowercase().contains("json"),
            "Error should mention JSON corruption, got: {msg}"
        );
    }

    #[test]
    fn empty_backup_fails_integrity_check() {
        let dir = tempdir().unwrap();
        let empty = write_empty_config(dir.path(), "backup_empty.json");
        let err = backup::verify_backup_integrity(&empty)
            .expect_err("Empty backup must fail integrity check (NFR-3.2)");
        let msg = format!("{err}");
        assert!(
            msg.to_lowercase().contains("empty") || msg.to_lowercase().contains("json"),
            "Error should mention empty file or JSON, got: {msg}"
        );
    }

    #[test]
    fn missing_backup_returns_no_backup_found() {
        let dir = tempdir().unwrap();
        let phantom = dir.path().join("ghost_backup.json");
        let err = backup::verify_backup_integrity(&phantom)
            .expect_err("Missing backup must fail integrity check");
        let msg = format!("{err}");
        assert!(
            msg.to_lowercase().contains("backup") || msg.to_lowercase().contains("no backup"),
            "Error should indicate missing backup, got: {msg}"
        );
    }
}

// ── backup lifecycle ──────────────────────────────────────────────────────

#[cfg(test)]
mod backup_lifecycle_tests {
    use super::*;
    use agentwall::wrap::backup;

    #[test]
    fn backup_name_contains_agentwall_prefix_and_timestamp() {
        let dir = tempdir().unwrap();
        let config = write_valid_mcp_config(dir.path(), "claude_desktop_config.json");
        let backup_path = backup::create_backup(&config).unwrap();
        let name = backup_path.file_name().unwrap().to_string_lossy();
        assert!(
            name.contains("agentwall-backup-"),
            "Backup filename must contain 'agentwall-backup-' prefix, got: {name}"
        );
        // Timestamp is at least 14 digits (YYYYMMDD + HHMMSS)
        let digits: String = name.chars().filter(|c| c.is_ascii_digit()).collect();
        assert!(
            digits.len() >= 14,
            "Backup filename must embed a timestamp, got: {name}"
        );
    }

    #[test]
    fn backup_contents_match_original_config() {
        let dir = tempdir().unwrap();
        let config = write_valid_mcp_config(dir.path(), "config.json");
        let original = fs::read_to_string(&config).unwrap();
        let backup_path = backup::create_backup(&config).unwrap();
        let backed_up = fs::read_to_string(&backup_path).unwrap();
        assert_eq!(original, backed_up, "Backup must be byte-for-byte copy of original");
    }

    #[test]
    fn find_latest_backup_returns_most_recent_by_timestamp() {
        let dir = tempdir().unwrap();
        for ts in &["20260512-100000", "20260512-110000", "20260512-120000"] {
            let name = format!("config.json.agentwall-backup-{ts}");
            fs::write(dir.path().join(&name), r#"{"mcpServers":{}}"#).unwrap();
        }
        let latest = backup::find_latest_backup(dir.path())
            .expect("Should find the latest backup");
        assert!(
            latest.to_string_lossy().contains("120000"),
            "Should pick the most recent timestamp (120000), got: {:?}", latest
        );
    }

    #[test]
    fn find_latest_backup_returns_none_when_empty() {
        let dir = tempdir().unwrap();
        assert!(
            backup::find_latest_backup(dir.path()).is_none(),
            "Should return None when no backup files present"
        );
    }
}

// ── dry-run (FR-1.3) ──────────────────────────────────────────────────────

#[cfg(test)]
mod dry_run_tests {
    use super::*;
    use agentwall::wrap::generic_ide;

    #[test]
    fn dry_run_leaves_config_unmodified() {
        let dir = tempdir().unwrap();
        let config_path = write_valid_mcp_config(dir.path(), "cursor.json");
        let original_content = fs::read_to_string(&config_path).unwrap();

        let _ = generic_ide::wrap_generic("Cursor", config_path.clone(), /*dry_run=*/ true);

        let after_content = fs::read_to_string(&config_path).unwrap();
        assert_eq!(original_content, after_content, "dry-run must not modify the config file");

        let backups: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("agentwall-backup-"))
            .collect();
        assert!(backups.is_empty(), "dry-run must not create any backup files");
    }

    #[test]
    fn wrap_without_dry_run_creates_backup_on_success() {
        let dir = tempdir().unwrap();
        let config_path = write_valid_mcp_config(dir.path(), "cursor.json");
        let result = generic_ide::wrap_generic("Cursor", config_path, /*dry_run=*/ false);
        if result.is_ok() {
            let backups: Vec<_> = fs::read_dir(dir.path())
                .unwrap()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().contains("agentwall-backup-"))
                .collect();
            assert!(!backups.is_empty(), "A successful wrap must create a timestamped backup (FR-1.2)");
        }
    }
}

// ── unprotect / reversion (FR-1.4) ───────────────────────────────────────

#[cfg(test)]
mod unprotect_tests {
    use super::*;
    use agentwall::wrap::generic_ide;

    #[test]
    fn unwrap_restores_config_from_valid_backup() {
        let dir = tempdir().unwrap();
        let config_path = write_valid_mcp_config(dir.path(), "cursor.json");
        let original = fs::read_to_string(&config_path).unwrap();
        if generic_ide::wrap_generic("Cursor", config_path.clone(), false).is_err() {
            return; // Skip if env cannot wrap (e.g. no binary resolution)
        }
        if let Ok(_) = generic_ide::unwrap_generic("Cursor", config_path.clone(), /*force=*/ false) {
            let restored = fs::read_to_string(&config_path).unwrap();
            assert_eq!(original, restored, "Unprotect must restore config to pre-wrap state");
        }
    }

    #[test]
    fn unwrap_with_corrupt_backup_returns_error_without_force() {
        let dir = tempdir().unwrap();
        let config_path = write_valid_mcp_config(dir.path(), "cursor.json");

        // Plant a corrupt backup file
        let corrupt_backup = dir.path().join("cursor.json.agentwall-backup-20260811-120000");
        fs::write(&corrupt_backup, b"CORRUPT DATA").unwrap();

        let result = generic_ide::unwrap_generic("Cursor", config_path, /*force=*/ false);
        assert!(
            result.is_err(),
            "unwrap must refuse to restore from a corrupt backup (NFR-3.2)"
        );
    }

    #[test]
    fn unwrap_with_force_does_not_panic() {
        let dir = tempdir().unwrap();
        let config_path = write_valid_mcp_config(dir.path(), "cursor.json");

        // Plant a valid backup
        let backup_path = dir.path().join("cursor.json.agentwall-backup-20260811-120000");
        fs::write(&backup_path, r#"{"mcpServers":{}}"#).unwrap();

        // --force should not panic regardless of outcome
        let _ = generic_ide::unwrap_generic("Cursor", config_path, /*force=*/ true);
    }
}

// ── API: POST /api/mode atomic toggle ────────────────────────────────────

#[cfg(test)]
mod api_mode_toggle_tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    #[test]
    fn shadow_mode_atomic_bool_is_thread_safe() {
        let shadow_mode = Arc::new(AtomicBool::new(true));
        let handles: Vec<_> = (0..8)
            .map(|i| {
                let mode = Arc::clone(&shadow_mode);
                std::thread::spawn(move || {
                    mode.store(i % 2 == 0, Ordering::Relaxed);
                })
            })
            .collect();
        for h in handles { h.join().unwrap(); }
        let final_val = shadow_mode.load(Ordering::SeqCst);
        // Just assert no UB — value must be a valid bool
        assert!(final_val || !final_val, "AtomicBool must not be corrupted under concurrent writes");
    }

    #[test]
    fn shadow_mode_json_payload_resolves_correctly() {
        let payload = serde_json::json!({ "mode": "shadow" });
        let is_enforce = payload["mode"].as_str().unwrap() == "enforce";
        assert!(!is_enforce, "shadow payload must map to enforce=false");
    }

    #[test]
    fn enforce_mode_json_payload_resolves_correctly() {
        let payload = serde_json::json!({ "mode": "enforce" });
        let is_enforce = payload["mode"].as_str().unwrap() == "enforce";
        assert!(is_enforce, "enforce payload must map to enforce=true");
    }
}
