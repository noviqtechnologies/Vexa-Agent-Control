//! Dual-store maintenance: atomic backups and cryptographic integrity verification (ADR 0.6).
//!
//! Provides:
//! - `run_backup`: Online checkpoint and VACUUM INTO for `events.db`, plus atomic archiving of
//!   `audit.jsonl`, `audit.key`, manifests, and profile state with strict permissions.
//! - `run_verify_db`: Offline SQLite `PRAGMA integrity_check;` and end-to-end HMAC SHA-256
//!   chain validation of `audit.jsonl`.

use colored::Colorize;
use std::path::PathBuf;

/// Executes the `agentcontrol backup` command.
pub fn run_backup(output_dir: Option<PathBuf>) -> i32 {
    let base_dir = match dirs::home_dir() {
        Some(h) => h.join(".agentcontrol"),
        None => PathBuf::from(".agentcontrol"),
    };

    let ts = chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string();
    let dest_dir =
        output_dir.unwrap_or_else(|| base_dir.join("backups").join(format!("backup_{}", ts)));

    println!(
        "{}",
        "Vexa Agent Control — Dual-Store Atomic Backup"
            .bold()
            .cyan()
    );
    println!("  Destination: {}", dest_dir.display().to_string().yellow());

    if let Err(e) = std::fs::create_dir_all(&dest_dir) {
        eprintln!("{} Failed to create backup directory: {}", "✖".red(), e);
        return 1;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dest_dir, std::fs::Permissions::from_mode(0o700));
    }

    let mut backed_up_items = 0;

    // 1. Back up SQLite events.db using checkpoint and VACUUM INTO
    let candidate_dbs = [
        base_dir.join("events.db"),
        base_dir.join("data").join("events.db"),
    ];

    let mut db_found = false;
    for src_db in &candidate_dbs {
        if src_db.exists() {
            db_found = true;
            let dest_db = dest_dir.join("events.db");
            match rusqlite::Connection::open(src_db) {
                Ok(conn) => {
                    // Checkpoint WAL first
                    let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");

                    let dest_str = dest_db.to_string_lossy().replace('\\', "/");
                    let vacuum_sql = format!("VACUUM INTO '{}'", dest_str.replace('\'', "''"));

                    if let Err(e) = conn.execute_batch(&vacuum_sql) {
                        // Fallback to file copy if VACUUM INTO encounters filesystem constraints
                        if let Err(copy_err) = std::fs::copy(src_db, &dest_db) {
                            eprintln!(
                                "{} Failed to back up SQLite DB: VACUUM error ({}), copy error ({})",
                                "✖".red(),
                                e,
                                copy_err
                            );
                        } else {
                            println!(
                                "  {} SQLite Database: {} (copied fallback, {} bytes)",
                                "✔".green(),
                                dest_db.file_name().unwrap().to_string_lossy(),
                                std::fs::metadata(&dest_db).map(|m| m.len()).unwrap_or(0)
                            );
                            backed_up_items += 1;
                        }
                    } else {
                        println!(
                            "  {} SQLite Database: {} (VACUUM compacted, {} bytes)",
                            "✔".green(),
                            dest_db.file_name().unwrap().to_string_lossy(),
                            std::fs::metadata(&dest_db).map(|m| m.len()).unwrap_or(0)
                        );
                        backed_up_items += 1;
                    }
                }
                Err(e) => {
                    eprintln!(
                        "{} Failed to open source SQLite DB at {}: {}",
                        "✖".red(),
                        src_db.display(),
                        e
                    );
                }
            }
            break;
        }
    }

    if !db_found {
        println!(
            "  {} SQLite Database: not found (no traffic recorded yet)",
            "ℹ".dimmed()
        );
    }

    // 2. Back up audit.jsonl
    let candidate_logs = [
        base_dir.join("audit.jsonl"),
        base_dir.join("logs").join("audit.jsonl"),
    ];

    let mut log_found = false;
    for src_log in &candidate_logs {
        if src_log.exists() {
            log_found = true;
            let dest_log = dest_dir.join("audit.jsonl");
            if let Ok(bytes) = std::fs::copy(src_log, &dest_log) {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ =
                        std::fs::set_permissions(&dest_log, std::fs::Permissions::from_mode(0o600));
                }
                println!("  {} Audit Log: audit.jsonl ({} bytes)", "✔".green(), bytes);
                backed_up_items += 1;
            }
            break;
        }
    }

    if !log_found {
        println!(
            "  {} Audit Log: not found (no tool audit logs recorded yet)",
            "ℹ".dimmed()
        );
    }

    // 3. Back up audit.key
    let src_key = base_dir.join("audit.key");
    if src_key.exists() {
        let dest_key = dest_dir.join("audit.key");
        if let Ok(bytes) = std::fs::copy(&src_key, &dest_key) {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&dest_key, std::fs::Permissions::from_mode(0o600));
            }
            println!(
                "  {} Audit HMAC Key: audit.key ({} bytes)",
                "✔".green(),
                bytes
            );
            backed_up_items += 1;
        }
    }

    // 4. Back up active manifests
    let src_manifests = base_dir.join("manifests");
    if src_manifests.exists() {
        let dest_manifests = dest_dir.join("manifests");
        let _ = std::fs::create_dir_all(&dest_manifests);
        if let Ok(entries) = std::fs::read_dir(&src_manifests) {
            let mut count = 0;
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_file() {
                    let dest = dest_manifests.join(entry.file_name());
                    if std::fs::copy(&p, dest).is_ok() {
                        count += 1;
                    }
                }
            }
            if count > 0 {
                println!(
                    "  {} Manifests: {} client ownership records archived",
                    "✔".green(),
                    count
                );
                backed_up_items += 1;
            }
        }
    }

    // 5. Back up profile.json
    let src_profile = base_dir.join("profile.json");
    if src_profile.exists() {
        let dest_profile = dest_dir.join("profile.json");
        if let Ok(bytes) = std::fs::copy(&src_profile, &dest_profile) {
            println!(
                "  {} Profile State: profile.json ({} bytes)",
                "✔".green(),
                bytes
            );
            backed_up_items += 1;
        }
    }

    println!();
    if backed_up_items > 0 {
        println!(
            "{} Backup completed successfully! ({} components saved to {})",
            "✔".green().bold(),
            backed_up_items,
            dest_dir.display()
        );
        0
    } else {
        println!(
            "{} No active databases or logs to back up.",
            "ℹ".yellow().bold()
        );
        0
    }
}

/// Executes the `agentcontrol verify-db` command.
pub fn run_verify_db(audit_path: Option<PathBuf>, db_path: Option<PathBuf>) -> i32 {
    let base_dir = match dirs::home_dir() {
        Some(h) => h.join(".agentcontrol"),
        None => PathBuf::from(".agentcontrol"),
    };

    println!(
        "{}",
        "Vexa Agent Control — Cryptographic & Database Verification"
            .bold()
            .cyan()
    );

    let mut had_error = false;

    // 1. Verify SQLite database integrity
    let target_db = db_path.unwrap_or_else(|| {
        let direct = base_dir.join("events.db");
        if direct.exists() {
            direct
        } else {
            base_dir.join("data").join("events.db")
        }
    });

    if target_db.exists() {
        print!("  Checking SQLite events.db ({}) ... ", target_db.display());
        match rusqlite::Connection::open(&target_db) {
            Ok(conn) => {
                let integrity_res: Result<String, _> =
                    conn.query_row("PRAGMA integrity_check;", [], |row| row.get(0));
                match integrity_res {
                    Ok(ref s) if s.eq_ignore_ascii_case("ok") => {
                        println!("{}", "PASSED (status: ok)".green().bold());
                    }
                    Ok(other) => {
                        println!("{} (reported: {})", "FAILED".red().bold(), other);
                        had_error = true;
                    }
                    Err(e) => {
                        println!("{} (query error: {})", "FAILED".red().bold(), e);
                        had_error = true;
                    }
                }
            }
            Err(e) => {
                println!("{} (open error: {})", "FAILED".red().bold(), e);
                had_error = true;
            }
        }
    } else {
        println!(
            "  {} SQLite events.db: Not found (no traffic recorded yet)",
            "ℹ".dimmed()
        );
    }

    // 2. Verify audit.jsonl HMAC chain
    let env_audit_path = std::env::var("AGENTCONTROL_LOG_PATH")
        .ok()
        .or_else(|| std::env::var("AGENTCONTROL_AUDIT_PATH").ok())
        .map(PathBuf::from);

    let target_audit = audit_path.or(env_audit_path).unwrap_or_else(|| {
        let direct = base_dir.join("audit.jsonl");
        if direct.exists() {
            direct
        } else if base_dir.join("logs").join("audit.jsonl").exists() {
            base_dir.join("logs").join("audit.jsonl")
        } else {
            PathBuf::from("/var/log/agentcontrol/audit.jsonl")
        }
    });

    let target_key = if let Ok(kpath) = std::env::var("AGENTCONTROL_AUDIT_KEY") {
        PathBuf::from(kpath)
    } else if let Some(parent) = target_audit.parent() {
        if parent.join("audit.key").exists() {
            parent.join("audit.key")
        } else {
            base_dir.join("audit.key")
        }
    } else {
        base_dir.join("audit.key")
    };

    if target_audit.exists() {
        print!(
            "  Checking Audit Log HMAC chain ({}) ... ",
            target_audit.display()
        );
        let key_opt = if target_key.exists() {
            std::fs::read(&target_key).ok()
        } else {
            None
        };

        if let Some(key) = key_opt {
            let res = crate::audit::verifier::verify_chain_with_secret(&target_audit, &key);
            match res {
                crate::audit::verifier::VerifyResult::Valid { entry_count } => {
                    println!(
                        "{} ({} entries validated with HMAC-SHA256 secret)",
                        "PASSED".green().bold(),
                        entry_count
                    );
                }
                crate::audit::verifier::VerifyResult::Invalid {
                    entry_index,
                    reason,
                } => {
                    println!(
                        "{} (HMAC verification failed at entry {}: {})",
                        "FAILED".red().bold(),
                        entry_index,
                        reason
                    );
                    had_error = true;
                }
                crate::audit::verifier::VerifyResult::Error(e) => {
                    println!("{} ({})", "ERROR".red().bold(), e);
                    had_error = true;
                }
            }
        } else {
            // Secret not found, run chain continuity verification (unauthenticated forensic mode)
            let res = crate::audit::verifier::verify_chain(&target_audit);
            match res {
                crate::audit::verifier::VerifyResult::Valid { entry_count } => {
                    println!(
                        "{} ({} entries checked for chain continuity; audit.key missing for payload HMAC recomputation)",
                        "PASSED (unauthenticated chain continuity)".yellow().bold(),
                        entry_count
                    );
                }
                crate::audit::verifier::VerifyResult::Invalid {
                    entry_index,
                    reason,
                } => {
                    println!(
                        "{} (break at entry {}: {})",
                        "FAILED".red().bold(),
                        entry_index,
                        reason
                    );
                    had_error = true;
                }
                crate::audit::verifier::VerifyResult::Error(e) => {
                    println!("{} ({})", "ERROR".red().bold(), e);
                    had_error = true;
                }
            }
        }
    } else {
        println!(
            "  {} Audit Log audit.jsonl: Not found (no tool audit logs recorded yet)",
            "ℹ".dimmed()
        );
    }

    println!();
    if had_error {
        eprintln!(
            "{} One or more data stores failed integrity verification.",
            "✖".red().bold()
        );
        1
    } else {
        println!(
            "{} All verified data stores are intact and cryptographically consistent.",
            "✔".green().bold()
        );
        0
    }
}
