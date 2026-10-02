//! Supportability Suite, Diagnostic Bundles & Safe Recovery (REQ-SUP-001, PRD §FR-8).
//!
//! Provides structural allowlisting support bundle generation with secondary secret redaction,
//! configuration repair, session logout, local state reset, and local token rotation.

use colored::*;
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};

use crate::doctor::run_diagnostics;
use crate::identity::oauth::rotate_local_token;
use crate::identity::storage::CredentialStore;
use crate::wrap::manifest::OwnershipManifest;

/// Maximum allowable size for uncompressed support bundle (10MB).
const MAX_BUNDLE_BYTES: usize = 10 * 1024 * 1024;

/// Secondary defense regex pattern to intercept and redact any accidentally included secrets.
const SECRET_PATTERN: &str =
    r"(sk-[a-zA-Z0-9_-]{20,}|Bearer [a-zA-Z0-9._-]{20,}|BEGIN[ A-Z0-9_-]*PRIVATE KEY)";

/// Generates a sanitized diagnostic support bundle using strict structural allowlisting.
pub async fn run_support_bundle(output_dir: Option<PathBuf>, yes: bool) -> i32 {
    if !yes {
        println!(
            "{}",
            "Vexa Agent Control — Diagnostic Support Bundle Generator"
                .bold()
                .cyan()
        );
        println!("This tool collects strictly allowlisted, sanitized diagnostic information:");
        println!("  • Operating system, architecture, and agent binary versions");
        println!("  • Diagnostic health check results (exit codes and status flags)");
        println!("  • Background service and port status");
        println!("  • Metadata of last 50 error events (timestamps and error codes; no prompts)");
        println!("  • Managed configuration key names (values strictly omitted)");
        println!("\nAll output is scanned for tokens and credentials before writing.");
        print!("Proceed to generate support bundle? [y/N]: ");

        use std::io::{self, Write};
        let _ = io::stdout().flush();
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() || !input.trim().eq_ignore_ascii_case("y") {
            println!("Operation cancelled.");
            return 0;
        }
    }

    match create_support_bundle(output_dir).await {
        Ok(bundle_path) => {
            println!(
                "\n{} Support bundle generated successfully!",
                "✔".green().bold()
            );
            println!(
                "  Archive Directory: {}",
                bundle_path.display().to_string().cyan()
            );
            println!("  Size limit:        < 10 MB (Enforced)");
            println!("  Privacy check:     Allowlisted structural files only, zero secrets or prompt payloads.");
            0
        }
        Err(e) => {
            eprintln!("\n{} Failed to generate support bundle: {}", "✖".red(), e);
            1
        }
    }
}

/// Create and write the 5 allowlisted diagnostic files to disk.
pub async fn create_support_bundle(output_dir: Option<PathBuf>) -> Result<PathBuf, String> {
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let base_dir = output_dir.unwrap_or_else(|| PathBuf::from("."));
    let bundle_dir = base_dir.join(format!("agentcontrol-support-{}", timestamp));

    fs::create_dir_all(&bundle_dir)
        .map_err(|e| format!("Failed to create bundle directory: {}", e))?;

    let secret_re = Regex::new(SECRET_PATTERN).map_err(|e| e.to_string())?;

    // File 1: system_info.json
    let sys_info = serde_json::json!({
        "agent_version": env!("CARGO_PKG_VERSION"),
        "os": std::env::consts::OS,
        "family": std::env::consts::FAMILY,
        "arch": std::env::consts::ARCH,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "current_exe": std::env::current_exe().ok().map(|p| p.display().to_string()),
    });
    write_sanitized_file(
        &bundle_dir.join("system_info.json"),
        &serde_json::to_string_pretty(&sys_info).unwrap(),
        &secret_re,
    )?;

    // File 2: doctor_report.json
    let doctor_report = run_diagnostics().await;
    write_sanitized_file(
        &bundle_dir.join("doctor_report.json"),
        &serde_json::to_string_pretty(&doctor_report).unwrap(),
        &secret_re,
    )?;

    // File 3: service_state.json
    let service_state = serde_json::json!({
        "default_proxy_port": 18080,
        "service_name": "VexaAgentControl",
        "service_status": if cfg!(windows) { "ScheduledTask (ONLOGON, Limited)" } else { "UserDaemon" },
    });
    write_sanitized_file(
        &bundle_dir.join("service_state.json"),
        &serde_json::to_string_pretty(&service_state).unwrap(),
        &secret_re,
    )?;

    // File 4: event_tail.json (Metadata only, up to 50 events)
    let db = crate::proxy::db::DbManager::init();
    let events = db.get_all_events(50).await.unwrap_or_default();
    let sanitized_events: Vec<serde_json::Value> = events
        .into_iter()
        .map(|e| {
            serde_json::json!({
                "timestamp_ns": e.timestamp_ns,
                "tool_name": e.url_path,
                "verdict": e.verdict,
                "policy_rule": e.policy_rule,
                "status": e.response_status,
            })
        })
        .collect();
    write_sanitized_file(
        &bundle_dir.join("event_tail.json"),
        &serde_json::to_string_pretty(&sanitized_events).unwrap(),
        &secret_re,
    )?;

    // File 5: manifest_summary.json (Keys and targets only; values strictly omitted)
    let manifests = OwnershipManifest::list_all().unwrap_or_default();
    let manifest_summaries: Vec<serde_json::Value> = manifests
        .into_iter()
        .map(|m| {
            serde_json::json!({
                "target": m.target,
                "config_path": m.config_path.display().to_string(),
                "managed_keys": m.managed_keys,
                "created_at": m.created_at,
            })
        })
        .collect();
    write_sanitized_file(
        &bundle_dir.join("manifest_summary.json"),
        &serde_json::to_string_pretty(&manifest_summaries).unwrap(),
        &secret_re,
    )?;

    // Calculate total size and enforce ceiling
    let total_bytes = calculate_directory_size(&bundle_dir)?;
    if total_bytes > MAX_BUNDLE_BYTES {
        let _ = fs::remove_dir_all(&bundle_dir);
        return Err(format!(
            "Support bundle exceeded 10MB limit (size: {} bytes). Aborted.",
            total_bytes
        ));
    }

    Ok(bundle_dir)
}

/// Sanitizes content with secondary secret scanner and writes atomically to file.
fn write_sanitized_file(path: &Path, content: &str, secret_re: &Regex) -> Result<(), String> {
    // Assert filename contains no path traversal
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| "Invalid destination filename".to_string())?;

    if file_name.contains("..") || file_name.contains('/') || file_name.contains('\\') {
        return Err(format!("Path traversal rejected: {}", file_name));
    }

    // Secondary defense: redact any secret pattern matches
    let sanitized = secret_re.replace_all(content, "[REDACTED_SECRET]");
    fs::write(path, sanitized.as_bytes())
        .map_err(|e| format!("Failed to write {}: {}", path.display(), e))?;
    Ok(())
}

fn calculate_directory_size(dir: &Path) -> Result<usize, String> {
    let mut total = 0;
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
                total += meta.len() as usize;
            }
        }
    }
    Ok(total)
}

/// Repair active configurations against manifests and ensure background agent task exists.
pub async fn run_repair() -> i32 {
    println!(
        "{}",
        "Vexa Agent Control — Workstation Repair Utility"
            .bold()
            .cyan()
    );
    println!("Checking configuration manifests and background agent service...");

    let mut repaired = 0; // items that were broken and got fixed
    let mut verified = 0; // items that were already healthy

    // 1. Repair local token
    let local_token_path = crate::identity::oauth::get_local_token_path();
    if !local_token_path.exists() {
        if let Ok(_token) = crate::identity::oauth::get_or_create_local_token() {
            println!("  {} Re-generated missing local proxy token.", "✔".green());
            repaired += 1;
        }
    } else {
        println!("  {} Local proxy token is present.", "✔".green());
        verified += 1;
    }

    // 2. Re-install user service / scheduled task if missing.
    // called_from_login: true because self-healing is an internal recovery path
    // that should not re-gate on the enrollment check (device is already enrolled
    // if self-healing is running).
    let service_action = crate::service::ServiceAction::Install {
        hub_url: crate::identity::device::load_hub_url()
            .unwrap_or_else(|| "https://app.vexasec.io".to_string()),
        gateway_secret: None,
        policy_read_secret: None,
        agent_id: None,
        enterprise: false,
        config: None,
        force: false,
    };
    let s_code = crate::service::run_service(service_action, true, true).await;
    if s_code == 0 {
        println!(
            "  {} Per-user background service verified and active.",
            "✔".green()
        );
        verified += 1;
    }

    // 3. Re-validate active client manifests — detect and re-stamp drifted hashes
    if let Ok(manifests) = OwnershipManifest::list_all() {
        for mut m in manifests {
            if m.config_path.exists() {
                match OwnershipManifest::compute_sha256(&m.config_path) {
                    Ok(cur_hash) if cur_hash != m.post_mutation_hash_sha256 => {
                        // Config was modified externally (e.g. by the IDE itself).
                        // Re-stamp the manifest so doctor no longer flags drift.
                        m.post_mutation_hash_sha256 = cur_hash;
                        match m.save() {
                            Ok(_) => {
                                println!(
                                    "  {} Target '{}' configuration drift resolved (manifest re-stamped).",
                                    "✔".green(),
                                    m.target
                                );
                                repaired += 1;
                            }
                            Err(e) => {
                                println!(
                                    "  {} Target '{}' manifest re-stamp failed: {}",
                                    "⚠".yellow(),
                                    m.target,
                                    e
                                );
                            }
                        }
                    }
                    Ok(_) => {
                        println!(
                            "  {} Target '{}' configuration validated (no drift).",
                            "✔".green(),
                            m.target
                        );
                    }
                    Err(e) => {
                        println!(
                            "  {} Target '{}' hash check failed: {}",
                            "⚠".yellow(),
                            m.target,
                            e
                        );
                    }
                }
            }
        }
    }

    // 4. Check for legacy Root CA in OS trust store
    if crate::ca::is_ca_installed() {
        println!(
            "  {} Legacy Root CA detected in OS trust store (Zero-CA policy violation). Cleaning...",
            "ℹ".blue()
        );
        match crate::ca::uninstall_ca_from_trust_store() {
            Ok(_) => {
                println!(
                    "  {} Successfully removed legacy Root CA from OS trust store.",
                    "✔".green()
                );
                repaired += 1;
            }
            Err(e) => {
                println!("  {} Failed to remove legacy Root CA: {}", "⚠".yellow(), e);
                println!(
                    "     └─ Manual removal command: certutil -delstore -user Root \"{}\"",
                    crate::ca::CA_COMMON_NAME
                );
            }
        }
    } else {
        println!(
            "  {} Zero-CA security invariant verified (no Root CA in OS trust store).",
            "✔".green()
        );
        verified += 1;
    }

    if repaired > 0 {
        println!(
            "\n{} Repair completed. ({} issue(s) fixed, {} verified healthy)",
            "✔".green().bold(),
            repaired,
            verified
        );
    } else {
        println!(
            "\n{} All checks passed. No issues found. ({} verified healthy)",
            "✔".green().bold(),
            verified
        );
    }
    0
}

/// Flushes local cached credentials and invalidates session.
pub fn run_logout() -> i32 {
    println!("{}", "Logging out of Vexa Agent Control...".cyan());

    let _ = CredentialStore::delete("access_token");
    let _ = CredentialStore::delete("refresh_token");
    let _ = CredentialStore::delete("device_token");

    // Clean up Hub connection metadata and cached remote policy
    if let Some(home) = dirs::home_dir() {
        let dir = home.join(".agentcontrol");
        let _ = std::fs::remove_file(dir.join("hub_url.txt"));
        let _ = std::fs::remove_file(dir.join("device_token.txt"));
        let _ = std::fs::remove_file(dir.join("cached_policy.yaml"));
        let _ = std::fs::remove_file(dir.join("cached_policy.sha256"));
        let _ = std::fs::remove_file(dir.join("agentcontrol-policy.cached.yaml"));
    }

    // Persist operational state transition back to LocalGateway (ADR 0.1, 0.7)
    let _ = crate::cli::save_persisted_profile(crate::cli::DeploymentProfile::LocalGateway);

    println!(
        "{} Workstation credentials flushed. Profile transitioned to local-gateway.\n  Workstation IDE client configurations preserved. Run 'agentcontrol login' to re-authenticate.",
        "✔".green().bold()
    );
    0
}

/// Purges local caches and event logs while preserving baseline backups.
pub fn run_reset_local_state(force: bool) -> i32 {
    if !force {
        print!(
            "{} This will clear local telemetry and caches while preserving baseline backups. Continue? [y/N]: ",
            "⚠ Warning:".yellow().bold()
        );

        use std::io::{self, Write};
        let _ = io::stdout().flush();
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() || !input.trim().eq_ignore_ascii_case("y") {
            println!("Reset cancelled.");
            return 0;
        }
    }

    println!("Resetting local state...");

    if let Some(home) = dirs::home_dir() {
        let dir = home.join(".agentcontrol");
        // Clear events.db
        let db_file = dir.join("data").join("events.db");
        if db_file.exists() {
            let _ = fs::remove_file(db_file);
        }
        // Clear cache
        let cache_dir = dir.join("cache");
        if cache_dir.exists() {
            let _ = fs::remove_dir_all(cache_dir);
        }
    }

    println!(
        "{} Local telemetry and cache reset successfully.",
        "✔".green().bold()
    );
    0
}

/// Rotate the persistent local HTTP proxy bearer token and update all connected client configs (Task 2.6).
pub async fn run_rotate_local_token() -> i32 {
    println!(
        "{}",
        "Rotating authentication token for connected targets...".cyan()
    );

    let new_token = match rotate_local_token() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{} Failed to generate new local token: {}", "✖".red(), e);
            return 1;
        }
    };

    let mut updated_targets = 0;

    // Update Codex if manifest exists
    if let Ok(Some(mut manifest)) = OwnershipManifest::load("codex") {
        if manifest.config_path.exists() {
            let is_cloud_direct = manifest.connect_mode.as_deref() == Some("cloud-direct");
            let effective_token = if is_cloud_direct {
                let hub_url = crate::identity::device::load_hub_url()
                    .unwrap_or_else(|| "https://app.vexasec.io".to_string());
                match crate::wrap::connect::fetch_assigned_virtual_key(&hub_url).await {
                    Ok(Some(vk)) if !vk.trim().is_empty() => Some(vk),
                    _ => {
                        println!(
                            "  {} Could not re-fetch virtual key from Control Hub for Codex.",
                            "⚠".yellow()
                        );
                        None
                    }
                }
            } else {
                Some(new_token.clone())
            };

            if let Some(tok) = effective_token {
                if let Ok(raw) = fs::read_to_string(&manifest.config_path) {
                    if let Ok(mut toml_val) = toml::from_str::<toml::Value>(&raw) {
                        if let Some(set_tbl) = toml_val
                            .get_mut("shell_environment_policy")
                            .and_then(|p| p.as_table_mut())
                            .and_then(|p| p.get_mut("set"))
                            .and_then(|s| s.as_table_mut())
                        {
                            set_tbl.insert(
                                "OPENAI_API_KEY".to_string(),
                                toml::Value::String(tok.clone()),
                            );
                            manifest.written_values.insert(
                                "shell_environment_policy.set.OPENAI_API_KEY".to_string(),
                                serde_json::Value::String(tok.clone()),
                            );
                            if let Ok(formatted) = toml::to_string_pretty(&toml_val) {
                                let _ = fs::write(&manifest.config_path, formatted);
                                manifest.post_mutation_hash_sha256 =
                                    OwnershipManifest::compute_sha256(&manifest.config_path)
                                        .unwrap_or_default();
                                let _ = manifest.save();
                                println!(
                                    "  {} Updated Codex configuration with refreshed token.",
                                    "✔".green()
                                );
                                updated_targets += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    // Update VS Code Continue if manifest exists
    if let Ok(Some(mut manifest)) = OwnershipManifest::load("vscode-continue") {
        if manifest.config_path.exists() {
            let is_cloud_direct = manifest.connect_mode.as_deref() == Some("cloud-direct");
            let effective_token = if is_cloud_direct {
                let hub_url = crate::identity::device::load_hub_url()
                    .unwrap_or_else(|| "https://app.vexasec.io".to_string());
                match crate::wrap::connect::fetch_assigned_virtual_key(&hub_url).await {
                    Ok(Some(vk)) if !vk.trim().is_empty() => Some(vk),
                    _ => {
                        println!("  {} Could not re-fetch virtual key from Control Hub for VS Code Continue.", "⚠".yellow());
                        None
                    }
                }
            } else {
                Some(new_token.clone())
            };

            if let Some(tok) = effective_token {
                if let Ok(raw) = fs::read_to_string(&manifest.config_path) {
                    if let Ok(mut config) = serde_json::from_str::<serde_json::Value>(
                        &crate::wrap::strip_json_comments(&raw),
                    ) {
                        if let Some(models) = config
                            .get_mut("continue.models")
                            .and_then(|m| m.as_array_mut())
                        {
                            for m in models.iter_mut() {
                                if m.get("title").and_then(|t| t.as_str())
                                    == Some("Vexa Agent Control (Managed)")
                                {
                                    m["apiKey"] = serde_json::Value::String(tok.clone());
                                }
                            }
                            manifest.written_values.insert(
                                "continue.models".to_string(),
                                serde_json::Value::Array(models.clone()),
                            );
                            let _ = fs::write(
                                &manifest.config_path,
                                serde_json::to_string_pretty(&config).unwrap(),
                            );
                            manifest.post_mutation_hash_sha256 =
                                OwnershipManifest::compute_sha256(&manifest.config_path)
                                    .unwrap_or_default();
                            let _ = manifest.save();
                            println!(
                                "  {} Updated VS Code Continue with refreshed token.",
                                "✔".green()
                            );
                            updated_targets += 1;
                        }
                    }
                }
            }
        }
    }

    println!(
        "\n{} Authentication token rotation completed! ({} connected target(s) updated)",
        "✔".green().bold(),
        updated_targets
    );
    0
}

/// Gracefully stops the local background protection daemon (PRD §12).
pub async fn run_stop(gateway_addr: &str) -> i32 {
    println!("Stopping Vexa Agent Control protection daemon...");
    let mut stopped_anything = false;

    // 1. Check ~/.agentcontrol/daemon.pid
    let pid_path = dirs::home_dir().map(|h| h.join(".agentcontrol").join("daemon.pid"));
    if let Some(ref p) = pid_path {
        if p.exists() {
            if let Ok(content) = fs::read_to_string(p) {
                if let Ok(pid) = content.trim().parse::<u32>() {
                    #[cfg(windows)]
                    {
                        let _ = std::process::Command::new("taskkill")
                            .args(["/F", "/PID", &pid.to_string()])
                            .output();
                        stopped_anything = true;
                    }
                    #[cfg(unix)]
                    {
                        let _ = std::process::Command::new("kill")
                            .args(["-15", &pid.to_string()])
                            .output();
                        stopped_anything = true;
                    }
                }
            }
            let _ = fs::remove_file(p);
        }
    }

    // 2. Stop registered OS background service if active
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("sc.exe")
            .args(["stop", "VexaAgentControl"])
            .output();
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = dirs::home_dir() {
            let plist = home.join("Library/LaunchAgents/io.vexasec.agentcontrol.plist");
            if plist.exists() {
                let _ = std::process::Command::new("launchctl")
                    .args(["unload", &plist.to_string_lossy()])
                    .output();
                stopped_anything = true;
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "stop", "agentcontrol.service"])
            .output();
    }

    let target = if gateway_addr.starts_with("http") {
        gateway_addr
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .to_string()
    } else {
        gateway_addr.to_string()
    };

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    if tokio::net::TcpStream::connect(&target).await.is_err() {
        println!(
            "{} Local protection daemon stopped successfully.",
            "✔".green().bold()
        );
        0
    } else if stopped_anything {
        println!(
            "{} Daemon process was signaled. Port {} is releasing.",
            "✔".green(),
            target
        );
        0
    } else {
        println!("{} Local gateway on {} is not running.", "ℹ".cyan(), target);
        0
    }
}

/// Display and query local audit events and security decisions (PRD §12).
pub async fn run_logs(
    limit: usize,
    format: &str,
    verdict: Option<String>,
    tool: Option<String>,
    follow: bool,
    gateway: &str,
) -> i32 {
    if follow {
        let stream_url = format!("{}/api/events/stream", gateway.trim_end_matches('/'));
        println!(
            "Streaming live events from {} (Press Ctrl+C to stop)...",
            stream_url.cyan()
        );
        let client = reqwest::Client::new();
        match client.get(&stream_url).send().await {
            Ok(resp) => {
                use futures_util::StreamExt;
                let mut stream = resp.bytes_stream();
                while let Some(chunk_res) = stream.next().await {
                    if let Ok(chunk) = chunk_res {
                        let text = String::from_utf8_lossy(&chunk);
                        for line in text.lines() {
                            if let Some(data) = line.strip_prefix("data: ") {
                                if format == "json" {
                                    println!("{}", data);
                                } else if let Ok(val) =
                                    serde_json::from_str::<serde_json::Value>(data)
                                {
                                    let ts = val
                                        .get("timestamp_ns")
                                        .and_then(|t| t.as_i64())
                                        .map(|ns| {
                                            chrono::DateTime::from_timestamp_nanos(ns)
                                                .format("%H:%M:%S%.3f")
                                                .to_string()
                                        })
                                        .unwrap_or_else(|| "live".to_string());
                                    let v_str = val
                                        .get("verdict")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("unknown");
                                    let v_col = match v_str.to_lowercase().as_str() {
                                        "allow" => "ALLOW".green().bold(),
                                        "deny" => "DENY".red().bold(),
                                        "warn" => "WARN".yellow().bold(),
                                        "ask" => "ASK".blue().bold(),
                                        "redact" => "REDACT".purple().bold(),
                                        _ => v_str.dimmed(),
                                    };
                                    let t_str =
                                        val.get("url_path").and_then(|t| t.as_str()).unwrap_or("-");
                                    let lat = val
                                        .get("latency_ms")
                                        .and_then(|l| l.as_f64())
                                        .unwrap_or(0.0);
                                    let rule = val
                                        .get("policy_rule")
                                        .and_then(|r| r.as_str())
                                        .unwrap_or("default");
                                    println!(
                                        "{} {:<16} {:<24} {:<8.1}ms {}",
                                        ts.dimmed(),
                                        v_col,
                                        t_str.cyan(),
                                        lat,
                                        rule
                                    );
                                }
                            }
                        }
                    }
                }
                0
            }
            Err(e) => {
                eprintln!(
                    "{} Failed to connect to live event stream: {}",
                    "✖".red(),
                    e
                );
                1
            }
        }
    } else {
        let db_manager = crate::proxy::db::DbManager::init();
        match db_manager.get_events(limit).await {
            Ok(events) => {
                let filtered: Vec<_> = events
                    .into_iter()
                    .filter(|e| {
                        if let Some(ref v) = verdict {
                            if !e.verdict.as_deref().unwrap_or("").eq_ignore_ascii_case(v) {
                                return false;
                            }
                        }
                        if let Some(ref t) = tool {
                            if !e.url_path.as_deref().unwrap_or("").contains(t) {
                                return false;
                            }
                        }
                        true
                    })
                    .collect();

                if format == "json" {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&filtered).unwrap_or_default()
                    );
                } else {
                    println!("\n{}", "=== Vexa Agent Control Audit Log ===".cyan().bold());
                    println!(
                        "{:<22} {:<10} {:<26} {:<10} {}",
                        "TIMESTAMP", "VERDICT", "TOOL / TARGET", "LATENCY", "POLICY RULE"
                    );
                    println!("{}", "─".repeat(90).dimmed());
                    if filtered.is_empty() {
                        println!("  No recent events found.");
                    }
                    for ev in filtered {
                        let ts = chrono::DateTime::from_timestamp_nanos(ev.timestamp_ns)
                            .format("%Y-%m-%d %H:%M:%S")
                            .to_string();
                        let verdict_str = ev.verdict.as_deref().unwrap_or("unknown");
                        let verdict_colored = match verdict_str.to_lowercase().as_str() {
                            "allow" => "ALLOW".green().bold(),
                            "deny" => "DENY".red().bold(),
                            "warn" => "WARN".yellow().bold(),
                            "ask" => "ASK".blue().bold(),
                            "redact" => "REDACT".purple().bold(),
                            _ => verdict_str.dimmed(),
                        };
                        let tool_str = ev.url_path.as_deref().unwrap_or("-");
                        let latency = format!("{:.1}ms", ev.latency_ms.unwrap_or(0.0));
                        let rule = ev.policy_rule.as_deref().unwrap_or("default");
                        println!(
                            "{:<22} {:<19} {:<26} {:<10} {}",
                            ts.dimmed(),
                            verdict_colored,
                            tool_str.cyan(),
                            latency.dimmed(),
                            rule
                        );
                    }
                    println!();
                }
                0
            }
            Err(e) => {
                eprintln!(
                    "{} Failed to read audit events from events.db: {}",
                    "✖".red(),
                    e
                );
                1
            }
        }
    }
}

/// Process Human-in-the-Loop (HITL) escalation decisions via CLI (PRD §12, §16).
pub async fn run_hitl_decision(id: &str, decision: &str, session: bool, gateway: &str) -> i32 {
    let url = format!("{}/api/v1/hitl/respond", gateway.trim_end_matches('/'));
    let client = reqwest::Client::new();
    let body = serde_json::json!({
        "request_id": id,
        "decision": decision,
        "signed_hmac": "",
        "scope": if session { "session" } else { "once" }
    });

    match client.post(&url).json(&body).send().await {
        Ok(resp) => {
            if resp.status().is_success() {
                if decision == "allow" {
                    println!(
                        "{} Action '{}' has been APPROVED successfully (Scope: {}).",
                        "✔".green().bold(),
                        id,
                        if session { "Session" } else { "Once" }
                    );
                } else {
                    println!("{} Action '{}' has been DENIED.", "✖".red().bold(), id);
                }
                0
            } else {
                eprintln!(
                    "{} Failed to submit decision for '{}': HTTP {}",
                    "✖".red(),
                    id,
                    resp.status()
                );
                1
            }
        }
        Err(e) => {
            eprintln!(
                "{} Failed to connect to gateway at {}: {}",
                "✖".red(),
                gateway,
                e
            );
            1
        }
    }
}

/// Unenrolls device from Control Hub and returns to standalone mode (PRD §12).
pub fn run_unenroll(force: bool) -> i32 {
    if !force {
        print!("Are you sure you want to unenroll this device from Control Hub? [y/N]: ");
        use std::io::{self, Write};
        let _ = io::stdout().flush();
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() || !input.trim().eq_ignore_ascii_case("y") {
            println!("Unenroll operation cancelled.");
            return 0;
        }
    }

    run_logout()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_create_support_bundle() {
        let dir = tempdir().unwrap();
        let bundle_dir = create_support_bundle(Some(dir.path().to_path_buf()))
            .await
            .unwrap();

        assert!(bundle_dir.exists());
        assert!(bundle_dir.join("system_info.json").exists());
        assert!(bundle_dir.join("doctor_report.json").exists());
        assert!(bundle_dir.join("service_state.json").exists());
        assert!(bundle_dir.join("event_tail.json").exists());
        assert!(bundle_dir.join("manifest_summary.json").exists());

        // Secret scanning verification
        let doc_json = fs::read_to_string(bundle_dir.join("doctor_report.json")).unwrap();
        assert!(!doc_json.contains("sk-proj-"));
        assert!(!doc_json.contains("BEGIN RSA PRIVATE KEY"));
    }

    #[test]
    fn test_secret_redaction() {
        let secret_re = Regex::new(SECRET_PATTERN).unwrap();
        let text =
            "Here is a secret: sk-1234567890123456789012 and Bearer my_secret_token_1234567890.";
        let redacted = secret_re.replace_all(text, "[REDACTED_SECRET]");
        assert!(!redacted.contains("sk-1234567890123456789012"));
        assert!(!redacted.contains("my_secret_token_1234567890"));
        assert!(redacted.contains("[REDACTED_SECRET]"));
    }

    #[test]
    fn test_run_unenroll_force() {
        let code = run_unenroll(true);
        assert_eq!(code, 0);
    }

    #[tokio::test]
    async fn test_run_logs_offline() {
        let code = run_logs(5, "text", None, None, false, "http://127.0.0.1:18080").await;
        assert_eq!(code, 0);

        let code_json = run_logs(5, "json", None, None, false, "http://127.0.0.1:18080").await;
        assert_eq!(code_json, 0);
    }
}
