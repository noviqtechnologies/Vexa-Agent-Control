//! Generic wrap/unwrap orchestration for standard IDEs (Cursor, VS Code, etc.)

use colored::*;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use super::claude::{UnwrapResult, WrapResult};
use super::{backup, transformer, WrapError};

pub fn wrap_generic(
    ide_name: &str,
    config_path: PathBuf,
    dry_run: bool,
) -> Result<WrapResult, WrapError> {
    if ide_name == "Cursor" {
        let _ = wrap_cursor_settings(dry_run);
    }
    if !config_path.exists() {
        return Err(WrapError::ConfigNotFound(config_path.display().to_string()));
    }

    let is_toml = config_path.extension().and_then(|e| e.to_str()) == Some("toml");
    let raw = fs::read_to_string(&config_path).map_err(WrapError::Io)?;

    let agentcontrol_bin = std::env::current_exe()
        .map_err(|e| WrapError::NoBinaryPath(e.to_string()))?
        .to_string_lossy()
        .to_string();

    if is_toml {
        let mut toml_val: toml::Value = toml::from_str(&raw)
            .map_err(|e| WrapError::InvalidJson(format!("invalid TOML: {}", e)))?;

        let table = toml_val
            .get_mut("mcp_servers")
            .and_then(|v| v.as_table_mut())
            .ok_or(WrapError::NoMcpServers)?;

        if table.is_empty() {
            return Err(WrapError::NoMcpServers);
        }

        let mut wrapped_count = 0;
        for (_name, server) in table.iter_mut() {
            if let Some(srv_table) = server.as_table_mut() {
                let current_cmd = srv_table
                    .get("command")
                    .and_then(|c| c.as_str())
                    .unwrap_or("");
                if current_cmd.to_lowercase().contains("agentcontrol") || current_cmd.to_lowercase().contains("agentwall") {
                    continue; // already wrapped
                }

                let orig_args = srv_table
                    .get("args")
                    .and_then(|a| a.as_array())
                    .cloned()
                    .unwrap_or_default();
                let mut new_args = vec![
                    toml::Value::String("stdio-proxy".to_string()),
                    toml::Value::String("--".to_string()),
                    toml::Value::String(current_cmd.to_string()),
                ];
                for arg in orig_args {
                    new_args.push(arg);
                }

                srv_table.insert(
                    "command".to_string(),
                    toml::Value::String(agentcontrol_bin.clone()),
                );
                srv_table.insert("args".to_string(), toml::Value::Array(new_args));
                wrapped_count += 1;
            }
        }

        if wrapped_count == 0 {
            return Err(WrapError::AlreadyWrapped);
        }

        if dry_run {
            println!(
                "{} {}",
                "🔍".blue(),
                format!("DRY-RUN MODE — no changes will be written for {}", ide_name)
                    .yellow()
                    .bold()
            );
            return Ok(WrapResult {
                config_path,
                backup_path: PathBuf::from("<dry-run: no backup created>"),
                servers_wrapped: wrapped_count,
                scan_responses: false,
            });
        }

        let backup_path = backup::create_backup(&config_path)?;
        if let Some(dir) = config_path.parent() {
            let _ = backup::prune_backups(dir, 5);
        }

        let output_str =
            toml::to_string_pretty(&toml_val).map_err(|e| WrapError::InvalidJson(e.to_string()))?;
        atomic_write(&config_path, &output_str)?;

        Ok(WrapResult {
            config_path,
            backup_path,
            servers_wrapped: wrapped_count,
            scan_responses: false,
        })
    } else {
        let config: serde_json::Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(_) => {
                let stripped = super::strip_json_comments(&raw);
                serde_json::from_str(&stripped).map_err(|e| WrapError::InvalidJson(e.to_string()))?
            }
        };

        let servers = config
            .get("mcpServers")
            .or_else(|| config.get("context_servers"))
            .or_else(|| config.get("experimental.context_servers"))
            .and_then(|v| v.as_object())
            .ok_or(WrapError::NoMcpServers)?;

        let command_servers: Vec<&serde_json::Value> = servers
            .values()
            .filter(|v| v.get("command").and_then(|c| c.as_str()).is_some())
            .collect();

        if command_servers.is_empty() {
            return Err(WrapError::NoMcpServers);
        }

        if command_servers.iter().all(|v| transformer::is_already_wrapped(v)) {
            return Err(WrapError::AlreadyWrapped);
        }

        let mut modified = config.clone();
        let (wrapped_count, _) = transformer::wrap_all_servers(&mut modified, &agentcontrol_bin)?;

        if dry_run {
            println!(
                "{} {}",
                "🔍".blue(),
                format!("DRY-RUN MODE — no changes will be written for {}", ide_name)
                    .yellow()
                    .bold()
            );
            println!(
                "{} Config: {}",
                "  →".dimmed(),
                config_path.display().to_string().cyan()
            );
            println!(
                "{} Servers that would be wrapped: {}",
                "  →".dimmed(),
                wrapped_count.to_string().green()
            );
            return Ok(WrapResult {
                config_path,
                backup_path: PathBuf::from("<dry-run: no backup created>"),
                servers_wrapped: wrapped_count,
                scan_responses: false,
            });
        }

        let backup_path = backup::create_backup(&config_path)?;

        if let Some(dir) = config_path.parent() {
            let _ = backup::prune_backups(dir, 5);
        }

        let output_str = serde_json::to_string_pretty(&modified)
            .map_err(|e| WrapError::InvalidJson(e.to_string()))?;
        serde_json::from_str::<serde_json::Value>(&output_str).map_err(|e| {
            let _ = fs::copy(&backup_path, &config_path);
            WrapError::InvalidJson(format!(
                "Transform produced invalid JSON: {}. Restored from backup.",
                e
            ))
        })?;

        atomic_write(&config_path, &output_str)?;

        Ok(WrapResult {
            config_path,
            backup_path,
            servers_wrapped: wrapped_count,
            scan_responses: false,
        })
    }
}

pub fn unwrap_generic(
    ide_name: &str,
    config_path: PathBuf,
    force: bool,
) -> Result<UnwrapResult, WrapError> {
    if ide_name == "Cursor" {
        let _ = unwrap_cursor_settings(force);
    }
    if !config_path.exists() {
        return Err(WrapError::ConfigNotFound(config_path.display().to_string()));
    }

    let config_dir = config_path.parent().unwrap_or(Path::new("."));

    match backup::find_latest_backup(config_dir) {
        Some(backup_path) => {
            if !force {
                backup::verify_backup_integrity(&backup_path)?;
            }
            fs::copy(&backup_path, &config_path)?;
            fs::remove_file(&backup_path)?;
            Ok(UnwrapResult {
                config_path,
                backup_path,
            })
        }
        None if force => {
            println!(
                "{} No backup found for {}. Manual cleanup instructions:",
                "⚠".yellow().bold(),
                ide_name
            );
            println!(
                "\nEdit {} and restore each mcpServer entry.",
                config_path.display().to_string().cyan()
            );
            Err(WrapError::NoBackupFound)
        }
        None => Err(WrapError::NoBackupFound),
    }
}

pub fn print_wrap_summary_generic(ide_name: &str, result: &WrapResult) {
    println!(
        "{} {}",
        "✔".green().bold(),
        format!("Vexa Agent Control wrapped {}.", ide_name).green().bold()
    );
    println!(
        "  {} Config:            {}",
        "→".dimmed(),
        result.config_path.display().to_string().cyan()
    );
    println!(
        "  {} Backup:            {}",
        "→".dimmed(),
        result.backup_path.display().to_string().cyan()
    );
    println!(
        "  {} Servers wrapped:   {}",
        "→".dimmed(),
        result.servers_wrapped.to_string().green()
    );
    println!("\n  {} Restart {} to apply changes.", "ℹ".blue(), ide_name);
}

pub fn print_unwrap_summary_generic(ide_name: &str, result: &UnwrapResult) {
    println!(
        "{} {}",
        "✔".green().bold(),
        format!("Vexa Agent Control removed from {}.", ide_name)
            .green()
            .bold()
    );
    println!(
        "  {} Config restored:   {}",
        "→".dimmed(),
        result.config_path.display().to_string().cyan()
    );
    println!(
        "  {} Backup removed:    {}",
        "→".dimmed(),
        result.backup_path.display().to_string().dimmed()
    );
    println!("\n  {} Restart {} to apply changes.", "ℹ".blue(), ide_name);
}

fn atomic_write(path: &Path, content: &str) -> Result<(), WrapError> {
    let tmp_path = path.with_extension("agentwall-tmp");
    {
        let mut f = fs::File::create(&tmp_path)?;
        f.write_all(content.as_bytes())?;
        f.sync_all()?;
    }
    fs::rename(&tmp_path, path)?;
    Ok(())
}

/// Injects proxy settings into Cursor's User/settings.json
pub fn wrap_cursor_settings(dry_run: bool) -> Result<(), WrapError> {
    if let Ok(settings_path) = super::config_path::cursor_settings_path() {
        let has_centralized_openai = std::env::var("OPENAI_API_KEY").is_ok()
            || std::env::var("AGENTCONTROL_CURSOR_MODE").ok().as_deref() == Some("byok");

        if !settings_path.exists() {
            if let Some(parent) = settings_path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            if !dry_run {
                let mut initial = serde_json::json!({
                    "http.proxy": "http://127.0.0.1:8080",
                    "cursor.general.disableHttp2": true
                });
                if has_centralized_openai {
                    initial["cursor.general.openaiApiKey"] = serde_json::json!("sk-agentcontrol-managed");
                }
                let _ = fs::write(
                    &settings_path,
                    serde_json::to_string_pretty(&initial).unwrap_or_default(),
                );
            }
            return Ok(());
        }

        let raw = fs::read_to_string(&settings_path).map_err(WrapError::Io)?;
        let mut settings: serde_json::Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(_) => {
                let stripped = super::strip_json_comments(&raw);
                serde_json::from_str(&stripped).unwrap_or(serde_json::json!({}))
            }
        };

        if !settings.is_object() {
            settings = serde_json::json!({});
        }

        let current_proxy = settings.get("http.proxy").and_then(|v| v.as_str());
        let current_h2 = settings
            .get("cursor.general.disableHttp2")
            .and_then(|v| v.as_bool());
        let current_key = settings
            .get("cursor.general.openaiApiKey")
            .and_then(|v| v.as_str());

        let already_configured = current_proxy == Some("http://127.0.0.1:8080")
            && current_h2 == Some(true)
            && (!has_centralized_openai || current_key == Some("sk-agentcontrol-managed"));

        if already_configured {
            return Ok(());
        }

        if dry_run {
            return Ok(());
        }

        let _ = backup::create_backup(&settings_path);
        settings["http.proxy"] = serde_json::json!("http://127.0.0.1:8080");
        settings["cursor.general.disableHttp2"] = serde_json::json!(true);
        if has_centralized_openai {
            settings["cursor.general.openaiApiKey"] = serde_json::json!("sk-agentcontrol-managed");
        }

        let output_str = serde_json::to_string_pretty(&settings)
            .map_err(|e| WrapError::InvalidJson(e.to_string()))?;
        atomic_write(&settings_path, &output_str)?;
    }
    Ok(())
}

/// Configures Cursor settings.json for centralized BYOK mode with sentinel key.
pub fn apply_centralized_cursor_config(has_openai_key: bool) -> Result<(), WrapError> {
    if let Ok(settings_path) = super::config_path::cursor_settings_path() {
        if let Some(parent) = settings_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        let mut settings: serde_json::Value = if settings_path.exists() {
            let raw = fs::read_to_string(&settings_path).map_err(WrapError::Io)?;
            match serde_json::from_str(&raw) {
                Ok(v) => v,
                Err(_) => {
                    let stripped = super::strip_json_comments(&raw);
                    serde_json::from_str(&stripped).unwrap_or(serde_json::json!({}))
                }
            }
        } else {
            serde_json::json!({})
        };

        if !settings.is_object() {
            settings = serde_json::json!({});
        }

        let _ = backup::create_backup(&settings_path);
        settings["http.proxy"] = serde_json::json!("http://127.0.0.1:8080");
        settings["cursor.general.disableHttp2"] = serde_json::json!(true);

        if has_openai_key {
            settings["cursor.general.openaiApiKey"] = serde_json::json!("sk-agentcontrol-managed");
        }

        let output_str = serde_json::to_string_pretty(&settings)
            .map_err(|e| WrapError::InvalidJson(e.to_string()))?;
        atomic_write(&settings_path, &output_str)?;
    }
    Ok(())
}

/// Restores Cursor's User/settings.json from backup
pub fn unwrap_cursor_settings(force: bool) -> Result<(), WrapError> {
    if let Ok(settings_path) = super::config_path::cursor_settings_path() {
        if settings_path.exists() {
            let config_dir = settings_path.parent().unwrap_or(Path::new("."));
            if let Some(backup_path) = backup::find_latest_backup(config_dir) {
                if !force {
                    let _ = backup::verify_backup_integrity(&backup_path);
                }
                let _ = fs::copy(&backup_path, &settings_path);
                let _ = fs::remove_file(&backup_path);
            }
        }
    }
    Ok(())
}

