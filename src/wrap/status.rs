//! `agentwall status` — enumerate all 8 IDE targets, showing path / exists / wrap status.
//!
//! This is read-only inspection — it never modifies any config.

use colored::*;
use std::path::{Path, PathBuf};

use super::{config_path, transformer};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IdeIntegrationSummary {
    pub name: String,
    pub path: String,
    pub exists: bool,
    pub is_wrapped: bool,
    pub total_servers: usize,
    pub wrapped_servers: usize,
}

pub fn get_all_integrations_summary() -> Vec<IdeIntegrationSummary> {
    let targets = gather_all();
    targets
        .into_iter()
        .map(|t| {
            let (path_str, exists, is_wrapped, total, wrapped) = match &t.path_result {
                Ok(path) => {
                    let exists = path.exists();
                    let (total, wrapped) = if exists {
                        check_wrap_status(path).unwrap_or((0, 0))
                    } else {
                        (0, 0)
                    };
                    let is_wrapped = exists && total > 0 && wrapped == total;
                    (path.to_string_lossy().to_string(), exists, is_wrapped, total, wrapped)
                }
                Err(e) => (format!("Path error: {}", e), false, false, 0, 0),
            };
            IdeIntegrationSummary {
                name: t.name.to_string(),
                path: path_str,
                exists,
                is_wrapped,
                total_servers: total,
                wrapped_servers: wrapped,
            }
        })
        .collect()
}

/// Classification of a target's path resolution reliability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathVerification {
    /// Path is correct and tested on all platforms (Claude Desktop).
    Verified,
    /// Path is a known-wrong or hypothetical guess. May watch the wrong file.
    Unverified,
}

struct TargetInfo {
    name: &'static str,
    verification: PathVerification,
    path_result: Result<PathBuf, String>,
}

/// Collect status for all 8 IDE targets.
fn gather_all() -> Vec<TargetInfo> {
    let targets: Vec<(
        &'static str,
        PathVerification,
        Result<PathBuf, super::WrapError>,
    )> = vec![
        (
            "Claude Desktop",
            PathVerification::Verified,
            config_path::claude_config_path(),
        ),
        (
            "Cursor",
            PathVerification::Verified,
            config_path::cursor_config_path(),
        ),
        (
            "Codex",
            PathVerification::Verified,
            config_path::codex_config_path(),
        ),
        (
            "VS Code",
            PathVerification::Unverified,
            config_path::vscode_config_path(),
        ),
        (
            "JetBrains",
            PathVerification::Unverified,
            config_path::jetbrains_config_path(),
        ),
        (
            "Zed",
            PathVerification::Unverified,
            config_path::zed_config_path(),
        ),
        (
            "Cline",
            PathVerification::Unverified,
            config_path::cline_config_path(),
        ),
        (
            "OpenCode",
            PathVerification::Unverified,
            config_path::opencode_config_path(),
        ),
        (
            "Antigravity",
            PathVerification::Verified,
            config_path::antigravity_config_path(),
        ),
    ];

    targets
        .into_iter()
        .map(|(name, verification, res)| TargetInfo {
            name,
            verification,
            path_result: res.map_err(|e| e.to_string()),
        })
        .collect()
}

use super::strip_json_comments;

/// Check whether all mcpServers in a config file are wrapped by Vexa Agent Control.
/// Returns (total_servers, wrapped_servers).
fn check_wrap_status(path: &PathBuf) -> Result<(usize, usize), String> {
    let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;

    if path.extension().and_then(|e| e.to_str()) == Some("toml") {
        let val: toml::Value = toml::from_str(&raw).map_err(|e| format!("invalid TOML: {}", e))?;
        let servers = match val.get("mcp_servers").and_then(|v| v.as_table()) {
            Some(s) => s,
            None => return Ok((0, 0)),
        };
        let total = servers.len();
        let wrapped = servers
            .values()
            .filter(|v| {
                if let Some(cmd) = v.get("command").and_then(|c| c.as_str()) {
                    cmd.to_lowercase().contains("agentcontrol") || cmd.to_lowercase().contains("agentwall")
                } else {
                    false
                }
            })
            .count();
        Ok((total, wrapped))
    } else {
        let config: serde_json::Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(_) => {
                let stripped = strip_json_comments(&raw);
                serde_json::from_str(&stripped).map_err(|e| format!("invalid JSON: {}", e))?
            }
        };

        let servers = config
            .get("mcpServers")
            .or_else(|| config.get("context_servers"))
            .or_else(|| config.get("experimental.context_servers"))
            .and_then(|v| v.as_object());

        let servers = match servers {
            Some(s) => s,
            None => return Ok((0, 0)),
        };

        let total = servers.len();
        let wrapped = servers
            .values()
            .filter(|v| transformer::is_already_wrapped(v))
            .count();

        Ok((total, wrapped))
    }
}

/// Print the status table for all 8 targets to stdout.
pub fn print_all_targets() {
    // Send snapshot in the background if dashboard client is configured
    gather_and_send_mcp_servers_snapshot();

    let targets = gather_all();

    // Header
    println!();
    println!("{}", "Vexa Agent Control — IDE Config Status".bold().white());
    println!("{}", "─".repeat(90).dimmed());
    println!(
        "  {:<18} {:<12} {:<8} {:<10} {}",
        "TARGET".bold(),
        "PATH".bold(),
        "EXISTS".bold(),
        "WRAPPED".bold(),
        "NOTES".bold()
    );
    println!("{}", "─".repeat(90).dimmed());

    for t in &targets {
        let verified_label = match t.verification {
            PathVerification::Verified => "[verified]".green().to_string(),
            PathVerification::Unverified => "[unverified]".yellow().to_string(),
        };

        match &t.path_result {
            Err(e) => {
                println!(
                    "  {:<18} {:<12} {:<8} {:<10} path error: {} {}",
                    t.name.cyan(),
                    "N/A".dimmed(),
                    "✖".red(),
                    "—".dimmed(),
                    e,
                    verified_label,
                );
            }
            Ok(path) => {
                let path_display = shorten_path(path);
                let exists = path.exists();
                let (exists_label, wrap_label, notes) = if !exists {
                    (
                        "✖".red().to_string(),
                        "—".dimmed().to_string(),
                        format!("file not found {}", verified_label),
                    )
                } else {
                    match check_wrap_status(path) {
                        Err(e) => (
                            "✔".green().to_string(),
                            "?".yellow().to_string(),
                            format!("read error: {} {}", e, verified_label),
                        ),
                        Ok((0, _)) => (
                            "✔".green().to_string(),
                            "—".dimmed().to_string(),
                            format!("no mcpServers {}", verified_label),
                        ),
                        Ok((total, wrapped)) if wrapped == total => (
                            "✔".green().to_string(),
                            format!("{}/{}", wrapped, total).green().to_string(),
                            format!("all wrapped {}", verified_label),
                        ),
                        Ok((total, wrapped)) if wrapped == 0 => (
                            "✔".green().to_string(),
                            format!("{}/{}", wrapped, total).red().bold().to_string(),
                            format!(
                                "⚠ unwrapped! run: agentcontrol wrap {} {}",
                                // P2-a fix: map IDE display names to valid CLI wrap target names.
                                // Previously used `.replace(' ', "-")` which produced invalid
                                // targets like "claude-desktop" instead of the correct "claude".
                                ide_wrap_target(t.name),
                                verified_label
                            ),
                        ),
                        Ok((total, wrapped)) => (
                            "✔".green().to_string(),
                            format!("{}/{}", wrapped, total).yellow().to_string(),
                            format!(
                                "⚠ partial — run: agentcontrol wrap {} {}",
                                ide_wrap_target(t.name),
                                verified_label
                            ),
                        ),
                    }
                };

                println!(
                    "  {:<18} {:<36} {:<8} {:<10} {}",
                    t.name.cyan(),
                    path_display.dimmed(),
                    exists_label,
                    wrap_label,
                    notes,
                );

                // Debug: always print full path on a second line for unverified targets
                if t.verification == PathVerification::Unverified && exists {
                    eprintln!("  [debug] {} full path: {}", t.name, path.display());
                }
            }
        }
    }

    println!("{}", "─".repeat(90).dimmed());
    println!(
        "  {} = path tested and correct.  {} = guessed/hypothetical path.",
        "[verified]".green(),
        "[unverified]".yellow()
    );
    println!();
}

/// Map an IDE display name to the valid `agentcontrol wrap <target>` CLI argument.
///
/// P2-a fix: `t.name.to_lowercase().replace(' ', "-")` previously produced
/// invalid targets like "claude-desktop" (unrecognised by the CLI). This function
/// returns the exact string accepted by the `wrap` subcommand for every known IDE.
fn ide_wrap_target(name: &str) -> &str {
    match name {
        "Claude Desktop" => "claude",
        "Cursor"         => "cursor",
        "Codex"          => "codex",
        "VS Code"        => "vscode",
        "JetBrains"      => "jetbrains",
        "Zed"            => "zed",
        "Cline"          => "cline",
        "OpenCode"       => "opencode",
        "Antigravity"    => "antigravity",
        // Fallback: lowercase with hyphens (safe for future targets).
        _                => name,
    }
}

/// Shorten a long path for table display (max 34 chars with ellipsis).
fn shorten_path(p: &Path) -> String {
    let s = p.display().to_string();
    if s.len() <= 34 {
        s
    } else {
        format!("...{}", &s[s.len().saturating_sub(31)..])
    }
}

pub fn gather_servers_for_snapshot(
    agent_id: String,
) -> control_plane_proto::mcp_server::McpServerSnapshot {
    let targets = gather_all();
    let mut servers_meta = Vec::new();

    for t in targets {
        if let Ok(path) = t.path_result {
            if path.exists() {
                if let Ok(raw) = std::fs::read_to_string(&path) {
                    if path.extension().and_then(|e| e.to_str()) == Some("toml") {
                        if let Ok(val) = toml::from_str::<toml::Value>(&raw) {
                            if let Some(servers) = val.get("mcp_servers").and_then(|v| v.as_table())
                            {
                                for (name, val) in servers {
                                    let wrapped = val
                                        .get("command")
                                        .and_then(|c| c.as_str())
                                        .map(|cmd| cmd.to_lowercase().contains("agentcontrol") || cmd.to_lowercase().contains("agentwall"))
                                        .unwrap_or(false);
                                    let path_verified =
                                        t.verification == PathVerification::Verified;
                                    servers_meta.push(
                                        control_plane_proto::mcp_server::SanitizedMcpServerMeta {
                                            ide_target: t.name.to_string(),
                                            server_name: name.to_string(),
                                            wrapped,
                                            path_verified,
                                        },
                                    );
                                }
                            }
                        }
                    } else {
                        let config: Result<serde_json::Value, _> = match serde_json::from_str(&raw) {
                            Ok(v) => Ok(v),
                            Err(_) => {
                                let stripped = strip_json_comments(&raw);
                                serde_json::from_str(&stripped)
                            }
                        };
                        if let Ok(config) = config {
                            let servers = config
                                .get("mcpServers")
                                .or_else(|| config.get("context_servers"))
                                .or_else(|| config.get("experimental.context_servers"))
                                .and_then(|v| v.as_object());

                            if let Some(servers) = servers {
                                for (name, val) in servers {
                                    let wrapped = transformer::is_already_wrapped(val);
                                    let path_verified = t.verification == PathVerification::Verified;
                                    servers_meta.push(
                                        control_plane_proto::mcp_server::SanitizedMcpServerMeta {
                                            ide_target: t.name.to_string(),
                                            server_name: name.to_string(),
                                            wrapped,
                                            path_verified,
                                        },
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    control_plane_proto::mcp_server::McpServerSnapshot {
        agent_id,
        servers: servers_meta,
    }
}

pub fn gather_and_send_mcp_servers_snapshot() {
    if let Some(client) = crate::control_plane_client::client::DashboardClient::from_env() {
        let device_identity = crate::identity::device::DeviceIdentity::load_or_create().ok();
        let agent_id = std::env::var("AGENT_ID")
            .ok()
            .or_else(|| crate::identity::device::load_device_token())
            .or_else(|| device_identity.as_ref().map(|id| id.device_id.clone()))
            .unwrap_or_else(|| {
                let user = std::env::var("USER")
                    .or_else(|_| std::env::var("USERNAME"))
                    .unwrap_or_else(|_| "user".to_string());
                let hostname = std::env::var("HOSTNAME")
                    .or_else(|_| std::env::var("COMPUTERNAME"))
                    .unwrap_or_else(|_| "host".to_string());
                format!("agent-{}-{}", user, hostname).to_lowercase()
            });
        let snapshot = gather_servers_for_snapshot(agent_id);
        client.send_mcp_server_snapshot(snapshot);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_wrap_status_toml() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("config.toml");
        let content = r#"
[mcp_servers.test_server]
command = "agentcontrol"
args = ["stdio-proxy", "--", "node", "server.js"]
"#;
        std::fs::write(&config_path, content).unwrap();

        let (total, wrapped) = check_wrap_status(&config_path).unwrap();
        assert_eq!(total, 1);
        assert_eq!(wrapped, 1);
    }
}
