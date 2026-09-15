//! `agentwall status` — enumerate all 8 IDE targets, showing path / exists / wrap status.
//!
//! This is read-only inspection — it never modifies any config.

use colored::*;
use std::path::{Path, PathBuf};

use super::{config_path, transformer};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum TargetState {
    NotDetected,
    Detected,
    Configured,
    McpWrapped,
    McpTrafficVerified,
    ProbeVerified,
    TrafficVerified,
    BypassPossible,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum FreshnessTier {
    ActiveFresh,  // < 15 minutes
    ActiveRecent, // 15m - 24h
    Stale,        // > 24h
    None,         // No traffic observed
}

impl FreshnessTier {
    pub fn label(&self) -> &'static str {
        match self {
            Self::ActiveFresh => "ACTIVE_FRESH",
            Self::ActiveRecent => "ACTIVE_RECENT",
            Self::Stale => "STALE",
            Self::None => "NO_TRAFFIC",
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IdeIntegrationSummary {
    pub name: String,
    pub path: String,
    pub exists: bool,
    pub states: Vec<TargetState>,
    pub freshness: FreshnessTier,
    pub is_wrapped: bool,
    pub total_servers: usize,
    pub wrapped_servers: usize,
    pub disclosures: Vec<String>,
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
                    (
                        path.to_string_lossy().to_string(),
                        exists,
                        is_wrapped,
                        total,
                        wrapped,
                    )
                }
                Err(e) => (format!("Path error: {}", e), false, false, 0, 0),
            };

            let mut states = Vec::new();
            let mut disclosures = Vec::new();

            if !exists {
                states.push(TargetState::NotDetected);
            } else {
                states.push(TargetState::Detected);
                if is_wrapped {
                    states.push(TargetState::McpWrapped);
                }
                if t.name == "Claude Desktop" {
                    disclosures.push("LLM completions route out-of-band directly to Anthropic Cloud; MCP tools governed via stdio-proxy.".to_string());
                } else {
                    states.push(TargetState::Configured);
                    states.push(TargetState::BypassPossible);
                }

                if t.name == "Codex" {
                    disclosures.push("Native shell execution (bash/git) is UNGOVERNED by local proxy.".to_string());
                }
            }

            IdeIntegrationSummary {
                name: t.name.to_string(),
                path: path_str,
                exists,
                states,
                freshness: FreshnessTier::None,
                is_wrapped,
                total_servers: total,
                wrapped_servers: wrapped,
                disclosures,
            }
        })
        .collect()
}

#[allow(dead_code)]
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

/// Collect status for verified supported IDE targets.
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
            PathVerification::Verified,
            config_path::vscode_config_path(),
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
                let cmd_wrapped = v
                    .get("command")
                    .and_then(|c| c.as_str())
                    .map(|cmd| {
                        cmd.to_lowercase().contains("agentcontrol")
                            || cmd.to_lowercase().contains("agentwall")
                    })
                    .unwrap_or(false);
                let args_wrapped = v
                    .get("args")
                    .and_then(|a| a.as_array())
                    .and_then(|arr| arr.first())
                    .and_then(|f| f.as_str())
                    == Some("stdio-proxy");
                cmd_wrapped || args_wrapped
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TargetStatusDetails {
    pub target: String,
    pub config_path: String,
    pub exists: bool,
    pub states: Vec<TargetState>,
    pub llm_routing: String,
    pub mcp_governance: String,
    pub freshness: String,
    pub total_servers: usize,
    pub wrapped_servers: usize,
    pub disclosures: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StatusReport {
    pub version: String,
    pub timestamp: String,
    pub targets: Vec<TargetStatusDetails>,
    pub endpoints: StatusEndpoints,
    pub global_disclosures: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StatusEndpoints {
    pub default_proxy_url: String,
    pub hub_url: String,
    pub device_enrolled: bool,
}

/// Print the status table or structured JSON for verified targets.
pub fn print_all_targets(json: bool) {
    let summaries = get_all_integrations_summary();
    let hub_url = crate::identity::device::load_hub_url()
        .unwrap_or_else(|| "https://app.vexasec.io".to_string());
    let enrolled = crate::identity::device::is_device_enrolled();

    let targets_details: Vec<TargetStatusDetails> = summaries
        .iter()
        .map(|s| {
            let llm_routing = if !s.exists {
                "NOT_DETECTED".to_string()
            } else if s.name == "Claude Desktop" {
                "DIRECT_CLOUD".to_string()
            } else if s.states.contains(&TargetState::Configured) {
                "PROXIED (18080)".to_string()
            } else {
                "NOT_CONFIGURED".to_string()
            };

            let mcp_gov = if !s.exists {
                "NOT_INSTALLED".to_string()
            } else if s.total_servers == 0 {
                "NO_SERVERS".to_string()
            } else if s.wrapped_servers == s.total_servers {
                format!("WRAPPED ({}/{})", s.wrapped_servers, s.total_servers)
            } else {
                format!("PARTIAL ({}/{})", s.wrapped_servers, s.total_servers)
            };

            TargetStatusDetails {
                target: s.name.clone(),
                config_path: s.path.clone(),
                exists: s.exists,
                states: s.states.clone(),
                llm_routing,
                mcp_governance: mcp_gov,
                freshness: s.freshness.label().to_string(),
                total_servers: s.total_servers,
                wrapped_servers: s.wrapped_servers,
                disclosures: s.disclosures.clone(),
            }
        })
        .collect();

    if json {
        let report = StatusReport {
            version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            targets: targets_details,
            endpoints: StatusEndpoints {
                default_proxy_url: "http://127.0.0.1:18080/v1".to_string(),
                hub_url,
                device_enrolled: enrolled,
            },
            global_disclosures: vec![
                "Native shell execution (bash/git) is UNGOVERNED by local proxy across all targets.".to_string(),
                "Workstation developers can configure personal API keys in environment variables (Bypass Possible).".to_string(),
                "Binary 'COMPLIANT' state is retired; independent capability states reflect actual workstation posture.".to_string(),
            ],
        };
        println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
        return;
    }

    // Only send snapshot in interactive table mode
    gather_and_send_mcp_servers_snapshot();

    println!();
    println!(
        "{} {}",
        "Vexa Agent Control — Target Governance & Capability Posture".bold().white(),
        format!("(v{})", env!("CARGO_PKG_VERSION")).cyan()
    );
    println!("{}", "─".repeat(105).dimmed());
    println!(
        "  {:<16} {:<32} {:<18} {:<18} {:<12}",
        "TARGET".bold(),
        "CONFIG PATH".bold(),
        "LLM ROUTING".bold(),
        "MCP GOVERNANCE".bold(),
        "FRESHNESS".bold()
    );
    println!("{}", "─".repeat(105).dimmed());

    for t in &targets_details {
        let path_disp = shorten_path(Path::new(&t.config_path));
        let routing_colored = if t.llm_routing.starts_with("PROXIED") {
            t.llm_routing.green()
        } else if t.llm_routing == "DIRECT_CLOUD" {
            t.llm_routing.yellow()
        } else {
            t.llm_routing.dimmed()
        };

        let mcp_colored = if t.mcp_governance.starts_with("WRAPPED") {
            t.mcp_governance.green()
        } else if t.mcp_governance.starts_with("PARTIAL") {
            t.mcp_governance.yellow()
        } else {
            t.mcp_governance.dimmed()
        };

        println!(
            "  {:<16} {:<32} {:<18} {:<18} {:<12}",
            t.target.cyan().bold(),
            path_disp.dimmed(),
            routing_colored,
            mcp_colored,
            t.freshness.dimmed()
        );
    }

    println!("{}", "─".repeat(105).dimmed());
    println!("{}", "  ACTIVE CAPABILITY STATES:".bold());
    for t in &targets_details {
        if t.exists {
            let names: Vec<String> = t.states.iter().map(|st| format!("{:?}", st)).collect();
            let note = if t.target == "Claude Desktop" {
                " (LLM completions route out-of-band to Anthropic Cloud)"
            } else {
                ""
            };
            println!("    • {:<14} [{}]{}", t.target.bold(), names.join(", ").blue(), note.dimmed());
        }
    }

    println!();
    println!("{}", "  SECURITY BOUNDARIES & DISCLOSURES (No Sugar Coating):".bold().yellow());
    println!(
        "    ⚠ Bypass Vector: Native shell commands (bash/git) run out-of-band and are UNGOVERNED by local proxy."
    );
    println!(
        "    ⚠ Bypass Vector: Developers can configure personal API keys in workstation environment variables."
    );
    println!(
        "    ℹ Claude Desktop: Native completions route directly to Anthropic Cloud; MCP tools governed via stdio-proxy."
    );
    println!(
        "    ℹ Integrity: Binary 'COMPLIANT' state is retired; capability states reflect exact workstation posture."
    );
    println!();
}

/// Map an IDE display name to the valid `agentcontrol wrap <target>` CLI argument.
///
/// P2-a fix: `t.name.to_lowercase().replace(' ', "-")` previously produced
/// invalid targets like "claude-desktop" (unrecognised by the CLI). This function
/// returns the exact string accepted by the `wrap` subcommand for every known IDE.
#[allow(dead_code)]
fn ide_wrap_target(name: &str) -> &str {
    match name {
        "Claude Desktop" => "claude",
        "Cursor" => "cursor",
        "Codex" => "codex",
        "VS Code" => "vscode",
        "JetBrains" => "jetbrains",
        "Zed" => "zed",
        "Cline" => "cline",
        "OpenCode" => "opencode",
        "Antigravity" => "antigravity",
        // Fallback: lowercase with hyphens (safe for future targets).
        _ => name,
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
                                        .map(|cmd| {
                                            cmd.to_lowercase().contains("agentcontrol")
                                                || cmd.to_lowercase().contains("agentwall")
                                        })
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
                        let config: Result<serde_json::Value, _> = match serde_json::from_str(&raw)
                        {
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
    let token_opt = std::env::var("AGENT_ID")
        .ok()
        .or_else(crate::identity::device::load_device_token)
        .or_else(|| {
            crate::identity::device::DeviceIdentity::load_or_create()
                .ok()
                .map(|id| id.device_id)
        });
    if token_opt.is_none() {
        return;
    }

    if let Some(client) = crate::control_plane_client::client::DashboardClient::from_env() {
        let agent_id = token_opt.unwrap();
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
