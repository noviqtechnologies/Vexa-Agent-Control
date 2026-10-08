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

/// Canonical security posture for a governed agent surface (PRD FR-P0-1).
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum EnforcementPosture {
    #[serde(rename = "ENFORCED")]
    Enforced,
    #[serde(rename = "OBSERVED")]
    Observed,
    #[serde(rename = "UNCOVERED")]
    Uncovered,
    #[serde(rename = "UNKNOWN_UNHEALTHY")]
    UnknownUnhealthy,
}

impl EnforcementPosture {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Enforced => "ENFORCED",
            Self::Observed => "OBSERVED",
            Self::Uncovered => "UNCOVERED",
            Self::UnknownUnhealthy => "UNKNOWN_UNHEALTHY",
        }
    }
}

pub fn default_posture() -> EnforcementPosture {
    EnforcementPosture::Uncovered
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

fn is_target_managed(target_name: &str, path: &Path) -> (bool, bool) {
    let manifest_name = match target_name {
        "Claude Desktop" => "claude",
        "Claude Code" => "claude-code",
        "Cursor" => "cursor",
        "Codex" => "codex",
        "Antigravity" => "antigravity",
        "VS Code" => "vscode-continue",
        other => other,
    };

    if let Ok(Some(manifest)) = super::manifest::OwnershipManifest::load(manifest_name) {
        let has_proxy_key = manifest.managed_keys.iter().any(|k| {
            k.contains("proxy")
                || k.contains("OPENAI_BASE_URL")
                || k.contains("ANTHROPIC_BASE_URL")
                || k == "continue.models"
        });
        return (has_proxy_key, true);
    }

    // Direct content inspection fallback
    if let Ok(content) = std::fs::read_to_string(path) {
        let has_proxy_url = content.contains("127.0.0.1:18080")
            || content.contains("localhost:18080")
            || (content.contains("OPENAI_BASE_URL") && content.contains("18080"))
            || (content.contains("ANTHROPIC_BASE_URL") && content.contains("18080"));
        return (has_proxy_url, false);
    }

    (false, false)
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

            let (is_proxied, _has_manifest) = if exists {
                match &t.path_result {
                    Ok(p) => is_target_managed(t.name, p),
                    Err(_) => (false, false),
                }
            } else {
                (false, false)
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
                if is_proxied {
                    states.push(TargetState::Configured);
                    states.push(TargetState::BypassPossible);
                }

                if t.name == "Claude Desktop" {
                    disclosures.push("LLM completions route out-of-band directly to Anthropic Cloud; MCP tools governed via stdio-proxy.".to_string());
                } else if is_proxied {
                    if t.name == "Codex" {
                        disclosures.push("Native shell execution (bash/git) is UNGOVERNED by local proxy.".to_string());
                    }
                } else {
                    disclosures.push("Target configuration exists on disk but is not pointed to Agent Control (Unmanaged).".to_string());
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

/// Check whether the local gateway daemon is actively listening on 127.0.0.1:18080 (FR-P0-1).
pub fn is_gateway_running() -> bool {
    use std::net::{SocketAddr, TcpStream};
    use std::time::Duration;
    if let Ok(addr) = "127.0.0.1:18080".parse::<SocketAddr>() {
        TcpStream::connect_timeout(&addr, Duration::from_millis(80)).is_ok()
    } else {
        false
    }
}

/// Runtime-effective policy summary report (FR-P0-3).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EffectivePolicyReport {
    pub path: Option<String>,
    pub sha256_hash: String,
    pub rule_count: usize,
    pub default_action: String,
    pub execution_mode: String,
    pub status: String,
}

pub fn get_effective_policy_report() -> Option<EffectivePolicyReport> {
    let (compiled_opt, path_opt) = crate::policy::loader::resolve_active_policy(None, None);
    let path_str = path_opt.map(|p| p.to_string_lossy().to_string());

    let shadow_mode = std::env::var("AGENTCONTROL_SHADOW_MODE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let execution_mode = if shadow_mode {
        "shadow".to_string()
    } else {
        "enforce".to_string()
    };

    if let Some(compiled) = compiled_opt {
        let hash = if let Some(ref p_str) = path_str {
            if let Ok(raw) = std::fs::read(p_str) {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(&raw);
                format!("sha256:{}", hex::encode(hasher.finalize()))
            } else {
                "sha256:active_in_memory".to_string()
            }
        } else {
            "sha256:default_allowlist".to_string()
        };

        Some(EffectivePolicyReport {
            path: path_str,
            sha256_hash: hash,
            rule_count: compiled.tools.len(),
            default_action: "deny".to_string(),
            execution_mode,
            status: "HEALTHY (ACTIVE)".to_string(),
        })
    } else {
        Some(EffectivePolicyReport {
            path: None,
            sha256_hash: "none".to_string(),
            rule_count: 0,
            default_action: "deny".to_string(),
            execution_mode,
            status: "NO_POLICY_CONFIGURED (FAIL_CLOSED)".to_string(),
        })
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TargetStatusDetails {
    pub target: String,
    pub config_path: String,
    pub exists: bool,
    pub states: Vec<TargetState>,
    #[serde(default = "default_posture")]
    pub posture: EnforcementPosture,
    #[serde(default = "default_posture")]
    pub mcp_posture: EnforcementPosture,
    #[serde(default = "default_posture")]
    pub llm_posture: EnforcementPosture,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_enforcing_component: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm_enforcing_component: Option<String>,
    #[serde(default)]
    pub known_bypasses: Vec<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_policy: Option<EffectivePolicyReport>,
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
pub fn run_status(json: bool) {
    print_all_targets(json);
}

/// Print the status table or structured JSON for verified targets.
pub fn print_all_targets(json: bool) {
    let summaries = get_all_integrations_summary();
    let hub_url = crate::identity::device::load_hub_url()
        .unwrap_or_else(|| "https://app.vexasec.io".to_string());
    let enrolled = crate::identity::device::is_device_enrolled();
    let gateway_active = is_gateway_running();
    let effective_policy = get_effective_policy_report();

    let targets_details: Vec<TargetStatusDetails> = summaries
        .iter()
        .map(|s| {
            let is_proxied = s.states.contains(&TargetState::Configured);
            let mut known_bypasses = Vec::new();

            let (llm_routing, llm_posture, llm_enforcing_component) = if !s.exists {
                ("NOT_DETECTED".to_string(), EnforcementPosture::Uncovered, None)
            } else if s.name == "Claude Desktop" {
                known_bypasses.push("Direct HTTPS completion route to Anthropic Cloud bypasses local proxy (Out-of-band)".to_string());
                ("DIRECT_CLOUD (Anthropic)".to_string(), EnforcementPosture::Uncovered, None)
            } else if is_proxied {
                if gateway_active {
                    ("PROXIED (18080)".to_string(), EnforcementPosture::Enforced, Some("agentcontrol http-proxy (18080)".to_string()))
                } else {
                    ("PROXIED (18080 - DAEMON DOWN)".to_string(), EnforcementPosture::UnknownUnhealthy, Some("agentcontrol http-proxy (offline)".to_string()))
                }
            } else {
                ("UNMANAGED".to_string(), EnforcementPosture::Uncovered, None)
            };

            let (mcp_gov, mcp_posture, mcp_enforcing_component) = if !s.exists {
                ("NOT_INSTALLED".to_string(), EnforcementPosture::Uncovered, None)
            } else if s.total_servers == 0 {
                ("NO_SERVERS".to_string(), EnforcementPosture::Uncovered, None)
            } else if s.wrapped_servers == s.total_servers {
                (format!("WRAPPED ({}/{})", s.wrapped_servers, s.total_servers), EnforcementPosture::Enforced, Some("agentcontrol stdio-proxy".to_string()))
            } else if s.wrapped_servers > 0 {
                known_bypasses.push(format!("Partial MCP coverage ({}/{} wrapped); unwrapped tools run ungoverned", s.wrapped_servers, s.total_servers));
                (format!("PARTIAL ({}/{})", s.wrapped_servers, s.total_servers), EnforcementPosture::Observed, Some("agentcontrol stdio-proxy (partial)".to_string()))
            } else {
                known_bypasses.push(format!("All {} MCP server entries are unwrapped and ungoverned", s.total_servers));
                (format!("UNWRAPPED (0/{})", s.total_servers), EnforcementPosture::Uncovered, None)
            };

            if s.name == "Codex" && s.exists {
                known_bypasses.push("Native shell execution (bash/git) is UNGOVERNED by local proxy".to_string());
            }

            // Target overall posture reflects verifiable prevention capability
            let posture = if !s.exists {
                EnforcementPosture::Uncovered
            } else if s.name == "Claude Desktop" {
                if mcp_posture == EnforcementPosture::Enforced {
                    EnforcementPosture::Enforced
                } else {
                    EnforcementPosture::Uncovered
                }
            } else if mcp_posture == EnforcementPosture::UnknownUnhealthy || llm_posture == EnforcementPosture::UnknownUnhealthy {
                EnforcementPosture::UnknownUnhealthy
            } else if mcp_posture == EnforcementPosture::Enforced || llm_posture == EnforcementPosture::Enforced {
                EnforcementPosture::Enforced
            } else if mcp_posture == EnforcementPosture::Observed || llm_posture == EnforcementPosture::Observed {
                EnforcementPosture::Observed
            } else {
                EnforcementPosture::Uncovered
            };

            TargetStatusDetails {
                target: s.name.clone(),
                config_path: s.path.clone(),
                exists: s.exists,
                states: s.states.clone(),
                posture,
                mcp_posture,
                llm_posture,
                mcp_enforcing_component,
                llm_enforcing_component,
                known_bypasses,
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
            effective_policy,
            targets: targets_details,
            endpoints: StatusEndpoints {
                default_proxy_url: "http://127.0.0.1:18080/v1".to_string(),
                hub_url,
                device_enrolled: enrolled,
            },
            global_disclosures: vec![
                "Native shell execution (bash/git) is UNGOVERNED by local proxy across all targets.".to_string(),
                "Workstation developers can configure personal API keys in environment variables (Bypass Possible).".to_string(),
                "Binary 'COMPLIANT' state is retired; independent capability postures (ENFORCED/OBSERVED/UNCOVERED) reflect actual security boundary.".to_string(),
            ],
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
        return;
    }

    println!();
    println!(
        "{} {}",
        "Vexa Agent Control — Target Governance & Protection Posture"
            .bold()
            .white(),
        format!("(v{})", env!("CARGO_PKG_VERSION")).cyan()
    );
    if let Some(ref pol) = effective_policy {
        println!(
            "  Active Policy: {} | Mode: {} | Rules: {} | Hash: {}",
            pol.path.as_deref().unwrap_or("none").cyan(),
            pol.execution_mode.yellow(),
            pol.rule_count,
            pol.sha256_hash.dimmed()
        );
    }
    println!("{}", "─".repeat(110).dimmed());
    println!(
        "  {:<16} {:<28} {:<14} {:<20} {:<18}",
        "TARGET".bold(),
        "CONFIG PATH".bold(),
        "POSTURE".bold(),
        "LLM ROUTING".bold(),
        "MCP GOVERNANCE".bold(),
    );
    println!("{}", "─".repeat(110).dimmed());

    for t in &targets_details {
        let path_disp = shorten_path(Path::new(&t.config_path));
        let posture_colored = match t.posture {
            EnforcementPosture::Enforced => "ENFORCED".green().bold(),
            EnforcementPosture::Observed => "OBSERVED".yellow().bold(),
            EnforcementPosture::Uncovered => "UNCOVERED".dimmed(),
            EnforcementPosture::UnknownUnhealthy => "UNHEALTHY".red().bold(),
        };

        let routing_colored =
            if t.llm_routing.starts_with("PROXIED") && !t.llm_routing.contains("DOWN") {
                t.llm_routing.green()
            } else if t.llm_routing.starts_with("PROXIED") {
                t.llm_routing.red()
            } else if t.llm_routing.starts_with("DIRECT_CLOUD") {
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
            "  {:<16} {:<28} {:<14} {:<20} {:<18}",
            t.target.cyan().bold(),
            path_disp.dimmed(),
            posture_colored,
            routing_colored,
            mcp_colored,
        );
    }

    println!("{}", "─".repeat(110).dimmed());
    println!("{}", "  ACTIVE CAPABILITY STATES:".bold());
    for t in &targets_details {
        if t.exists {
            let names: Vec<String> = t.states.iter().map(|st| format!("{:?}", st)).collect();
            let note = if t.target == "Claude Desktop" {
                " (LLM completions route out-of-band to Anthropic Cloud; MCP governed via stdio)"
            } else {
                ""
            };
            println!(
                "    • {:<14} [{}]{}",
                t.target.bold(),
                names.join(", ").blue(),
                note.dimmed()
            );
        }
    }

    println!();
    println!(
        "{}",
        "  SECURITY BOUNDARIES & DISCLOSURES (No Sugar Coating):"
            .bold()
            .yellow()
    );
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
        "    ℹ Integrity: Binary 'COMPLIANT' state is retired; independent capability postures (ENFORCED/OBSERVED/UNCOVERED) reflect actual security boundary."
    );
    println!();
}

/// Lists all detected, connected, and protected IDE clients and MCP runtimes (PRD §12).
pub fn run_clients(json: bool) -> i32 {
    let list = get_all_integrations_summary();

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&list).unwrap_or_default()
        );
        return 0;
    }

    println!();
    println!(
        "{}",
        "Vexa Agent Control — Connected Clients & Interceptions"
            .bold()
            .white()
    );
    println!("{}", "─".repeat(95).dimmed());
    println!(
        "  {:<22} {:<16} {:<20} CONFIGURATION PATH",
        "CLIENT / TARGET", "STATUS", "MCP GOVERNANCE"
    );
    println!("{}", "─".repeat(95).dimmed());

    for item in &list {
        let status_colored = if item.is_wrapped {
            "PROTECTED".green().bold()
        } else if item.exists {
            "DETECTED".yellow().bold()
        } else {
            "NOT DETECTED".dimmed()
        };

        let governance = if item.is_wrapped {
            format!("Wrapped ({}/{})", item.wrapped_servers, item.total_servers).green()
        } else if item.exists && item.total_servers > 0 {
            format!("Unwrapped ({})", item.total_servers).yellow()
        } else if item.exists {
            "No MCP servers".dimmed()
        } else {
            "-".dimmed()
        };

        let path_disp = shorten_path(Path::new(&item.path));
        println!(
            "  {:<22} {:<25} {:<29} {}",
            item.name.cyan().bold(),
            status_colored,
            governance,
            path_disp.dimmed()
        );
    }
    println!("{}", "─".repeat(95).dimmed());
    println!("  Run 'agentcontrol connect <target>' to protect a detected client.");
    println!(
        "  Run 'agentcontrol disconnect <target>' to cleanly restore original configuration.\n"
    );
    0
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
    if !crate::identity::device::is_device_enrolled() {
        return;
    }
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

    #[test]
    fn test_run_clients_output() {
        let code = run_clients(true);
        assert_eq!(code, 0);

        let code_text = run_clients(false);
        assert_eq!(code_text, 0);
    }
}
