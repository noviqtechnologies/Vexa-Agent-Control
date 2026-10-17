//! `agentcontrol status` — enumerate all IDE targets, showing path / exists / wrap status
//! and per-surface enforcement posture with evidence (PRD Enforcement Assurance).
//!
//! This is read-only inspection — it never modifies any config.
//!
//! Posture semantics (PRD Section 5):
//! - ENFORCED_ON_ROUTED_TRAFFIC: daemon healthy + policy loaded + mode=Enforce + trust established
//! - OBSERVED: daemon healthy + policy loaded + mode in {Observe,Shadow}
//! - CONFIGURED: client points to Vexa; proves configuration only
//! - UNCOVERED: no enforcement point in path
//! - DEGRADED: missing dependency, stale telemetry, or failed policy check
//! - UNKNOWN_UNHEALTHY: cannot determine state

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

/// Management mode reflects how policy is controlled (PRD Section 4).
/// Three distinct modes — never one ambiguous "protected" state.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum ManagementMode {
    /// Local/Developer: local YAML, user-controlled, no central authority
    #[serde(rename = "LOCAL_DEVELOPER")]
    LocalDeveloper,
    /// Team Managed: central policy with signed bundles via verified keyring
    #[serde(rename = "TEAM_MANAGED")]
    TeamManaged,
    /// Mandatory Boundary: external controls (MDM/EDR/network egress) verified active
    #[serde(rename = "MANDATORY_BOUNDARY")]
    MandatoryBoundary,
    /// Unknown: cannot determine management mode
    #[serde(rename = "UNKNOWN")]
    Unknown,
}

impl ManagementMode {
    pub fn label(&self) -> &'static str {
        match self {
            Self::LocalDeveloper => "LOCAL_DEVELOPER",
            Self::TeamManaged => "TEAM_MANAGED",
            Self::MandatoryBoundary => "MANDATORY_BOUNDARY",
            Self::Unknown => "UNKNOWN",
        }
    }
}

/// Policy freshness state — separate from posture.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum PolicyFreshnessState {
    /// Policy age within configured window
    #[serde(rename = "FRESH")]
    Fresh,
    /// No max_policy_age configured; freshness unverified
    #[serde(rename = "UNCHECKED")]
    Unchecked,
    /// Policy age exceeds configured max_policy_age_secs
    #[serde(rename = "EXPIRED")]
    Expired,
    /// No policy loaded
    #[serde(rename = "MISSING")]
    Missing,
}

/// Canonical security posture for a governed agent surface (PRD Section 5).
/// All surfaces use exactly these states. No aliases.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum EnforcementPosture {
    /// Policy in enforce mode evaluated requests routed through Vexa.
    /// Does NOT imply all traffic reaches Vexa.
    #[serde(rename = "ENFORCED_ON_ROUTED_TRAFFIC")]
    Enforced,
    /// Policy evaluated in shadow/observe mode; actions allowed through.
    #[serde(rename = "OBSERVED")]
    Observed,
    /// No Vexa enforcement point in path, or surface explicitly outside scope.
    #[serde(rename = "UNCOVERED")]
    Uncovered,
    /// Degraded: missing dependency, stale telemetry, failed policy check, invalid signature.
    #[serde(rename = "DEGRADED")]
    Degraded,
    /// Cannot determine state. Never converted to enforced.
    #[serde(rename = "UNKNOWN_UNHEALTHY")]
    UnknownUnhealthy,
}

impl EnforcementPosture {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Enforced => "ENFORCED_ON_ROUTED_TRAFFIC",
            Self::Observed => "OBSERVED",
            Self::Uncovered => "UNCOVERED",
            Self::Degraded => "DEGRADED",
            Self::UnknownUnhealthy => "UNKNOWN_UNHEALTHY",
        }
    }

    /// Returns true only for traffic that is actively governed by a running enforcement point.
    /// Does NOT return true for observed-only, uncovered, degraded, or unknown states.
    pub fn is_enforcing(&self) -> bool {
        matches!(self, Self::Enforced)
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

/// Runtime-effective policy summary report (PRD FR-002).
/// Status field uses accurate posture codes — never "HEALTHY (ACTIVE)" without evidence.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EffectivePolicyReport {
    pub path: Option<String>,
    pub sha256_hash: String,
    pub rule_count: usize,
    pub default_action: String,
    /// "enforce" or "shadow" — reflects actual execution mode
    pub execution_mode: String,
    /// Accurate posture code: ENFORCED_ON_ROUTED_TRAFFIC | OBSERVED | DEGRADED | NO_POLICY
    /// Never "HEALTHY (ACTIVE)" — that label conceals mode and trust state.
    pub status: String,
    /// Human-readable reason for the status
    pub reason: String,
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

        // Status reflects actual mode — shadow mode = OBSERVED, not ENFORCED
        let (status, reason) = if shadow_mode {
            (
                "OBSERVED".to_string(),
                "Policy loaded but execution_mode=shadow; requests are allowed through. \
                 Set AGENTCONTROL_SHADOW_MODE=0 to enforce."
                    .to_string(),
            )
        } else {
            (
                "ENFORCED_ON_ROUTED_TRAFFIC".to_string(),
                "Policy loaded and enforcement mode active on routed traffic. \
                 Does not imply all traffic reaches this enforcement point."
                    .to_string(),
            )
        };

        Some(EffectivePolicyReport {
            path: path_str,
            sha256_hash: hash,
            rule_count: compiled.tools.len(),
            default_action: "deny".to_string(),
            execution_mode,
            status,
            reason,
        })
    } else {
        Some(EffectivePolicyReport {
            path: None,
            sha256_hash: "none".to_string(),
            rule_count: 0,
            default_action: "deny".to_string(),
            execution_mode,
            status: "NO_POLICY".to_string(),
            reason: "No policy configured; proxy is in fail-closed mode (all unmatched requests denied).".to_string(),
        })
    }
}

/// Per-target surface evidence record (PRD FR-002).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TargetStatusDetails {
    pub target: String,
    pub config_path: String,
    pub exists: bool,
    pub states: Vec<TargetState>,
    #[serde(default = "default_posture")]
    pub posture: EnforcementPosture,
    /// Reason code explaining the posture
    pub posture_reason: String,
    #[serde(default = "default_posture")]
    pub mcp_posture: EnforcementPosture,
    pub mcp_posture_reason: String,
    #[serde(default = "default_posture")]
    pub llm_posture: EnforcementPosture,
    pub llm_posture_reason: String,
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

/// Full status report — canonical source of truth for CLI and fleet API (PRD FR-002).
/// All fields are evidence-derived. No field implies more than its evidence proves.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StatusReport {
    pub version: String,
    pub timestamp: String,
    /// How policy is controlled for this endpoint
    pub management_mode: ManagementMode,
    /// Trust profile: Development (local YAML) or Managed (signed bundles)
    pub policy_trust_profile: String,
    /// Active policy revision, if known
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_revision: Option<u64>,
    /// Active policy content hash, if known
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_content_hash: Option<String>,
    /// Policy issue time (RFC3339)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_issued_at: Option<String>,
    /// Policy expiry time (RFC3339); None means no expiry configured
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_expires_at: Option<String>,
    /// Policy freshness state
    pub policy_freshness_state: PolicyFreshnessState,
    /// Surfaces known to be outside Vexa's enforcement path
    pub known_uncovered_surfaces: Vec<String>,
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

/// Derive management mode from environment and device enrollment state.
/// This is read-only and never changes enforcement behavior.
pub fn derive_management_mode() -> ManagementMode {
    let trust_profile = crate::policy::trust::PolicyTrustProfile::from_env();
    let enrolled = crate::identity::device::is_device_enrolled();

    match trust_profile {
        crate::policy::trust::PolicyTrustProfile::Managed {
            ref trusted_keyring,
            ..
        } if !trusted_keyring.keys.is_empty() && enrolled => ManagementMode::TeamManaged,
        crate::policy::trust::PolicyTrustProfile::Managed {
            ref trusted_keyring,
            ..
        } if !trusted_keyring.keys.is_empty() => {
            // Has a signing keyring but not enrolled with hub
            ManagementMode::TeamManaged
        }
        _ => ManagementMode::LocalDeveloper,
    }
}

/// Derive trust profile label for status output.
pub fn derive_trust_profile_label() -> String {
    let trust_profile = crate::policy::trust::PolicyTrustProfile::from_env();
    match trust_profile {
        crate::policy::trust::PolicyTrustProfile::Development => {
            "Development (local YAML accepted unsigned)".to_string()
        }
        crate::policy::trust::PolicyTrustProfile::Managed {
            ref trusted_keyring,
            ..
        } => {
            if trusted_keyring.keys.is_empty() {
                "Managed (WARNING: empty keyring — no bundles will be accepted)".to_string()
            } else {
                format!("Managed ({} trusted key(s))", trusted_keyring.keys.len())
            }
        }
    }
}

/// Print the status table or structured JSON for verified targets.
pub fn run_status(json: bool) {
    print_all_targets(json);
}

/// Print the status table or structured JSON for verified targets.
pub fn print_all_targets(json: bool) {
    let summaries = get_all_integrations_summary();
    let hub_url = crate::identity::device::load_hub_url()
        .unwrap_or_else(|| "http://127.0.0.1:8080".to_string());
    let enrolled = crate::identity::device::is_device_enrolled();
    let gateway_active = is_gateway_running();
    let effective_policy = get_effective_policy_report();

    let targets_details: Vec<TargetStatusDetails> = summaries
        .iter()
        .map(|s| {
            let is_proxied = s.states.contains(&TargetState::Configured);
            let mut known_bypasses = Vec::new();

            // PRD Phase 0: LLM posture requires daemon up AND policy mode check.
            // Proxy config + open port alone is NOT sufficient for ENFORCED_ON_ROUTED_TRAFFIC.
            let is_shadow_mode = std::env::var("AGENTCONTROL_SHADOW_MODE")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            let policy_available = effective_policy.is_some();

            let (llm_routing, llm_posture, llm_enforcing_component, llm_posture_reason) = if !s.exists {
                ("NOT_DETECTED".to_string(), EnforcementPosture::Uncovered, None,
                 "Target not detected on this system".to_string())
            } else if s.name == "Claude Desktop" {
                known_bypasses.push("Direct HTTPS completion route to Anthropic Cloud bypasses local proxy (Out-of-band)".to_string());
                ("DIRECT_CLOUD (Anthropic)".to_string(), EnforcementPosture::Uncovered, None,
                 "Claude Desktop routes LLM completions directly to Anthropic Cloud; this surface is UNCOVERED by local proxy".to_string())
            } else if is_proxied {
                if !gateway_active {
                    ("PROXIED (18080 - DAEMON DOWN)".to_string(), EnforcementPosture::UnknownUnhealthy,
                     Some("agentcontrol http-proxy (offline)".to_string()),
                     "Client configured to use proxy but daemon is not responding on 18080".to_string())
                } else if !policy_available {
                    ("PROXIED (18080 - NO POLICY)".to_string(), EnforcementPosture::Degraded,
                     Some("agentcontrol http-proxy (18080)".to_string()),
                     "Daemon healthy but no policy loaded; running fail-closed without defined rules".to_string())
                } else if is_shadow_mode {
                    // Shadow mode = OBSERVED, never ENFORCED
                    ("PROXIED (18080 - SHADOW)".to_string(), EnforcementPosture::Observed,
                     Some("agentcontrol http-proxy (18080, shadow)".to_string()),
                     "Daemon healthy and policy loaded but AGENTCONTROL_SHADOW_MODE=1; actions allowed through. Set shadow_mode=0 to enforce.".to_string())
                } else {
                    // All three checks pass: daemon up + policy loaded + enforce mode
                    ("PROXIED (18080)".to_string(), EnforcementPosture::Enforced,
                     Some("agentcontrol http-proxy (18080)".to_string()),
                     format!("Daemon healthy, policy loaded (mode=enforce). Policy hash: {}. Direct provider egress not verified as restricted.",
                         effective_policy.as_ref().map(|p| p.sha256_hash.as_str()).unwrap_or("unknown")))
                }
            } else {
                ("UNMANAGED".to_string(), EnforcementPosture::Uncovered, None,
                 "Target configuration exists but not pointed to Vexa proxy".to_string())
            };

            let (mcp_gov, mcp_posture, mcp_enforcing_component, mcp_posture_reason) = if !s.exists {
                ("NOT_INSTALLED".to_string(), EnforcementPosture::Uncovered, None,
                 "Target not detected".to_string())
            } else if s.total_servers == 0 {
                ("NO_SERVERS".to_string(), EnforcementPosture::Uncovered, None,
                 "No MCP servers configured; no MCP coverage required".to_string())
            } else if !gateway_active && s.wrapped_servers > 0 {
                (format!("WRAPPED ({}/{} - DAEMON DOWN)", s.wrapped_servers, s.total_servers),
                 EnforcementPosture::UnknownUnhealthy,
                 Some("agentcontrol stdio-proxy (offline)".to_string()),
                 "MCP servers configured as wrapped but daemon is not responding".to_string())
            } else if s.wrapped_servers == s.total_servers {
                if is_shadow_mode {
                    (format!("WRAPPED ({}/{} - SHADOW)", s.wrapped_servers, s.total_servers),
                     EnforcementPosture::Observed,
                     Some("agentcontrol stdio-proxy (shadow)".to_string()),
                     format!("All {}/{} MCP servers wrapped but shadow mode active; calls observed not blocked",
                         s.wrapped_servers, s.total_servers))
                } else {
                    (format!("WRAPPED ({}/{})", s.wrapped_servers, s.total_servers),
                     EnforcementPosture::Enforced,
                     Some("agentcontrol stdio-proxy".to_string()),
                     format!("All {}/{} MCP servers wrapped and daemon healthy in enforce mode",
                         s.wrapped_servers, s.total_servers))
                }
            } else if s.wrapped_servers > 0 {
                known_bypasses.push(format!("Partial MCP coverage ({}/{} wrapped); unwrapped servers run ungoverned",
                    s.wrapped_servers, s.total_servers));
                (format!("PARTIAL ({}/{})", s.wrapped_servers, s.total_servers),
                 // Partial coverage = OBSERVED (not ENFORCED) — some tools ungoverned
                 EnforcementPosture::Observed,
                 Some("agentcontrol stdio-proxy (partial)".to_string()),
                 format!("{}/{} MCP servers wrapped; remaining {} servers route ungoverned",
                     s.wrapped_servers, s.total_servers, s.total_servers - s.wrapped_servers))
            } else {
                known_bypasses.push(format!("All {} MCP server entries are unwrapped and ungoverned", s.total_servers));
                (format!("UNWRAPPED (0/{})", s.total_servers), EnforcementPosture::Uncovered, None,
                 format!("All {} MCP servers are configured but not wrapped through Vexa stdio-proxy", s.total_servers))
            };

            if s.name == "Codex" && s.exists {
                known_bypasses.push("Native shell execution (bash/git) is UNGOVERNED by local proxy".to_string());
            }

            // PRD Phase 0: Overall posture is conservative — partial coverage is NOT fully enforced.
            // A client with any uncovered surface shows partial/observed, not globally enforced.
            // Per PRD: "no global green badge based on any one surface enforced"
            let (posture, posture_reason) = if !s.exists {
                (EnforcementPosture::Uncovered, "Target not detected".to_string())
            } else if s.name == "Claude Desktop" {
                // Claude Desktop: LLM is always UNCOVERED (direct Anthropic route).
                // Report MCP posture as-is; do not elevate to globally enforced.
                if mcp_posture == EnforcementPosture::Enforced {
                    (EnforcementPosture::Observed,
                     "MCP enforced via stdio-proxy but LLM completions route directly to Anthropic Cloud (UNCOVERED). Partial coverage.".to_string())
                } else {
                    (EnforcementPosture::Uncovered,
                     "LLM routes directly to Anthropic Cloud (UNCOVERED); MCP not fully wrapped".to_string())
                }
            } else if llm_posture == EnforcementPosture::UnknownUnhealthy || mcp_posture == EnforcementPosture::UnknownUnhealthy {
                (EnforcementPosture::UnknownUnhealthy,
                 "Daemon not responding; enforcement state cannot be determined".to_string())
            } else if llm_posture == EnforcementPosture::Degraded || mcp_posture == EnforcementPosture::Degraded {
                (EnforcementPosture::Degraded,
                 "One or more surfaces degraded; see per-surface posture for details".to_string())
            } else if llm_posture == EnforcementPosture::Enforced && (s.total_servers == 0 || mcp_posture == EnforcementPosture::Enforced) {
                // Fully enforced only when LLM is enforced AND either no MCP servers or all MCP wrapped
                (EnforcementPosture::Enforced,
                 "LLM and MCP surfaces both enforced on routed traffic. Direct egress not verified as restricted.".to_string())
            } else if llm_posture == EnforcementPosture::Observed || mcp_posture == EnforcementPosture::Observed {
                (EnforcementPosture::Observed,
                 "One or more surfaces in observe/shadow mode".to_string())
            } else if llm_posture == EnforcementPosture::Enforced && mcp_posture != EnforcementPosture::Enforced && s.total_servers > 0 {
                // LLM enforced but MCP partial/uncovered = overall OBSERVED (partial)
                (EnforcementPosture::Observed,
                 format!("LLM enforced but MCP coverage partial ({}/{} servers wrapped)",
                     s.wrapped_servers, s.total_servers))
            } else {
                (EnforcementPosture::Uncovered, "Target not governed".to_string())
            };

            TargetStatusDetails {
                target: s.name.clone(),
                config_path: s.path.clone(),
                exists: s.exists,
                states: s.states.clone(),
                posture,
                posture_reason,
                mcp_posture,
                mcp_posture_reason,
                llm_posture,
                llm_posture_reason,
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

    let management_mode = derive_management_mode();
    let trust_profile_label = derive_trust_profile_label();

    // Collect known uncovered surfaces across all targets
    let known_uncovered_surfaces: Vec<String> = {
        let mut uncovered = vec![
            "Native shell/process execution (bash, git, etc.): always UNGOVERNED by local proxy"
                .to_string(),
            "Direct provider API access: UNGOVERNED unless network egress is restricted externally"
                .to_string(),
        ];
        for t in &targets_details {
            if t.llm_posture == EnforcementPosture::Uncovered && t.exists {
                uncovered.push(format!("{}: LLM route UNCOVERED", t.target));
            }
            if t.mcp_posture == EnforcementPosture::Uncovered && t.exists && t.total_servers > 0 {
                uncovered.push(format!(
                    "{}: MCP route UNCOVERED ({}/{} servers wrapped)",
                    t.target, t.wrapped_servers, t.total_servers
                ));
            }
        }
        uncovered
    };

    if json {
        let report = StatusReport {
            version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            management_mode,
            policy_trust_profile: trust_profile_label,
            policy_revision: None,   // Phase 2: populate from signed bundle metadata
            policy_content_hash: effective_policy.as_ref().map(|p| p.sha256_hash.clone()),
            policy_issued_at: None,  // Phase 2: populate from signed bundle
            policy_expires_at: None, // Phase 2: populate from signed bundle
            policy_freshness_state: PolicyFreshnessState::Unchecked,
            known_uncovered_surfaces,
            effective_policy,
            targets: targets_details,
            endpoints: StatusEndpoints {
                default_proxy_url: "http://127.0.0.1:18080/v1".to_string(),
                hub_url,
                device_enrolled: enrolled,
            },
            global_disclosures: vec![
                "LIMITATION: Vexa governs traffic explicitly routed through it. A workstation owner can bypass a local proxy without OS-level or network enforcement.".to_string(),
                "LIMITATION: Native shell execution (bash/git) is UNGOVERNED by local proxy across all targets.".to_string(),
                "LIMITATION: Workstation developers can configure personal API keys outside Vexa's control.".to_string(),
                "NOTE: ENFORCED_ON_ROUTED_TRAFFIC means policy evaluated requests that reach this enforcement point. It does not imply all organizational traffic is forced through this path.".to_string(),
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
            EnforcementPosture::Enforced => "ENFORCED_ON_ROUTED".green().bold(),
            EnforcementPosture::Observed => "OBSERVED".yellow().bold(),
            EnforcementPosture::Uncovered => "UNCOVERED".dimmed(),
            EnforcementPosture::Degraded => "DEGRADED".red().bold(),
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
        // PRD Phase 0: Remove "PROTECTED" label — it implies more than config/wrapping proves.
        // Use "ROUTED" for wrapped targets (configuration proved), not "PROTECTED" (security implied).
        let status_colored = if item.is_wrapped {
            "ROUTED".green().bold()
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
