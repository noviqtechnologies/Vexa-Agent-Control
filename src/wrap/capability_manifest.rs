//! Machine-readable Capability Manifest & Blind-Spot Reporting (PRD FR-001, FR-021, NFR-003)
//!
//! Declares protocol and action coverage, OS/client versions, restrictions, failure behavior,
//! and explicit blind spots per supported client integration.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Standardized protection posture per FR-001 / FR-021.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PostureState {
    /// Configured in client files, but connectivity not yet confirmed.
    Configured,
    /// Loopback/IPC connectivity verified; no traffic observed yet.
    ConnectivityVerified,
    /// Traffic has been actively observed traversing the gateway.
    TrafficObserved,
    /// Verified via active security conformance test execution.
    EnforcedTested,
    /// Operating in shadow / live audit-only mode; decisions not blocked.
    ObservedOnly,
    /// Route or tool path has no interception mediation (blind spot).
    Uncovered,
    /// Gateway offline, configuration drifted, or writer degraded.
    Unhealthy,
}

impl PostureState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Configured => "CONFIGURED",
            Self::ConnectivityVerified => "CONNECTIVITY_VERIFIED",
            Self::TrafficObserved => "TRAFFIC_OBSERVED",
            Self::EnforcedTested => "ENFORCED_TESTED",
            Self::ObservedOnly => "OBSERVED_ONLY",
            Self::Uncovered => "UNCOVERED",
            Self::Unhealthy => "UNHEALTHY",
        }
    }
}

/// Operation capability inspection level.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionCapability {
    pub supported: bool,
    pub can_observe: bool,
    pub can_inspect: bool,
    pub can_modify: bool,
    pub can_allow: bool,
    pub can_deny: bool,
    pub can_pause: bool,
    pub can_audit: bool,
    pub failure_mode: String, // e.g. "FAIL_CLOSED", "FAIL_OPEN", "PASS_THROUGH"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limitation_notes: Option<String>,
}

/// Capability manifest for a single client/adapter surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientCapabilityManifest {
    pub schema_version: String,
    pub client_name: String,
    pub adapter_transport: String, // "stdio_proxy", "http_proxy", "uds_ipc", "named_pipe"
    pub supported_os: Vec<String>,
    pub current_posture: PostureState,
    pub last_verification_time: Option<String>,
    pub action_coverage: HashMap<String, ActionCapability>,
    pub declared_blind_spots: Vec<String>,
}

impl ClientCapabilityManifest {
    /// Generates the canonical manifest for a named client.
    pub fn for_client(client_name: &str, posture: PostureState) -> Self {
        let normalized = client_name.to_lowercase().replace('_', "-");
        match normalized.as_str() {
            "claude-desktop" | "claude" => Self {
                schema_version: "2.0.0".to_string(),
                client_name: "Claude Desktop".to_string(),
                adapter_transport: "stdio_proxy".to_string(),
                supported_os: vec!["windows".to_string(), "macos".to_string(), "linux".to_string()],
                current_posture: posture,
                last_verification_time: Some(chrono::Utc::now().to_rfc3339()),
                action_coverage: {
                    let mut m = HashMap::new();
                    m.insert(
                        "mcp_tools_call".to_string(),
                        ActionCapability {
                            supported: true,
                            can_observe: true,
                            can_inspect: true,
                            can_modify: true,
                            can_allow: true,
                            can_deny: true,
                            can_pause: true,
                            can_audit: true,
                            failure_mode: "FAIL_CLOSED".to_string(),
                            limitation_notes: Some("Mediates child stdio frames up to 16MB".to_string()),
                        },
                    );
                    m.insert(
                        "llm_chat_completions".to_string(),
                        ActionCapability {
                            supported: false,
                            can_observe: false,
                            can_inspect: false,
                            can_modify: false,
                            can_allow: false,
                            can_deny: false,
                            can_pause: false,
                            can_audit: false,
                            failure_mode: "PASS_THROUGH".to_string(),
                            limitation_notes: Some("Claude Desktop routes model completions directly to Anthropic Cloud".to_string()),
                        },
                    );
                    m
                },
                declared_blind_spots: vec![
                    "Model completions route directly to Anthropic Cloud out-of-band; only wrapped MCP tools are governed.".to_string(),
                    "Unwrapped MCP servers configured outside claude_desktop_config.json run unmonitored.".to_string(),
                ],
            },
            "cursor" => Self {
                schema_version: "2.0.0".to_string(),
                client_name: "Cursor IDE".to_string(),
                adapter_transport: "http_proxy".to_string(),
                supported_os: vec!["windows".to_string(), "macos".to_string(), "linux".to_string()],
                current_posture: posture,
                last_verification_time: Some(chrono::Utc::now().to_rfc3339()),
                action_coverage: {
                    let mut m = HashMap::new();
                    m.insert(
                        "llm_chat_completions".to_string(),
                        ActionCapability {
                            supported: true,
                            can_observe: true,
                            can_inspect: true,
                            can_modify: true,
                            can_allow: true,
                            can_deny: true,
                            can_pause: true,
                            can_audit: true,
                            failure_mode: "FAIL_CLOSED".to_string(),
                            limitation_notes: None,
                        },
                    );
                    m.insert(
                        "mcp_tools_call".to_string(),
                        ActionCapability {
                            supported: true,
                            can_observe: true,
                            can_inspect: true,
                            can_modify: true,
                            can_allow: true,
                            can_deny: true,
                            can_pause: true,
                            can_audit: true,
                            failure_mode: "FAIL_CLOSED".to_string(),
                            limitation_notes: Some("Requires MCP stdio wrapping in cursor config".to_string()),
                        },
                    );
                    m
                },
                declared_blind_spots: vec![
                    "Terminal shell executions spawned inside Cursor IDE bypass proxy unless explicitly wrapped.".to_string(),
                ],
            },
            "claude-code" => Self {
                schema_version: "2.0.0".to_string(),
                client_name: "Claude Code CLI".to_string(),
                adapter_transport: "http_proxy + stdio_proxy".to_string(),
                supported_os: vec!["windows".to_string(), "macos".to_string(), "linux".to_string()],
                current_posture: posture,
                last_verification_time: Some(chrono::Utc::now().to_rfc3339()),
                action_coverage: {
                    let mut m = HashMap::new();
                    m.insert(
                        "llm_chat_completions".to_string(),
                        ActionCapability {
                            supported: true,
                            can_observe: true,
                            can_inspect: true,
                            can_modify: true,
                            can_allow: true,
                            can_deny: true,
                            can_pause: false,
                            can_audit: true,
                            failure_mode: "FAIL_CLOSED".to_string(),
                            limitation_notes: Some("Via ANTHROPIC_BASE_URL redirection".to_string()),
                        },
                    );
                    m
                },
                declared_blind_spots: vec![
                    "Direct child processes invoked by Claude Code outside stdio wrappers run ungoverned.".to_string(),
                ],
            },
            "antigravity" => Self {
                schema_version: "2.0.0".to_string(),
                client_name: "Google Antigravity".to_string(),
                adapter_transport: "http_proxy + stdio_proxy".to_string(),
                supported_os: vec!["windows".to_string(), "macos".to_string(), "linux".to_string()],
                current_posture: posture,
                last_verification_time: Some(chrono::Utc::now().to_rfc3339()),
                action_coverage: {
                    let mut m = HashMap::new();
                    m.insert(
                        "mcp_tools_call".to_string(),
                        ActionCapability {
                            supported: true,
                            can_observe: true,
                            can_inspect: true,
                            can_modify: true,
                            can_allow: true,
                            can_deny: true,
                            can_pause: true,
                            can_audit: true,
                            failure_mode: "FAIL_CLOSED".to_string(),
                            limitation_notes: None,
                        },
                    );
                    m
                },
                declared_blind_spots: vec![
                    "Unconfigured sidecar processes run out-of-band.".to_string(),
                ],
            },
            "codex" => Self {
                schema_version: "2.0.0".to_string(),
                client_name: "OpenAI Codex CLI".to_string(),
                adapter_transport: "stdio_proxy".to_string(),
                supported_os: vec!["windows".to_string(), "macos".to_string(), "linux".to_string()],
                current_posture: posture,
                last_verification_time: Some(chrono::Utc::now().to_rfc3339()),
                action_coverage: {
                    let mut m = HashMap::new();
                    m.insert(
                        "llm_chat_completions".to_string(),
                        ActionCapability {
                            supported: true,
                            can_observe: true,
                            can_inspect: true,
                            can_modify: true,
                            can_allow: true,
                            can_deny: true,
                            can_pause: false,
                            can_audit: true,
                            failure_mode: "FAIL_CLOSED".to_string(),
                            limitation_notes: None,
                        },
                    );
                    m
                },
                declared_blind_spots: vec![
                    "Native bash and git operations outside Codex API calls are ungoverned by loopback proxy.".to_string(),
                ],
            },
            _ => Self {
                schema_version: "2.0.0".to_string(),
                client_name: client_name.to_string(),
                adapter_transport: "loopback_http".to_string(),
                supported_os: vec!["windows".to_string(), "macos".to_string(), "linux".to_string()],
                current_posture: posture,
                last_verification_time: Some(chrono::Utc::now().to_rfc3339()),
                action_coverage: HashMap::new(),
                declared_blind_spots: vec![
                    "Direct socket calls bypassing proxy URL run uninspected.".to_string(),
                ],
            },
        }
    }
}
