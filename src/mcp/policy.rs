//! MCP Protocol Constraints, Quotas & Parameter DLP (PRD §FR-7, Task 3.4)
//!
//! Enforces:
//! - Max frame size: 16MB (rejects with JSON-RPC error -32600)
//! - Max JSON nesting depth: 32 levels
//! - Monitored methods: tools/call, tools/list, resources/read, prompts/get
//! - Parameter DLP: regex pattern scanning for API keys, private keys, connection strings
//! - Sensitive parameter redaction ([REDACTED:<TYPE>]) or blocking (-32001)

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::OnceLock;

pub const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024; // 16 MiB
pub const MAX_JSON_DEPTH: usize = 32;
pub const DEFAULT_TOOL_TIMEOUT_SECS: u64 = 60;
pub const MAX_MEMORY_RSS_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcError {
    pub fn frame_exceeded() -> Self {
        Self {
            code: -32600,
            message: "JSON-RPC frame exceeded maximum size of 16MB".to_string(),
            data: None,
        }
    }

    pub fn depth_exceeded() -> Self {
        Self {
            code: -32600,
            message: "JSON-RPC nesting depth exceeded maximum of 32 levels".to_string(),
            data: None,
        }
    }

    pub fn policy_violation(reason: &str) -> Self {
        Self {
            code: -32001,
            message: format!(
                "Policy Violation: Sensitive Parameter Detected ({})",
                reason
            ),
            data: None,
        }
    }

    pub fn timeout(seconds: u64) -> Self {
        Self {
            code: -32000,
            message: format!("Tool execution timed out after {} seconds", seconds),
            data: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DlpFinding {
    pub pattern_type: &'static str,
    pub match_preview: String,
}

static API_KEY_REGEX: OnceLock<Regex> = OnceLock::new();
static PRIVATE_KEY_REGEX: OnceLock<Regex> = OnceLock::new();
static CONN_STRING_REGEX: OnceLock<Regex> = OnceLock::new();

fn get_api_key_regex() -> &'static Regex {
    API_KEY_REGEX.get_or_init(|| {
        Regex::new(r#"(sk-[a-zA-Z0-9_-]{20,}|ghp_[a-zA-Z0-9]{36}|glpat-[a-zA-Z0-9\-]{20,}|AKIA[0-9A-Z]{16})"#).unwrap()
    })
}

fn get_private_key_regex() -> &'static Regex {
    PRIVATE_KEY_REGEX.get_or_init(|| {
        Regex::new(r#"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----"#)
            .unwrap()
    })
}

fn get_conn_string_regex() -> &'static Regex {
    CONN_STRING_REGEX.get_or_init(|| {
        Regex::new(r#"(?:postgres|postgresql|mysql|mongodb|redis|amqp)://[^\s"']+"#).unwrap()
    })
}

/// Computes the maximum nesting depth of a JSON structure.
pub fn calculate_json_depth(val: &Value) -> usize {
    match val {
        Value::Array(arr) => 1 + arr.iter().map(calculate_json_depth).max().unwrap_or(0),
        Value::Object(obj) => 1 + obj.values().map(calculate_json_depth).max().unwrap_or(0),
        _ => 1,
    }
}

/// Scans string content for DLP findings and redacts in-place.
pub fn scan_and_redact_text(text: &str) -> (String, Vec<DlpFinding>) {
    let mut findings = Vec::new();
    let mut current = text.to_string();

    let api_key_re = get_api_key_regex();
    if api_key_re.is_match(&current) {
        findings.push(DlpFinding {
            pattern_type: "API_KEY",
            match_preview: "[REDACTED:API_KEY]".to_string(),
        });
        current = api_key_re
            .replace_all(&current, "[REDACTED:API_KEY]")
            .to_string();
    }

    let priv_key_re = get_private_key_regex();
    if priv_key_re.is_match(&current) {
        findings.push(DlpFinding {
            pattern_type: "PRIVATE_KEY",
            match_preview: "[REDACTED:PRIVATE_KEY]".to_string(),
        });
        current = priv_key_re
            .replace_all(&current, "[REDACTED:PRIVATE_KEY]")
            .to_string();
    }

    let conn_str_re = get_conn_string_regex();
    if conn_str_re.is_match(&current) {
        findings.push(DlpFinding {
            pattern_type: "CONNECTION_STRING",
            match_preview: "[REDACTED:CONNECTION_STRING]".to_string(),
        });
        current = conn_str_re
            .replace_all(&current, "[REDACTED:CONNECTION_STRING]")
            .to_string();
    }

    (current, findings)
}

/// Recursively scans JSON values in-place for sensitive parameters and replaces them with redacted tokens.
pub fn scan_and_redact_json(val: &mut Value) -> Vec<DlpFinding> {
    let mut findings = Vec::new();
    match val {
        Value::String(s) => {
            let (redacted, found) = scan_and_redact_text(s);
            if !found.is_empty() {
                *s = redacted;
                findings.extend(found);
            }
        }
        Value::Array(arr) => {
            for elem in arr {
                findings.extend(scan_and_redact_json(elem));
            }
        }
        Value::Object(map) => {
            for v in map.values_mut() {
                findings.extend(scan_and_redact_json(v));
            }
        }
        _ => {}
    }
    findings
}

/// Evaluates an inbound JSON-RPC 2.0 message against size, nesting depth, and parameter DLP rules.
pub fn inspect_jsonrpc_frame(
    raw_frame: &[u8],
    block_on_sensitive: bool,
) -> Result<(Value, Vec<DlpFinding>), JsonRpcError> {
    if raw_frame.len() > MAX_FRAME_SIZE {
        return Err(JsonRpcError::frame_exceeded());
    }

    let mut json_val: Value = match serde_json::from_slice(raw_frame) {
        Ok(v) => v,
        Err(_) => {
            return Err(JsonRpcError {
                code: -32700,
                message: "Parse error: Invalid JSON payload".to_string(),
                data: None,
            });
        }
    };

    let depth = calculate_json_depth(&json_val);
    if depth > MAX_JSON_DEPTH {
        return Err(JsonRpcError::depth_exceeded());
    }

    let mut all_findings = Vec::new();

    // Check if this is an inspected MCP method: tools/call, tools/list, resources/read, prompts/get
    if let Some(method) = json_val.get("method").and_then(|m| m.as_str()) {
        if method == "tools/call" || method == "resources/read" || method == "prompts/get" {
            if let Some(params) = json_val.get_mut("params") {
                if let Some(args) = params.get_mut("arguments") {
                    let findings = scan_and_redact_json(args);
                    if !findings.is_empty() {
                        if block_on_sensitive {
                            return Err(JsonRpcError::policy_violation(findings[0].pattern_type));
                        }
                        all_findings.extend(findings);
                    }
                }
            }
        }
    }

    Ok((json_val, all_findings))
}
