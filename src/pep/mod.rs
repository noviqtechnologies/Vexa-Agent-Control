//! Policy Enforcement Point (PEP) subsystem (Gate 2 & Gate 3).
//!
//! Provides protocol-specific enforcement adapters that mediate between external
//! agent tools/clients and the authoritative Policy Decision Point (PDP).
//! The PEP enforces the single forwarding gate invariant: downstream calls are made
//! ONLY if the authoritative PDP decision is `Allow`.

use decision_v1::Decision;

/// Result and error states produced across Policy Enforcement Points (PEP).
#[derive(Debug)]
pub enum PepError {
    /// Action denied by policy or pre-evaluation constraint
    Denied { reason: String, decision: Decision },
    /// Action suspended pending human-in-the-loop approval
    ApprovalRequired {
        approval_id: String,
        decision: Decision,
    },
    /// Malformed protocol or payload structure rejected before PDP
    ValidationFailed(String),
    /// Error encountered during downstream execution
    DownstreamError(String),
    /// Response scanner or DLP withheld the downstream result
    ResponseWithheld { reason: String },
    /// Security scanner error or panic in enforce fail-closed mode
    ScannerFailure { reason: String },
}

impl std::fmt::Display for PepError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Denied { reason, .. } => write!(f, "Policy evaluation denied: {}", reason),
            Self::ApprovalRequired { approval_id, .. } => {
                write!(f, "Approval required: {}", approval_id)
            }
            Self::ValidationFailed(msg) => write!(f, "Pre-evaluation validation failed: {}", msg),
            Self::DownstreamError(msg) => write!(f, "Downstream execution failed: {}", msg),
            Self::ResponseWithheld { reason } => {
                write!(f, "Response withheld by security scanner: {}", reason)
            }
            Self::ScannerFailure { reason } => {
                write!(f, "Scanner failure in fail-closed mode: {}", reason)
            }
        }
    }
}

impl std::error::Error for PepError {}

impl PepError {
    /// Convert PEP error state to standard JSON-RPC 2.0 error response object.
    pub fn to_jsonrpc_error(&self, id: &serde_json::Value) -> serde_json::Value {
        match self {
            Self::Denied { reason, decision } => serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32001,
                    "message": format!("Policy evaluation denied: {}", reason),
                    "data": {
                        "reason_code": reason,
                        "verdict": "deny",
                        "matched_group_id": decision.matched_group_id,
                    }
                }
            }),
            Self::ApprovalRequired {
                approval_id,
                decision,
            } => serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32002,
                    "message": format!("Approval required: {}", approval_id),
                    "data": {
                        "approval_id": approval_id,
                        "verdict": "require_approval",
                        "matched_group_id": decision.matched_group_id,
                    }
                }
            }),
            Self::ValidationFailed(msg) => serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32600,
                    "message": format!("Pre-evaluation validation failed: {}", msg),
                }
            }),
            Self::DownstreamError(msg) => serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32603,
                    "message": format!("Downstream execution failed: {}", msg),
                }
            }),
            Self::ResponseWithheld { reason } => serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32004,
                    "message": format!("Response withheld by security scanner: {}", reason),
                }
            }),
            Self::ScannerFailure { reason } => serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32005,
                    "message": format!("Scanner failure in fail-closed mode: {}", reason),
                }
            }),
        }
    }
}

pub mod http_llm;
pub mod mcp;
pub mod stdio;

pub use http_llm::*;
pub use mcp::*;
pub use stdio::*;
