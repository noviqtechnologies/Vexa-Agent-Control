//! Unified Scanner Failure & Panic Handler (Gate 0.3).
//!
//! Replaces ad-hoc, inconsistent catch_unwind blocks across the proxy
//! with a centralized failure matrix that strictly honors fail_closed
//! and enforce_mode, preventing unauthenticated fail-open on panic or timeout.

use serde_json::{json, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScannerFailureKind {
    Panic,
    Timeout,
    Error,
}

impl ScannerFailureKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Panic => "scanner_panic",
            Self::Timeout => "scanner_timeout",
            Self::Error => "scanner_error",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScannerFailureDecision {
    pub should_block: bool,
    pub log_reason: String,
    pub audit_event: &'static str,
}

pub fn handle_scanner_failure(
    kind: ScannerFailureKind,
    enforce_mode: bool,
    fail_closed: bool,
    component: &str,
) -> ScannerFailureDecision {
    let should_block = enforce_mode && fail_closed;
    let (audit_event, log_reason) = if should_block {
        (
            "SCANNER_FAILURE_BLOCKED",
            format!(
                "{}: {} failed in fail-closed mode",
                kind.as_str(),
                component
            ),
        )
    } else {
        (
            "SCANNER_FAILURE",
            format!(
                "{}: {} failed in shadow/fail-open mode",
                kind.as_str(),
                component
            ),
        )
    };

    ScannerFailureDecision {
        should_block,
        log_reason,
        audit_event,
    }
}

pub fn make_scanner_blocked_error(
    id: &Value,
    session_id: &str,
    component: &str,
    reason: &str,
) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32002,
            "message": format!("Operation blocked: {} failure in fail-closed mode ({})", component, reason),
            "data": { "session_id": session_id }
        }
    })
}
