//! Correlated execution, outcome, release, and audit lifecycle states (Gate 1.4).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DispatchState {
    NotSent,
    SendStarted,
    Accepted,
    DispatchUnknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum DownstreamOutcome {
    Success { status_code: u16 },
    Error { code: i64, message: String },
    Timeout,
    ConnectionFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum ReleaseDecision {
    Released,
    Redacted { fields: Vec<String> },
    Withheld { reason: String },
    ReleaseUnknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuditState {
    Committed,
    CommitFailed,
    ExportPending,
    ExportConfirmed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionLifecycle {
    pub request_id: String,
    pub session_id: String,
    pub trace_id: String,
    pub dispatch: DispatchState,
    pub downstream: Option<DownstreamOutcome>,
    pub release: Option<ReleaseDecision>,
    pub audit: AuditState,
}
