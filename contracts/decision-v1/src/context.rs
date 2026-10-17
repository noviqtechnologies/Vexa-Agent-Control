//! Authentication and session context for PDP evaluation (Gate 1.2).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Stdio,
    HttpJsonRpc,
    Sse,
    LlmRest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedPrincipal {
    pub identity_sub: String,
    pub identity_email: Option<String>,
    pub identity_groups: Vec<String>,
    pub client_id: Option<String>,
}

/// Evaluation context supplied by the Policy Enforcement Point (PEP).
/// Every field is populated from validated session/device credentials,
/// never unverified request parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluationContext {
    pub principal: AuthenticatedPrincipal,
    pub organization_id: Option<String>,
    pub workspace_id: Option<String>,
    pub session_id: String,
    pub device_id: Option<String>,
    pub adapter_id: String,
    pub adapter_protocol: Protocol,
    pub policy_revision: Option<u64>,
    pub policy_hash: Option<String>,
}
