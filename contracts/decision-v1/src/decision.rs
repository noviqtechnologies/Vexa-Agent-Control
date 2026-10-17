//! Authoritative policy decision and obligation types (Gate 1.2).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    Allow,
    Deny,
    RequireApproval,
    Indeterminate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Obligation {
    RequireApproval {
        approval_id: String,
        action_hash: String,
        ttl_secs: u64,
    },
    RedactParameters {
        parameter_paths: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub verdict: Verdict,
    pub reason_code: String,
    pub reason_detail: Option<String>,
    pub matched_group_id: Option<String>,
    pub obligations: Vec<Obligation>,
}

impl Decision {
    pub fn allow() -> Self {
        Self {
            verdict: Verdict::Allow,
            reason_code: "policy_allow".to_string(),
            reason_detail: None,
            matched_group_id: None,
            obligations: Vec::new(),
        }
    }

    pub fn deny(reason_code: impl Into<String>, detail: Option<String>) -> Self {
        Self {
            verdict: Verdict::Deny,
            reason_code: reason_code.into(),
            reason_detail: detail,
            matched_group_id: None,
            obligations: Vec::new(),
        }
    }

    pub fn require_approval(
        approval_id: String,
        action_hash: String,
        ttl_secs: u64,
        reason: String,
    ) -> Self {
        Self {
            verdict: Verdict::RequireApproval,
            reason_code: "require_approval".to_string(),
            reason_detail: Some(reason),
            matched_group_id: None,
            obligations: vec![Obligation::RequireApproval {
                approval_id,
                action_hash,
                ttl_secs,
            }],
        }
    }
}
