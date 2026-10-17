//! Safety invariants and advisory detection definitions (Gate 0.4).
//!
//! Differentiates between hard structural invariants (which can NEVER be
//! overridden by policy, only by explicit break-glass) and advisory detections.

use serde::{Deserialize, Serialize};

/// Controls that cannot be overridden by any user policy rule.
/// These are structural security invariants, not heuristic preferences.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HardInvariant {
    InvalidAuthentication,
    MalformedFrame,
    OversizedPayload,
    InvalidSignature,
    RevokedIdentity,
    ProtectedPathTraversal,
    DestructiveCommand,
    UnauthorizedExfiltration,
    UnsupportedMandatoryObligation,
}

/// Policy handling mode for advisory detections.
/// Policy can set: Warn, RequireApproval, or Deny.
/// Policy CANNOT set: silent Allow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdvisoryHandling {
    Warn,
    RequireApproval,
    Deny,
}

impl Default for AdvisoryHandling {
    fn default() -> Self {
        Self::Deny
    }
}

/// Break-glass override structure for authorized operational exceptions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakGlassOverride {
    pub operator_id: String,
    pub action_hash: String,
    pub scope: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub nonce: String,
    pub reason: String,
}

impl BreakGlassOverride {
    pub fn is_valid_for(&self, action_hash: &str) -> bool {
        if self.action_hash != action_hash {
            return false;
        }
        if chrono::Utc::now() > self.expires_at {
            return false;
        }
        true
    }
}
