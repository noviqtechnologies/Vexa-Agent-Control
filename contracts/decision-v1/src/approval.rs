//! Human-in-the-Loop (HITL) approval lifecycle specification & state machine (Gate 1.3).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApprovalState {
    Pending,
    Approved,
    Rejected,
    Consumed,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub approval_id: String,
    pub action_hash: String,
    pub principal_sub: String,
    pub device_id: Option<String>,
    pub session_id: String,
    pub policy_revision: u64,
    pub nonce: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub state: ApprovalState,
}

impl ApprovalRequest {
    pub fn is_valid_and_pending(&self, expected_hash: &str) -> bool {
        self.state == ApprovalState::Pending
            && self.action_hash == expected_hash
            && Utc::now() <= self.expires_at
    }

    /// Atomically transition to Consumed (Compare-And-Swap)
    pub fn consume(&mut self) -> Result<(), &'static str> {
        if self.state != ApprovalState::Approved {
            return Err("Cannot consume approval that is not approved");
        }
        if Utc::now() > self.expires_at {
            self.state = ApprovalState::Expired;
            return Err("Approval has expired");
        }
        self.state = ApprovalState::Consumed;
        Ok(())
    }
}
