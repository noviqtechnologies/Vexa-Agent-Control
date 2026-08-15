//! Typed OS-local helper IPC protocol and peer validation.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrapperInventoryReport {
    pub schema_version: String,
    pub message_type: String,
    pub report_id: String,
    pub user_session_id: String,
    pub observed_at: String,
    pub targets: InventoryTargets,
    pub integrity_summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InventoryTargets {
    pub discovered: u32,
    pub wrapped: u32,
    pub skipped: u32,
    pub failed: u32,
    pub unsupported: u32,
    pub unverified: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationHint {
    pub schema_version: String,
    pub hint_code: String,
    pub message: String,
    pub action: String,
}

impl WrapperInventoryReport {
    pub fn new(
        report_id: String,
        user_session_id: String,
        targets: InventoryTargets,
        integrity_summary: String,
    ) -> Self {
        Self {
            schema_version: "1.0".to_string(),
            message_type: "wrapper_inventory_report".to_string(),
            report_id,
            user_session_id,
            observed_at: chrono::Utc::now().to_rfc3339(),
            targets,
            integrity_summary,
        }
    }
}
