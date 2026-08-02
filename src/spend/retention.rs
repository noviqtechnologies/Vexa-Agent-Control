//! Spend data retention and automatic record purging policy configuration.

use serde::{Deserialize, Serialize};

/// Purge configuration for the spend database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// Spend counter rows older than this are purged. Default: 90 days.
    pub spend_counters_days: u32,
    /// Increase request rows older than this are purged. Default: 365 days.
    pub increase_requests_days: u32,
    /// Threshold-fired rows older than this are purged. Default: 90 days.
    pub thresholds_fired_days: u32,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            spend_counters_days: 90,
            increase_requests_days: 365,
            thresholds_fired_days: 90,
        }
    }
}
