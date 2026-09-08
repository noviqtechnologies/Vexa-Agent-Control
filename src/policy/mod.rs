//! Policy engine module for evaluation, DLP inspection, prompt injection, and schema loading.

pub mod community_rules;
/// FR-5 v2.0: Credential scope stub validator (FR-22 integration pending).
pub mod credential_scope;
pub mod dlp;
pub mod engine;
pub mod hitl;
pub mod identity;
pub mod injection;
pub mod loader;
pub mod mcp_score;
/// Remote policy loader: fetches active policy from the dashboard API (PostgreSQL)
/// and provides a background polling task for automatic hot-reload.
pub mod remote;
/// Remote provider keys & desired state reconciler (REQ-DSM-004)
pub mod remote_keys;
/// File-system watcher that hot-reloads the `--policy` YAML file when it changes
/// on disk, without requiring a daemon restart.
pub mod policy_file_watcher;
pub mod response_scanner;
pub mod safe_mode;
pub mod schema;
pub mod schema_drift;
pub mod semantic;
pub mod sharding;
pub mod snapshot;
pub mod threat_intel;

use std::sync::Arc;

/// Unified Scanner Suite compiled once at startup and shared cleanly across
/// pipeline hooks, proxy state, and request handlers (AR-1).
#[derive(Clone)]
pub struct SharedScanners {
    pub safe_mode_scanner: Arc<safe_mode::SafeModeScanner>,
    pub response_scanner: Arc<response_scanner::ResponseScanner>,
    pub dlp_scanner: Arc<dlp::DlpScanner>,
    pub injection_scanner: Arc<injection::InjectionScanner>,
    pub semantic_scanner: Arc<semantic::SemanticScanner>,
    pub schema_drift_detector: Arc<schema_drift::SchemaDriftDetector>,
}

impl SharedScanners {
    /// Initialize all scanners once, compiling underlying regex sets.
    pub fn new() -> Result<Self, String> {
        let safe_mode_scanner = Arc::new(
            safe_mode::SafeModeScanner::new()
                .map_err(|e| format!("Failed to compile SafeMode regexes: {}", e))?,
        );
        let response_scanner = Arc::new(
            response_scanner::ResponseScanner::new()
                .map_err(|e| format!("Failed to compile ResponseScanner regexes: {}", e))?,
        );
        let dlp_scanner = Arc::new(
            dlp::DlpScanner::new(None)
                .map_err(|e| format!("Failed to compile DLP regexes: {}", e))?,
        );
        let injection_scanner = Arc::new(
            injection::InjectionScanner::new()
                .map_err(|e| format!("Failed to compile Injection regexes: {}", e))?,
        );
        let semantic_scanner = Arc::new(
            semantic::SemanticScanner::new(semantic::SemanticConfig::default()),
        );
        let schema_drift_detector = Arc::new(
            schema_drift::SchemaDriftDetector::new(None),
        );

        Ok(Self {
            safe_mode_scanner,
            response_scanner,
            dlp_scanner,
            injection_scanner,
            semantic_scanner,
            schema_drift_detector,
        })
    }

    /// Default initialization panicking on regex compile error (for startup convenience).
    pub fn default_compiled() -> Self {
        Self::new().expect("Failed to initialize unified scanner suite")
    }
}

#[cfg(test)]
mod group_policy_test;

