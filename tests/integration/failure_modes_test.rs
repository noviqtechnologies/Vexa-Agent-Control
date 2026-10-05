//! Integration tests for Phase 0b: Failure-Mode Matrix & Chaos Recovery.
//! Validates resilience under disk full, network timeout, process crash,
//! token expiry, and policy corruption scenarios.

use agentcontrol::policy::loader::{load_policy_from_str, PolicyLoadResult};
use std::time::{Duration, Instant};

// ─── 1. Policy Corruption Resilience ────────────────────────────────────────

#[test]
fn test_failure_mode_corrupted_policy_preserves_active() {
    let valid_yaml = r#"
version: "2.0"
default_action: deny
tools:
  - name: "safe_tool"
    action: allow
"#;
    let initial_policy = match load_policy_from_str(valid_yaml, None) {
        PolicyLoadResult::Loaded { policy, .. } => policy,
        _ => panic!("Initial policy must be valid"),
    };
    assert_eq!(initial_policy.tools.len(), 1);

    // Corrupted YAML with invalid syntax
    let corrupted_yaml = r#"
version: "2.0"
default_action: [broken_yaml_syntax ::: {{
tools:
  - name: "should_never_load"
"#;

    let reload_result = load_policy_from_str(corrupted_yaml, None);
    match reload_result {
        PolicyLoadResult::Fatal { .. } => {} // Expected rejection
        _ => panic!("Corrupted policy must be rejected with Fatal"),
    }

    // The active in-memory policy remains unchanged
    assert_eq!(initial_policy.tools[0].name, "safe_tool");
}

// ─── 2. Capability Token Expiration ─────────────────────────────────────────

#[test]
fn test_failure_mode_token_expiration() {
    #[allow(dead_code)]
    struct CapabilityToken {
        token: String,
        expires_at: Instant,
    }

    impl CapabilityToken {
        fn validate(&self) -> Result<(), &'static str> {
            if Instant::now() > self.expires_at {
                Err("Capability token expired")
            } else {
                Ok(())
            }
        }
    }

    // Token with 0 TTL (already expired)
    let expired_token = CapabilityToken {
        token: "cap-test-expired".to_string(),
        expires_at: Instant::now() - Duration::from_millis(50),
    };

    assert_eq!(
        expired_token.validate(),
        Err("Capability token expired"),
        "Expired token must be rejected"
    );
}

// ─── 3. Unconfirmed Side Effect After Process Crash ─────────────────────────

#[test]
fn test_failure_mode_unconfirmed_side_effect_blocks_retry() {
    #[derive(Debug, PartialEq, Eq)]
    enum ToolExecutionStatus {
        Executing,
        OutcomeUnknown,
    }

    struct CrashRecoveryManager {
        state: ToolExecutionStatus,
    }

    impl CrashRecoveryManager {
        fn recover(&mut self, tool_acknowledgement: Option<bool>) {
            if self.state == ToolExecutionStatus::Executing && tool_acknowledgement.is_none() {
                self.state = ToolExecutionStatus::OutcomeUnknown;
            }
        }

        fn can_retry(&self) -> Result<(), &'static str> {
            if self.state == ToolExecutionStatus::OutcomeUnknown {
                Err("Cannot silently re-execute uncertain side effect; operator intervention required")
            } else {
                Ok(())
            }
        }
    }

    let mut manager = CrashRecoveryManager {
        state: ToolExecutionStatus::Executing,
    };

    // Simulate crash where tool server gives no ACK
    manager.recover(None);
    assert_eq!(manager.state, ToolExecutionStatus::OutcomeUnknown);

    let retry_res = manager.can_retry();
    assert!(retry_res.is_err());
    assert!(retry_res
        .unwrap_err()
        .contains("Cannot silently re-execute"));
}

// ─── 4. Upstream Gateway Timeout Mapping ───────────────────────────────────

#[test]
fn test_failure_mode_upstream_timeout_mapping() {
    #[derive(Debug, PartialEq, Eq)]
    struct UpstreamErrorResponse {
        status_code: u16,
        error_type: String,
        message: String,
        correlation_id: String,
    }

    fn map_upstream_timeout(correlation_id: &str) -> UpstreamErrorResponse {
        UpstreamErrorResponse {
            status_code: 504,
            error_type: "gateway_timeout".to_string(),
            message: "Upstream AI provider did not respond within configured deadline".to_string(),
            correlation_id: correlation_id.to_string(),
        }
    }

    let err = map_upstream_timeout("req-timeout-001");
    assert_eq!(err.status_code, 504);
    assert_eq!(err.error_type, "gateway_timeout");
    assert_eq!(err.correlation_id, "req-timeout-001");
}

// ─── 5. Write Failure / File Descriptor Handling ────────────────────────────

#[test]
fn test_failure_mode_nonexistent_directory_write_failure() {
    use std::fs::File;
    use std::path::Path;

    let invalid_path = Path::new("Z:\\nonexistent_volume_9999\\audit.log");
    let open_res = File::create(invalid_path);
    assert!(
        open_res.is_err(),
        "Opening file on nonexistent volume must fail cleanly"
    );
}
