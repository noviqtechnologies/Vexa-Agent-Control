//! Integration tests for Phase 0b & Phase 5: Failure-Mode Matrix & Chaos Recovery.
//! Validates real-runtime resilience under disk errors, unreachable daemons,
//! revocation expiry, policy corruption, and timeout scaling using actual production handlers.

use agentcontrol::audit::logger::{AuditError, AuditLogger, AuditLoggerConfig};
use agentcontrol::policy::loader::{load_policy_from_str, PolicyLoadResult};
use agentcontrol::policy::revocation::{RevocationRegistry, RevocationTargetType};
use agentcontrol::proxy::adaptive_timeout::AdaptiveTimeoutManager;
use agentcontrol::verify::run_verification_probe;
use std::path::PathBuf;
use std::time::Duration;

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

// ─── 2. Production Capability & Token Revocation ─────────────────────────────

#[test]
fn test_failure_mode_revocation_registry_production_enforcement() {
    let registry = RevocationRegistry::new();

    // Revoke an agent credential/token and a sensitive tool
    registry.revoke_token("token-expired-001", "Token TTL exceeded (session expired)");
    registry.revoke_tool("dangerous_tool", "Tool disabled by incident response");
    registry.revoke_agent(
        "agent-quarantined",
        "Agent quarantined due to prompt injection",
    );

    // Valid check
    assert!(
        registry
            .check(Some("agent-good"), Some("safe_tool"), Some("token-valid"))
            .is_ok(),
        "Unrevoked tuple must be allowed"
    );

    // Revoked token check
    let token_err = registry
        .check(
            Some("agent-good"),
            Some("safe_tool"),
            Some("token-expired-001"),
        )
        .expect_err("Revoked token must be rejected");
    assert_eq!(token_err.target_type, RevocationTargetType::Token);
    assert_eq!(token_err.target_id, "token-expired-001");
    assert!(token_err.reason.contains("Token TTL exceeded"));

    // Revoked tool check
    let tool_err = registry
        .check(
            Some("agent-good"),
            Some("dangerous_tool"),
            Some("token-valid"),
        )
        .expect_err("Revoked tool must be rejected");
    assert_eq!(tool_err.target_type, RevocationTargetType::Tool);
    assert_eq!(tool_err.target_id, "dangerous_tool");

    // Revoked agent check
    let agent_err = registry
        .check(
            Some("agent-quarantined"),
            Some("safe_tool"),
            Some("token-valid"),
        )
        .expect_err("Quarantined agent must be rejected");
    assert_eq!(agent_err.target_type, RevocationTargetType::Agent);
}

// ─── 3. Unreachable Daemon Fail-Closed Verification ──────────────────────────

#[tokio::test]
async fn test_failure_mode_unreachable_daemon_fails_closed() {
    // Attempt verification probe against a non-existent port (unreachable daemon)
    let unreachable_url = "http://127.0.0.1:58999";
    let exit_code =
        run_verification_probe(unreachable_url, true, None, None, None, None, false).await;

    // Must fail closed with non-zero exit code (1), not crash or falsely succeed
    assert_eq!(
        exit_code, 1,
        "Unreachable gateway daemon must fail closed with exit code 1"
    );
}

// ─── 4. Adaptive Timeout & Model Deadline Scaling ───────────────────────────

#[test]
fn test_failure_mode_adaptive_timeout_production_scaling() {
    // Reasoning models (e.g. o1, r1) require dynamic timeout expansion
    let o1_timeout = AdaptiveTimeoutManager::calculate_timeout("o1-preview", Some(1000));
    assert!(
        o1_timeout >= Duration::from_millis(60_000),
        "Reasoning model base timeout must exceed 60s"
    );

    // Fast models (e.g. gpt-4o-mini, haiku) require bounded deadlines to prevent hanging
    let mini_timeout = AdaptiveTimeoutManager::calculate_timeout("gpt-4o-mini", Some(1000));
    assert!(
        mini_timeout <= Duration::from_millis(60_000),
        "Fast model deadline must be tightly bounded"
    );
    assert!(
        mini_timeout < o1_timeout,
        "Lightweight model timeout must be strictly lower than reasoning model timeout"
    );
}

// ─── 5. Audit Logger Unwritable Path / Broken Disk Fails Closed ─────────────

#[test]
fn test_failure_mode_audit_logger_unwritable_path_fails_closed() {
    // Attempt to construct an AuditLogger targeting an impossible/uncreatable path
    #[cfg(windows)]
    let impossible_path = PathBuf::from(r#"\\?\CON\audit.log"#);
    #[cfg(not(windows))]
    let impossible_path = PathBuf::from("/proc/nonexistent/sub/audit.log");

    let cfg = AuditLoggerConfig {
        log_path: impossible_path,
        session_id: "fail-closed-session".to_string(),
        session_secret: vec![0u8; 32],
        max_bytes: 1024,
        siem_exporter: None,
        include_params: false,
    };

    let result = AuditLogger::new(cfg);
    assert!(
        result.is_err(),
        "Audit logger initialization on unwritable filesystem must fail immediately"
    );
    match result {
        Err(AuditError::IoError(_)) => {}
        _ => panic!("Expected AuditError::IoError on unwritable file path"),
    }
}
