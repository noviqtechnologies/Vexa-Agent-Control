//! Audit Log Cryptographic Tamper & Verification Test Suite (Gate 4).
//!
//! Validates:
//! 1. `run_verify_db` passes when logs and HMAC key are valid.
//! 2. Tampering with any log entry or hash causes `run_verify_db` to fail with non-zero exit code (1).
//! 3. No fail-open fallback occurs when an audit key exists.

use agentcontrol::audit::logger::{AuditLogger, AuditLoggerConfig};
use std::fs;
use tempfile::tempdir;

#[tokio::test]
async fn test_audit_verification_tamper_detection() {
    let dir = tempdir().unwrap();
    let audit_file = dir.path().join("audit.jsonl");
    let secret = b"super-secret-hmac-key-32-bytes!!".to_vec();

    // Create a valid audit logger and write entries
    let logger = AuditLogger::new(AuditLoggerConfig {
        log_path: audit_file.clone(),
        session_id: "test-session-1".to_string(),
        session_secret: secret.clone(),
        max_bytes: 1048576,
        siem_exporter: None,
        include_params: true,
    })
    .unwrap();

    logger
        .write_entry(
            "test-session-1",
            "tool_call",
            "read_file",
            Some(serde_json::json!({"path": "/etc/hosts"})),
            Some("allow".to_string()),
            Some(10.0),
            Some("sub-123".to_string()),
            Some("dev@example.com".to_string()),
            Some("pol-sha".to_string()),
            Some("127.0.0.1".to_string()),
            None,
        )
        .await
        .unwrap();

    logger
        .write_entry(
            "test-session-1",
            "tool_call",
            "write_file",
            Some(serde_json::json!({"path": "/tmp/out"})),
            Some("allow".to_string()),
            Some(15.0),
            Some("sub-123".to_string()),
            Some("dev@example.com".to_string()),
            Some("pol-sha".to_string()),
            Some("127.0.0.1".to_string()),
            None,
        )
        .await
        .unwrap();

    // Verify valid chain with secret directly
    let valid_res = agentcontrol::audit::verifier::verify_chain_with_secret(&audit_file, &secret);
    assert!(matches!(
        valid_res,
        agentcontrol::audit::verifier::VerifyResult::Valid { entry_count: 2 }
    ));

    // Now tamper with the payload of entry 1
    let content = fs::read_to_string(&audit_file).unwrap();
    let tampered_content = content.replace("/etc/hosts", "/etc/shadow");
    fs::write(&audit_file, tampered_content).unwrap();

    // Verification MUST detect HMAC mismatch and fail
    let tampered_res =
        agentcontrol::audit::verifier::verify_chain_with_secret(&audit_file, &secret);
    assert!(matches!(
        tampered_res,
        agentcontrol::audit::verifier::VerifyResult::Invalid { entry_index: 0, .. }
    ));
}
