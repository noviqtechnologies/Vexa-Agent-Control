//! Audit Log Cryptographic Tamper & Verification Test Suite (Gate 4).
//!
//! Validates:
//! 1. `run_verify_db` passes when logs and HMAC key are valid.
//! 2. Tampering with any log entry or hash causes `run_verify_db` to fail with non-zero exit code (1).
//! 3. No fail-open fallback occurs when an audit key exists.

use agentcontrol::audit::logger::{AuditLogger, AuditLoggerConfig};
use agentcontrol::audit::maintenance::run_verify_db;
use std::fs;
use tempfile::tempdir;

#[tokio::test]
async fn test_audit_verification_tamper_detection() {
    let dir = tempdir().unwrap();
    let audit_file = dir.path().join("audit.jsonl");
    let key_file = dir.path().join("audit.key");
    let secret = b"super-secret-hmac-key-32-bytes!!".to_vec();
    fs::write(&key_file, &secret).unwrap();

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

    // 1. Untampered: run_verify_db MUST return 0 (PASSED)
    let exit_code = run_verify_db(Some(audit_file.clone()), None);
    assert_eq!(
        exit_code, 0,
        "run_verify_db must return 0 for untampered audit log"
    );

    // 2. Now tamper with the payload of entry 1
    let content = fs::read_to_string(&audit_file).unwrap();
    let tampered_content = content.replace("/etc/hosts", "/etc/shadow");
    fs::write(&audit_file, tampered_content).unwrap();

    // 3. Tampered: run_verify_db MUST return 1 (FAILED)
    let tampered_exit_code = run_verify_db(Some(audit_file.clone()), None);
    assert_eq!(
        tampered_exit_code, 1,
        "run_verify_db must return non-zero exit code (1) when log payload is tampered"
    );
}
