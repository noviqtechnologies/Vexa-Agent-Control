//! Unit tests verifying US-003 and US-005 acceptance criteria.

use agentcontrol::policy::dlp::{DlpAction, DlpScanner};
use agentcontrol::policy::engine::EvalResult;
use agentcontrol::policy::loader::{load_policy_from_str, PolicyLoadResult};
use agentcontrol::policy::response_scanner::{ResponseScanConfig, ResponseScanner, ScanResult};
use serde_json::json;

// ---------------------------------------------------------------------------
// US-003: Policy Enforcement
// ---------------------------------------------------------------------------

#[test]
fn test_us003_ac1_default_deny_unlisted_tool() {
    let yaml = r#"
version: "2"
default_action: deny
tools:
  - name: "allowed_tool"
    action: "allow"
"#;
    let res = load_policy_from_str(yaml, None);
    if let PolicyLoadResult::Loaded { policy, .. } = res {
        // Allowed tool passes
        assert!(matches!(
            policy.evaluate("allowed_tool", &json!({}), None, &[]),
            EvalResult::Allow { .. }
        ));
        // Unlisted tool is denied immediately
        match policy.evaluate("unlisted_tool", &json!({}), None, &[]) {
            EvalResult::Deny { reason_code, .. } => {
                assert_eq!(reason_code, "not_in_policy");
            }
            _ => panic!("Expected Deny for unlisted tool"),
        }
    } else {
        panic!("Failed to load valid v2 policy");
    }
}

#[test]
fn test_us003_ac2_parameter_validation_bounds_and_regex() {
    let yaml = r#"
version: "2"
default_action: deny
tools:
  - name: "query_db"
    action: "allow"
    parameters:
      - name: "query"
        type: "string"
        required: true
        pattern: "^SELECT.*"
        max_length: 50
      - name: "path"
        type: "string"
        validators:
          - path_traversal
"#;
    let res = load_policy_from_str(yaml, None);
    if let PolicyLoadResult::Loaded { policy, .. } = res {
        // Valid params pass
        assert!(matches!(
            policy.evaluate(
                "query_db",
                &json!({"query": "SELECT * FROM users"}),
                None,
                &[]
            ),
            EvalResult::Allow { .. }
        ));

        // Pattern mismatch blocked
        match policy.evaluate("query_db", &json!({"query": "DROP TABLE users"}), None, &[]) {
            EvalResult::Deny { reason_code, .. } => {
                assert_eq!(reason_code, "param_pattern_mismatch");
            }
            _ => panic!("Expected Deny for pattern mismatch"),
        }

        // Max length exceeded blocked
        let long_query = "SELECT ".to_string() + &"x".repeat(60);
        match policy.evaluate("query_db", &json!({"query": long_query}), None, &[]) {
            EvalResult::Deny { reason_code, .. } => {
                assert_eq!(reason_code, "param_max_length_exceeded");
            }
            _ => panic!("Expected Deny for max length"),
        }

        // Path traversal validator blocked
        match policy.evaluate(
            "query_db",
            &json!({"query": "SELECT 1", "path": "../etc/passwd"}),
            None,
            &[],
        ) {
            EvalResult::Deny {
                reason_code,
                validator_name,
                ..
            } => {
                assert_eq!(reason_code, "validator_failed");
                assert_eq!(validator_name.as_deref(), Some("path_traversal"));
            }
            _ => panic!("Expected Deny for path traversal"),
        }
    } else {
        panic!("Failed to load policy");
    }
}

#[test]
fn test_us003_ac3_unknown_field_rejection_deny_unknown_fields() {
    let yaml = r#"
version: "2"
default_action: deny
unknown_custom_field: "invalid"
tools:
  - name: "test_tool"
    action: "allow"
"#;
    let res = load_policy_from_str(yaml, None);
    match res {
        PolicyLoadResult::Fatal { error } => {
            let err_msg = error.to_string();
            assert!(
                err_msg.contains("unknown field"),
                "Error should mention unknown field: {}",
                err_msg
            );
        }
        _ => panic!("Expected Fatal error for unknown field due to deny_unknown_fields"),
    }
}

#[test]
fn test_us003_ac4_schema_v1_and_v2_accepted() {
    let v1_yaml = r#"
version: "1"
default_action: deny
tools:
  - name: "tool_v1"
    action: "allow"
"#;
    let res1 = load_policy_from_str(v1_yaml, None);
    assert!(
        matches!(res1, PolicyLoadResult::Loaded { .. }),
        "v1 schema should be accepted"
    );

    let v2_yaml = r#"
version: "2"
default_action: deny
tools:
  - name: "tool_v2"
    action: "allow"
"#;
    let res2 = load_policy_from_str(v2_yaml, None);
    assert!(
        matches!(res2, PolicyLoadResult::Loaded { .. }),
        "v2 schema should be accepted"
    );
}

// ---------------------------------------------------------------------------
// US-005: Data Loss Prevention (DLP)
// ---------------------------------------------------------------------------

#[test]
fn test_us005_ac1_request_dlp_block_action() {
    let yaml = r#"
version: "2"
default_action: deny
tools:
  - name: "read_file"
    action: "allow"
llm:
  dlp:
    actions:
      - entity: "AWS Access Key"
        action: "block"
"#;
    let res = load_policy_from_str(yaml, None);
    if let PolicyLoadResult::Loaded { policy, .. } = res {
        let scanner = DlpScanner::new(None).unwrap();
        let content = "My AWS key is AKIAIOSFODNN7EXAMPLE";
        let findings = scanner.scan_content(content);
        assert!(!findings.is_empty());
        let action = scanner.resolve_action(&findings[0], Some(&policy));
        assert_eq!(action, DlpAction::Block);
    } else {
        panic!("Failed to load policy");
    }
}

#[test]
fn test_us005_ac2_request_dlp_redact_action_valid_json() {
    let yaml = r#"
version: "2"
default_action: deny
tools:
  - name: "exec_command"
    action: "allow"
llm:
  dlp:
    actions:
      - entity: "GitHub Token"
        action: "redact"
"#;
    let res = load_policy_from_str(yaml, None);
    if let PolicyLoadResult::Loaded { policy, .. } = res {
        let scanner = DlpScanner::new(None).unwrap();
        let content = "Use token ghp_123456789012345678901234567890123456";
        let findings = scanner.scan_content(content);
        assert!(!findings.is_empty());
        let action = scanner.resolve_action(&findings[0], Some(&policy));
        assert_eq!(action, DlpAction::Redact);

        // Test JSON value redaction produces valid JSON
        let mut val = json!({
            "command": "git push",
            "token": "ghp_123456789012345678901234567890123456"
        });
        scanner.redact_value(&mut val);

        assert!(val.is_object());
        let token_str = val["token"].as_str().unwrap();
        assert!(token_str.contains("[REDACTED:GitHub PAT (ghp)]"));
        assert!(!token_str.contains("ghp_123456789012345678901234567890123456"));
    } else {
        panic!("Failed to load policy");
    }
}

#[test]
fn test_us005_ac3_request_dlp_warn_action() {
    let yaml = r#"
version: "2"
default_action: deny
tools:
  - name: "run_shell"
    action: "allow"
llm:
  dlp:
    actions:
      - entity: "Environment Variable"
        action: "warn"
"#;
    let res = load_policy_from_str(yaml, None);
    if let PolicyLoadResult::Loaded { policy, .. } = res {
        let scanner = DlpScanner::new(None).unwrap();
        let content = "echo $AWS_SECRET_ACCESS_KEY";
        let findings = scanner.scan_content(content);
        assert!(!findings.is_empty());
        let action = scanner.resolve_action(&findings[0], Some(&policy));
        assert_eq!(action, DlpAction::Warn);
    } else {
        panic!("Failed to load policy");
    }
}

#[test]
fn test_us005_ac4_response_dlp_scannable_tools_scanned() {
    let scanner = ResponseScanner::new().unwrap();
    let config = ResponseScanConfig {
        enabled: true,
        block_mode: false,
        dry_run: false,
        max_scan_bytes: 1048576,
        scannable_tools: vec!["read_file".to_string()],
        safe_tools: vec!["ping".to_string()],
    };

    let response = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "content": "Secret key: AKIAIOSFODNN7EXAMPLE"
        }
    });

    let res = scanner.scan_response(&response, "read_file", &config);
    match res {
        ScanResult::Redact { findings } => {
            assert!(!findings.is_empty());
            assert_eq!(findings[0].category.as_str(), "AWS Access Key");
        }
        _ => panic!("Expected Redact for scannable tool with secret"),
    }
}

#[test]
fn test_us005_ac5_response_dlp_safe_tools_bypassed() {
    let scanner = ResponseScanner::new().unwrap();
    let config = ResponseScanConfig {
        enabled: true,
        block_mode: false,
        dry_run: false,
        max_scan_bytes: 1048576,
        scannable_tools: vec!["read_file".to_string()],
        safe_tools: vec!["ping".to_string(), "safe_read".to_string()],
    };

    let response = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "content": "Secret key: AKIAIOSFODNN7EXAMPLE"
        }
    });

    // Tool in safe_tools returns Pass (bypasses DLP scan)
    let res = scanner.scan_response(&response, "safe_read", &config);
    assert!(matches!(res, ScanResult::Pass));
}
