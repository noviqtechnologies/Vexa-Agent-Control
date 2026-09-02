use agentcontrol::policy::engine::CompiledPolicy;
use agentcontrol::policy::snapshot::{ConfigSnapshot, ConfigSnapshotStore};
use agentcontrol::proxy::pipeline::{OperationKind, RequestContext, SecurityVerdict};
use agentcontrol::proxy::replay_guard::{ReplayClassification, ReplayGuard};

#[test]
fn test_request_context_creation_and_elapsed() {
    let ctx = RequestContext::new(
        "req-123".to_string(),
        "sess-abc".to_string(),
        "tenant-primary".to_string(),
        Some("user-sub-1".to_string()),
        Some("user@company.com".to_string()),
        vec!["engineering".to_string()],
        "127.0.0.1".to_string(),
        OperationKind::LlmCompletion {
            model: "gpt-4o".to_string(),
            stream: false,
        },
        "snap-1".to_string(),
    );

    assert_eq!(ctx.request_id, "req-123");
    assert_eq!(ctx.tenant_id, "tenant-primary");
    assert!(ctx.elapsed_ms() >= 0.0);
    assert_eq!(ctx.operation_kind.operation_name(), "gpt-4o");
    assert!(ctx.operation_kind.is_retryable());
}

#[test]
fn test_operation_kind_replay_classification() {
    let llm_op = OperationKind::LlmCompletion {
        model: "claude-3-5-sonnet".to_string(),
        stream: false,
    };
    assert_eq!(
        ReplayGuard::classify(&llm_op, false, None),
        ReplayClassification::CanRetry { max_attempts: 3 }
    );

    // If stream already committed to client, replay is blocked
    assert_eq!(
        ReplayGuard::classify(&llm_op, true, None),
        ReplayClassification::CannotRetry {
            reason: "Stream already committed to client"
        }
    );

    // Non-idempotent MCP tool call cannot be replayed
    let mut_tool = OperationKind::McpToolCall {
        tool_name: "execute_sql_mutation".to_string(),
        is_idempotent: false,
    };
    assert_eq!(
        ReplayGuard::classify(&mut_tool, false, None),
        ReplayClassification::CannotRetry {
            reason: "Side-effecting MCP tool call is non-idempotent"
        }
    );

    // Idempotent MCP tool call can be replayed
    let read_tool = OperationKind::McpToolCall {
        tool_name: "read_file".to_string(),
        is_idempotent: true,
    };
    assert_eq!(
        ReplayGuard::classify(&read_tool, false, None),
        ReplayClassification::CanRetry { max_attempts: 2 }
    );
}

#[test]
fn test_config_snapshot_store_atomic_swaps() {
    let store = ConfigSnapshotStore::default();
    let initial = store.get_current();
    assert_eq!(initial.version, 0);

    let new_policy = CompiledPolicy::default();
    let snap1 = ConfigSnapshot::new(1, new_policy, Some(b"version: 1\ndefault_action: deny\n"));
    assert_eq!(snap1.version, 1);
    assert!(snap1.snapshot_id.starts_with("snap-1-"));

    let prev = store.swap(snap1);
    assert_eq!(prev.version, 0);

    let active = store.get_current();
    assert_eq!(active.version, 1);
    assert!(active.policy_hash.starts_with("sha256:"));
}

#[test]
fn test_security_verdict_helpers() {
    let allow = SecurityVerdict::Allow {
        matched_group_id: Some("devs".to_string()),
        risk_score: Some(0.1),
    };
    assert!(allow.is_allowed());

    let deny = SecurityVerdict::Deny {
        reason_code: "dlp_blocked".to_string(),
        message: "Secret pattern matched".to_string(),
        rule_id: Some("DLP-01".to_string()),
        param_name: Some("query".to_string()),
    };
    assert!(!deny.is_allowed());
}
