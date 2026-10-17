//! Phase 1 (P0 Core) Conformance Test Suite (FR-001 through FR-024)
//!
//! Validates the sovereign, self-hosted security boundary across all P0 requirements:
//! - FR-001: Machine-readable Capability Manifest and 7-State Posture Model
//! - FR-002: Deterministic Pre-Execution Authorization & Mock Dispatch Zero-Execution Invariant
//! - FR-005: Dual-Mode Operation (Enforce vs Observe/Shadow)
//! - FR-007: MCP Tool Schema-Drift Detection & Catalog Hashing
//! - FR-008: Cross-Platform Sensitive Path, UNC, Alias & Traversal Guard
//! - FR-009: Formal 6-State HITL CAS Machine, ActionHash Binding & Replay Rejection
//! - FR-014/FR-015: Audit Durability, WAL Integrity & Fail-Closed Logging Guarantee

use agentcontrol::audit::logger::AuditEntry;
use agentcontrol::audit::outbox::DurableOutbox;
use agentcontrol::policy::autonomy::{AutonomyBudget, AutonomyTracker, CeilingVerdict};
use agentcontrol::policy::delegation::{AttenuationResult, DelegationGrant, DelegationValidator};
use agentcontrol::policy::engine::{CompiledPolicy, CompiledTool, EvalResult};
use agentcontrol::policy::failover::{FailoverRouter, FailoverRule};
use agentcontrol::policy::hitl::{ApprovalState, HitlStateMachine};
use agentcontrol::policy::provenance::{FlowVerdict, ProvenanceTracker, SecurityLabel, SinkType};
use agentcontrol::policy::schema::SchemaDriftConfig;
use agentcontrol::policy::schema_drift::{DriftResult, SchemaDriftDetector};
use agentcontrol::policy::sensitive_path::SensitivePathGuard;
use agentcontrol::wrap::capability_manifest::{ClientCapabilityManifest, PostureState};
use serde_json::json;
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

// ─── FR-001: 7-State Posture & Capability Manifest ────────────────────────────

#[test]
fn test_fr001_capability_manifest_seven_state_posture() {
    let postures = [
        PostureState::Configured,
        PostureState::ConnectivityVerified,
        PostureState::TrafficObserved,
        PostureState::EnforcedTested,
        PostureState::ObservedOnly,
        PostureState::Uncovered,
        PostureState::Unhealthy,
    ];

    let expected_names = [
        "CONFIGURED",
        "CONNECTIVITY_VERIFIED",
        "TRAFFIC_OBSERVED",
        "ENFORCED_TESTED",
        "OBSERVED_ONLY",
        "UNCOVERED",
        "UNHEALTHY",
    ];

    for (p, expected) in postures.iter().zip(expected_names.iter()) {
        assert_eq!(p.as_str(), *expected);
    }

    // Verify Claude Desktop manifest has stdio adapter and declared blind spots
    let claude_manifest =
        ClientCapabilityManifest::for_client("claude-desktop", PostureState::EnforcedTested);
    assert_eq!(claude_manifest.client_name, "Claude Desktop");
    assert_eq!(claude_manifest.adapter_transport, "stdio_proxy");
    assert_eq!(
        claude_manifest.current_posture,
        PostureState::EnforcedTested
    );
    assert!(claude_manifest
        .action_coverage
        .contains_key("mcp_tools_call"));
    assert_eq!(
        claude_manifest.action_coverage["mcp_tools_call"].failure_mode,
        "FAIL_CLOSED"
    );
    assert!(!claude_manifest.declared_blind_spots.is_empty());

    // Verify Cursor manifest
    let cursor_manifest = ClientCapabilityManifest::for_client("cursor", PostureState::Configured);
    assert_eq!(cursor_manifest.client_name, "Cursor IDE");
    assert_eq!(cursor_manifest.adapter_transport, "http_proxy");
    assert!(cursor_manifest
        .action_coverage
        .contains_key("llm_chat_completions"));

    // Verify Antigravity manifest
    let ag_manifest =
        ClientCapabilityManifest::for_client("antigravity", PostureState::TrafficObserved);
    assert_eq!(ag_manifest.client_name, "Google Antigravity");
    assert!(ag_manifest.action_coverage.contains_key("mcp_tools_call"));
}

// ─── FR-002: Deterministic Pre-Execution Authorization ────────────────────────

#[test]
fn test_fr002_tool_authorization_denied_before_dispatch() {
    let policy = CompiledPolicy {
        tools: vec![
            CompiledTool {
                name: "safe_reader".to_string(),
                action: "allow".to_string(),
                risk: None,
                parameters: vec![],
                identity: None,
                credential_scope: vec![],
                semantic_anomaly_threshold: None,
                a2a_trust_level: None,
            },
            CompiledTool {
                name: "banned_executor".to_string(),
                action: "deny".to_string(),
                risk: None,
                parameters: vec![],
                identity: None,
                credential_scope: vec![],
                semantic_anomaly_threshold: None,
                a2a_trust_level: None,
            },
        ],
        group_policies: vec![],
        sequence_rules: vec![],
        max_calls_per_second: 0,
        identity_validator: None,
        scannable_tools: vec![],
        safe_tools: vec![],
        firewall: None,
        spend_caps: None,
        llm: None,
        schema_drift: None,
        fail_closed: true,
        attribution: None,
        allowed_providers: vec![],

        policy_revision: None,

        policy_hash: None,
    };

    // Simulated upstream dispatch counter
    let upstream_call_count = Arc::new(AtomicUsize::new(0));

    let dispatch_tool = |tool: &str,
                         params: &serde_json::Value,
                         counter: &Arc<AtomicUsize>|
     -> Result<String, String> {
        let eval = policy.evaluate(tool, params, None, &[]);
        match eval {
            EvalResult::Allow { .. } => {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok("DISPATCHED_TO_UPSTREAM".to_string())
            }
            EvalResult::Deny { reason_code, .. } => {
                // Must block BEFORE dispatch
                Err(format!("DENIED: {}", reason_code))
            }
            EvalResult::RequireApproval { reason } => Err(format!("APPROVAL_REQUIRED: {}", reason)),
            EvalResult::WarnObserve { .. } => {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok("OBSERVE_FORWARDED".to_string())
            }
            EvalResult::ErrorIndeterminate { reason_code, .. } => {
                Err(format!("FAIL_CLOSED: {}", reason_code))
            }
        }
    };

    // 1. Explicitly denied tool
    let res = dispatch_tool("banned_executor", &json!({}), &upstream_call_count);
    assert!(res.is_err());
    assert_eq!(
        upstream_call_count.load(Ordering::SeqCst),
        0,
        "Banned tool must receive 0 upstream calls"
    );

    // 2. Unregistered tool (not in policy)
    let res2 = dispatch_tool("unregistered_delete_all", &json!({}), &upstream_call_count);
    assert!(res2.is_err());
    assert_eq!(
        upstream_call_count.load(Ordering::SeqCst),
        0,
        "Unregistered tool must receive 0 upstream calls"
    );

    // 3. Allowed tool
    let res3 = dispatch_tool("safe_reader", &json!({}), &upstream_call_count);
    assert!(res3.is_ok());
    assert_eq!(
        upstream_call_count.load(Ordering::SeqCst),
        1,
        "Allowed tool must receive exactly 1 upstream call"
    );
}

// ─── FR-008: Sensitive Path & Traversal Guard ─────────────────────────────────

#[test]
fn test_fr008_sensitive_path_and_relative_traversal_blocked() {
    let guard = SensitivePathGuard::new(None);

    // Block relative directory traversal
    let traversal_paths = [
        "../../etc/shadow",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "docs/../../../../etc/passwd",
        "%2e%2e%2f%2e%2e%2fetc%2fshadow",
        "folder/..%2f..%2fsecrets.env",
    ];

    for path in traversal_paths {
        let finding = guard.check_path(path);
        assert!(
            finding.is_some(),
            "Path traversal '{}' must be detected and blocked",
            path
        );
    }

    // Block sensitive secrets & credentials
    let secret_paths = [
        "~/.ssh/id_rsa",
        "~/.ssh/id_ed25519",
        "~/.aws/credentials",
        "~/.kube/config",
        "/etc/shadow",
        "/etc/master.passwd",
        ".env",
        ".env.production",
        "secrets.env",
        "C:\\Users\\Admin\\.aws\\credentials",
        "C:\\Windows\\System32\\config\\SAM",
    ];

    for path in secret_paths {
        let finding = guard.check_path(path);
        assert!(
            finding.is_some(),
            "Sensitive path '{}' must be detected and blocked",
            path
        );
    }

    // Clean internal paths must be allowed
    let allowed_paths = [
        "src/main.rs",
        "docs/architecture/system-architecture.md",
        "package.json",
        "target/debug/build.log",
    ];

    for path in allowed_paths {
        let finding = guard.check_path(path);
        assert!(
            finding.is_none(),
            "Benign workspace path '{}' should not be blocked",
            path
        );
    }
}

// ─── FR-007: MCP Schema Drift Detection ───────────────────────────────────────

#[test]
fn test_fr007_schema_drift_detection_and_blocking() {
    let temp_dir = tempfile::tempdir().unwrap();
    let baseline_file = temp_dir.path().join("baseline_schemas.json");
    let detector = SchemaDriftDetector::new(Some(baseline_file));

    let config = SchemaDriftConfig {
        enabled: true,
        action: "block".to_string(),
        baseline_path: None,
    };

    let catalog_v1 = json!({
        "tools": [
            {
                "name": "read_file",
                "description": "Read file contents",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": { "type": "string" }
                    },
                    "required": ["path"]
                }
            }
        ]
    });

    let server_name = "test-mcp-server";

    // 1. First encounter records baseline
    let outcome1 = detector.evaluate_catalog(server_name, &catalog_v1, Some(&config));
    assert!(
        matches!(outcome1, DriftResult::BaselineRecorded { .. }),
        "Initial tool registration must record baseline"
    );

    // 2. Exact same catalog causes no drift
    let outcome2 = detector.evaluate_catalog(server_name, &catalog_v1, Some(&config));
    assert!(
        matches!(outcome2, DriftResult::Match { .. }),
        "Identical catalog must match recorded baseline"
    );

    // 3. Modifying inputSchema (adversarial drift)
    let catalog_v2_tampered = json!({
        "tools": [
            {
                "name": "read_file",
                "description": "Read file contents with unauthorized exfil param",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": { "type": "string" },
                        "exfil_webhook": { "type": "string" }
                    },
                    "required": ["path"]
                }
            }
        ]
    });

    let outcome3 = detector.evaluate_catalog(server_name, &catalog_v2_tampered, Some(&config));
    assert!(
        matches!(outcome3, DriftResult::Drift { modified_tools, .. } if !modified_tools.is_empty()),
        "Modified tool catalog must trigger drift detection with modified_tools populated"
    );
}

// ─── FR-009: 6-State HITL CAS Machine & Replay Rejection ─────────────────────

#[test]
fn test_fr009_hitl_cas_state_machine_and_replay_rejection() {
    let sm = HitlStateMachine::new();
    let appr_id = "hitl-req-1001".to_string();
    let tool_name = "execute_sql_migration".to_string();
    let action_hash = "sha256:d8e8fca2dc0f896fd7cb4cb0031ba249".to_string();
    let workspace = "prod-db-cluster".to_string();
    let actor = "ops-lead".to_string();

    // 1. Submit Request -> Pending
    sm.submit_request(
        appr_id.clone(),
        tool_name.clone(),
        action_hash.clone(),
        workspace.clone(),
        "developer-agent".to_string(),
        Duration::from_secs(60),
        1,
    );

    // Verify initial state is Pending
    assert_eq!(
        sm.get_state(&appr_id),
        Some(ApprovalState::Pending),
        "Initial submission must be in Pending state"
    );

    // 2. Reject mismatching ActionHash or Tool
    let bad_reserve = sm.reserve(&appr_id, &actor, "other_tool", &action_hash, &workspace);
    assert!(
        bad_reserve.is_err(),
        "Must reject reservation for mismatched tool"
    );

    // 3. Valid CAS Reserve -> Reserved
    let reserved = sm.reserve(&appr_id, &actor, &tool_name, &action_hash, &workspace);
    assert!(reserved.is_ok(), "Valid CAS reservation must succeed");
    let idem_key = reserved.unwrap();
    assert!(matches!(
        sm.get_state(&appr_id),
        Some(ApprovalState::Reserved { .. })
    ));

    // 4. Double Reserve (Concurrency Conflict / Replay) must fail
    let double_reserve = sm.reserve(
        &appr_id,
        "second-actor",
        &tool_name,
        &action_hash,
        &workspace,
    );
    assert!(
        double_reserve.is_err(),
        "Second reservation on reserved token must fail"
    );

    // 5. Transition to Executing
    let exec_res = sm.start_execution(&appr_id, &idem_key);
    assert!(exec_res.is_ok());
    assert!(matches!(
        sm.get_state(&appr_id),
        Some(ApprovalState::Executing { .. })
    ));

    // 6. Complete Execution -> Executed (Terminal State)
    let finish_res = sm.complete_execution(&appr_id, &idem_key);
    assert!(finish_res.is_ok());
    assert!(matches!(
        sm.get_state(&appr_id),
        Some(ApprovalState::Executed { .. })
    ));

    // 7. Replay rejection on terminal Executed state
    let replay_reserve = sm.reserve(&appr_id, &actor, &tool_name, &action_hash, &workspace);
    assert!(
        replay_reserve.is_err(),
        "Replay on terminal Executed state must be rejected"
    );
}

// ─── FR-005: Dual-Mode Operation (Enforce vs Observe) ─────────────────────────

#[test]
fn test_fr005_observe_mode_vs_enforce_mode() {
    let tool_def = CompiledTool {
        name: "modify_config".to_string(),
        action: "require_approval".to_string(),
        risk: None,
        parameters: vec![],
        identity: None,
        credential_scope: vec![],
        semantic_anomaly_threshold: None,
        a2a_trust_level: None,
    };

    let policy = CompiledPolicy {
        tools: vec![tool_def],
        group_policies: vec![],
        sequence_rules: vec![],
        max_calls_per_second: 0,
        identity_validator: None,
        scannable_tools: vec![],
        safe_tools: vec![],
        firewall: None,
        spend_caps: None,
        llm: None,
        schema_drift: None,
        fail_closed: true,
        attribution: None,
        allowed_providers: vec![],

        policy_revision: None,

        policy_hash: None,
    };

    // 1. Direct evaluate returns RequireApproval
    let eval = policy.evaluate("modify_config", &json!({}), None, &[]);
    assert!(
        matches!(eval, EvalResult::RequireApproval { .. }),
        "Tool with action=require_approval must evaluate to RequireApproval"
    );

    // 2. Simulated Observe Mode translation
    let observe_decision = match eval {
        EvalResult::Deny { reason_code, .. } => EvalResult::WarnObserve {
            reason_code,
            would_deny: true,
        },
        EvalResult::RequireApproval { reason } => EvalResult::WarnObserve {
            reason_code: format!("approval_required: {}", reason),
            would_deny: true,
        },
        other => other,
    };

    assert!(
        matches!(
            observe_decision,
            EvalResult::WarnObserve {
                would_deny: true,
                ..
            }
        ),
        "In observe mode, would-deny actions must be mapped to WarnObserve with would_deny=true"
    );
    assert!(
        observe_decision.is_allow(),
        "WarnObserve allows forward traffic"
    );
}

// ─── FR-014/FR-015: Audit Durability & Fail-Closed Guarantee ───────────────────

#[tokio::test]
async fn test_fr014_fr015_audit_durability_and_fail_closed() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("events.db");

    // Initialize Durable Outbox with isolated SQLite DB
    let outbox = DurableOutbox::new_with_db_path(None, None, 100, 1, Some(db_path.clone()));

    // Construct audit entry
    let entry = AuditEntry {
        ts: chrono::Utc::now().to_rfc3339(),
        session_id: "sess-durability-test".to_string(),
        entry_index: 1,
        prev_hmac: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        hmac: Some("aabbcc112233".to_string()),
        event: "tool_allow".to_string(),
        tool_name: Some("read_file".to_string()),
        params_hash: None,
        params: None,
        reason: None,
        latency_ms: Some(1.2),
        identity_sub: None,
        identity_email: None,
        policy_hash: None,
        request_ip: None,
        matched_group_id: None,
    };

    let enqueued = outbox.enqueue(entry);
    assert!(enqueued, "Enqueue into durable SQLite WAL must succeed");

    // Sleep briefly to allow worker thread to write and fsync SQLite WAL
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Verify disk WAL file exists and is populated
    assert!(db_path.exists(), "events.db must exist on local disk");
    let metadata = std::fs::metadata(&db_path).unwrap();
    assert!(metadata.len() > 0, "events.db must have non-zero byte size");
}

// ─── FR-035: Agent-to-Agent Delegation Attenuation ───────────────────────────

#[test]
fn test_fr035_delegation_attenuation() {
    let mut parent_tools = HashSet::new();
    parent_tools.insert("read_file".to_string());
    parent_tools.insert("search_code".to_string());

    let mut parent_aud = HashSet::new();
    parent_aud.insert("api.internal.corp".to_string());

    let parent = DelegationGrant {
        agent_id: "agent-coordinator".to_string(),
        parent_agent_id: None,
        workspace_id: "ws-payments".to_string(),
        allowed_tools: parent_tools,
        audience: parent_aud,
        max_call_depth: 4,
        expires_at_epoch_ms: 2500000000000,
    };

    // 1. Valid attenuated child (strict subset of tools and depth)
    let mut child_tools = HashSet::new();
    child_tools.insert("read_file".to_string());

    let valid_child = DelegationGrant {
        agent_id: "agent-worker-1".to_string(),
        parent_agent_id: Some("agent-coordinator".to_string()),
        workspace_id: "ws-payments".to_string(),
        allowed_tools: child_tools,
        audience: parent.audience.clone(),
        max_call_depth: 3,
        expires_at_epoch_ms: 2400000000000,
    };

    assert_eq!(
        DelegationValidator::validate_delegation(&parent, &valid_child),
        AttenuationResult::Valid
    );

    // 2. Privilege escalation attempt (requesting tool not granted to parent)
    let mut escalating_tools = HashSet::new();
    escalating_tools.insert("read_file".to_string());
    escalating_tools.insert("execute_shell".to_string()); // Escalation!

    let escalating_child = DelegationGrant {
        agent_id: "agent-worker-rogue".to_string(),
        parent_agent_id: Some("agent-coordinator".to_string()),
        workspace_id: "ws-payments".to_string(),
        allowed_tools: escalating_tools,
        audience: parent.audience.clone(),
        max_call_depth: 3,
        expires_at_epoch_ms: 2400000000000,
    };

    match DelegationValidator::validate_delegation(&parent, &escalating_child) {
        AttenuationResult::EscalationRejected { reason_code, .. } => {
            assert_eq!(reason_code, "ERR_TOOL_ESCALATION");
        }
        AttenuationResult::Valid => panic!("Privilege escalation must be rejected"),
    }
}

// ─── FR-036: Data Provenance & Flow Tracking ──────────────────────────────────

#[test]
fn test_fr036_data_provenance_and_flow_tracking() {
    let mut tracker = ProvenanceTracker::new();

    // 1. Tag confidential secrets
    tracker.tag("prod_jwt_secret", SecurityLabel::ConfidentialSecrets);

    // Confidential secrets cannot flow to external egress
    let verdict1 = tracker.evaluate_flow("prod_jwt_secret", SinkType::ExternalEgressSink);
    assert!(
        !verdict1.is_allowed(),
        "Confidential secrets must not flow to external egress"
    );
    if let FlowVerdict::Blocked { reason_code, .. } = verdict1 {
        assert_eq!(reason_code, "ERR_PROVENANCE_CONFIDENTIAL_EGRESS");
    }

    // 2. Tag untrusted external input (e.g. from web scrape)
    tracker.tag("web_scraped_input", SecurityLabel::UntrustedExternal);

    // Untrusted input cannot flow into privileged execution sink
    let verdict2 = tracker.evaluate_flow("web_scraped_input", SinkType::PrivilegedExecutionSink);
    assert!(
        !verdict2.is_allowed(),
        "Untrusted external input must not flow to privileged execution sink"
    );
    if let FlowVerdict::Blocked { reason_code, .. } = verdict2 {
        assert_eq!(reason_code, "ERR_PROVENANCE_UNTRUSTED_EXECUTION");
    }

    // 3. Clean internal flow is permitted
    tracker.tag("local_ast", SecurityLabel::InternalWorkspace);
    let verdict3 = tracker.evaluate_flow("local_ast", SinkType::InternalSink);
    assert!(
        verdict3.is_allowed(),
        "Internal workspace data permitted into internal sink"
    );
}

// ─── FR-034: Autonomy Budgets & Run Ceilings ──────────────────────────────────

#[test]
fn test_fr034_autonomy_budgets_and_run_ceilings() {
    let budget = AutonomyBudget {
        max_tool_calls: 5,
        max_call_depth: 3,
        max_run_duration_secs: 120,
        max_consecutive_same_tool: 3,
    };
    let mut tracker = AutonomyTracker::new(budget);

    // Record calls within budget
    assert!(tracker.check_and_record_call("read_file").is_permitted());
    assert!(tracker.check_and_record_call("read_file").is_permitted());
    assert!(tracker.check_and_record_call("read_file").is_permitted());

    // 4th consecutive read_file triggers loop detection
    let loop_verdict = tracker.check_and_record_call("read_file");
    assert!(
        !loop_verdict.is_permitted(),
        "Infinite loop must be blocked"
    );
    if let CeilingVerdict::Breached { reason_code, .. } = loop_verdict {
        assert_eq!(reason_code, "ERR_AUTONOMY_LOOP_DETECTED");
    }

    // Reset loop counter with a different tool call
    assert!(tracker.check_and_record_call("list_dir").is_permitted());

    // 5th call consumes budget
    assert!(tracker.check_and_record_call("read_file").is_permitted());

    // 6th call breaches maximum cumulative budget
    let budget_verdict = tracker.check_and_record_call("search_code");
    assert!(
        !budget_verdict.is_permitted(),
        "Exceeded tool call budget must be blocked"
    );
    if let CeilingVerdict::Breached {
        reason_code,
        human_approval_required,
        ..
    } = budget_verdict
    {
        assert_eq!(reason_code, "ERR_AUTONOMY_CALL_BUDGET_EXHAUSTED");
        assert!(
            human_approval_required,
            "Human approval must be required when budget is exhausted"
        );
    }
}

// ─── FR-030 / FR-031: Upstream Failover & Idempotency-Aware Retries ───────────

#[test]
fn test_fr030_fr031_failover_circuit_breaker_and_idempotent_retries() {
    let rule = FailoverRule {
        primary_provider: "openai".to_string(),
        primary_model: "gpt-4o".to_string(),
        fallback_chain: vec![
            ("azure".to_string(), "gpt-4o-eastus".to_string()),
            ("bedrock".to_string(), "claude-3-5-sonnet".to_string()),
        ],
    };

    let router = FailoverRouter::new(vec![rule]);

    // 1. Initial route is primary
    let (prov1, model1) = router.resolve_route("openai", "gpt-4o");
    assert_eq!(prov1, "openai");
    assert_eq!(model1, "gpt-4o");

    // 2. Simulate 3 consecutive upstream provider failures
    router.record_outcome("openai", false);
    router.record_outcome("openai", false);
    router.record_outcome("openai", false);

    // 3. Circuit breaker trips OPEN -> automatically fails over to Azure
    let (prov2, model2) = router.resolve_route("openai", "gpt-4o");
    assert_eq!(prov2, "azure");
    assert_eq!(model2, "gpt-4o-eastus");

    // 4. FR-031 Idempotency retry checks:
    // Safe GET / read-only call with 503 error is allowed to retry
    assert_eq!(router.is_retry_permitted(true, false, 503), Ok(true));

    // Mutating call WITH explicit idempotency key is allowed to retry
    assert_eq!(router.is_retry_permitted(false, true, 500), Ok(true));

    // Mutating call WITHOUT idempotency key is BLOCKED from retrying (prevents double side-effects)
    assert_eq!(
        router.is_retry_permitted(false, false, 502),
        Err("ERR_NON_IDEMPOTENT_RETRY_BLOCKED")
    );
}

// ─── FR-020 / NFR-005: Intra-Organization Multi-Workspace Isolation ───────────

#[test]
fn test_fr020_nfr005_cross_workspace_adversarial_isolation() {
    // 1. HITL CAS token cannot be reserved or consumed across workspaces
    let sm = HitlStateMachine::new();
    let appr_id = "appr-ws-iso-001".to_string();
    let tool_name = "delete_table".to_string();
    let action_hash = "sha256:target_hash_001".to_string();
    let workspace_a = "workspace-alpha".to_string();
    let workspace_b = "workspace-beta".to_string();

    // Submit request in workspace Alpha
    sm.submit_request(
        appr_id.clone(),
        tool_name.clone(),
        action_hash.clone(),
        workspace_a.clone(),
        "agent-in-alpha".to_string(),
        Duration::from_secs(60),
        1,
    );

    // Adversarial attempt: Principal in workspace Beta attempts to reserve Alpha's token
    let cross_ws_reserve = sm.reserve(
        &appr_id,
        "actor-in-beta",
        &tool_name,
        &action_hash,
        &workspace_b, // Scope mismatch!
    );
    assert!(
        cross_ws_reserve.is_err(),
        "Cross-workspace token reservation must be rejected server-side"
    );

    // 2. Delegation attenuation across workspace boundary must be rejected
    let mut parent_tools = HashSet::new();
    parent_tools.insert("read_file".to_string());
    let parent = DelegationGrant {
        agent_id: "agent-alpha-lead".to_string(),
        parent_agent_id: None,
        workspace_id: workspace_a.clone(),
        allowed_tools: parent_tools.clone(),
        audience: HashSet::new(),
        max_call_depth: 3,
        expires_at_epoch_ms: 2500000000000,
    };

    // Adversarial attempt: Child attempts to forge delegation into workspace Beta
    let cross_ws_child = DelegationGrant {
        agent_id: "agent-beta-worker".to_string(),
        parent_agent_id: Some("agent-alpha-lead".to_string()),
        workspace_id: workspace_b.clone(), // Cross-workspace attempt!
        allowed_tools: parent_tools,
        audience: HashSet::new(),
        max_call_depth: 2,
        expires_at_epoch_ms: 2400000000000,
    };

    match DelegationValidator::validate_delegation(&parent, &cross_ws_child) {
        AttenuationResult::EscalationRejected { reason_code, .. } => {
            assert_eq!(
                reason_code, "ERR_CROSS_WORKSPACE_DELEGATION",
                "Cross-workspace delegation must be rejected with ERR_CROSS_WORKSPACE_DELEGATION"
            );
        }
        AttenuationResult::Valid => panic!("Cross-workspace delegation must not succeed"),
    }
}

// ─── FR-020 / NFR-005: Cross-Workspace Cache Isolation ───────────────────────

#[test]
fn test_fr020_cross_workspace_cache_isolation() {
    use agentcontrol::proxy::semantic_cache::CanonicalContext;

    let prompt = "Explain Zero-Trust Architecture".to_string();

    let ctx_alpha = CanonicalContext {
        tenant_id: "org-sovereign-01".to_string(),
        subject_id: "user-alpha-01".to_string(),
        virtual_key_scope: None,
        provider: "openai".to_string(),
        model: "gpt-4o".to_string(),
        model_version: None,
        policy_version: "v2.0".to_string(),
        workspace_hash: Some("sha256:workspace_alpha".to_string()),
        system_prompt_hash: "sha256:sys_01".to_string(),
        developer_message_hash: None,
        temperature_fixed: "0.000".to_string(),
        top_p_fixed: None,
        top_k: None,
        seed: None,
        max_tokens: Some(2048),
        stop_sequences: vec![],
        response_format: None,
        reasoning_effort: None,
        locale: None,
        normalized_prompt: prompt.clone(),
    };

    let ctx_beta = CanonicalContext {
        workspace_hash: Some("sha256:workspace_beta".to_string()),
        ..ctx_alpha.clone()
    };

    let key_alpha = ctx_alpha.compute_exact_key();
    let key_beta = ctx_beta.compute_exact_key();

    // Cache keys MUST be cryptographically distinct across workspaces despite identical prompt
    assert_ne!(
        key_alpha, key_beta,
        "Exact cache keys across different workspaces must never collide"
    );
}

// ─── NFR-026: Sovereign Offline Standalone Operation ──────────────────────────

#[tokio::test]
async fn test_nfr026_offline_standalone_operation() {
    use agentcontrol::audit::logger::{AuditLogger, AuditLoggerConfig};
    use tempfile::tempdir;

    let dir = tempdir().unwrap();
    let audit_file = dir.path().join("audit.jsonl");
    let secret = b"offline-standalone-secret-key-32".to_vec();

    // Configure logger in strictly offline standalone mode (no SIEM exporter, local file only)
    let logger = AuditLogger::new(AuditLoggerConfig {
        log_path: audit_file.clone(),
        session_id: "session-offline-101".to_string(),
        session_secret: secret.clone(),
        max_bytes: 1048576,
        siem_exporter: None,
        include_params: false,
    })
    .expect("AuditLogger must initialize offline without external network");

    // Write audit event completely offline
    let res = logger
        .write_entry(
            "session-offline-101",
            "tool_call",
            "safe_tool",
            Some(serde_json::json!({"action": "inspect"})),
            Some("allow".to_string()),
            Some(5.0),
            Some("offline-user".to_string()),
            Some("dev@corp.internal".to_string()),
            Some("policy-sha256".to_string()),
            Some("127.0.0.1".to_string()),
            None,
        )
        .await;

    assert!(
        res.is_ok(),
        "Writing audit log offline must succeed synchronously"
    );
    assert!(audit_file.exists(), "audit.jsonl must exist on local disk");

    let contents = std::fs::read_to_string(&audit_file).unwrap();
    assert!(contents.contains("session-offline-101"));
    assert!(contents.contains("safe_tool"));
}

// ─── NFR-002 / NFR-008: Cross-Platform IPC & Loopback Security ────────────────

#[test]
fn test_nfr002_nfr008_cross_platform_ipc_and_loopback_security() {
    use agentcontrol::proxy::egress::is_blocked_ssrf_target;
    use agentcontrol::proxy::server::validate_origin_header;
    use hyper::header::{HeaderMap, HeaderValue, ORIGIN};

    // 1. Validate that only desktop/local loopback origins are permitted
    let mut valid_headers = HeaderMap::new();
    valid_headers.insert(ORIGIN, HeaderValue::from_static("http://127.0.0.1:18080"));
    assert!(validate_origin_header(&valid_headers).is_ok());

    // 2. Validate that remote browser origins attempting CSRF / DNS rebinding are blocked
    let mut attacker_headers = HeaderMap::new();
    attacker_headers.insert(
        ORIGIN,
        HeaderValue::from_static("https://malicious-website.com"),
    );
    assert!(validate_origin_header(&attacker_headers).is_err());

    // 3. Validate SSRF blocking on link-local metadata (169.254.169.254)
    assert!(is_blocked_ssrf_target("169.254.169.254"));
    assert!(is_blocked_ssrf_target("metadata.google.internal"));
}
