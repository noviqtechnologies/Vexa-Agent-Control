use agentcontrol::audit::logger::AuditLogger;
use agentcontrol::kill::KillMode;
use agentcontrol::policy::credential_scope::CredentialScopeValidator;
use agentcontrol::policy::engine::{CompiledPolicy, CompiledTool};
use agentcontrol::policy::response_scanner::{ResponseScanConfig, ResponseScanner};
use agentcontrol::policy::safe_mode::SafeModeScanner;
use agentcontrol::policy::schema::{
    CycleAction, CycleDetectionConfig, FirewallConfig, SpendCapsConfig,
};
use agentcontrol::proxy::handler::{evaluate_jsonrpc, ProxyAction, ProxyState, RateLimiter};
use agentcontrol::proxy::session::SessionContext;
use serde_json::json;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::Arc;

fn create_mock_proxy_state(policy: Option<CompiledPolicy>) -> Arc<ProxyState> {
    let log_path = std::env::temp_dir().join(format!("vexa_test_s5_{}.log", uuid::Uuid::new_v4()));
    let audit_logger = Arc::new(
        AuditLogger::new(agentcontrol::audit::logger::AuditLoggerConfig {
            log_path,
            session_id: "test-session".to_string(),
            session_secret: b"secret-12345678901234567890123456789012".to_vec(),
            max_bytes: 100000,
            siem_exporter: None,
            include_params: false,
        })
        .unwrap(),
    );

    let db_manager = Arc::new(agentcontrol::proxy::db::DbManager::init());

    Arc::new(ProxyState {
        policy: std::sync::RwLock::new(policy),
        audit_logger,
        session_id: "test-session".to_string(),
        kill_mode: KillMode::Connection,
        agent_pid: None,
        upstream_url: "".to_string(),
        dry_run: false,
        shadow_mode: std::sync::atomic::AtomicBool::new(false),
        policy_loaded: AtomicBool::new(true),
        rate_limiter: RateLimiter::new(0),
        http_client: reqwest::Client::new(),
        safe_mode_scanner: Arc::new(SafeModeScanner::new().unwrap()),
        ready: true,
        db_manager,
        response_scanner: Arc::new(ResponseScanner::new().unwrap()),
        response_scan_config: std::sync::RwLock::new(ResponseScanConfig::default()),
        dlp_scanner: Arc::new(agentcontrol::policy::dlp::DlpScanner::new(None).unwrap()),
        semantic_scanner: Arc::new(agentcontrol::policy::semantic::SemanticScanner::new(
            agentcontrol::policy::semantic::SemanticConfig::default(),
        )),
        injection_scanner: Arc::new(agentcontrol::policy::injection::InjectionScanner::default()),
        schema_drift_detector: Arc::new(
            agentcontrol::policy::schema_drift::SchemaDriftDetector::default(),
        ),
        tool_history: std::sync::Mutex::new(Vec::new()),
        sessions: dashmap::DashMap::new(),
        metrics_requests_total: Arc::new(AtomicU64::new(0)),
        metrics_allow_total: Arc::new(AtomicU64::new(0)),
        metrics_deny_total: Arc::new(AtomicU64::new(0)),
        metrics_rate_limited_total: Arc::new(AtomicU64::new(0)),
        metrics_firewall_cycle_total: Arc::new(AtomicU64::new(0)),
        metrics_siem_export_total: Arc::new(AtomicU64::new(0)),
        metrics_siem_export_failed_total: Arc::new(AtomicU64::new(0)),
        event_tx: tokio::sync::broadcast::channel(256).0,
        credential_scope_validator: Arc::new(CredentialScopeValidator::new(true)), // strict mode
        gateway_start_time: std::time::Instant::now(),
        policy_path: None,
        dashboard_client: None,
        listen_is_loopback: true,
        policy_read_secret: None,
        spend_ledger: None,
        pricing_table: None,
        centralized_mode: false,
        provider_keys: dashmap::DashMap::new(),
    })
}

#[tokio::test]
async fn test_us100_loop_prevention_pivot_error() {
    let firewall_cfg = FirewallConfig {
        enabled: true,
        cycle_detection: CycleDetectionConfig {
            max_attempts: 3,
            action: CycleAction::PivotError,
        },
    };

    let policy = CompiledPolicy {
        tools: vec![CompiledTool {
            name: "execute_command".to_string(),
            action: "allow".to_string(),
            risk: None,
            parameters: vec![],
            identity: None,
            credential_scope: vec![],
            semantic_anomaly_threshold: None,
            a2a_trust_level: None,
        }],
        group_policies: vec![],
        sequence_rules: vec![],
        max_calls_per_second: 0,
        identity_validator: None,
        scannable_tools: vec![],
        safe_tools: vec![],
        firewall: Some(firewall_cfg),
        spend_caps: None,
        llm: None,
        schema_drift: None,
    };

    let state = create_mock_proxy_state(Some(policy.clone()));
    let session = Arc::new(SessionContext::new(
        Some("test_agent".to_string()),
        None,
        vec![],
        Some(policy),
        None,
        None,
    ));

    let req_body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "execute_command",
            "arguments": { "command": "cat /tmp/nonexistent" }
        }
    });

    // Calls 1 and 2 should forward
    let act1 = evaluate_jsonrpc(&state, &session, &req_body).await;
    assert!(matches!(act1, ProxyAction::Forward));

    let act2 = evaluate_jsonrpc(&state, &session, &req_body).await;
    assert!(matches!(act2, ProxyAction::Forward));

    // Call 3 triggers loop detection (PivotError => JSON-RPC -32010 error response)
    let act3 = evaluate_jsonrpc(&state, &session, &req_body).await;
    if let ProxyAction::Respond(resp) = act3 {
        assert_eq!(resp["error"]["code"].as_i64().unwrap(), -32010);
        assert!(resp["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Cycle detected"));
    } else {
        panic!("Expected ProxyAction::Respond on 3rd identical call");
    }
}

#[tokio::test]
async fn test_us100_loop_prevention_different_params_not_blocked() {
    let firewall_cfg = FirewallConfig {
        enabled: true,
        cycle_detection: CycleDetectionConfig {
            max_attempts: 3,
            action: CycleAction::PivotError,
        },
    };

    let policy = CompiledPolicy {
        tools: vec![CompiledTool {
            name: "execute_command".to_string(),
            action: "allow".to_string(),
            risk: None,
            parameters: vec![],
            identity: None,
            credential_scope: vec![],
            semantic_anomaly_threshold: None,
            a2a_trust_level: None,
        }],
        group_policies: vec![],
        sequence_rules: vec![],
        max_calls_per_second: 0,
        identity_validator: None,
        scannable_tools: vec![],
        safe_tools: vec![],
        firewall: Some(firewall_cfg),
        spend_caps: None,
        llm: None,
        schema_drift: None,
    };

    let state = create_mock_proxy_state(Some(policy.clone()));
    let session = Arc::new(SessionContext::new(
        Some("test_agent".to_string()),
        None,
        vec![],
        Some(policy),
        None,
        None,
    ));

    for i in 1..=5 {
        let req_body = json!({
            "jsonrpc": "2.0",
            "id": i,
            "method": "tools/call",
            "params": {
                "name": "execute_command",
                "arguments": { "command": format!("echo attempt_{}", i) }
            }
        });
        let act = evaluate_jsonrpc(&state, &session, &req_body).await;
        assert!(
            matches!(act, ProxyAction::Forward),
            "Call {} with different params should forward",
            i
        );
    }
}

#[tokio::test]
async fn test_us101_spend_cap_enforcement_licensed_vs_unlicensed() {
    let spend_caps_cfg = SpendCapsConfig {
        enabled: true,
        license_key: None, // absent license key
        admin_api: false,
        pricing_table_path: None,
        concurrency_ceiling: Some(10),
        max_tokens_per_session: Some(1000),
        max_concurrent_sessions: Some(10),
        retention: None,
    };

    let policy = CompiledPolicy {
        tools: vec![CompiledTool {
            name: "run_llm".to_string(),
            action: "allow".to_string(),
            risk: None,
            parameters: vec![],
            identity: None,
            credential_scope: vec![],
            semantic_anomaly_threshold: None,
            a2a_trust_level: None,
        }],
        group_policies: vec![],
        sequence_rules: vec![],
        max_calls_per_second: 0,
        identity_validator: None,
        scannable_tools: vec![],
        safe_tools: vec![],
        firewall: None,
        spend_caps: Some(spend_caps_cfg),
        llm: None,
        schema_drift: None,
    };

    let state = create_mock_proxy_state(Some(policy.clone()));
    let session = Arc::new(SessionContext::new(
        Some("test_agent".to_string()),
        None,
        vec![],
        Some(policy),
        None,
        None,
    ));

    // Exceed token limit
    session
        .tokens_used
        .store(1500, std::sync::atomic::Ordering::Relaxed);

    let req_body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": "run_llm", "arguments": {} }
    });

    // When license key is absent, request should NOT be blocked (usage is recorded per US-101 AC-2)
    let act_unlicensed = evaluate_jsonrpc(&state, &session, &req_body).await;
    assert!(matches!(act_unlicensed, ProxyAction::Forward));
}

#[tokio::test]
async fn test_us103_credential_scope_strict_mode() {
    let policy = CompiledPolicy {
        tools: vec![
            CompiledTool {
                name: "restricted_tool".to_string(),
                action: "allow".to_string(),
                risk: None,
                parameters: vec![],
                identity: None,
                credential_scope: vec!["admin".to_string(), "write".to_string()],
                semantic_anomaly_threshold: None,
                a2a_trust_level: None,
            },
            CompiledTool {
                name: "public_tool".to_string(),
                action: "allow".to_string(),
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
    };

    let state = create_mock_proxy_state(Some(policy.clone()));

    // 1. Session without scope header calling restricted tool -> DENIED with -32403
    let session_no_header = Arc::new(SessionContext::new_with_scope(
        Some("agent_1".to_string()),
        None,
        vec![],
        Some(policy.clone()),
        None,
        None,
        None,
    ));

    let req_restricted = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": "restricted_tool", "arguments": {} }
    });

    let act1 = evaluate_jsonrpc(&state, &session_no_header, &req_restricted).await;
    if let ProxyAction::Respond(resp) = act1 {
        assert_eq!(resp["error"]["code"].as_i64().unwrap(), -32403);
        assert!(resp["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Credential Scope Insufficient"));
    } else {
        panic!("Expected ProxyAction::Respond with -32403 on missing scope header");
    }

    // 2. Session with matching scope header ("admin") calling restricted tool -> PERMITTED
    let session_with_scope = Arc::new(SessionContext::new_with_scope(
        Some("agent_1".to_string()),
        None,
        vec![],
        Some(policy.clone()),
        None,
        None,
        Some("admin, read-only".to_string()),
    ));

    let act2 = evaluate_jsonrpc(&state, &session_with_scope, &req_restricted).await;
    assert!(
        matches!(act2, ProxyAction::Forward),
        "Call with matching scope header should forward"
    );

    // 3. Unrestricted tool calling without scope header -> PERMITTED
    let req_public = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": { "name": "public_tool", "arguments": {} }
    });

    let act3 = evaluate_jsonrpc(&state, &session_no_header, &req_public).await;
    assert!(
        matches!(act3, ProxyAction::Forward),
        "Public tool call without scope header should forward"
    );
}
