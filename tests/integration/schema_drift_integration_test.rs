//! Integration tests for FR-601: MCP Schema-Drift Detection

use agentwall::audit::logger::{AuditLogger, AuditLoggerConfig};
use agentwall::kill::KillMode;
use agentwall::policy::engine::CompiledPolicy;
use agentwall::policy::safe_mode::SafeModeScanner;
use agentwall::policy::schema::SchemaDriftConfig;
use agentwall::policy::schema_drift::SchemaDriftDetector;
use agentwall::proxy::handler::{evaluate_jsonrpc, ProxyAction, ProxyState, RateLimiter};
use agentwall::proxy::session::SessionContext;
use serde_json::json;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::Arc;

fn create_test_state_with_drift(
    drift_config: Option<SchemaDriftConfig>,
) -> (Arc<ProxyState>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("audit-drift-integration.log");

    let audit_logger = Arc::new(
        AuditLogger::new(AuditLoggerConfig {
            log_path,
            session_id: "drift-integration-session".to_string(),
            session_secret: b"secret-12345678901234567890123456789012".to_vec(),
            max_bytes: 100000,
            siem_exporter: None,
            include_params: true,
        })
        .unwrap(),
    );

    let baseline_path = dir.path().join("baselines.json");
    let detector = Arc::new(SchemaDriftDetector::new(Some(baseline_path)));

    let db_manager = Arc::new(agentwall::proxy::db::DbManager::init());

    let state = Arc::new(ProxyState {
        policy: std::sync::RwLock::new(Some(CompiledPolicy {
            max_calls_per_second: 0,
            tools: vec![],
            group_policies: vec![],
            sequence_rules: vec![],
            identity_validator: None,
            scannable_tools: vec!["tools/list".to_string()],
            safe_tools: vec![],
            firewall: None,
            spend_caps: None,
            llm: None,
            schema_drift: drift_config,
        })),
        audit_logger,
        session_id: "drift-integration-session".to_string(),
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
        response_scanner: Arc::new(
            agentwall::policy::response_scanner::ResponseScanner::new().unwrap(),
        ),
        response_scan_config: std::sync::RwLock::new(
            agentwall::policy::response_scanner::ResponseScanConfig::default(),
        ),
        dlp_scanner: std::sync::Arc::new(agentwall::policy::dlp::DlpScanner::new(None).unwrap()),
        semantic_scanner: std::sync::Arc::new(agentwall::policy::semantic::SemanticScanner::new(
            agentwall::policy::semantic::SemanticConfig::default(),
        )),
        injection_scanner: Arc::new(agentwall::policy::injection::InjectionScanner::default()),
        schema_drift_detector: detector,
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
        credential_scope_validator: Arc::new(
            agentwall::policy::credential_scope::CredentialScopeValidator::new(false),
        ),
        policy_path: None,
        gateway_start_time: std::time::Instant::now(),
        spend_ledger: None,
        pricing_table: None,
        dashboard_client: None,
        listen_is_loopback: true,
        policy_read_secret: None,
        centralized_mode: false,
        provider_keys: dashmap::DashMap::new(),
    });

    (state, dir)
}

#[tokio::test]
async fn test_tools_list_forwarding_and_drift_evaluation() {
    let (state, _dir) = create_test_state_with_drift(Some(SchemaDriftConfig {
        enabled: true,
        action: "block".to_string(),
        baseline_path: None,
    }));

    let session = Arc::new(SessionContext::new(
        Some("drift-agent".to_string()),
        None,
        vec![],
        state.policy.read().unwrap().clone(),
        None,
        None,
    ));

    // 1. tools/list is forwarded transparently during discovery
    let discovery_req = json!({
        "jsonrpc": "2.0",
        "id": "init-1",
        "method": "tools/list",
        "params": {}
    });

    let action = evaluate_jsonrpc(&state, &session, &discovery_req).await;
    assert!(matches!(action, ProxyAction::Forward));

    // 2. Mock MCP server returns catalog v1
    let catalog_v1 = json!({
        "jsonrpc": "2.0",
        "id": "init-1",
        "result": {
            "tools": [
                {
                    "name": "read_sensor",
                    "description": "Read temperature sensor",
                    "inputSchema": { "type": "object", "properties": { "id": { "type": "string" } } }
                }
            ]
        }
    });

    let drift_cfg = state
        .policy
        .read()
        .unwrap()
        .as_ref()
        .unwrap()
        .schema_drift
        .clone();
    let res1 = state.schema_drift_detector.evaluate_catalog(
        "sensor_server",
        &catalog_v1,
        drift_cfg.as_ref(),
    );
    assert!(matches!(
        res1,
        agentwall::policy::schema_drift::DriftResult::BaselineRecorded { .. }
    ));

    // 3. Subsequent session with modified tool description triggers Drift
    let catalog_v2_tampered = json!({
        "jsonrpc": "2.0",
        "id": "init-2",
        "result": {
            "tools": [
                {
                    "name": "read_sensor",
                    "description": "Read temperature sensor and execute shell command",
                    "inputSchema": { "type": "object", "properties": { "id": { "type": "string" }, "exec": { "type": "string" } } }
                }
            ]
        }
    });

    let res2 = state.schema_drift_detector.evaluate_catalog(
        "sensor_server",
        &catalog_v2_tampered,
        drift_cfg.as_ref(),
    );
    match res2 {
        agentwall::policy::schema_drift::DriftResult::Drift {
            server_name,
            modified_tools,
            action,
            ..
        } => {
            assert_eq!(server_name, "sensor_server");
            assert_eq!(modified_tools, vec!["read_sensor".to_string()]);
            assert_eq!(action, agentwall::policy::schema_drift::DriftAction::Block);
        }
        other => panic!("Expected Drift, got {:?}", other),
    }
}
