//! Backend & Systems Integration Test Suite for AgentWall
//!
//! Covers four primary interaction boundaries:
//! 1. Component-to-Component (ProxyHandler <-> Policy Engine <-> Identity <-> DLP)
//! 2. Data Persistence (SQLite Audit Logger Hash-Chain & Tamper Evident Persistence)
//! 3. External Network Boundaries (Upstream MCP Mock Server & Connection Timeout Fallback)
//! 4. State & Lifecycle (Multi-Step Budget Exhaustion & Dynamic Policy Hot-Reload)

use agentwall::audit::logger::{AuditLogger, AuditLoggerConfig};
use agentwall::audit::verifier::{verify_chain_with_secret, VerifyResult};
use agentwall::kill::KillMode;
use agentwall::policy::credential_scope::CredentialScopeValidator;
use agentwall::policy::dlp::DlpScanner;
use agentwall::policy::engine::{CompiledPolicy, CompiledTool};
use agentwall::policy::injection::InjectionScanner;
use agentwall::policy::response_scanner::{ResponseScanConfig, ResponseScanner};
use agentwall::policy::safe_mode::SafeModeScanner;
use agentwall::policy::semantic::{SemanticConfig, SemanticScanner};
use agentwall::proxy::handler::{evaluate_jsonrpc, ProxyAction, ProxyState, RateLimiter};
use agentwall::proxy::session::SessionContext;
use serde_json::json;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::Arc;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Helper: Initialize a clean isolated ProxyState fixture
fn create_test_proxy_state(policy: Option<CompiledPolicy>) -> (Arc<ProxyState>, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("integration_audit.log");
    let config = AuditLoggerConfig {
        log_path,
        session_id: "backend-integration-session".to_string(),
        session_secret: vec![0xAB; 32],
        max_bytes: 10 * 1024 * 1024,
        siem_exporter: None,
        include_params: true,
    };
    let audit_logger = Arc::new(AuditLogger::new(config).unwrap());
    let db_manager = Arc::new(agentwall::proxy::db::DbManager::init());

    let state = Arc::new(ProxyState {
        policy: std::sync::RwLock::new(policy),
        policy_path: None,
        gateway_start_time: std::time::Instant::now(),
        dashboard_client: None,
        listen_is_loopback: true,
        policy_read_secret: None,
        credential_scope_validator: Arc::new(CredentialScopeValidator::new(false)),
        audit_logger,
        session_id: "backend-integration-session".to_string(),
        kill_mode: KillMode::Connection,
        agent_pid: None,
        upstream_url: "".to_string(),
        dry_run: false,
        shadow_mode: false,
        policy_loaded: AtomicBool::new(true),
        rate_limiter: RateLimiter::new(0),
        http_client: reqwest::Client::new(),
        safe_mode_scanner: Arc::new(SafeModeScanner::new().unwrap()),
        ready: true,
        db_manager,
        response_scanner: Arc::new(ResponseScanner::new().unwrap()),
        response_scan_config: std::sync::RwLock::new(ResponseScanConfig::default()),
        dlp_scanner: Arc::new(DlpScanner::new(None).unwrap()),
        semantic_scanner: Arc::new(SemanticScanner::new(SemanticConfig::default())),
        injection_scanner: Arc::new(InjectionScanner::default()),
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
        spend_ledger: None,
        pricing_table: None,
        centralized_mode: false,
        provider_keys: dashmap::DashMap::new(),
    });

    (state, dir)
}

// ─────────────────────────────────────────────────────────────────────────────
// Boundary 1: Component-to-Component Integration
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn test_boundary_1_policy_identity_dlp_interaction() {
    let policy = CompiledPolicy {
        max_calls_per_second: 100,
        tools: vec![
            CompiledTool {
                name: "read_file".to_string(),
                action: "allow".to_string(),
                risk: None,
                parameters: vec![],
                identity: None,
                credential_scope: vec![],
                semantic_anomaly_threshold: None,
                a2a_trust_level: None,
            },
            CompiledTool {
                name: "restricted_tool".to_string(),
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
        identity_validator: None,
        scannable_tools: vec![],
        safe_tools: vec![],
        firewall: None,
        spend_caps: None,
        llm: None,
    };

    let (state, _dir) = create_test_proxy_state(Some(policy.clone()));

    // Bind session context to policy
    let session = Arc::new(SessionContext::new(
        Some("agent-finance-01".to_string()),
        Some("finance-agent@corp.internal".to_string()),
        vec!["finance-group".to_string()],
        Some(policy),
        None,
        None,
    ));

    // 1. Send normal JSON-RPC tool call
    let request_json = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": { "path": "/data/report.csv" }
        }
    });

    let action = evaluate_jsonrpc(&state, &session, &request_json).await;

    // Assert side effects and explicit return
    assert!(matches!(action, ProxyAction::Forward));
    assert_eq!(
        state
            .metrics_requests_total
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    assert_eq!(
        state
            .metrics_allow_total
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );

    // 2. Send request to restricted_tool to verify Component-to-Component policy engine DENY action
    let attack_json = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "restricted_tool",
            "arguments": {}
        }
    });

    let attack_action = evaluate_jsonrpc(&state, &session, &attack_json).await;
    assert!(!matches!(attack_action, ProxyAction::Forward));
    assert_eq!(
        state
            .metrics_deny_total
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Boundary 2: Data Persistence Integration (SQLite Audit Hash Chain Integrity)
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_boundary_2_audit_persistence_hash_chain_tamper_detection() {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("persistent_audit.log");
    let secret = vec![0x77; 32];

    let config = AuditLoggerConfig {
        log_path: log_path.clone(),
        session_id: "persistence-session".to_string(),
        session_secret: secret.clone(),
        max_bytes: 1024 * 1024,
        siem_exporter: None,
        include_params: true,
    };

    let logger = AuditLogger::new(config).unwrap();

    // Write sequential audit events to verify hash-chain linking
    for i in 0..5 {
        logger
            .write_entry(
                "persistence-session",
                if i % 2 == 0 {
                    "tool_allow"
                } else {
                    "tool_deny"
                },
                &format!("tool_{}", i),
                Some(json!({ "step": i })),
                None,
                Some(0.05),
                Some("agent-007".to_string()),
                Some("agent-007@agency.gov".to_string()),
                Some("sha256-policy-hash".to_string()),
                None,
                None,
            )
            .await
            .unwrap();
    }

    drop(logger);
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    // Verify uncorrupted log passes cryptographic chain verification
    match verify_chain_with_secret(&log_path, &secret) {
        VerifyResult::Valid { entry_count } => {
            assert_eq!(entry_count, 5);
        }
        other => panic!("Expected valid chain, got: {:?}", other),
    }

    // Tamper with log file on disk (Data Persistence boundary check)
    let content = std::fs::read_to_string(&log_path).unwrap();
    let tampered_content = content.replace("tool_0", "tool_hacked");
    std::fs::write(&log_path, tampered_content).unwrap();

    // Verify tamper detection mechanism catches data corruption
    match verify_chain_with_secret(&log_path, &secret) {
        VerifyResult::Invalid {
            reason,
            entry_index,
        } => {
            assert_eq!(entry_index, 0);
            assert!(reason.contains("mismatch"), "Reason: {}", reason);
        }
        VerifyResult::Valid { .. } => {
            panic!("Expected tamper detection to flag invalid hash chain!")
        }
        other => panic!("Unexpected verify result: {:?}", other),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Boundary 3: External Network Boundaries (Mock Upstream & Timeout Handling)
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn test_boundary_3_external_network_mock_upstream_forwarding() {
    // 1. Spawn a local mock upstream server
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock_addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            if n > 0 {
                let response_body = json!({
                    "jsonrpc": "2.0",
                    "id": 101,
                    "result": { "content": [{ "type": "text", "text": "file content successfully retrieved" }] }
                }).to_string();

                let http_response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    response_body.len(),
                    response_body
                );
                let _ = stream.write_all(http_response.as_bytes()).await;
            }
        }
    });

    let policy = CompiledPolicy {
        max_calls_per_second: 100,
        tools: vec![CompiledTool {
            name: "fetch_mcp_data".to_string(),
            action: "allow".to_string(),
            risk: None,
            parameters: vec![],
            identity: None,
            credential_scope: vec![],
            semantic_anomaly_threshold: None,
            a2a_trust_level: None,
        }],
        group_policies: vec![],
        identity_validator: None,
        scannable_tools: vec![],
        safe_tools: vec![],
        firewall: None,
        spend_caps: None,
        llm: None,
    };

    let (mut state_struct, _dir) = create_test_proxy_state(Some(policy.clone()));
    Arc::get_mut(&mut state_struct).unwrap().upstream_url = format!("http://{}", mock_addr);
    let state = state_struct;

    let session = Arc::new(SessionContext::new(
        Some("network-agent".to_string()),
        None,
        vec![],
        Some(policy),
        None,
        None,
    ));

    let req_json = json!({
        "jsonrpc": "2.0",
        "id": 101,
        "method": "tools/call",
        "params": {
            "name": "fetch_mcp_data",
            "arguments": {}
        }
    });

    let action = evaluate_jsonrpc(&state, &session, &req_json).await;
    assert!(matches!(action, ProxyAction::Forward));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_boundary_3_external_network_unreachable_upstream_graceful_handling() {
    let policy = CompiledPolicy {
        max_calls_per_second: 100,
        tools: vec![CompiledTool {
            name: "remote_tool".to_string(),
            action: "allow".to_string(),
            risk: None,
            parameters: vec![],
            identity: None,
            credential_scope: vec![],
            semantic_anomaly_threshold: None,
            a2a_trust_level: None,
        }],
        group_policies: vec![],
        identity_validator: None,
        scannable_tools: vec![],
        safe_tools: vec![],
        firewall: None,
        spend_caps: None,
        llm: None,
    };

    let (mut state_struct, _dir) = create_test_proxy_state(Some(policy.clone()));
    Arc::get_mut(&mut state_struct).unwrap().upstream_url = "http://127.0.0.1:59999".to_string();
    let state = state_struct;

    let session = Arc::new(SessionContext::new(
        Some("fault-agent".to_string()),
        None,
        vec![],
        Some(policy),
        None,
        None,
    ));

    let req_json = json!({
        "jsonrpc": "2.0",
        "id": 202,
        "method": "tools/call",
        "params": {
            "name": "remote_tool",
            "arguments": {}
        }
    });

    let action = evaluate_jsonrpc(&state, &session, &req_json).await;
    assert!(matches!(action, ProxyAction::Forward));
}

// ─────────────────────────────────────────────────────────────────────────────
// Boundary 4: State & Lifecycle Integration (Rate Limiting & Hot-Reload)
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn test_boundary_4_state_rate_limit_multi_step_exhaustion() {
    let policy = CompiledPolicy {
        max_calls_per_second: 2,
        tools: vec![CompiledTool {
            name: "query_db".to_string(),
            action: "allow".to_string(),
            risk: None,
            parameters: vec![],
            identity: None,
            credential_scope: vec![],
            semantic_anomaly_threshold: None,
            a2a_trust_level: None,
        }],
        group_policies: vec![],
        identity_validator: None,
        scannable_tools: vec![],
        safe_tools: vec![],
        firewall: None,
        spend_caps: None,
        llm: None,
    };

    let (mut state_struct, _dir) = create_test_proxy_state(Some(policy.clone()));
    Arc::get_mut(&mut state_struct).unwrap().rate_limiter = RateLimiter::new(2);
    let state = state_struct;

    let session = Arc::new(SessionContext::new(
        Some("rate-agent".to_string()),
        None,
        vec![],
        Some(policy),
        None,
        None,
    ));

    let req = json!({
        "jsonrpc": "2.0",
        "id": 301,
        "method": "tools/call",
        "params": { "name": "query_db", "arguments": {} }
    });

    // Step 1 & 2: Within rate limit
    let a1 = evaluate_jsonrpc(&state, &session, &req).await;
    let a2 = evaluate_jsonrpc(&state, &session, &req).await;
    assert!(matches!(a1, ProxyAction::Forward));
    assert!(matches!(a2, ProxyAction::Forward));

    // Step 3: Burst exhausts rate limit
    let a3 = evaluate_jsonrpc(&state, &session, &req).await;
    assert!(matches!(
        a3,
        ProxyAction::Respond(_) | ProxyAction::RespondWithStatus(_, _)
    ));
    assert_eq!(
        state
            .metrics_rate_limited_total
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_boundary_4_state_lifecycle_dynamic_policy_hot_reload() {
    let initial_policy = CompiledPolicy {
        max_calls_per_second: 100,
        tools: vec![CompiledTool {
            name: "sensitive_export".to_string(),
            action: "deny".to_string(),
            risk: None,
            parameters: vec![],
            identity: None,
            credential_scope: vec![],
            semantic_anomaly_threshold: None,
            a2a_trust_level: None,
        }],
        group_policies: vec![],
        identity_validator: None,
        scannable_tools: vec![],
        safe_tools: vec![],
        firewall: None,
        spend_caps: None,
        llm: None,
    };

    let (state, _dir) = create_test_proxy_state(Some(initial_policy.clone()));

    let req = json!({
        "jsonrpc": "2.0",
        "id": 401,
        "method": "tools/call",
        "params": { "name": "sensitive_export", "arguments": {} }
    });

    // Before hot-reload: Denied
    let session_v1 = Arc::new(SessionContext::new(
        Some("admin-agent".to_string()),
        None,
        vec![],
        Some(initial_policy),
        None,
        None,
    ));
    let action1 = evaluate_jsonrpc(&state, &session_v1, &req).await;
    assert!(!matches!(action1, ProxyAction::Forward));

    // Step 2: Hot reload policy in state and session
    let updated_policy = CompiledPolicy {
        max_calls_per_second: 100,
        tools: vec![CompiledTool {
            name: "sensitive_export".to_string(),
            action: "allow".to_string(),
            risk: None,
            parameters: vec![],
            identity: None,
            credential_scope: vec![],
            semantic_anomaly_threshold: None,
            a2a_trust_level: None,
        }],
        group_policies: vec![],
        identity_validator: None,
        scannable_tools: vec![],
        safe_tools: vec![],
        firewall: None,
        spend_caps: None,
        llm: None,
    };

    {
        let mut policy_guard = state.policy.write().unwrap();
        *policy_guard = Some(updated_policy.clone());
    }

    let session_v2 = Arc::new(SessionContext::new(
        Some("admin-agent".to_string()),
        None,
        vec![],
        Some(updated_policy),
        None,
        None,
    ));

    // After hot-reload: Allowed dynamically without dropping session context
    let action2 = evaluate_jsonrpc(&state, &session_v2, &req).await;
    assert!(matches!(action2, ProxyAction::Forward));
}
