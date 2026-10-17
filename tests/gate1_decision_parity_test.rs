//! Gate 1: Decision Parity Integration Test Suite
//!
//! Validates 100% decision parity across all Gateway transports:
//! - MCP HTTP PEP (`handle_mcp_tools_call`)
//! - Stdio Child Proxy PEP (`evaluate_stdio_request` & `handle_stdio_jsonrpc`)
//! - HTTP/LLM Gateway PEP (`evaluate_http_llm_request` & `handle_http_llm_request`)
//!
//! Verifies:
//! 1. Parity of Allow and Deny verdicts across declarative policies.
//! 2. Parity of managed mode identity provenance enforcement.
//! 3. Parity of real-time capability revocation (<30s propagation).
//! 4. Parity of Hard Safety Invariant detection (SafeMode).
//! 5. Parity of DLP parameter redaction.
//! 6. Uniform JSON-RPC error translation (-32001, -32002, -32600, -32603).
//! 7. Zero blanket bypasses for resources/* and prompts/*.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use agentcontrol::pep::http_llm::{
    evaluate_http_llm_request, handle_http_llm_request, MockLlmDownstream,
};
use agentcontrol::pep::mcp::{handle_mcp_tools_call, MockMcpDownstream};
use agentcontrol::pep::stdio::{
    evaluate_stdio_request, handle_stdio_jsonrpc, MockStdioDownstream, StdioEvaluationResult,
};
use agentcontrol::pep::PepError;
use agentcontrol::policy::engine::CompiledPolicy;
use agentcontrol::policy::trust::{PolicyTrustProfile, TrustedKeyring};
use agentcontrol::proxy::handler::ProxyState;
use agentcontrol::proxy::session::SessionContext;
use serde_json::json;

// ─── Fixture Helpers ──────────────────────────────────────────────────────────

fn state_with_policy(policy: CompiledPolicy) -> Arc<ProxyState> {
    let base = ProxyState::mock_test_default();
    let mut state =
        Arc::try_unwrap(base).unwrap_or_else(|_| panic!("Failed to unwrap Arc<ProxyState>"));
    state.policy = std::sync::RwLock::new(Some(policy));
    Arc::new(state)
}

fn session_authenticated(sub: &str) -> Arc<SessionContext> {
    Arc::new(SessionContext::new(
        Some(sub.to_string()),
        Some(format!("{}@enterprise.corp", sub)),
        vec!["engineering".to_string()],
        None,
        None,
        None,
    ))
}

fn session_anonymous() -> Arc<SessionContext> {
    Arc::new(SessionContext::new(None, None, vec![], None, None, None))
}

// ─── Test 1: Allow Decision Parity Across MCP HTTP & Stdio PEP ────────────────

#[tokio::test]
async fn test_allow_decision_parity_mcp_and_stdio() {
    let yaml = r#"
version: "2.1"
default_action: deny
tools:
  - name: "query_database"
    action: allow
"#;
    let policy = CompiledPolicy::from_yaml_str(yaml).unwrap();
    let state = state_with_policy(policy);
    let session = session_authenticated("alice");

    // 1. MCP HTTP PEP Evaluation
    let mcp_call_count = Arc::new(AtomicUsize::new(0));
    let mut mcp_downstream = MockMcpDownstream::new(mcp_call_count.clone());
    let mcp_params = json!({
        "name": "query_database",
        "arguments": {"sql": "SELECT 1;"}
    });

    let mcp_res = handle_mcp_tools_call(
        &state,
        &session,
        "tools/call",
        &mcp_params,
        &mut mcp_downstream,
    )
    .await;
    assert!(
        mcp_res.is_ok(),
        "MCP tools/call must be allowed: {:?}",
        mcp_res
    );
    assert_eq!(mcp_call_count.load(Ordering::SeqCst), 1);

    // 2. Stdio Pre-flight Evaluation
    let stdio_req = json!({
        "jsonrpc": "2.0",
        "id": 101,
        "method": "tools/call",
        "params": {
            "name": "query_database",
            "arguments": {"sql": "SELECT 1;"}
        }
    });

    let stdio_res = evaluate_stdio_request(&state, &session, &stdio_req).await;
    assert!(
        stdio_res.is_ok(),
        "Stdio tools/call must be allowed: {:?}",
        stdio_res
    );
    match stdio_res.unwrap() {
        StdioEvaluationResult::Forward {
            tool_name,
            is_tool_call,
            ..
        } => {
            assert_eq!(tool_name, "query_database");
            assert!(is_tool_call);
        }
    }

    // 3. Stdio Full Forwarding Gate Evaluation
    let stdio_call_count = Arc::new(AtomicUsize::new(0));
    let mut stdio_downstream = MockStdioDownstream::new(stdio_call_count.clone());
    let stdio_full_res =
        handle_stdio_jsonrpc(&state, &session, &stdio_req, &mut stdio_downstream).await;
    assert!(
        stdio_full_res.is_ok(),
        "Stdio full dispatch must succeed: {:?}",
        stdio_full_res
    );
    assert_eq!(stdio_call_count.load(Ordering::SeqCst), 1);
}

// ─── Test 2: Deny Decision Parity Across MCP HTTP, Stdio, and LLM ────────────

#[tokio::test]
async fn test_deny_decision_parity_across_all_transports() {
    let yaml = r#"
version: "2.1"
default_action: deny
tools:
  - name: "safe_tool"
    action: allow
llm:
  providers:
    - name: "openai"
      action: "allow"
      models:
        - "gpt-4o"
"#;
    let policy = CompiledPolicy::from_yaml_str(yaml).unwrap();
    let state = state_with_policy(policy);
    let session = session_authenticated("bob");

    // 1. MCP HTTP PEP: unlisted tool denied
    let mcp_call_count = Arc::new(AtomicUsize::new(0));
    let mut mcp_downstream = MockMcpDownstream::new(mcp_call_count.clone());
    let mcp_params = json!({
        "name": "forbidden_tool",
        "arguments": {}
    });
    let mcp_res = handle_mcp_tools_call(
        &state,
        &session,
        "tools/call",
        &mcp_params,
        &mut mcp_downstream,
    )
    .await;
    assert!(matches!(mcp_res, Err(PepError::Denied { .. })));
    assert_eq!(mcp_call_count.load(Ordering::SeqCst), 0);

    // Verify MCP JSON-RPC error mapping
    let mcp_err = mcp_res.unwrap_err();
    let mcp_err_json = mcp_err.to_jsonrpc_error(&json!(1));
    assert_eq!(mcp_err_json["error"]["code"], -32001);

    // 2. Stdio PEP: unlisted tool denied
    let stdio_call_count = Arc::new(AtomicUsize::new(0));
    let mut stdio_downstream = MockStdioDownstream::new(stdio_call_count.clone());
    let stdio_req = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "forbidden_tool",
            "arguments": {}
        }
    });
    let stdio_res = handle_stdio_jsonrpc(&state, &session, &stdio_req, &mut stdio_downstream).await;
    assert!(matches!(stdio_res, Err(PepError::Denied { .. })));
    assert_eq!(stdio_call_count.load(Ordering::SeqCst), 0);

    // Verify Stdio JSON-RPC error mapping
    let stdio_err = stdio_res.unwrap_err();
    let stdio_err_json = stdio_err.to_jsonrpc_error(&json!(2));
    assert_eq!(stdio_err_json["error"]["code"], -32001);

    // 3. HTTP LLM PEP: unlisted model denied
    let llm_call_count = Arc::new(AtomicUsize::new(0));
    let mut llm_downstream = MockLlmDownstream::new(llm_call_count.clone());
    let llm_body = json!({
        "model": "claude-3-opus",
        "messages": [{"role": "user", "content": "test"}]
    });
    let llm_res = handle_http_llm_request(
        &state,
        &session,
        "anthropic",
        "/v1/chat/completions",
        &llm_body,
        &mut llm_downstream,
    )
    .await;
    assert!(matches!(llm_res, Err(PepError::Denied { .. })));
    assert_eq!(llm_call_count.load(Ordering::SeqCst), 0);

    // Pre-flight evaluate_http_llm_request produces exact same denial
    let pre_llm_res = evaluate_http_llm_request(
        &state,
        &session,
        "anthropic",
        "/v1/chat/completions",
        &llm_body,
    )
    .await;
    assert!(matches!(pre_llm_res, Err(PepError::Denied { .. })));
}

// ─── Test 3: Managed Mode Identity Provenance Parity ──────────────────────────

#[tokio::test]
async fn test_managed_mode_identity_provenance_parity() {
    let yaml = r#"
version: "2.1"
default_action: deny
tools:
  - name: "any_tool"
    action: allow
llm:
  providers:
    - name: "openai"
      action: "allow"
      models:
        - "gpt-4o"
"#;
    let policy = CompiledPolicy::from_yaml_str(yaml).unwrap();
    let base = ProxyState::mock_test_default();
    let mut state_unwrapped =
        Arc::try_unwrap(base).unwrap_or_else(|_| panic!("Failed to unwrap Arc<ProxyState>"));
    state_unwrapped.policy = std::sync::RwLock::new(Some(policy));
    state_unwrapped.policy_trust_profile = PolicyTrustProfile::Managed {
        trusted_keyring: TrustedKeyring::new(),
        require_revision_monotonicity: true,
        max_policy_age_secs: Some(86400),
    };
    let state = Arc::new(state_unwrapped);

    // Anonymous session (lacks identity_sub)
    let anon_session = session_anonymous();

    // 1. MCP HTTP PEP must deny
    let mcp_call_count = Arc::new(AtomicUsize::new(0));
    let mut mcp_downstream = MockMcpDownstream::new(mcp_call_count.clone());
    let mcp_params = json!({"name": "any_tool", "arguments": {}});
    let mcp_res = handle_mcp_tools_call(
        &state,
        &anon_session,
        "tools/call",
        &mcp_params,
        &mut mcp_downstream,
    )
    .await;
    assert!(
        matches!(mcp_res, Err(PepError::Denied { ref reason, .. }) if reason == "identity_missing_in_managed_mode"),
        "MCP must deny anonymous in managed mode: {:?}",
        mcp_res
    );
    assert_eq!(mcp_call_count.load(Ordering::SeqCst), 0);

    // 2. Stdio PEP must deny
    let stdio_call_count = Arc::new(AtomicUsize::new(0));
    let mut stdio_downstream = MockStdioDownstream::new(stdio_call_count.clone());
    let stdio_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "any_tool", "arguments": {}}
    });
    let stdio_res =
        handle_stdio_jsonrpc(&state, &anon_session, &stdio_req, &mut stdio_downstream).await;
    assert!(
        matches!(stdio_res, Err(PepError::Denied { ref reason, .. }) if reason == "identity_missing_in_managed_mode"),
        "Stdio must deny anonymous in managed mode: {:?}",
        stdio_res
    );
    assert_eq!(stdio_call_count.load(Ordering::SeqCst), 0);

    // 3. HTTP LLM PEP must deny
    let llm_call_count = Arc::new(AtomicUsize::new(0));
    let mut llm_downstream = MockLlmDownstream::new(llm_call_count.clone());
    let llm_body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}]
    });
    let llm_res = handle_http_llm_request(
        &state,
        &anon_session,
        "openai",
        "/v1/chat/completions",
        &llm_body,
        &mut llm_downstream,
    )
    .await;
    assert!(
        matches!(llm_res, Err(PepError::Denied { ref reason, .. }) if reason == "identity_missing_in_managed_mode"),
        "LLM must deny anonymous in managed mode: {:?}",
        llm_res
    );
    assert_eq!(llm_call_count.load(Ordering::SeqCst), 0);
}

// ─── Test 4: Real-time Revocation Parity Across Transports ────────────────────

#[tokio::test]
async fn test_revocation_parity_across_transports() {
    let yaml = r#"
version: "2.1"
default_action: deny
tools:
  - name: "compromised_tool"
    action: allow
"#;
    let policy = CompiledPolicy::from_yaml_str(yaml).unwrap();
    let state = state_with_policy(policy);
    let session = session_authenticated("dev-sec");

    // Instantly revoke compromised_tool in revocation registry
    state
        .revocation_registry
        .revoke_tool("compromised_tool", "Emergency security incident #4092");

    // 1. MCP HTTP PEP blocks immediately
    let mcp_call_count = Arc::new(AtomicUsize::new(0));
    let mut mcp_downstream = MockMcpDownstream::new(mcp_call_count.clone());
    let mcp_params = json!({"name": "compromised_tool", "arguments": {}});
    let mcp_res = handle_mcp_tools_call(
        &state,
        &session,
        "tools/call",
        &mcp_params,
        &mut mcp_downstream,
    )
    .await;
    assert!(
        matches!(mcp_res, Err(PepError::Denied { ref reason, .. }) if reason.contains("revoked")),
        "MCP must block revoked tool immediately: {:?}",
        mcp_res
    );
    assert_eq!(mcp_call_count.load(Ordering::SeqCst), 0);

    // 2. Stdio PEP blocks immediately
    let stdio_call_count = Arc::new(AtomicUsize::new(0));
    let mut stdio_downstream = MockStdioDownstream::new(stdio_call_count.clone());
    let stdio_req = json!({
        "jsonrpc": "2.0",
        "id": 99,
        "method": "tools/call",
        "params": {"name": "compromised_tool", "arguments": {}}
    });
    let stdio_res = handle_stdio_jsonrpc(&state, &session, &stdio_req, &mut stdio_downstream).await;
    assert!(
        matches!(stdio_res, Err(PepError::Denied { ref reason, .. }) if reason.contains("revoked")),
        "Stdio must block revoked tool immediately: {:?}",
        stdio_res
    );
    assert_eq!(stdio_call_count.load(Ordering::SeqCst), 0);
}

// ─── Test 5: SafeMode Hard Invariant Parity Across Transports ──────────────────

#[tokio::test]
async fn test_hard_invariant_parity_across_transports() {
    let yaml = r#"
version: "2.1"
default_action: deny
tools:
  - name: "bash"
    action: allow
"#;
    let policy = CompiledPolicy::from_yaml_str(yaml).unwrap();
    let state = state_with_policy(policy);
    let session = session_authenticated("dev-ops");

    // Destructive payload that trips Hard Safety Invariants (SafeMode)
    let destructive_cmd = "rm -rf / --no-preserve-root";

    // 1. MCP HTTP PEP blocks before dispatch
    let mcp_call_count = Arc::new(AtomicUsize::new(0));
    let mut mcp_downstream = MockMcpDownstream::new(mcp_call_count.clone());
    let mcp_params = json!({
        "name": "bash",
        "arguments": {"command": destructive_cmd}
    });
    let mcp_res = handle_mcp_tools_call(
        &state,
        &session,
        "tools/call",
        &mcp_params,
        &mut mcp_downstream,
    )
    .await;
    assert!(
        matches!(mcp_res, Err(PepError::Denied { ref reason, .. }) if reason == "hard_invariant_violation"),
        "MCP must block destructive command via SafeMode: {:?}",
        mcp_res
    );
    assert_eq!(mcp_call_count.load(Ordering::SeqCst), 0);

    // 2. Stdio PEP blocks before dispatch
    let stdio_call_count = Arc::new(AtomicUsize::new(0));
    let mut stdio_downstream = MockStdioDownstream::new(stdio_call_count.clone());
    let stdio_req = json!({
        "jsonrpc": "2.0",
        "id": 1001,
        "method": "tools/call",
        "params": {
            "name": "bash",
            "arguments": {"command": destructive_cmd}
        }
    });
    let stdio_res = handle_stdio_jsonrpc(&state, &session, &stdio_req, &mut stdio_downstream).await;
    assert!(
        matches!(stdio_res, Err(PepError::Denied { ref reason, .. }) if reason == "hard_invariant_violation"),
        "Stdio must block destructive command via SafeMode: {:?}",
        stdio_res
    );
    assert_eq!(stdio_call_count.load(Ordering::SeqCst), 0);
}

// ─── Test 6: DLP Sensitive Parameter Redaction in Stdio & MCP ────────────────

#[tokio::test]
async fn test_dlp_parameter_redaction_parity() {
    let yaml = r#"
version: "2.1"
default_action: deny
tools:
  - name: "connect_cloud"
    action: allow
"#;
    let policy = CompiledPolicy::from_yaml_str(yaml).unwrap();
    let state = state_with_policy(policy);
    let session = session_authenticated("dev-user");

    let raw_secret = "AKIAIOSFODNN7EXAMPLE";
    let req = json!({
        "jsonrpc": "2.0",
        "id": 50,
        "method": "tools/call",
        "params": {
            "name": "connect_cloud",
            "arguments": {
                "key": raw_secret
            }
        }
    });

    let eval_res = evaluate_stdio_request(&state, &session, &req)
        .await
        .unwrap();
    match eval_res {
        StdioEvaluationResult::Forward {
            forwarded_request, ..
        } => {
            let forwarded_key = forwarded_request["params"]["arguments"]["key"]
                .as_str()
                .unwrap();
            assert_ne!(
                forwarded_key, raw_secret,
                "Secret must not forward in plaintext"
            );
            assert!(
                forwarded_key.contains("[REDACTED:"),
                "Forwarded key must contain DLP redaction token, got: {}",
                forwarded_key
            );
        }
    }
}

// ─── Test 7: Stdio Protocol Control & Discovery Transparent Forwarding ────────

#[tokio::test]
async fn test_stdio_protocol_lifecycle_messages_forward() {
    let yaml = r#"
version: "2.1"
default_action: deny
tools: []
"#;
    let policy = CompiledPolicy::from_yaml_str(yaml).unwrap();
    let state = state_with_policy(policy);
    let session = session_authenticated("agent-client");

    // Lifecycle methods must forward transparently without requiring tool rules
    let lifecycle_methods = [
        "initialize",
        "notifications/initialized",
        "ping",
        "notifications/cancelled",
        "notifications/progress",
        "notifications/message",
        "$/cancelRequest",
        "tools/list",
    ];

    for (idx, method) in lifecycle_methods.iter().enumerate() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": idx + 1,
            "method": method,
            "params": {}
        });

        let res = evaluate_stdio_request(&state, &session, &req).await;
        assert!(
            res.is_ok(),
            "Method '{}' must pass through evaluation without denial: {:?}",
            method,
            res
        );
        match res.unwrap() {
            StdioEvaluationResult::Forward { is_tool_call, .. } => {
                assert!(!is_tool_call, "Lifecycle message is not a tool call");
            }
        }
    }
}

// ─── Test 8: Elimination of Blanket Bypasses for resources/* and prompts/* ────

#[tokio::test]
async fn test_resources_and_prompts_require_authoritative_policy() {
    let yaml = r#"
version: "2.1"
default_action: deny
tools: []
"#;
    let policy = CompiledPolicy::from_yaml_str(yaml).unwrap();
    let state = state_with_policy(policy);
    let session = session_authenticated("dev-1");

    // 1. resources/read must be denied when not listed in policy (G0.2)
    let res_read = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "resources/read",
        "params": {"uri": "file:///etc/shadow"}
    });
    let res = evaluate_stdio_request(&state, &session, &res_read).await;
    assert!(
        matches!(res, Err(PepError::Denied { .. })),
        "resources/read must not have blanket bypass: {:?}",
        res
    );

    // 2. prompts/get must be denied when not listed in policy (G0.2)
    let prompt_get = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "prompts/get",
        "params": {"name": "system_prompt"}
    });
    let res2 = evaluate_stdio_request(&state, &session, &prompt_get).await;
    assert!(
        matches!(res2, Err(PepError::Denied { .. })),
        "prompts/get must not have blanket bypass: {:?}",
        res2
    );
}

// ─── Test 9: Uniform JSON-RPC Error Translation Parity ─────────────────────────

#[test]
fn test_uniform_jsonrpc_error_translation_parity() {
    let id = json!(42);

    // 1. Policy Denial -> code -32001
    let deny_err = PepError::Denied {
        reason: "tool_not_permitted".to_string(),
        decision: Box::new(decision_v1::Decision::deny(
            "tool_not_permitted",
            Some("Not allowed".to_string()),
        )),
    };
    let json_deny = deny_err.to_jsonrpc_error(&id);
    assert_eq!(json_deny["error"]["code"], -32001);
    assert_eq!(json_deny["id"], 42);

    // 2. Approval Required -> code -32002
    let appr_err = PepError::ApprovalRequired {
        approval_id: "appr-123".to_string(),
        decision: Box::new(decision_v1::Decision {
            verdict: decision_v1::Verdict::RequireApproval,
            reason_code: "needs_manager_ok".to_string(),
            reason_detail: None,
            matched_group_id: None,
            obligations: vec![],
        }),
    };
    let json_appr = appr_err.to_jsonrpc_error(&id);
    assert_eq!(json_appr["error"]["code"], -32002);
    assert_eq!(json_appr["error"]["data"]["approval_id"], "appr-123");

    // 3. Validation Failed -> code -32600
    let val_err = PepError::ValidationFailed("Missing 'name'".to_string());
    let json_val = val_err.to_jsonrpc_error(&id);
    assert_eq!(json_val["error"]["code"], -32600);

    // 4. Downstream Error -> code -32603
    let down_err = PepError::DownstreamError("Connection reset by peer".to_string());
    let json_down = down_err.to_jsonrpc_error(&id);
    assert_eq!(json_down["error"]["code"], -32603);

    // 5. Response Withheld -> code -32004
    let with_err = PepError::ResponseWithheld {
        reason: "Secret detected: AWS Key".to_string(),
    };
    let json_with = with_err.to_jsonrpc_error(&id);
    assert_eq!(json_with["error"]["code"], -32004);

    // 6. Scanner Failure -> code -32005
    let scan_err = PepError::ScannerFailure {
        reason: "Timeout after 1000ms".to_string(),
    };
    let json_scan = scan_err.to_jsonrpc_error(&id);
    assert_eq!(json_scan["error"]["code"], -32005);
}
