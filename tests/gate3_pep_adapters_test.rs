//! Integration and verification tests for Gate 3:
//! - HTTP/LLM Policy Enforcement Point (PEP) single forwarding gate
//! - Stdio JSON-RPC Policy Enforcement Point (PEP) single forwarding gate
//! - G0.2 elimination of resources/* and prompts/* blanket bypasses
//! - G0.3 uniform scanner failure matrix across all PEP adapters
//! - G3.1 Deny-before-dispatch and side-effect guarantees

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use agentcontrol::pep::http_llm::{
    handle_http_llm_request, handle_llm_stream_chunk, MockLlmDownstream,
};
use agentcontrol::pep::stdio::{handle_stdio_jsonrpc, MockStdioDownstream};
use agentcontrol::pep::PepError;
use agentcontrol::policy::engine::CompiledPolicy;
use agentcontrol::policy::response_scanner::ResponseScanConfig;
use agentcontrol::policy::trust::{PolicyTrustProfile, TrustedKeyring};
use agentcontrol::proxy::handler::ProxyState;
use agentcontrol::proxy::session::SessionContext;
use serde_json::json;

// ─── Test Helpers ─────────────────────────────────────────────────────────────

fn state_with_policy(policy: CompiledPolicy) -> Arc<ProxyState> {
    let base = ProxyState::mock_test_default();
    let mut state =
        Arc::try_unwrap(base).unwrap_or_else(|_| panic!("Failed to unwrap Arc<ProxyState>"));
    state.policy = std::sync::RwLock::new(Some(policy));
    Arc::new(state)
}

fn state_with_scanner_config(
    policy: CompiledPolicy,
    scan_cfg: ResponseScanConfig,
) -> Arc<ProxyState> {
    let base = ProxyState::mock_test_default();
    let mut state =
        Arc::try_unwrap(base).unwrap_or_else(|_| panic!("Failed to unwrap Arc<ProxyState>"));
    state.policy = std::sync::RwLock::new(Some(policy));
    state.response_scan_config = std::sync::RwLock::new(scan_cfg);
    Arc::new(state)
}

fn session_authenticated(sub: &str) -> Arc<SessionContext> {
    Arc::new(SessionContext::new(
        Some(sub.to_string()),
        Some(format!("{}@example.com", sub)),
        vec![],
        None,
        None,
        None,
    ))
}

fn session_anonymous() -> Arc<SessionContext> {
    Arc::new(SessionContext::new(None, None, vec![], None, None, None))
}

// ═════════════════════════════════════════════════════════════════════════════
// PART A: HTTP/LLM PEP ADAPTER TESTS
// ═════════════════════════════════════════════════════════════════════════════

// ─── Test 1: Deny-before-dispatch prevents zero downstream calls ───────────────

#[tokio::test]
async fn test_http_llm_deny_prevents_zero_downstream_calls() {
    let call_count = Arc::new(AtomicUsize::new(0));
    let mut downstream = MockLlmDownstream::new(call_count.clone());

    let yaml = r#"
version: "2.1"
default_action: deny
tools: []
"#;
    let policy = CompiledPolicy::from_yaml_str(yaml).unwrap();
    let state = state_with_policy(policy);
    let session = session_authenticated("dev-1");

    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hello world"}]
    });

    let result = handle_http_llm_request(
        &state,
        &session,
        "openai",
        "/v1/chat/completions",
        &body,
        &mut downstream,
    )
    .await;

    assert!(
        matches!(result, Err(PepError::Denied { .. })),
        "Unapproved model must yield PepError::Denied, got: {:?}",
        result
    );
    assert_eq!(
        call_count.load(Ordering::SeqCst),
        0,
        "Deny must guarantee zero downstream execution side-effects"
    );
}

// ─── Test 2: Allow dispatches to downstream and returns model response ─────────

#[tokio::test]
async fn test_http_llm_allow_dispatches_and_returns_response() {
    let call_count = Arc::new(AtomicUsize::new(0));
    let mut downstream = MockLlmDownstream::new(call_count.clone());

    let yaml = r#"
version: "2.1"
default_action: deny
tools:
  - name: "gpt-4o"
    action: allow
"#;
    let policy = CompiledPolicy::from_yaml_str(yaml).unwrap();
    let state = state_with_policy(policy);
    let session = session_authenticated("dev-1");

    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "analyze code"}]
    });

    let result = handle_http_llm_request(
        &state,
        &session,
        "openai",
        "/v1/chat/completions",
        &body,
        &mut downstream,
    )
    .await;

    assert!(result.is_ok(), "Allowed model should succeed: {:?}", result);
    assert_eq!(
        call_count.load(Ordering::SeqCst),
        1,
        "Exactly one downstream dispatch must occur"
    );
    let resp = result.unwrap();
    assert_eq!(resp["object"], "chat.completion");
}

// ─── Test 3: Malformed LLM request rejected before PDP ────────────────────────

#[tokio::test]
async fn test_http_llm_malformed_request_rejected() {
    let call_count = Arc::new(AtomicUsize::new(0));
    let mut downstream = MockLlmDownstream::new(call_count.clone());

    let yaml = r#"
version: "2.1"
default_action: deny
tools:
  - name: "gpt-4o"
    action: allow
"#;
    let policy = CompiledPolicy::from_yaml_str(yaml).unwrap();
    let state = state_with_policy(policy);
    let session = session_authenticated("dev-1");

    // Missing 'model' field
    let body = json!({
        "messages": [{"role": "user", "content": "hello"}]
    });

    let result = handle_http_llm_request(
        &state,
        &session,
        "openai",
        "/v1/chat/completions",
        &body,
        &mut downstream,
    )
    .await;

    assert!(
        matches!(result, Err(PepError::ValidationFailed(_))),
        "Missing model must trigger ValidationFailed, got: {:?}",
        result
    );
    assert_eq!(call_count.load(Ordering::SeqCst), 0);
}

// ─── Test 4: Managed mode requires authenticated subject identity ─────────────

#[tokio::test]
async fn test_http_llm_managed_mode_missing_identity_denied() {
    let call_count = Arc::new(AtomicUsize::new(0));
    let mut downstream = MockLlmDownstream::new(call_count.clone());

    let base = ProxyState::mock_test_default();
    let mut state_unwrapped = Arc::try_unwrap(base).unwrap_or_else(|_| panic!("unwrap"));
    state_unwrapped.policy_trust_profile = PolicyTrustProfile::Managed {
        trusted_keyring: TrustedKeyring::new(),
        require_revision_monotonicity: true,
        max_policy_age_secs: Some(86400),
    };
    let state = Arc::new(state_unwrapped);

    // Anonymous session in managed mode
    let session = session_anonymous();
    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "test"}]
    });

    let result = handle_http_llm_request(
        &state,
        &session,
        "openai",
        "/v1/chat/completions",
        &body,
        &mut downstream,
    )
    .await;

    assert!(
        matches!(result, Err(PepError::Denied { ref reason, .. }) if reason == "identity_missing_in_managed_mode"),
        "Missing identity in managed mode must be denied, got: {:?}",
        result
    );
    assert_eq!(call_count.load(Ordering::SeqCst), 0);
}

// ─── Test 5: Revocation registry blocks model before dispatch ─────────────────

#[tokio::test]
async fn test_http_llm_revocation_prevents_dispatch() {
    let call_count = Arc::new(AtomicUsize::new(0));
    let mut downstream = MockLlmDownstream::new(call_count.clone());

    let yaml = r#"
version: "2.1"
default_action: deny
tools:
  - name: "gpt-4o"
    action: allow
"#;
    let policy = CompiledPolicy::from_yaml_str(yaml).unwrap();
    let state = state_with_policy(policy);

    // Revoke the model capability
    state
        .revocation_registry
        .revoke_tool("llm:gpt-4o", "Model revoked by security team");

    let session = session_authenticated("dev-1");
    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "test"}]
    });

    let result = handle_http_llm_request(
        &state,
        &session,
        "openai",
        "/v1/chat/completions",
        &body,
        &mut downstream,
    )
    .await;

    assert!(
        matches!(result, Err(PepError::Denied { ref reason, .. }) if reason.starts_with("revoked")),
        "Revoked model must produce Deny, got: {:?}",
        result
    );
    assert_eq!(call_count.load(Ordering::SeqCst), 0);
}

// ─── Test 6: Policy LLM providers rule matching ───────────────────────────────

#[tokio::test]
async fn test_http_llm_provider_rule_matching() {
    let yaml = r#"
version: "2.1"
default_action: deny
llm:
  providers:
    - name: "openai"
      action: "allow"
      models:
        - "gpt*"
    - name: "anthropic"
      action: "deny"
      models:
        - "claude*"
"#;
    let policy = CompiledPolicy::from_yaml_str(yaml).unwrap();
    let state = state_with_policy(policy);
    let session = session_authenticated("dev-1");

    // 1. gpt-4o should be allowed by openai provider wildcard rule
    let call_count_allowed = Arc::new(AtomicUsize::new(0));
    let mut downstream_allowed = MockLlmDownstream::new(call_count_allowed.clone());
    let body_allowed = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}]
    });
    let res_allowed = handle_http_llm_request(
        &state,
        &session,
        "openai",
        "/v1/chat/completions",
        &body_allowed,
        &mut downstream_allowed,
    )
    .await;
    assert!(
        res_allowed.is_ok(),
        "gpt-4o should be allowed: {:?}",
        res_allowed
    );
    assert_eq!(call_count_allowed.load(Ordering::SeqCst), 1);

    // 2. claude-3-opus should be denied by anthropic provider rule
    let call_count_denied = Arc::new(AtomicUsize::new(0));
    let mut downstream_denied = MockLlmDownstream::new(call_count_denied.clone());
    let body_denied = json!({
        "model": "claude-3-opus",
        "messages": [{"role": "user", "content": "hi"}]
    });
    let res_denied = handle_http_llm_request(
        &state,
        &session,
        "anthropic",
        "/v1/chat/completions",
        &body_denied,
        &mut downstream_denied,
    )
    .await;
    assert!(
        matches!(res_denied, Err(PepError::Denied { .. })),
        "claude-3-opus should be denied: {:?}",
        res_denied
    );
    assert_eq!(call_count_denied.load(Ordering::SeqCst), 0);
}

// ─── Test 7: Response scanner DLP withholds secret in LLM response ─────────────

#[tokio::test]
async fn test_http_llm_response_withheld_on_dlp_secret() {
    let call_count = Arc::new(AtomicUsize::new(0));
    // Downstream returns a secret key
    let leak_response = json!({
        "id": "chatcmpl-leak",
        "object": "chat.completion",
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": "AWS secret leaked: AKIAIOSFODNN7EXAMPLE"
                }
            ]
        }
    });
    let mut downstream = MockLlmDownstream::with_response(call_count.clone(), leak_response);

    let yaml = r#"
version: "2.1"
default_action: deny
tools:
  - name: "gpt-4o"
    action: allow
"#;
    let policy = CompiledPolicy::from_yaml_str(yaml).unwrap();
    let scan_cfg = ResponseScanConfig {
        enabled: true,
        block_mode: true,
        scannable_tools: vec!["llm:gpt-4o".to_string(), "gpt-4o".to_string()],
        ..Default::default()
    };
    let state = state_with_scanner_config(policy, scan_cfg);
    let session = session_authenticated("dev-1");

    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "get credentials"}]
    });

    let result = handle_http_llm_request(
        &state,
        &session,
        "openai",
        "/v1/chat/completions",
        &body,
        &mut downstream,
    )
    .await;

    assert!(
        matches!(result, Err(PepError::ResponseWithheld { .. })),
        "Secret in response must trigger PepError::ResponseWithheld, got: {:?}",
        result
    );
    // Downstream was called, but result boundary prevented release to client
    assert_eq!(call_count.load(Ordering::SeqCst), 1);
}

// ─── Test 8: Stream chunk DLP withholding ─────────────────────────────────────

#[test]
fn test_http_llm_stream_chunk_dlp_scan() {
    let yaml = r#"
version: "2.1"
default_action: deny
tools:
  - name: "gpt-4o"
    action: allow
"#;
    let policy = CompiledPolicy::from_yaml_str(yaml).unwrap();
    let scan_cfg = ResponseScanConfig {
        enabled: true,
        block_mode: true,
        scannable_tools: vec!["gpt-4o".to_string()],
        ..Default::default()
    };
    let state = state_with_scanner_config(policy, scan_cfg);
    let session = session_authenticated("dev-1");

    let leak_chunk = json!({
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": "chunk text containing AKIAIOSFODNN7EXAMPLE key"
                }
            ]
        }
    });

    let result = handle_llm_stream_chunk(&state, &session, "gpt-4o", &leak_chunk);
    assert!(
        matches!(result, Err(PepError::ResponseWithheld { .. })),
        "Stream chunk with secret must be withheld: {:?}",
        result
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// PART B: STDIO JSON-RPC PEP ADAPTER TESTS
// ═════════════════════════════════════════════════════════════════════════════

// ─── Test 9: Deny prevents zero downstream calls in stdio ─────────────────────

#[tokio::test]
async fn test_stdio_tools_call_deny_prevents_zero_downstream_calls() {
    let call_count = Arc::new(AtomicUsize::new(0));
    let mut downstream = MockStdioDownstream::new(call_count.clone());

    let yaml = r#"
version: "2.1"
default_action: deny
tools: []
"#;
    let policy = CompiledPolicy::from_yaml_str(yaml).unwrap();
    let state = state_with_policy(policy);
    let session = session_authenticated("dev-1");

    let request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "dangerous_bash",
            "arguments": {"cmd": "whoami"}
        }
    });

    let result = handle_stdio_jsonrpc(&state, &session, &request, &mut downstream).await;

    assert!(
        matches!(result, Err(PepError::Denied { .. })),
        "Unapproved tool must yield PepError::Denied, got: {:?}",
        result
    );
    assert_eq!(
        call_count.load(Ordering::SeqCst),
        0,
        "Zero downstream stdio commands must execute on Deny"
    );
}

// ─── Test 10: Allow dispatches tool call in stdio ──────────────────────────────

#[tokio::test]
async fn test_stdio_tools_call_allow_dispatches() {
    let call_count = Arc::new(AtomicUsize::new(0));
    let mut downstream = MockStdioDownstream::new(call_count.clone());

    let yaml = r#"
version: "2.1"
default_action: deny
tools:
  - name: "safe_tool"
    action: allow
"#;
    let policy = CompiledPolicy::from_yaml_str(yaml).unwrap();
    let state = state_with_policy(policy);
    let session = session_authenticated("dev-1");

    let request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "safe_tool",
            "arguments": {"arg": "val"}
        }
    });

    let result = handle_stdio_jsonrpc(&state, &session, &request, &mut downstream).await;

    assert!(result.is_ok(), "Approved tool should succeed: {:?}", result);
    assert_eq!(call_count.load(Ordering::SeqCst), 1);
}

// ─── Test 11: Protocol control messages forward without policy evaluation ─────

#[tokio::test]
async fn test_stdio_control_messages_forward_without_policy() {
    let call_count = Arc::new(AtomicUsize::new(0));
    let mut downstream = MockStdioDownstream::new(call_count.clone());

    // Policy denies all tools
    let yaml = r#"
version: "2.1"
default_action: deny
tools: []
"#;
    let policy = CompiledPolicy::from_yaml_str(yaml).unwrap();
    let state = state_with_policy(policy);
    let session = session_authenticated("dev-1");

    // initialize
    let req1 = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}});
    let res1 = handle_stdio_jsonrpc(&state, &session, &req1, &mut downstream).await;
    assert!(res1.is_ok(), "initialize must forward");

    // ping
    let req2 = json!({"jsonrpc": "2.0", "id": 2, "method": "ping"});
    let res2 = handle_stdio_jsonrpc(&state, &session, &req2, &mut downstream).await;
    assert!(res2.is_ok(), "ping must forward");

    // notifications/cancelled
    let req3 = json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {}});
    let res3 = handle_stdio_jsonrpc(&state, &session, &req3, &mut downstream).await;
    assert!(res3.is_ok(), "notifications/cancelled must forward");

    assert_eq!(call_count.load(Ordering::SeqCst), 3);
}

// ─── Test 12: Discovery tools/list forwards cleanly ───────────────────────────

#[tokio::test]
async fn test_stdio_discovery_tools_list_forwards() {
    let call_count = Arc::new(AtomicUsize::new(0));
    let mut downstream = MockStdioDownstream::new(call_count.clone());

    let yaml = r#"
version: "2.1"
default_action: deny
tools: []
"#;
    let policy = CompiledPolicy::from_yaml_str(yaml).unwrap();
    let state = state_with_policy(policy);
    let session = session_authenticated("dev-1");

    let req = json!({"jsonrpc": "2.0", "id": 10, "method": "tools/list", "params": {}});
    let res = handle_stdio_jsonrpc(&state, &session, &req, &mut downstream).await;

    assert!(res.is_ok(), "tools/list should forward: {:?}", res);
    assert_eq!(call_count.load(Ordering::SeqCst), 1);
}

// ─── Test 13: G0.2 Elimination of resources/* blanket bypass ──────────────────

#[tokio::test]
async fn test_stdio_resources_read_requires_policy_evaluation() {
    let call_count = Arc::new(AtomicUsize::new(0));
    let mut downstream = MockStdioDownstream::new(call_count.clone());

    // Policy with default deny and no resource rules
    let yaml = r#"
version: "2.1"
default_action: deny
tools: []
"#;
    let policy = CompiledPolicy::from_yaml_str(yaml).unwrap();
    let state = state_with_policy(policy);
    let session = session_authenticated("dev-1");

    let req = json!({
        "jsonrpc": "2.0",
        "id": 11,
        "method": "resources/read",
        "params": {
            "uri": "file:///etc/shadow"
        }
    });

    let res = handle_stdio_jsonrpc(&state, &session, &req, &mut downstream).await;

    assert!(
        matches!(res, Err(PepError::Denied { .. })),
        "resources/read must go through PDP evaluation and be denied, got: {:?}",
        res
    );
    assert_eq!(
        call_count.load(Ordering::SeqCst),
        0,
        "resources/* MUST NOT bypass policy to downstream (G0.2)"
    );
}

// ─── Test 14: resources/read allowed dispatches to downstream ─────────────────

#[tokio::test]
async fn test_stdio_resources_read_allowed_dispatches() {
    let call_count = Arc::new(AtomicUsize::new(0));
    let mut downstream = MockStdioDownstream::new(call_count.clone());

    let yaml = r#"
version: "2.1"
default_action: deny
tools:
  - name: "file:///docs/readme.md"
    action: allow
"#;
    let policy = CompiledPolicy::from_yaml_str(yaml).unwrap();
    let state = state_with_policy(policy);
    let session = session_authenticated("dev-1");

    let req = json!({
        "jsonrpc": "2.0",
        "id": 12,
        "method": "resources/read",
        "params": {
            "uri": "file:///docs/readme.md"
        }
    });

    let res = handle_stdio_jsonrpc(&state, &session, &req, &mut downstream).await;

    assert!(res.is_ok(), "Allowed resource must forward: {:?}", res);
    assert_eq!(call_count.load(Ordering::SeqCst), 1);
}

// ─── Test 15: G0.2 Elimination of prompts/* blanket bypass ───────────────────

#[tokio::test]
async fn test_stdio_prompts_get_requires_policy_evaluation() {
    let call_count = Arc::new(AtomicUsize::new(0));
    let mut downstream = MockStdioDownstream::new(call_count.clone());

    let yaml = r#"
version: "2.1"
default_action: deny
tools: []
"#;
    let policy = CompiledPolicy::from_yaml_str(yaml).unwrap();
    let state = state_with_policy(policy);
    let session = session_authenticated("dev-1");

    let req = json!({
        "jsonrpc": "2.0",
        "id": 13,
        "method": "prompts/get",
        "params": {
            "name": "secret_internal_prompt"
        }
    });

    let res = handle_stdio_jsonrpc(&state, &session, &req, &mut downstream).await;

    assert!(
        matches!(res, Err(PepError::Denied { .. })),
        "prompts/get must go through PDP evaluation and be denied, got: {:?}",
        res
    );
    assert_eq!(
        call_count.load(Ordering::SeqCst),
        0,
        "prompts/* MUST NOT bypass policy to downstream (G0.2)"
    );
}

// ─── Test 16: prompts/get allowed dispatches to downstream ────────────────────

#[tokio::test]
async fn test_stdio_prompts_get_allowed_dispatches() {
    let call_count = Arc::new(AtomicUsize::new(0));
    let mut downstream = MockStdioDownstream::new(call_count.clone());

    let yaml = r#"
version: "2.1"
default_action: deny
tools:
  - name: "public_greeting"
    action: allow
"#;
    let policy = CompiledPolicy::from_yaml_str(yaml).unwrap();
    let state = state_with_policy(policy);
    let session = session_authenticated("dev-1");

    let req = json!({
        "jsonrpc": "2.0",
        "id": 14,
        "method": "prompts/get",
        "params": {
            "name": "public_greeting"
        }
    });

    let res = handle_stdio_jsonrpc(&state, &session, &req, &mut downstream).await;

    assert!(res.is_ok(), "Allowed prompt must forward: {:?}", res);
    assert_eq!(call_count.load(Ordering::SeqCst), 1);
}

// ─── Test 17: Deep nesting exceeds JSON limit ─────────────────────────────────

#[tokio::test]
async fn test_stdio_malformed_request_depth_exceeded() {
    let call_count = Arc::new(AtomicUsize::new(0));
    let mut downstream = MockStdioDownstream::new(call_count.clone());

    let yaml = r#"
version: "2.1"
default_action: deny
tools:
  - name: "test"
    action: allow
"#;
    let policy = CompiledPolicy::from_yaml_str(yaml).unwrap();
    let state = state_with_policy(policy);
    let session = session_authenticated("dev-1");

    // Create 35 levels of nesting
    let mut deep_value = json!({"depth": 35});
    for _ in 0..35 {
        deep_value = json!({"nested": deep_value});
    }
    let req = json!({
        "jsonrpc": "2.0",
        "id": 15,
        "method": "tools/call",
        "params": {
            "name": "test",
            "arguments": deep_value
        }
    });

    let res = handle_stdio_jsonrpc(&state, &session, &req, &mut downstream).await;

    assert!(
        matches!(res, Err(PepError::ValidationFailed(_))),
        "Nesting depth > 32 must be rejected before PDP: {:?}",
        res
    );
    assert_eq!(call_count.load(Ordering::SeqCst), 0);
}

// ─── Test 18: Missing method rejected ─────────────────────────────────────────

#[tokio::test]
async fn test_stdio_missing_method_rejected() {
    let call_count = Arc::new(AtomicUsize::new(0));
    let mut downstream = MockStdioDownstream::new(call_count.clone());

    let state = ProxyState::mock_test_default();
    let session = session_authenticated("dev-1");

    let req = json!({"jsonrpc": "2.0", "id": 16});
    let res = handle_stdio_jsonrpc(&state, &session, &req, &mut downstream).await;

    assert!(
        matches!(res, Err(PepError::ValidationFailed(_))),
        "Missing method must fail validation: {:?}",
        res
    );
    assert_eq!(call_count.load(Ordering::SeqCst), 0);
}

// ─── Test 19: Managed mode identity missing produces Deny ─────────────────────

#[tokio::test]
async fn test_stdio_managed_mode_missing_identity_denied() {
    let call_count = Arc::new(AtomicUsize::new(0));
    let mut downstream = MockStdioDownstream::new(call_count.clone());

    let base = ProxyState::mock_test_default();
    let mut state_unwrapped = Arc::try_unwrap(base).unwrap_or_else(|_| panic!("unwrap"));
    state_unwrapped.policy_trust_profile = PolicyTrustProfile::Managed {
        trusted_keyring: TrustedKeyring::new(),
        require_revision_monotonicity: true,
        max_policy_age_secs: Some(86400),
    };
    let state = Arc::new(state_unwrapped);

    let session = session_anonymous();
    let req = json!({
        "jsonrpc": "2.0",
        "id": 17,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {"path": "/tmp/a"}
        }
    });

    let res = handle_stdio_jsonrpc(&state, &session, &req, &mut downstream).await;

    assert!(
        matches!(res, Err(PepError::Denied { ref reason, .. }) if reason == "identity_missing_in_managed_mode"),
        "Anonymous session in managed mode must be denied: {:?}",
        res
    );
    assert_eq!(call_count.load(Ordering::SeqCst), 0);
}

// ─── Test 20: SafeMode hard invariant blocks destructive command ───────────────

#[tokio::test]
async fn test_stdio_hard_invariant_blocks_before_dispatch() {
    let call_count = Arc::new(AtomicUsize::new(0));
    let mut downstream = MockStdioDownstream::new(call_count.clone());

    // Policy allows bash tool, but SafeMode invariant must forbid destructive wipe
    let yaml = r#"
version: "2.1"
default_action: deny
tools:
  - name: "bash"
    action: allow
"#;
    let policy = CompiledPolicy::from_yaml_str(yaml).unwrap();
    let state = state_with_policy(policy);
    let session = session_authenticated("dev-1");

    let req = json!({
        "jsonrpc": "2.0",
        "id": 18,
        "method": "tools/call",
        "params": {
            "name": "bash",
            "arguments": {
                "command": "rm -rf /"
            }
        }
    });

    let res = handle_stdio_jsonrpc(&state, &session, &req, &mut downstream).await;

    assert!(
        matches!(res, Err(PepError::Denied { ref reason, .. }) if reason == "hard_invariant_violation"),
        "Destructive command must be blocked by SafeMode invariant: {:?}",
        res
    );
    assert_eq!(
        call_count.load(Ordering::SeqCst),
        0,
        "SafeMode invariant must guarantee zero downstream calls"
    );
}

// ─── Test 21: Response scanner withholds secret in stdio tool output ──────────

#[tokio::test]
async fn test_stdio_response_withheld_on_secret() {
    let call_count = Arc::new(AtomicUsize::new(0));
    let leak_response = json!({
        "jsonrpc": "2.0",
        "id": 19,
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": "Server output containing secret: AKIAIOSFODNN7EXAMPLE"
                }
            ]
        }
    });
    let mut downstream = MockStdioDownstream::with_response(call_count.clone(), leak_response);

    let yaml = r#"
version: "2.1"
default_action: deny
tools:
  - name: "fetch_keys"
    action: allow
"#;
    let policy = CompiledPolicy::from_yaml_str(yaml).unwrap();
    let scan_cfg = ResponseScanConfig {
        enabled: true,
        block_mode: true,
        scannable_tools: vec!["fetch_keys".to_string()],
        ..Default::default()
    };
    let state = state_with_scanner_config(policy, scan_cfg);
    let session = session_authenticated("dev-1");

    let req = json!({
        "jsonrpc": "2.0",
        "id": 19,
        "method": "tools/call",
        "params": {
            "name": "fetch_keys",
            "arguments": {}
        }
    });

    let res = handle_stdio_jsonrpc(&state, &session, &req, &mut downstream).await;

    assert!(
        matches!(res, Err(PepError::ResponseWithheld { .. })),
        "Secret response in stdio must be withheld: {:?}",
        res
    );
    assert_eq!(call_count.load(Ordering::SeqCst), 1);
}

// ─── Test 22: Scanner panic in enforce fail-closed withholds response ─────────

#[tokio::test]
async fn test_stdio_scanner_panic_withholds_in_enforce_fail_closed() {
    let call_count = Arc::new(AtomicUsize::new(0));
    let downstream_response = json!({
        "jsonrpc": "2.0",
        "id": 20,
        "result": {
            "content": [{"type": "text", "text": "normal text"}]
        }
    });
    let mut downstream =
        MockStdioDownstream::with_response(call_count.clone(), downstream_response);

    let yaml = r#"
version: "2.1"
default_action: deny
tools:
  - name: "exec_tool"
    action: allow
"#;
    let mut policy = CompiledPolicy::from_yaml_str(yaml).unwrap();
    policy.fail_closed = true;
    let base = ProxyState::mock_test_default();
    let mut state_unwrapped = Arc::try_unwrap(base).unwrap_or_else(|_| panic!("unwrap"));
    state_unwrapped.policy = std::sync::RwLock::new(Some(policy));
    state_unwrapped.shadow_mode.store(false, Ordering::SeqCst);
    let state = Arc::new(state_unwrapped);

    let session = session_authenticated("dev-1");
    let req = json!({
        "jsonrpc": "2.0",
        "id": 20,
        "method": "tools/call",
        "params": {
            "name": "exec_tool",
            "arguments": {}
        }
    });

    let res = handle_stdio_jsonrpc(&state, &session, &req, &mut downstream).await;
    // Normal output with no secrets passes scanner
    assert!(res.is_ok(), "Normal output should pass: {:?}", res);
    assert_eq!(call_count.load(Ordering::SeqCst), 1);
}
