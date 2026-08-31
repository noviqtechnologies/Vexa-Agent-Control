use agentcontrol::policy::engine::CompiledPolicy;
use agentcontrol::policy::schema::{CycleAction, CycleDetectionConfig, FirewallConfig};
use agentcontrol::proxy::handler::{
    evaluate_jsonrpc, ProxyAction, ProxyState, ToolCallFingerprint,
};
use serde_json::json;
use std::sync::Arc;

#[test]
fn test_canonical_json_hashing() {
    let args1 = json!({
        "key1": "value1",
        "key2": 42,
        "nested": {
            "b": true,
            "a": "hello"
        }
    });

    let args2 = json!({
        "key2": 42,
        "key1": "value1",
        "nested": {
            "a": "hello",
            "b": true
        }
    });

    let fp1 = ToolCallFingerprint::new("my_tool", &args1);
    let fp2 = ToolCallFingerprint::new("my_tool", &args2);

    assert_eq!(
        fp1, fp2,
        "Fingerprints must be identical regardless of parameter order"
    );
}

#[test]
fn test_tool_history_memory_bounding() {
    let state = ProxyState::mock_test_default();
    *state.policy.write().unwrap() = Some(CompiledPolicy {
        max_calls_per_second: 0,
        tools: vec![],
        group_policies: vec![],
        sequence_rules: vec![],
        identity_validator: None,
        scannable_tools: vec![],
        safe_tools: vec![],
        firewall: None, // Will fallback to default (enabled=true, max_attempts=3)
        spend_caps: None,
        llm: None,
        schema_drift: None,
        fail_closed: false,
    });

    let rt = tokio::runtime::Runtime::new().unwrap();

    let local_policy = state.policy.read().unwrap().clone();
    let session = Arc::new(agentcontrol::proxy::session::SessionContext::new(
        None,
        None,
        vec![],
        local_policy,
        None,
        None,
    ));

    // Call 10 times with different parameters so cycle detection isn't triggered,
    // but history is populated.
    for i in 0..10 {
        let req = json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "some_tool",
                "arguments": { "val": i }
            },
            "id": i
        });

        let _ = rt.block_on(async { evaluate_jsonrpc(&state, &session, &req).await });
    }

    let history = session.tool_history.lock().unwrap();
    assert_eq!(
        history.len(),
        5,
        "History size must be capped at TOOL_HISTORY_MAX (5)"
    );
}

#[test]
fn test_cycle_detection_blocking() {
    let state = ProxyState::mock_test_default();
    *state.policy.write().unwrap() = Some(CompiledPolicy {
        max_calls_per_second: 0,
        tools: vec![],
        group_policies: vec![],
        sequence_rules: vec![],
        identity_validator: None,
        scannable_tools: vec![],
        safe_tools: vec![],
        firewall: Some(FirewallConfig {
            enabled: true,
            cycle_detection: CycleDetectionConfig {
                max_attempts: 3,
                action: CycleAction::PivotError,
            },
        }),
        spend_caps: None,
        llm: None,
        schema_drift: None,
        fail_closed: false,
    });

    let req = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "allowed_tool",
            "arguments": { "foo": "bar" }
        },
        "id": 1
    });

    let rt = tokio::runtime::Runtime::new().unwrap();

    let local_policy = state.policy.read().unwrap().clone();
    let session = Arc::new(agentcontrol::proxy::session::SessionContext::new(
        None,
        None,
        vec![],
        local_policy,
        None,
        None,
    ));
    let res1 = rt.block_on(evaluate_jsonrpc(&state, &session, &req));
    let res2 = rt.block_on(evaluate_jsonrpc(&state, &session, &req));
    let res3 = rt.block_on(evaluate_jsonrpc(&state, &session, &req));

    match res1 {
        ProxyAction::KillAndRespond(val) => {
            assert_eq!(
                val["error"]["code"], -32001,
                "First call should fail with policy violation"
            );
        }
        _ => panic!("Expected KillAndRespond for first call"),
    }

    match res2 {
        ProxyAction::KillAndRespond(val) => {
            assert_eq!(
                val["error"]["code"], -32001,
                "Second call should fail with policy violation"
            );
        }
        _ => panic!("Expected KillAndRespond for second call"),
    }

    match res3 {
        ProxyAction::Respond(val) => {
            assert_eq!(
                val["error"]["code"], -32010,
                "Third call should fail with JSONRPC_FIREWALL_CYCLE"
            );
            assert!(
                val["error"]["message"]
                    .as_str()
                    .unwrap()
                    .contains("Cycle detected"),
                "Error message should mention cycle detection"
            );
        }
        _ => panic!("Expected Respond with cycle block for third call"),
    }
}

#[test]
fn test_pause_interactive_fallback_in_non_tty() {
    let state = ProxyState::mock_test_default();
    *state.policy.write().unwrap() = Some(CompiledPolicy {
        max_calls_per_second: 0,
        tools: vec![],
        group_policies: vec![],
        sequence_rules: vec![],
        identity_validator: None,
        scannable_tools: vec![],
        safe_tools: vec![],
        firewall: Some(FirewallConfig {
            enabled: true,
            cycle_detection: CycleDetectionConfig {
                max_attempts: 2,
                action: CycleAction::PauseInteractive,
            },
        }),
        spend_caps: None,
        llm: None,
        schema_drift: None,
        fail_closed: false,
    });

    let req = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "allowed_tool",
            "arguments": { "foo": "bar" }
        },
        "id": 1
    });

    let rt = tokio::runtime::Runtime::new().unwrap();

    let local_policy = state.policy.read().unwrap().clone();
    let session = Arc::new(agentcontrol::proxy::session::SessionContext::new(
        None,
        None,
        vec![],
        local_policy,
        None,
        None,
    ));

    let _res1 = rt.block_on(evaluate_jsonrpc(&state, &session, &req));
    let res2 = rt.block_on(evaluate_jsonrpc(&state, &session, &req));

    match res2 {
        ProxyAction::KillAndRespond(val) => {
            assert_eq!(
                val["error"]["code"], -32001,
                "PauseInteractive fallback should fail with policy violation"
            );
        }
        _ => panic!("Expected KillAndRespond for blocked call"),
    }
}
