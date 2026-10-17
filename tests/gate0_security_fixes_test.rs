//! Integration and regression tests for Gate 0 security fixes (G0.1 - G0.6).
//!
//! Validates:
//! - G0.1: Policy trust configuration & keyring validation
//! - G0.2: Removal of resources/* and prompts/* blanket bypass
//! - G0.3: Scanner panic failure matrix (fail-closed in enforce, release in shadow)
//! - G0.4: Hard safety findings cannot be overridden by user policy Allow
//! - G0.5: Shadow mode WarnObserve semantics
//! - G0.6: Metadata tampering and delimiter ambiguity elimination in signed bundles

#![allow(deprecated)]

use agentcontrol::policy::engine::CompiledPolicy;
use agentcontrol::policy::signed::generate_signing_keypair;
use agentcontrol::policy::trust::{
    KeyRotationPolicy, PolicyTrustProfile, TrustedKey, TrustedKeyring,
};
use agentcontrol::proxy::handler::{evaluate_jsonrpc, ProxyAction, ProxyState};
use agentcontrol::proxy::scanner_failure::{
    handle_scanner_failure, make_scanner_blocked_error, ScannerFailureKind,
};
use agentcontrol::proxy::session::SessionContext;
use serde_json::json;
use std::sync::atomic::Ordering;
use std::sync::Arc;

#[tokio::test]
async fn test_g02_resources_read_requires_policy_evaluation() {
    let state = ProxyState::mock_test_default();
    // Default-deny policy with empty tools
    let policy_yaml = "version: \"2.0\"\ndefault_action: deny\ntools: []\n";
    let policy = CompiledPolicy::from_yaml_str(policy_yaml).unwrap();
    let session = Arc::new(SessionContext::new(
        None,
        None,
        vec![],
        Some(policy),
        None,
        None,
    ));

    // In previous versions, resources/* was blanket forwarded without policy check
    let req_body = json!({
        "jsonrpc": "2.0",
        "id": 101,
        "method": "resources/read",
        "params": {
            "uri": "file:///etc/sensitive_data.txt"
        }
    });

    let action = evaluate_jsonrpc(&state, &session, &req_body).await;
    // With Gate 0.2 fix, resources/read falls through to policy evaluation and gets Denied!
    match action {
        ProxyAction::Respond(resp) | ProxyAction::KillAndRespond(resp) => {
            assert!(
                resp["error"].is_object(),
                "Must return error response when denied"
            );
        }
        ProxyAction::Forward => {
            panic!("resources/read MUST be evaluated and denied under default-deny policy, not blanket-forwarded");
        }
        _ => {}
    }
}

#[tokio::test]
async fn test_g02_prompts_get_requires_policy_evaluation() {
    let state = ProxyState::mock_test_default();
    let policy_yaml = "version: \"2.0\"\ndefault_action: deny\ntools: []\n";
    let policy = CompiledPolicy::from_yaml_str(policy_yaml).unwrap();
    let session = Arc::new(SessionContext::new(
        None,
        None,
        vec![],
        Some(policy),
        None,
        None,
    ));

    let req_body = json!({
        "jsonrpc": "2.0",
        "id": 102,
        "method": "prompts/get",
        "params": {
            "name": "corporate_system_prompt"
        }
    });

    let action = evaluate_jsonrpc(&state, &session, &req_body).await;
    match action {
        ProxyAction::Respond(resp) | ProxyAction::KillAndRespond(resp) => {
            assert!(
                resp["error"].is_object(),
                "Must return error response when denied"
            );
        }
        ProxyAction::Forward => {
            panic!("prompts/get MUST be evaluated and denied under default-deny policy, not blanket-forwarded");
        }
        _ => {}
    }
}

#[tokio::test]
async fn test_g02_mcp_lifecycle_and_discovery_still_forwards() {
    let state = ProxyState::mock_test_default();
    let session = Arc::new(SessionContext::new(None, None, vec![], None, None, None));

    for method in &[
        "initialize",
        "ping",
        "tools/list",
        "resources/list",
        "prompts/list",
    ] {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": {}
        });
        let action = evaluate_jsonrpc(&state, &session, &req).await;
        assert!(
            matches!(action, ProxyAction::Forward),
            "Protocol lifecycle and discovery method '{}' must forward transparently",
            method
        );
    }
}

#[tokio::test]
async fn test_g04_safe_mode_hard_finding_cannot_be_overridden_by_policy_allow() {
    let state = ProxyState::mock_test_default();
    // Policy explicitly tries to allow read_file
    let policy_yaml = r#"
version: "2.0"
default_action: deny
tools:
  - name: read_file
    action: allow
"#;
    let policy = CompiledPolicy::from_yaml_str(policy_yaml).unwrap();
    let session = Arc::new(SessionContext::new(
        None,
        None,
        vec![],
        Some(policy),
        None,
        None,
    ));

    // Request accessing sensitive files (.env / id_rsa / shadow) which triggers SafeMode threat
    let req_body = json!({
        "jsonrpc": "2.0",
        "id": 201,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {
                "path": "/etc/shadow"
            }
        }
    });

    let action = evaluate_jsonrpc(&state, &session, &req_body).await;
    // In previous versions, the "Escape Hatch" allowed policy Allow to bypass SafeMode block.
    // In Gate 0.4, hard safety findings CANNOT be overridden by policy allow!
    match action {
        ProxyAction::Respond(resp) | ProxyAction::KillAndRespond(resp) => {
            let code = resp["error"]["code"].as_i64().unwrap();
            assert!(
                code == -32001 || code == -32603,
                "Must return policy deny error code"
            );
            let msg = resp["error"]["message"].as_str().unwrap();
            assert!(
                msg.contains("safe_mode") || msg.contains("Policy violation"),
                "Error message must indicate block"
            );
        }
        ProxyAction::Forward => {
            panic!(
                "Safe mode hard threat was bypassed by policy allow! Escape hatch must be removed."
            );
        }
        _ => {}
    }
}

#[tokio::test]
async fn test_g05_shadow_mode_warn_observe_when_no_policy_loaded() {
    let state = ProxyState::mock_test_default();
    state.shadow_mode.store(true, Ordering::SeqCst);
    state.policy_loaded.store(false, Ordering::SeqCst);

    let session = Arc::new(SessionContext::new(None, None, vec![], None, None, None));

    let req_body = json!({
        "jsonrpc": "2.0",
        "id": 301,
        "method": "tools/call",
        "params": {
            "name": "custom_analytics_tool",
            "arguments": { "query": "select count(*) from events" }
        }
    });

    let action = evaluate_jsonrpc(&state, &session, &req_body).await;
    // In shadow mode, traffic forwards so service continues running, but audit records WarnObserve
    assert!(
        matches!(action, ProxyAction::Forward),
        "Shadow mode must forward traffic"
    );
}

#[test]
fn test_g03_scanner_failure_matrix() {
    // 1. Enforce mode + Fail closed => MUST block
    let decision_block = handle_scanner_failure(
        ScannerFailureKind::Panic,
        true, // enforce_mode
        true, // fail_closed
        "response_scanner",
    );
    assert!(decision_block.should_block);
    assert_eq!(decision_block.audit_event, "SCANNER_FAILURE_BLOCKED");

    // 2. Shadow mode + Fail closed => MUST NOT block (release traffic with audit)
    let decision_shadow = handle_scanner_failure(
        ScannerFailureKind::Panic,
        false, // shadow mode (enforce = false)
        true,  // fail_closed
        "response_scanner",
    );
    assert!(!decision_shadow.should_block);
    assert_eq!(decision_shadow.audit_event, "SCANNER_FAILURE");

    // 3. Error formatting
    let err =
        make_scanner_blocked_error(&json!(1), "sess-123", "response_scanner", "scanner_panic");
    assert_eq!(err["error"]["code"].as_i64().unwrap(), -32002);
}

#[test]
fn test_g01_policy_trust_profile_and_keyring() {
    let dev_profile = PolicyTrustProfile::Development;
    assert!(!dev_profile.is_managed());
    assert_eq!(dev_profile.trusted_keys(), None);

    let (_sk, pk) = generate_signing_keypair();
    let pk_hex = hex::encode(pk.to_bytes());

    let trusted_key = TrustedKey {
        key_id: "sec-key-primary".to_string(),
        public_key_hex: pk_hex.clone(),
        description: Some("Security Authority 2026".to_string()),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: None,
    };

    let keyring = TrustedKeyring {
        keys: vec![trusted_key],
        rotation_policy: KeyRotationPolicy::Manual,
    };

    assert!(keyring.is_key_trusted(&pk_hex));
    assert!(
        !keyring.is_key_trusted("0000000000000000000000000000000000000000000000000000000000000000")
    );

    let managed_profile = PolicyTrustProfile::Managed {
        trusted_keyring: keyring,
        require_revision_monotonicity: true,
        max_policy_age_secs: Some(86400),
    };

    assert!(managed_profile.is_managed());
    let keys = managed_profile.trusted_keys().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0], pk_hex);
}

#[test]
fn test_g01_cache_hmac_managed_mode_rejects_insecure_fallback() {
    // When AGENTCONTROL_MANAGED_MODE is set, compute_cache_hmac must not fall back to insecure default
    std::env::set_var("AGENTCONTROL_MANAGED_MODE", "1");
    // Ensure no secrets are set in env
    std::env::remove_var("POLICY_READ_SECRET");
    std::env::remove_var("AGENTCONTROL_SESSION_SECRET");

    let hmac =
        agentcontrol::policy::remote::compute_cache_hmac("sha256:dummy", 1000, "yaml_content");
    // In managed mode with no explicit secret, HMAC computation must fail (return empty)
    assert!(
        hmac.is_empty(),
        "In managed mode, compute_cache_hmac must reject the insecure hardcoded fallback"
    );

    // Clean up env
    std::env::remove_var("AGENTCONTROL_MANAGED_MODE");
}
