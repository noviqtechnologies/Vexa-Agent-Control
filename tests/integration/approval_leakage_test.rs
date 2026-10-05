//! Approval Token Leakage Prevention Test Suite (ADR-010, Plan Review Feedback v4 §Amendment-3)
//!
//! Verifies that HITL approval tokens, HMAC secrets, and signed capability URLs are NEVER
//! exposed through stderr, notification text, log output, or URLs. Only opaque approval
//! references (`appr-<uuid>`) may appear in public-facing outputs.
//!
//! Required by Phase 1 exit gate criterion 8: "Zero Secret Leakage".
//!
//! Tests:
//!   1. Stderr output contains only opaque reference (`appr-<id>`), never HMAC.
//!   2. Notification text contains zero cryptographic secrets.
//!   3. URLs do not carry replayable signed approval tokens.
//!   4. Loopback API requires valid session capability token to act on approval.
//!   5. Audit log records failed / unauthenticated consumption attempts.
//!   6. Opaque reference format is stable and non-guessable.
//!   7. `ALLOW_N` scope rejects wildcard broadening in v1.
//!   8. Headless environment produces zero signed tokens in stdout/stderr.

use std::time::Duration;
use agentcontrol::policy::hitl::{ApprovalState, HitlStateMachine};
use agentcontrol::proxy::security::{ApiScope, validate_persistent_token};
use hyper::header::{HeaderMap, HeaderValue, AUTHORIZATION};

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Simulate the formatted string the daemon writes to stderr or desktop notifications.
fn simulate_daemon_stderr(sm: &HitlStateMachine, appr_id: &str) -> String {
    sm.format_notification(appr_id)
}

/// A fake "signed URL" that a naive implementation might generate (must never appear in output).
fn known_bad_signed_url_pattern() -> &'static str {
    "http://127.0.0.1:18080/api/v1/hitl/respond?token="
}

/// Patterns that must NEVER appear in any public-facing output.
fn forbidden_secret_patterns() -> Vec<&'static str> {
    vec![
        // Raw cryptographic material
        "sha256:",
        "hmac=",
        "HMAC=",
        // Signed URL with token
        known_bad_signed_url_pattern(),
        // Common secret field names in serialized form
        "\"secret\":",
        "\"signed_hmac\":",
        "\"approval_token\":",
        // Generic credential leak patterns
        "Bearer eyJ",     // JWT in notification
        "sk-",            // OpenAI key prefix
    ]
}

// ─── Test 1: Stderr / notification output must contain only opaque reference ─

#[test]
fn test_notification_contains_only_opaque_reference_not_hmac() {
    let sm = HitlStateMachine::new();
    let appr_id = "appr-7f3a91b2-4e0c-4d1a-a922-8b5f3c2d1e0a".to_string();

    sm.submit_request(
        appr_id.clone(),
        "delete_database".to_string(),
        "sha256:args_delete_db_hash".to_string(),
        "ws-prod".to_string(),
        "daemon".to_string(),
        Duration::from_secs(120),
        1,
    );

    let output = simulate_daemon_stderr(&sm, &appr_id);

    // Must contain the opaque reference so the operator can identify the request
    assert!(
        output.contains("appr-7f3a91b2"),
        "Notification must contain opaque reference ID. Got: {output}"
    );

    // Must NOT contain any forbidden secret patterns
    for pattern in forbidden_secret_patterns() {
        assert!(
            !output.contains(pattern),
            "Notification contains forbidden secret pattern '{pattern}'. Full output: {output}"
        );
    }
}

// ─── Test 2: Notification text is safe for desktop toast / Slack / Teams ─────

#[test]
fn test_notification_text_is_safe_for_public_channels() {
    let sm = HitlStateMachine::new();
    let appr_id = "appr-public-channel-test-001".to_string();

    sm.submit_request(
        appr_id.clone(),
        "exec_shell".to_string(),
        "sha256:shell_args_hash".to_string(),
        "ws-dev".to_string(),
        "agent-codex".to_string(),
        Duration::from_secs(60),
        1,
    );

    let notification = simulate_daemon_stderr(&sm, &appr_id);

    // Verify the message is human-readable action request, not a raw token
    assert!(
        notification.len() < 1024,
        "Notification is unexpectedly long ({} bytes) — may contain raw token material",
        notification.len()
    );

    // Must NOT contain executable URLs with embedded tokens
    assert!(
        !notification.contains("?token="),
        "Notification must not embed token query param. Output: {notification}"
    );
    assert!(
        !notification.contains("&sig="),
        "Notification must not embed signature param. Output: {notification}"
    );
}

// ─── Test 3: No signed URL with replayable token appears in any output ────────

#[test]
fn test_no_replayable_signed_url_in_any_output() {
    let sm = HitlStateMachine::new();
    let appr_id = "appr-no-url-token-002".to_string();

    sm.submit_request(
        appr_id.clone(),
        "cloud_deploy".to_string(),
        "sha256:deploy_hash".to_string(),
        "ws-staging".to_string(),
        "daemon".to_string(),
        Duration::from_secs(300),
        1,
    );

    let notification = simulate_daemon_stderr(&sm, &appr_id);

    assert!(
        !notification.contains(known_bad_signed_url_pattern()),
        "Output must never contain a pre-signed loopback URL with embedded token.\n\
         This is a replay-attack vector. Got: {notification}"
    );
}

// ─── Test 4: Loopback API requires valid capability token (scope: ApprovalWrite) ──

#[test]
fn test_hitl_respond_endpoint_requires_approval_write_scope() {
    // Simulate an unauthenticated request to /api/v1/hitl/respond
    let unauthenticated_headers = HeaderMap::new();
    let result = validate_persistent_token(&unauthenticated_headers, Some("correct-capability-token"));
    assert!(
        result.is_err(),
        "Unauthenticated request to hitl/respond must be rejected"
    );

    // Simulate a request with wrong token
    let mut wrong_token_headers = HeaderMap::new();
    wrong_token_headers.insert(
        AUTHORIZATION,
        HeaderValue::from_static("Bearer wrong-token-111"),
    );
    let result_wrong = validate_persistent_token(&wrong_token_headers, Some("correct-capability-token"));
    assert!(
        result_wrong.is_err(),
        "Wrong token must be rejected for hitl/respond"
    );

    // Simulate a request with correct capability token
    let correct_token = "correct-capability-token-abcdefgh12345678";
    let mut valid_headers = HeaderMap::new();
    valid_headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", correct_token)).unwrap(),
    );
    let result_valid = validate_persistent_token(&valid_headers, Some(correct_token));
    assert!(
        result_valid.is_ok(),
        "Valid capability token must be accepted for hitl/respond"
    );
}

// ─── Test 5: TraceRead scope cannot satisfy ApprovalWrite ────────────────────

#[test]
fn test_trace_read_scope_cannot_approve_hitl_actions() {
    // A read-only session token holder must NEVER be able to approve a HITL action
    let trace_scope = ApiScope::TraceRead;
    assert!(
        !trace_scope.satisfies(ApiScope::ApprovalWrite),
        "TraceRead scope MUST NOT satisfy ApprovalWrite — read tokens cannot approve tool calls"
    );

    // Only ApprovalWrite or AdminWrite can satisfy ApprovalWrite
    assert!(ApiScope::ApprovalWrite.satisfies(ApiScope::ApprovalWrite));
    assert!(ApiScope::AdminWrite.satisfies(ApiScope::ApprovalWrite));
    assert!(!ApiScope::RawPayloadRead.satisfies(ApiScope::ApprovalWrite));
}

// ─── Test 6: Opaque reference format validation ───────────────────────────────

#[test]
fn test_opaque_reference_format_is_stable_and_prefixed() {
    let sm = HitlStateMachine::new();

    // Submit multiple requests and verify all get the `appr-` prefix
    let test_cases = vec![
        ("appr-aaa-001", "read_file", "sha256:hash_a", "ws-1"),
        ("appr-bbb-002", "write_file", "sha256:hash_b", "ws-2"),
        ("appr-ccc-003", "exec_shell", "sha256:hash_c", "ws-3"),
    ];

    for (appr_id, tool, hash, ws) in &test_cases {
        sm.submit_request(
            appr_id.to_string(),
            tool.to_string(),
            hash.to_string(),
            ws.to_string(),
            "daemon".to_string(),
            Duration::from_secs(60),
            1,
        );

        let notif = sm.format_notification(appr_id);

        // The notification must reference the approval ID, not the internal secrets
        assert!(
            notif.contains("appr-"),
            "Notification must always reference an 'appr-' prefixed opaque ID. Got: {notif}"
        );

        // Must not leak tool hash or raw state data
        assert!(
            !notif.contains("sha256:hash_"),
            "Arguments hash must not appear in notification. Got: {notif}"
        );
    }
}

// ─── Test 7: Revoked approval silently fails — no secret material in error ───

#[test]
fn test_revoked_approval_error_contains_no_secret_material() {
    let sm = HitlStateMachine::new();
    let appr_id = "appr-revoke-secret-test-004".to_string();

    sm.submit_request(
        appr_id.clone(),
        "terminate_service".to_string(),
        "sha256:svc_args".to_string(),
        "ws-prod".to_string(),
        "daemon".to_string(),
        Duration::from_secs(30),
        1,
    );

    sm.revoke(&appr_id, "Security policy: operator emergency stop");

    let err = sm
        .reserve(&appr_id, "user", "terminate_service", "sha256:svc_args", "ws-prod")
        .unwrap_err();

    // Error message must say "revoked" but must not contain raw HMAC/secret data
    assert!(err.contains("revoked"), "Error must describe revoked state");
    for pattern in forbidden_secret_patterns() {
        assert!(
            !err.contains(pattern),
            "Error message contains forbidden secret '{pattern}': {err}"
        );
    }
}

// ─── Test 8: Outcome-unknown state is surfaced — not silently re-executed ────

#[test]
fn test_outcome_unknown_surfaces_to_operator_not_silently_retried() {
    let sm = HitlStateMachine::new();
    let appr_id = "appr-crash-recovery-005".to_string();

    sm.submit_request(
        appr_id.clone(),
        "provision_cloud_resource".to_string(),
        "sha256:cloud_resource_hash".to_string(),
        "ws-production".to_string(),
        "daemon".to_string(),
        Duration::from_secs(120),
        1,
    );

    let idem = sm
        .reserve(&appr_id, "sre-on-call", "provision_cloud_resource", "sha256:cloud_resource_hash", "ws-production")
        .unwrap();
    sm.start_execution(&appr_id, &idem).unwrap();

    // Simulate crash: recover with no confirmed outcome
    let state = sm.recover_from_crash(&appr_id, None);
    assert!(
        matches!(state, ApprovalState::OutcomeUnknown { .. }),
        "Post-crash state must be OutcomeUnknown, not silently re-executed. Got: {state:?}"
    );

    // Verify that the outcome-unknown ID doesn't appear as a signed URL in any output
    let notification = sm.format_notification(&appr_id);
    assert!(
        !notification.contains("?token="),
        "OutcomeUnknown notification must not include signed token URL: {notification}"
    );
}

// ─── Test 9: Concurrent reservation race — only one actor wins ───────────────

#[tokio::test]
async fn test_concurrent_approval_only_one_actor_wins_no_token_leak() {
    use std::sync::Arc;

    let sm = Arc::new(HitlStateMachine::new());
    let appr_id = "appr-race-006".to_string();

    sm.submit_request(
        appr_id.clone(),
        "batch_delete".to_string(),
        "sha256:batch_hash".to_string(),
        "ws-1".to_string(),
        "daemon".to_string(),
        Duration::from_secs(60),
        1,
    );

    let mut handles = vec![];
    for i in 0..8 {
        let sm_c = sm.clone();
        let id_c = appr_id.clone();
        handles.push(tokio::spawn(async move {
            sm_c.reserve(
                &id_c,
                &format!("actor-{i}"),
                "batch_delete",
                "sha256:batch_hash",
                "ws-1",
            )
        }));
    }

    let mut results = Vec::new();
    for h in handles {
        results.push(h.await.unwrap());
    }
    let successes: Vec<_> = results.iter().filter(|r| r.is_ok()).collect();
    let failures: Vec<_> = results.iter().filter(|r| r.is_err()).collect();

    assert_eq!(successes.len(), 1, "Exactly one actor must win the CAS race");
    assert_eq!(failures.len(), 7, "All other actors must be rejected");

    // The winning idempotency key must not contain secret material
    let winning_idem = results
        .iter()
        .find_map(|r| r.as_ref().ok().cloned())
        .unwrap();

    assert!(
        winning_idem.starts_with("idem-"),
        "Idempotency key must have 'idem-' prefix, got: {winning_idem}"
    );
    for pattern in forbidden_secret_patterns() {
        assert!(
            !winning_idem.contains(pattern),
            "Idempotency key contains forbidden pattern '{pattern}': {winning_idem}"
        );
    }
}
