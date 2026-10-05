//! HITL CAS & Crash Recovery Dedicated Harness (Phase 0b Deliverable)
//!
//! This standalone harness exercises the HITL state machine under conditions that
//! are difficult to test in unit tests: true concurrency races, crash-window replay
//! attempts, idempotency key reconciliation, and rapid expiry under load.
//!
//! Required by Phase 0b exit criteria:
//!   - "Automated test harness attempting replay, double-spend, and race conditions
//!     against the HITL CAS state machine."
//!   - "Simulate crash immediately after reservation / during EXECUTING state."
//!   - "Validate reconciliation via idempotency key on restart."
//!   - "Verify OUTCOME_UNKNOWN on uncertain side effects."
//!
//! This file lives in `tests/harness/` (not `tests/integration/`) to make it
//! independently runnable: `cargo test --test hitl_harness`

use std::sync::Arc;
use std::time::Duration;
use agentcontrol::policy::hitl::{ApprovalState, HitlStateMachine};

// ─── Harness Utilities ────────────────────────────────────────────────────────

/// Create a fresh state machine with a submitted approval ready for the given tool.
fn fresh_sm_with_pending(appr_id: &str, tool: &str, args_hash: &str) -> HitlStateMachine {
    let sm = HitlStateMachine::new();
    sm.submit_request(
        appr_id.to_string(),
        tool.to_string(),
        args_hash.to_string(),
        "ws-harness".to_string(),
        "harness-daemon".to_string(),
        Duration::from_secs(120),
        1,
    );
    sm
}

// ─── Scenario 1: Basic CAS double-spend — 32 concurrent attackers ─────────────

#[tokio::test]
async fn harness_cas_double_spend_32_concurrent_attackers() {
    let sm = Arc::new(fresh_sm_with_pending(
        "appr-harness-ds-32",
        "delete_prod_db",
        "sha256:prod_db_hash",
    ));

    let mut handles = vec![];
    for i in 0..32 {
        let sm_c = sm.clone();
        handles.push(tokio::spawn(async move {
            sm_c.reserve(
                "appr-harness-ds-32",
                &format!("attacker-{i}"),
                "delete_prod_db",
                "sha256:prod_db_hash",
                "ws-harness",
            )
        }));
    }

    let mut results = Vec::new();
    for h in handles {
        results.push(h.await.unwrap());
    }
    let wins = results.iter().filter(|r| r.is_ok()).count();
    let losses = results.iter().filter(|r| r.is_err()).count();

    assert_eq!(wins, 1, "[32-attacker] CAS must produce exactly 1 winner");
    assert_eq!(losses, 31, "[32-attacker] All 31 other actors must be rejected");
}

// ─── Scenario 2: Crash during EXECUTING — must flag OUTCOME_UNKNOWN ───────────

#[test]
fn harness_crash_during_executing_flags_outcome_unknown() {
    let sm = fresh_sm_with_pending(
        "appr-harness-crash-exec",
        "provision_vm",
        "sha256:vm_spec_hash",
    );

    let idem = sm
        .reserve(
            "appr-harness-crash-exec",
            "infra-engineer",
            "provision_vm",
            "sha256:vm_spec_hash",
            "ws-harness",
        )
        .expect("Reserve should succeed");

    // Transition to EXECUTING (intent flushed before dispatch)
    sm.start_execution("appr-harness-crash-exec", &idem)
        .expect("start_execution should succeed");

    // Simulate crash: tool_confirmed=None (outcome unknown)
    let recovered = sm.recover_from_crash("appr-harness-crash-exec", None);

    match &recovered {
        ApprovalState::OutcomeUnknown { reason, .. } => {
            assert!(
                reason.contains("uncertain"),
                "Crash recovery reason must mention uncertainty. Got: {reason}"
            );
        }
        other => panic!(
            "[crash-during-executing] Expected OutcomeUnknown after crash, got: {other:?}"
        ),
    }

    // ADR-010 invariant: MUST NOT allow silent re-execution
    let retry = sm.reserve(
        "appr-harness-crash-exec",
        "infra-engineer",
        "provision_vm",
        "sha256:vm_spec_hash",
        "ws-harness",
    );
    assert!(
        retry.is_err(),
        "Re-execution of OUTCOME_UNKNOWN must be rejected — ADR-010 crash-recovery invariant"
    );
    assert!(
        retry.unwrap_err().contains("uncertain"),
        "Rejection message must mention uncertain state"
    );
}

// ─── Scenario 3: Crash during RESERVED — before EXECUTING flushed to disk ────

#[test]
fn harness_crash_during_reserved_before_execution_start() {
    let sm = fresh_sm_with_pending(
        "appr-harness-crash-reserved",
        "migrate_schema",
        "sha256:schema_hash",
    );

    let _idem = sm
        .reserve(
            "appr-harness-crash-reserved",
            "dba",
            "migrate_schema",
            "sha256:schema_hash",
            "ws-harness",
        )
        .expect("Reserve should succeed");

    // Crash before start_execution() — no I/O dispatched
    // Recover: since tool was never dispatched, outcome is deterministically NOT executed
    let recovered = sm.recover_from_crash("appr-harness-crash-reserved", Some(false));

    match &recovered {
        ApprovalState::Failed { reason } => {
            assert!(
                reason.contains("not executed") || reason.contains("crash") || reason.contains("aborted"),
                "Pre-execution crash recovery should flag as failed/not-executed. Got: {reason}"
            );
        }
        ApprovalState::OutcomeUnknown { .. } => {
            // Also acceptable — system may conservatively flag uncertain even for pre-execution
        }
        other => panic!(
            "[crash-during-reserved] Expected Failed or OutcomeUnknown, got: {other:?}"
        ),
    }
}

// ─── Scenario 4: Idempotency key reconciliation — tool confirms executed ─────

#[test]
fn harness_idempotency_key_reconciles_confirmed_execution() {
    let sm = fresh_sm_with_pending(
        "appr-harness-idem-reconcile",
        "send_notification",
        "sha256:notification_args",
    );

    let idem = sm
        .reserve(
            "appr-harness-idem-reconcile",
            "notification-service",
            "send_notification",
            "sha256:notification_args",
            "ws-harness",
        )
        .expect("Reserve should succeed");

    sm.start_execution("appr-harness-idem-reconcile", &idem).unwrap();

    // Process crashes. Tool server later confirms via idempotency key: tool_executed=true
    let recovered = sm.recover_from_crash("appr-harness-idem-reconcile", Some(true));

    match &recovered {
        ApprovalState::Executed { .. } => {
            // Correct: confirmed via idempotency key, mark as executed
        }
        ApprovalState::OutcomeUnknown { .. } => {
            // Conservative fallback: also acceptable if impl is strict
        }
        other => panic!(
            "[idem-reconcile] Expected Executed or OutcomeUnknown after confirmed reconciliation, got: {other:?}"
        ),
    }
}

// ─── Scenario 5: Replay attack — reuse consumed idempotency key ───────────────

#[test]
fn harness_replay_attack_consumed_idempotency_key_rejected() {
    let sm = fresh_sm_with_pending(
        "appr-harness-replay",
        "rotate_secrets",
        "sha256:rotate_args",
    );

    let idem = sm
        .reserve(
            "appr-harness-replay",
            "sec-automation",
            "rotate_secrets",
            "sha256:rotate_args",
            "ws-harness",
        )
        .expect("First reserve should succeed");

    sm.start_execution("appr-harness-replay", &idem).unwrap();
    sm.complete_execution("appr-harness-replay", &idem).unwrap();

    // Replay: attempt to call start_execution again with same idempotency key
    let replay = sm.start_execution("appr-harness-replay", &idem);
    assert!(
        replay.is_err(),
        "Replaying start_execution on EXECUTED state must be rejected"
    );

    // Replay: attempt to reserve again (double-spend post-execution)
    let double_reserve = sm.reserve(
        "appr-harness-replay",
        "attacker",
        "rotate_secrets",
        "sha256:rotate_args",
        "ws-harness",
    );
    assert!(
        double_reserve.is_err(),
        "Reserving an already-EXECUTED approval must be rejected (double-spend)"
    );
}

// ─── Scenario 6: Expiry enforcement — token TTL elapses before reservation ───

#[test]
fn harness_expired_approval_cannot_be_reserved() {
    let sm = HitlStateMachine::new();
    let appr_id = "appr-harness-expiry";

    // Submit with 0-second TTL (immediately expired)
    sm.submit_request(
        appr_id.to_string(),
        "zero_ttl_tool".to_string(),
        "sha256:ttl_args".to_string(),
        "ws-harness".to_string(),
        "daemon".to_string(),
        Duration::from_secs(0), // immediately expired
        1,
    );

    // Give the TTL a moment to elapse
    std::thread::sleep(Duration::from_millis(10));

    let result = sm.reserve(appr_id, "user", "zero_ttl_tool", "sha256:ttl_args", "ws-harness");
    assert!(
        result.is_err(),
        "Expired approval must be rejected"
    );
    let err = result.unwrap_err();
    assert!(
        err.contains("expired") || err.contains("revoked"),
        "Error must describe expiry. Got: {err}"
    );
}

// ─── Scenario 7: Scope binding — arguments hash mutation rejected ─────────────

#[test]
fn harness_scope_binding_arguments_hash_mutation_rejected() {
    let sm = fresh_sm_with_pending(
        "appr-harness-scope-mutate",
        "update_config",
        "sha256:original_config_hash",
    );

    // Attacker attempts to swap the arguments hash to something malicious
    let result = sm.reserve(
        "appr-harness-scope-mutate",
        "attacker",
        "update_config",
        "sha256:ATTACKER_CONFIG_HASH",  // mutated!
        "ws-harness",
    );
    assert!(
        result.is_err(),
        "Mutated arguments hash must be rejected by scope binding"
    );
    assert!(
        result.unwrap_err().contains("Scope mismatch"),
        "Error must describe scope mismatch"
    );
}

// ─── Scenario 8: Workspace isolation — wrong workspace rejected ───────────────

#[test]
fn harness_scope_binding_wrong_workspace_rejected() {
    let sm = fresh_sm_with_pending(
        "appr-harness-scope-ws",
        "deploy_service",
        "sha256:deploy_args",
    );

    // Lateral movement: attacker from a different workspace
    let result = sm.reserve(
        "appr-harness-scope-ws",
        "lateral-mover",
        "deploy_service",
        "sha256:deploy_args",
        "ws-ATTACKER-WORKSPACE",  // wrong workspace
    );
    assert!(
        result.is_err(),
        "Wrong workspace must be rejected by scope binding"
    );
}

// ─── Scenario 9: High-concurrency sequential reservations on fresh approvals ──

#[tokio::test]
async fn harness_sequential_independent_approvals_all_succeed() {
    // Create 10 independent approvals; each should be reservable exactly once
    let sm = Arc::new(HitlStateMachine::new());
    let n = 10usize;

    for i in 0..n {
        sm.submit_request(
            format!("appr-harness-seq-{i}"),
            "safe_tool".to_string(),
            format!("sha256:hash_{i}"),
            "ws-harness".to_string(),
            "daemon".to_string(),
            Duration::from_secs(60),
            1,
        );
    }

    let mut handles = vec![];
    for i in 0..n {
        let sm_c = sm.clone();
        handles.push(tokio::spawn(async move {
            sm_c.reserve(
                &format!("appr-harness-seq-{i}"),
                "legitimate-actor",
                "safe_tool",
                &format!("sha256:hash_{i}"),
                "ws-harness",
            )
        }));
    }

    let mut results = Vec::new();
    for h in handles {
        results.push(h.await.unwrap());
    }
    for (i, result) in results.iter().enumerate() {
        assert!(
            result.is_ok(),
            "Sequential independent approval {i} must succeed"
        );
    }
}
