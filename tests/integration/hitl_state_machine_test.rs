//! Integration test harness for ADR-010: HITL 6-State Crash/Recovery Machine,
//! Idempotency Keys, Scope Binding, and Secret Isolation.

use std::sync::Arc;
use std::time::Duration;
use agentcontrol::policy::hitl::{ApprovalState, HitlStateMachine};

// ─── Tests ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_hitl_atomic_cas_double_spend_prevention() {
    let sm = Arc::new(HitlStateMachine::new());
    let appr_id = "appr-concurrency-test-001".to_string();

    sm.submit_request(
        appr_id.clone(),
        "write_file".to_string(),
        "sha256:target_args_hash".to_string(),
        "ws-main".to_string(),
        "agentwall-daemon".to_string(),
        Duration::from_secs(60),
        1,
    );

    let mut handles = vec![];
    for task_idx in 0..16 {
        let sm_clone = sm.clone();
        let appr_id_clone = appr_id.clone();
        handles.push(tokio::spawn(async move {
            sm_clone.reserve(
                &appr_id_clone,
                &format!("actor-{}", task_idx),
                "write_file",
                "sha256:target_args_hash",
                "ws-main",
            )
        }));
    }

    let mut success_count = 0;
    let mut failure_count = 0;

    for handle in handles {
        match handle.await.unwrap() {
            Ok(_) => success_count += 1,
            Err(_) => failure_count += 1,
        }
    }

    assert_eq!(success_count, 1, "Exactly one thread must succeed in CAS reservation");
    assert_eq!(failure_count, 15, "All competing threads must be rejected");
}

#[test]
fn test_hitl_full_lifecycle_happy_path() {
    let sm = HitlStateMachine::new();
    let appr_id = "appr-happy-001".to_string();

    sm.submit_request(
        appr_id.clone(),
        "bash".to_string(),
        "sha256:args123".to_string(),
        "ws-1".to_string(),
        "daemon".to_string(),
        Duration::from_secs(30),
        1,
    );

    let idem = sm.reserve(&appr_id, "user-dev", "bash", "sha256:args123", "ws-1").unwrap();
    assert!(idem.starts_with("idem-"));

    assert!(sm.start_execution(&appr_id, &idem).is_ok());
    assert!(sm.complete_execution(&appr_id, &idem).is_ok());
}

#[test]
fn test_hitl_crash_recovery_outcome_unknown_no_silent_reexecution() {
    let sm = HitlStateMachine::new();
    let appr_id = "appr-crash-001".to_string();

    sm.submit_request(
        appr_id.clone(),
        "cloud_delete_resource".to_string(),
        "sha256:cloud_args".to_string(),
        "ws-prod".to_string(),
        "daemon".to_string(),
        Duration::from_secs(60),
        1,
    );

    let idem = sm.reserve(&appr_id, "admin", "cloud_delete_resource", "sha256:cloud_args", "ws-prod").unwrap();
    sm.start_execution(&appr_id, &idem).unwrap();

    // Simulate crash before complete_execution: tool_confirmed is None
    let recovered_state = sm.recover_from_crash(&appr_id, None);
    match recovered_state {
        ApprovalState::OutcomeUnknown { reason, .. } => {
            assert!(reason.contains("uncertain"));
        }
        other => panic!("Expected OutcomeUnknown, got: {:?}", other),
    }

    // Proves ADR-010 invariant: Cannot silently retry an uncertain side effect
    let retry_res = sm.reserve(&appr_id, "admin", "cloud_delete_resource", "sha256:cloud_args", "ws-prod");
    assert!(retry_res.is_err());
    assert!(retry_res.unwrap_err().contains("uncertain"));
}

#[test]
fn test_hitl_scope_binding_mismatch_rejected() {
    let sm = HitlStateMachine::new();
    let appr_id = "appr-scope-001".to_string();

    sm.submit_request(
        appr_id.clone(),
        "read_file".to_string(),
        "sha256:valid_hash".to_string(),
        "ws-1".to_string(),
        "daemon".to_string(),
        Duration::from_secs(30),
        1,
    );

    // Mismatched arguments_hash
    let res = sm.reserve(&appr_id, "user", "read_file", "sha256:TAMPERED_HASH", "ws-1");
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("Scope mismatch"));

    // Mismatched tool_name
    let res_tool = sm.reserve(&appr_id, "user", "dangerous_tool", "sha256:valid_hash", "ws-1");
    assert!(res_tool.is_err());
    assert!(res_tool.unwrap_err().contains("Scope mismatch"));
}

#[test]
fn test_hitl_notification_secret_isolation() {
    let sm = HitlStateMachine::new();
    let appr_id = "appr-01925b3a-8f12-7000".to_string();

    sm.submit_request(
        appr_id.clone(),
        "deploy_code".to_string(),
        "sha256:args".to_string(),
        "ws-1".to_string(),
        "daemon".to_string(),
        Duration::from_secs(30),
        1,
    );

    let notif = sm.format_notification(&appr_id);
    assert!(notif.contains("appr-01925b3a"), "Must contain opaque reference ID");
    assert!(!notif.contains("secret"), "Must not leak secret keys");
    assert!(!notif.contains("http://127.0.0.1:18080/api/v1/hitl/respond?token="), "Must not contain executable signed URL");
}

#[test]
fn test_hitl_revocation_prevents_execution() {
    let sm = HitlStateMachine::new();
    let appr_id = "appr-rev-001".to_string();
    sm.submit_request(
        appr_id.clone(),
        "rm".to_string(),
        "sha256:rm_hash".to_string(),
        "ws-1".to_string(),
        "daemon".to_string(),
        Duration::from_secs(30),
        1,
    );
    sm.revoke(&appr_id, "Operator emergency revoke");
    let res = sm.reserve(&appr_id, "admin", "rm", "sha256:rm_hash", "ws-1");
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("revoked"));
}
