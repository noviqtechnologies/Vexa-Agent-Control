//! Unit test suite for FR-304 / NFR-303: HITL Policy Escalation & HMAC Callback Verification

use agentcontrol::policy::hitl::{EscalationRequest, EscalationResponse, HitlManager};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[test]
fn test_hitl_escalation_hmac_verification() {
    let secret = "hmac-secret-key-prod";
    let manager = HitlManager::new(secret);
    let req_id = "req-999";

    let req = EscalationRequest {
        request_id: req_id.to_string(),
        agent_id: "agent-x".to_string(),
        command: "drop database production".to_string(),
        risk_reason: "SQL destruction attempt".to_string(),
        timestamp_ms: 1000,
    };
    manager.submit_escalation(req);

    // Valid HMAC signature
    let message = format!("{}:ALLOW_ONCE", req_id);
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(message.as_bytes());
    let valid_sig = hex::encode(mac.finalize().into_bytes());

    let res = manager.process_callback(&EscalationResponse {
        request_id: req_id.to_string(),
        decision: "ALLOW_ONCE".to_string(),
        signed_hmac: valid_sig,
    });
    assert!(res.is_ok());
    assert!(res.unwrap());
}

#[test]
fn test_hitl_escalation_invalid_signature_rejected() {
    let secret = "hmac-secret-key-prod";
    let manager = HitlManager::new(secret);
    let req_id = "req-1000";

    manager.submit_escalation(EscalationRequest {
        request_id: req_id.to_string(),
        agent_id: "agent-y".to_string(),
        command: "delete_file".to_string(),
        risk_reason: "Destructive file action".to_string(),
        timestamp_ms: 1000,
    });

    let res = manager.process_callback(&EscalationResponse {
        request_id: req_id.to_string(),
        decision: "ALLOW_ONCE".to_string(),
        signed_hmac: "invalid_bogus_signature".to_string(),
    });
    assert!(res.is_err());
}
