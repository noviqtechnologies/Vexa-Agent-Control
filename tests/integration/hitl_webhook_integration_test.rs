//! Integration test suite for FR-304: HITL Webhook Interception & HMAC Escalation Flow

use agentcontrol::policy::hitl::{EscalationRequest, EscalationResponse, HitlManager};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[test]
fn test_hitl_webhook_integration_flow() {
    let secret_key = "integration-test-secret-key";
    let hitl = HitlManager::new(secret_key);

    let req_id = "escalate-req-77";
    hitl.submit_escalation(EscalationRequest {
        request_id: req_id.to_string(),
        agent_id: "agent-ci".to_string(),
        command: "rm -rf /data".to_string(),
        risk_reason: "Destructive file removal".to_string(),
        timestamp_ms: 5000,
    });

    let message = format!("{}:PERMANENT_ALLOW", req_id);
    let mut mac = HmacSha256::new_from_slice(secret_key.as_bytes()).unwrap();
    mac.update(message.as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());

    let res = hitl.process_callback(&EscalationResponse {
        request_id: req_id.to_string(),
        decision: "PERMANENT_ALLOW".to_string(),
        signed_hmac: sig,
    });

    assert!(res.is_ok());
    assert!(res.unwrap());
}
