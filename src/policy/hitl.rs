//! FR-304: Human-in-the-Loop (HITL) Policy Escalation
//! Asynchronous escalation engine for dangerous P0 commands, managing webhooks
//! and verifying HMAC signed authorization responses.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationRequest {
    pub request_id: String,
    pub agent_id: String,
    pub command: String,
    pub risk_reason: String,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationResponse {
    pub request_id: String,
    pub decision: String, // "ALLOW_ONCE", "PERMANENT_ALLOW", "DENY"
    pub signed_hmac: String,
}

pub struct HitlManager {
    pending_requests: Arc<Mutex<HashMap<String, (EscalationRequest, Instant)>>>,
    secret_key: String,
}

impl HitlManager {
    pub fn new(secret_key: impl Into<String>) -> Self {
        Self {
            pending_requests: Arc::new(Mutex::new(HashMap::new())),
            secret_key: secret_key.into(),
        }
    }

    pub fn submit_escalation(&self, request: EscalationRequest) {
        let mut map = self.pending_requests.lock().unwrap();
        map.insert(request.request_id.clone(), (request, Instant::now()));
    }

    /// Verifies the HMAC signature on an incoming approval callback.
    pub fn verify_signature(&self, request_id: &str, decision: &str, signature: &str) -> bool {
        let message = format!("{}:{}", request_id, decision);
        let mut mac = match HmacSha256::new_from_slice(self.secret_key.as_bytes()) {
            Ok(m) => m,
            Err(_) => return false,
        };
        mac.update(message.as_bytes());
        let expected = hex::encode(mac.finalize().into_bytes());
        expected == signature
    }

    pub fn process_callback(&self, response: &EscalationResponse) -> Result<bool, String> {
        if !self.verify_signature(&response.request_id, &response.decision, &response.signed_hmac) {
            return Err("Invalid HMAC signature on escalation callback".to_string());
        }

        let mut map = self.pending_requests.lock().unwrap();
        if let Some((_, created_at)) = map.remove(&response.request_id) {
            if created_at.elapsed() > Duration::from_secs(300) {
                return Err("Escalation request timed out".to_string());
            }
            Ok(response.decision == "ALLOW_ONCE" || response.decision == "PERMANENT_ALLOW")
        } else {
            Err("Request ID not found or already processed".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hitl_escalation_flow() {
        let secret = "super-secret-hmac-key";
        let manager = HitlManager::new(secret);
        let req_id = "req-12345";

        let req = EscalationRequest {
            request_id: req_id.to_string(),
            agent_id: "agent-007".to_string(),
            command: "rm -rf /prod".to_string(),
            risk_reason: "Dangerous root deletion".to_string(),
            timestamp_ms: 10000,
        };

        manager.submit_escalation(req);

        // Sign the response
        let message = format!("{}:ALLOW_ONCE", req_id);
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(message.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());

        let callback = EscalationResponse {
            request_id: req_id.to_string(),
            decision: "ALLOW_ONCE".to_string(),
            signed_hmac: signature,
        };

        let result = manager.process_callback(&callback);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
}
