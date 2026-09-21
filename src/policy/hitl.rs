use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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

struct PendingRequestEntry {
    #[allow(dead_code)]
    request: EscalationRequest,
    created_at: Instant,
    responder: Option<tokio::sync::oneshot::Sender<bool>>,
}

pub struct HitlManager {
    pending_requests: Arc<Mutex<HashMap<String, PendingRequestEntry>>>,
    secret_key: String,
}

impl HitlManager {
    pub fn new(secret_key: impl Into<String>) -> Self {
        Self {
            pending_requests: Arc::new(Mutex::new(HashMap::new())),
            secret_key: secret_key.into(),
        }
    }

    /// Sign a decision for a request ID using HMAC-SHA256
    pub fn sign_decision(&self, request_id: &str, decision: &str) -> String {
        let message = format!("{}:{}", request_id, decision);
        let mut mac = match HmacSha256::new_from_slice(self.secret_key.as_bytes()) {
            Ok(m) => m,
            Err(_) => return String::new(),
        };
        mac.update(message.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    pub fn submit_escalation(&self, request: EscalationRequest) {
        let mut map = self.pending_requests.lock().unwrap();
        map.insert(
            request.request_id.clone(),
            PendingRequestEntry {
                request,
                created_at: Instant::now(),
                responder: None,
            },
        );
    }

    pub fn submit_escalation_with_channel(
        &self,
        request: EscalationRequest,
        responder: tokio::sync::oneshot::Sender<bool>,
    ) {
        let mut map = self.pending_requests.lock().unwrap();
        map.insert(
            request.request_id.clone(),
            PendingRequestEntry {
                request,
                created_at: Instant::now(),
                responder: Some(responder),
            },
        );
    }

    /// Verifies the HMAC signature on an incoming approval callback.
    pub fn verify_signature(&self, request_id: &str, decision: &str, signature: &str) -> bool {
        let expected = self.sign_decision(request_id, decision);
        !expected.is_empty() && expected == signature
    }

    pub fn process_callback(&self, response: &EscalationResponse) -> Result<bool, String> {
        if !self.verify_signature(
            &response.request_id,
            &response.decision,
            &response.signed_hmac,
        ) {
            return Err("Invalid HMAC signature on escalation callback".to_string());
        }

        let mut map = self.pending_requests.lock().unwrap();
        if let Some(entry) = map.remove(&response.request_id) {
            if entry.created_at.elapsed() > Duration::from_secs(300) {
                if let Some(tx) = entry.responder {
                    let _ = tx.send(false);
                }
                return Err("Escalation request timed out".to_string());
            }
            let is_allowed =
                response.decision == "ALLOW_ONCE" || response.decision == "PERMANENT_ALLOW";
            if let Some(tx) = entry.responder {
                let _ = tx.send(is_allowed);
            }
            Ok(is_allowed)
        } else {
            Err("Request ID not found or already processed".to_string())
        }
    }

    /// Dispatches an out-of-band OS desktop notification toast and awaits user confirmation.
    /// Works cross-platform on Windows, macOS, and Linux, with headless/SSH fallback.
    pub async fn request_desktop_approval(
        &self,
        tool_name: &str,
        risk_reason: &str,
        listen_addr: &str,
        timeout_secs: u64,
    ) -> bool {
        let request_id = uuid::Uuid::new_v4().to_string();
        let (tx, rx) = tokio::sync::oneshot::channel::<bool>();

        let allow_sig = self.sign_decision(&request_id, "ALLOW_ONCE");
        let deny_sig = self.sign_decision(&request_id, "DENY");

        let req = EscalationRequest {
            request_id: request_id.clone(),
            agent_id: "agent-local".to_string(),
            command: tool_name.to_string(),
            risk_reason: risk_reason.to_string(),
            timestamp_ms: chrono::Utc::now().timestamp_millis() as u64,
        };

        self.submit_escalation_with_channel(req, tx);

        // Dispatch desktop toast / alert dialog asynchronously
        Self::dispatch_os_toast(
            &request_id,
            tool_name,
            risk_reason,
            listen_addr,
            &allow_sig,
            &deny_sig,
        );

        // Await user approval with timeout (default 30 seconds)
        match tokio::time::timeout(Duration::from_secs(timeout_secs), rx).await {
            Ok(Ok(allowed)) => allowed,
            _ => {
                // Timeout or channel closed — clean up pending entry and fail closed
                let mut map = self.pending_requests.lock().unwrap();
                map.remove(&request_id);
                false
            }
        }
    }

    /// Cross-platform desktop toast dispatcher.
    pub fn dispatch_os_toast(
        request_id: &str,
        tool_name: &str,
        risk_reason: &str,
        listen_addr: &str,
        allow_sig: &str,
        deny_sig: &str,
    ) {
        let req_id = request_id.to_string();
        let tool = tool_name.to_string();
        let reason = risk_reason.to_string();
        let addr = listen_addr.to_string();
        let allow = allow_sig.to_string();
        let deny = deny_sig.to_string();

        tokio::task::spawn_blocking(move || {
            #[cfg(target_os = "windows")]
            {
                // Windows: Native modal message dialog via PowerShell PresentationFramework
                let script = format!(
                    "Add-Type -AssemblyName PresentationFramework; \
                     $msg = 'AgentControl Security Approval Required:`n`nTool: {tool}`nReason: {reason}`n`nAllow this call once?'; \
                     $res = [System.Windows.MessageBox]::Show($msg, 'AgentControl Security Alert', 'YesNo', 'Warning'); \
                     $decision = if ($res -eq 'Yes') {{ 'ALLOW_ONCE' }} else {{ 'DENY' }}; \
                     $sig = if ($res -eq 'Yes') {{ '{allow}' }} else {{ '{deny}' }}; \
                     $body = @{{ request_id = '{req_id}'; decision = $decision; signed_hmac = $sig }} | ConvertTo-Json; \
                     try {{ Invoke-RestMethod -Uri 'http://{addr}/api/v1/hitl/respond' -Method Post -Body $body -ContentType 'application/json' -TimeoutSec 5 }} catch {{}}",
                    tool = tool,
                    reason = reason,
                    req_id = req_id,
                    allow = allow,
                    deny = deny,
                    addr = addr
                );

                let _ = std::process::Command::new("powershell")
                    .args(["-NoProfile", "-NonInteractive", "-Command", &script])
                    .spawn();
            }

            #[cfg(target_os = "macos")]
            {
                // macOS: Native alert dialog via osascript
                let script = format!(
                    "tell application \"System Events\"\n\
                     activate\n\
                     set dialogResult to display alert \"AgentControl Security Alert\" \
                     message \"Agent requested tool '{tool}'\\nReason: {reason}\\n\\nAllow this call once?\" \
                     buttons {{\"Deny\", \"Approve Once\"}} default button 2 cancel button 1\n\
                     if button returned of dialogResult is \"Approve Once\" then\n\
                         do shell script \"curl -s -X POST http://{addr}/api/v1/hitl/respond -H 'Content-Type: application/json' -d '{{\\\"request_id\\\":\\\"{req_id}\\\",\\\"decision\\\":\\\"ALLOW_ONCE\\\",\\\"signed_hmac\\\":\\\"{allow}\\\"}}'\"\n\
                     else\n\
                         do shell script \"curl -s -X POST http://{addr}/api/v1/hitl/respond -H 'Content-Type: application/json' -d '{{\\\"request_id\\\":\\\"{req_id}\\\",\\\"decision\\\":\\\"DENY\\\",\\\"signed_hmac\\\":\\\"{deny}\\\"}}'\"\n\
                     end if\n\
                     end tell",
                    tool = tool,
                    reason = reason,
                    addr = addr,
                    req_id = req_id,
                    allow = allow,
                    deny = deny
                );

                let _ = std::process::Command::new("osascript")
                    .args(["-e", &script])
                    .spawn();
            }

            #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
            {
                // Linux / BSD: Check for GUI display server
                let has_display =
                    std::env::var("DISPLAY").is_ok() || std::env::var("WAYLAND_DISPLAY").is_ok();

                if has_display {
                    // Try zenity first
                    let zenity_res = std::process::Command::new("zenity")
                        .args([
                            "--question",
                            "--title=AgentControl Security Approval",
                            &format!("--text=Agent requested tool: {}\nReason: {}\n\nAllow this call once?", tool, reason),
                            "--ok-label=Approve Once",
                            "--cancel-label=Deny",
                        ])
                        .status();

                    let is_allowed = match zenity_res {
                        Ok(status) => status.success(),
                        Err(_) => {
                            // Fallback to notify-send
                            let approve_url = format!(
                                "http://{}/api/v1/hitl/respond?request_id={}&decision=ALLOW_ONCE&signed_hmac={}",
                                addr, req_id, allow
                            );
                            let _ = std::process::Command::new("notify-send")
                                .args([
                                    "AgentControl Security Alert",
                                    &format!("Tool '{}' paused. Approve: {}", tool, approve_url),
                                ])
                                .spawn();
                            false
                        }
                    };

                    let decision = if is_allowed { "ALLOW_ONCE" } else { "DENY" };
                    let sig = if is_allowed { &allow } else { &deny };
                    let payload = serde_json::json!({
                        "request_id": req_id,
                        "decision": decision,
                        "signed_hmac": sig
                    });

                    let client = reqwest::blocking::Client::new();
                    let _ = client
                        .post(format!("http://{}/api/v1/hitl/respond", addr))
                        .json(&payload)
                        .send();
                } else {
                    // Headless / SSH fallback
                    eprintln!(
                        "⚠️ [AgentControl HITL] Headless environment. Tool '{}' requested ({}). Approve at: http://{}/api/v1/hitl/respond?request_id={}&decision=ALLOW_ONCE&signed_hmac={}",
                        tool, reason, addr, req_id, allow
                    );
                }
            }
        });
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

    #[tokio::test]
    async fn test_hitl_channel_resolution() {
        let secret = "secret-key-async";
        let manager = Arc::new(HitlManager::new(secret));
        let req_id = "req-async-1";

        let (tx, rx) = tokio::sync::oneshot::channel::<bool>();
        let req = EscalationRequest {
            request_id: req_id.to_string(),
            agent_id: "agent-local".to_string(),
            command: "delete_db".to_string(),
            risk_reason: "Dropping production database".to_string(),
            timestamp_ms: 12345,
        };

        manager.submit_escalation_with_channel(req, tx);

        // Simulate async callback in background
        let manager_clone = Arc::clone(&manager);
        let sig = manager.sign_decision(req_id, "ALLOW_ONCE");
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            let callback = EscalationResponse {
                request_id: req_id.to_string(),
                decision: "ALLOW_ONCE".to_string(),
                signed_hmac: sig,
            };
            let _ = manager_clone.process_callback(&callback);
        });

        let allowed = rx.await.unwrap();
        assert!(allowed);
    }
}
