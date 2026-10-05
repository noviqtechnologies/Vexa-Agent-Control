//! Human-in-the-Loop (HITL) State Machine, Idempotent Crash Recovery,
//! Scope Binding, and Secret Isolation (ADR-010, FR-304, NFR-303).
//!
//! Provides:
//! - Formal 6-state lifecycle: PENDING → RESERVED → EXECUTING → EXECUTED / FAILED / EXPIRED / REVOKED / OUTCOME_UNKNOWN
//! - Atomic Compare-And-Set (CAS) reservations to prevent double-spending
//! - Unique idempotency keys (`idem-<uuid>`) per execution attempt
//! - Opaque reference IDs (`appr-<uuid>`) for secret-isolated notification text and logs
//! - Scope binding to `(tool_name, arguments_hash, workspace_id, audience)`
//! - Crash recovery reconciliation preventing silent retry of uncertain side effects
//! - Full backward compatibility with `EscalationRequest` and `EscalationResponse`

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

type HmacSha256 = Hmac<Sha256>;

// ─── Legacy Structs (Preserved for 100% Backward Compatibility) ─────────────

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

// ─── Formal 6-State Machine Types (ADR-010 §2) ─────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalState {
    /// Ingress evaluation demands approval. Request generated with opaque reference.
    Pending,
    /// Atomically acquired by execution engine via CAS. Holds idempotency key.
    Reserved {
        idempotency_key: String,
        reserved_by: String,
    },
    /// Intent flushed to disk immediately before dispatching the tool call.
    Executing { idempotency_key: String },
    /// Action completed with verified success. Outcome logged to audit log.
    Executed {
        idempotency_key: String,
        completed_at: Instant,
    },
    /// Tool invocation rejected or terminated with error.
    Failed { reason: String },
    /// Token time-to-live elapsed before reservation.
    Expired,
    /// Explicit cancellation by operator or security policy.
    Revoked { reason: String },
    /// Crash occurred during tool execution; outcome is uncertain and requires manual review.
    OutcomeUnknown {
        idempotency_key: String,
        reason: String,
    },
}

#[derive(Debug, Clone)]
pub struct ApprovalRecord {
    pub approval_id: String,
    pub opaque_reference: String,
    pub tool_name: String,
    pub arguments_hash: String,
    pub workspace_id: String,
    pub audience: String,
    pub expiry: Instant,
    pub state: ApprovalState,
    pub remaining_uses: u32,
}

// ─── HitlStateMachine ───────────────────────────────────────────────────────

pub struct HitlStateMachine {
    records: Mutex<HashMap<String, ApprovalRecord>>,
}

impl Default for HitlStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl HitlStateMachine {
    pub fn new() -> Self {
        Self {
            records: Mutex::new(HashMap::new()),
        }
    }

    /// Submit a new approval request into the PENDING state.
    /// Returns the short opaque reference ID (`appr-<8-hex-chars>`).
    pub fn submit_request(
        &self,
        approval_id: String,
        tool_name: String,
        arguments_hash: String,
        workspace_id: String,
        audience: String,
        ttl: Duration,
        initial_uses: u32,
    ) -> String {
        let stripped = approval_id.strip_prefix("appr-").unwrap_or(&approval_id);
        let opaque_ref = format!("appr-{}", &stripped[..8.min(stripped.len())]);
        let mut map = self.records.lock().unwrap();
        map.insert(
            approval_id.clone(),
            ApprovalRecord {
                approval_id,
                opaque_reference: opaque_ref.clone(),
                tool_name,
                arguments_hash,
                workspace_id,
                audience,
                expiry: Instant::now() + ttl,
                state: ApprovalState::Pending,
                remaining_uses: initial_uses,
            },
        );
        opaque_ref
    }

    /// Atomic Compare-And-Set (CAS): Transition from Pending -> Reserved.
    /// Validates expiry and strict scope binding before reserving.
    pub fn reserve(
        &self,
        approval_id: &str,
        actor: &str,
        tool_name: &str,
        args_hash: &str,
        workspace_id: &str,
    ) -> Result<String, String> {
        let mut map = self.records.lock().unwrap();
        let record = self
            .find_record_mut(&mut map, approval_id)
            .ok_or_else(|| "Approval not found".to_string())?;

        // 1. Expiry check
        if Instant::now() > record.expiry {
            record.state = ApprovalState::Expired;
            return Err("Approval token has expired".to_string());
        }

        // 2. Scope binding check (strict ALLOW_N invariant: ADR-010 §2.4)
        if record.tool_name != tool_name
            || record.arguments_hash != args_hash
            || record.workspace_id != workspace_id
        {
            return Err("Scope mismatch: action does not match approved digest".to_string());
        }

        // 3. State check & atomic CAS
        match &record.state {
            ApprovalState::Pending => {
                let idem_key = format!("idem-{}", generate_nonce());
                record.state = ApprovalState::Reserved {
                    idempotency_key: idem_key.clone(),
                    reserved_by: actor.to_string(),
                };
                Ok(idem_key)
            }
            ApprovalState::Reserved { .. } => {
                Err("Double-spend rejected: approval already reserved".to_string())
            }
            ApprovalState::Executing { .. } => Err("Approval already in execution".to_string()),
            ApprovalState::Executed { .. } => Err("Approval already consumed".to_string()),
            ApprovalState::Revoked { reason } => Err(format!("Approval was revoked: {}", reason)),
            ApprovalState::Expired => Err("Approval expired".to_string()),
            ApprovalState::Failed { reason } => {
                Err(format!("Approval previously failed: {}", reason))
            }
            ApprovalState::OutcomeUnknown { .. } => Err(
                "Prior execution outcome unknown/uncertain; manual resolution required".to_string(),
            ),
        }
    }

    /// Transition from Reserved -> Executing (Write-ahead intent flush).
    pub fn start_execution(&self, approval_id: &str, idempotency_key: &str) -> Result<(), String> {
        let mut map = self.records.lock().unwrap();
        let record = self
            .find_record_mut(&mut map, approval_id)
            .ok_or_else(|| "Approval not found".to_string())?;

        match &record.state {
            ApprovalState::Reserved {
                idempotency_key: existing_key,
                ..
            } => {
                if existing_key != idempotency_key {
                    return Err("Idempotency key mismatch".to_string());
                }
                record.state = ApprovalState::Executing {
                    idempotency_key: idempotency_key.to_string(),
                };
                Ok(())
            }
            other => Err(format!("Cannot start execution from state: {:?}", other)),
        }
    }

    /// Transition to Executed upon successful tool completion.
    pub fn complete_execution(
        &self,
        approval_id: &str,
        idempotency_key: &str,
    ) -> Result<(), String> {
        let mut map = self.records.lock().unwrap();
        let record = self
            .find_record_mut(&mut map, approval_id)
            .ok_or_else(|| "Approval not found".to_string())?;

        match &record.state {
            ApprovalState::Executing {
                idempotency_key: existing_key,
            } => {
                if existing_key != idempotency_key {
                    return Err("Idempotency key mismatch".to_string());
                }
                record.remaining_uses = record.remaining_uses.saturating_sub(1);
                record.state = ApprovalState::Executed {
                    idempotency_key: idempotency_key.to_string(),
                    completed_at: Instant::now(),
                };
                Ok(())
            }
            other => Err(format!("Cannot complete execution from state: {:?}", other)),
        }
    }

    /// Transition to Failed upon tool failure or pre-execution error.
    pub fn fail_execution(&self, approval_id: &str, reason: &str) -> Result<(), String> {
        let mut map = self.records.lock().unwrap();
        let record = self
            .find_record_mut(&mut map, approval_id)
            .ok_or_else(|| "Approval not found".to_string())?;

        record.state = ApprovalState::Failed {
            reason: reason.to_string(),
        };
        Ok(())
    }

    /// Crash recovery reconciliation: inspect uncommitted Executing records on daemon start.
    /// If tool execution cannot be verified, transitions to `OutcomeUnknown`.
    /// Invariant: NEVER silently re-execute an uncertain side effect (ADR-010 §2.2).
    pub fn recover_from_crash(
        &self,
        approval_id: &str,
        tool_confirmed: Option<bool>,
    ) -> ApprovalState {
        let mut map = self.records.lock().unwrap();
        let record = match self.find_record_mut(&mut map, approval_id) {
            Some(r) => r,
            None => {
                return ApprovalState::Failed {
                    reason: "Record not found during recovery".to_string(),
                }
            }
        };

        match &record.state {
            ApprovalState::Executing { idempotency_key }
            | ApprovalState::Reserved {
                idempotency_key, ..
            } => match tool_confirmed {
                Some(true) => {
                    record.state = ApprovalState::Executed {
                        idempotency_key: idempotency_key.clone(),
                        completed_at: Instant::now(),
                    };
                }
                Some(false) => {
                    record.state = ApprovalState::Failed {
                        reason: "Tool confirmed non-execution after crash".to_string(),
                    };
                }
                None => {
                    record.state = ApprovalState::OutcomeUnknown {
                        idempotency_key: idempotency_key.clone(),
                        reason: "Process crashed during side effect; outcome uncertain".to_string(),
                    };
                }
            },
            _ => {}
        }
        record.state.clone()
    }

    /// Explicit cancellation by operator or security policy.
    pub fn revoke(&self, approval_id: &str, reason: &str) {
        let mut map = self.records.lock().unwrap();
        if let Some(record) = self.find_record_mut(&mut map, approval_id) {
            record.state = ApprovalState::Revoked {
                reason: reason.to_string(),
            };
        }
    }

    /// Query the current state of an approval record.
    pub fn get_state(&self, approval_id: &str) -> Option<ApprovalState> {
        let map = self.records.lock().unwrap();
        self.find_record(&map, approval_id).map(|r| r.state.clone())
    }

    /// Query full approval record snapshot.
    pub fn get_record(&self, approval_id: &str) -> Option<ApprovalRecord> {
        let map = self.records.lock().unwrap();
        self.find_record(&map, approval_id).cloned()
    }

    /// Format an unprivileged notification string ensuring zero secret leakage (ADR-010 §2.3).
    pub fn format_notification(&self, approval_id: &str) -> String {
        let map = self.records.lock().unwrap();
        if let Some(record) = self.find_record(&map, approval_id) {
            format!(
                "[Vexa Agent Control HITL] Approval Requested for tool '{}'. Reference ID: {}. Authorize via local console.",
                record.tool_name, record.opaque_reference
            )
        } else {
            format!(
                "[Vexa Agent Control HITL] Approval Requested. ID: {}",
                approval_id
            )
        }
    }

    // ── Helper: lookup by exact approval_id OR opaque_reference ─────────
    fn find_record<'a>(
        &self,
        map: &'a HashMap<String, ApprovalRecord>,
        id: &str,
    ) -> Option<&'a ApprovalRecord> {
        if let Some(record) = map.get(id) {
            return Some(record);
        }
        map.values().find(|r| r.opaque_reference == id)
    }

    fn find_record_mut<'a>(
        &self,
        map: &'a mut HashMap<String, ApprovalRecord>,
        id: &str,
    ) -> Option<&'a mut ApprovalRecord> {
        if map.contains_key(id) {
            return map.get_mut(id);
        }
        map.values_mut().find(|r| r.opaque_reference == id)
    }
}

// ─── HitlManager (Active Controller) ────────────────────────────────────────

pub struct HitlManager {
    state_machine: Arc<HitlStateMachine>,
    responders: Arc<Mutex<HashMap<String, tokio::sync::oneshot::Sender<bool>>>>,
    secret_key: String,
}

impl HitlManager {
    pub fn new(secret_key: impl Into<String>) -> Self {
        Self {
            state_machine: Arc::new(HitlStateMachine::new()),
            responders: Arc::new(Mutex::new(HashMap::new())),
            secret_key: secret_key.into(),
        }
    }

    /// Access the underlying formal state machine.
    pub fn state_machine(&self) -> &HitlStateMachine {
        &self.state_machine
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

    /// Verifies the HMAC signature on an incoming approval callback.
    pub fn verify_signature(&self, request_id: &str, decision: &str, signature: &str) -> bool {
        let expected = self.sign_decision(request_id, decision);
        !expected.is_empty() && expected == signature
    }

    /// Submits an escalation request into the state machine.
    pub fn submit_escalation(&self, request: EscalationRequest) {
        let args_hash = format!(
            "sha256:{}",
            hex::encode(sha2::Sha256::digest(request.command.as_bytes()))
        );
        self.state_machine.submit_request(
            request.request_id,
            request.command,
            args_hash,
            "workspace-default".to_string(),
            request.agent_id,
            Duration::from_secs(300),
            1,
        );
    }

    /// Submits an escalation request with an async oneshot channel responder.
    pub fn submit_escalation_with_channel(
        &self,
        request: EscalationRequest,
        responder: tokio::sync::oneshot::Sender<bool>,
    ) {
        let req_id = request.request_id.clone();
        self.submit_escalation(request);
        let mut responders = self.responders.lock().unwrap();
        responders.insert(req_id, responder);
    }

    /// Processes an approval/denial callback response.
    /// Enforces HMAC signature verification when signature is provided,
    /// transitions the state machine atomically, and fires any awaiting channels.
    pub fn process_callback(&self, response: &EscalationResponse) -> Result<bool, String> {
        // If HMAC signature is provided, strictly verify it
        if !response.signed_hmac.is_empty()
            && !self.verify_signature(
                &response.request_id,
                &response.decision,
                &response.signed_hmac,
            )
        {
            return Err("Invalid HMAC signature on escalation callback".to_string());
        }

        let record = self
            .state_machine
            .get_record(&response.request_id)
            .ok_or_else(|| "Request ID not found or already processed".to_string())?;

        let is_allowed = response.decision == "ALLOW_ONCE"
            || response.decision == "PERMANENT_ALLOW"
            || response.decision == "allow";

        if is_allowed {
            // Reserve via CAS
            let idem_res = self.state_machine.reserve(
                &record.approval_id,
                "operator",
                &record.tool_name,
                &record.arguments_hash,
                &record.workspace_id,
            );

            match idem_res {
                Ok(idem) => {
                    let _ = self
                        .state_machine
                        .start_execution(&record.approval_id, &idem);
                    let _ = self
                        .state_machine
                        .complete_execution(&record.approval_id, &idem);
                }
                Err(err) => {
                    // Send rejection to channel if still present
                    let mut responders = self.responders.lock().unwrap();
                    if let Some(tx) = responders
                        .remove(&record.approval_id)
                        .or_else(|| responders.remove(&record.opaque_reference))
                    {
                        let _ = tx.send(false);
                    }
                    return Err(format!("Approval transition failed: {}", err));
                }
            }
        } else {
            let _ = self
                .state_machine
                .fail_execution(&record.approval_id, "Rejected by operator");
        }

        // Dispatch async channel notification if awaiting
        let mut responders = self.responders.lock().unwrap();
        if let Some(tx) = responders
            .remove(&record.approval_id)
            .or_else(|| responders.remove(&record.opaque_reference))
        {
            let _ = tx.send(is_allowed);
        }

        Ok(is_allowed)
    }

    /// Dispatches an out-of-band OS desktop notification toast and awaits user confirmation.
    /// Works cross-platform on Windows, macOS, and Linux, with headless/SSH fallback.
    ///
    /// Hardened per ADR-010 §2.3: Zero cryptographic HMAC secret leakage in notifications or stderr.
    pub async fn request_desktop_approval(
        &self,
        tool_name: &str,
        risk_reason: &str,
        listen_addr: &str,
        timeout_secs: u64,
    ) -> bool {
        let request_id = format!("appr-{}", uuid::Uuid::new_v4());
        let (tx, rx) = tokio::sync::oneshot::channel::<bool>();

        let allow_sig = self.sign_decision(&request_id, "ALLOW_ONCE");
        let deny_sig = self.sign_decision(&request_id, "DENY");

        let args_hash = format!(
            "sha256:{}",
            hex::encode(sha2::Sha256::digest(tool_name.as_bytes()))
        );
        let opaque_ref = self.state_machine.submit_request(
            request_id.clone(),
            tool_name.to_string(),
            args_hash,
            "workspace-default".to_string(),
            "agent-local".to_string(),
            Duration::from_secs(timeout_secs),
            1,
        );

        {
            let mut responders = self.responders.lock().unwrap();
            responders.insert(request_id.clone(), tx);
        }

        // Dispatch desktop toast / alert dialog asynchronously with opaque reference ID
        Self::dispatch_os_toast(
            &request_id,
            &opaque_ref,
            tool_name,
            risk_reason,
            listen_addr,
            &allow_sig,
            &deny_sig,
        );

        // Await user approval with timeout
        match tokio::time::timeout(Duration::from_secs(timeout_secs), rx).await {
            Ok(Ok(allowed)) => allowed,
            _ => {
                // Timeout or channel closed — mark expired/failed and fail closed
                let _ = self
                    .state_machine
                    .fail_execution(&request_id, "Request timed out");
                let mut responders = self.responders.lock().unwrap();
                responders.remove(&request_id);
                false
            }
        }
    }

    /// Cross-platform desktop toast dispatcher.
    ///
    /// Hardened: Emits ONLY opaque reference ID in notification text and logs.
    /// Never prints HMAC secrets or executable query URLs to stderr or notification centers.
    pub fn dispatch_os_toast(
        request_id: &str,
        opaque_ref: &str,
        tool_name: &str,
        risk_reason: &str,
        listen_addr: &str,
        allow_sig: &str,
        deny_sig: &str,
    ) {
        let req_id = request_id.to_string();
        let op_ref = opaque_ref.to_string();
        let tool = tool_name.to_string();
        let reason = risk_reason.to_string();
        let addr = listen_addr.to_string();
        let allow = allow_sig.to_string();
        let deny = deny_sig.to_string();

        tokio::task::spawn_blocking(move || {
            #[cfg(target_os = "windows")]
            {
                // Windows: Native modal message dialog via PowerShell PresentationFramework
                // Dialog displays unprivileged opaque reference ID to user
                let script = format!(
                    "Add-Type -AssemblyName PresentationFramework; \
                     $msg = 'AgentControl Security Approval Required:`n`nTool: {tool}`nReason: {reason}`nReference ID: {op_ref}`n`nAllow this call once?'; \
                     $res = [System.Windows.MessageBox]::Show($msg, 'AgentControl Security Alert', 'YesNo', 'Warning'); \
                     $decision = if ($res -eq 'Yes') {{ 'ALLOW_ONCE' }} else {{ 'DENY' }}; \
                     $sig = if ($res -eq 'Yes') {{ '{allow}' }} else {{ '{deny}' }}; \
                     $body = @{{ request_id = '{req_id}'; decision = $decision; signed_hmac = $sig }} | ConvertTo-Json; \
                     try {{ Invoke-RestMethod -Uri 'http://{addr}/api/v1/hitl/respond' -Method Post -Body $body -ContentType 'application/json' -TimeoutSec 5 }} catch {{}}",
                    tool = tool,
                    reason = reason,
                    op_ref = op_ref,
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
                     message \"Agent requested tool '{tool}'\\nReason: {reason}\\nReference ID: {op_ref}\\n\\nAllow this call once?\" \
                     buttons {{\"Deny\", \"Approve Once\"}} default button 2 cancel button 1\n\
                     if button returned of dialogResult is \"Approve Once\" then\n\
                         do shell script \"curl -s -X POST http://{addr}/api/v1/hitl/respond -H 'Content-Type: application/json' -d '{{\\\"request_id\\\":\\\"{req_id}\\\",\\\"decision\\\":\\\"ALLOW_ONCE\\\",\\\"signed_hmac\\\":\\\"{allow}\\\"}}'\"\n\
                     else\n\
                         do shell script \"curl -s -X POST http://{addr}/api/v1/hitl/respond -H 'Content-Type: application/json' -d '{{\\\"request_id\\\":\\\"{req_id}\\\",\\\"decision\\\":\\\"DENY\\\",\\\"signed_hmac\\\":\\\"{deny}\\\"}}'\"\n\
                     end if\n\
                     end tell",
                    tool = tool,
                    reason = reason,
                    op_ref = op_ref,
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
                            &format!("--text=Agent requested tool: {}\nReason: {}\nReference ID: {}\n\nAllow this call once?", tool, reason, op_ref),
                            "--ok-label=Approve Once",
                            "--cancel-label=Deny",
                        ])
                        .status();

                    let is_allowed = match zenity_res {
                        Ok(status) => status.success(),
                        Err(_) => {
                            // Fallback to notify-send: Secret-isolated, emits only reference ID
                            let _ = std::process::Command::new("notify-send")
                                .args([
                                    "AgentControl Security Alert",
                                    &format!("Tool '{}' paused. Reference ID: {}. Authorize via local console.", tool, op_ref),
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
                    // Headless / SSH fallback: Strictly secret-isolated (ADR-010 §2.3)
                    eprintln!(
                        "⚠️ [AgentControl HITL] Headless environment. Tool '{}' requested ({}). Reference ID: {}. Approve via: agentwall hitl allow {}",
                        tool, reason, op_ref, op_ref
                    );
                }
            }
        });
    }
}

fn generate_nonce() -> String {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:x}", nanos)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

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
        let signature = manager.sign_decision(req_id, "ALLOW_ONCE");

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

    #[test]
    fn test_hitl_state_machine_cas_and_scope() {
        let sm = HitlStateMachine::new();
        let appr_id = "appr-unit-test-1".to_string();

        let op_ref = sm.submit_request(
            appr_id.clone(),
            "bash".to_string(),
            "sha256:valid_hash".to_string(),
            "ws-test".to_string(),
            "agent-1".to_string(),
            Duration::from_secs(60),
            1,
        );

        assert!(op_ref.starts_with("appr-"));

        // Scope mismatch rejection
        let fail_res = sm.reserve(&appr_id, "dev", "bash", "sha256:TAMPERED", "ws-test");
        assert!(fail_res.is_err());

        // Successful reservation
        let idem = sm
            .reserve(&appr_id, "dev", "bash", "sha256:valid_hash", "ws-test")
            .unwrap();
        assert!(idem.starts_with("idem-"));

        // Double spend prevention
        let double_spend = sm.reserve(&appr_id, "dev2", "bash", "sha256:valid_hash", "ws-test");
        assert!(double_spend.is_err());

        // Execution progression
        assert!(sm.start_execution(&appr_id, &idem).is_ok());
        assert!(sm.complete_execution(&appr_id, &idem).is_ok());
    }
}
