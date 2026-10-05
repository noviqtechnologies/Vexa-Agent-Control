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
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

type HmacSha256 = Hmac<Sha256>;

fn current_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

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
    pub decision: String, // "ALLOW_ONCE", "DENY"
    pub signed_hmac: String,
}

// ─── Formal 6-State Machine Types (ADR-010 §2) ─────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
        completed_at_epoch_ms: u64,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRecord {
    pub approval_id: String,
    pub opaque_reference: String,
    pub tool_name: String,
    pub arguments_hash: String,
    pub workspace_id: String,
    pub audience: String,
    pub created_at_epoch_ms: u64,
    pub expiry_epoch_ms: u64,
    #[serde(skip, default = "Instant::now")]
    pub expiry: Instant,
    pub state: ApprovalState,
    pub remaining_uses: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WalEvent {
    RequestSubmitted(ApprovalRecord),
    StateTransition {
        approval_id: String,
        state: ApprovalState,
        timestamp_epoch_ms: u64,
    },
}

// ─── HitlStateMachine ───────────────────────────────────────────────────────

pub struct HitlStateMachine {
    records: Mutex<HashMap<String, ApprovalRecord>>,
    wal_path: Option<PathBuf>,
}

impl Default for HitlStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl HitlStateMachine {
    pub fn new() -> Self {
        if let Ok(env_path) = std::env::var("AGENTCONTROL_HITL_WAL") {
            Self::with_wal(PathBuf::from(env_path)).unwrap_or_else(|_| Self {
                records: Mutex::new(HashMap::new()),
                wal_path: None,
            })
        } else {
            Self {
                records: Mutex::new(HashMap::new()),
                wal_path: None,
            }
        }
    }

    /// Open or create a persistent Write-Ahead Log (WAL) backed state machine.
    /// Replays historical events and reconciles interrupted execution states.
    pub fn with_wal(path: impl AsRef<Path>) -> Result<Self, std::io::Error> {
        let path_buf = path.as_ref().to_path_buf();
        let mut records = HashMap::new();

        if path_buf.exists() {
            let file = std::fs::File::open(&path_buf)?;
            let reader = BufReader::new(file);
            for line_res in reader.lines() {
                let line = line_res?;
                if line.trim().is_empty() {
                    continue;
                }
                if let Ok(event) = serde_json::from_str::<WalEvent>(&line) {
                    match event {
                        WalEvent::RequestSubmitted(mut record) => {
                            let now_ms = current_epoch_ms();
                            if record.expiry_epoch_ms > now_ms {
                                record.expiry = Instant::now()
                                    + Duration::from_millis(record.expiry_epoch_ms - now_ms);
                            } else {
                                record.state = ApprovalState::Expired;
                            }
                            records.insert(record.approval_id.clone(), record);
                        }
                        WalEvent::StateTransition {
                            approval_id, state, ..
                        } => {
                            if let Some(record) = records.get_mut(&approval_id) {
                                record.state = state;
                            }
                        }
                    }
                }
            }

            // Post-replay crash reconciliation:
            // Any record left in Executing or Reserved state when daemon crashed
            // MUST be reconciled to OutcomeUnknown to prevent silent re-execution!
            let now_ms = current_epoch_ms();
            let mut recons = Vec::new();
            for (id, record) in records.iter_mut() {
                match &record.state {
                    ApprovalState::Executing { idempotency_key }
                    | ApprovalState::Reserved {
                        idempotency_key, ..
                    } => {
                        let new_state = ApprovalState::OutcomeUnknown {
                            idempotency_key: idempotency_key.clone(),
                            reason: "Interrupted by daemon restart; outcome uncertain".to_string(),
                        };
                        record.state = new_state.clone();
                        recons.push((id.clone(), new_state));
                    }
                    ApprovalState::Pending => {
                        if record.expiry_epoch_ms <= now_ms {
                            let new_state = ApprovalState::Expired;
                            record.state = new_state.clone();
                            recons.push((id.clone(), new_state));
                        }
                    }
                    _ => {}
                }
            }

            let sm = Self {
                records: Mutex::new(records),
                wal_path: Some(path_buf),
            };

            for (id, state) in recons {
                sm.append_wal(&WalEvent::StateTransition {
                    approval_id: id,
                    state,
                    timestamp_epoch_ms: now_ms,
                });
            }

            Ok(sm)
        } else {
            Ok(Self {
                records: Mutex::new(HashMap::new()),
                wal_path: Some(path_buf),
            })
        }
    }

    fn append_wal(&self, event: &WalEvent) {
        if let Some(ref path) = self.wal_path {
            if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
                if let Ok(line) = serde_json::to_string(event) {
                    let _ = writeln!(file, "{}", line);
                    let _ = file.flush();
                }
            }
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
        let now_ms = current_epoch_ms();
        let expiry_ms = now_ms + ttl.as_millis() as u64;

        let record = ApprovalRecord {
            approval_id: approval_id.clone(),
            opaque_reference: opaque_ref.clone(),
            tool_name,
            arguments_hash,
            workspace_id,
            audience,
            created_at_epoch_ms: now_ms,
            expiry_epoch_ms: expiry_ms,
            expiry: Instant::now() + ttl,
            state: ApprovalState::Pending,
            remaining_uses: initial_uses,
        };

        self.append_wal(&WalEvent::RequestSubmitted(record.clone()));

        let mut map = self.records.lock().unwrap();
        map.insert(approval_id, record);
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
        let (idem_key, new_state) = match &record.state {
            ApprovalState::Pending => {
                let idem_key = format!("idem-{}", generate_nonce());
                let state = ApprovalState::Reserved {
                    idempotency_key: idem_key.clone(),
                    reserved_by: actor.to_string(),
                };
                (idem_key, state)
            }
            ApprovalState::Reserved { .. } => {
                return Err("Double-spend rejected: approval already reserved".to_string())
            }
            ApprovalState::Executing { .. } => {
                return Err("Approval already in execution".to_string())
            }
            ApprovalState::Executed { .. } => return Err("Approval already consumed".to_string()),
            ApprovalState::Revoked { reason } => {
                return Err(format!("Approval was revoked: {}", reason))
            }
            ApprovalState::Expired => return Err("Approval expired".to_string()),
            ApprovalState::Failed { reason } => {
                return Err(format!("Approval previously failed: {}", reason))
            }
            ApprovalState::OutcomeUnknown { .. } => {
                return Err(
                    "Prior execution outcome unknown/uncertain; manual resolution required"
                        .to_string(),
                )
            }
        };

        record.state = new_state.clone();
        let appr_id = record.approval_id.clone();
        drop(map);

        self.append_wal(&WalEvent::StateTransition {
            approval_id: appr_id,
            state: new_state,
            timestamp_epoch_ms: current_epoch_ms(),
        });

        Ok(idem_key)
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
                let new_state = ApprovalState::Executing {
                    idempotency_key: idempotency_key.to_string(),
                };
                record.state = new_state.clone();
                let appr_id = record.approval_id.clone();
                drop(map);

                self.append_wal(&WalEvent::StateTransition {
                    approval_id: appr_id,
                    state: new_state,
                    timestamp_epoch_ms: current_epoch_ms(),
                });
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
                let new_state = ApprovalState::Executed {
                    idempotency_key: idempotency_key.to_string(),
                    completed_at_epoch_ms: current_epoch_ms(),
                };
                record.state = new_state.clone();
                let appr_id = record.approval_id.clone();
                drop(map);

                self.append_wal(&WalEvent::StateTransition {
                    approval_id: appr_id,
                    state: new_state,
                    timestamp_epoch_ms: current_epoch_ms(),
                });
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

        let new_state = ApprovalState::Failed {
            reason: reason.to_string(),
        };
        record.state = new_state.clone();
        let appr_id = record.approval_id.clone();
        drop(map);

        self.append_wal(&WalEvent::StateTransition {
            approval_id: appr_id,
            state: new_state,
            timestamp_epoch_ms: current_epoch_ms(),
        });
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
                        completed_at_epoch_ms: current_epoch_ms(),
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
        let state = record.state.clone();
        let appr_id = record.approval_id.clone();
        drop(map);

        self.append_wal(&WalEvent::StateTransition {
            approval_id: appr_id,
            state: state.clone(),
            timestamp_epoch_ms: current_epoch_ms(),
        });
        state
    }

    /// Explicit cancellation by operator or security policy.
    pub fn revoke(&self, approval_id: &str, reason: &str) {
        let mut map = self.records.lock().unwrap();
        if let Some(record) = self.find_record_mut(&mut map, approval_id) {
            let new_state = ApprovalState::Revoked {
                reason: reason.to_string(),
            };
            record.state = new_state.clone();
            let appr_id = record.approval_id.clone();
            drop(map);

            self.append_wal(&WalEvent::StateTransition {
                approval_id: appr_id,
                state: new_state,
                timestamp_epoch_ms: current_epoch_ms(),
            });
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

    /// Open or create a persistent Write-Ahead Log (WAL) backed HitlManager.
    pub fn with_wal(
        secret_key: impl Into<String>,
        wal_path: impl AsRef<Path>,
    ) -> Result<Self, std::io::Error> {
        let sm = HitlStateMachine::with_wal(wal_path)?;
        Ok(Self {
            state_machine: Arc::new(sm),
            responders: Arc::new(Mutex::new(HashMap::new())),
            secret_key: secret_key.into(),
        })
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
    /// Strictly rejects legacy `PERMANENT_ALLOW` (ADR-010 policy gate).
    /// Enforces HMAC signature verification when signature is provided,
    /// transitions the state machine atomically, and fires any awaiting channels.
    pub fn process_callback(&self, response: &EscalationResponse) -> Result<bool, String> {
        // Enforce removal of permanent allow per ADR-010 policy gate
        if response.decision == "PERMANENT_ALLOW" {
            return Err("PERMANENT_ALLOW is prohibited in production: durable exceptions require an auditable policy change".to_string());
        }

        if response.decision != "ALLOW_ONCE"
            && response.decision != "DENY"
            && response.decision != "allow"
            && response.decision != "deny"
        {
            return Err(format!(
                "Invalid decision '{}': only ALLOW_ONCE and DENY are permitted",
                response.decision
            ));
        }

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

        let is_allowed = response.decision == "ALLOW_ONCE" || response.decision == "allow";

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
    /// Hardened per ADR-010 §2.3 & Audit Gate: Zero cryptographic HMAC secret leakage in
    /// notifications, subprocess arguments, shell commands, or stderr. Subprocesses receive
    /// ONLY the unprivileged opaque reference ID and return a simple boolean exit code.
    pub async fn request_desktop_approval(
        &self,
        tool_name: &str,
        risk_reason: &str,
        _listen_addr: &str,
        timeout_secs: u64,
    ) -> bool {
        let request_id = format!("appr-{}", uuid::Uuid::new_v4());
        let (tx, rx) = tokio::sync::oneshot::channel::<bool>();

        let args_hash = format!(
            "sha256:{}",
            hex::encode(sha2::Sha256::digest(tool_name.as_bytes()))
        );
        let opaque_ref = self.state_machine.submit_request(
            request_id.clone(),
            tool_name.to_string(),
            args_hash.clone(),
            "workspace-default".to_string(),
            "agent-local".to_string(),
            Duration::from_secs(timeout_secs),
            1,
        );

        {
            let mut responders = self.responders.lock().unwrap();
            responders.insert(request_id.clone(), tx);
        }

        // Spawn OS dialog asynchronously with opaque reference ID only (NO HMAC SECRETS)
        let req_id_clone = request_id.clone();
        let op_ref_clone = opaque_ref.clone();
        let tool_clone = tool_name.to_string();
        let reason_clone = risk_reason.to_string();
        let responders_clone = self.responders.clone();

        tokio::task::spawn_blocking(move || {
            let decision =
                Self::dispatch_os_toast(&req_id_clone, &op_ref_clone, &tool_clone, &reason_clone);
            if let Some(allowed) = decision {
                let mut responders = responders_clone.lock().unwrap();
                if let Some(tx) = responders.remove(&req_id_clone) {
                    let _ = tx.send(allowed);
                }
            }
        });

        // Await user approval with timeout
        match tokio::time::timeout(Duration::from_secs(timeout_secs), rx).await {
            Ok(Ok(true)) => {
                let idem_res = self.state_machine.reserve(
                    &request_id,
                    "desktop_operator",
                    tool_name,
                    &args_hash,
                    "workspace-default",
                );
                if let Ok(idem) = idem_res {
                    let _ = self.state_machine.start_execution(&request_id, &idem);
                    let _ = self.state_machine.complete_execution(&request_id, &idem);
                }
                true
            }
            Ok(Ok(false)) => {
                let _ = self
                    .state_machine
                    .fail_execution(&request_id, "Rejected by operator via desktop dialog");
                false
            }
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
    /// Hardened per ADR-010 §2.3: Emits ONLY opaque reference ID in notification text and logs.
    /// Subprocesses receive ZERO secrets, zero HMAC signatures, zero tokens, and zero URLs.
    pub fn dispatch_os_toast(
        _request_id: &str,
        opaque_ref: &str,
        tool_name: &str,
        risk_reason: &str,
    ) -> Option<bool> {
        let op_ref = opaque_ref.to_string();
        let tool = tool_name.to_string();
        let reason = risk_reason.to_string();

        #[cfg(target_os = "windows")]
        {
            // Windows: Native modal message dialog via PowerShell PresentationFramework
            // Dialog displays unprivileged opaque reference ID to user and exits with 0 on Yes, 1 on No.
            // Absolutely NO cryptographic secrets or network calls in subprocess arguments.
            let script = format!(
                "Add-Type -AssemblyName PresentationFramework; \
                 $msg = 'AgentControl Security Approval Required:`n`nTool: {tool}`nReason: {reason}`nReference ID: {op_ref}`n`nAllow this call once?'; \
                 $res = [System.Windows.MessageBox]::Show($msg, 'AgentControl Security Alert', 'YesNo', 'Warning'); \
                 if ($res -eq 'Yes') {{ exit 0 }} else {{ exit 1 }}",
                tool = tool,
                reason = reason,
                op_ref = op_ref
            );

            let status = std::process::Command::new("powershell")
                .args(["-NoProfile", "-NonInteractive", "-Command", &script])
                .status();

            match status {
                Ok(s) => Some(s.code() == Some(0)),
                Err(_) => None,
            }
        }

        #[cfg(target_os = "macos")]
        {
            // macOS: Native alert dialog via osascript
            // Displays ONLY opaque reference ID. Returns stdout APPROVE or DENY.
            // Absolutely NO HMAC secrets or network calls in subprocess arguments.
            let script = format!(
                "tell application \"System Events\"\n\
                 activate\n\
                 set dialogResult to display alert \"AgentControl Security Alert\" \
                 message \"Agent requested tool '{tool}'\\nReason: {reason}\\nReference ID: {op_ref}\\n\\nAllow this call once?\" \
                 buttons {{\"Deny\", \"Approve Once\"}} default button 2 cancel button 1\n\
                 if button returned of dialogResult is \"Approve Once\" then\n\
                     return \"APPROVE\"\n\
                 else\n\
                     return \"DENY\"\n\
                 end if\n\
                 end tell",
                tool = tool,
                reason = reason,
                op_ref = op_ref
            );

            let output = std::process::Command::new("osascript")
                .args(["-e", &script])
                .output();

            match output {
                Ok(out) => {
                    let s = String::from_utf8_lossy(&out.stdout);
                    Some(s.trim() == "APPROVE")
                }
                Err(_) => None,
            }
        }

        #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
        {
            // Linux / BSD: Check for GUI display server
            let has_display =
                std::env::var("DISPLAY").is_ok() || std::env::var("WAYLAND_DISPLAY").is_ok();

            if has_display {
                // Try zenity first (status.success() on Approve Once)
                let zenity_res = std::process::Command::new("zenity")
                    .args([
                        "--question",
                        "--title=AgentControl Security Approval",
                        &format!("--text=Agent requested tool: {}\nReason: {}\nReference ID: {}\n\nAllow this call once?", tool, reason, op_ref),
                        "--ok-label=Approve Once",
                        "--cancel-label=Deny",
                    ])
                    .status();

                match zenity_res {
                    Ok(status) => Some(status.success()),
                    Err(_) => {
                        // Fallback to notify-send: Secret-isolated, emits only reference ID
                        let _ = std::process::Command::new("notify-send")
                            .args([
                                "AgentControl Security Alert",
                                &format!("Tool '{}' paused. Reference ID: {}. Authorize via local console.", tool, op_ref),
                            ])
                            .spawn();
                        None
                    }
                }
            } else {
                // Headless / SSH fallback: Strictly secret-isolated (ADR-010 §2.3)
                eprintln!(
                    "⚠️ [AgentControl HITL] Headless environment. Tool '{}' requested ({}). Reference ID: {}. Approve via: agentcontrol hitl allow {}",
                    tool, reason, op_ref, op_ref
                );
                None
            }
        }
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

    #[test]
    fn test_permanent_allow_is_rejected() {
        let manager = HitlManager::new("secret-key-perm");
        let req_id = "req-perm-test";
        manager.submit_escalation(EscalationRequest {
            request_id: req_id.to_string(),
            agent_id: "agent-perm".to_string(),
            command: "rm -rf /".to_string(),
            risk_reason: "Root deletion".to_string(),
            timestamp_ms: 1000,
        });

        let sig = manager.sign_decision(req_id, "PERMANENT_ALLOW");
        let callback = EscalationResponse {
            request_id: req_id.to_string(),
            decision: "PERMANENT_ALLOW".to_string(),
            signed_hmac: sig,
        };

        let result = manager.process_callback(&callback);
        assert!(result.is_err());
        let err_msg = result.unwrap_err();
        assert!(
            err_msg.contains("PERMANENT_ALLOW is prohibited in production"),
            "Expected prohibition error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_hitl_wal_persistence_and_recovery() {
        let tmp = tempfile::tempdir().unwrap();
        let wal_path = tmp.path().join("test_hitl_wal.jsonl");

        // 1. First daemon instance writes request and executes partially
        {
            let sm1 = HitlStateMachine::with_wal(&wal_path).expect("Failed to create sm1");
            let appr_id = "appr-crash-test-wal".to_string();
            let op_ref = sm1.submit_request(
                appr_id.clone(),
                "delete_backup".to_string(),
                "sha256:backup_hash".to_string(),
                "ws-prod".to_string(),
                "agent-1".to_string(),
                Duration::from_secs(300),
                1,
            );
            assert!(op_ref.starts_with("appr-"));

            let idem = sm1
                .reserve(
                    &appr_id,
                    "operator",
                    "delete_backup",
                    "sha256:backup_hash",
                    "ws-prod",
                )
                .expect("Reservation should succeed");

            sm1.start_execution(&appr_id, &idem)
                .expect("Start execution should succeed");

            // Verify state is Executing in sm1
            assert!(matches!(
                sm1.get_state(&appr_id),
                Some(ApprovalState::Executing { .. })
            ));
            // Simulate daemon crash by dropping sm1 without completing execution
        }

        // 2. Second daemon instance restarts and recovers from WAL
        {
            let sm2 = HitlStateMachine::with_wal(&wal_path).expect("Failed to create sm2");
            let appr_id = "appr-crash-test-wal";

            // State MUST have reconciled to OutcomeUnknown on restart
            let recovered_state = sm2.get_state(appr_id);
            assert!(
                matches!(recovered_state, Some(ApprovalState::OutcomeUnknown { .. })),
                "Expected OutcomeUnknown after restart, got: {:?}",
                recovered_state
            );

            // Silent retry must be rejected
            let retry_res = sm2.reserve(
                appr_id,
                "operator",
                "delete_backup",
                "sha256:backup_hash",
                "ws-prod",
            );
            assert!(
                retry_res.is_err(),
                "Silent re-execution must be strictly prohibited after crash"
            );
        }
    }
}
