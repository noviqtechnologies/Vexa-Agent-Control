//! JSON-RPC dispatch and method routing (FR-101)
//!
//! ## v6.1 Changes
//!
//! - Prometheus-compatible atomic counters added to `ProxyState` (Guidance #9).
//!   Exposed via `GET /metrics` on the gateway's listen address.
//! - `KillMode::Process` / `KillMode::Both` removed from the kill path (Guidance #2).

use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use super::db::DbManager;
use crate::audit::logger::AuditLogger;
use crate::kill::KillMode;
use crate::logging::{self, Level};
use crate::policy::engine::{CompiledPolicy, EvalResult};
use crate::policy::schema::CycleAction;

/// FR-306: A fingerprint of a tool call for cycle detection.
/// Stores the tool name and a hash of the canonicalized arguments.
#[derive(Clone, Debug)]
pub struct ToolCallFingerprint {
    pub tool_name: String,
    pub args_hash: u64,
    pub raw_args: serde_json::Value,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl PartialEq for ToolCallFingerprint {
    fn eq(&self, other: &Self) -> bool {
        self.tool_name == other.tool_name && self.args_hash == other.args_hash
    }
}
impl Eq for ToolCallFingerprint {}

impl ToolCallFingerprint {
    pub fn new(tool_name: &str, args: &Value) -> Self {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        // Canonicalize: serialize to sorted JSON string for deterministic comparison.
        let canonical = canonical_json(args);
        let mut hasher = DefaultHasher::new();
        canonical.hash(&mut hasher);
        Self {
            tool_name: tool_name.to_string(),
            args_hash: hasher.finish(),
            raw_args: args.clone(),
            timestamp: chrono::Utc::now(),
        }
    }
}

/// Produce a canonical JSON string with sorted object keys for deterministic hashing.
fn canonical_json(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let entries: Vec<String> = keys
                .iter()
                .map(|k| format!("{:?}:{}", k, canonical_json(&map[*k])))
                .collect();
            format!("{{{}}}", entries.join(","))
        }
        Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(canonical_json).collect();
            format!("[{}]", items.join(","))
        }
        _ => value.to_string(),
    }
}

/// Shared proxy state
pub struct ProxyState {
    pub policy: std::sync::RwLock<Option<CompiledPolicy>>,
    pub audit_logger: Arc<AuditLogger>,
    pub session_id: String,
    pub kill_mode: KillMode,
    pub agent_pid: Option<u32>,
    pub upstream_url: String,
    pub dry_run: bool,
    pub shadow_mode: std::sync::atomic::AtomicBool,
    /// FR-113: Whether a policy file was successfully loaded
    pub policy_loaded: std::sync::atomic::AtomicBool,
    pub rate_limiter: RateLimiter,
    pub http_client: reqwest::Client,
    pub safe_mode_scanner: Arc<crate::policy::safe_mode::SafeModeScanner>,
    pub ready: bool,
    pub db_manager: Arc<DbManager>,
    /// FR-303b: Response scanner for secret detection
    pub response_scanner: Arc<crate::policy::response_scanner::ResponseScanner>,
    /// FR-303b: Response scan configuration
    pub response_scan_config:
        std::sync::RwLock<crate::policy::response_scanner::ResponseScanConfig>,
    /// FR-12: Content-Aware DLP & Secret Detection on outbound requests
    pub dlp_scanner: Arc<crate::policy::dlp::DlpScanner>,
    /// FR-12B: Semantic anomaly scanner (Phi-4-Mini heuristic stub)
    pub semantic_scanner: Arc<crate::policy::semantic::SemanticScanner>,
    /// FR-13: Injection & Poisoning Detector
    pub injection_scanner: Arc<crate::policy::injection::InjectionScanner>,
    /// FR-601: Cross-session MCP Schema-Drift Detector
    pub schema_drift_detector: Arc<crate::policy::schema_drift::SchemaDriftDetector>,
    /// FR-306: Sliding window of recent tool call fingerprints (bounded to 5).
    pub tool_history: std::sync::Mutex<Vec<ToolCallFingerprint>>,

    /// FR-3: SSE broadcast channel for real-time dashboard streaming
    pub event_tx: tokio::sync::broadcast::Sender<String>,
    pub spend_ledger: Option<Arc<crate::spend::SpendLedger>>,
    pub pricing_table: Option<Arc<crate::spend::PricingTable>>,

    /// Dynamic sessions registry mapping validated client tokens/identities to isolated session contexts (FR-101)
    pub sessions: dashmap::DashMap<String, Arc<super::session::SessionContext>>,

    // ── Guidance #9: Prometheus-compatible atomic counters ─────────────────
    /// Total tool call requests evaluated (tools/call only).
    pub metrics_requests_total: Arc<AtomicU64>,
    /// Total tool calls that resulted in ALLOW.
    pub metrics_allow_total: Arc<AtomicU64>,
    /// Total tool calls that resulted in DENY (policy violation, safe mode, etc.).
    pub metrics_deny_total: Arc<AtomicU64>,
    /// Total requests dropped by the rate limiter.
    pub metrics_rate_limited_total: Arc<AtomicU64>,
    /// Total tool calls blocked by the agent firewall (cycle detection).
    pub metrics_firewall_cycle_total: Arc<AtomicU64>,

    // ── FR-104: SIEM export counters ─────────────────────────────────────
    /// Total audit entries successfully exported to the SIEM backend.
    pub metrics_siem_export_total: Arc<AtomicU64>,
    /// Total audit entries that failed SIEM export (fell back to local disk).
    pub metrics_siem_export_failed_total: Arc<AtomicU64>,

    // ── FR-5 v2.0: Centralized Enforcement Gateway fields ────────────────
    /// Credential scope stub validator (FR-5.5.5 / AC-5.8).
    /// Strict mode (--strict-credential-scope) upgrades mismatches from WARN → DENY.
    pub credential_scope_validator: Arc<crate::policy::credential_scope::CredentialScopeValidator>,
    /// Policy file path for hot-reload via POST /reload (FR-5 v2.0).
    pub policy_path: Option<String>,
    /// Gateway process start time for uptime reporting via GET /gateway/status.
    pub gateway_start_time: std::time::Instant,

    /// FR-23: Optional client for sending redacted events to the SaaS dashboard-api.
    pub dashboard_client: Option<Arc<crate::control_plane_client::client::DashboardClient>>,

    /// Whether the listen address is loopback-only (127.0.0.1 / ::1).
    pub listen_is_loopback: bool,
    /// Shared secret for authenticating dashboard-api→gateway policy read requests.
    pub policy_read_secret: Option<String>,

    /// FR-1 centralized mode: if true, Gateway acts as a fleet proxy for multiple agents/users.
    pub centralized_mode: bool,
    /// FR-1 centralized mode: Provider API keys distributed from Hub, securely held in memory.
    pub provider_keys: dashmap::DashMap<String, String>,
}

pub struct RateLimiter {
    pub max_per_second: u32,
    tokens: std::sync::Mutex<f64>,
    last_updated: std::sync::Mutex<Instant>,
}

impl RateLimiter {
    pub fn new(max_per_second: u32) -> Self {
        Self {
            max_per_second,
            tokens: std::sync::Mutex::new(max_per_second as f64),
            last_updated: std::sync::Mutex::new(Instant::now()),
        }
    }

    pub fn acquire(&self) -> bool {
        if self.max_per_second == 0 {
            return true;
        }

        let now = Instant::now();
        let mut last_updated = self.last_updated.lock().unwrap_or_else(|e| e.into_inner());
        let mut tokens = self.tokens.lock().unwrap_or_else(|e| e.into_inner());

        let elapsed_sec = now.duration_since(*last_updated).as_secs_f64();
        *tokens =
            (*tokens + elapsed_sec * self.max_per_second as f64).min(self.max_per_second as f64);
        *last_updated = now;

        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// JSON-RPC error codes
const JSONRPC_METHOD_NOT_FOUND: i64 = -32601;
const JSONRPC_POLICY_VIOLATION: i64 = -32001;
/// FR-306: Custom error code for firewall cycle detection.
const JSONRPC_FIREWALL_CYCLE: i64 = -32010;

/// FR-306: Minimum entries in the tool call history sliding window.
/// The effective cap is max(TOOL_HISTORY_MIN, max_attempts) — computed per evaluation
/// so policies with max_attempts > 5 are never silently broken (Fix 2).
const TOOL_HISTORY_MIN: usize = 5;

pub enum ProxyAction {
    Forward,
    Respond(Value),
    RespondWithStatus(hyper::StatusCode, Value),
    KillAndRespond(Value),
    KillAndRespondWithStatus(hyper::StatusCode, Value),
}

/// Handle an incoming JSON-RPC request body to determine the proxy action.
/// Returns a `ProxyAction`. Evaluates against the dynamic, isolated `SessionContext`.
pub async fn evaluate_jsonrpc(
    state: &ProxyState,
    session: &Arc<super::session::SessionContext>,
    body: &Value,
) -> ProxyAction {
    let id = body.get("id").cloned().unwrap_or(Value::Null);
    let method = body.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let params = body.get("params").cloned().unwrap_or(Value::Null);

    // Whitelist standard MCP lifecycle and discovery methods (FR-304)
    if method == "initialize"
        || method == "notifications/initialized"
        || method == "ping"
        || method == "tools/list"
        || method.starts_with("notifications/")
        || method.starts_with("resources/")
        || method.starts_with("prompts/")
    {
        // Transparent proxy — no policy evaluation for lifecycle and discovery
        return ProxyAction::Forward;
    }

    if method != "tools/call" {
        // Unknown method — reject and log as DENY
        let _ = state
            .audit_logger
            .write_entry(
                &session.session_id,
                "tool_deny",
                method,
                None,
                Some("unknown_method".to_string()),
                None,
                session.identity_sub.clone(),
                session.identity_email.clone(),
                None,
                session.request_ip.clone(),
                None,
            )
            .await;
        logging::log_event(
            Level::Warn,
            "tool_deny",
            json!({"tool": method, "session": &session.session_id, "reason": "unknown_method", "sub": &session.identity_sub}),
        );
        return ProxyAction::Respond(make_error(
            &id,
            JSONRPC_METHOD_NOT_FOUND,
            "Method not found",
        ));
    }

    // tools/call — extract tool name and arguments
    let tool_name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
    let mut tool_params = params.get("arguments").cloned().unwrap_or(Value::Null);

    // Rate limit check (FR-107) — strictly isolated per session
    if !session.rate_limiter.acquire() {
        state.metrics_requests_total.fetch_add(1, Ordering::Relaxed);
        state
            .metrics_rate_limited_total
            .fetch_add(1, Ordering::Relaxed);
        let _ = state
            .audit_logger
            .write_entry(
                &session.session_id,
                "rate_limited",
                tool_name,
                None,
                None,
                None,
                session.identity_sub.clone(),
                session.identity_email.clone(),
                None,
                session.request_ip.clone(),
                None,
            )
            .await;
        logging::log_event(
            Level::Warn,
            "rate_limited",
            json!({
                "tool": tool_name,
                "session": &session.session_id,
                "limit_per_sec": session.rate_limiter.max_per_second,
                "sub": &session.identity_sub,
            }),
        );
        return ProxyAction::Respond(json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32029,
                "message": "Rate limit exceeded",
                "data": {
                    "session_id": &session.session_id,
                    "limit_per_sec": session.rate_limiter.max_per_second
                }
            }
        }));
    }

    // Increment total requests counter after rate limit pass
    state.metrics_requests_total.fetch_add(1, Ordering::Relaxed);

    // FR-306: Cycle Detection (Agent Firewall) — must run before policy/DLP so it
    // can intercept loops even for tools not yet in the allow-list.
    // Strictly isolated per session via session.tool_history.
    let cycle_action_to_take = {
        let firewall_cfg = session.policy.as_ref().and_then(|p| p.firewall.as_ref());
        let effective_cfg = firewall_cfg.cloned().unwrap_or_default();

        if effective_cfg.enabled {
            let fingerprint = ToolCallFingerprint::new(tool_name, &tool_params);
            let mut history = session
                .tool_history
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let max_attempts = effective_cfg.cycle_detection.max_attempts as usize;

            // Dynamic window cap — always at least as large as max_attempts.
            let effective_window = max_attempts.max(TOOL_HISTORY_MIN);

            // Append and bound the window
            history.push(fingerprint.clone());
            let len = history.len();
            if len > effective_window {
                history.drain(..len - effective_window);
            }

            if max_attempts > 0 && history.len() >= max_attempts {
                let tail = &history[history.len() - max_attempts..];
                let all_identical = tail.iter().all(|f| *f == fingerprint);

                if all_identical {
                    // Clear history so agent gets a fresh start on developer override
                    history.clear();
                    state
                        .metrics_firewall_cycle_total
                        .fetch_add(1, Ordering::Relaxed);
                    Some((effective_cfg.cycle_detection.action, max_attempts))
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    };

    if let Some((action, max_attempts)) = cycle_action_to_take {
        // Cycle detected — always write to the durable audit log.
        let _ = state
            .audit_logger
            .write_entry(
                &session.session_id,
                "firewall_cycle_block",
                tool_name,
                None,
                Some(format!(
                    "cycle_detected: {} consecutive identical calls (max_attempts={})",
                    max_attempts, max_attempts
                )),
                None,
                session.identity_sub.clone(),
                session.identity_email.clone(),
                None,
                session.request_ip.clone(),
                None,
            )
            .await;
        // P2-c fix: Only emit the firewall_cycle_block event to stderr for actions that need
        // immediate operator attention (Block / PauseInteractive). PivotError returns a graceful
        // JSON-RPC error to the client and is recorded in audit.jsonl — printing a raw JSON line
        // to the terminal on every cycle-detected pivot creates confusing startup noise.
        if !matches!(action, CycleAction::PivotError) {
            logging::log_event(
                Level::Warn,
                "firewall_cycle_block",
                json!({
                    "tool": tool_name,
                    "session": &session.session_id,
                    "consecutive_calls": max_attempts,
                    "action": match action {
                        CycleAction::PivotError => "pivot_error",
                        CycleAction::Block => "block",
                        CycleAction::PauseInteractive => "pause_interactive",
                    }
                }),
            );
        }

        match action {
            CycleAction::PivotError => {
                return ProxyAction::Respond(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": JSONRPC_FIREWALL_CYCLE,
                        "message": format!(
                            "AgentWall: Cycle detected — tool '{}' called {} times with identical arguments. Try a different approach.",
                            tool_name, max_attempts
                        ),
                        "data": {
                            "session_id": &session.session_id,
                            "tool": tool_name,
                            "cycle_length": max_attempts
                        }
                    }
                }));
            }
            CycleAction::Block => {
                return handle_deny(
                    state,
                    &session.session_id,
                    &id,
                    tool_name,
                    &format!(
                        "firewall_cycle_block: {} consecutive identical calls",
                        max_attempts
                    ),
                    session.identity_sub.clone(),
                    session.identity_email.clone(),
                    session.request_ip.clone(),
                    false,
                    None,
                    None,
                    None,
                )
                .await;
            }
            CycleAction::PauseInteractive => {
                let user_allowed = try_interactive_pause(tool_name, max_attempts);
                if user_allowed {
                    let _ = state
                        .audit_logger
                        .write_entry(
                            &session.session_id,
                            "firewall_cycle_override",
                            tool_name,
                            None,
                            Some("developer_override".to_string()),
                            None,
                            session.identity_sub.clone(),
                            session.identity_email.clone(),
                            None,
                            session.request_ip.clone(),
                            None,
                        )
                        .await;
                    logging::log_event(
                        Level::Warn,
                        "firewall_cycle_override",
                        json!({
                            "tool": tool_name,
                            "session": &session.session_id
                        }),
                    );
                    // Fall through to normal evaluation
                } else {
                    return handle_deny(
                        state, &session.session_id, &id, tool_name,
                        &format!("firewall_cycle_block: {} consecutive identical calls (interactive_denied)", max_attempts),
                        session.identity_sub.clone(), session.identity_email.clone(),
                        session.request_ip.clone(),
                        false, None, None, None,
                    ).await;
                }
            }
        }
    }

    // FR-12: Content-Aware DLP & Secret Detection on outbound tool call parameters
    let params_str = tool_params.to_string();
    let dlp_findings = state.dlp_scanner.scan_content(&params_str);
    if !dlp_findings.is_empty() {
        if state.shadow_mode.load(Ordering::Relaxed) {
            logging::log_event(
                Level::Warn,
                "dlp_finding",
                json!({
                    "tool": tool_name,
                    "session": &session.session_id,
                    "findings": dlp_findings.iter().map(|f| format!("{}: {}", f.category.as_str(), f.preview)).collect::<Vec<_>>()
                }),
            );
        } else {
            // Evaluate ladder actions per finding
            let actions: Vec<crate::policy::dlp::DlpAction> = dlp_findings
                .iter()
                .map(|f| state.dlp_scanner.resolve_action(f, session.policy.as_ref()))
                .collect();

            if actions.contains(&crate::policy::dlp::DlpAction::Block) {
                let block_finding = dlp_findings
                    .iter()
                    .zip(&actions)
                    .find(|(_, a)| **a == crate::policy::dlp::DlpAction::Block)
                    .map(|(f, _)| f)
                    .unwrap_or(&dlp_findings[0]);

                return handle_deny(
                    state,
                    &session.session_id,
                    &id,
                    tool_name,
                    &format!("dlp: {}", block_finding.pattern_name),
                    session.identity_sub.clone(),
                    session.identity_email.clone(),
                    session.request_ip.clone(),
                    true,
                    None,
                    None,
                    None,
                )
                .await;
            } else if actions.contains(&crate::policy::dlp::DlpAction::Redact) {
                state.dlp_scanner.redact_value(&mut tool_params);
                let _ = state
                    .audit_logger
                    .write_entry(
                        &session.session_id,
                        "dlp_request_redacted",
                        tool_name,
                        None,
                        Some(format!("Redacted {} secret(s)", dlp_findings.len())),
                        None,
                        session.identity_sub.clone(),
                        session.identity_email.clone(),
                        None,
                        session.request_ip.clone(),
                        None,
                    )
                    .await;
                logging::log_event(
                    Level::Warn,
                    "dlp_request_redacted",
                    json!({
                        "tool": tool_name,
                        "session": &session.session_id,
                        "count": dlp_findings.len(),
                    }),
                );
            } else {
                // All actions are Warn
                let _ = state
                    .audit_logger
                    .write_entry(
                        &session.session_id,
                        "dlp_request_warn",
                        tool_name,
                        None,
                        Some(format!("DLP match: {}", dlp_findings[0].pattern_name)),
                        None,
                        session.identity_sub.clone(),
                        session.identity_email.clone(),
                        None,
                        session.request_ip.clone(),
                        None,
                    )
                    .await;
                logging::log_event(
                    Level::Warn,
                    "dlp_request_warn",
                    json!({
                        "tool": tool_name,
                        "session": &session.session_id,
                        "finding": dlp_findings[0].pattern_name,
                    }),
                );
            }
        }
    }

    // FR-13: Prompt Injection Scanning on outbound tool call parameters
    let enforce_mode = !state.shadow_mode.load(Ordering::Relaxed);
    let inj_scan_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        state
            .injection_scanner
            .scan_response(&tool_params, tool_name, &session.session_id, enforce_mode)
    }));

    match inj_scan_result {
        Ok(crate::policy::injection::ScanResult::Block { findings }) => {
            let f = &findings[0];
            let _ = state
                .audit_logger
                .write_entry(
                    &session.session_id,
                    "injection_blocked",
                    tool_name,
                    None,
                    Some(format!("pattern={} preview={}", f.pattern_name, f.preview)),
                    None,
                    session.identity_sub.clone(),
                    session.identity_email.clone(),
                    None,
                    session.request_ip.clone(),
                    None,
                )
                .await;
            logging::log_event(
                Level::Warn,
                "injection_blocked",
                json!({
                    "tool": tool_name,
                    "session": &session.session_id,
                    "pattern": &f.pattern_name
                }),
            );

            return handle_deny(
                state,
                &session.session_id,
                &id,
                tool_name,
                &format!("injection: {}", f.pattern_name),
                session.identity_sub.clone(),
                session.identity_email.clone(),
                session.request_ip.clone(),
                true,
                None,
                None,
                None,
            )
            .await;
        }
        Ok(crate::policy::injection::ScanResult::Warn { findings }) => {
            let f = &findings[0];
            let _ = state
                .audit_logger
                .write_entry(
                    &session.session_id,
                    "injection_warning",
                    tool_name,
                    None,
                    Some(format!("pattern={} preview={}", f.pattern_name, f.preview)),
                    None,
                    session.identity_sub.clone(),
                    session.identity_email.clone(),
                    None,
                    session.request_ip.clone(),
                    None,
                )
                .await;
            logging::log_event(
                Level::Warn,
                "injection_warning",
                json!({
                    "tool": tool_name,
                    "session": &session.session_id,
                    "pattern": &f.pattern_name
                }),
            );
        }
        _ => {}
    }

    // FR-12B: Semantic Scanner (Phi-4-Mini Heuristic Stub)
    if state.semantic_scanner.config.enabled {
        let tool_name_clone = tool_name.to_string();
        let session_id_clone = session.session_id.clone();
        let semantic_scanner = state.semantic_scanner.clone();
        let db_manager = state.db_manager.clone();
        let shadow_mode = state.shadow_mode.load(Ordering::Relaxed);

        // Fire and forget async evaluation
        tokio::spawn(async move {
            let finding = semantic_scanner.calculate_score_sync(&tool_name_clone, &params_str);
            let timestamp_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);

            // Write to DB
            db_manager.update_anomaly_score(
                session_id_clone.clone(),
                timestamp_ns,
                finding.anomaly_score as f64,
            );

            if finding.anomaly_score >= semantic_scanner.config.threshold {
                logging::log_event(
                    Level::Warn,
                    "semantic_anomaly",
                    json!({
                        "tool": tool_name_clone,
                        "session": &session_id_clone,
                        "score": finding.anomaly_score,
                        "type": finding.finding_type.as_str(),
                        "explanation": finding.explanation,
                        "shadow_mode": shadow_mode
                    }),
                );
            }
        });

        // Note: For full enforce mode, we could await the score here and block.
        // Currently keeping it purely async to avoid adding latency per AC-12.7.
    }

    // ── Step 2: Credential Scope Validation (FR-5 / AC-5.8 / US-103) ─────────────
    // Read credential scope requirements from the per-tool policy rule.
    // Scope header comes from the MCP agent via X-AgentWall-Credential-Scope.
    // In WARN mode (default): mismatches are logged and the call continues.
    // In STRICT mode (--strict-credential-scope): mismatches cause hard DENY.
    if !state.shadow_mode.load(Ordering::Relaxed) {
        let required_scopes: Vec<String> = {
            let policy_guard = state.policy.read().unwrap_or_else(|e| e.into_inner());
            policy_guard
                .as_ref()
                .and_then(|p| p.tools.iter().find(|t| t.name == tool_name))
                .map(|t| t.credential_scope.clone())
                .unwrap_or_default()
        };

        if !required_scopes.is_empty() {
            let scope_check = state.credential_scope_validator.validate(
                tool_name,
                &required_scopes,
                session.agent_scope_header.as_deref(),
                &session.session_id,
            );

            if let crate::policy::credential_scope::CredentialScopeResult::Insufficient { reason } =
                scope_check
            {
                let reason_str = reason.clone();
                state.metrics_deny_total.fetch_add(1, Ordering::Relaxed);
                let _ = state
                    .audit_logger
                    .write_entry(
                        &session.session_id,
                        "credential_scope_deny",
                        tool_name,
                        None,
                        Some(reason_str.clone()),
                        None,
                        session.identity_sub.clone(),
                        session.identity_email.clone(),
                        None,
                        session.request_ip.clone(),
                        None,
                    )
                    .await;
                logging::log_event(
                    Level::Warn,
                    "credential_scope_deny",
                    json!({
                        "tool": tool_name,
                        "session": &session.session_id,
                        "reason": &reason_str,
                    }),
                );
                return ProxyAction::Respond(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32403,
                        "message": format!("Credential Scope Insufficient: {}", reason_str),
                        "data": {
                            "session_id": &session.session_id,
                            "tool": tool_name,
                            "required_scopes": required_scopes,
                        }
                    }
                }));
            }

            if let Some(credential_id) = session.active_credential_id.as_deref() {
                let agent_id = session.identity_sub.as_deref().unwrap_or("unknown-agent");
                let scope_result =
                    crate::identity::scope_validator::IdentityScopeValidator::validate(
                        agent_id,
                        tool_name,
                        credential_id,
                    );

                if let crate::identity::scope_validator::CredentialScopeCheckResult::Insufficient(reason) = &scope_result {
                    let reason_str = reason.clone();
                    state.metrics_deny_total.fetch_add(1, Ordering::Relaxed);
                    let _ = state.audit_logger.write_entry(
                        &session.session_id,
                        "credential_scope_deny",
                        tool_name,
                        None,
                        Some(reason_str.clone()),
                        None,
                        session.identity_sub.clone(),
                        session.identity_email.clone(),
                        None,
                        session.request_ip.clone(),
                        None,
                    ).await;
                    logging::log_event(
                        Level::Warn,
                        "credential_scope_deny",
                        json!({
                            "tool": tool_name,
                            "session": &session.session_id,
                            "reason": &reason_str,
                        }),
                    );
                    return ProxyAction::Respond(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32403,
                            "message": format!("Credential Scope Insufficient: {}", reason_str),
                            "data": {
                                "session_id": &session.session_id,
                                "tool": tool_name,
                                "required_scopes": required_scopes,
                            }
                        }
                    }));
                } else if let crate::identity::scope_validator::CredentialScopeCheckResult::Invalid(reason) = &scope_result {
                    let reason_str = reason.clone();
                    state.metrics_deny_total.fetch_add(1, Ordering::Relaxed);
                    let _ = state.audit_logger.write_entry(
                        &session.session_id,
                        "credential_invalid",
                        tool_name,
                        None,
                        Some(reason_str.clone()),
                        None,
                        session.identity_sub.clone(),
                        session.identity_email.clone(),
                        None,
                        session.request_ip.clone(),
                        None,
                    ).await;
                    logging::log_event(
                        Level::Warn,
                        "credential_invalid",
                        json!({
                            "tool": tool_name,
                            "session": &session.session_id,
                            "reason": &reason_str,
                        }),
                    );
                    return ProxyAction::Respond(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32401,
                            "message": format!("Invalid Credential: {}", reason_str),
                            "data": {
                                "session_id": &session.session_id,
                                "tool": tool_name,
                            }
                        }
                    }));
                } else if let crate::identity::scope_validator::CredentialScopeCheckResult::Expired = &scope_result {
                    state.metrics_deny_total.fetch_add(1, Ordering::Relaxed);
                    let _ = state.audit_logger.write_entry(
                        &session.session_id,
                        "credential_expired",
                        tool_name,
                        None,
                        Some("credential expired".to_string()),
                        None,
                        session.identity_sub.clone(),
                        session.identity_email.clone(),
                        None,
                        session.request_ip.clone(),
                        None,
                    ).await;
                    logging::log_event(
                        Level::Warn,
                        "credential_expired",
                        json!({
                            "tool": tool_name,
                            "session": &session.session_id,
                            "credential_id": credential_id,
                        }),
                    );
                    return ProxyAction::Respond(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32401,
                            "message": "Credential Expired",
                            "data": {
                                "session_id": &session.session_id,
                                "tool": tool_name,
                            }
                        }
                    }));
                }
            }
        }
    }

    // ── Step 2.5: Spend Cap & Token Limit Enforcement (FR-102 / US-101) ─────
    if let Some(spend_caps) = session.policy.as_ref().and_then(|p| p.spend_caps.as_ref()) {
        if spend_caps.enabled {
            let is_licensed =
                crate::license::validator::is_license_valid(spend_caps.license_key.as_deref());

            // 1. Session token budget check
            if let Some(max_tokens) = spend_caps.max_tokens_per_session {
                let used = session
                    .tokens_used
                    .load(std::sync::atomic::Ordering::Relaxed);
                if used >= max_tokens {
                    if is_licensed {
                        state.metrics_deny_total.fetch_add(1, Ordering::Relaxed);
                        let _ = state
                            .audit_logger
                            .write_entry(
                                &session.session_id,
                                "spend_cap_exceeded",
                                tool_name,
                                None,
                                Some(format!(
                                    "session token budget exhausted: used={} max={}",
                                    used, max_tokens
                                )),
                                None,
                                session.identity_sub.clone(),
                                session.identity_email.clone(),
                                None,
                                session.request_ip.clone(),
                                None,
                            )
                            .await;
                        logging::log_event(
                            Level::Warn,
                            "spend_cap_exceeded",
                            json!({
                                "tool": tool_name,
                                "session": &session.session_id,
                                "used_tokens": used,
                                "max_tokens": max_tokens,
                            }),
                        );
                        return ProxyAction::Respond(json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "error": {
                                "code": -32029,
                                "message": format!("Token spend cap exceeded for session: {} tokens used (max: {})", used, max_tokens),
                                "data": {
                                    "session_id": &session.session_id,
                                    "used_tokens": used,
                                    "max_tokens": max_tokens,
                                }
                            }
                        }));
                    } else {
                        // Unlicensed: record usage without blocking (US-101 AC-2)
                        logging::log_event(
                            Level::Info,
                            "spend_cap_exceeded_unlicensed",
                            json!({
                                "tool": tool_name,
                                "session": &session.session_id,
                                "used_tokens": used,
                                "max_tokens": max_tokens,
                                "note": "License absent — usage recorded without enforcement",
                            }),
                        );
                    }
                }
            }

            // 2. Spend Ledger check (if initialized)
            if let Some(ledger) = &state.spend_ledger {
                let agent_id = session
                    .identity_sub
                    .clone()
                    .unwrap_or_else(|| session.session_id.clone());
                let res = ledger
                    .check_and_increment(agent_id, session.identity_groups.clone(), 0)
                    .await;
                if let crate::spend::SpendCheckResult::BudgetExhausted {
                    cap_cents,
                    spent_cents,
                } = res
                {
                    if is_licensed {
                        state.metrics_deny_total.fetch_add(1, Ordering::Relaxed);
                        return ProxyAction::Respond(json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "error": {
                                "code": -32029,
                                "message": format!("Spend limit exceeded: {} cents spent (cap: {} cents)", spent_cents, cap_cents),
                                "data": {
                                    "session_id": &session.session_id,
                                    "spent_cents": spent_cents,
                                    "cap_cents": cap_cents,
                                }
                            }
                        }));
                    }
                }
            }
        }
    }

    // ADR: Sequence rule evaluation against sliding window tracker
    if let Some(ref policy) = session.policy {
        let tracker = session
            .sliding_window
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let seq_eval = policy.evaluate_sequence(tool_name, &tool_params, &tracker);
        if let EvalResult::Deny { validator_name, .. } = seq_eval {
            state.metrics_deny_total.fetch_add(1, Ordering::Relaxed);
            let rule_desc = validator_name.unwrap_or_else(|| "Sequence rule block".to_string());
            return ProxyAction::Respond(make_error(
                &id,
                -32600,
                &format!("Multi-step security violation: {}", rule_desc),
            ));
        }
    }

    // Push fingerprint into sliding window tracker for multi-step sequence evaluation
    {
        let mut tracker = session
            .sliding_window
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        tracker.push(ToolCallFingerprint::new(tool_name, &tool_params));
    }

    // Safe Mode Evaluation (FR-303a) — tool-aware scanning
    let safe_mode_threat = state.safe_mode_scanner.scan_tool(tool_name, &tool_params);

    // Policy evaluation against frozen session-specific policy context
    let start = Instant::now();
    let eval_result = session.policy.as_ref().map(|policy| {
        policy.evaluate(
            tool_name,
            &tool_params,
            session.identity_sub.as_deref(),
            &session.identity_groups,
        )
    });
    let eval_ms = start.elapsed().as_secs_f64() * 1000.0;

    let final_eval = match (eval_result, safe_mode_threat) {
        (Some(EvalResult::Allow { matched_group_id }), Some(threat)) => {
            // Escape Hatch: User policy explicitly allowed this, overriding Safe Mode block.
            logging::log_event(
                Level::Warn,
                "safe_mode_override",
                json!({"tool": tool_name, "session": &session.session_id, "threat": threat.category.as_str(), "reason": "user_policy_override"}),
            );
            EvalResult::Allow { matched_group_id }
        }
        (Some(EvalResult::Allow { matched_group_id }), None) => {
            EvalResult::Allow { matched_group_id }
        }
        (
            Some(EvalResult::Deny {
                matched_group_id, ..
            }),
            Some(threat),
        ) => EvalResult::Deny {
            reason_code: "safe_mode_deny".to_string(),
            param_name: Some(threat.param_name.clone()),
            param_value: None,
            pattern: Some(threat.pattern_name.clone()),
            json_pointer: Some(format!(
                "{} Edit policy: agentwall edit-policy",
                threat.reason
            )),
            validator_name: None,
            matched_group_id,
        },
        (
            Some(EvalResult::Deny {
                reason_code,
                param_name,
                param_value,
                pattern,
                json_pointer,
                validator_name,
                matched_group_id,
            }),
            None,
        ) => EvalResult::Deny {
            reason_code,
            param_name,
            param_value,
            pattern,
            json_pointer,
            validator_name,
            matched_group_id,
        },
        (None, Some(threat)) => EvalResult::Deny {
            reason_code: "safe_mode_deny".to_string(),
            param_name: Some(threat.param_name.clone()),
            param_value: None,
            pattern: Some(threat.pattern_name.clone()),
            json_pointer: Some(format!(
                "{} Edit policy: agentwall edit-policy",
                threat.reason
            )),
            validator_name: None,
            matched_group_id: None,
        },
        (None, None) => {
            if !state.policy_loaded.load(Ordering::Relaxed) {
                // Out-Of-The-Box Safe Mode: No policy loaded, Safe Mode is clean.
                EvalResult::Allow {
                    matched_group_id: None,
                }
            } else {
                // Policy was loaded but is missing/degraded
                EvalResult::Deny {
                    reason_code: "no_valid_policy_loaded".to_string(),
                    param_name: None,
                    param_value: None,
                    pattern: None,
                    json_pointer: None,
                    validator_name: None,
                    matched_group_id: None,
                }
            }
        }
    };

    // Identity claims were validated during dynamic session creation (OIDC cache)
    let identity_sub = session.identity_sub.clone();
    let identity_email = session.identity_email.clone();

    match final_eval {
        EvalResult::Allow { matched_group_id } => {
            state.metrics_allow_total.fetch_add(1, Ordering::Relaxed);
            // ALLOW path: log → fsync → forward (NFR-204)
            let log_result = state
                .audit_logger
                .write_entry(
                    &session.session_id,
                    "tool_allow",
                    tool_name,
                    Some(tool_params.clone()),
                    None,
                    Some(eval_ms),
                    identity_sub.clone(),
                    identity_email.clone(),
                    None,
                    session.request_ip.clone(),
                    matched_group_id.clone(),
                )
                .await;

            if let Err(e) = log_result {
                // fsync failed — follow DENY path (NFR-204)
                logging::log_event(
                    Level::Error,
                    "log_flush_failed",
                    json!({"reason": e.to_string(), "action": "deny_applied"}),
                );
                return handle_deny(
                    state,
                    &session.session_id,
                    &id,
                    tool_name,
                    "log_flush_failed",
                    identity_sub,
                    identity_email,
                    session.request_ip.clone(),
                    false,
                    None,
                    None,
                    matched_group_id,
                )
                .await;
            }

            logging::log_event(
                Level::Info,
                "tool_allow",
                json!({
                    "tool":      tool_name,
                    "session":   &session.session_id,
                    "latency_ms": eval_ms,
                    "sub":       &identity_sub,
                    "email":     &identity_email,
                    "group":     &matched_group_id,
                }),
            );

            ProxyAction::Forward
        }
        EvalResult::Deny {
            reason_code,
            param_name,
            param_value,
            pattern,
            json_pointer,
            validator_name,
            matched_group_id,
        } => {
            state.metrics_deny_total.fetch_add(1, Ordering::Relaxed);
            let mut reason_parts = vec![format!("reason={}", reason_code)];
            if let Some(n) = &param_name {
                reason_parts.push(format!("param={}", n));
            }
            if let Some(v) = &param_value {
                reason_parts.push(format!("value={}", v));
            }
            if let Some(p) = &pattern {
                reason_parts.push(format!("pattern={}", p));
            }
            if let Some(ptr) = &json_pointer {
                reason_parts.push(format!("pointer={}", ptr));
            }
            if let Some(vn) = &validator_name {
                reason_parts.push(format!("validator={}", vn));
            }
            let reason = reason_parts.join(" ");

            if state.dry_run {
                // DRY_RUN_DENY: log but forward anyway, no kill
                let _ = state
                    .audit_logger
                    .write_entry(
                        &session.session_id,
                        "tool_dry_run_deny",
                        tool_name,
                        None,
                        Some(reason.clone()),
                        None,
                        identity_sub.clone(),
                        identity_email.clone(),
                        None,
                        session.request_ip.clone(),
                        matched_group_id.clone(),
                    )
                    .await;
                logging::log_event(
                    Level::Warn,
                    "tool_dry_run_deny",
                    json!({
                        "tool":    tool_name,
                        "session": &session.session_id,
                        "reason":  &reason,
                        "sub":     &identity_sub,
                        "email":   &identity_email,
                        "group":   &matched_group_id,
                    }),
                );
                ProxyAction::Forward
            } else {
                let is_val_fail = reason_code == "validator_failed";
                handle_deny(
                    state,
                    &session.session_id,
                    &id,
                    tool_name,
                    &reason,
                    identity_sub,
                    identity_email,
                    session.request_ip.clone(),
                    is_val_fail,
                    param_name,
                    validator_name,
                    matched_group_id,
                )
                .await
            }
        }
    }
}

/// Handle the DENY path: write audit entry → send JSON-RPC error → signal kill.
///
/// The audit entry is written and fsync-confirmed before the error response is
/// constructed — satisfying NFR-204 (no forward without a durable log entry).
#[allow(clippy::too_many_arguments)]
async fn handle_deny(
    state: &ProxyState,
    session_id: &str,
    id: &Value,
    tool_name: &str,
    reason: &str,
    identity_sub: Option<String>,
    identity_email: Option<String>,
    request_ip: Option<String>,
    is_validator_fail: bool,
    failing_param: Option<String>,
    failing_validator: Option<String>,
    matched_group_id: Option<String>,
) -> ProxyAction {
    let log_result = state
        .audit_logger
        .write_entry(
            session_id,
            "tool_deny",
            tool_name,
            None,
            Some(reason.to_string()),
            None,
            identity_sub.clone(),
            identity_email.clone(),
            None,
            request_ip.clone(),
            matched_group_id.clone(),
        )
        .await;

    if let Err(e) = log_result {
        logging::log_event(
            Level::Error,
            "log_flush_failed",
            json!({"reason": e.to_string(), "action": "deny_applied"}),
        );
    }

    logging::log_event(
        Level::Warn,
        "tool_deny",
        json!({
            "tool":    tool_name,
            "session": session_id,
            "reason":  reason,
            "sub":     &identity_sub,
            "email":   &identity_email,
        }),
    );

    let rule_id = if reason.to_lowercase().contains("dlp")
        || reason.to_lowercase().contains("secret")
        || reason.to_lowercase().contains("access key")
    {
        "DLP-01-HIGH-ENTROPY"
    } else if reason.to_lowercase().contains("injection")
        || reason.to_lowercase().contains("jailbreak")
        || reason.to_lowercase().contains("override")
    {
        "INJ-04-OVERRIDE"
    } else {
        "tool_deny"
    };

    let error_response = json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": if is_validator_fail { -32003 } else { JSONRPC_POLICY_VIOLATION },
            "message": format!("Policy violation: {}", reason),
            "data": {
                "session_id": session_id,
                "rule": rule_id,
                "parameter":  failing_param,
                "validator":  failing_validator,
                "kill_mode":  state.kill_mode.as_str()
            }
        }
    });

    if is_validator_fail {
        ProxyAction::KillAndRespondWithStatus(hyper::StatusCode::BAD_REQUEST, error_response)
    } else {
        ProxyAction::KillAndRespond(error_response)
    }
}

/// Create a JSON-RPC error response
fn make_error(id: &Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message
        }
    })
}

/// FR-306: Attempt to pause and ask the developer via the system console.
/// Returns true if the user typed 'y' to allow the call through.
/// Returns false if the user denied, or if console I/O is not available (non-TTY).
fn try_interactive_pause(tool_name: &str, consecutive_calls: usize) -> bool {
    use std::io::{BufRead, Write};

    // Do not block when running under cargo tests/CI
    if std::env::var("CARGO_MANIFEST_DIR").is_ok() {
        return false;
    }

    // Try to open the system console directly (not stdin, which may be owned by JSON-RPC).
    #[cfg(target_os = "windows")]
    let console_result = {
        std::fs::OpenOptions::new()
            .read(true)
            .open("CONIN$")
            .and_then(|reader| {
                let mut stderr = std::io::stderr();
                writeln!(
                    stderr,
                    "\n⚠️  AgentWall Firewall: Cycle detected — tool '{}' called {} times with identical arguments.",
                    tool_name, consecutive_calls
                ).ok();
                writeln!(stderr, "   Allow this call? (y/N): ").ok();
                stderr.flush().ok();

                let mut line = String::new();
                let mut buf_reader = std::io::BufReader::new(reader);
                buf_reader.read_line(&mut line)?;
                Ok(line.trim().eq_ignore_ascii_case("y"))
            })
    };

    #[cfg(not(target_os = "windows"))]
    let console_result = {
        std::fs::OpenOptions::new()
            .read(true)
            .open("/dev/tty")
            .and_then(|reader| {
                let mut stderr = std::io::stderr();
                writeln!(
                    stderr,
                    "\n⚠️  AgentWall Firewall: Cycle detected — tool '{}' called {} times with identical arguments.",
                    tool_name, consecutive_calls
                ).ok();
                writeln!(stderr, "   Allow this call? (y/N): ").ok();
                stderr.flush().ok();

                let mut line = String::new();
                let mut buf_reader = std::io::BufReader::new(reader);
                buf_reader.read_line(&mut line)?;
                Ok(line.trim().eq_ignore_ascii_case("y"))
            })
    };

    match console_result {
        Ok(allowed) => allowed,
        Err(_) => {
            // Non-TTY environment — cannot interact. Log warning and fall back to block.
            eprintln!(
                "⚠️  AgentWall: pause_interactive requested but no TTY available. Falling back to block."
            );
            false
        }
    }
}
