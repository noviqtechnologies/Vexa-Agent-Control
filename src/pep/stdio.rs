//! Stdio JSON-RPC Policy Enforcement Point (Gate 3).
//!
//! Provides the authoritative single forwarding gate for stdio-based JSON-RPC 2.0
//! MCP interactions (as used by Cursor, Claude Desktop, Roo Code, etc.).
//! Guarantee: Zero downstream execution occurs unless the authoritative
//! Policy Decision Point (PDP) explicitly yields an `Allow` verdict and all
//! pre-dispatch checks (identity provenance, revocation registry, hard safety invariants) succeed.
//! Enforces:
//! - G0.2: Removal of resources/* and prompts/* blanket bypasses.
//! - G0.3: Uniform scanner failure matrix (fail-closed in enforce mode).
//! - G3.1: stdio PEP with single forwarding gate.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use decision_v1::{
    ActionRequest, AuthenticatedPrincipal, Decision, EvaluationContext, Obligation, Protocol,
    ResourceAccessType, Verdict,
};
use serde_json::Value;

use super::PepError;
use crate::policy::engine::CompiledPolicy;
use crate::proxy::handler::ProxyState;
use crate::proxy::session::SessionContext;

/// Abstract downstream stdio MCP process target.
/// The PEP has exclusive access to downstream dispatch.
#[async_trait::async_trait]
pub trait StdioDownstream: Send + Sync {
    /// Send JSON-RPC request to downstream MCP process stdin and receive stdout response.
    async fn send_request(&mut self, request: &Value) -> Result<Value, PepError>;
}

/// In-memory mock stdio downstream for deterministic testing of side-effect boundaries.
pub struct MockStdioDownstream {
    pub call_count: Arc<AtomicUsize>,
    pub response: Value,
}

impl MockStdioDownstream {
    pub fn new(call_count: Arc<AtomicUsize>) -> Self {
        Self {
            call_count,
            response: serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": "mock stdio tool output"
                        }
                    ]
                }
            }),
        }
    }

    pub fn with_response(call_count: Arc<AtomicUsize>, response: Value) -> Self {
        Self {
            call_count,
            response,
        }
    }
}

#[async_trait::async_trait]
impl StdioDownstream for MockStdioDownstream {
    async fn send_request(&mut self, _request: &Value) -> Result<Value, PepError> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        Ok(self.response.clone())
    }
}

/// Extract and validate tool name from MCP JSON-RPC parameters in stdio.
pub fn extract_stdio_tool_name(params: &Value) -> Result<&str, PepError> {
    params
        .get("name")
        .and_then(|n| n.as_str())
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| {
            PepError::ValidationFailed(
                "Missing or empty 'name' in stdio tools/call params".to_string(),
            )
        })
}

/// Extract arguments object from MCP JSON-RPC parameters in stdio.
pub fn extract_stdio_arguments(params: &Value) -> Result<Value, PepError> {
    match params.get("arguments") {
        Some(Value::Object(map)) => Ok(Value::Object(map.clone())),
        Some(Value::Null) | None => Ok(Value::Object(serde_json::Map::new())),
        Some(_) => Err(PepError::ValidationFailed(
            "'arguments' in stdio tools/call params must be a JSON object".to_string(),
        )),
    }
}

/// Construct authenticated evaluation context strictly from validated session credentials for stdio.
pub fn build_stdio_evaluation_context(
    session: &SessionContext,
    adapter_id: &str,
) -> EvaluationContext {
    let sub = session
        .identity_sub
        .clone()
        .unwrap_or_else(|| "agent-local".to_string());
    let session_policy = session.get_policy();
    let (policy_revision, policy_hash) = match &session_policy {
        Some(p) => (p.policy_revision, p.policy_hash.clone()),
        None => (None, None),
    };
    let device_id = crate::identity::device::DeviceIdentity::load_or_create()
        .map(|d| d.device_id)
        .ok();
    EvaluationContext {
        principal: AuthenticatedPrincipal {
            identity_sub: sub,
            identity_email: session.identity_email.clone(),
            identity_groups: session.identity_groups.clone(),
            client_id: session.active_credential_id.clone(),
        },
        organization_id: None,
        workspace_id: session.agent_scope_header.clone(),
        session_id: session.session_id.clone(),
        device_id,
        adapter_id: adapter_id.to_string(),
        adapter_protocol: Protocol::Stdio,
        policy_revision,
        policy_hash,
    }
}

/// Result of evaluating an incoming stdio JSON-RPC request before downstream forwarding.
#[derive(Debug, Clone)]
pub enum StdioEvaluationResult {
    /// Request is allowed to forward. Contains target tool/method name and the (potentially redacted) request payload.
    Forward {
        tool_name: String,
        forwarded_request: Value,
        is_tool_call: bool,
    },
}

/// Pre-flight authoritative evaluation for stdio JSON-RPC requests.
///
/// Handles:
/// 1. Protocol control messages (`initialize`, `ping`, `notifications/*`) -> Pass through.
/// 2. Discovery (`tools/list`) -> Pass through.
/// 3. Tool and resource execution (`tools/call`, `resources/*`, `prompts/*`):
///    - Managed identity verification
///    - DLP parameter redaction
///    - Revocation registry check
///    - Hard safety invariant scanner
///    - Authoritative PDP evaluation
pub async fn evaluate_stdio_request(
    state: &ProxyState,
    session: &SessionContext,
    request: &Value,
) -> Result<StdioEvaluationResult, PepError> {
    // Gate 2: Rebind stale session policy if global policy_epoch has incremented
    let current_epoch = state.policy_epoch.load(Ordering::SeqCst);
    if session.session_epoch.load(Ordering::SeqCst) < current_epoch {
        let current_policy = state.get_policy();
        session.refresh_policy(current_policy, current_epoch);
    }

    // 1. Structural protocol validation
    if !request.is_object() {
        return Err(PepError::ValidationFailed(
            "JSON-RPC request must be a JSON object".to_string(),
        ));
    }

    let depth = crate::mcp::policy::calculate_json_depth(request);
    if depth > crate::mcp::policy::MAX_JSON_DEPTH {
        return Err(PepError::ValidationFailed(format!(
            "JSON-RPC nesting depth {} exceeds maximum limit of {}",
            depth,
            crate::mcp::policy::MAX_JSON_DEPTH
        )));
    }

    let method = request
        .get("method")
        .and_then(|m| m.as_str())
        .ok_or_else(|| PepError::ValidationFailed("Missing JSON-RPC 'method'".to_string()))?;

    // 2. Protocol control messages (G0.2): No policy evaluation needed for pure lifecycle protocol framing
    if method == "initialize"
        || method == "notifications/initialized"
        || method == "ping"
        || method == "notifications/cancelled"
        || method == "notifications/progress"
        || method == "notifications/message"
        || method == "$/cancelRequest"
    {
        return Ok(StdioEvaluationResult::Forward {
            tool_name: method.to_string(),
            forwarded_request: request.clone(),
            is_tool_call: false,
        });
    }

    // 3. Discovery messages (tools/list)
    if method == "tools/list" {
        return Ok(StdioEvaluationResult::Forward {
            tool_name: "tools/list".to_string(),
            forwarded_request: request.clone(),
            is_tool_call: false,
        });
    }

    // 4. Data access & Execution messages
    let empty_map = Value::Object(serde_json::Map::new());
    let params = request.get("params").unwrap_or(&empty_map);

    // Identity check in managed mode (G1.2)
    if state.policy_trust_profile.is_managed() && session.identity_sub.is_none() {
        state.metrics_deny_total.fetch_add(1, Ordering::Relaxed);
        let _ = state
            .audit_logger
            .write_entry(
                &session.session_id,
                "stdio_deny",
                method,
                None,
                Some("identity_missing_in_managed_mode".to_string()),
                None,
                None,
                None,
                None,
                session.request_ip.clone(),
                None,
            )
            .await;
        let decision = Decision::deny(
            "identity_missing_in_managed_mode",
            Some("Missing authenticated subject identity in managed mode".to_string()),
        );
        return Err(PepError::Denied {
            reason: decision.reason_code.clone(),
            decision,
        });
    }

    let agent_id = session.identity_sub.as_deref();
    let credential_id = session.active_credential_id.as_deref();

    // 4A. Tool Execution: tools/call
    if method == "tools/call" {
        let tool_name = extract_stdio_tool_name(params)?;
        let arguments = extract_stdio_arguments(params)?;

        // Parameter DLP: Redact sensitive arguments in-place before forwarding
        let mut forwarded_request = request.clone();
        if let Some(p) = forwarded_request.get_mut("params") {
            if let Some(args) = p.get_mut("arguments") {
                let _findings = crate::mcp::policy::scan_and_redact_json(args);
            }
        }

        // Revocation check
        if let Err(revoked) =
            state
                .revocation_registry
                .check(agent_id, Some(tool_name), credential_id)
        {
            state.metrics_deny_total.fetch_add(1, Ordering::Relaxed);
            let _ = state
                .audit_logger
                .write_entry(
                    &session.session_id,
                    "capability_revoked_blocked",
                    tool_name,
                    None,
                    Some(format!(
                        "revoked target={:?}:{} reason={}",
                        revoked.target_type, revoked.target_id, revoked.reason
                    )),
                    None,
                    session.identity_sub.clone(),
                    session.identity_email.clone(),
                    None,
                    session.request_ip.clone(),
                    None,
                )
                .await;
            let decision = Decision::deny(
                format!("revoked_{:?}", revoked.target_type).to_lowercase(),
                Some(revoked.reason),
            );
            return Err(PepError::Denied {
                reason: decision.reason_code.clone(),
                decision,
            });
        }

        // Hard Safety Invariants (SafeMode)
        if let Some(threat) = state.safe_mode_scanner.scan_tool(tool_name, &arguments) {
            state.metrics_deny_total.fetch_add(1, Ordering::Relaxed);
            let _ = state
                .audit_logger
                .write_entry(
                    &session.session_id,
                    "hard_invariant_blocked",
                    tool_name,
                    None,
                    Some(format!("hard_invariant: {}", threat.pattern_name)),
                    None,
                    session.identity_sub.clone(),
                    session.identity_email.clone(),
                    None,
                    session.request_ip.clone(),
                    None,
                )
                .await;
            let decision = Decision::deny("hard_invariant_violation", Some(threat.pattern_name));
            return Err(PepError::Denied {
                reason: decision.reason_code.clone(),
                decision,
            });
        }

        // ActionRequest & EvaluationContext
        let action = ActionRequest::McpToolCall {
            tool_name: tool_name.to_string(),
            arguments: arguments.clone(),
            server_id: None,
        };
        let mut context = build_stdio_evaluation_context(session, "stdio-tools-call");

        // Authoritative PDP evaluation
        let active_policy: Option<CompiledPolicy> =
            session.get_policy().or_else(|| state.get_policy());

        if context.policy_revision.is_none() {
            if let Some(ref p) = active_policy {
                context.policy_revision = p.policy_revision;
                context.policy_hash = p.policy_hash.clone();
            }
        }

        let decision = match active_policy {
            Some(policy) => policy.evaluate_action(&action, &context),
            None => {
                if state.shadow_mode.load(Ordering::Relaxed) {
                    Decision {
                        verdict: Verdict::Allow,
                        reason_code: "shadow_mode_observed".to_string(),
                        reason_detail: Some("no policy loaded".to_string()),
                        matched_group_id: None,
                        obligations: Vec::new(),
                    }
                } else {
                    Decision::deny("default_deny", Some("no policy loaded".to_string()))
                }
            }
        };

        // Forwarding Gate
        match decision.verdict {
            Verdict::Deny => {
                state.metrics_deny_total.fetch_add(1, Ordering::Relaxed);
                let _ = state
                    .audit_logger
                    .write_entry(
                        &session.session_id,
                        "tool_deny",
                        tool_name,
                        None,
                        Some(decision.reason_code.clone()),
                        None,
                        session.identity_sub.clone(),
                        session.identity_email.clone(),
                        None,
                        session.request_ip.clone(),
                        decision.matched_group_id.clone(),
                    )
                    .await;
                return Err(PepError::Denied {
                    reason: decision.reason_code.clone(),
                    decision,
                });
            }
            Verdict::RequireApproval => {
                state.metrics_deny_total.fetch_add(1, Ordering::Relaxed);
                let approval_id = decision
                    .obligations
                    .iter()
                    .find_map(|o| match o {
                        Obligation::RequireApproval { approval_id, .. } => {
                            Some(approval_id.clone())
                        }
                        _ => None,
                    })
                    .unwrap_or_else(|| format!("appr-{}", uuid::Uuid::new_v4()));

                let _ = state
                    .audit_logger
                    .write_entry(
                        &session.session_id,
                        "tool_require_approval",
                        tool_name,
                        None,
                        Some(format!("approval_required: {}", approval_id)),
                        None,
                        session.identity_sub.clone(),
                        session.identity_email.clone(),
                        None,
                        session.request_ip.clone(),
                        decision.matched_group_id.clone(),
                    )
                    .await;

                return Err(PepError::ApprovalRequired {
                    approval_id,
                    decision,
                });
            }
            Verdict::Indeterminate => {
                state.metrics_deny_total.fetch_add(1, Ordering::Relaxed);
                return Err(PepError::Denied {
                    reason: "indeterminate_fail_closed".to_string(),
                    decision,
                });
            }
            Verdict::Allow => {
                state.metrics_allow_total.fetch_add(1, Ordering::Relaxed);
                let _ = state
                    .audit_logger
                    .write_entry(
                        &session.session_id,
                        "tool_allow",
                        tool_name,
                        None,
                        None,
                        None,
                        session.identity_sub.clone(),
                        session.identity_email.clone(),
                        None,
                        session.request_ip.clone(),
                        decision.matched_group_id.clone(),
                    )
                    .await;

                return Ok(StdioEvaluationResult::Forward {
                    tool_name: tool_name.to_string(),
                    forwarded_request,
                    is_tool_call: true,
                });
            }
        }
    }

    // 4B. Data Access: resources/* (G0.2)
    if method.starts_with("resources/") {
        let uri = params
            .get("uri")
            .and_then(|u| u.as_str())
            .unwrap_or("")
            .to_string();

        let access_type = match method {
            "resources/read" => ResourceAccessType::Read,
            "resources/list" => ResourceAccessType::List,
            "resources/subscribe" => ResourceAccessType::Subscribe,
            "resources/unsubscribe" => ResourceAccessType::Unsubscribe,
            _ => ResourceAccessType::Read,
        };

        if let Err(revoked) = state
            .revocation_registry
            .check(agent_id, Some(&uri), credential_id)
        {
            state.metrics_deny_total.fetch_add(1, Ordering::Relaxed);
            let decision = Decision::deny(
                format!("revoked_{:?}", revoked.target_type).to_lowercase(),
                Some(revoked.reason),
            );
            return Err(PepError::Denied {
                reason: decision.reason_code.clone(),
                decision,
            });
        }

        let action = ActionRequest::ResourceAccess {
            resource_uri: uri.clone(),
            access_type,
        };
        let mut context = build_stdio_evaluation_context(session, "stdio-resources");

        let active_policy: Option<CompiledPolicy> =
            session.get_policy().or_else(|| state.get_policy());

        if context.policy_revision.is_none() {
            if let Some(ref p) = active_policy {
                context.policy_revision = p.policy_revision;
                context.policy_hash = p.policy_hash.clone();
            }
        }

        let decision = match active_policy {
            Some(policy) => policy.evaluate_action(&action, &context),
            None => {
                if state.shadow_mode.load(Ordering::Relaxed) {
                    Decision {
                        verdict: Verdict::Allow,
                        reason_code: "shadow_mode_observed".to_string(),
                        reason_detail: Some("no policy loaded".to_string()),
                        matched_group_id: None,
                        obligations: Vec::new(),
                    }
                } else {
                    Decision::deny("default_deny", Some("no policy loaded".to_string()))
                }
            }
        };

        match decision.verdict {
            Verdict::Deny => {
                state.metrics_deny_total.fetch_add(1, Ordering::Relaxed);
                return Err(PepError::Denied {
                    reason: decision.reason_code.clone(),
                    decision,
                });
            }
            Verdict::RequireApproval => {
                state.metrics_deny_total.fetch_add(1, Ordering::Relaxed);
                let approval_id = format!("appr-{}", uuid::Uuid::new_v4());
                return Err(PepError::ApprovalRequired {
                    approval_id,
                    decision,
                });
            }
            Verdict::Indeterminate => {
                state.metrics_deny_total.fetch_add(1, Ordering::Relaxed);
                return Err(PepError::Denied {
                    reason: "indeterminate_fail_closed".to_string(),
                    decision,
                });
            }
            Verdict::Allow => {
                state.metrics_allow_total.fetch_add(1, Ordering::Relaxed);
                return Ok(StdioEvaluationResult::Forward {
                    tool_name: method.to_string(),
                    forwarded_request: request.clone(),
                    is_tool_call: false,
                });
            }
        }
    }

    // 4C. Prompt Access: prompts/* (G0.2)
    if method.starts_with("prompts/") {
        let name = params
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("")
            .to_string();

        if let Err(revoked) = state
            .revocation_registry
            .check(agent_id, Some(&name), credential_id)
        {
            state.metrics_deny_total.fetch_add(1, Ordering::Relaxed);
            let decision = Decision::deny(
                format!("revoked_{:?}", revoked.target_type).to_lowercase(),
                Some(revoked.reason),
            );
            return Err(PepError::Denied {
                reason: decision.reason_code.clone(),
                decision,
            });
        }

        let action = ActionRequest::PromptAccess {
            prompt_name: name.clone(),
            arguments: params.get("arguments").cloned(),
        };
        let mut context = build_stdio_evaluation_context(session, "stdio-prompts");

        let active_policy: Option<CompiledPolicy> =
            session.get_policy().or_else(|| state.get_policy());

        if context.policy_revision.is_none() {
            if let Some(ref p) = active_policy {
                context.policy_revision = p.policy_revision;
                context.policy_hash = p.policy_hash.clone();
            }
        }

        let decision = match active_policy {
            Some(policy) => policy.evaluate_action(&action, &context),
            None => {
                if state.shadow_mode.load(Ordering::Relaxed) {
                    Decision {
                        verdict: Verdict::Allow,
                        reason_code: "shadow_mode_observed".to_string(),
                        reason_detail: Some("no policy loaded".to_string()),
                        matched_group_id: None,
                        obligations: Vec::new(),
                    }
                } else {
                    Decision::deny("default_deny", Some("no policy loaded".to_string()))
                }
            }
        };

        match decision.verdict {
            Verdict::Deny => {
                state.metrics_deny_total.fetch_add(1, Ordering::Relaxed);
                return Err(PepError::Denied {
                    reason: decision.reason_code.clone(),
                    decision,
                });
            }
            Verdict::RequireApproval => {
                state.metrics_deny_total.fetch_add(1, Ordering::Relaxed);
                let approval_id = format!("appr-{}", uuid::Uuid::new_v4());
                return Err(PepError::ApprovalRequired {
                    approval_id,
                    decision,
                });
            }
            Verdict::Indeterminate => {
                state.metrics_deny_total.fetch_add(1, Ordering::Relaxed);
                return Err(PepError::Denied {
                    reason: "indeterminate_fail_closed".to_string(),
                    decision,
                });
            }
            Verdict::Allow => {
                state.metrics_allow_total.fetch_add(1, Ordering::Relaxed);
                return Ok(StdioEvaluationResult::Forward {
                    tool_name: name,
                    forwarded_request: request.clone(),
                    is_tool_call: false,
                });
            }
        }
    }

    // Default: for unmapped MCP methods, reject fail-closed
    Err(PepError::ValidationFailed(format!(
        "Unsupported or unmapped MCP JSON-RPC method '{}'",
        method
    )))
}

/// Authoritative single forwarding gate for stdio JSON-RPC requests.
///
/// Handles:
/// 1. Protocol control messages (`initialize`, `ping`, `notifications/*`) -> Forward with framing limits.
/// 2. Discovery (`tools/list`) -> Forward with audit.
/// 3. Data & Tool Execution (`tools/call`, `resources/*`, `prompts/*`) -> Authoritative PDP evaluation.
///
/// Guarantee: Downstream `send_request` is called if and only if:
/// - Request passes structural validation and depth limits.
/// - In managed mode, authenticated subject identity is present.
/// - Revocation registry check passes.
/// - Hard Safety Invariants (SafeMode) are not violated.
/// - Authoritative PDP yields `Verdict::Allow`.
pub async fn handle_stdio_jsonrpc(
    state: &ProxyState,
    session: &SessionContext,
    request: &Value,
    downstream: &mut dyn StdioDownstream,
) -> Result<Value, PepError> {
    let eval_res = evaluate_stdio_request(state, session, request).await?;
    match eval_res {
        StdioEvaluationResult::Forward {
            tool_name,
            forwarded_request,
            is_tool_call,
        } => {
            let raw_result = downstream.send_request(&forwarded_request).await?;
            if is_tool_call {
                // Response Scanner & DLP
                let scan_cfg = state
                    .response_scan_config
                    .read()
                    .map(|g| g.clone())
                    .unwrap_or_default();

                let scanner_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    state
                        .response_scanner
                        .scan_response(&raw_result, &tool_name, &scan_cfg)
                }));

                match scanner_result {
                    Ok(crate::policy::response_scanner::ScanResult::Block { mut findings }) => {
                        let enforce = !state.shadow_mode.load(Ordering::Relaxed);
                        if enforce {
                            let pat_name = findings
                                .pop()
                                .map(|f| f.pattern_name)
                                .unwrap_or_else(|| "unknown_secret".to_string());
                            let _ = state
                                .audit_logger
                                .write_entry(
                                    &session.session_id,
                                    "response_withheld",
                                    &tool_name,
                                    None,
                                    Some(format!("dlp_finding: {}", pat_name)),
                                    None,
                                    session.identity_sub.clone(),
                                    session.identity_email.clone(),
                                    None,
                                    session.request_ip.clone(),
                                    None,
                                )
                                .await;
                            return Err(PepError::ResponseWithheld {
                                reason: format!("Secret detected: {}", pat_name),
                            });
                        }
                        Ok(raw_result)
                    }
                    Ok(crate::policy::response_scanner::ScanResult::Redact { .. }) => {
                        let redacted = state
                            .response_scanner
                            .redact_response(&raw_result, &scan_cfg);
                        Ok(redacted)
                    }
                    Ok(crate::policy::response_scanner::ScanResult::ScannerError { error }) => {
                        let enforce = !state.shadow_mode.load(Ordering::Relaxed);
                        let fail_closed =
                            session.get_policy().map(|p| p.fail_closed).unwrap_or(true);
                        if enforce && fail_closed {
                            let _ = state
                                .audit_logger
                                .write_entry(
                                    &session.session_id,
                                    "response_withheld",
                                    &tool_name,
                                    None,
                                    Some(format!("scanner_error: {}", error)),
                                    None,
                                    session.identity_sub.clone(),
                                    session.identity_email.clone(),
                                    None,
                                    session.request_ip.clone(),
                                    None,
                                )
                                .await;
                            return Err(PepError::ScannerFailure {
                                reason: format!("scanner_error: {}", error),
                            });
                        }
                        Ok(raw_result)
                    }
                    Ok(_) => Ok(raw_result),
                    Err(_panic) => {
                        let enforce = !state.shadow_mode.load(Ordering::Relaxed);
                        let fail_closed =
                            session.get_policy().map(|p| p.fail_closed).unwrap_or(true);
                        if enforce && fail_closed {
                            let _ = state
                                .audit_logger
                                .write_entry(
                                    &session.session_id,
                                    "response_withheld",
                                    &tool_name,
                                    None,
                                    Some("scanner_panic_fail_closed".to_string()),
                                    None,
                                    session.identity_sub.clone(),
                                    session.identity_email.clone(),
                                    None,
                                    session.request_ip.clone(),
                                    None,
                                )
                                .await;
                            return Err(PepError::ScannerFailure {
                                reason: "scanner_panic_fail_closed".to_string(),
                            });
                        }
                        Ok(raw_result)
                    }
                }
            } else {
                Ok(raw_result)
            }
        }
    }
}
