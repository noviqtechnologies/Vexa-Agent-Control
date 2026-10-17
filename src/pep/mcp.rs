//! MCP Policy Enforcement Point (Gate 2).
//!
//! Provides the single forwarding gate for Model Context Protocol (MCP) `tools/call`.
//! Guarantee: No downstream execution side-effect occurs unless the authoritative
//! Policy Decision Point (PDP) explicitly yields an `Allow` verdict and all
//! pre-dispatch checks (revocation, hard safety invariants, firewall) succeed.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use decision_v1::{
    ActionRequest, AuthenticatedPrincipal, Decision, EvaluationContext, Obligation, Protocol,
    Verdict,
};
use serde_json::Value;

use crate::policy::engine::CompiledPolicy;
use crate::proxy::handler::ProxyState;
use crate::proxy::session::SessionContext;

pub use super::PepError;

/// Abstract downstream MCP server target.
/// The PEP has exclusive access to downstream dispatch.
#[async_trait::async_trait]
pub trait McpDownstream: Send + Sync {
    /// Dispatch tool call to the downstream tool provider.
    async fn call_tool(&mut self, name: &str, arguments: &Value) -> Result<Value, PepError>;
}

/// In-memory mock downstream provider for deterministic testing of side-effect boundaries.
pub struct MockMcpDownstream {
    pub call_count: Arc<AtomicUsize>,
    pub response: Value,
}

impl MockMcpDownstream {
    pub fn new(call_count: Arc<AtomicUsize>) -> Self {
        Self {
            call_count,
            response: serde_json::json!({
                "content": [
                    {
                        "type": "text",
                        "text": "mock tool output"
                    }
                ]
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
impl McpDownstream for MockMcpDownstream {
    async fn call_tool(&mut self, _name: &str, _arguments: &Value) -> Result<Value, PepError> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        Ok(self.response.clone())
    }
}

/// Concrete HTTP downstream MCP provider for production gateway forwarding.
pub struct HttpMcpDownstream {
    pub client: reqwest::Client,
    pub upstream_url: String,
    pub request_id: Value,
}

#[async_trait::async_trait]
impl McpDownstream for HttpMcpDownstream {
    async fn call_tool(&mut self, name: &str, arguments: &Value) -> Result<Value, PepError> {
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": self.request_id,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments,
            }
        });
        let resp = self
            .client
            .post(&self.upstream_url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| PepError::DownstreamError(e.to_string()))?;

        let val = resp
            .json::<Value>()
            .await
            .map_err(|e| PepError::DownstreamError(e.to_string()))?;

        if let Some(err) = val.get("error") {
            return Err(PepError::DownstreamError(err.to_string()));
        }
        if let Some(result) = val.get("result") {
            Ok(result.clone())
        } else {
            Ok(val)
        }
    }
}

/// Extract and validate tool name from MCP JSON-RPC parameters.
pub fn extract_tool_name(params: &Value) -> Result<&str, PepError> {
    params
        .get("name")
        .and_then(|n| n.as_str())
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| {
            PepError::ValidationFailed("Missing or empty 'name' in tools/call params".to_string())
        })
}

/// Extract and validate arguments object from MCP JSON-RPC parameters.
pub fn extract_arguments(params: &Value) -> Result<Value, PepError> {
    match params.get("arguments") {
        Some(Value::Object(map)) => Ok(Value::Object(map.clone())),
        Some(Value::Null) | None => Ok(Value::Object(serde_json::Map::new())),
        Some(_) => Err(PepError::ValidationFailed(
            "'arguments' in tools/call params must be a JSON object".to_string(),
        )),
    }
}

/// Construct authenticated evaluation context strictly from validated session credentials.
pub fn build_evaluation_context(session: &SessionContext) -> EvaluationContext {
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
        adapter_id: "mcp-tools-call".to_string(),
        adapter_protocol: Protocol::Stdio,
        policy_revision,
        policy_hash,
    }
}

/// Authoritative single forwarding gate for MCP `tools/call`.
/// Downstream is called if and only if:
/// 1. Request parameters pass structural validation.
/// 2. Capability is not revoked in the revocation registry.
/// 3. No Hard Invariant (SafeMode) is violated.
/// 4. Authoritative PDP decision yields `Verdict::Allow`.
pub async fn handle_mcp_tools_call(
    state: &ProxyState,
    session: &SessionContext,
    method: &str,
    params: &Value,
    downstream: &mut dyn McpDownstream,
) -> Result<Value, PepError> {
    // Gate 2: Rebind stale session policy if global policy_epoch has incremented
    let current_epoch = state.policy_epoch.load(Ordering::SeqCst);
    if session.session_epoch.load(Ordering::SeqCst) < current_epoch {
        let current_policy = state.get_policy();
        session.refresh_policy(current_policy, current_epoch);
    }

    // 1. Structural protocol validation
    if method != "tools/call" {
        return Err(PepError::ValidationFailed(format!(
            "Expected method 'tools/call', got '{}'",
            method
        )));
    }

    let tool_name = extract_tool_name(params)?;
    let arguments = extract_arguments(params)?;

    // 2. Pre-evaluation identity provenance check in managed mode (G1.2)
    if state.policy_trust_profile.is_managed() && session.identity_sub.is_none() {
        state.metrics_deny_total.fetch_add(1, Ordering::Relaxed);
        let _ = state
            .audit_logger
            .write_entry(
                &session.session_id,
                "tool_deny",
                tool_name,
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

    // 3. Pre-evaluation revocation check (<30s propagation guarantee)
    let agent_id = session.identity_sub.as_deref();
    let credential_id = session.active_credential_id.as_deref();
    if let Err(revoked) = state
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

    // 3. Pre-evaluation Hard Safety Invariants (cannot be overridden by policy)
    if let Some(threat) = state.safe_mode_scanner.scan_tool(tool_name, &arguments) {
        // Hard Invariant findings unconditionally produce Deny
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

    // 4. Construct typed action request and evaluation context
    let action = ActionRequest::McpToolCall {
        tool_name: tool_name.to_string(),
        arguments: arguments.clone(),
        server_id: None,
    };
    // 5. Authoritative PDP evaluation
    let active_policy: Option<CompiledPolicy> = session.get_policy().or_else(|| state.get_policy());

    let mut context = build_evaluation_context(session);
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

    // 6. Single Forwarding Gate: enforce verdict
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
            Err(PepError::Denied {
                reason: decision.reason_code.clone(),
                decision,
            })
        }
        Verdict::RequireApproval => {
            state.metrics_deny_total.fetch_add(1, Ordering::Relaxed);
            let approval_id = decision
                .obligations
                .iter()
                .find_map(|o| match o {
                    Obligation::RequireApproval { approval_id, .. } => Some(approval_id.clone()),
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

            Err(PepError::ApprovalRequired {
                approval_id,
                decision,
            })
        }
        Verdict::Indeterminate => {
            state.metrics_deny_total.fetch_add(1, Ordering::Relaxed);
            Err(PepError::Denied {
                reason: "indeterminate_fail_closed".to_string(),
                decision,
            })
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

            // EXCLUSIVE FORWARDING: exactly one dispatch call
            let raw_result = downstream.call_tool(tool_name, &arguments).await?;

            // 7. Post-flight Response Scanning (Result Boundary)
            let scan_cfg = state
                .response_scan_config
                .read()
                .map(|g| g.clone())
                .unwrap_or_default();

            let scanner_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                state
                    .response_scanner
                    .scan_response(&raw_result, tool_name, &scan_cfg)
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
                                tool_name,
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
                    let fail_closed = session.get_policy().map(|p| p.fail_closed).unwrap_or(true);
                    if enforce && fail_closed {
                        let _ = state
                            .audit_logger
                            .write_entry(
                                &session.session_id,
                                "response_withheld",
                                tool_name,
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
                    let fail_closed = session.get_policy().map(|p| p.fail_closed).unwrap_or(true);
                    if enforce && fail_closed {
                        let _ = state
                            .audit_logger
                            .write_entry(
                                &session.session_id,
                                "response_withheld",
                                tool_name,
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
        }
    }
}
