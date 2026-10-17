//! HTTP/LLM Policy Enforcement Point (Gate 3).
//!
//! Provides the authoritative single forwarding gate for HTTP-based LLM API calls
//! (e.g. OpenAI / Anthropic / Gemini completions, chat, embeddings).
//! Guarantee: Zero downstream execution occurs unless the authoritative
//! Policy Decision Point (PDP) explicitly yields an `Allow` verdict and all
//! pre-dispatch checks (identity provenance, revocation registry, hard safety invariants) succeed.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use decision_v1::{
    ActionRequest, AuthenticatedPrincipal, Decision, EvaluationContext, LlmRequestType, Obligation,
    Protocol, Verdict,
};
use serde_json::Value;

use super::PepError;
use crate::policy::engine::CompiledPolicy;
use crate::proxy::handler::ProxyState;
use crate::proxy::session::SessionContext;

/// Abstract downstream LLM provider target.
/// The PEP has exclusive access to downstream dispatch.
#[async_trait::async_trait]
pub trait LlmDownstream: Send + Sync {
    /// Dispatch LLM request to the downstream model provider.
    async fn forward_request(
        &mut self,
        provider: &str,
        model: &str,
        body: &Value,
    ) -> Result<Value, PepError>;
}

/// In-memory mock downstream provider for deterministic testing of side-effect boundaries.
pub struct MockLlmDownstream {
    pub call_count: Arc<AtomicUsize>,
    pub response: Value,
}

impl MockLlmDownstream {
    pub fn new(call_count: Arc<AtomicUsize>) -> Self {
        Self {
            call_count,
            response: serde_json::json!({
                "id": "chatcmpl-mock-pep",
                "object": "chat.completion",
                "created": 1700000000,
                "model": "mock-model",
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": "mock llm response content"
                        }
                    ]
                },
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": "mock llm response content"
                        },
                        "finish_reason": "stop"
                    }
                ],
                "usage": {
                    "prompt_tokens": 12,
                    "completion_tokens": 8,
                    "total_tokens": 20
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
impl LlmDownstream for MockLlmDownstream {
    async fn forward_request(
        &mut self,
        _provider: &str,
        _model: &str,
        _body: &Value,
    ) -> Result<Value, PepError> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        Ok(self.response.clone())
    }
}

/// Extract and validate model name from LLM request body.
pub fn extract_model(body: &Value) -> Result<&str, PepError> {
    body.get("model")
        .and_then(|m| m.as_str())
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| {
            PepError::ValidationFailed("Missing or empty 'model' in LLM request body".to_string())
        })
}

/// Infer LLM request type (Chat, Completion, Embedding) from path and payload structure.
pub fn infer_llm_request_type(url_path: &str, body: &Value) -> LlmRequestType {
    if url_path.contains("chat") || body.get("messages").is_some() {
        LlmRequestType::Chat
    } else if url_path.contains("embed") {
        LlmRequestType::Embedding
    } else {
        LlmRequestType::Completion
    }
}

/// Construct authenticated evaluation context strictly from validated session credentials.
pub fn build_llm_evaluation_context(session: &SessionContext) -> EvaluationContext {
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
        adapter_id: "http-llm".to_string(),
        adapter_protocol: Protocol::LlmRest,
        policy_revision,
        policy_hash,
    }
}

/// Pre-flight authoritative evaluation for HTTP/LLM requests.
///
/// Handles:
/// 1. Structural protocol validation
/// 2. Identity provenance check in managed mode (G1.2)
/// 3. Revocation registry check (<30s propagation guarantee)
/// 4. Hard Safety Invariants (SafeMode)
/// 5. Authoritative PDP evaluation (CompiledPolicy::evaluate_action)
/// 6. Metrics & durable audit logging
pub async fn evaluate_http_llm_request(
    state: &ProxyState,
    session: &SessionContext,
    provider: &str,
    url_path: &str,
    body: &Value,
) -> Result<Decision, PepError> {
    // Gate 2: Rebind stale session policy if global policy_epoch has incremented
    let current_epoch = state.policy_epoch.load(Ordering::SeqCst);
    if session.session_epoch.load(Ordering::SeqCst) < current_epoch {
        let current_policy = state.get_policy();
        session.refresh_policy(current_policy, current_epoch);
    }

    // 1. Structural protocol validation
    if !body.is_object() {
        return Err(PepError::ValidationFailed(
            "LLM request body must be a JSON object".to_string(),
        ));
    }

    let model = extract_model(body)?;
    let tool_name = format!("llm:{}", model);

    // 2. Pre-evaluation identity provenance check in managed mode (G1.2)
    if state.policy_trust_profile.is_managed() && session.identity_sub.is_none() {
        state.metrics_deny_total.fetch_add(1, Ordering::Relaxed);
        let _ = state
            .audit_logger
            .write_entry(
                &session.session_id,
                "llm_deny",
                &tool_name,
                Some(serde_json::json!({ "model": model, "provider": provider })),
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
            decision: Box::new(decision),
        });
    }

    // 3. Pre-evaluation revocation check (<30s propagation guarantee)
    let agent_id = session.identity_sub.as_deref();
    let credential_id = session.active_credential_id.as_deref();
    let revocation_check = state
        .revocation_registry
        .check(agent_id, Some(&tool_name), credential_id)
        .and_then(|_| {
            state
                .revocation_registry
                .check(agent_id, Some(model), credential_id)
        });
    if let Err(revoked) = revocation_check {
        state.metrics_deny_total.fetch_add(1, Ordering::Relaxed);
        let _ = state
            .audit_logger
            .write_entry(
                &session.session_id,
                "capability_revoked_blocked",
                &tool_name,
                Some(serde_json::json!({ "model": model, "provider": provider })),
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
            decision: Box::new(decision),
        });
    }

    // 4. Pre-evaluation Hard Safety Invariants
    // Check if tools in LLM function definitions or prompt violate invariant rules
    if let Some(threat) = state.safe_mode_scanner.scan_tool(model, body) {
        state.metrics_deny_total.fetch_add(1, Ordering::Relaxed);
        let _ = state
            .audit_logger
            .write_entry(
                &session.session_id,
                "hard_invariant_blocked",
                &tool_name,
                Some(serde_json::json!({ "model": model, "provider": provider })),
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
            decision: Box::new(decision),
        });
    }

    // 5. Construct typed action request and evaluation context
    let request_type = infer_llm_request_type(url_path, body);
    let action = ActionRequest::LlmRequest {
        provider: provider.to_string(),
        model: model.to_string(),
        request_type,
    };
    // 6. Authoritative PDP evaluation
    let mut active_policy: Option<CompiledPolicy> =
        session.get_policy().or_else(|| state.get_policy());

    // JIT fallback policy load from candidate paths if uninitialized
    if active_policy.is_none() {
        let candidate_paths = [
            std::path::PathBuf::from("agentcontrol-policy.yaml"),
            dirs::home_dir()
                .map(|h| h.join("agentcontrol-policy.yaml"))
                .unwrap_or_default(),
            dirs::home_dir()
                .map(|h| h.join(".agentcontrol/agentcontrol-policy.yaml"))
                .unwrap_or_default(),
            std::path::PathBuf::from(
                r"C:\Windows\System32\config\systemprofile\.agentcontrol\agentcontrol-policy.yaml",
            ),
            std::path::PathBuf::from(r"C:\Program Files\AgentControl\agentcontrol-policy.yaml"),
        ];

        for p in &candidate_paths {
            if p.exists() {
                if let crate::policy::loader::PolicyLoadResult::Loaded { policy, .. } =
                    crate::policy::loader::load_policy(p, None)
                {
                    state.update_policy(Some(policy.clone()));
                    active_policy = Some(policy);
                    break;
                }
            }
        }
    }

    let mut context = build_llm_evaluation_context(session);
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
                Decision::deny(
                    "no_active_policy",
                    Some("No active policy configured on the gateway".to_string()),
                )
            }
        }
    };

    // 7. Single Forwarding Gate: enforce verdict
    match decision.verdict {
        Verdict::Deny => {
            state.metrics_deny_total.fetch_add(1, Ordering::Relaxed);
            let _ = state
                .audit_logger
                .write_entry(
                    &session.session_id,
                    "llm_deny",
                    &tool_name,
                    Some(serde_json::json!({ "model": model, "provider": provider })),
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
                decision: Box::new(decision),
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
                    "llm_require_approval",
                    &tool_name,
                    Some(serde_json::json!({ "model": model, "provider": provider })),
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
                decision: Box::new(decision),
            })
        }
        Verdict::Indeterminate => {
            state.metrics_deny_total.fetch_add(1, Ordering::Relaxed);
            Err(PepError::Denied {
                reason: "indeterminate_fail_closed".to_string(),
                decision: Box::new(decision),
            })
        }
        Verdict::Allow => {
            state.metrics_allow_total.fetch_add(1, Ordering::Relaxed);
            let _ = state
                .audit_logger
                .write_entry(
                    &session.session_id,
                    "llm_allow",
                    &tool_name,
                    Some(serde_json::json!({ "model": model, "provider": provider })),
                    None,
                    None,
                    session.identity_sub.clone(),
                    session.identity_email.clone(),
                    None,
                    session.request_ip.clone(),
                    decision.matched_group_id.clone(),
                )
                .await;
            Ok(decision)
        }
    }
}

/// Authoritative single forwarding gate for HTTP/LLM requests.
/// Downstream is called if and only if:
/// 1. Request parameters pass structural validation.
/// 2. Identity provenance satisfies managed mode requirements.
/// 3. Capability is not revoked in the revocation registry.
/// 4. No Hard Invariant (SafeMode) is violated.
/// 5. Authoritative PDP decision yields `Verdict::Allow`.
pub async fn handle_http_llm_request(
    state: &ProxyState,
    session: &SessionContext,
    provider: &str,
    url_path: &str,
    body: &Value,
    downstream: &mut dyn LlmDownstream,
) -> Result<Value, PepError> {
    let _decision = evaluate_http_llm_request(state, session, provider, url_path, body).await?;
    let model = extract_model(body)?;
    let tool_name = format!("llm:{}", model);

    // EXCLUSIVE FORWARDING: exactly one dispatch call
    let raw_result = downstream.forward_request(provider, model, body).await?;

    // 8. Post-flight Response Scanning (Result Boundary)
    let scan_cfg = state
        .response_scan_config
        .read()
        .map(|g| g.clone())
        .unwrap_or_default();

    let scanner_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let first = state
            .response_scanner
            .scan_response(&raw_result, &tool_name, &scan_cfg);
        if matches!(
            first,
            crate::policy::response_scanner::ScanResult::Pass
                | crate::policy::response_scanner::ScanResult::Clean
        ) {
            state
                .response_scanner
                .scan_response(&raw_result, model, &scan_cfg)
        } else {
            first
        }
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
            let fail_closed = session.get_policy().map(|p| p.fail_closed).unwrap_or(true);
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
            let fail_closed = session.get_policy().map(|p| p.fail_closed).unwrap_or(true);
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
}

/// Helper to scan streaming LLM chunks and enforce result boundary.
pub fn handle_llm_stream_chunk(
    state: &ProxyState,
    session: &SessionContext,
    model: &str,
    chunk: &Value,
) -> Result<Value, PepError> {
    let scan_cfg = state
        .response_scan_config
        .read()
        .map(|g| g.clone())
        .unwrap_or_default();

    let scan_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        state
            .response_scanner
            .scan_response(chunk, model, &scan_cfg)
    }));

    match scan_result {
        Ok(crate::policy::response_scanner::ScanResult::Block { mut findings }) => {
            let enforce = !state.shadow_mode.load(Ordering::Relaxed);
            if enforce {
                let pat_name = findings
                    .pop()
                    .map(|f| f.pattern_name)
                    .unwrap_or_else(|| "unknown_secret".to_string());
                return Err(PepError::ResponseWithheld {
                    reason: format!("Stream chunk secret detected: {}", pat_name),
                });
            }
            Ok(chunk.clone())
        }
        Ok(crate::policy::response_scanner::ScanResult::Redact { .. }) => {
            let redacted = state.response_scanner.redact_response(chunk, &scan_cfg);
            Ok(redacted)
        }
        Ok(crate::policy::response_scanner::ScanResult::ScannerError { error }) => {
            let enforce = !state.shadow_mode.load(Ordering::Relaxed);
            let fail_closed = session.get_policy().map(|p| p.fail_closed).unwrap_or(true);
            if enforce && fail_closed {
                return Err(PepError::ScannerFailure {
                    reason: format!("stream_scanner_error: {}", error),
                });
            }
            Ok(chunk.clone())
        }
        Ok(_) => Ok(chunk.clone()),
        Err(_) => {
            let enforce = !state.shadow_mode.load(Ordering::Relaxed);
            let fail_closed = session.get_policy().map(|p| p.fail_closed).unwrap_or(true);
            if enforce && fail_closed {
                return Err(PepError::ScannerFailure {
                    reason: "stream_scanner_panic_fail_closed".to_string(),
                });
            }
            Ok(chunk.clone())
        }
    }
}
