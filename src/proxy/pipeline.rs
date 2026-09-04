//! Phase-Oriented Execution Pipeline & Canonical Request Envelope (Phase 1)
//!
//! Provides a structured, deterministic request lifecycle:
//! 1. Ingress & Protocol Normalization
//! 2. Context & Identity Binding
//! 3. Policy Snapshot Acquisition
//! 4. Security & Safety Inspection (DLP + Injection + Safe Mode + Sequence Rules)
//! 5. Preflight Spend & Token Reservation
//! 6. Route Planning & Deployment Selection
//! 7. Upstream Execution & Attempt Management
//! 8. Response & Stream Sanitization
//! 9. Settlement & Durable Outbox Event Export

use serde::{Deserialize, Serialize};
use std::time::Instant;

/// Canonical operation classification for safety and retry policies.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum OperationKind {
    /// LLM completion / chat request (generally safe to retry on transport failure).
    LlmCompletion {
        model: String,
        stream: bool,
    },
    /// MCP tool call (state-mutating operations MUST NOT be blindly replayed).
    McpToolCall {
        tool_name: String,
        is_idempotent: bool,
    },
    /// Embedding generation request.
    Embedding {
        model: String,
    },
}

impl OperationKind {
    pub fn is_retryable(&self) -> bool {
        match self {
            OperationKind::LlmCompletion { .. } => true,
            OperationKind::Embedding { .. } => true,
            OperationKind::McpToolCall { is_idempotent, .. } => *is_idempotent,
        }
    }

    pub fn operation_name(&self) -> &str {
        match self {
            OperationKind::LlmCompletion { model, .. } => model.as_str(),
            OperationKind::McpToolCall { tool_name, .. } => tool_name.as_str(),
            OperationKind::Embedding { model } => model.as_str(),
        }
    }
}

/// The immutable request context passed through all pipeline stages.
#[derive(Clone, Debug)]
pub struct RequestContext {
    pub request_id: String,
    pub session_id: String,
    pub tenant_id: String,
    pub identity_sub: Option<String>,
    pub identity_email: Option<String>,
    pub identity_groups: Vec<String>,
    pub client_ip: String,
    pub operation_kind: OperationKind,
    pub policy_snapshot_id: String,
    pub created_at: Instant,
}

impl RequestContext {
    pub fn new(
        request_id: String,
        session_id: String,
        tenant_id: String,
        identity_sub: Option<String>,
        identity_email: Option<String>,
        identity_groups: Vec<String>,
        client_ip: String,
        operation_kind: OperationKind,
        policy_snapshot_id: String,
    ) -> Self {
        Self {
            request_id,
            session_id,
            tenant_id,
            identity_sub,
            identity_email,
            identity_groups,
            client_ip,
            operation_kind,
            policy_snapshot_id,
            created_at: Instant::now(),
        }
    }

    pub fn elapsed_ms(&self) -> f64 {
        self.created_at.elapsed().as_secs_f64() * 1000.0
    }

    pub fn for_session(session_id: &str) -> Self {
        Self::new(
            uuid::Uuid::new_v4().to_string(),
            session_id.to_string(),
            "default".to_string(),
            None,
            None,
            Vec::new(),
            "127.0.0.1".to_string(),
            OperationKind::McpToolCall {
                tool_name: "default".to_string(),
                is_idempotent: false,
            },
            "default".to_string(),
        )
    }
}

/// Security decision outcome from inline detectors and compiled policy evaluation.
#[derive(Clone, Debug)]
pub enum SecurityVerdict {
    Allow {
        matched_group_id: Option<String>,
        risk_score: Option<f32>,
    },
    Deny {
        reason_code: String,
        message: String,
        rule_id: Option<String>,
        param_name: Option<String>,
    },
    Redact {
        modified_payload: serde_json::Value,
        findings_count: usize,
    },
    Warn {
        reason: String,
    },
}

impl SecurityVerdict {
    pub fn is_allowed(&self) -> bool {
        matches!(self, SecurityVerdict::Allow { .. } | SecurityVerdict::Redact { .. } | SecurityVerdict::Warn { .. })
    }
}

/// Preflight budget and spend reservation result.
#[derive(Clone, Debug)]
pub enum ReservationResult {
    Reserved {
        reservation_id: String,
        estimated_microcents: u64,
    },
    Bypassed,
    Rejected {
        reason: String,
        cap_microcents: u64,
        spent_microcents: u64,
    },
}

/// Target route determination.
#[derive(Clone, Debug)]
pub enum RouteDecision {
    Selected {
        deployment_id: String,
        endpoint_url: String,
        provider: String,
        model: String,
        retry_allowed: bool,
    },
    Rejected {
        reason: String,
    },
}

/// Pluggable security decision service trait.
pub trait SecurityDecisionService: Send + Sync {
    fn evaluate_tool_call(
        &self,
        ctx: &RequestContext,
        tool_name: &str,
        params: &mut serde_json::Value,
    ) -> SecurityVerdict;

    fn evaluate_llm_request(
        &self,
        ctx: &RequestContext,
        model: &str,
        payload: &serde_json::Value,
    ) -> SecurityVerdict;
}

/// Pluggable spend and token reservation service trait.
pub trait ReservationService: Send + Sync {
    fn reserve(
        &self,
        ctx: &RequestContext,
        estimated_microcents: u64,
    ) -> ReservationResult;

    fn settle(
        &self,
        ctx: &RequestContext,
        reservation_id: &str,
        actual_microcents: u64,
    );
}

/// Pluggable deployment router service trait.
pub trait DeploymentRouterService: Send + Sync {
    fn plan_route(
        &self,
        ctx: &RequestContext,
        provider: &str,
        model: &str,
    ) -> RouteDecision;

    fn report_attempt_outcome(
        &self,
        deployment_id: &str,
        success: bool,
        latency_ms: u64,
        status_code: Option<u16>,
    );
}
