//! Vexa Agent Control Decision Contract v1 (Gate 1).
//!
//! Provides strongly typed representations of:
//! - ActionRequest: Narrowed variants (MCP Tool Call, LLM Request, Resource/Prompt Access)
//! - EvaluationContext: Provenance-backed principal, tenant, session, and adapter context
//! - Decision & Obligation: Authoritative verdicts and runtime obligations
//! - ApprovalRequest: Lifecycle state machine for Human-in-the-Loop approvals
//! - ActionLifecycle: Correlated dispatch, outcome, release, and audit states

pub mod action;
pub mod approval;
pub mod context;
pub mod decision;
pub mod lifecycle;

pub use action::{ActionRequest, LlmRequestType, ResourceAccessType};
pub use approval::{ApprovalRequest, ApprovalState};
pub use context::{AuthenticatedPrincipal, EvaluationContext, Protocol};
pub use decision::{Decision, Obligation, Verdict};
pub use lifecycle::{
    ActionLifecycle, AuditState, DispatchState, DownstreamOutcome, ReleaseDecision,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_request_serialization_roundtrip() {
        let action = ActionRequest::McpToolCall {
            tool_name: "read_file".to_string(),
            arguments: serde_json::json!({ "path": "/etc/hosts" }),
            server_id: Some("srv-local".to_string()),
        };

        let json_str = serde_json::to_string(&action).unwrap();
        let deserialized: ActionRequest = serde_json::from_str(&json_str).unwrap();
        assert_eq!(action, deserialized);
        assert_eq!(action.target_identifier(), "read_file");
    }

    #[test]
    fn test_decision_verdict_helpers() {
        let allow = Decision::allow();
        assert_eq!(allow.verdict, Verdict::Allow);

        let deny = Decision::deny("rule_violation", Some("Path not allowed".to_string()));
        assert_eq!(deny.verdict, Verdict::Deny);

        let approval = Decision::require_approval(
            "appr-1".to_string(),
            "hash-123".to_string(),
            300,
            "Approval needed".to_string(),
        );
        assert_eq!(approval.verdict, Verdict::RequireApproval);
        assert_eq!(approval.obligations.len(), 1);
    }

    #[test]
    fn test_approval_state_cas_transition() {
        let mut req = ApprovalRequest {
            approval_id: "appr-test".to_string(),
            action_hash: "hash-xyz".to_string(),
            principal_sub: "user-1".to_string(),
            device_id: None,
            session_id: "sess-1".to_string(),
            policy_revision: 1,
            nonce: "nonce-123".to_string(),
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            state: ApprovalState::Pending,
        };

        assert!(req.is_valid_and_pending("hash-xyz"));
        assert!(!req.is_valid_and_pending("wrong-hash"));

        // Cannot consume when pending
        assert!(req.consume().is_err());

        // Approve then consume
        req.state = ApprovalState::Approved;
        assert!(req.consume().is_ok());
        assert_eq!(req.state, ApprovalState::Consumed);

        // Cannot consume twice
        assert!(req.consume().is_err());
    }
}
