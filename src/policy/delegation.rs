//! Agent-to-Agent Delegation and Attenuation Engine (PRD FR-035)
//!
//! Enforces hierarchical capability attenuation: child agents cannot receive or exercise
//! privileges exceeding those granted to the parent agent across tools, parameters,
//! audience, and execution time-to-live (TTL).

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

/// Capability grant for an agent session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DelegationGrant {
    pub agent_id: String,
    pub parent_agent_id: Option<String>,
    pub workspace_id: String,
    pub allowed_tools: HashSet<String>,
    pub audience: HashSet<String>,
    pub max_call_depth: u32,
    pub expires_at_epoch_ms: u64,
}

/// Result of delegation attenuation check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttenuationResult {
    Valid,
    EscalationRejected {
        reason_code: &'static str,
        violation_detail: String,
    },
}

impl AttenuationResult {
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }
}

/// Delegation Attenuation Validator.
pub struct DelegationValidator;

impl DelegationValidator {
    /// Validate that child_grant is a strict attenuated subset of parent_grant.
    pub fn validate_delegation(
        parent: &DelegationGrant,
        child: &DelegationGrant,
    ) -> AttenuationResult {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // 1. Parent must not be expired
        if parent.expires_at_epoch_ms <= now_ms {
            return AttenuationResult::EscalationRejected {
                reason_code: "ERR_PARENT_EXPIRED",
                violation_detail: format!(
                    "Parent grant for agent '{}' has expired",
                    parent.agent_id
                ),
            };
        }

        // 2. Workspace boundary must match exactly
        if parent.workspace_id != child.workspace_id {
            return AttenuationResult::EscalationRejected {
                reason_code: "ERR_CROSS_WORKSPACE_DELEGATION",
                violation_detail: format!(
                    "Cannot delegate across workspaces (parent: {}, child: {})",
                    parent.workspace_id, child.workspace_id
                ),
            };
        }

        // 3. Child TTL cannot exceed parent TTL
        if child.expires_at_epoch_ms > parent.expires_at_epoch_ms {
            return AttenuationResult::EscalationRejected {
                reason_code: "ERR_TTL_ESCALATION",
                violation_detail: format!(
                    "Child expiry ({}) exceeds parent expiry ({})",
                    child.expires_at_epoch_ms, parent.expires_at_epoch_ms
                ),
            };
        }

        // 4. Max call depth: child depth cannot exceed parent depth - 1
        if child.max_call_depth >= parent.max_call_depth {
            return AttenuationResult::EscalationRejected {
                reason_code: "ERR_DEPTH_ESCALATION",
                violation_detail: format!(
                    "Child call depth ({}) must be strictly less than parent depth ({})",
                    child.max_call_depth, parent.max_call_depth
                ),
            };
        }

        // 5. Tool attenuation: child tools must be subset of parent tools
        for tool in &child.allowed_tools {
            if !parent.allowed_tools.contains(tool) {
                return AttenuationResult::EscalationRejected {
                    reason_code: "ERR_TOOL_ESCALATION",
                    violation_detail: format!(
                        "Child requested unauthorized tool '{}' not held by parent",
                        tool
                    ),
                };
            }
        }

        // 6. Audience attenuation: child audience must be subset of parent audience
        for aud in &child.audience {
            if !parent.audience.contains(aud) {
                return AttenuationResult::EscalationRejected {
                    reason_code: "ERR_AUDIENCE_ESCALATION",
                    violation_detail: format!(
                        "Child requested audience '{}' outside parent scope",
                        aud
                    ),
                };
            }
        }

        AttenuationResult::Valid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_parent() -> DelegationGrant {
        let mut tools = HashSet::new();
        tools.insert("read_file".to_string());
        tools.insert("search_code".to_string());

        let mut audience = HashSet::new();
        audience.insert("api.internal.dev".to_string());

        DelegationGrant {
            agent_id: "agent-parent".to_string(),
            parent_agent_id: None,
            workspace_id: "ws-engineering".to_string(),
            allowed_tools: tools,
            audience,
            max_call_depth: 3,
            expires_at_epoch_ms: 2000000000000,
        }
    }

    #[test]
    fn test_valid_attenuation_passes() {
        let parent = make_test_parent();
        let mut child_tools = HashSet::new();
        child_tools.insert("read_file".to_string()); // strict subset

        let child = DelegationGrant {
            agent_id: "agent-child".to_string(),
            parent_agent_id: Some("agent-parent".to_string()),
            workspace_id: "ws-engineering".to_string(),
            allowed_tools: child_tools,
            audience: parent.audience.clone(),
            max_call_depth: 2,
            expires_at_epoch_ms: 1999999999000,
        };

        assert_eq!(
            DelegationValidator::validate_delegation(&parent, &child),
            AttenuationResult::Valid
        );
    }

    #[test]
    fn test_tool_escalation_rejected() {
        let parent = make_test_parent();
        let mut child_tools = HashSet::new();
        child_tools.insert("read_file".to_string());
        child_tools.insert("delete_database".to_string()); // escalation!

        let child = DelegationGrant {
            agent_id: "agent-child".to_string(),
            parent_agent_id: Some("agent-parent".to_string()),
            workspace_id: "ws-engineering".to_string(),
            allowed_tools: child_tools,
            audience: parent.audience.clone(),
            max_call_depth: 2,
            expires_at_epoch_ms: 1999999999000,
        };

        match DelegationValidator::validate_delegation(&parent, &child) {
            AttenuationResult::EscalationRejected { reason_code, .. } => {
                assert_eq!(reason_code, "ERR_TOOL_ESCALATION");
            }
            AttenuationResult::Valid => panic!("Should reject tool escalation"),
        }
    }

    #[test]
    fn test_cross_workspace_delegation_rejected() {
        let parent = make_test_parent();
        let child = DelegationGrant {
            agent_id: "agent-child".to_string(),
            parent_agent_id: Some("agent-parent".to_string()),
            workspace_id: "ws-other-tenant".to_string(), // Cross workspace attack!
            allowed_tools: parent.allowed_tools.clone(),
            audience: parent.audience.clone(),
            max_call_depth: 2,
            expires_at_epoch_ms: 1999999999000,
        };

        match DelegationValidator::validate_delegation(&parent, &child) {
            AttenuationResult::EscalationRejected { reason_code, .. } => {
                assert_eq!(reason_code, "ERR_CROSS_WORKSPACE_DELEGATION");
            }
            AttenuationResult::Valid => panic!("Should reject cross-workspace delegation"),
        }
    }
}
