//! Phase 1: Explainable verdict engine for structured block decisions.
//!
//! When the policy engine blocks a tool call, it produces a `VerdictReport`
//! containing machine-readable evidence: which rule fired, what triggered it,
//! the risk category, and remediation instructions.
//!
//! This enables:
//! - Audit V2 entries to carry structured `verdict` fields.
//! - The proxy to return RFC 7807 problem details to blocked clients.
//! - Operators to diagnose blocks without reading raw policy files.
//!
//! See: Phase 1 Implementation Plan §4 ("Explainable Block Decisions")

use serde::{Deserialize, Serialize};

/// A structured explanation of why a tool call was blocked or flagged.
///
/// Designed to be:
/// 1. Embedded in audit V2 entries (`AuditEntryV2.verdict`).
/// 2. Returned as RFC 7807 problem detail to MCP clients.
/// 3. Displayed in the trace explorer UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictReport {
    /// The final decision.
    pub decision: VerdictDecision,
    /// Ordered list of rules that contributed to this verdict.
    /// The first rule is the primary trigger; subsequent rules are corroborating.
    pub triggered_rules: Vec<TriggeredRule>,
    /// Overall risk category for the blocked action.
    pub risk_category: RiskCategory,
    /// Human-readable summary of the verdict.
    pub summary: String,
    /// Optional remediation instructions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    /// Policy file hash at the time of evaluation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
    /// Wall-clock evaluation latency in microseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eval_latency_us: Option<u64>,
}

/// The final enforcement decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerdictDecision {
    /// Tool call was allowed.
    Allow,
    /// Tool call was blocked by policy.
    Deny,
    /// Tool call requires human-in-the-loop approval.
    RequireApproval,
    /// Tool call was allowed but flagged for review.
    AllowWithWarning,
}

/// A single rule that contributed to the verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggeredRule {
    /// Machine-readable rule identifier (e.g. `dlp-api-key-001`, `cmd-sudo-block`).
    pub rule_id: String,
    /// Human-readable rule name.
    pub rule_name: String,
    /// Which detector family fired this rule.
    pub detector: DetectorFamily,
    /// Confidence score (0.0 = low confidence, 1.0 = certain match).
    pub confidence: f64,
    /// Short evidence snippet (redacted if necessary) showing what triggered the rule.
    /// Maximum 200 characters to prevent data leakage.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_snippet: Option<String>,
    /// The specific parameter or field that triggered the rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub triggering_field: Option<String>,
}

/// Detector family classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectorFamily {
    /// Policy allowlist/denylist evaluation.
    PolicyEngine,
    /// DLP (Data Loss Prevention) credential/secret scanner.
    Dlp,
    /// Prompt injection / jailbreak detection.
    PromptInjection,
    /// Shell command safety analysis.
    CommandPolicy,
    /// Filesystem path sensitivity analysis.
    SensitivePath,
    /// Egress/network destination filtering.
    EgressFilter,
    /// MCP schema drift detection.
    SchemaDrift,
    /// Rate limiting / spend cap enforcement.
    RateLimit,
    /// Safe mode (restrictive default) enforcement.
    SafeMode,
    /// Sequence rule (stateful) enforcement.
    SequenceRule,
    /// Semantic analysis.
    Semantic,
    /// Response content scanning.
    ResponseScanner,
    /// Identity / OIDC validation.
    Identity,
}

/// Risk categories aligned with enterprise security taxonomies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskCategory {
    /// Credential or API key exposure.
    CredentialExposure,
    /// Attempt to execute privileged commands.
    PrivilegeEscalation,
    /// Access to sensitive filesystem paths.
    SensitiveDataAccess,
    /// Data exfiltration via network egress.
    DataExfiltration,
    /// Prompt injection or jailbreak attempt.
    PromptInjection,
    /// Unauthorized tool usage (not in allowlist).
    UnauthorizedTool,
    /// Schema drift (tool schema has changed unexpectedly).
    SchemaDrift,
    /// Spending or rate limit exceeded.
    ResourceExhaustion,
    /// Policy violation (generic catch-all).
    PolicyViolation,
    /// Sequence-dependent security constraint.
    SequenceViolation,
    /// Identity or authorization failure.
    AuthorizationFailure,
}

impl VerdictReport {
    /// Create a simple ALLOW verdict with no triggered rules.
    pub fn allow(summary: impl Into<String>) -> Self {
        Self {
            decision: VerdictDecision::Allow,
            triggered_rules: Vec::new(),
            risk_category: RiskCategory::PolicyViolation,
            summary: summary.into(),
            remediation: None,
            policy_hash: None,
            eval_latency_us: None,
        }
    }

    /// Create a DENY verdict with a single triggered rule.
    pub fn deny(
        rule_id: impl Into<String>,
        rule_name: impl Into<String>,
        detector: DetectorFamily,
        risk_category: RiskCategory,
        summary: impl Into<String>,
        evidence_snippet: Option<String>,
        remediation: Option<String>,
    ) -> Self {
        let evidence = evidence_snippet.map(|s| {
            // Truncate evidence to prevent data leakage in responses.
            if s.len() > 200 {
                format!("{}…", &s[..197])
            } else {
                s
            }
        });

        Self {
            decision: VerdictDecision::Deny,
            triggered_rules: vec![TriggeredRule {
                rule_id: rule_id.into(),
                rule_name: rule_name.into(),
                detector,
                confidence: 1.0,
                evidence_snippet: evidence,
                triggering_field: None,
            }],
            risk_category,
            summary: summary.into(),
            remediation,
            policy_hash: None,
            eval_latency_us: None,
        }
    }

    /// Create a verdict requiring HITL approval.
    pub fn require_approval(
        rule_id: impl Into<String>,
        rule_name: impl Into<String>,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            decision: VerdictDecision::RequireApproval,
            triggered_rules: vec![TriggeredRule {
                rule_id: rule_id.into(),
                rule_name: rule_name.into(),
                detector: DetectorFamily::PolicyEngine,
                confidence: 1.0,
                evidence_snippet: None,
                triggering_field: None,
            }],
            risk_category: RiskCategory::PolicyViolation,
            summary: summary.into(),
            remediation: Some("Approve or deny via the local console or API.".to_string()),
            policy_hash: None,
            eval_latency_us: None,
        }
    }

    /// Add a corroborating triggered rule to this verdict.
    pub fn with_rule(mut self, rule: TriggeredRule) -> Self {
        self.triggered_rules.push(rule);
        self
    }

    /// Set the policy hash for this verdict.
    pub fn with_policy_hash(mut self, hash: impl Into<String>) -> Self {
        self.policy_hash = Some(hash.into());
        self
    }

    /// Set the evaluation latency for this verdict.
    pub fn with_latency(mut self, latency_us: u64) -> Self {
        self.eval_latency_us = Some(latency_us);
        self
    }

    /// Convert to an RFC 7807 problem detail JSON value for HTTP responses.
    pub fn to_problem_detail(&self, instance: &str) -> serde_json::Value {
        let status = match self.decision {
            VerdictDecision::Deny => 403,
            VerdictDecision::RequireApproval => 409,
            VerdictDecision::AllowWithWarning => 200,
            VerdictDecision::Allow => 200,
        };

        let mut detail = serde_json::json!({
            "type": "https://vexasec.io/problems/policy-verdict",
            "title": format!("{:?}", self.decision),
            "status": status,
            "detail": self.summary,
            "instance": instance,
            "risk_category": self.risk_category,
        });

        if !self.triggered_rules.is_empty() {
            detail["triggered_rules"] = serde_json::to_value(&self.triggered_rules)
                .unwrap_or_default();
        }

        if let Some(ref remediation) = self.remediation {
            detail["remediation"] = serde_json::Value::String(remediation.clone());
        }

        detail
    }

    /// Convert to an `AuditEntryV2::VerdictExplanation` for embedding in audit entries.
    pub fn to_audit_verdict(&self) -> Option<crate::audit::v2::VerdictExplanation> {
        if self.triggered_rules.is_empty() {
            return None;
        }

        let primary = &self.triggered_rules[0];
        Some(crate::audit::v2::VerdictExplanation {
            rule_id: primary.rule_id.clone(),
            risk_category: format!("{:?}", self.risk_category),
            evidence_snippet: primary.evidence_snippet.clone(),
            remediation: self.remediation.clone(),
        })
    }
}

// ─── Unit Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allow_verdict() {
        let v = VerdictReport::allow("Tool call permitted by allowlist");
        assert_eq!(v.decision, VerdictDecision::Allow);
        assert!(v.triggered_rules.is_empty());
    }

    #[test]
    fn test_deny_verdict_with_evidence() {
        let v = VerdictReport::deny(
            "dlp-api-key-001",
            "API Key Detection",
            DetectorFamily::Dlp,
            RiskCategory::CredentialExposure,
            "Tool parameters contain an API key",
            Some("sk-abc123...".to_string()),
            Some("Remove the API key from parameters and use environment variables.".to_string()),
        );

        assert_eq!(v.decision, VerdictDecision::Deny);
        assert_eq!(v.triggered_rules.len(), 1);
        assert_eq!(v.triggered_rules[0].rule_id, "dlp-api-key-001");
        assert_eq!(v.risk_category, RiskCategory::CredentialExposure);
    }

    #[test]
    fn test_evidence_truncation() {
        let long_evidence = "x".repeat(500);
        let v = VerdictReport::deny(
            "test-rule",
            "Test",
            DetectorFamily::Dlp,
            RiskCategory::CredentialExposure,
            "test",
            Some(long_evidence),
            None,
        );

        let snippet = v.triggered_rules[0].evidence_snippet.as_ref().unwrap();
        assert!(snippet.len() <= 201); // 197 chars + "…" (3 bytes in UTF-8)
    }

    #[test]
    fn test_problem_detail_json() {
        let v = VerdictReport::deny(
            "cmd-sudo-block",
            "Sudo Block",
            DetectorFamily::CommandPolicy,
            RiskCategory::PrivilegeEscalation,
            "Command uses sudo",
            None,
            Some("Remove sudo prefix".to_string()),
        );

        let pd = v.to_problem_detail("/api/v1/tools/call/bash");
        assert_eq!(pd["status"], 403);
        assert_eq!(pd["detail"], "Command uses sudo");
        assert!(pd["triggered_rules"].is_array());
    }

    #[test]
    fn test_audit_verdict_conversion() {
        let v = VerdictReport::deny(
            "injection-001",
            "Prompt Injection",
            DetectorFamily::PromptInjection,
            RiskCategory::PromptInjection,
            "Injection pattern detected",
            Some("ignore previous instructions".to_string()),
            Some("Review prompt content".to_string()),
        );

        let audit_v = v.to_audit_verdict().unwrap();
        assert_eq!(audit_v.rule_id, "injection-001");
        assert_eq!(audit_v.evidence_snippet, Some("ignore previous instructions".to_string()));
    }

    #[test]
    fn test_builder_pattern() {
        let v = VerdictReport::deny(
            "test",
            "Test Rule",
            DetectorFamily::PolicyEngine,
            RiskCategory::UnauthorizedTool,
            "Not allowed",
            None,
            None,
        )
        .with_policy_hash("sha256:abcdef")
        .with_latency(1500)
        .with_rule(TriggeredRule {
            rule_id: "secondary-001".to_string(),
            rule_name: "Secondary Check".to_string(),
            detector: DetectorFamily::SafeMode,
            confidence: 0.85,
            evidence_snippet: None,
            triggering_field: Some("params.command".to_string()),
        });

        assert_eq!(v.triggered_rules.len(), 2);
        assert_eq!(v.policy_hash, Some("sha256:abcdef".to_string()));
        assert_eq!(v.eval_latency_us, Some(1500));
    }

    #[test]
    fn test_serialization_round_trip() {
        let v = VerdictReport::deny(
            "dlp-001",
            "DLP",
            DetectorFamily::Dlp,
            RiskCategory::CredentialExposure,
            "Secret found",
            Some("sk-...".to_string()),
            Some("Use env vars".to_string()),
        );

        let json = serde_json::to_string(&v).unwrap();
        let parsed: VerdictReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.decision, VerdictDecision::Deny);
        assert_eq!(parsed.triggered_rules[0].rule_id, "dlp-001");
    }
}
