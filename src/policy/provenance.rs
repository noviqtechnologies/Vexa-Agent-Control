//! Data Provenance and Flow Tracking Engine (PRD FR-036)
//!
//! Tracks data sensitivity and origin labels across mediated tool sources and sinks,
//! preventing untrusted external inputs from reaching privileged execution sinks,
//! and blocking confidential workspace data from leaking to untrusted egress sinks.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Security classification label for data elements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SecurityLabel {
    /// Safe, public or sanitized data.
    Public = 0,
    /// Internal workspace data (code, internal documentation).
    InternalWorkspace = 1,
    /// Sensitive credentials, private keys, customer PII.
    ConfidentialSecrets = 2,
    /// Untrusted external data (web scrapers, user input, external APIs).
    UntrustedExternal = 3,
}

impl SecurityLabel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Public => "PUBLIC",
            Self::InternalWorkspace => "INTERNAL_WORKSPACE",
            Self::ConfidentialSecrets => "CONFIDENTIAL_SECRETS",
            Self::UntrustedExternal => "UNTRUSTED_EXTERNAL",
        }
    }
}

/// Permissible sink types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SinkType {
    /// Internal developer terminal or local file write.
    InternalSink,
    /// Privileged shell command execution or DB write.
    PrivilegedExecutionSink,
    /// Outbound HTTP/API network egress.
    ExternalEgressSink,
}

/// Verdict of provenance flow evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowVerdict {
    Allowed,
    Blocked {
        reason_code: &'static str,
        message: String,
    },
}

impl FlowVerdict {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed)
    }
}

/// Bounded in-memory provenance tracker for an active agent session.
pub struct ProvenanceTracker {
    variable_labels: HashMap<String, SecurityLabel>,
}

impl Default for ProvenanceTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl ProvenanceTracker {
    pub fn new() -> Self {
        Self {
            variable_labels: HashMap::new(),
        }
    }

    /// Tag a parameter, variable or output with a security label.
    pub fn tag(&mut self, identifier: impl Into<String>, label: SecurityLabel) {
        self.variable_labels.insert(identifier.into(), label);
    }

    /// Get current label for an identifier (defaults to Public if untagged).
    pub fn get_label(&self, identifier: &str) -> SecurityLabel {
        self.variable_labels
            .get(identifier)
            .copied()
            .unwrap_or(SecurityLabel::Public)
    }

    /// Evaluate if data with `source_label` is permitted to flow into `sink_type`.
    pub fn evaluate_flow(&self, identifier: &str, sink_type: SinkType) -> FlowVerdict {
        let label = self.get_label(identifier);

        match (label, sink_type) {
            // Rule 1: Confidential secrets cannot be dispatched to external egress sinks
            (SecurityLabel::ConfidentialSecrets, SinkType::ExternalEgressSink) => {
                FlowVerdict::Blocked {
                    reason_code: "ERR_PROVENANCE_CONFIDENTIAL_EGRESS",
                    message: format!(
                        "Exfiltration blocked: identifier '{}' carries CONFIDENTIAL_SECRETS and cannot flow to ExternalEgressSink",
                        identifier
                    ),
                }
            }
            // Rule 2: Untrusted external inputs cannot flow directly to privileged execution sinks
            (SecurityLabel::UntrustedExternal, SinkType::PrivilegedExecutionSink) => {
                FlowVerdict::Blocked {
                    reason_code: "ERR_PROVENANCE_UNTRUSTED_EXECUTION",
                    message: format!(
                        "Indirect prompt injection blocked: identifier '{}' carries UNTRUSTED_EXTERNAL taint and cannot flow to PrivilegedExecutionSink",
                        identifier
                    ),
                }
            }
            _ => FlowVerdict::Allowed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_confidential_to_external_egress_blocked() {
        let mut tracker = ProvenanceTracker::new();
        tracker.tag("api_key_output", SecurityLabel::ConfidentialSecrets);

        let verdict = tracker.evaluate_flow("api_key_output", SinkType::ExternalEgressSink);
        assert!(!verdict.is_allowed());
        if let FlowVerdict::Blocked { reason_code, .. } = verdict {
            assert_eq!(reason_code, "ERR_PROVENANCE_CONFIDENTIAL_EGRESS");
        }
    }

    #[test]
    fn test_untrusted_to_privileged_execution_blocked() {
        let mut tracker = ProvenanceTracker::new();
        tracker.tag("scraped_web_payload", SecurityLabel::UntrustedExternal);

        let verdict =
            tracker.evaluate_flow("scraped_web_payload", SinkType::PrivilegedExecutionSink);
        assert!(!verdict.is_allowed());
        if let FlowVerdict::Blocked { reason_code, .. } = verdict {
            assert_eq!(reason_code, "ERR_PROVENANCE_UNTRUSTED_EXECUTION");
        }
    }

    #[test]
    fn test_internal_to_internal_allowed() {
        let mut tracker = ProvenanceTracker::new();
        tracker.tag("code_diff", SecurityLabel::InternalWorkspace);

        let verdict = tracker.evaluate_flow("code_diff", SinkType::InternalSink);
        assert!(verdict.is_allowed());
    }
}
