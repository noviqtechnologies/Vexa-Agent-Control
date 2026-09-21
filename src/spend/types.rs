//! Typed money and usage primitives for SMB LLM Spend Management v2.
//!
//! Enforces compile-time distinction between token quantities and monetary amounts.
//! Floating point and unitless integers are prohibited for financial calculations.

use serde::{Deserialize, Serialize};

/// Integer microcents representation: 1 USD = 100,000,000 microcents.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
pub struct MoneyMicrocents(pub i64);

impl MoneyMicrocents {
    pub const ZERO: MoneyMicrocents = MoneyMicrocents(0);

    pub fn from_dollars(dollars: f64) -> Self {
        Self((dollars * 100_000_000.0).round() as i64)
    }

    pub fn to_dollars(self) -> f64 {
        self.0 as f64 / 100_000_000.0
    }

    pub fn as_microcents(self) -> i64 {
        self.0
    }
}

impl std::ops::Add for MoneyMicrocents {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl std::ops::Sub for MoneyMicrocents {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

/// Typed token count for input prompt tokens.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
pub struct InputTokens(pub u64);

/// Typed token count for generated output completion tokens.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
pub struct OutputTokens(pub u64);

/// Typed token count for prompt caching hits.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
pub struct CachedTokens(pub u64);

/// ISO 4217 Currency Code (v1 strictly USD).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CurrencyCode(pub String);

impl Default for CurrencyCode {
    fn default() -> Self {
        Self("USD".to_string())
    }
}

// ── V2 API DTOs ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendV2AuthorizeReq {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_id: Option<String>,
    pub request_id: String,
    pub idempotency_key: String,
    pub project_id: String,
    pub provider: String,
    pub model: String,
    pub input_token_estimate: i64,
    pub max_output_tokens: i64,
    pub request_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendV2AuthorizeResp {
    pub decision: String, // "allow" | "deny"
    pub reason_code: String,
    pub reservation_id: Option<String>,
    pub reservation_expires_at: Option<String>,
    pub reserved_microcents: Option<MoneyMicrocents>,
    pub currency: Option<String>,
    pub policy_versions: Option<Vec<String>>,
    pub price_book_version: Option<String>,
    pub correlation_id: Option<String>,
    pub disclosure_safe_scope: Option<String>,
    pub reset_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendV2SettleReq {
    pub request_id: String,
    pub idempotency_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_request_id: Option<String>,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cached_input_tokens: i64,
    pub is_estimated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage_source: Option<String>,
    pub status: i32,
    pub request_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendV2SettleResp {
    pub status: String,
    pub reservation_id: String,
    pub settled_microcents: MoneyMicrocents,
    pub released_microcents: MoneyMicrocents,
    pub currency: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendV2ReleaseReq {
    pub request_id: String,
    pub idempotency_key: String,
    pub reason: String,
    pub request_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendV2ReleaseResp {
    pub status: String,
    pub reservation_id: String,
    pub released_microcents: MoneyMicrocents,
}

/// 4-Tier Client Attribution Context for Agencies & Multi-Tenant Workspaces.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttributionContext {
    pub client_id: String,
    pub project_id: String,
    pub cost_center: String,
}

impl Default for AttributionContext {
    fn default() -> Self {
        Self {
            client_id: "default".to_string(),
            project_id: "default".to_string(),
            cost_center: "default".to_string(),
        }
    }
}

impl AttributionContext {
    /// Validates and normalizes slug (^[a-zA-Z0-9_\-\.]{1,64}$).
    /// Replaces commas, quotes, spaces, and invalid chars with underscores to prevent CSV injection.
    pub fn sanitize_slug(input: &str) -> String {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return "default".to_string();
        }
        let sanitized: String = trimmed
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' {
                    c
                } else {
                    '_'
                }
            })
            .take(64)
            .collect();
        if sanitized.is_empty() {
            "default".to_string()
        } else {
            sanitized
        }
    }

    pub fn new(client: &str, project: &str, cost_center: &str) -> Self {
        Self {
            client_id: Self::sanitize_slug(client),
            project_id: Self::sanitize_slug(project),
            cost_center: Self::sanitize_slug(cost_center),
        }
    }

    /// Resolves attribution using 4-tier precedence:
    /// Tier 1: HTTP Request Header (X-AgentControl-*, X-AgentWall-*)
    /// Tier 2: Environment Variable (AGENTCONTROL_*)
    /// Tier 3: GitOps Policy YAML metadata
    /// Tier 4: Session Default / Fallback ("default")
    ///
    /// If central_tenant_lock is Some (and non-empty/non-default), client_id is locked to the central tenant.
    pub fn resolve(
        header_client: Option<&str>,
        header_project: Option<&str>,
        header_cost_center: Option<&str>,
        policy_attribution: Option<&AttributionContext>,
        central_tenant_lock: Option<&str>,
    ) -> Self {
        let client_id = header_client
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.trim().to_string())
            .or_else(|| std::env::var("AGENTCONTROL_CLIENT_ID").ok())
            .or_else(|| policy_attribution.map(|p| p.client_id.clone()))
            .unwrap_or_else(|| "default".to_string());

        let project_id = header_project
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.trim().to_string())
            .or_else(|| std::env::var("AGENTCONTROL_PROJECT_ID").ok())
            .or_else(|| policy_attribution.map(|p| p.project_id.clone()))
            .unwrap_or_else(|| "default".to_string());

        let cost_center = header_cost_center
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.trim().to_string())
            .or_else(|| std::env::var("AGENTCONTROL_COST_CENTER").ok())
            .or_else(|| policy_attribution.map(|p| p.cost_center.clone()))
            .unwrap_or_else(|| "default".to_string());

        let mut attr = Self::new(&client_id, &project_id, &cost_center);

        // Central Tenant Boundary Lock:
        if let Some(lock) = central_tenant_lock {
            let lock_slug = Self::sanitize_slug(lock);
            if !lock_slug.is_empty() && lock_slug != "default" {
                attr.client_id = lock_slug;
            }
        }

        attr
    }
}

/// Invoice-ready usage record for client attribution and finance billing export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendExportRecord {
    pub timestamp: String,
    pub request_id: String,
    pub client_id: String,
    pub project_id: String,
    pub cost_center: String,
    pub agent_id: String,
    pub provider: String,
    pub model: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
    pub cost_cents: u64,
    pub cost_usd: f64,
    pub is_estimated: bool,
}

/// Filter options for spend export query.
#[derive(Debug, Clone, Default)]
pub struct SpendExportFilter {
    pub client_id: Option<String>,
    pub project_id: Option<String>,
    pub start_timestamp: Option<i64>,
    pub end_timestamp: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attribution_precedence_header_wins() {
        let policy_attr = AttributionContext::new("policy_client", "policy_proj", "policy_cc");
        let resolved = AttributionContext::resolve(
            Some("hdr_client"),
            Some("hdr_proj"),
            Some("hdr_cc"),
            Some(&policy_attr),
            None,
        );
        assert_eq!(resolved.client_id, "hdr_client");
        assert_eq!(resolved.project_id, "hdr_proj");
        assert_eq!(resolved.cost_center, "hdr_cc");
    }

    #[test]
    fn test_attribution_precedence_policy_over_fallback() {
        let policy_attr = AttributionContext::new("policy_client", "policy_proj", "policy_cc");
        let resolved = AttributionContext::resolve(None, None, None, Some(&policy_attr), None);
        assert_eq!(resolved.client_id, "policy_client");
        assert_eq!(resolved.project_id, "policy_proj");
        assert_eq!(resolved.cost_center, "policy_cc");
    }

    #[test]
    fn test_attribution_precedence_fallback() {
        let resolved = AttributionContext::resolve(None, None, None, None, None);
        assert_eq!(resolved.client_id, "default");
        assert_eq!(resolved.project_id, "default");
        assert_eq!(resolved.cost_center, "default");
    }

    #[test]
    fn test_attribution_central_tenant_lock() {
        let resolved = AttributionContext::resolve(
            Some("rogue_client"),
            Some("proj1"),
            None,
            None,
            Some("locked_corp"),
        );
        assert_eq!(resolved.client_id, "locked_corp");
        assert_eq!(resolved.project_id, "proj1");
    }

    #[test]
    fn test_attribution_slug_sanitization() {
        let dirty = "Client, Inc. / Dept #1 <script> @!%*";
        let clean = AttributionContext::sanitize_slug(dirty);
        assert!(!clean.contains(','));
        assert!(!clean.contains('<'));
        assert!(!clean.contains(' '));
        assert!(clean
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.'));
    }
}
