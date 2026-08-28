//! Typed money and usage primitives for SMB LLM Spend Management v2.
//!
//! Enforces compile-time distinction between token quantities and monetary amounts.
//! Floating point and unitless integers are prohibited for financial calculations.

use serde::{Deserialize, Serialize};

/// Integer microcents representation: 1 USD = 100,000,000 microcents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
pub struct InputTokens(pub u64);

/// Typed token count for generated output completion tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
pub struct OutputTokens(pub u64);

/// Typed token count for prompt caching hits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
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
