use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BudgetScope {
    Org,
    Group(String),
    User(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BudgetPeriod {
    Daily,
    Weekly,
    Monthly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetConfig {
    pub scope: BudgetScope,
    pub cap_cents: u64,
    pub period: BudgetPeriod,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSpend {
    pub agent_id: String,
    pub period_start: DateTime<Utc>,
    pub spent_cents: u64,
    pub cap_cents: Option<u64>,
    pub is_estimated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IncreaseRequestStatus {
    Pending,
    Approved,
    Denied,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncreaseRequest {
    pub request_id: String,
    pub agent_id: String,
    pub current_cap_cents: u64,
    pub reason: Option<String>,
    pub submitted_at: DateTime<Utc>,
    pub status: IncreaseRequestStatus,
    pub resolved_by: Option<String>,
    pub new_cap_cents: Option<u64>,
}

#[derive(Debug, Clone)]
pub enum SpendCheckResult {
    Ok { remaining_cents: u64 },
    BudgetExhausted { cap_cents: u64, spent_cents: u64 },
    NoBudgetConfigured,
    LedgerUnavailable,
}
