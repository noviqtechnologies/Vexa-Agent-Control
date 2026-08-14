//! Spend tracking, token ledger accounting, budget enforcement, and LLM model pricing subsystem (FR-120).

pub mod ledger;
pub mod model;
pub mod pricing;
pub mod retention;
pub mod types;

pub use ledger::{SpendCmd, SpendLedger};
pub use model::{
    AgentSpend, BudgetConfig, BudgetPeriod, BudgetScope, IncreaseRequest, IncreaseRequestStatus,
    SpendCheckResult,
};
pub use pricing::{ModelPrice, PricingTable};
pub use retention::RetentionPolicy;
pub use types::{
    CachedTokens, CurrencyCode, InputTokens, MoneyMicrocents, OutputTokens, SpendV2AuthorizeReq,
    SpendV2AuthorizeResp, SpendV2ReleaseReq, SpendV2ReleaseResp, SpendV2SettleReq,
    SpendV2SettleResp,
};
