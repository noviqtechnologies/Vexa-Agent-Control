//! Policy engine module for evaluation, DLP inspection, prompt injection, and schema loading.

pub mod community_rules;
/// FR-5 v2.0: Credential scope stub validator (FR-22 integration pending).
pub mod credential_scope;
pub mod dlp;
pub mod engine;
pub mod identity;
pub mod injection;
pub mod loader;
/// Remote policy loader: fetches active policy from the dashboard API (PostgreSQL)
/// and provides a background polling task for automatic hot-reload.
pub mod remote;
pub mod response_scanner;
pub mod safe_mode;
pub mod schema;
pub mod semantic;

#[cfg(test)]
mod group_policy_test;
