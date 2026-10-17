//! Automated Upstream Failover, Circuit Breaking & Idempotency Management (PRD FR-030, FR-031)
//!
//! Provides deterministic resilience across LLM providers:
//! - Tracks consecutive failures per provider and opens circuit breakers when thresholds are exceeded.
//! - Automatically routes requests to configured fallback equivalent providers.
//! - Enforces idempotency-aware retries: only safe/idempotent requests (or requests with valid
//!   idempotency keys) may be retried; non-idempotent side effects are blocked from retrying.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// Circuit breaker operational state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CircuitState {
    /// Normal operation: requests pass through.
    Closed,
    /// Provider failing: requests immediately routed to fallback without calling upstream.
    Open,
    /// Recovery probe: single test request allowed to verify if upstream has recovered.
    HalfOpen,
}

/// Status and statistics for a single upstream provider.
#[derive(Debug, Clone)]
pub struct ProviderHealth {
    pub consecutive_failures: u32,
    pub state: CircuitState,
    pub last_state_change: Instant,
    pub failure_threshold: u32,
    pub recovery_timeout: Duration,
}

impl ProviderHealth {
    pub fn new(failure_threshold: u32, recovery_timeout: Duration) -> Self {
        Self {
            consecutive_failures: 0,
            state: CircuitState::Closed,
            last_state_change: Instant::now(),
            failure_threshold,
            recovery_timeout,
        }
    }

    pub fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.state = CircuitState::Closed;
        self.last_state_change = Instant::now();
    }

    pub fn record_failure(&mut self) {
        self.consecutive_failures += 1;
        if self.consecutive_failures >= self.failure_threshold {
            self.state = CircuitState::Open;
            self.last_state_change = Instant::now();
        }
    }

    pub fn can_dispatch(&mut self) -> bool {
        match self.state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                if self.last_state_change.elapsed() >= self.recovery_timeout {
                    self.state = CircuitState::HalfOpen;
                    self.last_state_change = Instant::now();
                    true
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => false, // Currently executing a probe
        }
    }
}

/// Fallback route rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailoverRule {
    pub primary_provider: String,
    pub primary_model: String,
    pub fallback_chain: Vec<(String, String)>, // (provider, model)
}

/// Upstream Failover & Idempotency Router.
pub struct FailoverRouter {
    providers: RwLock<HashMap<String, ProviderHealth>>,
    rules: HashMap<String, FailoverRule>,
}

impl FailoverRouter {
    pub fn new(rules: Vec<FailoverRule>) -> Self {
        let mut map = HashMap::new();
        for r in rules {
            map.insert(format!("{}:{}", r.primary_provider, r.primary_model), r);
        }
        Self {
            providers: RwLock::new(HashMap::new()),
            rules: map,
        }
    }

    /// Select the best available provider/model, evaluating circuit breaker states.
    pub fn resolve_route(
        &self,
        requested_provider: &str,
        requested_model: &str,
    ) -> (String, String) {
        let key = format!("{}:{}", requested_provider, requested_model);

        // Check primary health
        let is_primary_available = {
            let mut providers = self.providers.write().unwrap();
            let health = providers
                .entry(requested_provider.to_string())
                .or_insert_with(|| ProviderHealth::new(3, Duration::from_secs(30)));
            health.can_dispatch()
        };

        if is_primary_available {
            return (requested_provider.to_string(), requested_model.to_string());
        }

        // Primary circuit is OPEN: evaluate fallbacks from rule
        if let Some(rule) = self.rules.get(&key) {
            let mut providers = self.providers.write().unwrap();
            for (fb_prov, fb_model) in &rule.fallback_chain {
                let health = providers
                    .entry(fb_prov.clone())
                    .or_insert_with(|| ProviderHealth::new(3, Duration::from_secs(30)));
                if health.can_dispatch() {
                    return (fb_prov.clone(), fb_model.clone());
                }
            }
        }

        // Default to requested if no healthy fallback found
        (requested_provider.to_string(), requested_model.to_string())
    }

    /// Record outcome of an upstream call.
    pub fn record_outcome(&self, provider: &str, is_success: bool) {
        let mut providers = self.providers.write().unwrap();
        if let Some(health) = providers.get_mut(provider) {
            if is_success {
                health.record_success();
            } else {
                health.record_failure();
            }
        }
    }

    /// Evaluate whether a failed request is safe to retry under FR-031.
    pub fn is_retry_permitted(
        &self,
        is_idempotent_method: bool,
        has_idempotency_key: bool,
        http_status_code: u16,
    ) -> Result<bool, &'static str> {
        // Only transient server errors (500, 502, 503, 504, 429) are retry candidates
        let is_transient = matches!(http_status_code, 429 | 500 | 502 | 503 | 504);
        if !is_transient {
            return Ok(false);
        }

        // Safe/idempotent reads or explicit idempotency-keyed mutations may retry
        if is_idempotent_method || has_idempotency_key {
            Ok(true)
        } else {
            // Non-idempotent call with no idempotency key must NOT retry to prevent duplicate side effects
            Err("ERR_NON_IDEMPOTENT_RETRY_BLOCKED")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_breaker_failover_trigger() {
        let rule = FailoverRule {
            primary_provider: "openai".to_string(),
            primary_model: "gpt-4o".to_string(),
            fallback_chain: vec![
                ("azure".to_string(), "gpt-4o-eastus".to_string()),
                ("anthropic".to_string(), "claude-3-5-sonnet".to_string()),
            ],
        };

        let router = FailoverRouter::new(vec![rule]);

        // 1. Initial route is primary
        let (prov, model) = router.resolve_route("openai", "gpt-4o");
        assert_eq!(prov, "openai");
        assert_eq!(model, "gpt-4o");

        // 2. Trigger 3 consecutive failures on openai
        router.record_outcome("openai", false);
        router.record_outcome("openai", false);
        router.record_outcome("openai", false);

        // 3. Next route automatically fails over to Azure
        let (prov2, model2) = router.resolve_route("openai", "gpt-4o");
        assert_eq!(prov2, "azure");
        assert_eq!(model2, "gpt-4o-eastus");
    }

    #[test]
    fn test_idempotency_retry_boundary() {
        let router = FailoverRouter::new(vec![]);

        // 1. Idempotent GET/read with 503 is allowed to retry
        assert_eq!(router.is_retry_permitted(true, false, 503), Ok(true));

        // 2. Non-idempotent POST/mutation with idempotency key is allowed to retry
        assert_eq!(router.is_retry_permitted(false, true, 500), Ok(true));

        // 3. Non-idempotent POST/mutation WITHOUT idempotency key is BLOCKED from retrying
        assert_eq!(
            router.is_retry_permitted(false, false, 502),
            Err("ERR_NON_IDEMPOTENT_RETRY_BLOCKED")
        );
    }
}
