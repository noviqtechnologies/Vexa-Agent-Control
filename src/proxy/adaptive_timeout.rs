//! Adaptive Model-Aware Timeouts and Concurrency Backpressure (P0)
//!
//! Provides dynamic timeout scaling based on model architecture and token estimates,
//! and tracks concurrent in-flight requests per virtual key.

use dashmap::DashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct ModelTimeoutProfile {
    pub base_timeout_ms: u64,
    pub per_token_timeout_ms: u64,
    pub max_timeout_ms: u64,
}

pub struct AdaptiveTimeoutManager {
    concurrency_map: DashMap<String, Arc<AtomicUsize>>,
}

impl Default for AdaptiveTimeoutManager {
    fn default() -> Self {
        Self::new()
    }
}

impl AdaptiveTimeoutManager {
    pub fn new() -> Self {
        Self {
            concurrency_map: DashMap::new(),
        }
    }

    /// Calculate dynamic timeout for a model given expected completion tokens.
    pub fn calculate_timeout(model: &str, expected_tokens: Option<usize>) -> Duration {
        let tokens = expected_tokens.unwrap_or(500) as u64;

        let profile = if model.contains("o1") || model.contains("o3") || model.contains("r1") || model.contains("reasoning") {
            // Reasoning / Deep-thinking models take significantly longer
            ModelTimeoutProfile {
                base_timeout_ms: 60_000,
                per_token_timeout_ms: 200,
                max_timeout_ms: 300_000,
            }
        } else if model.contains("gpt-4o-mini") || model.contains("flash") || model.contains("haiku") {
            // Fast / Light models
            ModelTimeoutProfile {
                base_timeout_ms: 15_000,
                per_token_timeout_ms: 30,
                max_timeout_ms: 60_000,
            }
        } else if model.contains("claude-3-5") || model.contains("gpt-4o") || model.contains("sonnet") {
            // High capability standard models
            ModelTimeoutProfile {
                base_timeout_ms: 30_000,
                per_token_timeout_ms: 60,
                max_timeout_ms: 120_000,
            }
        } else {
            // Default profile
            ModelTimeoutProfile {
                base_timeout_ms: 30_000,
                per_token_timeout_ms: 50,
                max_timeout_ms: 120_000,
            }
        };

        let calculated = profile.base_timeout_ms + (tokens * profile.per_token_timeout_ms);
        let final_ms = calculated.min(profile.max_timeout_ms);
        Duration::from_millis(final_ms)
    }

    /// Acquire a concurrency slot for a virtual key.
    /// Returns Ok(guard) or Err(current_concurrency) if max_concurrent > 0 and exceeded.
    pub fn acquire(&self, key_id: &str, max_concurrent: usize) -> Result<ConcurrencyGuard, usize> {
        let counter = self
            .concurrency_map
            .entry(key_id.to_string())
            .or_insert_with(|| Arc::new(AtomicUsize::new(0)))
            .clone();

        let current = counter.load(Ordering::Relaxed);
        if max_concurrent > 0 && current >= max_concurrent {
            return Err(current);
        }

        counter.fetch_add(1, Ordering::Relaxed);
        Ok(ConcurrencyGuard { counter })
    }
}

pub struct ConcurrencyGuard {
    counter: Arc<AtomicUsize>,
}

impl Drop for ConcurrencyGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Relaxed);
    }
}
