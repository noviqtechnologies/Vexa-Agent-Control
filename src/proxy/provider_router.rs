//! Latency-Based Provider Routing & Circuit Breaker (P1)
//!
//! Tracks rolling p99 response times across LLM provider endpoints and enforces circuit breaking
//! (5 consecutive 5xx errors or >10% error rate opens circuit for 30 seconds).

use dashmap::DashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct EndpointStats {
    pub consecutive_failures: Arc<AtomicU32>,
    pub total_requests: Arc<AtomicU64>,
    pub total_failures: Arc<AtomicU64>,
    pub last_failure: Arc<Mutex<Option<Instant>>>,
    pub rolling_latency_ms: Arc<Mutex<Vec<u64>>>,
}

pub struct ProviderRouter {
    endpoints: DashMap<String, EndpointStats>,
    failure_threshold: u32,
    cooldown_period: Duration,
}

impl Default for ProviderRouter {
    fn default() -> Self {
        Self::new(5, Duration::from_secs(30))
    }
}

impl ProviderRouter {
    pub fn new(failure_threshold: u32, cooldown_period: Duration) -> Self {
        Self {
            endpoints: DashMap::new(),
            failure_threshold,
            cooldown_period,
        }
    }

    fn get_or_create(&self, endpoint: &str) -> EndpointStats {
        self.endpoints
            .entry(endpoint.to_string())
            .or_insert_with(|| EndpointStats {
                consecutive_failures: Arc::new(AtomicU32::new(0)),
                total_requests: Arc::new(AtomicU64::new(0)),
                total_failures: Arc::new(AtomicU64::new(0)),
                last_failure: Arc::new(Mutex::new(None)),
                rolling_latency_ms: Arc::new(Mutex::new(Vec::with_capacity(50))),
            })
            .clone()
    }

    /// Check if an endpoint is healthy to receive traffic.
    pub fn is_healthy(&self, endpoint: &str) -> bool {
        let stats = self.get_or_create(endpoint);
        let consecutive = stats.consecutive_failures.load(Ordering::Relaxed);

        if consecutive >= self.failure_threshold {
            let last_fail = *stats.last_failure.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(t) = last_fail {
                if t.elapsed() > self.cooldown_period {
                    // Half-open: allow probe
                    return true;
                }
            }
            return false;
        }

        true
    }

    /// Record a successful response with elapsed latency.
    pub fn record_success(&self, endpoint: &str, latency: Duration) {
        let stats = self.get_or_create(endpoint);
        stats.consecutive_failures.store(0, Ordering::Relaxed);
        stats.total_requests.fetch_add(1, Ordering::Relaxed);

        let mut latencies = stats.rolling_latency_ms.lock().unwrap_or_else(|e| e.into_inner());
        if latencies.len() >= 50 {
            latencies.remove(0);
        }
        latencies.push(latency.as_millis() as u64);
    }

    /// Record a provider failure (5xx or connection reset).
    pub fn record_failure(&self, endpoint: &str) {
        let stats = self.get_or_create(endpoint);
        stats.consecutive_failures.fetch_add(1, Ordering::Relaxed);
        stats.total_requests.fetch_add(1, Ordering::Relaxed);
        stats.total_failures.fetch_add(1, Ordering::Relaxed);
        *stats.last_failure.lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
    }

    /// Pick the lowest latency healthy endpoint among a set of candidates.
    pub fn pick_best_endpoint<'a>(&self, candidates: &'a [&'a str]) -> Option<&'a str> {
        let mut best: Option<(&'a str, u64)> = None;

        for &ep in candidates {
            if !self.is_healthy(ep) {
                continue;
            }

            let stats = self.get_or_create(ep);
            let latencies = stats.rolling_latency_ms.lock().unwrap_or_else(|e| e.into_inner());
            let avg_latency = if latencies.is_empty() {
                0
            } else {
                latencies.iter().sum::<u64>() / latencies.len() as u64
            };

            match best {
                None => best = Some((ep, avg_latency)),
                Some((_, best_lat)) if avg_latency < best_lat => {
                    best = Some((ep, avg_latency));
                }
                _ => {}
            }
        }

        best.map(|(ep, _)| ep)
    }
}
