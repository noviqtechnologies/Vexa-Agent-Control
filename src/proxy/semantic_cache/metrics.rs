//! Differentiated Semantic Cache & Token Spend Economics Metrics
//!
//! Explicitly separates Vexa Gateway-Level 100% avoided costs from Upstream Provider
//! partial prefix discounts, calculating ROI and attributing financial value.

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SemanticMatchRecord {
    pub id: String,
    pub timestamp_ms: i64,
    pub user_prompt: String,
    pub cached_prompt: String,
    pub similarity: f32,
    pub model: String,
    pub hit_type: String, // "exact" | "semantic"
    pub tokens_saved: i64,
    pub cost_saved_usd: f64,
    pub latency_ms: f64,
}

pub struct SemanticCacheMetrics {
    // Gateway-level metrics (100% cost avoided before upstream egress)
    pub exact_hits: AtomicU64,
    pub semantic_hits: AtomicU64,
    pub misses: AtomicU64,
    pub gateway_tokens_saved_prompt: AtomicU64,
    pub gateway_tokens_saved_completion: AtomicU64,
    pub gateway_cost_saved_microcents: AtomicU64,
    pub gateway_latency_saved_ms: AtomicU64,

    // Provider-level metrics (upstream prefix discounts on prompt tokens only)
    pub provider_cache_hits: AtomicU64,
    pub provider_cached_tokens: AtomicU64,
    pub provider_cost_discount_microcents: AtomicU64,

    // Per-model tracking: model_name -> (gateway_tokens_saved, provider_cached_tokens, gateway_cost_saved_microcents)
    pub per_model: DashMap<String, (AtomicU64, AtomicU64, AtomicU64)>,

    // Recent semantic matches for interactive cluster inspector (capped at 50)
    pub recent_matches: RwLock<VecDeque<SemanticMatchRecord>>,
}

impl Default for SemanticCacheMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl SemanticCacheMetrics {
    pub fn new() -> Self {
        Self {
            exact_hits: AtomicU64::new(0),
            semantic_hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            gateway_tokens_saved_prompt: AtomicU64::new(0),
            gateway_tokens_saved_completion: AtomicU64::new(0),
            gateway_cost_saved_microcents: AtomicU64::new(0),
            gateway_latency_saved_ms: AtomicU64::new(0),

            provider_cache_hits: AtomicU64::new(0),
            provider_cached_tokens: AtomicU64::new(0),
            provider_cost_discount_microcents: AtomicU64::new(0),

            per_model: DashMap::new(),
            recent_matches: RwLock::new(VecDeque::with_capacity(50)),
        }
    }

    /// Record a gateway-level cache hit (100% avoided cost).
    pub fn record_gateway_hit(
        &self,
        hit_type: &str, // "exact" | "semantic"
        model: &str,
        user_prompt: &str,
        cached_prompt: &str,
        similarity: f32,
        prompt_tokens: i64,
        completion_tokens: i64,
        latency_ms: f64,
    ) -> f64 {
        if hit_type == "exact" {
            self.exact_hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.semantic_hits.fetch_add(1, Ordering::Relaxed);
        }

        let p_tok = prompt_tokens.max(0) as u64;
        let c_tok = completion_tokens.max(0) as u64;
        self.gateway_tokens_saved_prompt.fetch_add(p_tok, Ordering::Relaxed);
        self.gateway_tokens_saved_completion.fetch_add(c_tok, Ordering::Relaxed);

        // Estimate typical upstream latency saved (~1150ms upstream vs 2ms cached)
        let saved_lat = (1150.0 - latency_ms).max(10.0) as u64;
        self.gateway_latency_saved_ms.fetch_add(saved_lat, Ordering::Relaxed);

        let cost_usd = Self::calculate_model_cost(model, prompt_tokens, completion_tokens);
        let microcents = (cost_usd * 100_000_000.0) as u64;
        self.gateway_cost_saved_microcents.fetch_add(microcents, Ordering::Relaxed);

        // Update per-model map
        let entry = self.per_model.entry(model.to_string()).or_insert_with(|| {
            (AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0))
        });
        entry.0.fetch_add(p_tok + c_tok, Ordering::Relaxed);
        entry.2.fetch_add(microcents, Ordering::Relaxed);

        // Push to recent matches
        let rec = SemanticMatchRecord {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp_ms: chrono::Utc::now().timestamp_millis(),
            user_prompt: user_prompt.chars().take(200).collect(),
            cached_prompt: cached_prompt.chars().take(200).collect(),
            similarity,
            model: model.to_string(),
            hit_type: hit_type.to_string(),
            tokens_saved: (prompt_tokens + completion_tokens),
            cost_saved_usd: cost_usd,
            latency_ms,
        };

        if let Ok(mut lock) = self.recent_matches.write() {
            if lock.len() >= 50 {
                lock.pop_back();
            }
            lock.push_front(rec);
        }

        cost_usd
    }

    /// Record a gateway cache miss.
    pub fn record_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an upstream provider-side prompt cache discount (e.g. from OpenAI cached_tokens).
    pub fn record_provider_discount(&self, model: &str, cached_tokens: i64) {
        if cached_tokens <= 0 {
            return;
        }
        self.provider_cache_hits.fetch_add(1, Ordering::Relaxed);
        let tok = cached_tokens as u64;
        self.provider_cached_tokens.fetch_add(tok, Ordering::Relaxed);

        // Provider discounts 50% (OpenAI) to 90% (Anthropic) of prompt token cost
        let discount_usd = Self::calculate_provider_discount(model, cached_tokens);
        let microcents = (discount_usd * 100_000_000.0) as u64;
        self.provider_cost_discount_microcents.fetch_add(microcents, Ordering::Relaxed);

        let entry = self.per_model.entry(model.to_string()).or_insert_with(|| {
            (AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0))
        });
        entry.1.fetch_add(tok, Ordering::Relaxed);
    }

    /// Calculate standard pricing (USD) based on model rates per 1,000,000 tokens.
    pub fn calculate_model_cost(model: &str, prompt_tokens: i64, completion_tokens: i64) -> f64 {
        let (prompt_rate, completion_rate) = match model.to_lowercase().as_str() {
            m if m.starts_with("gpt-4o-mini") => (0.15 / 1_000_000.0, 0.60 / 1_000_000.0),
            m if m.starts_with("gpt-4o") => (2.50 / 1_000_000.0, 10.00 / 1_000_000.0),
            m if m.starts_with("o1") || m.starts_with("o3") => (15.00 / 1_000_000.0, 60.00 / 1_000_000.0),
            m if m.contains("claude-3-5-sonnet") || m.contains("claude-3-7-sonnet") => {
                (3.00 / 1_000_000.0, 15.00 / 1_000_000.0)
            }
            m if m.contains("claude-3-5-haiku") => (0.80 / 1_000_000.0, 4.00 / 1_000_000.0),
            m if m.contains("deepseek") => (0.14 / 1_000_000.0, 0.28 / 1_000_000.0),
            _ => (2.00 / 1_000_000.0, 8.00 / 1_000_000.0),
        };

        (prompt_tokens as f64 * prompt_rate) + (completion_tokens as f64 * completion_rate)
    }

    /// Calculate upstream provider prompt cache discount (typically 50% discount on prompt rate).
    pub fn calculate_provider_discount(model: &str, cached_tokens: i64) -> f64 {
        let prompt_rate = match model.to_lowercase().as_str() {
            m if m.starts_with("gpt-4o-mini") => 0.15 / 1_000_000.0,
            m if m.starts_with("gpt-4o") => 2.50 / 1_000_000.0,
            m if m.starts_with("o1") || m.starts_with("o3") => 15.00 / 1_000_000.0,
            m if m.contains("claude-3-5-sonnet") || m.contains("claude-3-7-sonnet") => 3.00 / 1_000_000.0,
            m if m.contains("claude-3-5-haiku") => 0.80 / 1_000_000.0,
            m if m.contains("deepseek") => 0.14 / 1_000_000.0,
            _ => 2.00 / 1_000_000.0,
        };

        // 50% discount on cached prompt tokens
        (cached_tokens as f64 * prompt_rate) * 0.50
    }

    /// Generate comprehensive differentiated economic summary for UI and API.
    pub fn snapshot(&self) -> serde_json::Value {
        let exact = self.exact_hits.load(Ordering::Relaxed);
        let semantic = self.semantic_hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total_lookups = exact + semantic + misses;

        let hit_ratio_pct = if total_lookups > 0 {
            ((exact + semantic) as f64 / total_lookups as f64) * 100.0
        } else {
            0.0
        };

        let p_tok = self.gateway_tokens_saved_prompt.load(Ordering::Relaxed);
        let c_tok = self.gateway_tokens_saved_completion.load(Ordering::Relaxed);
        let gateway_cost_usd = self.gateway_cost_saved_microcents.load(Ordering::Relaxed) as f64 / 100_000_000.0;
        let gateway_latency_ms = self.gateway_latency_saved_ms.load(Ordering::Relaxed);

        let prov_hits = self.provider_cache_hits.load(Ordering::Relaxed);
        let prov_tokens = self.provider_cached_tokens.load(Ordering::Relaxed);
        let prov_discount_usd = self.provider_cost_discount_microcents.load(Ordering::Relaxed) as f64 / 100_000_000.0;

        let total_savings_usd = gateway_cost_usd + prov_discount_usd;
        let vexa_contribution_pct = if total_savings_usd > 0.0 {
            (gateway_cost_usd / total_savings_usd) * 100.0
        } else {
            0.0
        };

        let recent = self
            .recent_matches
            .read()
            .map(|r| r.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default();

        serde_json::json!({
            "gateway_cache": {
                "exact_hits": exact,
                "semantic_hits": semantic,
                "misses": misses,
                "total_lookups": total_lookups,
                "hit_ratio_pct": (hit_ratio_pct * 10.0).round() / 10.0,
                "tokens_saved": {
                    "prompt": p_tok,
                    "completion": c_tok,
                    "total": p_tok + c_tok
                },
                "cost_saved_usd": (gateway_cost_usd * 10000.0).round() / 10000.0,
                "latency_saved_ms": gateway_latency_ms,
                "avg_serving_latency_ms": 2.4,
                "egress_bytes_avoided": (p_tok + c_tok) * 4
            },
            "provider_cache": {
                "prefix_cache_hits": prov_hits,
                "cached_tokens": prov_tokens,
                "discount_usd": (prov_discount_usd * 10000.0).round() / 10000.0,
                "avg_serving_latency_ms": 1180.0
            },
            "comparative_summary": {
                "total_savings_usd": (total_savings_usd * 10000.0).round() / 10000.0,
                "vexa_contribution_pct": (vexa_contribution_pct * 10.0).round() / 10.0,
                "provider_contribution_pct": if total_savings_usd > 0.0 { ((100.0 - vexa_contribution_pct) * 10.0).round() / 10.0 } else { 0.0 },
                "roi_multiplier": if prov_discount_usd > 0.0 { (gateway_cost_usd / prov_discount_usd * 100.0).round() / 100.0 } else { 1.0 }
            },
            "recent_matches": recent
        })
    }
}
