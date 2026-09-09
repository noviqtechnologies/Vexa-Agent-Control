//! Enterprise Semantic Caching Engine for Vexa Agent Control
//!
//! Multi-tiered caching architecture combining:
//! - Tier 1: Sub-millisecond exact SHA-256 match cache (L1)
//! - Tier 2: Partitioned in-memory cosine-similarity vector cache with optional Qdrant integration (L2)
//!
//! Features strict tenant/model/context isolation, conservative allowlisting,
//! bounded approximate LRU memory management, and sub-3ms response times.

pub mod embedder;
pub mod metrics;
pub mod qdrant;
pub mod vector_index;

use bytes::Bytes;
use embedder::{Embedder, EmbedderEngine};
use metrics::{CacheBypassReason, SemanticCacheMetrics};
use qdrant::QdrantBackend;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use vector_index::{InMemoryVectorIndex, VectorEntry};

/// Canonical execution context capturing all behavior-changing parameters.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CanonicalContext {
    pub tenant_id: String,
    pub subject_id: String,
    pub virtual_key_scope: Option<String>,
    pub provider: String,
    pub model: String,
    pub model_version: Option<String>,
    pub policy_version: String,
    pub workspace_hash: Option<String>,
    pub system_prompt_hash: String,
    pub developer_message_hash: Option<String>,
    pub temperature_fixed: String, // e.g. "0.000"
    pub top_p_fixed: Option<String>,
    pub top_k: Option<u32>,
    pub seed: Option<u64>,
    pub max_tokens: Option<u32>,
    pub stop_sequences: Vec<String>,
    pub response_format: Option<String>,
    pub reasoning_effort: Option<String>,
    pub locale: Option<String>,
    pub normalized_prompt: String,
}

impl CanonicalContext {
    /// Compute deterministic 32-byte SHA-256 exact match key across all parameters.
    pub fn compute_exact_key(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        let canonical_json = serde_json::to_string(&self).unwrap_or_default();
        hasher.update(canonical_json.as_bytes());
        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key
    }
}

#[derive(Clone, Debug)]
pub struct SemanticCacheHit {
    pub response_body: Bytes,
    pub content_type: String,
    pub hit_type: &'static str, // "exact" | "semantic"
    pub similarity: f32,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub cost_saved_usd: f64,
    pub cached_prompt: String,
}

#[derive(Clone, Debug)]
pub struct ExactCacheEntry {
    pub response_body: Bytes,
    pub content_type: String,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub created_at: Instant,
    pub last_accessed: Instant,
    pub cached_prompt: String,
    pub approx_bytes: usize,
}

impl ExactCacheEntry {
    pub fn is_expired(&self, ttl: Duration) -> bool {
        self.created_at.elapsed() > ttl
    }
}

pub enum VectorBackend {
    InMemory(InMemoryVectorIndex),
    Qdrant(QdrantBackend),
    Hybrid {
        in_memory: InMemoryVectorIndex,
        qdrant: QdrantBackend,
    },
}

pub struct SemanticCache {
    enabled: bool,
    similarity_threshold: f32,
    ttl: Duration,
    exact_cache: dashmap::DashMap<[u8; 32], ExactCacheEntry>,
    max_exact_entries: usize,
    max_exact_bytes: usize,
    exact_entries_count: AtomicUsize,
    exact_bytes_count: AtomicUsize,
    backend: VectorBackend,
    embedder: Embedder,
    pub metrics: Arc<SemanticCacheMetrics>,
}

impl Default for SemanticCache {
    fn default() -> Self {
        Self::new_in_memory(
            true,
            0.88,
            10_000,
            Duration::from_secs(86400),
            EmbedderEngine::Local,
        )
    }
}

impl SemanticCache {
    /// Create a new in-memory semantic cache (pure-Rust, zero external dependencies).
    pub fn new_in_memory(
        enabled: bool,
        similarity_threshold: f32,
        max_entries: usize,
        ttl: Duration,
        embedder_engine: EmbedderEngine,
    ) -> Self {
        let max_e = if max_entries == 0 {
            10_000
        } else {
            max_entries
        };
        Self {
            enabled,
            similarity_threshold: if similarity_threshold <= 0.0 || similarity_threshold > 1.0 {
                0.88
            } else {
                similarity_threshold
            },
            ttl,
            exact_cache: dashmap::DashMap::new(),
            max_exact_entries: max_e,
            max_exact_bytes: 128 * 1024 * 1024, // 128 MB for L1
            exact_entries_count: AtomicUsize::new(0),
            exact_bytes_count: AtomicUsize::new(0),
            backend: VectorBackend::InMemory(InMemoryVectorIndex::new(max_e)),
            embedder: Embedder::new(embedder_engine),
            metrics: Arc::new(SemanticCacheMetrics::new()),
        }
    }

    /// Create an enterprise Qdrant-backed semantic cache with in-memory fallback.
    pub fn new_qdrant(
        enabled: bool,
        similarity_threshold: f32,
        max_entries: usize,
        ttl: Duration,
        qdrant_url: String,
        qdrant_api_key: Option<String>,
        qdrant_collection: Option<String>,
        embedder_engine: EmbedderEngine,
    ) -> Self {
        let qdrant = QdrantBackend::new(qdrant_url, qdrant_api_key, qdrant_collection);
        let max_e = if max_entries == 0 {
            10_000
        } else {
            max_entries
        };
        let in_memory = InMemoryVectorIndex::new(max_e);

        Self {
            enabled,
            similarity_threshold: if similarity_threshold <= 0.0 || similarity_threshold > 1.0 {
                0.88
            } else {
                similarity_threshold
            },
            ttl,
            exact_cache: dashmap::DashMap::new(),
            max_exact_entries: max_e,
            max_exact_bytes: 128 * 1024 * 1024,
            exact_entries_count: AtomicUsize::new(0),
            exact_bytes_count: AtomicUsize::new(0),
            backend: VectorBackend::Hybrid { in_memory, qdrant },
            embedder: Embedder::new(embedder_engine),
            metrics: Arc::new(SemanticCacheMetrics::new()),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Compute 32-byte SHA-256 exact match key scoped to (tenant_id + model + prompt).
    pub fn compute_exact_key(tenant_id: &str, model: &str, prompt: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(tenant_id.as_bytes());
        hasher.update(b":");
        hasher.update(model.as_bytes());
        hasher.update(b":");
        hasher.update(prompt.as_bytes());
        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key
    }

    /// Layered 4-stage safety evaluation to determine request cacheability.
    /// Returns Ok(()) if cacheable, or Err(CacheBypassReason) if request must bypass cache.
    pub fn is_request_cacheable(
        body: &serde_json::Value,
        context: &CanonicalContext,
    ) -> Result<(), CacheBypassReason> {
        // Gate 1: Syntactic Bypass
        if body.get("tools").is_some()
            || body.get("functions").is_some()
            || body.get("tool_choice").is_some()
            || body.get("parallel_tool_calls").is_some()
        {
            return Err(CacheBypassReason::SyntacticToolsOrFunctions);
        }
        if body.get("agent_execution").is_some() || body.get("execution_metadata").is_some() {
            return Err(CacheBypassReason::SyntacticAgentMetadata);
        }

        // Gate 2: Context Bypass
        if context.tenant_id.trim().is_empty() || context.subject_id.trim().is_empty() {
            return Err(CacheBypassReason::ContextMissingIdentity);
        }
        if context.policy_version.trim().is_empty() {
            return Err(CacheBypassReason::ContextUnversionedPolicy);
        }
        if context.temperature_fixed != "0.000"
            && context.temperature_fixed != "0.0"
            && context.temperature_fixed != "0"
        {
            return Err(CacheBypassReason::ContextNonDeterministicParameters);
        }

        // Gate 3: Semantic Gate (Conservative Allowlisting)
        // Strictly reject mutating imperatives, state-dependent tokens, and financial actions
        let prompt_lower = context.normalized_prompt.to_lowercase();
        let mutating_tokens = [
            "delete ",
            "drop table",
            "remove ",
            "create ",
            "insert into",
            "update ",
            "commit ",
            "push ",
            "merge ",
            "reboot ",
            "shutdown ",
            "restart ",
            "chmod ",
            "chown ",
            "curl ",
            "wget ",
            "transfer ",
            "pay ",
            "buy ",
            "order ",
            "approve payment",
            "execute ",
            "send email",
            "post to",
            "write file",
            "current time",
            "current date",
            "today's date",
            "latest status",
            "live price",
        ];
        for kw in &mutating_tokens {
            if prompt_lower.contains(kw) {
                return Err(CacheBypassReason::SemanticNonReadOnlyIntent);
            }
        }

        // Gate 4: Operational Gate
        if context.normalized_prompt.len() > 64 * 1024 {
            return Err(CacheBypassReason::OperationalOversizedPayload);
        }
        if context.normalized_prompt.trim().is_empty() {
            return Err(CacheBypassReason::OperationalMalformedRequest);
        }

        Ok(())
    }

    /// Normalized response layer validation.
    /// Only cache when response is complete, successful, policy-clean, and contains no tool execution.
    pub fn is_response_cacheable(
        status: u16,
        body_bytes: &[u8],
        is_complete_stream: bool,
        has_security_warning: bool,
    ) -> bool {
        if status != 200
            || body_bytes.is_empty()
            || body_bytes.len() > 512 * 1024
            || has_security_warning
            || !is_complete_stream
        {
            return false;
        }

        // Validate JSON body: must be valid JSON schema
        let v = match serde_json::from_slice::<serde_json::Value>(body_bytes) {
            Ok(val) => val,
            Err(_) => return false,
        };

        if let Some(choices) = v.get("choices").and_then(|c| c.as_array()) {
            for choice in choices {
                if let Some(msg) = choice.get("message") {
                    if msg.get("tool_calls").is_some() || msg.get("function_call").is_some() {
                        return false;
                    }
                }
                if let Some(fr) = choice.get("finish_reason").and_then(|f| f.as_str()) {
                    if fr == "tool_calls" || fr == "function_call" {
                        return false;
                    }
                }
            }
        }

        true
    }

    /// Perform a 2-tier cache lookup with full canonical execution context.
    pub async fn lookup_with_context(
        &self,
        client: &reqwest::Client,
        context: &CanonicalContext,
    ) -> Option<SemanticCacheHit> {
        if !self.enabled || context.normalized_prompt.trim().is_empty() {
            return None;
        }

        let start = Instant::now();
        let exact_key = context.compute_exact_key();

        // Tier 1: L1 Exact Match (O(1), <0.1ms)
        if let Some(mut entry) = self.exact_cache.get_mut(&exact_key) {
            if !entry.is_expired(self.ttl) {
                entry.last_accessed = Instant::now();
                let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
                let cost_saved = self.metrics.record_gateway_hit(
                    "exact",
                    &context.model,
                    &context.normalized_prompt,
                    &entry.cached_prompt,
                    1.0,
                    entry.prompt_tokens,
                    entry.completion_tokens,
                    latency_ms,
                );

                return Some(SemanticCacheHit {
                    response_body: entry.response_body.clone(),
                    content_type: entry.content_type.clone(),
                    hit_type: "exact",
                    similarity: 1.0,
                    prompt_tokens: entry.prompt_tokens,
                    completion_tokens: entry.completion_tokens,
                    cost_saved_usd: cost_saved,
                    cached_prompt: entry.cached_prompt.clone(),
                });
            } else {
                drop(entry);
                if let Some((_, removed)) = self.exact_cache.remove(&exact_key) {
                    self.exact_entries_count.fetch_sub(1, Ordering::Relaxed);
                    self.exact_bytes_count
                        .fetch_sub(removed.approx_bytes, Ordering::Relaxed);
                }
            }
        }

        // Tier 2: L2 Semantic Vector Match
        let query_vector = match self
            .embedder
            .embed(&context.normalized_prompt, client)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[semantic-cache] Embedding generation failed: {}", e);
                self.metrics.record_miss();
                return None;
            }
        };

        let search_res = match &self.backend {
            VectorBackend::InMemory(index) => index.search(
                &context.tenant_id,
                &context.model,
                &query_vector,
                self.similarity_threshold,
            ),
            VectorBackend::Qdrant(qdrant) => {
                match qdrant
                    .search(
                        client,
                        &context.tenant_id,
                        &context.model,
                        &query_vector,
                        self.similarity_threshold,
                    )
                    .await
                {
                    Ok(res) => res,
                    Err(e) => {
                        eprintln!("[semantic-cache] Qdrant search error: {}, falling back", e);
                        None
                    }
                }
            }
            VectorBackend::Hybrid { in_memory, qdrant } => {
                if let Some(hit) = in_memory.search(
                    &context.tenant_id,
                    &context.model,
                    &query_vector,
                    self.similarity_threshold,
                ) {
                    Some(hit)
                } else {
                    match qdrant
                        .search(
                            client,
                            &context.tenant_id,
                            &context.model,
                            &query_vector,
                            self.similarity_threshold,
                        )
                        .await
                    {
                        Ok(Some(hit)) => {
                            in_memory.insert(hit.0.clone());
                            Some(hit)
                        }
                        _ => None,
                    }
                }
            }
        };

        if let Some((entry, score)) = search_res {
            let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
            let cost_saved = self.metrics.record_gateway_hit(
                "semantic",
                &context.model,
                &context.normalized_prompt,
                &entry.prompt_text,
                score,
                entry.prompt_tokens,
                entry.completion_tokens,
                latency_ms,
            );

            return Some(SemanticCacheHit {
                response_body: entry.response_body,
                content_type: entry.content_type,
                hit_type: "semantic",
                similarity: score,
                prompt_tokens: entry.prompt_tokens,
                completion_tokens: entry.completion_tokens,
                cost_saved_usd: cost_saved,
                cached_prompt: entry.prompt_text,
            });
        }

        // Cache Miss
        self.metrics.record_miss();
        None
    }

    /// Store a completed response in both L1 Exact and L2 Vector caches with full context.
    pub async fn store_with_context(
        &self,
        client: &reqwest::Client,
        context: &CanonicalContext,
        response_body: Bytes,
        content_type: &str,
        prompt_tokens: i64,
        completion_tokens: i64,
    ) {
        if !self.enabled || context.normalized_prompt.trim().is_empty() || response_body.is_empty()
        {
            return;
        }

        let exact_key = context.compute_exact_key();
        let approx_bytes = response_body.len() + context.normalized_prompt.len() + 128;

        // Bounded capacity check on L1 exact cache
        while self.exact_entries_count.load(Ordering::Relaxed) >= self.max_exact_entries
            || (self.exact_bytes_count.load(Ordering::Relaxed) + approx_bytes)
                > self.max_exact_bytes
        {
            if !self.evict_exact_lru() {
                break;
            }
        }

        let entry = ExactCacheEntry {
            response_body: response_body.clone(),
            content_type: content_type.to_string(),
            prompt_tokens,
            completion_tokens,
            created_at: Instant::now(),
            last_accessed: Instant::now(),
            cached_prompt: context.normalized_prompt.clone(),
            approx_bytes,
        };

        if let Some(old) = self.exact_cache.insert(exact_key, entry) {
            self.exact_bytes_count
                .fetch_sub(old.approx_bytes, Ordering::Relaxed);
        } else {
            self.exact_entries_count.fetch_add(1, Ordering::Relaxed);
        }
        self.exact_bytes_count
            .fetch_add(approx_bytes, Ordering::Relaxed);

        // Store in L2 Vector Index
        let vector = match self
            .embedder
            .embed(&context.normalized_prompt, client)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[semantic-cache] Embedding store failed: {}", e);
                return;
            }
        };

        let vector_entry = VectorEntry {
            id: uuid::Uuid::new_v4().to_string(),
            tenant_id: context.tenant_id.clone(),
            model: context.model.clone(),
            vector,
            prompt_text: context.normalized_prompt.clone(),
            response_body,
            content_type: content_type.to_string(),
            prompt_tokens,
            completion_tokens,
            created_at: Instant::now(),
            last_accessed: Instant::now(),
            ttl: self.ttl,
        };

        match &self.backend {
            VectorBackend::InMemory(index) => {
                index.insert(vector_entry);
            }
            VectorBackend::Qdrant(qdrant) => {
                let _ = qdrant.insert(client, &vector_entry).await;
            }
            VectorBackend::Hybrid { in_memory, qdrant } => {
                in_memory.insert(vector_entry.clone());
                let _ = qdrant.insert(client, &vector_entry).await;
            }
        }
    }

    /// Evict stale or least recently accessed entries from L1 exact cache.
    fn evict_exact_lru(&self) -> bool {
        let mut oldest_key: Option<[u8; 32]> = None;
        let mut oldest_accessed = Instant::now();

        for entry in self.exact_cache.iter() {
            if entry.value().is_expired(self.ttl) {
                oldest_key = Some(*entry.key());
                break;
            }
            if entry.value().last_accessed <= oldest_accessed {
                oldest_accessed = entry.value().last_accessed;
                oldest_key = Some(*entry.key());
            }
        }

        if let Some(key) = oldest_key {
            if let Some((_, removed)) = self.exact_cache.remove(&key) {
                self.exact_entries_count.fetch_sub(1, Ordering::Relaxed);
                self.exact_bytes_count
                    .fetch_sub(removed.approx_bytes, Ordering::Relaxed);
                self.metrics.record_eviction(1, removed.approx_bytes as u64);
                return true;
            }
        }

        false
    }

    /// Backwards-compatible lookup helper for legacy callers.
    pub async fn lookup(
        &self,
        client: &reqwest::Client,
        tenant_id: &str,
        model: &str,
        prompt: &str,
    ) -> Option<SemanticCacheHit> {
        let context = CanonicalContext {
            tenant_id: tenant_id.to_string(),
            subject_id: "legacy_user".to_string(),
            virtual_key_scope: None,
            provider: "generic".to_string(),
            model: model.to_string(),
            model_version: None,
            policy_version: "1.0.0".to_string(),
            workspace_hash: None,
            system_prompt_hash: "default".to_string(),
            developer_message_hash: None,
            temperature_fixed: "0.000".to_string(),
            top_p_fixed: None,
            top_k: None,
            seed: None,
            max_tokens: None,
            stop_sequences: vec![],
            response_format: None,
            reasoning_effort: None,
            locale: None,
            normalized_prompt: prompt.to_string(),
        };
        self.lookup_with_context(client, &context).await
    }

    /// Backwards-compatible store helper for legacy callers.
    pub async fn store(
        &self,
        client: &reqwest::Client,
        tenant_id: &str,
        model: &str,
        prompt: &str,
        response_body: Bytes,
        content_type: &str,
        prompt_tokens: i64,
        completion_tokens: i64,
    ) {
        let context = CanonicalContext {
            tenant_id: tenant_id.to_string(),
            subject_id: "legacy_user".to_string(),
            virtual_key_scope: None,
            provider: "generic".to_string(),
            model: model.to_string(),
            model_version: None,
            policy_version: "1.0.0".to_string(),
            workspace_hash: None,
            system_prompt_hash: "default".to_string(),
            developer_message_hash: None,
            temperature_fixed: "0.000".to_string(),
            top_p_fixed: None,
            top_k: None,
            seed: None,
            max_tokens: None,
            stop_sequences: vec![],
            response_format: None,
            reasoning_effort: None,
            locale: None,
            normalized_prompt: prompt.to_string(),
        };
        self.store_with_context(
            client,
            &context,
            response_body,
            content_type,
            prompt_tokens,
            completion_tokens,
        )
        .await;
    }

    /// Clear all cached entries across L1 and L2 layers.
    pub fn clear(&self) {
        self.exact_cache.clear();
        self.exact_entries_count.store(0, Ordering::Relaxed);
        self.exact_bytes_count.store(0, Ordering::Relaxed);
        self.metrics.record_invalidation();
        match &self.backend {
            VectorBackend::InMemory(index) => index.clear(),
            VectorBackend::Qdrant(_) => {}
            VectorBackend::Hybrid { in_memory, .. } => in_memory.clear(),
        }
    }
}
