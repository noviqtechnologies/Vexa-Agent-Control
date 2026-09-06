//! Enterprise Semantic Caching Engine for Vexa Agent Control
//!
//! Multi-tiered caching architecture combining:
//! - Tier 1: Sub-millisecond exact SHA-256 match cache (L1)
//! - Tier 2: Vector cosine similarity cache using In-Memory HNSW or remote Qdrant clusters (L2)
//!
//! Features strict tenant/model isolation, differentiated token economics, and sub-3ms response times.

pub mod embedder;
pub mod metrics;
pub mod qdrant;
pub mod vector_index;

use bytes::Bytes;
use embedder::{Embedder, EmbedderEngine};
use metrics::SemanticCacheMetrics;
use qdrant::QdrantBackend;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{Duration, Instant};
use vector_index::{InMemoryVectorIndex, VectorEntry};

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
    exact_cache: dashmap::DashMap<[u8; 32], (Bytes, String, i64, i64, Instant, String)>,
    backend: VectorBackend,
    embedder: Embedder,
    pub metrics: Arc<SemanticCacheMetrics>,
}

impl Default for SemanticCache {
    fn default() -> Self {
        Self::new_in_memory(true, 0.88, 10_000, Duration::from_secs(86400), EmbedderEngine::Local)
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
        Self {
            enabled,
            similarity_threshold: if similarity_threshold <= 0.0 || similarity_threshold > 1.0 {
                0.88
            } else {
                similarity_threshold
            },
            ttl,
            exact_cache: dashmap::DashMap::new(),
            backend: VectorBackend::InMemory(InMemoryVectorIndex::new(max_entries)),
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
        let in_memory = InMemoryVectorIndex::new(max_entries);

        Self {
            enabled,
            similarity_threshold: if similarity_threshold <= 0.0 || similarity_threshold > 1.0 {
                0.88
            } else {
                similarity_threshold
            },
            ttl,
            exact_cache: dashmap::DashMap::new(),
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

    /// Perform a 2-tier cache lookup (L1 Exact Hash -> L2 Semantic Vector).
    pub async fn lookup(
        &self,
        client: &reqwest::Client,
        tenant_id: &str,
        model: &str,
        prompt: &str,
    ) -> Option<SemanticCacheHit> {
        if !self.enabled || prompt.trim().is_empty() {
            return None;
        }

        let start = Instant::now();

        // Tier 1: L1 Exact Match (O(1), <0.1ms)
        let exact_key = Self::compute_exact_key(tenant_id, model, prompt);
        if let Some(entry) = self.exact_cache.get(&exact_key) {
            let (body, content_type, p_tok, c_tok, created_at, cached_prompt) = entry.value();
            if created_at.elapsed() <= self.ttl {
                let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
                let cost_saved = self.metrics.record_gateway_hit(
                    "exact",
                    model,
                    prompt,
                    cached_prompt,
                    1.0,
                    *p_tok,
                    *c_tok,
                    latency_ms,
                );

                return Some(SemanticCacheHit {
                    response_body: body.clone(),
                    content_type: content_type.clone(),
                    hit_type: "exact",
                    similarity: 1.0,
                    prompt_tokens: *p_tok,
                    completion_tokens: *c_tok,
                    cost_saved_usd: cost_saved,
                    cached_prompt: cached_prompt.clone(),
                });
            } else {
                drop(entry);
                self.exact_cache.remove(&exact_key);
            }
        }

        // Tier 2: L2 Semantic Vector Match
        let query_vector = match self.embedder.embed(prompt, client).await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[semantic-cache] Embedding generation failed: {}", e);
                self.metrics.record_miss();
                return None;
            }
        };

        let search_res = match &self.backend {
            VectorBackend::InMemory(index) => {
                index.search(tenant_id, model, &query_vector, self.similarity_threshold)
            }
            VectorBackend::Qdrant(qdrant) => {
                match qdrant.search(client, tenant_id, model, &query_vector, self.similarity_threshold).await {
                    Ok(res) => res,
                    Err(e) => {
                        eprintln!("[semantic-cache] Qdrant search error: {}, falling back", e);
                        None
                    }
                }
            }
            VectorBackend::Hybrid { in_memory, qdrant } => {
                // Check local memory first for speed
                if let Some(hit) = in_memory.search(tenant_id, model, &query_vector, self.similarity_threshold) {
                    Some(hit)
                } else {
                    // Check remote Qdrant
                    match qdrant.search(client, tenant_id, model, &query_vector, self.similarity_threshold).await {
                        Ok(Some(hit)) => {
                            // Populate into local memory
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
                model,
                prompt,
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

    /// Store a completed response in both L1 Exact and L2 Vector caches.
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
        if !self.enabled || prompt.trim().is_empty() || response_body.is_empty() {
            return;
        }

        // 1. Store in L1 Exact Cache
        let exact_key = Self::compute_exact_key(tenant_id, model, prompt);
        self.exact_cache.insert(
            exact_key,
            (
                response_body.clone(),
                content_type.to_string(),
                prompt_tokens,
                completion_tokens,
                Instant::now(),
                prompt.to_string(),
            ),
        );

        // 2. Generate vector embedding
        let vector = match self.embedder.embed(prompt, client).await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[semantic-cache] Embedding store failed: {}", e);
                return;
            }
        };

        let entry = VectorEntry {
            id: uuid::Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_string(),
            model: model.to_string(),
            vector,
            prompt_text: prompt.to_string(),
            response_body,
            content_type: content_type.to_string(),
            prompt_tokens,
            completion_tokens,
            created_at: Instant::now(),
            ttl: self.ttl,
        };

        // 3. Store in L2 Vector Index
        match &self.backend {
            VectorBackend::InMemory(index) => {
                index.insert(entry);
            }
            VectorBackend::Qdrant(qdrant) => {
                let _ = qdrant.insert(client, &entry).await;
            }
            VectorBackend::Hybrid { in_memory, qdrant } => {
                in_memory.insert(entry.clone());
                let _ = qdrant.insert(client, &entry).await;
            }
        }
    }

    /// Clear all cached entries across L1 and L2 layers.
    pub fn clear(&self) {
        self.exact_cache.clear();
        match &self.backend {
            VectorBackend::InMemory(index) => index.clear(),
            VectorBackend::Qdrant(_) => {}
            VectorBackend::Hybrid { in_memory, .. } => in_memory.clear(),
        }
    }
}
