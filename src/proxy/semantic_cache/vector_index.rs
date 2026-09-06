//! Pure-Rust In-Memory Vector Index for Semantic Prompt Caching
//!
//! Stores L2-normalized prompt embeddings partitioned by (tenant_id, model).
//! Performs fast SIMD-friendly cosine similarity searches with zero external dependencies,
//! providing sub-millisecond retrieval across Windows, Linux, and macOS.

use bytes::Bytes;
use dashmap::DashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct VectorEntry {
    pub id: String,
    pub tenant_id: String,
    pub model: String,
    pub vector: Vec<f32>, // L2-normalized
    pub prompt_text: String,
    pub response_body: Bytes,
    pub content_type: String,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub created_at: Instant,
    pub ttl: Duration,
}

impl VectorEntry {
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > self.ttl
    }
}

pub struct InMemoryVectorIndex {
    // Partitioned by (tenant_id, model) namespace for strict tenant isolation
    partitions: DashMap<(String, String), Vec<VectorEntry>>,
    max_entries: usize,
    entry_count: AtomicUsize,
}

impl InMemoryVectorIndex {
    pub fn new(max_entries: usize) -> Self {
        Self {
            partitions: DashMap::new(),
            max_entries: if max_entries == 0 { 10_000 } else { max_entries },
            entry_count: AtomicUsize::new(0),
        }
    }

    /// Compute cosine similarity between two normalized vectors (dot product).
    #[inline]
    pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
        if a.len() != b.len() || a.is_empty() {
            return 0.0;
        }
        let mut dot = 0.0f32;
        for (x, y) in a.iter().zip(b.iter()) {
            dot += x * y;
        }
        dot.clamp(-1.0, 1.0)
    }

    /// L2 normalize a vector in-place so dot product equals cosine similarity.
    pub fn normalize_vector(v: &mut [f32]) {
        let norm_sq: f32 = v.iter().map(|x| x * x).sum();
        let norm = norm_sq.sqrt();
        if norm > 1e-9 {
            let inv = 1.0 / norm;
            for x in v.iter_mut() {
                *x *= inv;
            }
        }
    }

    /// Search for nearest semantic neighbor within the tenant and model partition.
    pub fn search(
        &self,
        tenant_id: &str,
        model: &str,
        query_vector: &[f32],
        similarity_threshold: f32,
    ) -> Option<(VectorEntry, f32)> {
        let key = (tenant_id.to_string(), model.to_string());
        let partition = self.partitions.get(&key)?;

        let mut best_entry: Option<VectorEntry> = None;
        let mut best_score: f32 = -1.0;

        for entry in partition.iter() {
            if entry.is_expired() {
                continue;
            }
            let sim = Self::cosine_similarity(&entry.vector, query_vector);
            if sim >= similarity_threshold && sim > best_score {
                best_score = sim;
                best_entry = Some(entry.clone());
            }
        }

        best_entry.map(|e| (e, best_score))
    }

    /// Insert a new vector entry with capacity eviction.
    pub fn insert(&self, mut entry: VectorEntry) {
        Self::normalize_vector(&mut entry.vector);
        let key = (entry.tenant_id.clone(), entry.model.clone());

        // Capacity check & eviction
        if self.entry_count.load(Ordering::Relaxed) >= self.max_entries {
            self.evict_stale_or_oldest();
        }

        let mut partition = self.partitions.entry(key).or_default();
        // Remove existing entry with same id if updating
        if let Some(pos) = partition.iter().position(|e| e.id == entry.id) {
            partition.remove(pos);
            self.entry_count.fetch_sub(1, Ordering::Relaxed);
        }

        partition.push(entry);
        self.entry_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Evict expired entries across partitions; if none expired, evict oldest entry.
    fn evict_stale_or_oldest(&self) {
        let mut evicted = false;

        for mut part in self.partitions.iter_mut() {
            let before = part.len();
            part.retain(|e| !e.is_expired());
            let removed = before - part.len();
            if removed > 0 {
                self.entry_count.fetch_sub(removed, Ordering::Relaxed);
                evicted = true;
            }
        }

        // If no expired entries, evict the oldest entry from the largest partition
        if !evicted {
            if let Some(mut largest) = self.partitions.iter_mut().max_by_key(|p| p.value().len()) {
                if !largest.is_empty() {
                    largest.remove(0);
                    self.entry_count.fetch_sub(1, Ordering::Relaxed);
                }
            }
        }
    }

    /// Clear all entries.
    pub fn clear(&self) {
        self.partitions.clear();
        self.entry_count.store(0, Ordering::Relaxed);
    }

    /// Get current total count of cached vectors.
    pub fn total_entries(&self) -> usize {
        self.entry_count.load(Ordering::Relaxed)
    }
}
