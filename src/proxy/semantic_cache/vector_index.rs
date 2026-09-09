//! Pure-Rust In-Memory Vector Index for Semantic Prompt Caching
//!
//! Stores L2-normalized prompt embeddings partitioned by (tenant_id, model).
//! Performs fast SIMD-friendly cosine similarity searches with zero external dependencies,
//! providing sub-millisecond retrieval across Windows, Linux, and macOS.
//!
//! Enforces dual capacity bounds (max entries and max total memory bytes) with
//! bounded approximate LRU eviction and strict payload size validation.

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
    pub last_accessed: Instant,
    pub ttl: Duration,
}

impl VectorEntry {
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > self.ttl
    }

    /// Calculate approximate in-memory footprint of this entry in bytes.
    pub fn approximate_size_bytes(&self) -> usize {
        self.id.len()
            + self.tenant_id.len()
            + self.model.len()
            + (self.vector.len() * std::mem::size_of::<f32>())
            + self.prompt_text.len()
            + self.response_body.len()
            + self.content_type.len()
            + 64 // struct overhead
    }
}

pub struct InMemoryVectorIndex {
    // Partitioned by (tenant_id, model) namespace for strict tenant isolation
    partitions: DashMap<(String, String), Vec<VectorEntry>>,
    max_entries: usize,
    max_total_bytes: usize,
    max_prompt_bytes: usize,
    max_response_bytes: usize,
    entry_count: AtomicUsize,
    total_bytes: AtomicUsize,
}

impl InMemoryVectorIndex {
    pub fn new(max_entries: usize) -> Self {
        Self::with_limits(
            max_entries,
            256 * 1024 * 1024, // 256 MB default
            64 * 1024,         // 64 KB max prompt
            512 * 1024,        // 512 KB max response
        )
    }

    pub fn with_limits(
        max_entries: usize,
        max_total_bytes: usize,
        max_prompt_bytes: usize,
        max_response_bytes: usize,
    ) -> Self {
        Self {
            partitions: DashMap::new(),
            max_entries: if max_entries == 0 {
                10_000
            } else {
                max_entries
            },
            max_total_bytes: if max_total_bytes == 0 {
                256 * 1024 * 1024
            } else {
                max_total_bytes
            },
            max_prompt_bytes: if max_prompt_bytes == 0 {
                64 * 1024
            } else {
                max_prompt_bytes
            },
            max_response_bytes: if max_response_bytes == 0 {
                512 * 1024
            } else {
                max_response_bytes
            },
            entry_count: AtomicUsize::new(0),
            total_bytes: AtomicUsize::new(0),
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
    /// Safely handles zero-length, NaN, and near-zero vectors.
    pub fn normalize_vector(v: &mut [f32]) {
        let norm_sq: f32 = v.iter().map(|x| x * x).sum();
        let norm = norm_sq.sqrt();
        if !norm.is_nan() && norm > 1e-9 {
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
        let mut partition = self.partitions.get_mut(&key)?;

        let mut best_idx: Option<usize> = None;
        let mut best_score: f32 = -1.0;

        for (idx, entry) in partition.iter().enumerate() {
            if entry.is_expired() {
                continue;
            }
            let sim = Self::cosine_similarity(&entry.vector, query_vector);
            if sim >= similarity_threshold && sim > best_score {
                best_score = sim;
                best_idx = Some(idx);
            }
        }

        if let Some(idx) = best_idx {
            // Update last_accessed timestamp for approximate LRU
            partition[idx].last_accessed = Instant::now();
            let entry_clone = partition[idx].clone();
            Some((entry_clone, best_score))
        } else {
            None
        }
    }

    /// Insert a new vector entry with capacity eviction.
    /// Rejects oversized payloads exceeding configured limits.
    pub fn insert(&self, mut entry: VectorEntry) -> bool {
        if entry.prompt_text.len() > self.max_prompt_bytes
            || entry.response_body.len() > self.max_response_bytes
            || entry.vector.len() > 1536
            || entry.vector.is_empty()
        {
            return false;
        }

        Self::normalize_vector(&mut entry.vector);
        let entry_bytes = entry.approximate_size_bytes();
        let key = (entry.tenant_id.clone(), entry.model.clone());

        // Capacity check & eviction (entry count or total bytes limit)
        while self.entry_count.load(Ordering::Relaxed) >= self.max_entries
            || (self.total_bytes.load(Ordering::Relaxed) + entry_bytes) > self.max_total_bytes
        {
            if !self.evict_stale_or_oldest() {
                // If unable to evict any entries (e.g. single huge entry filling cache), reject insert safely
                if (self.total_bytes.load(Ordering::Relaxed) + entry_bytes) > self.max_total_bytes {
                    return false;
                }
                break;
            }
        }

        let mut partition = self.partitions.entry(key).or_default();
        // Remove existing entry with same id if updating
        if let Some(pos) = partition.iter().position(|e| e.id == entry.id) {
            let old_bytes = partition[pos].approximate_size_bytes();
            partition.remove(pos);
            self.entry_count.fetch_sub(1, Ordering::Relaxed);
            self.total_bytes.fetch_sub(old_bytes, Ordering::Relaxed);
        }

        partition.push(entry);
        self.entry_count.fetch_add(1, Ordering::Relaxed);
        self.total_bytes.fetch_add(entry_bytes, Ordering::Relaxed);
        true
    }

    /// Evict expired entries across partitions; if none expired, evict oldest entry from largest partition.
    /// Returns true if at least one entry was evicted.
    fn evict_stale_or_oldest(&self) -> bool {
        let mut freed_entries = 0usize;
        let mut freed_bytes = 0usize;

        for mut part in self.partitions.iter_mut() {
            let mut retained = Vec::with_capacity(part.len());
            for e in part.drain(..) {
                if e.is_expired() {
                    freed_entries += 1;
                    freed_bytes += e.approximate_size_bytes();
                } else {
                    retained.push(e);
                }
            }
            *part = retained;
        }

        if freed_entries > 0 {
            self.entry_count.fetch_sub(freed_entries, Ordering::Relaxed);
            self.total_bytes.fetch_sub(freed_bytes, Ordering::Relaxed);
            return true;
        }

        // If no expired entries, evict the entry with the oldest last_accessed in the largest partition
        if let Some(mut largest) = self.partitions.iter_mut().max_by_key(|p| p.value().len()) {
            if !largest.is_empty() {
                // Find index of oldest accessed entry
                let oldest_idx = largest
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, e)| e.last_accessed)
                    .map(|(idx, _)| idx)
                    .unwrap_or(0);

                let removed = largest.remove(oldest_idx);
                let bytes = removed.approximate_size_bytes();
                self.entry_count.fetch_sub(1, Ordering::Relaxed);
                self.total_bytes.fetch_sub(bytes, Ordering::Relaxed);
                return true;
            }
        }

        false
    }

    /// Clear all entries.
    pub fn clear(&self) {
        self.partitions.clear();
        self.entry_count.store(0, Ordering::Relaxed);
        self.total_bytes.store(0, Ordering::Relaxed);
    }

    /// Get current total count of cached vectors.
    pub fn total_entries(&self) -> usize {
        self.entry_count.load(Ordering::Relaxed)
    }

    /// Get current total estimated bytes allocated in index.
    pub fn total_bytes(&self) -> usize {
        self.total_bytes.load(Ordering::Relaxed)
    }
}
