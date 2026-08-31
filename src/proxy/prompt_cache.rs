//! Tenant-scoped exact prompt caching (Pillar 1)
//!
//! Keys are hashed using SHA-256 over (tenant_id + ":" + virtual_key_id + ":" + model + ":" + normalized_prompt).
//! Responses are stored as reference-counted `bytes::Bytes` for zero-copy hot path serving.

use bytes::Bytes;
use dashmap::DashMap;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct CachedPromptEntry {
    pub response_body: Bytes,
    pub content_type: String,
    pub created_at: Instant,
    pub ttl: Duration,
    pub model: String,
}

pub struct PromptCache {
    entries: DashMap<[u8; 32], CachedPromptEntry>,
    max_entries: usize,
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
}

impl Default for PromptCache {
    fn default() -> Self {
        Self::new(10_000)
    }
}

impl PromptCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: DashMap::new(),
            max_entries: if max_entries == 0 { 10_000 } else { max_entries },
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
        }
    }

    /// Compute a secure 32-byte SHA-256 hash preventing cross-tenant or cross-key collision.
    pub fn compute_key(
        tenant_id: &str,
        virtual_key_id: &str,
        model: &str,
        normalized_prompt: &str,
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(tenant_id.as_bytes());
        hasher.update(b":");
        hasher.update(virtual_key_id.as_bytes());
        hasher.update(b":");
        hasher.update(model.as_bytes());
        hasher.update(b":");
        hasher.update(normalized_prompt.as_bytes());
        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key
    }

    /// Look up an entry. Returns None if missing or expired.
    pub fn get(&self, key: &[u8; 32]) -> Option<CachedPromptEntry> {
        if let Some(entry) = self.entries.get(key) {
            if entry.created_at.elapsed() <= entry.ttl {
                self.hits.fetch_add(1, Ordering::Relaxed);
                return Some(entry.clone());
            } else {
                drop(entry);
                self.entries.remove(key);
                self.evictions.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Insert or update an entry with capacity eviction.
    pub fn insert(
        &self,
        key: [u8; 32],
        response_body: Bytes,
        content_type: String,
        ttl: Duration,
        model: String,
    ) {
        if self.entries.len() >= self.max_entries {
            // Evict expired or arbitrary key
            if let Some(first_key) = self.entries.iter().next().map(|r| *r.key()) {
                self.entries.remove(&first_key);
                self.evictions.fetch_add(1, Ordering::Relaxed);
            }
        }

        self.entries.insert(
            key,
            CachedPromptEntry {
                response_body,
                content_type,
                created_at: Instant::now(),
                ttl,
                model,
            },
        );
    }

    /// Invalidate entries for a specific key hash or flush all
    pub fn invalidate(&self, key: &[u8; 32]) {
        self.entries.remove(key);
    }

    pub fn clear(&self) {
        self.entries.clear();
    }

    pub fn stats(&self) -> (u64, u64, u64, usize) {
        (
            self.hits.load(Ordering::Relaxed),
            self.misses.load(Ordering::Relaxed),
            self.evictions.load(Ordering::Relaxed),
            self.entries.len(),
        )
    }
}
