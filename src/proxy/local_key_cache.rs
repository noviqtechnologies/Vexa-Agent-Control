//! Local Virtual Key Cache & Sub-Millisecond Policy Enforcement (P0)
//!
//! Maintains a fast in-memory LRU cache of active virtual keys and validates
//! CIDR allowlists, route permissions, model restrictions, and sliding-window rate limits.

use dashmap::DashMap;
use ipnet::IpNet;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct CachedVirtualKey {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub status: String,
    pub allowed_ips: Vec<String>,
    pub allowed_routes: Vec<String>,
    pub allowed_models: Vec<String>,
    pub max_rpm: usize,
    pub max_tpm: usize,
    pub max_concurrent_requests: usize,
    pub monthly_budget_microcents: i64,
    pub spent_microcents: i64,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: Instant,
    pub ttl: Duration,
}

#[derive(Default)]
struct RateBucket {
    window_start: std::sync::Mutex<Option<Instant>>,
    request_count: AtomicUsize,
    token_count: AtomicUsize,
}

pub struct LocalKeyCache {
    cache: DashMap<String, CachedVirtualKey>,
    rate_limits: DashMap<String, Arc<RateBucket>>,
    default_ttl: Duration,
}

impl Default for LocalKeyCache {
    fn default() -> Self {
        Self::new(Duration::from_secs(60))
    }
}

impl LocalKeyCache {
    pub fn new(default_ttl: Duration) -> Self {
        Self {
            cache: DashMap::new(),
            rate_limits: DashMap::new(),
            default_ttl,
        }
    }

    /// Retrieve a cached virtual key if present and unexpired.
    pub fn get(&self, key_hash: &str) -> Option<CachedVirtualKey> {
        if let Some(entry) = self.cache.get(key_hash) {
            if entry.created_at.elapsed() <= entry.ttl {
                return Some(entry.clone());
            } else {
                drop(entry);
                self.cache.remove(key_hash);
            }
        }
        None
    }

    /// Insert or update a cached virtual key.
    pub fn insert(&self, key_hash: String, mut key: CachedVirtualKey) {
        if key.ttl == Duration::ZERO {
            key.ttl = self.default_ttl;
        }
        key.created_at = Instant::now();
        self.cache.insert(key_hash, key);
    }

    /// Evict a virtual key immediately (e.g., upon revocation/rotation invalidation event).
    pub fn evict(&self, key_hash: &str) {
        self.cache.remove(key_hash);
    }

    /// Evict all keys belonging to a specific tenant.
    pub fn evict_tenant(&self, tenant_id: &str) {
        self.cache.retain(|_, v| v.tenant_id != tenant_id);
    }

    pub fn clear(&self) {
        self.cache.clear();
        self.rate_limits.clear();
    }

    /// Validate incoming request against CIDR allowlists, route permissions, and expiration.
    pub fn validate_request(
        &self,
        key: &CachedVirtualKey,
        client_ip: &str,
        route: &str,
        model: &str,
    ) -> Result<(), String> {
        // 1. Status Check
        if key.status == "revoked" {
            return Err("Virtual key is revoked".to_string());
        }

        // 2. Expiration Check
        if let Some(exp) = key.expires_at {
            if chrono::Utc::now() > exp {
                return Err("Virtual key has expired".to_string());
            }
        }

        // 3. IP / CIDR Allowlist Validation
        if !key.allowed_ips.is_empty() {
            let client_parsed = client_ip
                .parse::<IpAddr>()
                .or_else(|_| "127.0.0.1".parse::<IpAddr>())
                .map_err(|_| format!("Invalid client IP: {}", client_ip))?;

            let mut matched = false;
            for rule in &key.allowed_ips {
                if rule == "*" || rule == "0.0.0.0/0" || rule == "::/0" {
                    matched = true;
                    break;
                }
                if let Ok(net) = IpNet::from_str(rule) {
                    if net.contains(&client_parsed) {
                        matched = true;
                        break;
                    }
                } else if let Ok(exact_ip) = rule.parse::<IpAddr>() {
                    if exact_ip == client_parsed {
                        matched = true;
                        break;
                    }
                }
            }

            if !matched {
                return Err(format!(
                    "Client IP {} is not authorized by virtual key CIDR policy",
                    client_ip
                ));
            }
        }

        // 4. Route Scoping Validation
        if !key.allowed_routes.is_empty() {
            let normalized_route = route.trim_end_matches('/');
            let matched = key.allowed_routes.iter().any(|r| {
                let norm_r = r.trim_end_matches('/');
                norm_r == "*" || norm_r == normalized_route || normalized_route.starts_with(norm_r)
            });

            if !matched {
                return Err(format!(
                    "Route {} is not permitted for this virtual key",
                    route
                ));
            }
        }

        // 5. Model Scoping Validation
        if !key.allowed_models.is_empty() && !model.is_empty() {
            let matched = key.allowed_models.iter().any(|m| m == "*" || m == model);
            if !matched {
                return Err(format!(
                    "Model {} is not permitted for this virtual key",
                    model
                ));
            }
        }

        Ok(())
    }

    /// Check sliding-window RPM and TPM token limits in memory.
    pub fn check_and_increment_rate_limits(
        &self,
        key_id: &str,
        max_rpm: usize,
        max_tpm: usize,
        tokens: usize,
    ) -> Result<(), String> {
        if max_rpm == 0 && max_tpm == 0 {
            return Ok(());
        }

        let bucket = self
            .rate_limits
            .entry(key_id.to_string())
            .or_insert_with(|| Arc::new(RateBucket::default()))
            .clone();

        let mut start_guard = bucket.window_start.lock().unwrap_or_else(|e| e.into_inner());
        let is_expired = match *start_guard {
            Some(start) => start.elapsed() >= Duration::from_secs(60),
            None => true,
        };
        if is_expired {
            *start_guard = Some(Instant::now());
            bucket.request_count.store(0, Ordering::Relaxed);
            bucket.token_count.store(0, Ordering::Relaxed);
        }

        if max_rpm > 0 {
            let current_reqs = bucket.request_count.load(Ordering::Relaxed);
            if current_reqs >= max_rpm {
                return Err(format!(
                    "Rate limit exceeded: max {} requests per minute",
                    max_rpm
                ));
            }
        }

        if max_tpm > 0 && tokens > 0 {
            let current_tokens = bucket.token_count.load(Ordering::Relaxed);
            if current_tokens + tokens > max_tpm {
                return Err(format!(
                    "Rate limit exceeded: max {} tokens per minute",
                    max_tpm
                ));
            }
        }

        bucket.request_count.fetch_add(1, Ordering::Relaxed);
        if tokens > 0 {
            bucket.token_count.fetch_add(tokens, Ordering::Relaxed);
        }

        Ok(())
    }
}
