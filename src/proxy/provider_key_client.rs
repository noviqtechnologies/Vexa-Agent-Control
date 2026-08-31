//! Secure Provider Key Decryption Client (P0)
//!
//! Fetches decrypted provider keys at request time over HTTPS REST with mTLS/shared secret.
//! Decrypted keys are held in memory for up to 5 minutes and NEVER written to disk.

use dashmap::DashMap;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

#[derive(Serialize)]
struct DecryptRequest<'a> {
    tenant_id: &'a str,
    provider: &'a str,
}

#[derive(Deserialize)]
struct DecryptResponse {
    api_key: String,
}

#[derive(Clone)]
struct CachedKey {
    api_key: String,
    created_at: Instant,
    ttl: Duration,
}

pub struct ProviderKeyClient {
    client: Client,
    endpoint_url: String,
    auth_token: Option<String>,
    cache: DashMap<String, CachedKey>,
    cache_ttl: Duration,
}

impl ProviderKeyClient {
    pub fn new(endpoint_url: String, auth_token: Option<String>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .pool_idle_timeout(Duration::from_secs(60))
            .build()
            .unwrap_or_default();

        Self {
            client,
            endpoint_url,
            auth_token,
            cache: DashMap::new(),
            cache_ttl: Duration::from_secs(300), // 5 minutes
        }
    }

    /// Retrieve the decrypted provider key for a tenant and provider.
    pub async fn get_provider_key(&self, tenant_id: &str, provider: &str) -> Result<String, String> {
        let cache_key = format!("{}:{}", tenant_id, provider);

        // Check local cache
        if let Some(entry) = self.cache.get(&cache_key) {
            if entry.created_at.elapsed() <= entry.ttl {
                return Ok(entry.api_key.clone());
            } else {
                drop(entry);
                self.cache.remove(&cache_key);
            }
        }

        // Fetch from Control Plane
        let mut req = self.client.post(&self.endpoint_url).json(&DecryptRequest {
            tenant_id,
            provider,
        });

        if let Some(ref token) = self.auth_token {
            req = req.bearer_auth(token);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| format!("Failed to request provider key: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!(
                "Provider key decryption endpoint returned status {}",
                resp.status()
            ));
        }

        let body = resp
            .json::<DecryptResponse>()
            .await
            .map_err(|e| format!("Failed to parse provider key response: {}", e))?;

        // Cache in memory
        self.cache.insert(
            cache_key,
            CachedKey {
                api_key: body.api_key.clone(),
                created_at: Instant::now(),
                ttl: self.cache_ttl,
            },
        );

        Ok(body.api_key)
    }

    pub fn evict(&self, tenant_id: &str, provider: &str) {
        let cache_key = format!("{}:{}", tenant_id, provider);
        self.cache.remove(&cache_key);
    }
}
