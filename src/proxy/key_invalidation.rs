//! Real-Time Key Invalidation Subscriber (Zero-Redis Architecture)
//!
//! Subscribes to the Go Control Plane SSE stream (GET /api/v1/internal/invalidation-stream)
//! to immediately evict rotated or revoked virtual keys from the local in-memory cache.

use super::local_key_cache::LocalKeyCache;
use super::prompt_cache::PromptCache;
use futures_util::StreamExt;
use reqwest::Client;
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;

#[derive(Deserialize, Debug)]
pub struct InvalidationEvent {
    pub action: String, // "evict_key", "evict_tenant", "flush_all"
    pub key_hash: Option<String>,
    pub tenant_id: Option<String>,
}

pub struct KeyInvalidationSubscriber {
    stream_url: String,
    auth_token: Option<String>,
    key_cache: Arc<LocalKeyCache>,
    prompt_cache: Arc<PromptCache>,
}

impl KeyInvalidationSubscriber {
    pub fn new(
        stream_url: String,
        auth_token: Option<String>,
        key_cache: Arc<LocalKeyCache>,
        prompt_cache: Arc<PromptCache>,
    ) -> Self {
        Self {
            stream_url,
            auth_token,
            key_cache,
            prompt_cache,
        }
    }

    /// Spawns a background task maintaining the persistent SSE stream with reconnect backoff.
    pub fn start(self: Arc<Self>) {
        tokio::spawn(async move {
            let client = Client::builder()
                .tcp_keepalive(Duration::from_secs(30))
                .build()
                .unwrap_or_default();

            let mut backoff = Duration::from_secs(1);

            loop {
                let mut req = client.get(&self.stream_url);
                if let Some(ref token) = self.auth_token {
                    req = req.bearer_auth(token);
                }

                match req.send().await {
                    Ok(resp) if resp.status().is_success() => {
                        backoff = Duration::from_secs(1); // Reset backoff on successful connect
                        let mut stream = resp.bytes_stream();

                        while let Some(chunk_res) = stream.next().await {
                            match chunk_res {
                                Ok(chunk) => {
                                    let text = String::from_utf8_lossy(&chunk);
                                    for line in text.lines() {
                                        if let Some(data_json) = line.strip_prefix("data: ") {
                                            if let Ok(event) =
                                                serde_json::from_str::<InvalidationEvent>(data_json.trim())
                                            {
                                                self.handle_event(event);
                                            }
                                        }
                                    }
                                }
                                Err(_) => break, // Stream error, reconnect
                            }
                        }
                    }
                    _ => {
                        // Connection failed or non-200
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(Duration::from_secs(30));
                    }
                }
            }
        });
    }

    fn handle_event(&self, event: InvalidationEvent) {
        match event.action.as_str() {
            "evict_key" => {
                if let Some(hash) = event.key_hash {
                    self.key_cache.evict(&hash);
                }
            }
            "evict_tenant" => {
                if let Some(tid) = event.tenant_id {
                    self.key_cache.evict_tenant(&tid);
                }
            }
            "flush_all" => {
                self.key_cache.clear();
                self.prompt_cache.clear();
            }
            _ => {}
        }
    }
}
