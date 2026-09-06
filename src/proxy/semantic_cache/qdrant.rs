//! Qdrant REST Vector Database Backend for Enterprise Semantic Caching
//!
//! Communicates with Qdrant clusters via standard HTTP REST using `reqwest`.
//! Eliminates native C++/protoc/gRPC dependencies while delivering full enterprise Qdrant vector clustering.

use base64::Engine;
use bytes::Bytes;
use serde_json::json;
use std::time::{Duration, Instant};

pub struct QdrantBackend {
    url: String,
    api_key: Option<String>,
    collection: String,
}

impl QdrantBackend {
    pub fn new(url: String, api_key: Option<String>, collection: Option<String>) -> Self {
        Self {
            url: url.trim_end_matches('/').to_string(),
            api_key,
            collection: collection.unwrap_or_else(|| "vexa_semantic_cache".to_string()),
        }
    }

    /// Search for nearest semantic match in Qdrant with tenant and model filtering.
    pub async fn search(
        &self,
        client: &reqwest::Client,
        tenant_id: &str,
        model: &str,
        query_vector: &[f32],
        similarity_threshold: f32,
    ) -> Result<Option<(super::vector_index::VectorEntry, f32)>, String> {
        let endpoint = format!("{}/collections/{}/points/search", self.url, self.collection);

        let query_body = json!({
            "vector": query_vector,
            "limit": 1,
            "score_threshold": similarity_threshold,
            "with_payload": true,
            "filter": {
                "must": [
                    {
                        "key": "tenant_id",
                        "match": { "value": tenant_id }
                    },
                    {
                        "key": "model",
                        "match": { "value": model }
                    }
                ]
            }
        });

        let mut req = client.post(&endpoint).json(&query_body);
        if let Some(ref key) = self.api_key {
            req = req.header("api-key", key);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| format!("Qdrant search request failed: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!("Qdrant search returned HTTP {}", resp.status()));
        }

        let json_resp: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("Invalid Qdrant JSON: {}", e))?;

        if let Some(result_arr) = json_resp.get("result").and_then(|r| r.as_array()) {
            if let Some(top) = result_arr.first() {
                let score = top.get("score").and_then(|s| s.as_f64()).unwrap_or(0.0) as f32;
                if score >= similarity_threshold {
                    if let Some(payload) = top.get("payload") {
                        let id = top.get("id").and_then(|i| i.as_str()).unwrap_or("").to_string();
                        let prompt_text = payload.get("prompt_text").and_then(|p| p.as_str()).unwrap_or("").to_string();
                        let content_type = payload.get("content_type").and_then(|c| c.as_str()).unwrap_or("application/json").to_string();
                        let prompt_tokens = payload.get("prompt_tokens").and_then(|p| p.as_i64()).unwrap_or(0);
                        let completion_tokens = payload.get("completion_tokens").and_then(|c| c.as_i64()).unwrap_or(0);

                        let raw_body = if let Some(b64) = payload.get("response_body_b64").and_then(|b| b.as_str()) {
                            base64::engine::general_purpose::STANDARD
                                .decode(b64)
                                .unwrap_or_default()
                        } else if let Some(body_str) = payload.get("response_body").and_then(|b| b.as_str()) {
                            body_str.as_bytes().to_vec()
                        } else {
                            Vec::new()
                        };

                        let entry = super::vector_index::VectorEntry {
                            id,
                            tenant_id: tenant_id.to_string(),
                            model: model.to_string(),
                            vector: query_vector.to_vec(),
                            prompt_text,
                            response_body: Bytes::from(raw_body),
                            content_type,
                            prompt_tokens,
                            completion_tokens,
                            created_at: Instant::now(),
                            ttl: Duration::from_secs(86400),
                        };

                        return Ok(Some((entry, score)));
                    }
                }
            }
        }

        Ok(None)
    }

    /// Insert or update a point in Qdrant with payload metadata.
    pub async fn insert(
        &self,
        client: &reqwest::Client,
        entry: &super::vector_index::VectorEntry,
    ) -> Result<(), String> {
        let endpoint = format!("{}/collections/{}/points?wait=false", self.url, self.collection);

        let b64_body = base64::engine::general_purpose::STANDARD.encode(&entry.response_body);

        let point_id = if entry.id.is_empty() {
            uuid::Uuid::new_v4().to_string()
        } else {
            entry.id.clone()
        };

        let insert_body = json!({
            "points": [
                {
                    "id": point_id,
                    "vector": entry.vector,
                    "payload": {
                        "tenant_id": entry.tenant_id,
                        "model": entry.model,
                        "prompt_text": entry.prompt_text,
                        "response_body_b64": b64_body,
                        "content_type": entry.content_type,
                        "prompt_tokens": entry.prompt_tokens,
                        "completion_tokens": entry.completion_tokens,
                    }
                }
            ]
        });

        let mut req = client.put(&endpoint).json(&insert_body);
        if let Some(ref key) = self.api_key {
            req = req.header("api-key", key);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| format!("Qdrant insert request failed: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!("Qdrant insert returned HTTP {}", resp.status()));
        }

        Ok(())
    }
}
