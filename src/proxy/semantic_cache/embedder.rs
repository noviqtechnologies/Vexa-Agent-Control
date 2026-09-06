//! Semantic Embedding Engine for Prompt Vectorization
//!
//! Supports production OpenAI & Ollama embeddings alongside a high-speed, deterministic
//! pure-Rust local vectorizer for offline development, testing, and air-gapped deployments.

use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum EmbedderEngine {
    Local,
    OpenAi {
        api_key: String,
        endpoint: String,
        model: String,
    },
    Ollama {
        endpoint: String,
        model: String,
    },
}

impl Default for EmbedderEngine {
    fn default() -> Self {
        Self::Local
    }
}

pub struct Embedder {
    engine: EmbedderEngine,
}

impl Embedder {
    pub fn new(engine: EmbedderEngine) -> Self {
        Self { engine }
    }

    /// Generate an L2-normalized embedding vector for the prompt text.
    pub async fn embed(&self, text: &str, client: &reqwest::Client) -> Result<Vec<f32>, String> {
        match &self.engine {
            EmbedderEngine::Local => Ok(Self::local_vectorize(text)),
            EmbedderEngine::OpenAi {
                api_key,
                endpoint,
                model,
            } => {
                let url = if endpoint.is_empty() {
                    "https://api.openai.com/v1/embeddings".to_string()
                } else {
                    format!("{}/v1/embeddings", endpoint.trim_end_matches('/'))
                };

                let body = json!({
                    "input": text,
                    "model": if model.is_empty() { "text-embedding-3-small" } else { model.as_str() }
                });

                let resp = client
                    .post(&url)
                    .header("Authorization", format!("Bearer {}", api_key))
                    .header("Content-Type", "application/json")
                    .json(&body)
                    .send()
                    .await
                    .map_err(|e| format!("OpenAI embedding request failed: {}", e))?;

                if !resp.status().is_success() {
                    // Fall back to local vectorizer rather than hard-failing
                    eprintln!(
                        "[semantic-cache] Upstream embedding error: HTTP {}, falling back to local vectorizer",
                        resp.status()
                    );
                    return Ok(Self::local_vectorize(text));
                }

                let json_resp: serde_json::Value = resp
                    .json()
                    .await
                    .map_err(|e| format!("Invalid embedding JSON: {}", e))?;

                if let Some(vec) = json_resp
                    .get("data")
                    .and_then(|d| d.as_array())
                    .and_then(|arr| arr.first())
                    .and_then(|item| item.get("embedding"))
                    .and_then(|emb| emb.as_array())
                {
                    let mut floats: Vec<f32> = vec
                        .iter()
                        .filter_map(|v| v.as_f64().map(|f| f as f32))
                        .collect();
                    super::vector_index::InMemoryVectorIndex::normalize_vector(&mut floats);
                    Ok(floats)
                } else {
                    Ok(Self::local_vectorize(text))
                }
            }
            EmbedderEngine::Ollama { endpoint, model } => {
                let url = if endpoint.is_empty() {
                    "http://localhost:11434/api/embeddings".to_string()
                } else {
                    format!("{}/api/embeddings", endpoint.trim_end_matches('/'))
                };

                let body = json!({
                    "prompt": text,
                    "model": if model.is_empty() { "nomic-embed-text" } else { model.as_str() }
                });

                let resp = client
                    .post(&url)
                    .header("Content-Type", "application/json")
                    .json(&body)
                    .send()
                    .await
                    .map_err(|e| format!("Ollama embedding request failed: {}", e))?;

                if !resp.status().is_success() {
                    return Ok(Self::local_vectorize(text));
                }

                let json_resp: serde_json::Value = resp
                    .json()
                    .await
                    .map_err(|e| format!("Invalid Ollama embedding JSON: {}", e))?;

                if let Some(emb) = json_resp.get("embedding").and_then(|v| v.as_array()) {
                    let mut floats: Vec<f32> = emb
                        .iter()
                        .filter_map(|v| v.as_f64().map(|f| f as f32))
                        .collect();
                    super::vector_index::InMemoryVectorIndex::normalize_vector(&mut floats);
                    Ok(floats)
                } else {
                    Ok(Self::local_vectorize(text))
                }
            }
        }
    }

    /// Pure-Rust deterministic 384-dimensional lexical-semantic feature hashing vectorizer.
    ///
    /// Uses word unigrams, bigrams, and character n-grams with sub-linear term frequency
    /// and sign-hashed projections. Normalized with L2 norm so dot products measure cosine similarity.
    pub fn local_vectorize(text: &str) -> Vec<f32> {
        const DIMENSIONS: usize = 384;
        let mut vector = vec![0.0f32; DIMENSIONS];
        let normalized = text.to_lowercase();
        let words: Vec<&str> = normalized
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| !w.is_empty())
            .collect();

        if words.is_empty() {
            // Uniform unit vector for empty input
            let val = 1.0 / (DIMENSIONS as f32).sqrt();
            return vec![val; DIMENSIONS];
        }

        // 1. Unigrams with sign hashing
        for word in &words {
            let h = hash_str(word);
            let idx = (h as usize) % DIMENSIONS;
            let sign = if (h >> 31) & 1 == 0 { 1.0 } else { -1.0 };
            vector[idx] += sign * 1.5;
        }

        // 2. Bigrams for semantic phrasing
        for pair in words.windows(2) {
            let combined = format!("{}_{}", pair[0], pair[1]);
            let h = hash_str(&combined);
            let idx = (h as usize) % DIMENSIONS;
            let sign = if (h >> 31) & 1 == 0 { 1.0 } else { -1.0 };
            vector[idx] += sign * 2.0;
        }

        // 3. Character 3-grams for root-word stems & spelling tolerance
        let chars: Vec<char> = normalized.chars().filter(|c| c.is_alphanumeric() || *c == ' ').collect();
        if chars.len() >= 3 {
            for window in chars.windows(3) {
                let s: String = window.iter().collect();
                let h = hash_str(&s);
                let idx = (h as usize) % DIMENSIONS;
                let sign = if (h >> 31) & 1 == 0 { 1.0 } else { -1.0 };
                vector[idx] += sign * 0.5;
            }
        }

        // Apply L2 normalization
        super::vector_index::InMemoryVectorIndex::normalize_vector(&mut vector);
        vector
    }
}

/// Fast FNV-1a 64-bit hash
fn hash_str(s: &str) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in s.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}
