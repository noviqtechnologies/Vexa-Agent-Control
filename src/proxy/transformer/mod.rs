//! Bidirectional Provider Transformation Layer (Phase 3)
//!
//! Standardizes multi-provider LLM API requests and responses (OpenAI, Azure OpenAI,
//! Groq, Anthropic, Google Gemini, AWS Bedrock) into a normalized canonical representation.

pub mod anthropic;
pub mod azure_openai;
pub mod bedrock;
pub mod gemini;
pub mod groq;
pub mod openai;

use bytes::Bytes;
use hyper::HeaderMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;

/// Canonical message format adhering to unified chat conventions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CanonicalMessage {
    pub role: String,
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Normalized LLM Request representation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NormalizedLLMRequest {
    pub model: String,
    pub messages: Vec<CanonicalMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<i64>,
    pub stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Value>,
    #[serde(default)]
    pub extra_params: serde_json::Map<String, Value>,
}

impl NormalizedLLMRequest {
    /// Ingest from a standard OpenAI-shaped request body.
    pub fn from_openai_value(val: &Value) -> Result<Self, String> {
        let model = val
            .get("model")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing 'model' field".to_string())?
            .to_string();

        let stream = val.get("stream").and_then(|v| v.as_bool()).unwrap_or(false);
        let temperature = val.get("temperature").and_then(|v| v.as_f64()).map(|f| f as f32);
        let max_tokens = val
            .get("max_tokens")
            .or_else(|| val.get("max_completion_tokens"))
            .and_then(|v| v.as_i64());
        let tools = val.get("tools").cloned();

        let mut messages = Vec::new();
        if let Some(msgs) = val.get("messages").and_then(|v| v.as_array()) {
            for m in msgs {
                let role = m.get("role").and_then(|v| v.as_str()).unwrap_or("user").to_string();
                let content = if let Some(s) = m.get("content").and_then(|v| v.as_str()) {
                    s.to_string()
                } else if let Some(arr) = m.get("content").and_then(|v| v.as_array()) {
                    // Extract text parts from multi-modal array
                    let mut text = String::new();
                    for part in arr {
                        if let Some(t) = part.get("text").and_then(|v| v.as_str()) {
                            text.push_str(t);
                        }
                    }
                    text
                } else {
                    String::new()
                };

                let tool_calls = m.get("tool_calls").cloned();
                let tool_call_id = m.get("tool_call_id").and_then(|v| v.as_str()).map(|s| s.to_string());
                let name = m.get("name").and_then(|v| v.as_str()).map(|s| s.to_string());

                messages.push(CanonicalMessage {
                    role,
                    content,
                    tool_calls,
                    tool_call_id,
                    name,
                });
            }
        }

        let mut extra_params = serde_json::Map::new();
        if let Some(obj) = val.as_object() {
            for (k, v) in obj {
                if k != "model" && k != "messages" && k != "stream" && k != "temperature" && k != "max_tokens" && k != "max_completion_tokens" && k != "tools" {
                    extra_params.insert(k.clone(), v.clone());
                }
            }
        }

        Ok(Self {
            model,
            messages,
            temperature,
            max_tokens,
            stream,
            tools,
            extra_params,
        })
    }
}

/// Provider transformation interface contract.
pub trait ProviderTransformer: Send + Sync {
    fn provider_name(&self) -> &'static str;
    
    /// Transform a normalized request to upstream endpoint URL, headers, and request body.
    fn transform_request(
        &self,
        req: &NormalizedLLMRequest,
        api_key: &str,
        base_url: Option<&str>,
    ) -> Result<(String, HeaderMap, Bytes), String>;

    /// Normalize an upstream response body into standard OpenAI-compatible format.
    fn normalize_response(
        &self,
        status: u16,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<Value, String>;

    /// Normalize an incoming raw SSE stream chunk into standard OpenAI data chunk framing.
    fn normalize_stream_chunk(&self, chunk: &[u8]) -> Result<Option<String>, String>;
}

/// Factory to resolve the transformer for a given provider.
pub fn get_transformer(provider: &str) -> Option<Arc<dyn ProviderTransformer>> {
    match provider.to_lowercase().as_str() {
        "openai" => Some(Arc::new(openai::OpenAiTransformer)),
        "azure" | "azure_openai" => Some(Arc::new(azure_openai::AzureOpenAiTransformer)),
        "groq" => Some(Arc::new(groq::GroqTransformer)),
        "anthropic" => Some(Arc::new(anthropic::AnthropicTransformer)),
        "google" | "gemini" => Some(Arc::new(gemini::GeminiTransformer)),
        "bedrock" | "aws_bedrock" => Some(Arc::new(bedrock::BedrockTransformer)),
        _ => None,
    }
}
