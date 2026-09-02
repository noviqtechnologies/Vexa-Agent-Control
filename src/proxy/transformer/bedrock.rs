//! AWS Bedrock Provider Transformer

use bytes::Bytes;
use hyper::HeaderMap;
use serde_json::Value;
use super::{NormalizedLLMRequest, ProviderTransformer};

pub struct BedrockTransformer;

impl ProviderTransformer for BedrockTransformer {
    fn provider_name(&self) -> &'static str {
        "bedrock"
    }

    fn transform_request(
        &self,
        req: &NormalizedLLMRequest,
        api_key: &str,
        base_url: Option<&str>,
    ) -> Result<(String, HeaderMap, Bytes), String> {
        let region = std::env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".to_string());
        let endpoint = format!(
            "{}/model/{}/converse",
            base_url.unwrap_or(&format!("https://bedrock-runtime.{}.amazonaws.com", region)).trim_end_matches('/'),
            req.model
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            hyper::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );
        if !api_key.is_empty() {
            headers.insert(
                hyper::header::AUTHORIZATION,
                format!("Bearer {}", api_key).parse().map_err(|e| format!("Invalid auth: {}", e))?,
            );
        }

        let mut bedrock_messages = Vec::new();
        for m in &req.messages {
            let role = if m.role == "assistant" { "assistant" } else { "user" };
            bedrock_messages.push(serde_json::json!({
                "role": role,
                "content": [{ "text": m.content }]
            }));
        }

        let body = serde_json::json!({
            "messages": bedrock_messages,
            "inferenceConfig": {
                "maxTokens": req.max_tokens.unwrap_or(2048),
                "temperature": req.temperature.unwrap_or(0.7),
            }
        });

        let bytes = serde_json::to_vec(&body).map_err(|e| format!("Serialize error: {}", e))?;
        Ok((endpoint, headers, Bytes::from(bytes)))
    }

    fn normalize_response(
        &self,
        _status: u16,
        _headers: &HeaderMap,
        body: &[u8],
    ) -> Result<Value, String> {
        let val: Value = serde_json::from_slice(body).map_err(|e| format!("Bedrock JSON parse error: {}", e))?;
        
        let text = val
            .get("output")
            .and_then(|o| o.get("message"))
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_array())
            .and_then(|arr| arr.first())
            .and_then(|part| part.get("text"))
            .and_then(|t| t.as_str())
            .unwrap_or("");

        let input_tokens = val.get("usage").and_then(|u| u.get("inputTokens")).and_then(|v| v.as_i64()).unwrap_or(0);
        let output_tokens = val.get("usage").and_then(|u| u.get("outputTokens")).and_then(|v| v.as_i64()).unwrap_or(0);

        let normalized = serde_json::json!({
            "id": "bedrock-resp",
            "object": "chat.completion",
            "created": chrono::Utc::now().timestamp(),
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": text,
                },
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": input_tokens,
                "completion_tokens": output_tokens,
                "total_tokens": input_tokens + output_tokens,
            }
        });

        Ok(normalized)
    }

    fn normalize_stream_chunk(&self, chunk: &[u8]) -> Result<Option<String>, String> {
        let text = std::str::from_utf8(chunk).map_err(|e| format!("UTF-8 error: {}", e))?;
        Ok(Some(text.to_string()))
    }
}
