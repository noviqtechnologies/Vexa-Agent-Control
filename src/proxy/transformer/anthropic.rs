//! Anthropic Messages API Provider Transformer

use bytes::Bytes;
use hyper::HeaderMap;
use serde_json::Value;
use super::{NormalizedLLMRequest, ProviderTransformer};

pub struct AnthropicTransformer;

impl ProviderTransformer for AnthropicTransformer {
    fn provider_name(&self) -> &'static str {
        "anthropic"
    }

    fn transform_request(
        &self,
        req: &NormalizedLLMRequest,
        api_key: &str,
        base_url: Option<&str>,
    ) -> Result<(String, HeaderMap, Bytes), String> {
        let endpoint = format!(
            "{}/v1/messages",
            base_url.unwrap_or("https://api.anthropic.com").trim_end_matches('/')
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            hyper::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );
        headers.insert(
            "x-api-key".parse::<hyper::header::HeaderName>().unwrap(),
            api_key.parse().map_err(|e| format!("Invalid anthropic api key: {}", e))?,
        );
        headers.insert(
            "anthropic-version".parse::<hyper::header::HeaderName>().unwrap(),
            "2023-06-01".parse().unwrap(),
        );

        let mut system_prompt = String::new();
        let mut anthropic_messages = Vec::new();

        for m in &req.messages {
            if m.role == "system" {
                if !system_prompt.is_empty() {
                    system_prompt.push_str("\n\n");
                }
                system_prompt.push_str(&m.content);
            } else {
                let role = if m.role == "assistant" { "assistant" } else { "user" };
                anthropic_messages.push(serde_json::json!({
                    "role": role,
                    "content": m.content,
                }));
            }
        }

        // Anthropic requires at least 1 user message
        if anthropic_messages.is_empty() {
            anthropic_messages.push(serde_json::json!({
                "role": "user",
                "content": "Hello"
            }));
        }

        let max_tokens = req.max_tokens.unwrap_or(4096);

        let mut body = serde_json::json!({
            "model": req.model,
            "messages": anthropic_messages,
            "max_tokens": max_tokens,
            "stream": req.stream,
        });

        if !system_prompt.is_empty() {
            body["system"] = serde_json::json!(system_prompt);
        }
        if let Some(t) = req.temperature {
            body["temperature"] = serde_json::json!(t);
        }

        let bytes = serde_json::to_vec(&body).map_err(|e| format!("Serialize error: {}", e))?;
        Ok((endpoint, headers, Bytes::from(bytes)))
    }

    fn normalize_response(
        &self,
        _status: u16,
        _headers: &HeaderMap,
        body: &[u8],
    ) -> Result<Value, String> {
        let val: Value = serde_json::from_slice(body).map_err(|e| format!("Anthropic JSON parse error: {}", e))?;

        // Extract content text
        let mut text_content = String::new();
        if let Some(content_arr) = val.get("content").and_then(|v| v.as_array()) {
            for item in content_arr {
                if let Some(t) = item.get("text").and_then(|v| v.as_str()) {
                    text_content.push_str(t);
                }
            }
        }

        let input_tokens = val.get("usage").and_then(|u| u.get("input_tokens")).and_then(|v| v.as_i64()).unwrap_or(0);
        let output_tokens = val.get("usage").and_then(|u| u.get("output_tokens")).and_then(|v| v.as_i64()).unwrap_or(0);

        let normalized = serde_json::json!({
            "id": val.get("id").and_then(|v| v.as_str()).unwrap_or("anthropic-resp"),
            "object": "chat.completion",
            "created": chrono::Utc::now().timestamp(),
            "model": val.get("model").and_then(|v| v.as_str()).unwrap_or("claude"),
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": text_content,
                },
                "finish_reason": match val.get("stop_reason").and_then(|v| v.as_str()) {
                    Some("max_tokens") => "length",
                    Some("tool_use") => "tool_calls",
                    _ => "stop",
                }
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
        let raw = std::str::from_utf8(chunk).map_err(|e| format!("UTF-8 error: {}", e))?;
        
        // Anthropic SSE events: event: content_block_delta \n data: {"delta":{"text":"..."}}
        let mut out = String::new();
        for line in raw.lines() {
            if let Some(data_str) = line.strip_prefix("data: ") {
                if let Ok(parsed) = serde_json::from_str::<Value>(data_str.trim()) {
                    if let Some(delta_text) = parsed.get("delta").and_then(|d| d.get("text")).and_then(|t| t.as_str()) {
                        let openai_chunk = serde_json::json!({
                            "id": "anthropic-chunk",
                            "object": "chat.completion.chunk",
                            "created": chrono::Utc::now().timestamp(),
                            "choices": [{
                                "index": 0,
                                "delta": {
                                    "content": delta_text
                                },
                                "finish_reason": null
                            }]
                        });
                        out.push_str(&format!("data: {}\n\n", openai_chunk));
                    }
                }
            }
        }

        if out.is_empty() {
            Ok(Some(raw.to_string()))
        } else {
            Ok(Some(out))
        }
    }
}
