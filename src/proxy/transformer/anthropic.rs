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
            } else if m.role == "tool" {
                // OpenAI tool response message -> Anthropic tool_result block
                let tool_id = m.tool_call_id.as_deref().unwrap_or("tool_call");
                anthropic_messages.push(serde_json::json!({
                    "role": "user",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": tool_id,
                        "content": m.content,
                    }]
                }));
            } else if m.role == "assistant" && m.tool_calls.is_some() {
                // Assistant message with tool calls -> Anthropic tool_use blocks
                let mut content_blocks = Vec::new();
                if !m.content.is_empty() {
                    content_blocks.push(serde_json::json!({
                        "type": "text",
                        "text": m.content,
                    }));
                }
                if let Some(tool_calls_arr) = m.tool_calls.as_ref().and_then(|v| v.as_array()) {
                    for tc in tool_calls_arr {
                        let id = tc.get("id").and_then(|v| v.as_str()).unwrap_or("tool_use");
                        let name = tc.get("function").and_then(|f| f.get("name")).and_then(|v| v.as_str()).unwrap_or_default();
                        let args_val = tc.get("function").and_then(|f| f.get("arguments")).and_then(|v| {
                            if let Some(s) = v.as_str() {
                                serde_json::from_str::<Value>(s).ok()
                            } else {
                                Some(v.clone())
                            }
                        }).unwrap_or_else(|| serde_json::json!({}));

                        content_blocks.push(serde_json::json!({
                            "type": "tool_use",
                            "id": id,
                            "name": name,
                            "input": args_val,
                        }));
                    }
                }
                anthropic_messages.push(serde_json::json!({
                    "role": "assistant",
                    "content": content_blocks,
                }));
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

        // Convert OpenAI tools to Anthropic input_schema format
        if let Some(ref tools) = req.tools {
            if let Some(arr) = tools.as_array() {
                let mut anthropic_tools = Vec::new();
                for t in arr {
                    if let Some(func) = t.get("function") {
                        let name = func.get("name").and_then(|v| v.as_str()).unwrap_or_default();
                        let desc = func.get("description").and_then(|v| v.as_str()).unwrap_or_default();
                        let schema = func.get("parameters").cloned().unwrap_or(serde_json::json!({"type": "object"}));
                        anthropic_tools.push(serde_json::json!({
                            "name": name,
                            "description": desc,
                            "input_schema": schema,
                        }));
                    } else if t.get("name").is_some() && t.get("input_schema").is_some() {
                        anthropic_tools.push(t.clone());
                    }
                }
                if !anthropic_tools.is_empty() {
                    body["tools"] = serde_json::json!(anthropic_tools);
                }
            }
        }

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

        // Extract content text and tool calls
        let mut text_content = String::new();
        let mut tool_calls = Vec::new();

        if let Some(content_arr) = val.get("content").and_then(|v| v.as_array()) {
            for item in content_arr {
                let ctype = item.get("type").and_then(|v| v.as_str()).unwrap_or_default();
                if ctype == "text" {
                    if let Some(t) = item.get("text").and_then(|v| v.as_str()) {
                        text_content.push_str(t);
                    }
                } else if ctype == "tool_use" {
                    let id = item.get("id").and_then(|v| v.as_str()).unwrap_or("call_default");
                    let name = item.get("name").and_then(|v| v.as_str()).unwrap_or_default();
                    let input_val = item.get("input").cloned().unwrap_or_else(|| serde_json::json!({}));
                    let input_str = serde_json::to_string(&input_val).unwrap_or_else(|_| "{}".to_string());

                    tool_calls.push(serde_json::json!({
                        "id": id,
                        "type": "function",
                        "function": {
                            "name": name,
                            "arguments": input_str,
                        }
                    }));
                }
            }
        }

        // Empty message defense: ensure IDEs never get empty choices when no tool call was emitted
        if text_content.is_empty() && tool_calls.is_empty() {
            text_content = "*(AgentControl Gateway: Upstream model returned empty output)*".to_string();
        }

        let input_tokens = val.get("usage").and_then(|u| u.get("input_tokens")).and_then(|v| v.as_i64()).unwrap_or(0);
        let output_tokens = val.get("usage").and_then(|u| u.get("output_tokens")).and_then(|v| v.as_i64()).unwrap_or(0);

        let finish_reason = match val.get("stop_reason").and_then(|v| v.as_str()) {
            Some("max_tokens") => "length",
            Some("tool_use") => "tool_calls",
            _ => if !tool_calls.is_empty() { "tool_calls" } else { "stop" },
        };

        let mut message_obj = serde_json::json!({
            "role": "assistant",
            "content": text_content,
        });

        if !tool_calls.is_empty() {
            message_obj["tool_calls"] = serde_json::json!(tool_calls);
        }

        let normalized = serde_json::json!({
            "id": val.get("id").and_then(|v| v.as_str()).unwrap_or("anthropic-resp"),
            "object": "chat.completion",
            "created": chrono::Utc::now().timestamp(),
            "model": val.get("model").and_then(|v| v.as_str()).unwrap_or("claude"),
            "choices": [{
                "index": 0,
                "message": message_obj,
                "finish_reason": finish_reason,
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
        let raw = String::from_utf8_lossy(chunk);
        
        let mut out = String::new();
        for line in raw.lines() {
            let line_trimmed = line.trim();
            if let Some(data_str) = line_trimmed.strip_prefix("data: ") {
                let trimmed_data = data_str.trim();
                if trimmed_data == "[DONE]" {
                    out.push_str("data: [DONE]\n\n");
                    continue;
                }
                if let Ok(parsed) = serde_json::from_str::<Value>(trimmed_data) {
                    let event_type = parsed.get("type").and_then(|v| v.as_str()).unwrap_or_default();
                    if event_type == "content_block_delta" {
                        if let Some(delta) = parsed.get("delta") {
                            let delta_type = delta.get("type").and_then(|v| v.as_str()).unwrap_or_default();
                            if delta_type == "text_delta" {
                                if let Some(delta_text) = delta.get("text").and_then(|t| t.as_str()) {
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
                            } else if delta_type == "input_json_delta" {
                                if let Some(partial_json) = delta.get("partial_json").and_then(|p| p.as_str()) {
                                    let block_idx = parsed.get("index").and_then(|i| i.as_u64()).unwrap_or(0);
                                    let openai_chunk = serde_json::json!({
                                        "id": "anthropic-chunk",
                                        "object": "chat.completion.chunk",
                                        "created": chrono::Utc::now().timestamp(),
                                        "choices": [{
                                            "index": 0,
                                            "delta": {
                                                "tool_calls": [{
                                                    "index": block_idx,
                                                    "function": {
                                                        "arguments": partial_json
                                                    }
                                                }]
                                            },
                                            "finish_reason": null
                                        }]
                                    });
                                    out.push_str(&format!("data: {}\n\n", openai_chunk));
                                }
                            }
                        }
                    } else if event_type == "content_block_start" {
                        if let Some(block) = parsed.get("content_block") {
                            if block.get("type").and_then(|v| v.as_str()) == Some("tool_use") {
                                let block_idx = parsed.get("index").and_then(|i| i.as_u64()).unwrap_or(0);
                                let id = block.get("id").and_then(|v| v.as_str()).unwrap_or("call_default");
                                let name = block.get("name").and_then(|v| v.as_str()).unwrap_or_default();
                                let openai_chunk = serde_json::json!({
                                    "id": "anthropic-chunk",
                                    "object": "chat.completion.chunk",
                                    "created": chrono::Utc::now().timestamp(),
                                    "choices": [{
                                        "index": 0,
                                        "delta": {
                                            "tool_calls": [{
                                                "index": block_idx,
                                                "id": id,
                                                "type": "function",
                                                "function": {
                                                    "name": name,
                                                    "arguments": ""
                                                }
                                            }]
                                        },
                                        "finish_reason": null
                                    }]
                                });
                                out.push_str(&format!("data: {}\n\n", openai_chunk));
                            }
                        }
                    } else if event_type == "message_delta" {
                        let stop_reason = parsed.get("delta").and_then(|d| d.get("stop_reason")).and_then(|s| s.as_str());
                        let finish_reason = match stop_reason {
                            Some("tool_use") => Some("tool_calls"),
                            Some("max_tokens") => Some("length"),
                            Some("end_turn") | Some("stop_sequence") => Some("stop"),
                            _ => None,
                        };
                        if let Some(fr) = finish_reason {
                            let openai_chunk = serde_json::json!({
                                "id": "anthropic-chunk",
                                "object": "chat.completion.chunk",
                                "created": chrono::Utc::now().timestamp(),
                                "choices": [{
                                    "index": 0,
                                    "delta": {},
                                    "finish_reason": fr
                                }]
                            });
                            out.push_str(&format!("data: {}\n\n", openai_chunk));
                        }
                    } else if event_type == "message_stop" {
                        out.push_str("data: [DONE]\n\n");
                    }
                }
            }
        }

        if out.is_empty() {
            Ok(None)
        } else {
            Ok(Some(out))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::transformer::NormalizedLLMRequest;

    #[test]
    fn test_anthropic_transform_request_tools_and_messages() {
        let transformer = AnthropicTransformer;
        let req_json = serde_json::json!({
            "model": "claude-3-7-sonnet",
            "stream": true,
            "temperature": 0.7,
            "max_tokens": 1024,
            "messages": [
                {"role": "system", "content": "You are a test assistant."},
                {"role": "user", "content": "Run tool"},
                {"role": "tool", "tool_call_id": "call_123", "content": "Tool output text"}
            ],
            "tools": [{
                "type": "function",
                "function": {
                    "name": "read_file",
                    "description": "Read file contents",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"}
                        },
                        "required": ["path"]
                    }
                }
            }]
        });
        let req = NormalizedLLMRequest::from_openai_value(&req_json)
            .expect("Failed to create NormalizedLLMRequest");

        let (url, headers, body_bytes) = transformer
            .transform_request(&req, "sk-ant-test-key", None)
            .expect("Transform request should succeed");

        assert_eq!(url, "https://api.anthropic.com/v1/messages");
        assert_eq!(headers.get("x-api-key").unwrap(), "sk-ant-test-key");
        assert_eq!(headers.get("anthropic-version").unwrap(), "2023-06-01");

        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body["system"], "You are a test assistant.");
        assert_eq!(body["max_tokens"], 1024);
        assert_eq!(body["stream"], true);

        // Check tool mapping
        let tools = body["tools"].as_array().expect("Tools should be array");
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "read_file");
        assert_eq!(tools[0]["description"], "Read file contents");
        assert!(tools[0]["input_schema"].is_object());

        // Check messages mapping
        let msgs = body["messages"].as_array().expect("Messages should be array");
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0]["role"], "user");
        assert_eq!(msgs[0]["content"], "Run tool");

        // Tool result should become user message with tool_result block
        assert_eq!(msgs[1]["role"], "user");
        let content_blocks = msgs[1]["content"].as_array().unwrap();
        assert_eq!(content_blocks[0]["type"], "tool_result");
        assert_eq!(content_blocks[0]["tool_use_id"], "call_123");
        assert_eq!(content_blocks[0]["content"], "Tool output text");
    }

    #[test]
    fn test_anthropic_normalize_response_empty_defense() {
        let transformer = AnthropicTransformer;
        let empty_anthropic = serde_json::json!({
            "id": "msg_01",
            "type": "message",
            "role": "assistant",
            "model": "claude-3-5-sonnet",
            "content": [],
            "stop_reason": "end_turn",
            "usage": {
                "input_tokens": 10,
                "output_tokens": 0
            }
        });

        let headers = hyper::HeaderMap::new();
        let bytes = serde_json::to_vec(&empty_anthropic).unwrap();
        let normalized = transformer.normalize_response(200, &headers, &bytes).unwrap();

        let choices = normalized["choices"].as_array().unwrap();
        let message = &choices[0]["message"];
        let content = message["content"].as_str().unwrap();
        assert!(!content.is_empty(), "Empty content must be safeguarded with fallback text");
        assert!(content.contains("AgentControl Gateway"));
    }

    #[test]
    fn test_anthropic_normalize_stream_chunk_tool_calling() {
        let transformer = AnthropicTransformer;

        // 1. content_block_start with tool_use
        let start_event = b"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_01\",\"name\":\"execute_command\",\"input\":{}}}\n\n";
        let chunk1 = transformer.normalize_stream_chunk(start_event).unwrap().unwrap();
        assert!(chunk1.contains("data: "));
        assert!(chunk1.contains("\"execute_command\""));
        assert!(chunk1.contains("\"tool_calls\""));

        // 2. content_block_delta with input_json_delta
        let delta_event = b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"cmd\\\": \\\"ls\\\"}\"}}\n\n";
        let chunk2 = transformer.normalize_stream_chunk(delta_event).unwrap().unwrap();
        assert!(chunk2.contains("{\\\"cmd\\\": \\\"ls\\\"}"));

        // 3. message_delta with stop_reason tool_use
        let delta_stop = b"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"}}\n\n";
        let chunk3 = transformer.normalize_stream_chunk(delta_stop).unwrap().unwrap();
        assert!(chunk3.contains("\"finish_reason\":\"tool_calls\""));

        // 4. message_stop
        let stop_event = b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
        let chunk4 = transformer.normalize_stream_chunk(stop_event).unwrap().unwrap();
        assert_eq!(chunk4, "data: [DONE]\n\n");
    }
}
