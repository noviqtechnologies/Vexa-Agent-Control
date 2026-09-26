use crate::proxy::handler::ProxyState;
use crate::proxy::server::{full_to_box_body, BoxBody};
use crate::proxy::session::SessionContext;
use crate::proxy::transformer::ProviderTransformer;
use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use serde_json::{json, Value};
use sha2::Digest;
use std::sync::Arc;

pub(crate) fn emit_llm_telemetry(
    state: &Arc<ProxyState>,
    session: &SessionContext,
    model: &str,
    decision: control_plane_proto::redact::RawDecision,
) {
    if let Some(ref dc) = state.dashboard_client {
        let agent_id = session.identity_sub.as_deref().unwrap_or("agent-local");
        let tool_name = format!("llm:{}", model);
        let raw = control_plane_proto::redact::RawEventForRedaction {
            session_id: &session.session_id,
            agent_id,
            tool_name: &tool_name,
            tool_name_is_allowlisted: true,
            decision,
            timestamp_ms: chrono::Utc::now().timestamp_millis(),
            dlp_findings: &[],
            injection_findings: &[],
            semantic_findings: &[],
        };
        let redacted = control_plane_proto::redact::redact_event(&raw);
        dc.send_event(redacted);
    }
}

fn estimate_input_tokens(body: &Value) -> i64 {
    let mut total_chars = 0;
    if let Some(messages) = body.get("messages").and_then(|v| v.as_array()) {
        for msg in messages {
            if let Some(content) = msg.get("content").and_then(|v| v.as_str()) {
                total_chars += content.len();
            }
        }
    } else if let Some(prompt) = body.get("prompt").and_then(|v| v.as_str()) {
        total_chars += prompt.len();
    }
    let est = (total_chars as i64 / 4) + 10;
    if est <= 0 {
        10
    } else {
        est
    }
}

pub(crate) fn extract_prompt_text(body: &Value) -> String {
    let mut parts = Vec::new();
    if let Some(sys) = body.get("system").and_then(|v| v.as_str()) {
        if !sys.trim().is_empty() {
            parts.push(sys.trim());
        }
    }
    if let Some(messages) = body.get("messages").and_then(|v| v.as_array()) {
        for msg in messages {
            if let Some(content) = msg.get("content").and_then(|v| v.as_str()) {
                if !content.trim().is_empty() {
                    parts.push(content.trim());
                }
            } else if let Some(blocks) = msg.get("content").and_then(|v| v.as_array()) {
                for b in blocks {
                    if let Some(t) = b.get("text").and_then(|v| v.as_str()) {
                        if !t.trim().is_empty() {
                            parts.push(t.trim());
                        }
                    }
                }
            }
        }
    } else if let Some(prompt) = body.get("prompt").and_then(|v| v.as_str()) {
        if !prompt.trim().is_empty() {
            parts.push(prompt.trim());
        }
    }
    parts.join("\n")
}

pub(crate) fn extract_completion_text_from_bytes(bytes: &[u8]) -> String {
    if let Ok(json_val) = serde_json::from_slice::<Value>(bytes) {
        if let Some(choices) = json_val.get("choices").and_then(|v| v.as_array()) {
            if let Some(first) = choices.first() {
                if let Some(content) = first
                    .get("message")
                    .and_then(|m| m.get("content"))
                    .and_then(|c| c.as_str())
                {
                    return content.to_string();
                }
            }
        }
        if let Some(content_arr) = json_val.get("content").and_then(|v| v.as_array()) {
            for block in content_arr {
                if let Some(t) = block.get("text").and_then(|v| v.as_str()) {
                    return t.to_string();
                }
            }
        }
    }
    String::from_utf8_lossy(bytes).to_string()
}

/// Sanitizes tool/function parameter schemas in a request body so they conform
/// to OpenAI broker requirements:
/// - Top-level schema MUST have `type: "object"`
/// - Top-level schema MUST NOT use `anyOf` / `oneOf` / `allOf` / `enum` / `const` / `not`
/// - Schema must be a valid object (non-objects or empty schemas are normalized)
/// - Any `required` array entries must exist in `properties`
///
/// If a schema violates these rules, it is repaired in-place (lifting properties from valid
/// object branches of anyOf/oneOf/allOf if possible, or falling back to a permissive object schema),
/// preventing HTTP 400 errors from the central broker (error_code: invalid_function_parameters).
pub(crate) fn sanitize_tool_schemas(body: &mut Value) {
    const FORBIDDEN_KEYS: &[&str] = &["anyOf", "oneOf", "allOf", "enum", "const", "not"];

    fn sanitize_schema_value(schema: &mut Value) {
        let obj = match schema.as_object_mut() {
            Some(o) => o,
            None => {
                *schema = json!({
                    "type": "object",
                    "properties": {},
                    "additionalProperties": true
                });
                return;
            }
        };

        let has_forbidden = FORBIDDEN_KEYS.iter().any(|k| obj.contains_key(*k));
        let missing_object_type = match obj.get("type") {
            Some(Value::String(s)) => s != "object",
            _ => true,
        };

        if has_forbidden || missing_object_type {
            // Attempt to extract properties / required from an object sub-schema in anyOf/oneOf/allOf
            let mut extracted_properties = None;
            let mut extracted_required = None;

            for &key in &["anyOf", "oneOf", "allOf"] {
                if let Some(branches) = obj.get(key).and_then(|v| v.as_array()) {
                    for branch in branches {
                        if let Some(branch_obj) = branch.as_object() {
                            let is_obj_branch = branch_obj
                                .get("type")
                                .and_then(|t| t.as_str())
                                .map(|t| t == "object")
                                .unwrap_or_else(|| branch_obj.contains_key("properties"));
                            if is_obj_branch && branch_obj.contains_key("properties") {
                                extracted_properties = branch_obj.get("properties").cloned();
                                extracted_required = branch_obj.get("required").cloned();
                                break;
                            }
                        }
                    }
                }
                if extracted_properties.is_some() {
                    break;
                }
            }

            for key in FORBIDDEN_KEYS {
                obj.remove(*key);
            }

            obj.insert("type".to_string(), Value::String("object".to_string()));

            if !obj.contains_key("properties") {
                if let Some(props) = extracted_properties {
                    obj.insert("properties".to_string(), props);
                    if let Some(req) = extracted_required {
                        obj.insert("required".to_string(), req);
                    }
                } else {
                    obj.insert("properties".to_string(), Value::Object(serde_json::Map::new()));
                    obj.insert("additionalProperties".to_string(), Value::Bool(true));
                }
            }
        }

        // Clean up required array so it only references existing keys in properties
        let valid_keys: Option<std::collections::HashSet<String>> = obj
            .get("properties")
            .and_then(|p| p.as_object())
            .map(|p| p.keys().cloned().collect());

        if let Some(keys) = valid_keys {
            if let Some(req_arr) = obj.get_mut("required").and_then(|r| r.as_array_mut()) {
                req_arr.retain(|k| {
                    k.as_str().map(|s| keys.contains(s)).unwrap_or(false)
                });
            }
        } else if obj.contains_key("required") {
            obj.remove("required");
        }
    }

    fn sanitize_tool_item(tool: &mut Value) {
        if let Some(obj) = tool.as_object_mut() {
            // 1. Direct schema fields on tool object (e.g. MCP tools or OpenAI Responses protocol)
            if let Some(params) = obj.get_mut("parameters") {
                sanitize_schema_value(params);
            }
            if let Some(input_schema) = obj.get_mut("input_schema") {
                sanitize_schema_value(input_schema);
            }
            if let Some(input_schema_camel) = obj.get_mut("inputSchema") {
                sanitize_schema_value(input_schema_camel);
            }
            if let Some(schema) = obj.get_mut("schema") {
                sanitize_schema_value(schema);
            }

            // 2. OpenAI function wrapper: { type: "function", function: { parameters: ... } }
            if let Some(func_val) = obj.get_mut("function") {
                if let Some(func_obj) = func_val.as_object_mut() {
                    if let Some(params) = func_obj.get_mut("parameters") {
                        sanitize_schema_value(params);
                    }
                    if let Some(input_schema) = func_obj.get_mut("input_schema") {
                        sanitize_schema_value(input_schema);
                    }
                    if let Some(input_schema_camel) = func_obj.get_mut("inputSchema") {
                        sanitize_schema_value(input_schema_camel);
                    }
                    if let Some(schema) = func_obj.get_mut("schema") {
                        sanitize_schema_value(schema);
                    }
                }
            }

            // 3. Nested tool arrays (e.g. MCP tool groups: tools[i].tools[j])
            if let Some(nested_tools) = obj.get_mut("tools").and_then(|t| t.as_array_mut()) {
                for inner_tool in nested_tools.iter_mut() {
                    sanitize_tool_item(inner_tool);
                }
            }
        }
    }

    // Top-level tools array
    if let Some(tools) = body.get_mut("tools").and_then(|v| v.as_array_mut()) {
        for tool in tools.iter_mut() {
            sanitize_tool_item(tool);
        }
    }

    // Top-level functions array (legacy OpenAI format)
    if let Some(functions) = body.get_mut("functions").and_then(|v| v.as_array_mut()) {
        for func in functions.iter_mut() {
            sanitize_tool_item(func);
        }
    }
}

pub(crate) fn infer_provider_from_model(model: &str) -> String {
    let lower = model.to_lowercase();
    if lower.starts_with("gpt-")
        || lower.starts_with("o1")
        || lower.starts_with("o3")
        || lower.starts_with("o4")
        || lower.starts_with("text-")
        || lower.starts_with("chatgpt")
        || lower.contains("openai")
    {
        "openai".to_string()
    } else if lower.starts_with("claude-") || lower.contains("anthropic") {
        "anthropic".to_string()
    } else if lower.starts_with("gemini") || lower.contains("google") {
        "google".to_string()
    } else if lower.starts_with("deepseek") {
        "deepseek".to_string()
    } else if lower.starts_with("groq") || lower.contains("llama") || lower.contains("mixtral") {
        "groq".to_string()
    } else if std::env::var("ANTHROPIC_API_KEY").is_ok() && std::env::var("OPENAI_API_KEY").is_err()
    {
        "anthropic".to_string()
    } else if std::env::var("GEMINI_API_KEY").is_ok() && std::env::var("OPENAI_API_KEY").is_err() {
        "google".to_string()
    } else {
        std::env::var("DEFAULT_LLM_PROVIDER").unwrap_or_else(|_| "openai".to_string())
    }
}

/// Finds the boundary of the first complete SSE event block in `buf`.
/// Returns (index_of_start_of_delimiter, length_of_delimiter).
pub(crate) fn find_sse_event_boundary(buf: &[u8]) -> Option<(usize, usize)> {
    let mut i = 0;
    while i < buf.len() {
        if buf[i] == b'\n' {
            if i + 1 < buf.len() && buf[i + 1] == b'\n' {
                return Some((i, 2));
            }
        } else if buf[i] == b'\r' {
            if i + 3 < buf.len()
                && buf[i + 1] == b'\n'
                && buf[i + 2] == b'\r'
                && buf[i + 3] == b'\n'
            {
                return Some((i, 4));
            }
        }
        i += 1;
    }
    None
}

/// Sanitizes a complete SSE event block (one or more lines ending in \n\n).
/// Preserves event:, id:, and data: fields in the same event block without premature splitting,
/// strips broker-internal fields (`obfuscation`), and standardizes ending to `\n\n`.
pub(crate) fn sanitize_sse_block(block: &str) -> Option<String> {
    let block_trimmed = block.trim();
    if block_trimmed.is_empty() {
        return None;
    }
    if block_trimmed == "data: [DONE]"
        || block_trimmed == "data:[DONE]"
        || block_trimmed == "[DONE]"
    {
        return Some("data: [DONE]\n\n".to_string());
    }

    let mut out_lines = Vec::new();
    for line in block.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed == "data: [DONE]" || trimmed == "data:[DONE]" {
            out_lines.push("data: [DONE]".to_string());
            continue;
        }
        if let Some(data_str) = trimmed.strip_prefix("data: ") {
            let data_clean = data_str.trim();
            if data_clean == "[DONE]" {
                out_lines.push("data: [DONE]".to_string());
            } else if let Ok(mut json_val) = serde_json::from_str::<serde_json::Value>(data_clean) {
                if let Some(obj) = json_val.as_object_mut() {
                    obj.remove("obfuscation");
                }
                if let Ok(clean_json) = serde_json::to_string(&json_val) {
                    out_lines.push(format!("data: {}", clean_json));
                } else {
                    out_lines.push(format!("data: {}", data_clean));
                }
            } else {
                out_lines.push(format!("data: {}", data_clean));
            }
        } else if let Some(data_str) = trimmed.strip_prefix("data:") {
            let data_clean = data_str.trim();
            if data_clean == "[DONE]" {
                out_lines.push("data: [DONE]".to_string());
            } else if let Ok(mut json_val) = serde_json::from_str::<serde_json::Value>(data_clean) {
                if let Some(obj) = json_val.as_object_mut() {
                    obj.remove("obfuscation");
                }
                if let Ok(clean_json) = serde_json::to_string(&json_val) {
                    out_lines.push(format!("data: {}", clean_json));
                } else {
                    out_lines.push(format!("data: {}", data_clean));
                }
            } else {
                out_lines.push(format!("data: {}", data_clean));
            }
        } else {
            // Preserve event:, id:, : comment, etc.
            out_lines.push(trimmed.to_string());
        }
    }

    if out_lines.is_empty() {
        None
    } else {
        let mut res = out_lines.join("\n");
        res.push_str("\n\n");
        Some(res)
    }
}

/// Backwards-compatible wrapper around `sanitize_sse_block`.
#[allow(dead_code)]
pub(crate) fn sanitize_sse_line(line: &str) -> Option<String> {
    sanitize_sse_block(line)
}

/// Robust Server-Sent Events (SSE) stream sanitizer and normalizer.
/// Strips broker-internal fields (like `obfuscation`), standardizes CRLF/LF line endings,
/// preserves event framing, keep-alives, and `data: [DONE]`, ensuring strict compliance
/// with OpenAI / Anthropic / Cline SDK parsers.
#[allow(dead_code)]
pub(crate) fn clean_sse_stream(raw_bytes: &[u8]) -> Vec<u8> {
    let mut byte_buffer = raw_bytes.to_vec();
    let mut out = Vec::with_capacity(raw_bytes.len() + 64);

    while let Some((pos, delim_len)) = find_sse_event_boundary(&byte_buffer) {
        let event_bytes = byte_buffer[..pos].to_vec();
        byte_buffer.drain(..pos + delim_len);
        let block_str = String::from_utf8_lossy(&event_bytes);
        if let Some(clean) = sanitize_sse_block(&block_str) {
            out.extend_from_slice(clean.as_bytes());
        }
    }

    if !byte_buffer.is_empty() {
        let block_str = String::from_utf8_lossy(&byte_buffer);
        if let Some(clean) = sanitize_sse_block(&block_str) {
            out.extend_from_slice(clean.as_bytes());
        }
    }

    if out.is_empty() {
        raw_bytes.to_vec()
    } else {
        out
    }
}

/// Normalizes incoming OpenAI chat completion messages.
/// When AI IDE extensions (like Roo Code / Cline) use OpenAI-compatible endpoints with conversation
/// history containing Anthropic-style tool blocks (`type: "tool_use"` and `type: "tool_result"`),
/// this function translates them into standard OpenAI schema (`tool_calls` and `role: "tool"`),
/// preventing upstream OpenAI providers from returning 400 Bad Request.
pub(crate) fn normalize_inbound_openai_messages(body: &mut Value) {
    let Some(messages) = body.get_mut("messages").and_then(|v| v.as_array_mut()) else {
        return;
    };

    let mut normalized = Vec::with_capacity(messages.len());

    for msg in messages.drain(..) {
        let role = msg
            .get("role")
            .and_then(|r| r.as_str())
            .unwrap_or("")
            .to_string();
        let content = msg.get("content");

        if role == "assistant" {
            if let Some(blocks) = content.and_then(|c| c.as_array()) {
                let mut tool_calls = Vec::new();
                let mut text_parts = Vec::new();

                for block in blocks {
                    if let Some(btype) = block.get("type").and_then(|t| t.as_str()) {
                        if btype == "tool_use" {
                            let id = block
                                .get("id")
                                .and_then(|i| i.as_str())
                                .unwrap_or("call_default")
                                .to_string();
                            let name = block
                                .get("name")
                                .and_then(|n| n.as_str())
                                .unwrap_or("unknown")
                                .to_string();
                            let input_str = match block.get("input") {
                                Some(Value::String(s)) => s.clone(),
                                Some(v) => serde_json::to_string(v).unwrap_or_default(),
                                None => "{}".to_string(),
                            };
                            tool_calls.push(json!({
                                "id": id,
                                "type": "function",
                                "function": {
                                    "name": name,
                                    "arguments": input_str
                                }
                            }));
                        } else if btype == "text" {
                            if let Some(t) = block.get("text").and_then(|t| t.as_str()) {
                                text_parts.push(t.to_string());
                            }
                        }
                    } else if let Some(s) = block.as_str() {
                        text_parts.push(s.to_string());
                    }
                }

                if !tool_calls.is_empty() {
                    let mut norm_msg = serde_json::Map::new();
                    norm_msg.insert("role".to_string(), Value::String("assistant".to_string()));
                    if text_parts.is_empty() {
                        norm_msg.insert("content".to_string(), Value::Null);
                    } else {
                        norm_msg
                            .insert("content".to_string(), Value::String(text_parts.join("\n")));
                    }
                    norm_msg.insert("tool_calls".to_string(), Value::Array(tool_calls));
                    normalized.push(Value::Object(norm_msg));
                    continue;
                } else if !text_parts.is_empty() {
                    let mut norm_msg = serde_json::Map::new();
                    norm_msg.insert("role".to_string(), Value::String("assistant".to_string()));
                    norm_msg.insert("content".to_string(), Value::String(text_parts.join("\n")));
                    normalized.push(Value::Object(norm_msg));
                    continue;
                }
            }
            normalized.push(msg);
        } else if role == "user" {
            if let Some(blocks) = content.and_then(|c| c.as_array()) {
                let mut tool_results = Vec::new();
                let mut text_parts = Vec::new();

                for block in blocks {
                    if let Some(btype) = block.get("type").and_then(|t| t.as_str()) {
                        if btype == "tool_result" {
                            let tool_id = block
                                .get("tool_use_id")
                                .and_then(|i| i.as_str())
                                .unwrap_or("call_default")
                                .to_string();
                            let tr_content = match block.get("content") {
                                Some(Value::String(s)) => s.clone(),
                                Some(Value::Array(arr)) => {
                                    let mut inner_texts = Vec::new();
                                    for item in arr {
                                        if let Some(t) = item.get("text").and_then(|t| t.as_str()) {
                                            inner_texts.push(t.to_string());
                                        } else if let Some(s) = item.as_str() {
                                            inner_texts.push(s.to_string());
                                        }
                                    }
                                    if inner_texts.is_empty() {
                                        serde_json::to_string(arr).unwrap_or_default()
                                    } else {
                                        inner_texts.join("\n")
                                    }
                                }
                                Some(v) => serde_json::to_string(v).unwrap_or_default(),
                                None => String::new(),
                            };
                            tool_results.push(json!({
                                "role": "tool",
                                "tool_call_id": tool_id,
                                "content": tr_content
                            }));
                        } else if btype == "text" {
                            if let Some(t) = block.get("text").and_then(|t| t.as_str()) {
                                text_parts.push(t.to_string());
                            }
                        }
                    } else if let Some(s) = block.as_str() {
                        text_parts.push(s.to_string());
                    }
                }

                if !tool_results.is_empty() {
                    for tr in tool_results {
                        normalized.push(tr);
                    }
                    if !text_parts.is_empty() {
                        normalized.push(json!({
                            "role": "user",
                            "content": text_parts.join("\n")
                        }));
                    }
                    continue;
                } else {
                    let has_other_blocks = blocks.iter().any(|b| {
                        let btype = b.get("type").and_then(|t| t.as_str()).unwrap_or("");
                        btype != "text"
                    });
                    if !has_other_blocks && !text_parts.is_empty() {
                        normalized.push(json!({
                            "role": "user",
                            "content": text_parts.join("\n")
                        }));
                        continue;
                    }
                }
            }
            normalized.push(msg);
        } else {
            normalized.push(msg);
        }
    }

    *messages = normalized;
}

/// Helper function to detect if a model supports reasoning parameters (o1, o3, o4, etc.)
pub(crate) fn is_reasoning_capable_model(model: &str) -> bool {
    let lower = model.to_lowercase();
    lower.starts_with("o1")
        || lower.starts_with("o3")
        || lower.starts_with("o4")
        || lower.contains("reasoner")
        || lower.contains("reasoning")
        || lower.contains("r1")
}

/// Helper to construct a standardized error response adhering to protocol specification (OpenAI vs Anthropic vs Responses API)
/// with clear origin tagging ("agentcontrol" vs "upstream_provider") and streaming error framing so IDE
/// clients (Roo Code, Cursor, Cline, Codex Desktop) display the diagnostic error directly in chat instead of failing with
/// "The model returned no assistant messages" or "stream closed before response.completed".
pub(crate) fn make_error_response_with_protocol(
    status: StatusCode,
    origin: &'static str, // "agentcontrol" or "upstream_provider"
    error_code: &str,
    message: &str,
    details: Option<serde_json::Value>,
    is_streaming: bool,
    req_id: &str,
    is_anthropic_protocol: bool,
    is_responses_protocol: bool,
) -> Response<BoxBody> {
    let mut err_obj = serde_json::json!({
        "origin": origin,
        "type": if origin == "agentcontrol" { "agentcontrol_error" } else { "upstream_provider_error" },
        "code": error_code,
        "message": format!("[{}] {}", if origin == "agentcontrol" { "AgentControl Gateway" } else { "Upstream Provider" }, message),
    });

    if let Some(d) = details.clone() {
        err_obj["details"] = d;
    }

    crate::logging::log_event(
        crate::logging::Level::Error,
        "llm_proxy_error",
        serde_json::json!({
            "status_code": status.as_u16(),
            "origin": origin,
            "error_code": error_code,
            "message": message,
            "request_id": req_id,
            "details": details,
            "is_streaming": is_streaming,
            "is_responses_protocol": is_responses_protocol,
            "is_anthropic_protocol": is_anthropic_protocol
        }),
    );

    if is_streaming {
        let sse_content = format!(
            "\n⚠️ **[{}]**: {}\n",
            if origin == "agentcontrol" {
                "AgentControl Gateway"
            } else {
                "Upstream Provider Error"
            },
            message
        );

        if is_anthropic_protocol {
            let start_event = serde_json::json!({
                "type": "message_start",
                "message": {
                    "id": format!("err-{}", req_id),
                    "type": "message",
                    "role": "assistant",
                    "content": [],
                    "model": "agentcontrol-error",
                    "stop_reason": null,
                    "stop_sequence": null,
                    "usage": { "input_tokens": 0, "output_tokens": 0 }
                }
            });
            let block_start = serde_json::json!({
                "type": "content_block_start",
                "index": 0,
                "content_block": { "type": "text", "text": "" }
            });
            let block_delta = serde_json::json!({
                "type": "content_block_delta",
                "index": 0,
                "delta": { "type": "text_delta", "text": sse_content }
            });
            let block_stop = serde_json::json!({
                "type": "content_block_stop",
                "index": 0
            });
            let msg_delta = serde_json::json!({
                "type": "message_delta",
                "delta": { "stop_reason": "end_turn", "stop_sequence": null },
                "usage": { "output_tokens": 10 }
            });
            let msg_stop = serde_json::json!({
                "type": "message_stop"
            });

            let payload = format!(
                "event: message_start\ndata: {}\n\nevent: content_block_start\ndata: {}\n\nevent: content_block_delta\ndata: {}\n\nevent: content_block_stop\ndata: {}\n\nevent: message_delta\ndata: {}\n\nevent: message_stop\ndata: {}\n\n",
                serde_json::to_string(&start_event).unwrap_or_default(),
                serde_json::to_string(&block_start).unwrap_or_default(),
                serde_json::to_string(&block_delta).unwrap_or_default(),
                serde_json::to_string(&block_stop).unwrap_or_default(),
                serde_json::to_string(&msg_delta).unwrap_or_default(),
                serde_json::to_string(&msg_stop).unwrap_or_default()
            );

            let (tx, rx) =
                tokio::sync::mpsc::channel::<Result<hyper::body::Frame<Bytes>, hyper::Error>>(2);
            let _ = tx.try_send(Ok(hyper::body::Frame::data(Bytes::from(payload))));
            let stream_body = http_body_util::BodyExt::boxed(http_body_util::StreamBody::new(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            ));

            Response::builder()
                .status(StatusCode::OK)
                .header(
                    hyper::header::CONTENT_TYPE,
                    "text/event-stream; charset=utf-8",
                )
                .header(hyper::header::CACHE_CONTROL, "no-cache, no-transform")
                .header(hyper::header::CONNECTION, "keep-alive")
                .header("X-Accel-Buffering", "no")
                .header("X-AgentControl-Origin", origin)
                .header(
                    "X-AgentControl-Verdict",
                    if origin == "agentcontrol" {
                        "blocked"
                    } else {
                        "upstream_error"
                    },
                )
                .header("X-AgentControl-Request-ID", req_id)
                .body(stream_body)
                .unwrap()
        } else if is_responses_protocol {
            let now = chrono::Utc::now().timestamp();
            let err_resp_id = format!("resp_err_{}", req_id);
            let err_msg_id = format!("msg_err_{}", req_id);
            let payload = format!(
                "event: response.created\ndata: {}\n\nevent: response.output_item.added\ndata: {}\n\nevent: response.content_part.added\ndata: {}\n\nevent: response.output_text.delta\ndata: {}\n\nevent: response.output_text.done\ndata: {}\n\nevent: response.content_part.done\ndata: {}\n\nevent: response.output_item.done\ndata: {}\n\nevent: response.completed\ndata: {}\n\n",
                serde_json::json!({
                    "response": {
                        "id": err_resp_id,
                        "object": "response",
                        "status": "in_progress",
                        "created_at": now,
                        "model": "agentcontrol-error",
                        "output": []
                    }
                }),
                serde_json::json!({
                    "output_index": 0,
                    "item": {
                        "id": err_msg_id,
                        "type": "message",
                        "role": "assistant",
                        "content": [],
                        "status": "in_progress"
                    }
                }),
                serde_json::json!({
                    "output_index": 0,
                    "content_index": 0,
                    "item_id": err_msg_id,
                    "part": {
                        "type": "output_text",
                        "text": ""
                    }
                }),
                serde_json::json!({
                    "output_index": 0,
                    "content_index": 0,
                    "item_id": err_msg_id,
                    "delta": sse_content
                }),
                serde_json::json!({
                    "output_index": 0,
                    "content_index": 0,
                    "item_id": err_msg_id,
                    "text": sse_content
                }),
                serde_json::json!({
                    "output_index": 0,
                    "content_index": 0,
                    "item_id": err_msg_id,
                    "part": {
                        "type": "output_text",
                        "text": sse_content
                    }
                }),
                serde_json::json!({
                    "output_index": 0,
                    "item": {
                        "id": err_msg_id,
                        "type": "message",
                        "role": "assistant",
                        "content": [{
                            "type": "output_text",
                            "text": sse_content
                        }],
                        "status": "completed"
                    }
                }),
                serde_json::json!({
                    "response": {
                        "id": err_resp_id,
                        "object": "response",
                        "status": "completed",
                        "completed_at": now,
                        "created_at": now,
                        "model": "agentcontrol-error",
                        "output": [{
                            "id": err_msg_id,
                            "type": "message",
                            "role": "assistant",
                            "content": [{
                                "type": "output_text",
                                "text": sse_content
                            }],
                            "status": "completed"
                        }],
                        "usage": {
                            "input_tokens": 0,
                            "output_tokens": 0,
                            "total_tokens": 0
                        }
                    }
                })
            );

            let (tx, rx) =
                tokio::sync::mpsc::channel::<Result<hyper::body::Frame<Bytes>, hyper::Error>>(2);
            let _ = tx.try_send(Ok(hyper::body::Frame::data(Bytes::from(payload))));
            let stream_body = http_body_util::BodyExt::boxed(http_body_util::StreamBody::new(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            ));

            Response::builder()
                .status(StatusCode::OK)
                .header(
                    hyper::header::CONTENT_TYPE,
                    "text/event-stream; charset=utf-8",
                )
                .header(hyper::header::CACHE_CONTROL, "no-cache, no-transform")
                .header(hyper::header::CONNECTION, "keep-alive")
                .header("X-Accel-Buffering", "no")
                .header("X-AgentControl-Origin", origin)
                .header(
                    "X-AgentControl-Verdict",
                    if origin == "agentcontrol" {
                        "blocked"
                    } else {
                        "upstream_error"
                    },
                )
                .header("X-AgentControl-Request-ID", req_id)
                .body(stream_body)
                .unwrap()
        } else {
            let sse_chunk = serde_json::json!({
                "id": format!("err-{}", req_id),
                "object": "chat.completion.chunk",
                "created": chrono::Utc::now().timestamp(),
                "choices": [{
                    "index": 0,
                    "delta": {
                        "role": "assistant",
                        "content": sse_content
                    },
                    "finish_reason": "stop"
                }]
            });

            let sse_payload = format!(
                "data: {}\n\ndata: [DONE]\n\n",
                serde_json::to_string(&sse_chunk).unwrap_or_default()
            );
            let (tx, rx) =
                tokio::sync::mpsc::channel::<Result<hyper::body::Frame<Bytes>, hyper::Error>>(2);
            let _ = tx.try_send(Ok(hyper::body::Frame::data(Bytes::from(sse_payload))));
            let stream_body = http_body_util::BodyExt::boxed(http_body_util::StreamBody::new(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            ));

            Response::builder()
                .status(StatusCode::OK)
                .header(
                    hyper::header::CONTENT_TYPE,
                    "text/event-stream; charset=utf-8",
                )
                .header(hyper::header::CACHE_CONTROL, "no-cache, no-transform")
                .header(hyper::header::CONNECTION, "keep-alive")
                .header("X-Accel-Buffering", "no")
                .header("X-AgentControl-Origin", origin)
                .header(
                    "X-AgentControl-Verdict",
                    if origin == "agentcontrol" {
                        "blocked"
                    } else {
                        "upstream_error"
                    },
                )
                .header("X-AgentControl-Request-ID", req_id)
                .body(stream_body)
                .unwrap()
        }
    } else if is_anthropic_protocol {
        let anthropic_err = serde_json::json!({
            "type": "error",
            "error": {
                "type": if origin == "agentcontrol" { "agentcontrol_error" } else { "invalid_request_error" },
                "message": format!("[{}] {}", if origin == "agentcontrol" { "AgentControl Gateway" } else { "Upstream Provider" }, message),
                "code": error_code,
            }
        });
        let json_bytes = serde_json::to_vec(&anthropic_err).unwrap_or_default();
        Response::builder()
            .status(status)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .header("X-AgentControl-Origin", origin)
            .header(
                "X-AgentControl-Verdict",
                if origin == "agentcontrol" {
                    "blocked"
                } else {
                    "upstream_error"
                },
            )
            .header("X-AgentControl-Request-ID", req_id)
            .body(full_to_box_body(Full::new(Bytes::from(json_bytes))))
            .unwrap()
    } else {
        let json_body = serde_json::json!({ "error": err_obj });
        let json_bytes = serde_json::to_vec(&json_body).unwrap_or_default();
        Response::builder()
            .status(status)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .header("X-AgentControl-Origin", origin)
            .header(
                "X-AgentControl-Verdict",
                if origin == "agentcontrol" {
                    "blocked"
                } else {
                    "upstream_error"
                },
            )
            .header("X-AgentControl-Request-ID", req_id)
            .body(full_to_box_body(Full::new(Bytes::from(json_bytes))))
            .unwrap()
    }
}

pub(crate) fn make_error_response(
    status: StatusCode,
    origin: &'static str,
    error_code: &str,
    message: &str,
    details: Option<serde_json::Value>,
    is_streaming: bool,
    req_id: &str,
) -> Response<BoxBody> {
    make_error_response_with_protocol(
        status,
        origin,
        error_code,
        message,
        details,
        is_streaming,
        req_id,
        false,
        false,
    )
}

/// Returns true if the token is an AgentControl Virtual Key, sentinel token, or gateway-internal secret.
/// These tokens authenticate the client TO the AgentControl Gateway and must NEVER be forwarded
/// to upstream AI providers (OpenAI, Anthropic, Google, etc.) as raw API keys.
pub fn is_internal_agentcontrol_key(token: &str) -> bool {
    let t = token.strip_prefix("Bearer ").unwrap_or(token).trim();
    t.starts_with("sk-vex-")
        || t.starts_with("vex_")
        || t.starts_with("vexa_")
        || t.contains("agentcontrol-managed")
}

/// Retrieves an environment variable from process env, or falls back to reading from a local `.env` file
/// in current or parent directories.
pub fn get_env_or_dotenv(key: &str) -> Option<String> {
    if let Ok(v) = std::env::var(key) {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    let candidates = [
        std::path::PathBuf::from(".env"),
        std::path::PathBuf::from("../.env"),
        std::path::PathBuf::from("../../.env"),
    ];

    for path in &candidates {
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with('#') || trimmed.is_empty() {
                    continue;
                }
                if let Some((k, v)) = trimmed.split_once('=') {
                    if k.trim() == key {
                        let cleaned = v.trim().trim_matches('"').trim_matches('\'').trim();
                        if !cleaned.is_empty() {
                            return Some(cleaned.to_string());
                        }
                    }
                }
            }
        }
    }

    None
}

pub async fn handle_request(
    req: Request<Incoming>,
    state: Arc<ProxyState>,
    client_ip: &str,
) -> Result<Response<BoxBody>, hyper::Error> {
    let _start_time = std::time::Instant::now();

    // Handle GET /v1/models and GET /models connectivity check for Cline / OpenAI clients
    if req.method() == hyper::Method::GET {
        let path = req.uri().path();
        if path == "/v1/models"
            || path == "/models"
            || path.starts_with("/v1/models/")
            || path.starts_with("/models/")
        {
            let global_policy = state.policy.read().ok().and_then(|g| g.clone());
            let mut model_entries = Vec::new();

            if let Some(policy) = global_policy.as_ref() {
                if let Some(llm_config) = &policy.llm {
                    if let Some(providers) = &llm_config.providers {
                        for provider in providers {
                            if let Some(models) = &provider.models {
                                for m in models {
                                    if m != "*" && !m.ends_with('*') {
                                        model_entries.push(serde_json::json!({
                                            "id": m,
                                            "object": "model",
                                            "created": 1700000000,
                                            "owned_by": provider.name
                                        }));
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if model_entries.is_empty() {
                let default_models = [
                    ("gpt-4o", "openai"),
                    ("gpt-4o-mini", "openai"),
                    ("gpt-4-turbo", "openai"),
                    ("o1", "openai"),
                    ("o1-preview", "openai"),
                    ("o1-mini", "openai"),
                    ("o3-mini", "openai"),
                    ("claude-3-7-sonnet-20250219", "anthropic"),
                    ("claude-3-7-sonnet-latest", "anthropic"),
                    ("claude-3-5-sonnet-20241022", "anthropic"),
                    ("claude-3-5-sonnet-latest", "anthropic"),
                    ("claude-3-5-haiku-20241022", "anthropic"),
                    ("claude-3-opus-20240229", "anthropic"),
                    ("gemini-2.0-flash", "google"),
                    ("gemini-2.0-flash-exp", "google"),
                    ("gemini-1.5-pro", "google"),
                    ("gemini-1.5-flash", "google"),
                    ("deepseek-chat", "deepseek"),
                    ("deepseek-reasoner", "deepseek"),
                ];
                for (m, p) in &default_models {
                    model_entries.push(serde_json::json!({
                        "id": m,
                        "object": "model",
                        "created": 1700000000,
                        "owned_by": p
                    }));
                }
            }

            let resp = serde_json::json!({
                "object": "list",
                "data": model_entries
            });
            return Ok(crate::proxy::server::json_response(StatusCode::OK, &resp));
        }

        return Ok(crate::proxy::server::json_response(
            StatusCode::METHOD_NOT_ALLOWED,
            &serde_json::json!({"error": "Method Not Allowed"}),
        ));
    }

    // Extract authorization header & credential header from incoming agent request
    let req_path = req.uri().path().to_string();
    let is_anthropic_protocol = req_path == "/v1/messages"
        || req_path == "/messages"
        || req_path.starts_with("/v1/messages/")
        || req_path.starts_with("/messages/")
        || req.headers().contains_key("anthropic-version");
    let is_responses_protocol = req_path == "/v1/responses";

    let auth_header = req
        .headers()
        .get(hyper::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let credential_header = req
        .headers()
        .get("X-AgentControl-Credential")
        .or_else(|| req.headers().get("X-AgentWall-Credential"))
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let scope_header = req
        .headers()
        .get("X-AgentControl-Credential-Scope")
        .or_else(|| req.headers().get("X-AgentControl-Scope"))
        .or_else(|| req.headers().get("X-AgentWall-Credential-Scope"))
        .or_else(|| {
            req.headers()
                .get("X-AgentControl-Scope")
                .or_else(|| req.headers().get("X-AgentWall-Scope"))
        })
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let client_id_hdr = req
        .headers()
        .get("X-AgentControl-Client-ID")
        .or_else(|| req.headers().get("X-AgentWall-Client-ID"))
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let project_id_hdr = req
        .headers()
        .get("X-AgentControl-Project-ID")
        .or_else(|| req.headers().get("X-AgentWall-Project-ID"))
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let cost_center_hdr = req
        .headers()
        .get("X-AgentControl-Cost-Center")
        .or_else(|| req.headers().get("X-AgentWall-Cost-Center"))
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let session = match crate::proxy::server::resolve_session(
        &state,
        auth_header.as_deref(),
        credential_header.as_deref(),
        scope_header.as_deref(),
        client_ip,
    )
    .await
    {
        Ok(s) => s,
        Err((status, err_msg)) => {
            return Ok(make_error_response_with_protocol(
                status,
                "agentcontrol",
                "unauthorized",
                &err_msg,
                None,
                false,
                &uuid::Uuid::new_v4().to_string(),
                is_anthropic_protocol,
                is_responses_protocol,
            ));
        }
    };

    let policy_attr = session.policy.as_ref().and_then(|p| p.attribution.as_ref());
    let req_attribution = crate::spend::types::AttributionContext::resolve(
        client_id_hdr.as_deref(),
        project_id_hdr.as_deref(),
        cost_center_hdr.as_deref(),
        policy_attr,
        policy_attr.map(|a| a.client_id.as_str()),
    );

    if req.method() != hyper::Method::POST {
        return Ok(make_error_response_with_protocol(
            StatusCode::METHOD_NOT_ALLOWED,
            "agentcontrol",
            "method_not_allowed",
            "Method Not Allowed",
            None,
            false,
            &uuid::Uuid::new_v4().to_string(),
            is_anthropic_protocol,
            is_responses_protocol,
        ));
    }

    use http_body_util::BodyExt;
    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return Ok(make_error_response_with_protocol(
                StatusCode::BAD_REQUEST,
                "agentcontrol",
                "bad_request",
                "Failed to read request body",
                None,
                false,
                &uuid::Uuid::new_v4().to_string(),
                is_anthropic_protocol,
                is_responses_protocol,
            ));
        }
    };

    let mut body: Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(_) => {
            return Ok(make_error_response_with_protocol(
                StatusCode::BAD_REQUEST,
                "agentcontrol",
                "invalid_json",
                "Invalid JSON payload in request body",
                None,
                false,
                &uuid::Uuid::new_v4().to_string(),
                is_anthropic_protocol,
                is_responses_protocol,
            ));
        }
    };

    if !is_anthropic_protocol && !is_responses_protocol {
        normalize_inbound_openai_messages(&mut body);
    }

    let is_streaming = body
        .get("stream")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let req_uuid = uuid::Uuid::new_v4().to_string();
    let start_time = std::time::Instant::now();

    let model = match body.get("model").and_then(|v| v.as_str()) {
        Some(m) => m.to_string(),
        None => {
            return Ok(make_error_response_with_protocol(
                StatusCode::BAD_REQUEST,
                "agentcontrol",
                "missing_model_field",
                "Missing 'model' field in request body",
                None,
                is_streaming,
                &req_uuid,
                is_anthropic_protocol,
                is_responses_protocol,
            ));
        }
    };

    // Sanitize reasoning parameter for models that do not support reasoning effort
    // (e.g. gpt-4o, gpt-4o-mini, gpt-4, etc.)
    if !is_reasoning_capable_model(&model) {
        if let Some(obj) = body.as_object_mut() {
            obj.remove("reasoning");
            obj.remove("reasoning_effort");
        }
    }

    // Sanitize tool schemas early across all protocols and tool nesting levels
    sanitize_tool_schemas(&mut body);

    // Evaluate LLM policy — resolve from session scope, active global state, or JIT disk policy
    let global_policy = state.policy.read().ok().and_then(|g| g.clone());
    let (provider_rule, provider_name) = match session.policy.as_ref().or(global_policy.as_ref()) {
        Some(policy) => {
            if let Some(llm_config) = &policy.llm {
                if let Some(providers) = &llm_config.providers {
                    let mut matched = None;
                    for provider in providers {
                        if let Some(models) = &provider.models {
                            if models.iter().any(|m| {
                                m == "*"
                                    || m == &model
                                    || (m.ends_with('*')
                                        && model.starts_with(m.trim_end_matches('*')))
                            }) {
                                matched = Some((provider.clone(), provider.name.clone()));
                                break;
                            }
                        } else {
                            matched = Some((provider.clone(), provider.name.clone()));
                            break;
                        }
                    }
                    match matched {
                        Some(m) => m,
                        None => {
                            emit_llm_telemetry(
                                &state,
                                &session,
                                &model,
                                control_plane_proto::redact::RawDecision::Denied,
                            );
                            let _ = state
                                .audit_logger
                                .write_entry(
                                    &session.session_id,
                                    "llm_deny",
                                    &format!("llm:{}", model),
                                    Some(json!({"model": model})),
                                    Some(format!("Model '{}' not allowed by policy", model)),
                                    Some(start_time.elapsed().as_secs_f64() * 1000.0),
                                    session.identity_sub.clone(),
                                    session.identity_email.clone(),
                                    Some("sha256:active".to_string()),
                                    session.request_ip.clone(),
                                    None,
                                )
                                .await;
                            return Ok(make_error_response_with_protocol(
                                StatusCode::FORBIDDEN,
                                "agentcontrol",
                                "model_not_allowed",
                                &format!("Model '{}' is not allowed by policy", model),
                                None,
                                is_streaming,
                                &req_uuid,
                                is_anthropic_protocol,
                                is_responses_protocol,
                            ));
                        }
                    }
                } else {
                    return Ok(make_error_response_with_protocol(
                        StatusCode::FORBIDDEN,
                        "agentcontrol",
                        "providers_not_configured",
                        "LLM providers not configured in active policy",
                        None,
                        is_streaming,
                        &req_uuid,
                        is_anthropic_protocol,
                        is_responses_protocol,
                    ));
                }
            } else {
                (
                    crate::policy::schema::LlmProviderRule {
                        name: "default".to_string(),
                        action: "allow".to_string(),
                        models: None,
                        max_tokens_per_request: None,
                        dlp_tier: None,
                    },
                    "default".to_string(),
                )
            }
        }
        None => {
            // Check if local policy file exists on disk and load it JIT
            let mut loaded_policy = None;
            let candidate_paths = [
                std::path::PathBuf::from("agentcontrol-policy.yaml"),
                dirs::home_dir()
                    .map(|h| h.join("agentcontrol-policy.yaml"))
                    .unwrap_or_default(),
                dirs::home_dir()
                    .map(|h| h.join(".agentcontrol/agentcontrol-policy.yaml"))
                    .unwrap_or_default(),
                std::path::PathBuf::from(
                    r"C:\Windows\System32\config\systemprofile\.agentcontrol\agentcontrol-policy.yaml",
                ),
                std::path::PathBuf::from(r"C:\Program Files\AgentControl\agentcontrol-policy.yaml"),
            ];

            for p in &candidate_paths {
                if p.exists() {
                    if let crate::policy::loader::PolicyLoadResult::Loaded { policy, .. } =
                        crate::policy::loader::load_policy(p, None)
                    {
                        if let Ok(mut w) = state.policy.write() {
                            *w = Some(policy.clone());
                            state
                                .policy_loaded
                                .store(true, std::sync::atomic::Ordering::SeqCst);
                        }
                        loaded_policy = Some(policy);
                        break;
                    }
                }
            }

            if let Some(policy) = loaded_policy {
                if let Some(llm_config) = &policy.llm {
                    if let Some(providers) = &llm_config.providers {
                        let mut matched = None;
                        for provider in providers {
                            if let Some(models) = &provider.models {
                                if models.iter().any(|m| {
                                    m == "*"
                                        || m == &model
                                        || (m.ends_with('*')
                                            && model.starts_with(m.trim_end_matches('*')))
                                }) {
                                    matched = Some((provider.clone(), provider.name.clone()));
                                    break;
                                }
                            } else {
                                matched = Some((provider.clone(), provider.name.clone()));
                                break;
                            }
                        }
                        match matched {
                            Some(m) => m,
                            None => {
                                emit_llm_telemetry(
                                    &state,
                                    &session,
                                    &model,
                                    control_plane_proto::redact::RawDecision::Denied,
                                );
                                return Ok(make_error_response_with_protocol(
                                    StatusCode::FORBIDDEN,
                                    "agentcontrol",
                                    "model_not_allowed",
                                    &format!("Model '{}' is not allowed by policy", model),
                                    None,
                                    is_streaming,
                                    &req_uuid,
                                    is_anthropic_protocol,
                                    is_responses_protocol,
                                ));
                            }
                        }
                    } else {
                        return Ok(make_error_response_with_protocol(
                            StatusCode::FORBIDDEN,
                            "agentcontrol",
                            "providers_not_configured",
                            "LLM providers not configured in loaded policy",
                            None,
                            is_streaming,
                            &req_uuid,
                            is_anthropic_protocol,
                            is_responses_protocol,
                        ));
                    }
                } else {
                    (
                        crate::policy::schema::LlmProviderRule {
                            name: "default".to_string(),
                            action: "allow".to_string(),
                            models: None,
                            max_tokens_per_request: None,
                            dlp_tier: None,
                        },
                        "default".to_string(),
                    )
                }
            } else {
                emit_llm_telemetry(
                    &state,
                    &session,
                    &model,
                    control_plane_proto::redact::RawDecision::Denied,
                );
                return Ok(make_error_response_with_protocol(
                    StatusCode::FORBIDDEN,
                    "agentcontrol",
                    "no_active_policy",
                    "No active policy configured on the gateway",
                    None,
                    is_streaming,
                    &req_uuid,
                    is_anthropic_protocol,
                    is_responses_protocol,
                ));
            }
        }
    };

    if provider_rule.action == "deny" {
        emit_llm_telemetry(
            &state,
            &session,
            &model,
            control_plane_proto::redact::RawDecision::Denied,
        );
        let _ = state
            .audit_logger
            .write_entry(
                &session.session_id,
                "llm_deny",
                &format!("{}:{}", provider_name, model),
                Some(json!({"provider": provider_name, "model": model})),
                Some(format!("Model '{}' is denied by policy", model)),
                Some(start_time.elapsed().as_secs_f64() * 1000.0),
                session.identity_sub.clone(),
                session.identity_email.clone(),
                Some("sha256:active".to_string()),
                session.request_ip.clone(),
                None,
            )
            .await;
        return Ok(make_error_response_with_protocol(
            StatusCode::FORBIDDEN,
            "agentcontrol",
            "policy_denied",
            &format!("Model '{}' is denied by policy rule", model),
            None,
            is_streaming,
            &req_uuid,
            is_anthropic_protocol,
            is_responses_protocol,
        ));
    }

    let provider_name = if provider_name == "default" {
        infer_provider_from_model(&model)
    } else {
        provider_name
    };

    // Validate virtual key against local key cache if present
    if let Some(ref auth) = auth_header {
        let token = auth.strip_prefix("Bearer ").unwrap_or(auth).trim();
        if is_internal_agentcontrol_key(token) {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(token.as_bytes());
            let key_hash = hex::encode(hasher.finalize());

            if let Some(cached_key) = state.local_key_cache.get(&key_hash) {
                if let Err(reason) = state.local_key_cache.validate_request(
                    &cached_key,
                    client_ip,
                    &req_path,
                    &model,
                ) {
                    emit_llm_telemetry(
                        &state,
                        &session,
                        &model,
                        control_plane_proto::redact::RawDecision::Denied,
                    );
                    return Ok(make_error_response_with_protocol(
                        StatusCode::FORBIDDEN,
                        "agentcontrol",
                        "virtual_key_policy_denied",
                        &format!("Virtual key policy violation: {}", reason),
                        None,
                        is_streaming,
                        &req_uuid,
                        is_anthropic_protocol,
                        is_responses_protocol,
                    ));
                }
            }
        }
    }

    let llm_mode = std::env::var("AGENTCONTROL_LLM_MODE").unwrap_or_else(|_| {
        if state.centralized_mode || crate::identity::device::is_device_enrolled() {
            "central_enforce".to_string()
        } else {
            "local_compat".to_string()
        }
    });

    let input_est = estimate_input_tokens(&body);

    // ── 1. Centralized Modes (Zero Local Key Custody) ──────────────────────────
    if llm_mode == "central_enforce" || llm_mode == "central_shadow" {
        let hub_url = crate::identity::device::load_hub_url();
        let broker = crate::proxy::broker_client::BrokerClient::new(hub_url);

        let max_output = body
            .get("max_tokens")
            .or_else(|| body.get("max_completion_tokens"))
            .and_then(|v| v.as_i64())
            .unwrap_or(2048);

        let incoming_virtual_key = auth_header
            .as_deref()
            .map(|a| a.strip_prefix("Bearer ").unwrap_or(a).trim())
            .filter(|token| is_internal_agentcontrol_key(token))
            .map(|s| s.to_string());

        let broker_req = crate::proxy::broker_client::BrokerLLMRequest {
            schema_version: "3.0".to_string(),
            request_id: req_uuid.clone(),
            provider: provider_name.clone(),
            project_ref: session
                .identity_sub
                .clone()
                .unwrap_or_else(|| "default".to_string()),
            model: model.clone(),
            protocol: if is_anthropic_protocol || provider_name == "anthropic" {
                "anthropic_messages".to_string()
            } else if is_responses_protocol {
                "openai_responses".to_string()
            } else {
                "openai_chat_completions".to_string()
            },
            stream: is_streaming,
            llm_mode: Some(llm_mode.clone()),
            input_token_estimate: Some(input_est),
            max_output_tokens: Some(max_output),
            virtual_key: incoming_virtual_key,
            payload: {
                // Sanitize tool schemas before forwarding to the broker.
                // The OpenAI broker rejects top-level `anyOf`/`oneOf`/`allOf`/`enum`/`const`/`not`
                // and schemas without `type: "object"` (HTTP 400 invalid_function_parameters).
                let mut sanitized_body = body.clone();
                sanitize_tool_schemas(&mut sanitized_body);
                sanitized_body
            },
        };

        if is_streaming {
            match broker.invoke_brokered_stream(&broker_req).await {
                Ok(upstream_resp) => {
                    let status = StatusCode::from_u16(upstream_resp.status().as_u16())
                        .unwrap_or(StatusCode::OK);

                    if !status.is_success() {
                        let raw_bytes = upstream_resp.bytes().await.unwrap_or_default();
                        let upstream_err_json = serde_json::from_slice::<Value>(&raw_bytes).ok();
                        let err_msg = upstream_err_json
                            .as_ref()
                            .and_then(|j| j.get("error"))
                            .and_then(|e| e.get("message").or_else(|| e.get("error")))
                            .and_then(|m| m.as_str())
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| {
                                let s = std::str::from_utf8(&raw_bytes).unwrap_or("");
                                if s.is_empty() {
                                    format!("HTTP {}", status.as_u16())
                                } else {
                                    s.to_string()
                                }
                            });
                        let formatted_msg = format!(
                            "Upstream broker returned HTTP {}: {}",
                            status.as_u16(),
                            err_msg
                        );
                        return Ok(make_error_response_with_protocol(
                            status,
                            "upstream_provider",
                            &format!("upstream_http_{}", status.as_u16()),
                            &formatted_msg,
                            upstream_err_json,
                            is_streaming,
                            &req_uuid,
                            is_anthropic_protocol,
                            is_responses_protocol,
                        ));
                    }

                    emit_llm_telemetry(
                        &state,
                        &session,
                        &model,
                        control_plane_proto::redact::RawDecision::Allowed,
                    );
                    let mut stream = upstream_resp.bytes_stream();
                    let (tx, rx) = tokio::sync::mpsc::channel::<
                        Result<hyper::body::Frame<Bytes>, hyper::Error>,
                    >(64);
                    let state_clone_for_broker_stream = state.clone();
                    let session_clone_for_broker_stream = session.clone();
                    let model_clone_for_broker_stream = model.clone();
                    let provider_name_clone_for_broker_stream = provider_name.clone();
                    let start_time_for_broker_stream = start_time;
                    let input_est_for_broker_stream = input_est;
                    let req_uuid_for_broker_stream = req_uuid.clone();
                    let is_anthropic_for_broker_stream = is_anthropic_protocol;
                    let is_responses_for_broker_stream = is_responses_protocol;
                    tokio::spawn(async move {
                        let mut byte_buffer = Vec::<u8>::new();
                        let mut has_emitted_content = false;
                        let mut streamed_chunks_count: u64 = 0;
                        let mut streamed_tokens_est: u64 = 0;
                        while let Some(chunk_res) = stream.next().await {
                            match chunk_res {
                                Ok(chunk) => {
                                    byte_buffer.extend_from_slice(&chunk);
                                    while let Some((pos, delim_len)) =
                                        find_sse_event_boundary(&byte_buffer)
                                    {
                                        let event_bytes = byte_buffer[..pos].to_vec();
                                        byte_buffer.drain(..pos + delim_len);
                                        let text = String::from_utf8_lossy(&event_bytes);
                                        if let Some(clean_event) = sanitize_sse_block(&text) {
                                            has_emitted_content = true;
                                            streamed_chunks_count += 1;
                                            streamed_tokens_est +=
                                                (clean_event.len() as u64 / 4).max(1);
                                            if tx
                                                .send(Ok(hyper::body::Frame::data(Bytes::from(
                                                    clean_event,
                                                ))))
                                                .await
                                                .is_err()
                                            {
                                                // REQ-OPS-003 / Task 3.3: Downstream client disconnect (TCP RST / client abort)
                                                crate::logging::log_event(
                                                    crate::logging::Level::Warn,
                                                    "streaming_client_disconnect",
                                                    serde_json::json!({
                                                        "request_id": req_uuid_for_broker_stream,
                                                        "chunks_streamed": streamed_chunks_count,
                                                        "tokens_settled": streamed_tokens_est
                                                    }),
                                                );
                                                let broker_cancel =
                                                    crate::proxy::broker_client::BrokerClient::new(
                                                        crate::identity::device::load_hub_url(),
                                                    );
                                                let req_id_cancel =
                                                    req_uuid_for_broker_stream.clone();
                                                tokio::spawn(async move {
                                                    let _ = broker_cancel
                                                        .cancel_brokered_stream(&req_id_cancel)
                                                        .await;
                                                });
                                                return;
                                            }
                                        }
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                        if !byte_buffer.is_empty() {
                            let text = String::from_utf8_lossy(&byte_buffer);
                            if let Some(clean_event) = sanitize_sse_block(&text) {
                                has_emitted_content = true;
                                let _ = tx
                                    .send(Ok(hyper::body::Frame::data(Bytes::from(clean_event))))
                                    .await;
                            }
                        }
                        if !has_emitted_content && !is_responses_for_broker_stream {
                            let payload = if is_anthropic_for_broker_stream {
                                let err_chunk = serde_json::json!({
                                    "type": "error",
                                    "error": {
                                        "type": "api_error",
                                        "message": "[AgentControl Gateway] Upstream broker completed stream without content deltas"
                                    }
                                });
                                format!(
                                    "event: error\ndata: {}\n\n",
                                    serde_json::to_string(&err_chunk).unwrap_or_default()
                                )
                            } else {
                                let err_chunk = serde_json::json!({
                                    "error": {
                                        "message": "[AgentControl Gateway] Upstream broker completed stream without content deltas",
                                        "type": "server_error",
                                        "code": "empty_stream"
                                    }
                                });
                                format!(
                                    "data: {}\n\ndata: [DONE]\n\n",
                                    serde_json::to_string(&err_chunk).unwrap_or_default()
                                )
                            };
                            let _ = tx
                                .send(Ok(hyper::body::Frame::data(Bytes::from(payload))))
                                .await;
                        }

                        // Send structured request log to control hub "Request Logs" tab
                        if let Some(ref dc) = state_clone_for_broker_stream.dashboard_client {
                            let key_hash = {
                                use sha2::{Digest, Sha256};
                                session_clone_for_broker_stream
                                    .identity_sub
                                    .as_deref()
                                    .map(|sub| {
                                        let mut h = Sha256::new();
                                        h.update(sub.as_bytes());
                                        format!("sha256:{:.8}", hex::encode(h.finalize()))
                                    })
                            };
                            dc.send_llm_request_log(crate::control_plane_client::client::LlmRequestLog {
                                request_id: req_uuid_for_broker_stream.clone(),
                                session_id: session_clone_for_broker_stream.session_id.clone(),
                                key_hash,
                                model: model_clone_for_broker_stream.clone(),
                                provider: provider_name_clone_for_broker_stream.clone(),
                                is_streaming: true,
                                prompt_tokens: input_est_for_broker_stream,
                                completion_tokens: streamed_tokens_est as i64,
                                total_tokens: (input_est_for_broker_stream + streamed_tokens_est as i64),
                                latency_ms: start_time_for_broker_stream.elapsed().as_secs_f64() * 1000.0,
                                status_code: 200,
                                verdict: "allow".to_string(),
                                identity_sub: session_clone_for_broker_stream
                                    .identity_sub
                                    .clone()
                                    .or_else(|| crate::identity::device::load_user_email()),
                                identity_email: session_clone_for_broker_stream
                                    .identity_email
                                    .clone()
                                    .or_else(|| crate::identity::device::load_user_email()),
                                request_ip: session_clone_for_broker_stream.request_ip.clone(),
                                timestamp_ms: chrono::Utc::now().timestamp_millis(),
                                is_estimated: true,
                                protocol: if is_anthropic_for_broker_stream {
                                    "anthropic_messages".to_string()
                                } else if is_responses_for_broker_stream {
                                    "openai_responses".to_string()
                                } else {
                                    "openai_chat_completions".to_string()
                                },
                            });
                        }
                    });

                    let stream_body =
                        http_body_util::BodyExt::boxed(http_body_util::StreamBody::new(
                            tokio_stream::wrappers::ReceiverStream::new(rx),
                        ));
                    let resp_builder = Response::builder()
                        .status(status)
                        .header(
                            hyper::header::CONTENT_TYPE,
                            "text/event-stream; charset=utf-8",
                        )
                        .header(hyper::header::CACHE_CONTROL, "no-cache, no-transform")
                        .header(hyper::header::CONNECTION, "keep-alive")
                        .header("X-Accel-Buffering", "no");

                    return Ok(resp_builder.body(stream_body).unwrap());
                }
                Err(e) => {
                    if let Some(crate::proxy::broker_client::BrokerError::BudgetExceeded(msg)) =
                        e.downcast_ref::<crate::proxy::broker_client::BrokerError>()
                    {
                        let finops_err = serde_json::json!({
                            "error": {
                                "message": format!("Vexa FinOps: Monthly spend budget limit reached ({}). Contact your administrator.", msg),
                                "type": "budget_exceeded",
                                "code": "BUDGET_EXCEEDED"
                            }
                        });
                        return Ok(make_error_response_with_protocol(
                            StatusCode::TOO_MANY_REQUESTS,
                            "finops",
                            "BUDGET_EXCEEDED",
                            &format!("Vexa FinOps: Monthly spend budget limit reached ({}). Contact your administrator.", msg),
                            Some(finops_err),
                            is_streaming,
                            &req_uuid,
                            is_anthropic_protocol,
                            is_responses_protocol,
                        ));
                    }
                    return Ok(make_error_response_with_protocol(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "agentcontrol",
                        "broker_stream_failed",
                        &format!("Central broker streaming failed (fail-closed): {}", e),
                        None,
                        is_streaming,
                        &req_uuid,
                        is_anthropic_protocol,
                        is_responses_protocol,
                    ));
                }
            }
        } else {
            match broker.invoke_brokered_llm(&broker_req).await {
                Ok(brokered_resp) => {
                    emit_llm_telemetry(
                        &state,
                        &session,
                        &model,
                        control_plane_proto::redact::RawDecision::Allowed,
                    );
                    if let Some(ref dc) = state.dashboard_client {
                        let usage = brokered_resp.response.get("usage");
                        let p_tokens = usage
                            .and_then(|u| u.get("prompt_tokens"))
                            .and_then(|v| v.as_i64())
                            .unwrap_or(input_est);
                        let c_tokens = usage
                            .and_then(|u| u.get("completion_tokens"))
                            .and_then(|v| v.as_i64())
                            .unwrap_or(0);
                        let t_tokens = usage
                            .and_then(|u| u.get("total_tokens"))
                            .and_then(|v| v.as_i64())
                            .unwrap_or(p_tokens + c_tokens);
                        let key_hash = {
                            use sha2::{Digest, Sha256};
                            session
                                .identity_sub
                                .as_deref()
                                .map(|sub| {
                                    let mut h = Sha256::new();
                                    h.update(sub.as_bytes());
                                    format!("sha256:{:.8}", hex::encode(h.finalize()))
                                })
                        };
                        dc.send_llm_request_log(crate::control_plane_client::client::LlmRequestLog {
                            request_id: req_uuid.clone(),
                            session_id: session.session_id.clone(),
                            key_hash,
                            model: model.clone(),
                            provider: provider_name.clone(),
                            is_streaming: false,
                            prompt_tokens: p_tokens,
                            completion_tokens: c_tokens,
                            total_tokens: t_tokens,
                            latency_ms: start_time.elapsed().as_secs_f64() * 1000.0,
                            status_code: 200,
                            verdict: "allow".to_string(),
                            identity_sub: session
                                .identity_sub
                                .clone()
                                .or_else(|| crate::identity::device::load_user_email()),
                            identity_email: session
                                .identity_email
                                .clone()
                                .or_else(|| crate::identity::device::load_user_email()),
                            request_ip: session.request_ip.clone(),
                            timestamp_ms: chrono::Utc::now().timestamp_millis(),
                            is_estimated: false,
                            protocol: if is_anthropic_protocol {
                                "anthropic_messages".to_string()
                            } else if is_responses_protocol {
                                "openai_responses".to_string()
                            } else {
                                "openai_chat_completions".to_string()
                            },
                        });
                    }
                    let resp_bytes =
                        serde_json::to_vec(&brokered_resp.response).unwrap_or_default();
                    let mut builder = Response::builder().status(StatusCode::OK);
                    builder = builder.header(hyper::header::CONTENT_TYPE, "application/json");
                    return Ok(builder
                        .body(full_to_box_body(Full::new(Bytes::from(resp_bytes))))
                        .unwrap());
                }
                Err(e) => {
                    if let Some(crate::proxy::broker_client::BrokerError::BudgetExceeded(msg)) =
                        e.downcast_ref::<crate::proxy::broker_client::BrokerError>()
                    {
                        let finops_err = serde_json::json!({
                            "error": {
                                "message": format!("Vexa FinOps: Monthly spend budget limit reached ({}). Contact your administrator.", msg),
                                "type": "budget_exceeded",
                                "code": "BUDGET_EXCEEDED"
                            }
                        });
                        return Ok(make_error_response_with_protocol(
                            StatusCode::TOO_MANY_REQUESTS,
                            "finops",
                            "BUDGET_EXCEEDED",
                            &format!("Vexa FinOps: Monthly spend budget limit reached ({}). Contact your administrator.", msg),
                            Some(finops_err),
                            is_streaming,
                            &req_uuid,
                            is_anthropic_protocol,
                            is_responses_protocol,
                        ));
                    }
                    return Ok(make_error_response_with_protocol(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "agentcontrol",
                        "broker_request_failed",
                        &format!("Central broker request failed (fail-closed): {}", e),
                        None,
                        is_streaming,
                        &req_uuid,
                        is_anthropic_protocol,
                        is_responses_protocol,
                    ));
                }
            }
        }
    }

    // ── 2. Local Compat Mode (Local env keys / request headers) ────────────────
    let api_key = match state
        .provider_keys
        .get(&provider_name)
        .map(|k| k.clone())
        .or_else(|| match provider_name.as_str() {
            "openai" => get_env_or_dotenv("OPENAI_API_KEY"),
            "anthropic" => get_env_or_dotenv("ANTHROPIC_API_KEY"),
            "google" | "gemini" => {
                get_env_or_dotenv("GEMINI_API_KEY").or_else(|| get_env_or_dotenv("GOOGLE_API_KEY"))
            }
            _ => get_env_or_dotenv(&format!("{}_API_KEY", provider_name.to_uppercase())),
        })
        .or_else(|| {
            auth_header.as_deref().and_then(|h| {
                let token = h.strip_prefix("Bearer ").unwrap_or(h).trim();
                // Critical: Virtual Keys (sk-vex-...) and internal managed keys must NEVER
                // be forwarded to upstream providers as raw API keys.
                if !token.is_empty()
                    && !is_internal_agentcontrol_key(token)
                    && (token.starts_with("sk-") || token.starts_with("AIza") || token.len() > 15)
                {
                    Some(token.to_string())
                } else {
                    None
                }
            })
        }) {
        Some(k) => k,
        None => {
            let is_virtual_key = auth_header
                .as_deref()
                .map(is_internal_agentcontrol_key)
                .unwrap_or(false);

            let (code, msg) = if is_virtual_key {
                (
                    "missing_upstream_provider_key",
                    format!(
                        "AgentControl Virtual Key accepted, but upstream API key for provider '{}' is not configured on this gateway. To dispatch requests upstream, configure {}_API_KEY in your environment, create a .env file, or configure provider keys in the Vexa Console.",
                        provider_name,
                        provider_name.to_uppercase()
                    ),
                )
            } else {
                (
                    "missing_provider_api_key",
                    format!(
                        "API key for provider '{}' is not configured on the gateway (set {}_API_KEY environment variable or configure in Dashboard)",
                        provider_name,
                        provider_name.to_uppercase()
                    ),
                )
            };

            return Ok(make_error_response_with_protocol(
                StatusCode::SERVICE_UNAVAILABLE,
                "agentcontrol",
                code,
                &msg,
                None,
                is_streaming,
                &req_uuid,
                is_anthropic_protocol,
                is_responses_protocol,
            ));
        }
    };

    // ── Gateway Semantic Cache Lookup (Pillar 1) ─────────────────────────────
    let prompt_text = extract_prompt_text(&body);
    let tenant_id = session
        .identity_sub
        .as_deref()
        .unwrap_or("default")
        .to_string();
    let temp_fixed = body
        .get("temperature")
        .and_then(|t| t.as_f64())
        .map(|f| format!("{:.3}", f))
        .unwrap_or_else(|| "0.000".to_string());

    let canonical_ctx = crate::proxy::semantic_cache::CanonicalContext {
        tenant_id: tenant_id.clone(),
        subject_id: session
            .identity_email
            .as_deref()
            .unwrap_or("anonymous")
            .to_string(),
        virtual_key_scope: scope_header.clone(),
        provider: provider_name.clone(),
        model: model.clone(),
        model_version: None,
        policy_version: "1.0.82".to_string(),
        workspace_hash: None,
        system_prompt_hash: "system_default".to_string(),
        developer_message_hash: None,
        temperature_fixed: temp_fixed,
        top_p_fixed: body
            .get("top_p")
            .and_then(|t| t.as_f64())
            .map(|f| format!("{:.3}", f)),
        top_k: None,
        seed: body.get("seed").and_then(|s| s.as_u64()),
        max_tokens: body
            .get("max_tokens")
            .and_then(|m| m.as_u64())
            .map(|u| u as u32),
        stop_sequences: vec![],
        response_format: body.get("response_format").map(|rf| rf.to_string()),
        reasoning_effort: body
            .get("reasoning_effort")
            .and_then(|re| re.as_str())
            .map(|s| s.to_string()),
        locale: None,
        normalized_prompt: prompt_text.clone(),
    };

    let is_cacheable_req = match crate::proxy::semantic_cache::SemanticCache::is_request_cacheable(
        &body,
        &canonical_ctx,
    ) {
        Ok(()) => true,
        Err(reason) => {
            state.semantic_cache.metrics.record_bypass(reason);
            false
        }
    };

    if state.semantic_cache.is_enabled() && is_cacheable_req && !prompt_text.is_empty() {
        if let Some(hit) = state
            .semantic_cache
            .lookup_with_context(&state.http_client, &canonical_ctx)
            .await
        {
            session.tokens_used.fetch_add(
                (hit.prompt_tokens + hit.completion_tokens) as u64,
                std::sync::atomic::Ordering::Relaxed,
            );

            emit_llm_telemetry(
                &state,
                &session,
                &model,
                control_plane_proto::redact::RawDecision::Allowed,
            );
            let _ = state
                .audit_logger
                .write_entry(
                    &session.session_id,
                    "llm_cache_hit",
                    &format!("{}:{}", provider_name, model),
                    Some(json!({
                        "provider": provider_name,
                        "model": model,
                        "cache_hit_type": hit.hit_type,
                        "similarity": hit.similarity,
                        "tokens_saved": hit.prompt_tokens + hit.completion_tokens,
                        "cost_saved_usd": hit.cost_saved_usd,
                        "cached_prompt": hit.cached_prompt,
                    })),
                    Some(format!(
                        "Satisfied by Vexa Gateway Semantic Cache ({}) with similarity {:.3}",
                        hit.hit_type, hit.similarity
                    )),
                    Some(start_time.elapsed().as_secs_f64() * 1000.0),
                    session.identity_sub.clone(),
                    session.identity_email.clone(),
                    Some("sha256:active".to_string()),
                    session.request_ip.clone(),
                    None,
                )
                .await;

            let hit_header = if hit.hit_type == "exact" {
                "HIT-EXACT"
            } else {
                "HIT-SEMANTIC"
            };
            let sim_str = format!("{:.3}", hit.similarity);
            let cost_saved_str = format!("{:.4}", hit.cost_saved_usd);
            let tokens_saved_str = format!("{}", hit.prompt_tokens + hit.completion_tokens);

            if is_streaming {
                let cached_text = extract_completion_text_from_bytes(&hit.response_body);
                let (tx, rx) = tokio::sync::mpsc::channel::<
                    Result<hyper::body::Frame<Bytes>, hyper::Error>,
                >(4);

                let stream_payload = if is_anthropic_protocol {
                    format!(
                        "event: message_start\ndata: {}\n\nevent: content_block_start\ndata: {}\n\nevent: content_block_delta\ndata: {}\n\nevent: content_block_stop\ndata: {{\"type\":\"content_block_stop\",\"index\":0}}\n\nevent: message_delta\ndata: {}\n\nevent: message_stop\ndata: {{\"type\":\"message_stop\"}}\n\n",
                        serde_json::json!({
                            "type": "message_start",
                            "message": {
                                "id": format!("msg-cached-{}", req_uuid),
                                "type": "message",
                                "role": "assistant",
                                "model": model,
                                "content": [],
                                "stop_reason": null,
                                "stop_sequence": null,
                                "usage": { "input_tokens": 0, "output_tokens": hit.completion_tokens }
                            }
                        }),
                        serde_json::json!({
                            "type": "content_block_start",
                            "index": 0,
                            "content_block": { "type": "text", "text": "" }
                        }),
                        serde_json::json!({
                            "type": "content_block_delta",
                            "index": 0,
                            "delta": { "type": "text_delta", "text": cached_text }
                        }),
                        serde_json::json!({
                            "type": "message_delta",
                            "delta": { "stop_reason": "end_turn", "stop_sequence": null },
                            "usage": { "output_tokens": hit.completion_tokens }
                        })
                    )
                } else {
                    let sse_chunk = serde_json::json!({
                        "id": format!("chatcmpl-cached-{}", req_uuid),
                        "object": "chat.completion.chunk",
                        "created": chrono::Utc::now().timestamp(),
                        "model": model,
                        "choices": [{
                            "index": 0,
                            "delta": {
                                "role": "assistant",
                                "content": cached_text
                            },
                            "finish_reason": "stop"
                        }]
                    });
                    format!(
                        "data: {}\n\ndata: [DONE]\n\n",
                        serde_json::to_string(&sse_chunk).unwrap_or_default()
                    )
                };

                let _ = tx.try_send(Ok(hyper::body::Frame::data(Bytes::from(stream_payload))));
                let stream_body = http_body_util::BodyExt::boxed(http_body_util::StreamBody::new(
                    tokio_stream::wrappers::ReceiverStream::new(rx),
                ));

                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(
                        hyper::header::CONTENT_TYPE,
                        "text/event-stream; charset=utf-8",
                    )
                    .header(hyper::header::CACHE_CONTROL, "no-cache, no-transform")
                    .header(hyper::header::CONNECTION, "keep-alive")
                    .header("X-Accel-Buffering", "no")
                    .header("X-AgentControl-Origin", "agentcontrol")
                    .header("X-AgentControl-Verdict", "allowed")
                    .header("X-AgentControl-Cache", hit_header)
                    .header("X-AgentControl-Similarity", sim_str)
                    .header("X-AgentControl-Savings-Type", "GATEWAY_FULL_AVOIDANCE")
                    .header("X-AgentControl-Cost-Saved-USD", cost_saved_str)
                    .header("X-AgentControl-Tokens-Saved", tokens_saved_str)
                    .header("X-AgentControl-Request-ID", &req_uuid)
                    .body(stream_body)
                    .unwrap());
            } else {
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(hyper::header::CONTENT_TYPE, hit.content_type)
                    .header("X-AgentControl-Origin", "agentcontrol")
                    .header("X-AgentControl-Verdict", "allowed")
                    .header("X-AgentControl-Cache", hit_header)
                    .header("X-AgentControl-Similarity", sim_str)
                    .header("X-AgentControl-Savings-Type", "GATEWAY_FULL_AVOIDANCE")
                    .header("X-AgentControl-Cost-Saved-USD", cost_saved_str)
                    .header("X-AgentControl-Tokens-Saved", tokens_saved_str)
                    .header("X-AgentControl-Request-ID", &req_uuid)
                    .body(full_to_box_body(Full::new(hit.response_body)))
                    .unwrap());
            }
        }
    }

    // ── Preflight Spend Authorization (Optional in local_compat) ──────────────
    let hub_url = crate::identity::device::load_hub_url();
    let mut active_reservation_id: Option<String> = None;
    let gateway_secret = std::env::var("GATEWAY_SECRET").ok();

    if state.centralized_mode || hub_url.is_some() {
        if hub_url.is_none() {
            if state.centralized_mode {
                return Ok(make_error_response_with_protocol(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "agentcontrol",
                    "spend_governance_unreachable",
                    "Centralized enforce mode requires DASHBOARD_API_URL for spend preflight governance",
                    None,
                    is_streaming,
                    &req_uuid,
                    is_anthropic_protocol,
                    is_responses_protocol,
                ));
            }
        } else if let Some(ref hub_base) = hub_url {
            let max_output = body
                .get("max_tokens")
                .or_else(|| body.get("max_completion_tokens"))
                .and_then(|v| v.as_i64())
                .unwrap_or(2048);

            let body_str = serde_json::to_string(&body).unwrap_or_default();
            let mut hasher = sha2::Sha256::new();
            hasher.update(body_str.as_bytes());
            let req_hash = hex::encode(hasher.finalize());

            let device_id = crate::identity::device::load_device_token()
                .or_else(|| {
                    crate::identity::device::DeviceIdentity::load_or_create()
                        .ok()
                        .map(|id| id.device_id)
                })
                .or_else(|| std::env::var("AGENTCONTROL_DEVICE_ID").ok())
                .or_else(|| std::env::var("GATEWAY_ID").ok())
                .unwrap_or_else(|| session.session_id.clone());

            let current_user = session
                .identity_email
                .clone()
                .or_else(|| session.identity_sub.clone())
                .or_else(|| crate::identity::device::load_user_email())
                .or_else(|| {
                    let u = crate::identity::device::get_current_user();
                    if u.is_empty() || u == "unknown" {
                        None
                    } else {
                        Some(u)
                    }
                });

            let local_hostname = crate::identity::device::get_hostname();
            let device_name = if !local_hostname.is_empty() {
                Some(local_hostname)
            } else {
                None
            };

            let auth_req = crate::spend::types::SpendV2AuthorizeReq {
                gateway_id: Some(device_id),
                request_id: req_uuid.clone(),
                idempotency_key: format!("auth-{}", req_uuid),
                project_id: session
                    .identity_sub
                    .clone()
                    .unwrap_or_else(|| "default".to_string()),
                provider: provider_name.clone(),
                model: model.clone(),
                input_token_estimate: input_est,
                max_output_tokens: max_output,
                request_hash: req_hash,
                session_id: Some(session.session_id.clone()),
                internal_user_id: current_user,
                device_name,
                virtual_key_prefix: None,
                virtual_key_alias: None,
            };

            let auth_url = format!("{}/api/v2/spend/authorize", hub_base.trim_end_matches('/'));
            let mut req_builder = state.http_client.post(&auth_url);
            if let Some(ref sec) = gateway_secret {
                req_builder = req_builder.header("Authorization", format!("Bearer {}", sec));
            }

            match req_builder.json(&auth_req).send().await {
                Ok(resp) => {
                    if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
                        emit_llm_telemetry(
                            &state,
                            &session,
                            &model,
                            control_plane_proto::redact::RawDecision::Denied,
                        );
                        let deny_body: serde_json::Value = resp.json().await.unwrap_or_default();
                        let _ = state
                            .audit_logger
                            .write_entry(
                                &session.session_id,
                                "llm_spend_deny",
                                &format!("{}:{}", provider_name, model),
                                Some(json!({"provider": provider_name, "model": model, "deny_details": deny_body})),
                                Some("Preflight spend budget exceeded or denied before dispatch".to_string()),
                                Some(start_time.elapsed().as_secs_f64() * 1000.0),
                                session.identity_sub.clone(),
                                session.identity_email.clone(),
                                Some("sha256:active".to_string()),
                                session.request_ip.clone(),
                                None,
                            )
                            .await;

                        let reason_code = deny_body
                            .get("reason_code")
                            .and_then(|v| v.as_str())
                            .unwrap_or("spend_budget_exhausted")
                            .to_string();
                        let scope = deny_body
                            .get("disclosure_safe_scope")
                            .and_then(|v| v.as_str())
                            .unwrap_or("spend budget");
                        let reset_info = deny_body
                            .get("reset_at")
                            .and_then(|v| v.as_str())
                            .map(|t| format!(" (quota window resets at {})", t))
                            .unwrap_or_default();
                        let msg = format!(
                            "Spend budget limit exceeded for {} tier{}. Please request a budget adjustment from your workspace administrator under LLM Providers & Spend Governance in the AgentControl Console, or switch to an alternate project/model.",
                            scope, reset_info
                        );

                        return Ok(make_error_response_with_protocol(
                            StatusCode::TOO_MANY_REQUESTS,
                            "agentcontrol",
                            &reason_code,
                            &msg,
                            Some(deny_body),
                            is_streaming,
                            &req_uuid,
                            is_anthropic_protocol,
                            is_responses_protocol,
                        ));
                    } else if resp.status().is_success() {
                        if let Ok(allow_resp) = resp
                            .json::<crate::spend::types::SpendV2AuthorizeResp>()
                            .await
                        {
                            active_reservation_id = allow_resp.reservation_id;
                        }
                    } else if state.centralized_mode {
                        let msg = format!(
                            "Spend authorization preflight returned non-success status: {}",
                            resp.status()
                        );
                        return Ok(make_error_response_with_protocol(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "agentcontrol",
                            "spend_governance_denied",
                            &msg,
                            None,
                            is_streaming,
                            &req_uuid,
                            is_anthropic_protocol,
                            is_responses_protocol,
                        ));
                    }
                }
                Err(e) => {
                    if state.centralized_mode {
                        let msg = format!("Spend authorization preflight failed: {}", e);
                        return Ok(make_error_response_with_protocol(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "agentcontrol",
                            "spend_governance_unreachable",
                            &msg,
                            None,
                            is_streaming,
                            &req_uuid,
                            is_anthropic_protocol,
                            is_responses_protocol,
                        ));
                    }
                }
            }
        }
    }

    // ADR-010: Inject include_usage stream options for OpenAI streaming
    if (!is_anthropic_protocol || provider_name == "openai")
        && (provider_name == "openai" || provider_name == "google" || provider_name == "gemini")
    {
        if let Some(obj) = body.as_object_mut() {
            if obj.get("stream").and_then(|v| v.as_bool()).unwrap_or(false) {
                obj.insert("stream_options".to_string(), json!({"include_usage": true}));
            }
        }
    }

    // AR-2: Pluggable Routing Strategy Resolution
    let mut routed_endpoint: Option<String> = None;

    if let Ok(policy_guard) = state.policy.read() {
        if let Some(ref policy) = *policy_guard {
            if let Some(ref llm_cfg) = policy.llm {
                if let Some(ref groups) = llm_cfg.model_groups {
                    for grp in groups {
                        if grp.name == model
                            || grp.name == provider_name
                            || grp.deployments.iter().any(|d| d.model_name == model)
                        {
                            let strat = crate::proxy::routing::get_strategy(
                                grp.routing_strategy.as_deref().unwrap_or("priority"),
                                grp.allowed_regions.clone(),
                            );
                            let candidates: Vec<crate::proxy::provider_router::Deployment> = grp
                                .deployments
                                .iter()
                                .map(|d| crate::proxy::provider_router::Deployment {
                                    id: d.id.clone(),
                                    provider: d.provider.clone(),
                                    model_name: d.model_name.clone(),
                                    endpoint_url: d.endpoint_url.clone(),
                                    credential_ref: d.credential_ref.clone(),
                                    priority: d.priority.unwrap_or(1),
                                    weight: d.weight.unwrap_or(1),
                                    region: d.region.clone(),
                                })
                                .collect();

                            match strat.select(&candidates, state.provider_router.as_ref()) {
                                crate::proxy::routing::RoutingDecision::Selected(dep) => {
                                    routed_endpoint = Some(dep.endpoint_url);
                                    break;
                                }
                                crate::proxy::routing::RoutingDecision::NoEligibleDeployment {
                                    reason,
                                } => {
                                    eprintln!(
                                        "[routing] No eligible deployment in model group {}: {}",
                                        grp.name, reason
                                    );
                                    return Ok(crate::proxy::server::json_response(
                                        StatusCode::SERVICE_UNAVAILABLE,
                                        &serde_json::json!({
                                            "error": {
                                                "message": format!("Routing policy failure: {}", reason),
                                                "type": "routing_policy_violation",
                                                "code": "no_eligible_deployment"
                                            }
                                        }),
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if routed_endpoint.is_none() {
        if let Some(dep) = state.provider_router.select_deployment(&model) {
            routed_endpoint = Some(dep.endpoint_url);
        }
    }

    // Build upstream request — cross-protocol adaptation & header preparation
    let (target_endpoint, upstream_headers, req_body_bytes) =
        if !is_anthropic_protocol && provider_name == "anthropic" {
            // OpenAI client -> Anthropic upstream transformation
            let norm_req =
                match crate::proxy::transformer::NormalizedLLMRequest::from_openai_value(&body) {
                    Ok(nr) => nr,
                    Err(e) => {
                        return Ok(make_error_response_with_protocol(
                            StatusCode::BAD_REQUEST,
                            "agentcontrol",
                            "request_normalization_failed",
                            &e,
                            None,
                            is_streaming,
                            &req_uuid,
                            is_anthropic_protocol,
                            is_responses_protocol,
                        ));
                    }
                };
            let base_url = std::env::var("ANTHROPIC_BASE_URL").ok();
            match crate::proxy::transformer::anthropic::AnthropicTransformer.transform_request(
                &norm_req,
                &api_key,
                base_url.as_deref(),
            ) {
                Ok((ep, hdrs, bytes)) => (ep, hdrs, bytes),
                Err(e) => {
                    return Ok(make_error_response_with_protocol(
                        StatusCode::BAD_REQUEST,
                        "agentcontrol",
                        "request_transformation_failed",
                        &e,
                        None,
                        is_streaming,
                        &req_uuid,
                        is_anthropic_protocol,
                        is_responses_protocol,
                    ));
                }
            }
        } else if is_anthropic_protocol && provider_name != "anthropic" {
            // Anthropic client -> OpenAI upstream transformation
            let mut openai_messages = Vec::new();
            if let Some(sys) = body.get("system").and_then(|v| v.as_str()) {
                openai_messages.push(json!({"role": "system", "content": sys}));
            }
            if let Some(msgs) = body.get("messages").and_then(|v| v.as_array()) {
                for m in msgs {
                    let role = m.get("role").and_then(|v| v.as_str()).unwrap_or("user");
                    if let Some(content_str) = m.get("content").and_then(|v| v.as_str()) {
                        openai_messages.push(json!({"role": role, "content": content_str}));
                    } else if let Some(content_arr) = m.get("content").and_then(|v| v.as_array()) {
                        let mut text = String::new();
                        for part in content_arr {
                            if let Some(t) = part.get("text").and_then(|v| v.as_str()) {
                                text.push_str(t);
                            }
                        }
                        openai_messages.push(json!({"role": role, "content": text}));
                    }
                }
            }
            let mut openai_body = json!({
                "model": model,
                "messages": openai_messages,
                "stream": is_streaming,
            });
            if let Some(mt) = body.get("max_tokens").and_then(|v| v.as_i64()) {
                openai_body["max_tokens"] = json!(mt);
            }
            if let Some(temp) = body.get("temperature") {
                openai_body["temperature"] = temp.clone();
            }
            let base_url = match provider_name.as_str() {
                "google" | "gemini" => std::env::var("GEMINI_BASE_URL").unwrap_or_else(|_| {
                    "https://generativelanguage.googleapis.com/v1beta/openai".to_string()
                }),
                _ => std::env::var("OPENAI_BASE_URL")
                    .unwrap_or_else(|_| "https://api.openai.com".to_string()),
            };
            let ep = format!("{}/v1/chat/completions", base_url.trim_end_matches('/'));
            let mut hdrs = hyper::HeaderMap::new();
            hdrs.insert(
                hyper::header::CONTENT_TYPE,
                "application/json".parse().unwrap(),
            );
            hdrs.insert(
                hyper::header::AUTHORIZATION,
                format!("Bearer {}", api_key).parse().unwrap(),
            );
            let bytes = Bytes::from(serde_json::to_vec(&openai_body).unwrap_or_default());
            (ep, hdrs, bytes)
        } else if provider_name == "anthropic" {
            // Native Anthropic client -> Anthropic upstream
            let base_url = std::env::var("ANTHROPIC_BASE_URL")
                .unwrap_or_else(|_| "https://api.anthropic.com".to_string());
            let ep = format!("{}/v1/messages", base_url.trim_end_matches('/'));
            let mut hdrs = hyper::HeaderMap::new();
            hdrs.insert(
                hyper::header::CONTENT_TYPE,
                "application/json".parse().unwrap(),
            );
            hdrs.insert(
                "x-api-key".parse::<hyper::header::HeaderName>().unwrap(),
                api_key.parse().unwrap(),
            );
            hdrs.insert(
                "anthropic-version"
                    .parse::<hyper::header::HeaderName>()
                    .unwrap(),
                "2023-06-01".parse().unwrap(),
            );
            let bytes = Bytes::from(serde_json::to_vec(&body).unwrap_or_default());
            (ep, hdrs, bytes)
        } else {
            // Native OpenAI client -> OpenAI / Gemini / Groq upstream
            let base_url = match provider_name.as_str() {
                "google" | "gemini" => std::env::var("GEMINI_BASE_URL").unwrap_or_else(|_| {
                    "https://generativelanguage.googleapis.com/v1beta/openai".to_string()
                }),
                _ => std::env::var("OPENAI_BASE_URL")
                    .unwrap_or_else(|_| "https://api.openai.com".to_string()),
            };
            let ep = if let Some(routed) = routed_endpoint {
                routed
            } else if is_responses_protocol {
                format!("{}/v1/responses", base_url.trim_end_matches('/'))
            } else {
                format!("{}/v1/chat/completions", base_url.trim_end_matches('/'))
            };
            let mut hdrs = hyper::HeaderMap::new();
            hdrs.insert(
                hyper::header::CONTENT_TYPE,
                "application/json".parse().unwrap(),
            );
            hdrs.insert(
                hyper::header::AUTHORIZATION,
                format!("Bearer {}", api_key).parse().unwrap(),
            );
            let bytes = Bytes::from(serde_json::to_vec(&body).unwrap_or_default());
            (ep, hdrs, bytes)
        };

    let mut req_builder = state.http_client.post(&target_endpoint);
    for (k, v) in upstream_headers.iter() {
        req_builder = req_builder.header(k.as_str(), v.to_str().unwrap_or_default());
    }

    let req_to_send = match req_builder.body(req_body_bytes).build() {
        Ok(r) => r,
        Err(_) => {
            return Ok(make_error_response_with_protocol(
                StatusCode::INTERNAL_SERVER_ERROR,
                "agentcontrol",
                "request_build_failed",
                "Failed to build upstream request",
                None,
                is_streaming,
                &req_uuid,
                is_anthropic_protocol,
                is_responses_protocol,
            ));
        }
    };

    let req_start = std::time::Instant::now();
    match state.http_client.execute(req_to_send).await {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                state
                    .provider_router
                    .record_success(&target_endpoint, req_start.elapsed());
            } else {
                state.provider_router.record_failure(&target_endpoint);
            }

            if !status.is_success() {
                let resp_bytes = resp.bytes().await.unwrap_or_default();
                let upstream_err_json = serde_json::from_slice::<Value>(&resp_bytes).ok();
                let err_msg = upstream_err_json
                    .as_ref()
                    .and_then(|j| j.get("error"))
                    .and_then(|e| e.get("message").or_else(|| e.get("error")))
                    .and_then(|m| m.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| {
                        let s = std::str::from_utf8(&resp_bytes).unwrap_or("");
                        if s.is_empty() {
                            format!(
                                "HTTP {} {}",
                                status.as_u16(),
                                status.canonical_reason().unwrap_or("Error")
                            )
                        } else {
                            s.to_string()
                        }
                    });

                let formatted_msg = format!(
                    "Upstream {} returned HTTP {}: {}",
                    provider_name.to_uppercase(),
                    status.as_u16(),
                    err_msg
                );

                if let Some(ref hub_base) = hub_url {
                    if let Some(ref res_id) = active_reservation_id {
                        let release_req = crate::spend::types::SpendV2ReleaseReq {
                            request_id: req_uuid.clone(),
                            idempotency_key: format!("release-{}", req_uuid),
                            reason: "provider_error".to_string(),
                            request_hash: req_uuid.clone(),
                        };
                        let release_url = format!(
                            "{}/api/v2/spend/reservations/{}/release",
                            hub_base.trim_end_matches('/'),
                            res_id
                        );
                        let mut release_builder = state.http_client.post(&release_url);
                        if let Some(ref sec) = gateway_secret {
                            release_builder =
                                release_builder.header("Authorization", format!("Bearer {}", sec));
                        }
                        let _ = release_builder.json(&release_req).send().await;
                    }
                }

                return Ok(make_error_response_with_protocol(
                    status,
                    "upstream_provider",
                    &format!("upstream_http_{}", status.as_u16()),
                    &formatted_msg,
                    upstream_err_json,
                    is_streaming,
                    &req_uuid,
                    is_anthropic_protocol,
                    is_responses_protocol,
                ));
            }

            if is_streaming {
                let mut stream = resp.bytes_stream();
                let (tx, rx) = tokio::sync::mpsc::channel::<
                    Result<hyper::body::Frame<Bytes>, hyper::Error>,
                >(64);

                let state_clone = state.clone();
                let session_clone = session.clone();
                let provider_name_clone = provider_name.clone();
                let model_clone = model.clone();
                let req_uuid_clone = req_uuid.clone();
                let hub_url_clone = hub_url.clone();
                let active_reservation_id_clone = active_reservation_id.clone();
                let gateway_secret_clone = gateway_secret.clone();
                let body_clone = body.clone();
                let start_time_clone = start_time;
                let is_anthropic_protocol_clone = is_anthropic_protocol;
                let is_responses_protocol_clone = is_responses_protocol;
                let prompt_text_clone = prompt_text.clone();
                let tenant_id_clone = tenant_id.clone();
                let req_attribution_stream_clone = req_attribution.clone();

                tokio::spawn(async move {
                    let mut accumulated_chars = 0usize;
                    let mut accumulated_text = String::new();
                    let mut prompt_tokens_val = input_est;
                    let mut completion_tokens_val = 0i64;
                    let mut cached_tokens_val = 0i64;
                    let mut total_tokens_val = None;
                    let mut found_provider_usage = false;
                    let mut has_emitted_content_or_tool = false;
                    let mut first_token_instant: Option<std::time::Instant> = None;
                    let mut byte_buffer = Vec::<u8>::new();

                    let is_cross_to_openai =
                        !is_anthropic_protocol_clone && provider_name_clone == "anthropic";
                    let is_cross_to_anthropic =
                        is_anthropic_protocol_clone && provider_name_clone != "anthropic";
                    let anthropic_transformer =
                        crate::proxy::transformer::anthropic::AnthropicTransformer;

                    while let Some(chunk_res) = stream.next().await {
                        match chunk_res {
                            Ok(chunk) => {
                                byte_buffer.extend_from_slice(&chunk);
                                while let Some((pos, delim_len)) =
                                    find_sse_event_boundary(&byte_buffer)
                                {
                                    let event_bytes = byte_buffer[..pos].to_vec();
                                    byte_buffer.drain(..pos + delim_len);

                                    if is_cross_to_openai {
                                        if let Ok(Some(openai_chunks)) = anthropic_transformer
                                            .normalize_stream_chunk(&event_bytes)
                                        {
                                            for line in openai_chunks.lines() {
                                                let trimmed = line.trim();
                                                if let Some(data_str) =
                                                    trimmed.strip_prefix("data: ")
                                                {
                                                    if let Ok(cj) = serde_json::from_str::<Value>(
                                                        data_str.trim(),
                                                    ) {
                                                        if let Some(choices) = cj
                                                            .get("choices")
                                                            .and_then(|v| v.as_array())
                                                        {
                                                            for c in choices {
                                                                if let Some(delta) = c.get("delta")
                                                                {
                                                                    if let Some(txt) = delta
                                                                        .get("content")
                                                                        .and_then(|v| v.as_str())
                                                                    {
                                                                        if !txt.is_empty() {
                                                                            accumulated_chars +=
                                                                                txt.len();
                                                                            accumulated_text
                                                                                .push_str(txt);
                                                                            has_emitted_content_or_tool = true;
                                                                        }
                                                                    }
                                                                    if delta
                                                                        .get("tool_calls")
                                                                        .is_some()
                                                                    {
                                                                        has_emitted_content_or_tool = true;
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            if tx
                                                .send(Ok(hyper::body::Frame::data(Bytes::from(
                                                    openai_chunks,
                                                ))))
                                                .await
                                                .is_err()
                                            {
                                                return;
                                            }
                                        }
                                    } else if is_cross_to_anthropic {
                                        let text = String::from_utf8_lossy(&event_bytes);
                                        for line in text.lines() {
                                            let trimmed = line.trim();
                                            if let Some(data_str) = trimmed.strip_prefix("data: ") {
                                                let data_trimmed = data_str.trim();
                                                if data_trimmed == "[DONE]" {
                                                    let term = "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
                                                    let _ = tx
                                                        .send(Ok(hyper::body::Frame::data(
                                                            Bytes::from(term),
                                                        )))
                                                        .await;
                                                    continue;
                                                }
                                                if let Ok(cj) =
                                                    serde_json::from_str::<Value>(data_trimmed)
                                                {
                                                    if let Some(choices) =
                                                        cj.get("choices").and_then(|v| v.as_array())
                                                    {
                                                        for c in choices {
                                                            if let Some(delta) = c.get("delta") {
                                                                if let Some(content) = delta
                                                                    .get("content")
                                                                    .and_then(|v| v.as_str())
                                                                {
                                                                    if !content.is_empty() {
                                                                        accumulated_chars +=
                                                                            content.len();
                                                                        accumulated_text
                                                                            .push_str(content);
                                                                        has_emitted_content_or_tool = true;
                                                                        let anthropic_event = format!(
                                                                            "event: content_block_delta\ndata: {}\n\n",
                                                                            serde_json::json!({
                                                                                "type": "content_block_delta",
                                                                                "index": 0,
                                                                                "delta": {
                                                                                    "type": "text_delta",
                                                                                    "text": content
                                                                                }
                                                                            })
                                                                        );
                                                                        if tx.send(Ok(hyper::body::Frame::data(Bytes::from(anthropic_event)))).await.is_err() {
                                                                            return;
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    } else {
                                        let text = String::from_utf8_lossy(&event_bytes);
                                        for line in text.lines() {
                                            let trimmed = line.trim();
                                            if let Some(data_str) = trimmed.strip_prefix("data: ") {
                                                let data_trimmed = data_str.trim();
                                                if data_trimmed != "[DONE]" {
                                                    if let Ok(chunk_json) =
                                                        serde_json::from_str::<Value>(data_trimmed)
                                                    {
                                                        if let Some(usage) = chunk_json.get("usage")
                                                        {
                                                            found_provider_usage = true;
                                                            if let Some(pt) = usage
                                                                .get("prompt_tokens")
                                                                .or_else(|| {
                                                                    usage.get("input_tokens")
                                                                })
                                                                .and_then(|v| v.as_i64())
                                                            {
                                                                prompt_tokens_val = pt;
                                                            }
                                                            if let Some(ct) = usage
                                                                .get("completion_tokens")
                                                                .or_else(|| {
                                                                    usage.get("output_tokens")
                                                                })
                                                                .and_then(|v| v.as_i64())
                                                            {
                                                                completion_tokens_val = ct;
                                                            }
                                                            if let Some(details) =
                                                                usage.get("prompt_tokens_details")
                                                            {
                                                                if let Some(c) = details
                                                                    .get("cached_tokens")
                                                                    .and_then(|v| v.as_i64())
                                                                {
                                                                    cached_tokens_val = c;
                                                                }
                                                            }
                                                            if let Some(tt) = usage
                                                                .get("total_tokens")
                                                                .and_then(|v| v.as_u64())
                                                            {
                                                                total_tokens_val = Some(tt);
                                                            }
                                                        }
                                                        if let Some(choices) = chunk_json
                                                            .get("choices")
                                                            .and_then(|v| v.as_array())
                                                        {
                                                            for choice in choices {
                                                                if let Some(delta) =
                                                                    choice.get("delta")
                                                                {
                                                                    if let Some(content) = delta
                                                                        .get("content")
                                                                        .and_then(|v| v.as_str())
                                                                    {
                                                                        if !content.is_empty() {
                                                                            accumulated_chars +=
                                                                                content.len();
                                                                            accumulated_text
                                                                                .push_str(content);
                                                                            has_emitted_content_or_tool = true;
                                                                        }
                                                                    }
                                                                    if delta
                                                                        .get("tool_calls")
                                                                        .is_some()
                                                                    {
                                                                        has_emitted_content_or_tool = true;
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        if let Some(delta) = chunk_json.get("delta")
                                                        {
                                                            if let Some(t) = delta
                                                                .get("text")
                                                                .and_then(|v| v.as_str())
                                                            {
                                                                if !t.is_empty() {
                                                                    accumulated_chars += t.len();
                                                                    accumulated_text.push_str(t);
                                                                    has_emitted_content_or_tool =
                                                                        true;
                                                                }
                                                            }
                                                        }
                                                        if chunk_json
                                                            .get("content_block")
                                                            .and_then(|b| b.get("type"))
                                                            .and_then(|v| v.as_str())
                                                            == Some("tool_use")
                                                        {
                                                            has_emitted_content_or_tool = true;
                                                        }
                                                    }
                                                }
                                            }
                                        }

                                        if let Some(clean_block) = sanitize_sse_block(&text) {
                                            if tx
                                                .send(Ok(hyper::body::Frame::data(Bytes::from(
                                                    clean_block,
                                                ))))
                                                .await
                                                .is_err()
                                            {
                                                return;
                                            }
                                        }
                                    }
                                }
                                if first_token_instant.is_none()
                                    && (has_emitted_content_or_tool || accumulated_chars > 0)
                                {
                                    first_token_instant = Some(std::time::Instant::now());
                                }
                            }
                            Err(_) => break,
                        }
                    }

                    let ttft_ms_val = first_token_instant
                        .map(|t| t.duration_since(start_time_clone).as_millis() as i64);

                    if !byte_buffer.is_empty() {
                        let text = String::from_utf8_lossy(&byte_buffer);
                        if let Some(clean_block) = sanitize_sse_block(&text) {
                            let _ = tx
                                .send(Ok(hyper::body::Frame::data(Bytes::from(clean_block))))
                                .await;
                        }
                    }

                    // Empty assistant message defense:
                    // If stream completed and 0 text deltas and 0 tool calls were emitted, inject explicit error.
                    // Skip for is_responses_protocol: the upstream OpenAI Responses API sends its own
                    // response.completed event and manages its own stream lifecycle.
                    if !has_emitted_content_or_tool && !is_responses_protocol_clone {
                        if is_anthropic_protocol_clone {
                            let err_event = format!(
                                "event: error\ndata: {}\n\n",
                                serde_json::json!({
                                    "type": "error",
                                    "error": {
                                        "type": "api_error",
                                        "message": "[AgentControl Gateway] Upstream model completed turn without output deltas"
                                    }
                                })
                            );
                            let _ = tx
                                .send(Ok(hyper::body::Frame::data(Bytes::from(err_event))))
                                .await;
                        } else {
                            let err_chunk = serde_json::json!({
                                "error": {
                                    "message": "[AgentControl Gateway] Upstream model completed turn without output deltas",
                                    "type": "gateway_stream_error",
                                    "code": "empty_stream"
                                }
                            });
                            let payload = format!(
                                "data: {}\n\ndata: [DONE]\n\n",
                                serde_json::to_string(&err_chunk).unwrap_or_default()
                            );
                            let _ = tx
                                .send(Ok(hyper::body::Frame::data(Bytes::from(payload))))
                                .await;
                        }
                    }

                    if !found_provider_usage {
                        if completion_tokens_val == 0 && accumulated_chars > 0 {
                            completion_tokens_val = (accumulated_chars as i64 / 4) + 1;
                        }
                    }
                    if total_tokens_val.is_none()
                        && (prompt_tokens_val > 0 || completion_tokens_val > 0)
                    {
                        total_tokens_val = Some((prompt_tokens_val + completion_tokens_val) as u64);
                    }
                    if let Some(tt) = total_tokens_val {
                        session_clone
                            .tokens_used
                            .fetch_add(tt, std::sync::atomic::Ordering::Relaxed);
                    }

                    if let Some(ref hub_base) = hub_url_clone {
                        if let Some(ref res_id) = active_reservation_id_clone {
                            let settle_req = crate::spend::types::SpendV2SettleReq {
                                request_id: req_uuid_clone.clone(),
                                idempotency_key: format!("settle-{}", req_uuid_clone),
                                provider_request_id: None,
                                input_tokens: prompt_tokens_val,
                                output_tokens: completion_tokens_val,
                                cached_input_tokens: cached_tokens_val,
                                is_estimated: !found_provider_usage,
                                usage_source: Some(if found_provider_usage {
                                    "provider_reported".to_string()
                                } else {
                                    "character_estimate".to_string()
                                }),
                                status: 200,
                                request_hash: req_uuid_clone.clone(),
                                ttft_ms: ttft_ms_val,
                            };
                            let settle_url = format!(
                                "{}/api/v2/spend/reservations/{}/settle",
                                hub_base.trim_end_matches('/'),
                                res_id
                            );
                            let mut settle_builder = state_clone.http_client.post(&settle_url);
                            if let Some(ref sec) = gateway_secret_clone {
                                settle_builder = settle_builder
                                    .header("Authorization", format!("Bearer {}", sec));
                            }
                            let _ = settle_builder.json(&settle_req).send().await;
                        }
                    }

                    // Settle exact usage in local SpendLedger
                    if let Some(ledger) = &state_clone.spend_ledger {
                        let agent_id = session_clone
                            .identity_sub
                            .clone()
                            .unwrap_or_else(|| "anonymous".to_string());
                        let groups = session_clone.identity_groups.clone();
                        let tot = total_tokens_val
                            .unwrap_or((prompt_tokens_val + completion_tokens_val) as u64);
                        let cost_cents = if let Some(pricing) = &state_clone.pricing_table {
                            pricing.estimate_cents(
                                &model_clone,
                                prompt_tokens_val as u64,
                                completion_tokens_val as u64,
                            )
                        } else {
                            (tot * 3 / 1000).max(1)
                        };
                        let ledger_clone = ledger.clone();
                        let attr = req_attribution_stream_clone.clone();
                        let req_id = req_uuid_clone.clone();
                        let prov = provider_name_clone.clone();
                        let mdl = model_clone.clone();
                        tokio::spawn(async move {
                            let _ = ledger_clone
                                .check_and_increment(agent_id.clone(), groups, cost_cents)
                                .await;
                            ledger_clone.settle_usage(
                                req_id,
                                agent_id,
                                attr,
                                prov,
                                mdl,
                                prompt_tokens_val as u64,
                                completion_tokens_val as u64,
                                tot,
                                cost_cents,
                                !found_provider_usage,
                            );
                        });
                    }

                    if cached_tokens_val > 0 {
                        state_clone
                            .semantic_cache
                            .metrics
                            .record_provider_discount(&model_clone, cached_tokens_val);
                    }
                    if has_emitted_content_or_tool && !accumulated_text.is_empty() {
                        let synthetic_resp = serde_json::json!({
                            "id": format!("chatcmpl-{}", req_uuid_clone),
                            "object": "chat.completion",
                            "created": chrono::Utc::now().timestamp(),
                            "model": model_clone,
                            "choices": [{
                                "index": 0,
                                "message": {
                                    "role": "assistant",
                                    "content": accumulated_text
                                },
                                "finish_reason": "stop"
                            }],
                            "usage": {
                                "prompt_tokens": prompt_tokens_val,
                                "completion_tokens": completion_tokens_val,
                                "total_tokens": prompt_tokens_val + completion_tokens_val
                            }
                        });
                        let bytes =
                            Bytes::from(serde_json::to_vec(&synthetic_resp).unwrap_or_default());
                        state_clone
                            .semantic_cache
                            .store(
                                &state_clone.http_client,
                                &tenant_id_clone,
                                &model_clone,
                                &prompt_text_clone,
                                bytes,
                                "application/json",
                                prompt_tokens_val,
                                completion_tokens_val,
                            )
                            .await;
                    }

                    emit_llm_telemetry(
                        &state_clone,
                        &session_clone,
                        &model_clone,
                        control_plane_proto::redact::RawDecision::Allowed,
                    );

                    // Send structured request log to control hub "Request Logs" tab
                    if let Some(ref dc) = state_clone.dashboard_client {
                        let protocol_str = if is_anthropic_protocol_clone {
                            "anthropic_messages"
                        } else if is_responses_protocol_clone {
                            "openai_responses"
                        } else {
                            "openai_chat_completions"
                        };
                        let auth_hdr = session_clone.request_ip.clone(); // reuse field for IP
                        let key_hash = {
                            use sha2::{Digest, Sha256};
                            session_clone
                                .identity_sub
                                .as_deref()
                                .map(|sub| {
                                    let mut h = Sha256::new();
                                    h.update(sub.as_bytes());
                                    format!("sha256:{:.8}", hex::encode(h.finalize()))
                                })
                        };
                        dc.send_llm_request_log(
                            crate::control_plane_client::client::LlmRequestLog {
                                request_id: req_uuid_clone.clone(),
                                session_id: session_clone.session_id.clone(),
                                key_hash,
                                model: model_clone.clone(),
                                provider: provider_name_clone.clone(),
                                is_streaming: true,
                                prompt_tokens: prompt_tokens_val,
                                completion_tokens: completion_tokens_val,
                                total_tokens: total_tokens_val
                                    .unwrap_or((prompt_tokens_val + completion_tokens_val) as u64)
                                    as i64,
                                latency_ms: start_time_clone.elapsed().as_secs_f64() * 1000.0,
                                status_code: 200,
                                verdict: "allow".to_string(),
                                identity_sub: session_clone
                                    .identity_sub
                                    .clone()
                                    .or_else(|| crate::identity::device::load_user_email()),
                                identity_email: session_clone
                                    .identity_email
                                    .clone()
                                    .or_else(|| crate::identity::device::load_user_email()),
                                request_ip: auth_hdr,
                                timestamp_ms: chrono::Utc::now().timestamp_millis(),
                                is_estimated: !found_provider_usage,
                                protocol: protocol_str.to_string(),
                            },
                        );
                    }

                    let _ = state_clone.audit_logger.write_entry(
                        &session_clone.session_id,
                        "llm_allow",
                        &format!("{}:{}", provider_name_clone, model_clone),
                        Some(json!({"provider": provider_name_clone, "model": model_clone, "total_tokens": total_tokens_val})),
                        None,
                        Some(start_time_clone.elapsed().as_secs_f64() * 1000.0),
                        session_clone.identity_sub.clone(),
                        session_clone.identity_email.clone(),
                        Some("sha256:active".to_string()),
                        session_clone.request_ip.clone(),
                        None,
                    ).await;

                    let egress_event = crate::proxy::db::EgressEvent {
                        timestamp_ns: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
                        session_id: session_clone.session_id.clone(),
                        transport: "llm".to_string(),
                        method: Some("POST".to_string()),
                        target_host: match provider_name_clone.as_str() {
                            "anthropic" => "api.anthropic.com".to_string(),
                            "openai" => "api.openai.com".to_string(),
                            "google" | "gemini" => "generativelanguage.googleapis.com".to_string(),
                            _ => "api.openai.com".to_string(),
                        },
                        target_port: Some(443),
                        url_path: Some(format!("/v1/chat/completions?model={}", model_clone)),
                        request_headers: None,
                        request_body: Some(serde_json::to_string(&body_clone).unwrap_or_default()),
                        request_body_hash: None,
                        response_status: Some(200),
                        response_body: None,
                        response_body_hash: None,
                        dlp_findings: None,
                        injection_findings: None,
                        latency_ms: Some(start_time_clone.elapsed().as_secs_f64() * 1000.0),
                        verdict: Some("allow".to_string()),
                        semantic_anomaly_score: None,
                        identity_context: session_clone.identity_sub.clone(),
                        source: Some("production".to_string()),
                        policy_rule: Some("llm_egress_allowlist".to_string()),
                    };

                    let db = state_clone.db_manager.clone();
                    if let Ok(json_str) = serde_json::to_string(&egress_event) {
                        let _ = state_clone.event_tx.send(json_str);
                    }
                    tokio::spawn(async move {
                        let _ = db.insert(egress_event).await;
                        db.prune();
                    });
                });

                let stream_body = http_body_util::BodyExt::boxed(http_body_util::StreamBody::new(
                    tokio_stream::wrappers::ReceiverStream::new(rx),
                ));
                let resp = Response::builder()
                    .status(StatusCode::OK)
                    .header(
                        hyper::header::CONTENT_TYPE,
                        "text/event-stream; charset=utf-8",
                    )
                    .header(hyper::header::CACHE_CONTROL, "no-cache, no-transform")
                    .header(hyper::header::CONNECTION, "keep-alive")
                    .header("X-Accel-Buffering", "no")
                    .header("X-AgentControl-Origin", "upstream_provider")
                    .header("X-AgentControl-Verdict", "allowed")
                    .header("X-AgentControl-Request-ID", &req_uuid)
                    .header("X-AgentControl-Client-ID", &req_attribution.client_id)
                    .header("X-AgentControl-Project-ID", &req_attribution.project_id)
                    .header("X-AgentControl-Cost-Center", &req_attribution.cost_center)
                    .body(stream_body)
                    .unwrap();

                return Ok(resp);
            } else {
                let headers = resp.headers().clone();
                let resp_bytes = resp.bytes().await.unwrap_or_default();
                let mut final_resp_bytes = resp_bytes.clone();
                let mut total_tokens = None;
                let mut prompt_tokens_val = 0i64;
                let mut completion_tokens_val = 0i64;
                let mut cached_tokens_val = 0i64;
                let is_estimated = false;
                let usage_source = "provider_reported".to_string();

                if !is_anthropic_protocol && provider_name == "anthropic" {
                    // Normalize Anthropic JSON response to OpenAI format
                    if let Ok(normalized) =
                        crate::proxy::transformer::anthropic::AnthropicTransformer
                            .normalize_response(status.as_u16(), &headers, &resp_bytes)
                    {
                        final_resp_bytes =
                            Bytes::from(serde_json::to_vec(&normalized).unwrap_or_default());
                        if let Some(usage) = normalized.get("usage") {
                            prompt_tokens_val = usage
                                .get("prompt_tokens")
                                .and_then(|v| v.as_i64())
                                .unwrap_or(0);
                            completion_tokens_val = usage
                                .get("completion_tokens")
                                .and_then(|v| v.as_i64())
                                .unwrap_or(0);
                            if let Some(tt) = usage.get("total_tokens").and_then(|v| v.as_u64()) {
                                total_tokens = Some(tt);
                                session
                                    .tokens_used
                                    .fetch_add(tt, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                    }
                } else if is_anthropic_protocol && provider_name != "anthropic" {
                    // Normalize OpenAI JSON response to Anthropic format
                    if let Ok(resp_json) = serde_json::from_slice::<Value>(&resp_bytes) {
                        let mut text_content = String::new();
                        if let Some(choices) = resp_json.get("choices").and_then(|v| v.as_array()) {
                            if let Some(first) = choices.first() {
                                if let Some(content) = first
                                    .get("message")
                                    .and_then(|m| m.get("content"))
                                    .and_then(|v| v.as_str())
                                {
                                    text_content = content.to_string();
                                }
                            }
                        }
                        if text_content.is_empty() {
                            text_content =
                                "*(AgentControl Gateway: Upstream model returned empty output)*"
                                    .to_string();
                        }
                        let anthropic_resp = json!({
                            "id": resp_json.get("id").and_then(|v| v.as_str()).unwrap_or("msg-resp"),
                            "type": "message",
                            "role": "assistant",
                            "model": model,
                            "content": [{
                                "type": "text",
                                "text": text_content
                            }],
                            "stop_reason": "end_turn",
                            "stop_sequence": null,
                            "usage": {
                                "input_tokens": input_est,
                                "output_tokens": (text_content.len() as i64 / 4) + 1
                            }
                        });
                        final_resp_bytes =
                            Bytes::from(serde_json::to_vec(&anthropic_resp).unwrap_or_default());
                    }
                } else if let Ok(mut resp_json) = serde_json::from_slice::<Value>(&resp_bytes) {
                    if !is_anthropic_protocol {
                        if let Some(choices) =
                            resp_json.get_mut("choices").and_then(|v| v.as_array_mut())
                        {
                            if let Some(first) = choices.first_mut() {
                                let has_content = first
                                    .get("message")
                                    .and_then(|m| m.get("content"))
                                    .and_then(|v| v.as_str())
                                    .map(|s| !s.is_empty())
                                    .unwrap_or(false);
                                let has_tools = first
                                    .get("message")
                                    .and_then(|m| m.get("tool_calls"))
                                    .is_some();
                                if !has_content && !has_tools {
                                    if let Some(msg) = first.get_mut("message") {
                                        msg["content"] = json!("*(AgentControl Gateway: Upstream model returned empty output)*");
                                    }
                                    final_resp_bytes = Bytes::from(
                                        serde_json::to_vec(&resp_json).unwrap_or_default(),
                                    );
                                }
                            }
                        }
                    }
                    if let Some(usage) = resp_json.get("usage") {
                        prompt_tokens_val = usage
                            .get("prompt_tokens")
                            .or_else(|| usage.get("input_tokens"))
                            .and_then(|v| v.as_i64())
                            .unwrap_or(0);
                        completion_tokens_val = usage
                            .get("completion_tokens")
                            .or_else(|| usage.get("output_tokens"))
                            .and_then(|v| v.as_i64())
                            .unwrap_or(0);
                        if let Some(prompt_details) = usage.get("prompt_tokens_details") {
                            cached_tokens_val = prompt_details
                                .get("cached_tokens")
                                .and_then(|v| v.as_i64())
                                .unwrap_or(0);
                        }
                        if let Some(tt) = usage.get("total_tokens").and_then(|v| v.as_u64()) {
                            total_tokens = Some(tt);
                            session
                                .tokens_used
                                .fetch_add(tt, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                }

                if let Some(ref hub_base) = hub_url {
                    if let Some(ref res_id) = active_reservation_id {
                        let non_streaming_ttft = start_time.elapsed().as_millis() as i64;
                        let settle_req = crate::spend::types::SpendV2SettleReq {
                            request_id: req_uuid.clone(),
                            idempotency_key: format!("settle-{}", req_uuid),
                            provider_request_id: None,
                            input_tokens: prompt_tokens_val,
                            output_tokens: completion_tokens_val,
                            cached_input_tokens: cached_tokens_val,
                            is_estimated,
                            usage_source: Some(usage_source),
                            status: status.as_u16() as i32,
                            request_hash: req_uuid.clone(),
                            ttft_ms: Some(non_streaming_ttft),
                        };
                        let settle_url = format!(
                            "{}/api/v2/spend/reservations/{}/settle",
                            hub_base.trim_end_matches('/'),
                            res_id
                        );
                        let mut settle_builder = state.http_client.post(&settle_url);
                        if let Some(ref sec) = gateway_secret {
                            settle_builder =
                                settle_builder.header("Authorization", format!("Bearer {}", sec));
                        }
                        let _ = settle_builder.json(&settle_req).send().await;
                    }
                }

                // Settle exact usage in local SpendLedger
                if let Some(ledger) = &state.spend_ledger {
                    let agent_id = session
                        .identity_sub
                        .clone()
                        .unwrap_or_else(|| "anonymous".to_string());
                    let groups = session.identity_groups.clone();
                    let cost_cents = if let Some(pricing) = &state.pricing_table {
                        pricing.estimate_cents(
                            &model,
                            prompt_tokens_val as u64,
                            completion_tokens_val as u64,
                        )
                    } else {
                        ((total_tokens
                            .unwrap_or((prompt_tokens_val + completion_tokens_val) as u64))
                            * 3
                            / 1000)
                            .max(1)
                    };
                    let ledger_clone = ledger.clone();
                    let attr = req_attribution.clone();
                    let req_id = req_uuid.clone();
                    let prov = provider_name.clone();
                    let mdl = model.clone();
                    let total_tok =
                        total_tokens.unwrap_or((prompt_tokens_val + completion_tokens_val) as u64);
                    tokio::spawn(async move {
                        let _ = ledger_clone
                            .check_and_increment(agent_id.clone(), groups, cost_cents)
                            .await;
                        ledger_clone.settle_usage(
                            req_id,
                            agent_id,
                            attr,
                            prov,
                            mdl,
                            prompt_tokens_val as u64,
                            completion_tokens_val as u64,
                            total_tok,
                            cost_cents,
                            is_estimated,
                        );
                    });
                }

                emit_llm_telemetry(
                    &state,
                    &session,
                    &model,
                    control_plane_proto::redact::RawDecision::Allowed,
                );

                // Send structured request log to control hub "Request Logs" tab
                if let Some(ref dc) = state.dashboard_client {
                    let protocol_str = if is_anthropic_protocol {
                        "anthropic_messages"
                    } else if is_responses_protocol {
                        "openai_responses"
                    } else {
                        "openai_chat_completions"
                    };
                    let key_hash = {
                        use sha2::{Digest, Sha256};
                        session
                            .identity_sub
                            .as_deref()
                            .map(|sub| {
                                let mut h = Sha256::new();
                                h.update(sub.as_bytes());
                                format!("sha256:{:.8}", hex::encode(h.finalize()))
                            })
                    };
                    dc.send_llm_request_log(
                        crate::control_plane_client::client::LlmRequestLog {
                            request_id: req_uuid.clone(),
                            session_id: session.session_id.clone(),
                            key_hash,
                            model: model.clone(),
                            provider: provider_name.clone(),
                            is_streaming: false,
                            prompt_tokens: prompt_tokens_val,
                            completion_tokens: completion_tokens_val,
                            total_tokens: total_tokens
                                .unwrap_or((prompt_tokens_val + completion_tokens_val) as u64)
                                as i64,
                            latency_ms: start_time.elapsed().as_secs_f64() * 1000.0,
                            status_code: status.as_u16(),
                            verdict: "allow".to_string(),
                            identity_sub: session
                                .identity_sub
                                .clone()
                                .or_else(|| crate::identity::device::load_user_email()),
                            identity_email: session
                                .identity_email
                                .clone()
                                .or_else(|| crate::identity::device::load_user_email()),
                            request_ip: session.request_ip.clone(),
                            timestamp_ms: chrono::Utc::now().timestamp_millis(),
                            is_estimated: false,
                            protocol: protocol_str.to_string(),
                        },
                    );
                }

                let _ = state
                    .audit_logger
                    .write_entry(
                        &session.session_id,
                        "llm_allow",
                        &format!("{}:{}", provider_name, model),
                        Some(json!({"provider": provider_name, "model": model, "total_tokens": total_tokens})),
                        None,
                        Some(start_time.elapsed().as_secs_f64() * 1000.0),
                        session.identity_sub.clone(),
                        session.identity_email.clone(),
                        Some("sha256:active".to_string()),
                        session.request_ip.clone(),
                        None,
                    )
                    .await;

                let egress_event = crate::proxy::db::EgressEvent {
                    timestamp_ns: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
                    session_id: session.session_id.clone(),
                    transport: "llm".to_string(),
                    method: Some("POST".to_string()),
                    target_host: match provider_name.as_str() {
                        "anthropic" => "api.anthropic.com".to_string(),
                        "openai" => "api.openai.com".to_string(),
                        "google" | "gemini" => "generativelanguage.googleapis.com".to_string(),
                        _ => "api.openai.com".to_string(),
                    },
                    target_port: Some(443),
                    url_path: Some(format!("/v1/chat/completions?model={}", model)),
                    request_headers: None,
                    request_body: Some(serde_json::to_string(&body).unwrap_or_default()),
                    request_body_hash: None,
                    response_status: Some(status.as_u16() as i64),
                    response_body: None,
                    response_body_hash: None,
                    dlp_findings: None,
                    injection_findings: None,
                    latency_ms: Some(start_time.elapsed().as_secs_f64() * 1000.0),
                    verdict: Some("allow".to_string()),
                    semantic_anomaly_score: None,
                    identity_context: session.identity_sub.clone(),
                    source: Some("production".to_string()),
                    policy_rule: Some("llm_egress_allowlist".to_string()),
                };

                let db = state.db_manager.clone();
                if let Ok(json_str) = serde_json::to_string(&egress_event) {
                    let _ = state.event_tx.send(json_str);
                }
                tokio::spawn(async move {
                    let _ = db.insert(egress_event).await;
                    db.prune();
                });

                if cached_tokens_val > 0 {
                    state
                        .semantic_cache
                        .metrics
                        .record_provider_discount(&model, cached_tokens_val);
                }
                let is_cacheable_resp =
                    crate::proxy::semantic_cache::SemanticCache::is_response_cacheable(
                        status.as_u16(),
                        &final_resp_bytes,
                        true,
                        false,
                    );
                if is_cacheable_req && is_cacheable_resp && state.semantic_cache.is_enabled() {
                    state
                        .semantic_cache
                        .store_with_context(
                            &state.http_client,
                            &canonical_ctx,
                            final_resp_bytes.clone(),
                            "application/json",
                            prompt_tokens_val,
                            completion_tokens_val,
                        )
                        .await;
                }

                let mut builder = Response::builder().status(status);
                builder = builder
                    .header(hyper::header::CONTENT_TYPE, "application/json")
                    .header("X-AgentControl-Origin", "upstream_provider")
                    .header("X-AgentControl-Verdict", "allowed")
                    .header("X-AgentControl-Request-ID", &req_uuid)
                    .header("X-AgentControl-Client-ID", &req_attribution.client_id)
                    .header("X-AgentControl-Project-ID", &req_attribution.project_id)
                    .header("X-AgentControl-Cost-Center", &req_attribution.cost_center);
                let body_frame = full_to_box_body(Full::new(final_resp_bytes));
                let resp = builder.body(body_frame).unwrap_or_else(|_| {
                    Response::builder()
                        .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                        .body(full_to_box_body(Full::new(Bytes::from(
                            "Internal Server Error",
                        ))))
                        .expect("static fallback response should never fail")
                });
                Ok(resp)
            }
        }
        Err(e) => {
            state.provider_router.record_failure(&target_endpoint);
            if let Some(ref hub_base) = hub_url {
                if let Some(ref res_id) = active_reservation_id {
                    let release_req = crate::spend::types::SpendV2ReleaseReq {
                        request_id: req_uuid.clone(),
                        idempotency_key: format!("release-{}", req_uuid),
                        reason: "gateway_upstream_timeout".to_string(),
                        request_hash: req_uuid.clone(),
                    };
                    let release_url = format!(
                        "{}/api/v2/spend/reservations/{}/release",
                        hub_base.trim_end_matches('/'),
                        res_id
                    );
                    let mut release_builder = state.http_client.post(&release_url);
                    if let Some(ref sec) = gateway_secret {
                        release_builder =
                            release_builder.header("Authorization", format!("Bearer {}", sec));
                    }
                    let _ = release_builder.json(&release_req).send().await;
                }
            }

            let msg = format!(
                "Failed to connect to upstream LLM provider '{}': {}",
                provider_name, e
            );
            Ok(make_error_response_with_protocol(
                StatusCode::BAD_GATEWAY,
                "agentcontrol",
                "upstream_connection_failed",
                &msg,
                None,
                is_streaming,
                &req_uuid,
                is_anthropic_protocol,
                is_responses_protocol,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_sse_stream_standard() {
        let raw = b"data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Hello\"},\"finish_reason\":null}]}\n\ndata: [DONE]\n\n";
        let cleaned = clean_sse_stream(raw);
        let s = String::from_utf8(cleaned).unwrap();
        assert!(s.contains("data: "));
        assert!(s.contains("Hello"));
        assert!(s.ends_with("data: [DONE]\n\n"));
    }

    #[test]
    fn test_clean_sse_stream_crlf_and_obfuscation() {
        let raw = b"data: {\"id\":\"chatcmpl-2\",\"obfuscation\":\"internal\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"World\"}}]}\r\n\r\ndata: [DONE]\r\n\r\n";
        let cleaned = clean_sse_stream(raw);
        let s = String::from_utf8(cleaned).unwrap();
        assert!(!s.contains("obfuscation"));
        assert!(s.contains("World"));
        assert!(s.ends_with("data: [DONE]\n\n"));
        // Ensure no stray carriage returns exist
        assert!(!s.contains('\r'));
    }

    #[test]
    fn test_infer_provider_from_model() {
        assert_eq!(infer_provider_from_model("gpt-4o"), "openai");
        assert_eq!(infer_provider_from_model("gpt-4o-mini"), "openai");
        assert_eq!(infer_provider_from_model("o1-preview"), "openai");
        assert_eq!(infer_provider_from_model("o3-mini"), "openai");
        assert_eq!(
            infer_provider_from_model("claude-3-5-sonnet-20241022"),
            "anthropic"
        );
        assert_eq!(
            infer_provider_from_model("claude-3-7-sonnet-20250219"),
            "anthropic"
        );
        assert_eq!(infer_provider_from_model("gemini-1.5-pro"), "google");
        assert_eq!(infer_provider_from_model("gemini-2.0-flash"), "google");
        assert_eq!(infer_provider_from_model("deepseek-chat"), "deepseek");
        assert_eq!(infer_provider_from_model("deepseek-reasoner"), "deepseek");
        assert_eq!(infer_provider_from_model("groq/llama-3.3-70b"), "groq");
    }

    #[test]
    fn test_find_sse_event_boundary() {
        let lf_frame = b"data: hello\n\ndata: world";
        assert_eq!(find_sse_event_boundary(lf_frame), Some((11, 2)));

        let crlf_frame = b"event: ping\r\ndata: {}\r\n\r\nnext";
        assert_eq!(find_sse_event_boundary(crlf_frame), Some((21, 4)));

        let partial = b"event: message_start\ndata: { incomplete";
        assert_eq!(find_sse_event_boundary(partial), None);
    }

    #[test]
    fn test_sanitize_sse_block_multiline_preservation() {
        // Anthropic event frame with event: and data:
        let raw_block = "event: content_block_delta\r\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"Hello\"}}\r\n";
        let cleaned = sanitize_sse_block(raw_block).expect("Block should not be None");
        assert!(cleaned.starts_with("event: content_block_delta\n"));
        assert!(cleaned.contains("data: "));
        assert!(cleaned.contains("\"type\":\"content_block_delta\""));
        assert!(cleaned.contains("\"text\":\"Hello\""));
        assert!(cleaned.ends_with("\n\n"));
        // Critical: it must NOT contain an extra \n\n between event and data!
        assert!(!cleaned.contains("event: content_block_delta\n\n"));
    }

    #[test]
    fn test_clean_sse_stream_preserves_multiline_anthropic_event() {
        let raw = b"event: message_start\ndata: {\"type\":\"message_start\"}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"Hi\"}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
        let cleaned = clean_sse_stream(raw);
        let cleaned_str = String::from_utf8(cleaned).unwrap();
        assert!(cleaned_str.contains("event: message_start\ndata: "));
        assert!(cleaned_str.contains("event: content_block_delta\ndata: "));
        assert!(cleaned_str.contains("\"text\":\"Hi\""));
        assert!(cleaned_str.contains("event: message_stop\ndata: "));
        assert!(!cleaned_str.contains("event: message_start\n\n"));
        assert!(!cleaned_str.contains("event: content_block_delta\n\n"));
        assert!(!cleaned_str.contains("event: message_stop\n\n"));
    }

    #[test]
    fn test_make_error_response_anthropic_sse_streaming() {
        let resp = make_error_response_with_protocol(
            StatusCode::BAD_REQUEST,
            "agentcontrol",
            "policy_blocked",
            "Sensitive data detected",
            None,
            true,
            "req-anthropic-err",
            true,  // is_anthropic_protocol
            false, // is_responses_protocol
        );
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("Content-Type").unwrap(),
            "text/event-stream; charset=utf-8"
        );
        assert_eq!(
            resp.headers().get("X-AgentControl-Verdict").unwrap(),
            "blocked"
        );
    }

    #[test]
    fn test_estimate_input_tokens() {
        let body = serde_json::json!({
            "messages": [
                {"role": "user", "content": "hello world"}
            ]
        });
        let est = estimate_input_tokens(&body);
        assert!(est >= 10);
    }

    #[test]
    fn test_make_error_response_json() {
        let resp = make_error_response(
            StatusCode::BAD_REQUEST,
            "agentcontrol",
            "policy_denied",
            "Test policy violation",
            None,
            false,
            "req-123",
        );
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.headers().get("X-AgentControl-Origin").unwrap(),
            "agentcontrol"
        );
        assert_eq!(
            resp.headers().get("X-AgentControl-Verdict").unwrap(),
            "blocked"
        );
        assert_eq!(
            resp.headers().get("X-AgentControl-Request-ID").unwrap(),
            "req-123"
        );
    }

    #[test]
    fn test_make_error_response_sse_streaming() {
        let resp = make_error_response(
            StatusCode::UNAUTHORIZED,
            "upstream_provider",
            "upstream_http_401",
            "Invalid API Key",
            None,
            true,
            "req-456",
        );
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("X-AgentControl-Origin").unwrap(),
            "upstream_provider"
        );
        assert_eq!(
            resp.headers().get("X-AgentControl-Verdict").unwrap(),
            "upstream_error"
        );
        assert_eq!(
            resp.headers().get("Content-Type").unwrap(),
            "text/event-stream; charset=utf-8"
        );
    }

    #[test]
    fn test_emit_llm_telemetry_redaction_contract() {
        let raw = control_plane_proto::redact::RawEventForRedaction {
            session_id: "sess-test",
            agent_id: "agent-test",
            tool_name: "llm:gpt-4o",
            tool_name_is_allowlisted: true,
            decision: control_plane_proto::redact::RawDecision::Allowed,
            timestamp_ms: 1788506717000,
            dlp_findings: &[],
            injection_findings: &[],
            semantic_findings: &[],
        };
        let redacted = control_plane_proto::redact::redact_event(&raw);
        assert_eq!(redacted.session_id, "sess-test");
        assert_eq!(redacted.agent_id, "agent-test");
        assert_eq!(redacted.tool_name, "llm:gpt-4o");
        assert_eq!(
            redacted.decision,
            control_plane_proto::event::RedactedDecision::Allowed
        );
    }

    #[test]
    fn test_normalize_inbound_openai_messages_anthropic_tool_blocks() {
        let mut body = serde_json::json!({
            "model": "gpt-4o",
            "messages": [
                {
                    "role": "user",
                    "content": "Please read file"
                },
                {
                    "role": "assistant",
                    "content": [{
                        "type": "tool_use",
                        "id": "call_123",
                        "name": "read_file",
                        "input": {"path": "Cargo.toml"}
                    }]
                },
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "call_123",
                            "content": "[package]\nname = \"agentcontrol\""
                        },
                        {
                            "type": "text",
                            "text": "What is the package name?"
                        }
                    ]
                }
            ]
        });

        normalize_inbound_openai_messages(&mut body);

        let msgs = body["messages"].as_array().unwrap();
        assert_eq!(
            msgs.len(),
            4,
            "Tool result should split into separate tool message + user text message"
        );

        // [0] user
        assert_eq!(msgs[0]["role"], "user");
        assert_eq!(msgs[0]["content"], "Please read file");

        // [1] assistant with tool_calls
        assert_eq!(msgs[1]["role"], "assistant");
        let tool_calls = msgs[1]["tool_calls"]
            .as_array()
            .expect("Must have tool_calls array");
        assert_eq!(tool_calls[0]["id"], "call_123");
        assert_eq!(tool_calls[0]["function"]["name"], "read_file");

        // [2] tool result
        assert_eq!(msgs[2]["role"], "tool");
        assert_eq!(msgs[2]["tool_call_id"], "call_123");
        assert_eq!(msgs[2]["content"], "[package]\nname = \"agentcontrol\"");

        // [3] remaining user text
        assert_eq!(msgs[3]["role"], "user");
        assert_eq!(msgs[3]["content"], "What is the package name?");
    }

    #[test]
    fn test_normalize_inbound_openai_messages_flattens_text_blocks() {
        let mut body = serde_json::json!({
            "model": "gpt-4o",
            "messages": [
                {
                    "role": "assistant",
                    "content": [
                        {"type": "text", "text": "Part 1"},
                        {"type": "text", "text": "Part 2"}
                    ]
                },
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "Hello"},
                        {"type": "text", "text": "World"}
                    ]
                }
            ]
        });

        normalize_inbound_openai_messages(&mut body);

        let msgs = body["messages"].as_array().unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0]["role"], "assistant");
        assert_eq!(msgs[0]["content"], "Part 1\nPart 2");
        assert_eq!(msgs[1]["role"], "user");
        assert_eq!(msgs[1]["content"], "Hello\nWorld");
    }

    #[test]
    fn test_is_internal_agentcontrol_key_detection() {
        // Virtual keys created by AgentControl control-plane
        assert!(is_internal_agentcontrol_key(
            "sk-vex-3abcdef1234567890abcdef1234567890"
        ));
        assert!(is_internal_agentcontrol_key(
            "Bearer sk-vex-3abcdef1234567890abcdef1234567890"
        ));
        assert!(is_internal_agentcontrol_key("vex_token_abc123"));
        assert!(is_internal_agentcontrol_key("vexa_secret_xyz789"));
        assert!(is_internal_agentcontrol_key(
            "sk-agentcontrol-managed-sentinel"
        ));
        assert!(is_internal_agentcontrol_key("Bearer agentcontrol-managed"));

        // Upstream provider keys should NOT be flagged as internal keys
        assert!(!is_internal_agentcontrol_key(
            "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"
        ));
        assert!(!is_internal_agentcontrol_key(
            "Bearer sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"
        ));
        assert!(!is_internal_agentcontrol_key(
            "sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890"
        ));
        assert!(!is_internal_agentcontrol_key(
            "AIzaSyD1234567890abcdefghijklmnopqrstuv"
        ));
    }

    // ── sanitize_tool_schemas ────────────────────────────────────────────────

    #[test]
    fn test_sanitize_tool_schemas_valid_passthrough() {
        // A well-formed schema must NOT be modified.
        let mut body = json!({
            "tools": [{
                "type": "function",
                "function": {
                    "name": "my_tool",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "foo": { "type": "string" }
                        }
                    }
                }
            }]
        });
        sanitize_tool_schemas(&mut body);
        let params = body["tools"][0]["function"]["parameters"].clone();
        assert_eq!(params["type"], "object");
        assert!(params.get("properties").is_some());
        // Must not add unnecessary additionalProperties to a valid schema
        assert_eq!(params.get("additionalProperties"), None);
    }

    #[test]
    fn test_sanitize_tool_schemas_anyof_top_level() {
        // Simulates the `automation_update` failure: top-level anyOf without type:object
        let mut body = json!({
            "tools": [{
                "type": "function",
                "function": {
                    "name": "automation_update",
                    "parameters": {
                        "anyOf": [
                            { "type": "string" },
                            { "type": "null" }
                        ]
                    }
                }
            }]
        });
        sanitize_tool_schemas(&mut body);
        let params = &body["tools"][0]["function"]["parameters"];
        assert_eq!(params["type"], "object", "anyOf must be replaced with object type");
        assert!(params.get("anyOf").is_none(), "anyOf must be stripped from sanitized schema");
    }

    #[test]
    fn test_sanitize_tool_schemas_nested_tools_group() {
        // OpenAI responses protocol nests MCP tool groups as tools[].tools[]
        let mut body = json!({
            "tools": [{
                "type": "mcp",
                "tools": [{
                    "type": "function",
                    "function": {
                        "name": "automation_update",
                        "parameters": {
                            "oneOf": [
                                { "type": "object", "properties": {} },
                                { "type": "null" }
                            ]
                        }
                    }
                }]
            }]
        });
        sanitize_tool_schemas(&mut body);
        let params = &body["tools"][0]["tools"][0]["function"]["parameters"];
        assert_eq!(params["type"], "object");
        assert!(params.get("oneOf").is_none());
    }

    #[test]
    fn test_sanitize_tool_schemas_anthropic_input_schema() {
        // Anthropic uses input_schema instead of function.parameters
        let mut body = json!({
            "tools": [{
                "name": "some_tool",
                "input_schema": {
                    "enum": ["a", "b", "c"]
                }
            }]
        });
        sanitize_tool_schemas(&mut body);
        let schema = &body["tools"][0]["input_schema"];
        assert_eq!(schema["type"], "object");
        assert!(schema.get("enum").is_none());
    }

    #[test]
    fn test_sanitize_tool_schemas_exact_error_tools_9_tools_1_parameters() {
        // Simulates the exact reported error: tools[9].tools[1].parameters with top-level anyOf
        let mut tools_array = Vec::new();
        for i in 0..9 {
            tools_array.push(json!({
                "type": "function",
                "function": {
                    "name": format!("dummy_tool_{}", i),
                    "parameters": {
                        "type": "object",
                        "properties": {}
                    }
                }
            }));
        }

        // tools[9] is an MCP tool group containing tools[0] and tools[1] (automation_update)
        tools_array.push(json!({
            "type": "mcp",
            "server_name": "automation-server",
            "tools": [
                {
                    "name": "automation_list",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "limit": { "type": "integer" }
                        }
                    }
                },
                {
                    "name": "automation_update",
                    "parameters": {
                        "anyOf": [
                            {
                                "type": "object",
                                "properties": {
                                    "rule_id": { "type": "string" },
                                    "status": { "type": "string" }
                                },
                                "required": ["rule_id"]
                            },
                            { "type": "null" }
                        ]
                    }
                }
            ]
        }));

        let mut body = json!({ "tools": tools_array });
        sanitize_tool_schemas(&mut body);

        let target_param = &body["tools"][9]["tools"][1]["parameters"];
        assert_eq!(target_param["type"], "object");
        assert!(target_param.get("anyOf").is_none());
        assert_eq!(target_param["properties"]["rule_id"]["type"], "string");
        assert_eq!(target_param["properties"]["status"]["type"], "string");
        assert_eq!(target_param["required"], json!(["rule_id"]));
    }

    #[test]
    fn test_sanitize_tool_schemas_direct_top_level_parameters() {
        // Direct parameters on top-level tool without "function" wrapper
        let mut body = json!({
            "tools": [{
                "name": "direct_tool",
                "parameters": {
                    "oneOf": [
                        { "type": "string" },
                        { "type": "number" }
                    ]
                }
            }]
        });
        sanitize_tool_schemas(&mut body);
        let params = &body["tools"][0]["parameters"];
        assert_eq!(params["type"], "object");
        assert!(params.get("oneOf").is_none());
        assert_eq!(params["additionalProperties"], true);
    }

    #[test]
    fn test_sanitize_tool_schemas_cleans_dangling_required() {
        // Schema with required entries that do not exist in properties
        let mut body = json!({
            "tools": [{
                "name": "tool_with_bad_req",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "valid_prop": { "type": "string" }
                    },
                    "required": ["valid_prop", "non_existent_prop"]
                }
            }]
        });
        sanitize_tool_schemas(&mut body);
        let params = &body["tools"][0]["parameters"];
        assert_eq!(params["required"], json!(["valid_prop"]));
    }

    #[test]
    fn test_sanitize_tool_schemas_legacy_functions() {
        let mut body = json!({
            "functions": [{
                "name": "legacy_func",
                "parameters": {
                    "anyOf": [{ "type": "string" }]
                }
            }]
        });
        sanitize_tool_schemas(&mut body);
        let params = &body["functions"][0]["parameters"];
        assert_eq!(params["type"], "object");
        assert!(params.get("anyOf").is_none());
    }

    #[test]
    fn test_sanitize_tool_schemas_no_tools_field() {
        // Body without a tools field must not panic or be modified
        let mut body = json!({ "messages": [{ "role": "user", "content": "hi" }] });
        let before = body.clone();
        sanitize_tool_schemas(&mut body);
        assert_eq!(body, before);
    }
}
