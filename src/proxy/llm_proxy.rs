use crate::proxy::handler::ProxyState;
use crate::proxy::server::{full_to_box_body, BoxBody};
use crate::proxy::session::SessionContext;
use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use serde_json::{json, Value};
use sha2::Digest;
use crate::proxy::transformer::ProviderTransformer;
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

pub(crate) fn infer_provider_from_model(model: &str) -> String {
    let lower = model.to_lowercase();
    if lower.starts_with("gpt-")
        || lower.starts_with("o1")
        || lower.starts_with("o3")
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
    } else if std::env::var("ANTHROPIC_API_KEY").is_ok() && std::env::var("OPENAI_API_KEY").is_err() {
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
            if i + 3 < buf.len() && buf[i + 1] == b'\n' && buf[i + 2] == b'\r' && buf[i + 3] == b'\n' {
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
    if block_trimmed == "data: [DONE]" || block_trimmed == "data:[DONE]" || block_trimmed == "[DONE]" {
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
        let role = msg.get("role").and_then(|r| r.as_str()).unwrap_or("").to_string();
        let content = msg.get("content");

        if role == "assistant" {
            if let Some(blocks) = content.and_then(|c| c.as_array()) {
                let mut tool_calls = Vec::new();
                let mut text_parts = Vec::new();

                for block in blocks {
                    if let Some(btype) = block.get("type").and_then(|t| t.as_str()) {
                        if btype == "tool_use" {
                            let id = block.get("id").and_then(|i| i.as_str()).unwrap_or("call_default").to_string();
                            let name = block.get("name").and_then(|n| n.as_str()).unwrap_or("unknown").to_string();
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
                        norm_msg.insert("content".to_string(), Value::String(text_parts.join("\n")));
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
                            let tool_id = block.get("tool_use_id").and_then(|i| i.as_str()).unwrap_or("call_default").to_string();
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

/// Helper to construct a standardized error response adhering to protocol specification (OpenAI vs Anthropic)
/// with clear origin tagging ("agentcontrol" vs "upstream_provider") and streaming error framing so IDE
/// clients (Roo Code, Cursor, Cline) display the diagnostic error directly in chat instead of failing with
/// "The model returned no assistant messages".
pub(crate) fn make_error_response_with_protocol(
    status: StatusCode,
    origin: &'static str, // "agentcontrol" or "upstream_provider"
    error_code: &str,
    message: &str,
    details: Option<serde_json::Value>,
    is_streaming: bool,
    req_id: &str,
    is_anthropic_protocol: bool,
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

    if is_streaming {
        let sse_content = format!("\n⚠️ **[{}]**: {}\n", if origin == "agentcontrol" { "AgentControl Gateway" } else { "Upstream Provider Error" }, message);

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

            let (tx, rx) = tokio::sync::mpsc::channel::<Result<hyper::body::Frame<Bytes>, hyper::Error>>(2);
            let _ = tx.try_send(Ok(hyper::body::Frame::data(Bytes::from(payload))));
            let stream_body = http_body_util::BodyExt::boxed(http_body_util::StreamBody::new(tokio_stream::wrappers::ReceiverStream::new(rx)));

            Response::builder()
                .status(StatusCode::OK)
                .header(hyper::header::CONTENT_TYPE, "text/event-stream; charset=utf-8")
                .header(hyper::header::CACHE_CONTROL, "no-cache, no-transform")
                .header(hyper::header::CONNECTION, "keep-alive")
                .header("X-Accel-Buffering", "no")
                .header("X-AgentControl-Origin", origin)
                .header("X-AgentControl-Verdict", if origin == "agentcontrol" { "blocked" } else { "upstream_error" })
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

            let sse_payload = format!("data: {}\n\ndata: [DONE]\n\n", serde_json::to_string(&sse_chunk).unwrap_or_default());
            let (tx, rx) = tokio::sync::mpsc::channel::<Result<hyper::body::Frame<Bytes>, hyper::Error>>(2);
            let _ = tx.try_send(Ok(hyper::body::Frame::data(Bytes::from(sse_payload))));
            let stream_body = http_body_util::BodyExt::boxed(http_body_util::StreamBody::new(tokio_stream::wrappers::ReceiverStream::new(rx)));

            Response::builder()
                .status(StatusCode::OK)
                .header(hyper::header::CONTENT_TYPE, "text/event-stream; charset=utf-8")
                .header(hyper::header::CACHE_CONTROL, "no-cache, no-transform")
                .header(hyper::header::CONNECTION, "keep-alive")
                .header("X-Accel-Buffering", "no")
                .header("X-AgentControl-Origin", origin)
                .header("X-AgentControl-Verdict", if origin == "agentcontrol" { "blocked" } else { "upstream_error" })
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
            .header("X-AgentControl-Verdict", if origin == "agentcontrol" { "blocked" } else { "upstream_error" })
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
            .header("X-AgentControl-Verdict", if origin == "agentcontrol" { "blocked" } else { "upstream_error" })
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
    make_error_response_with_protocol(status, origin, error_code, message, details, is_streaming, req_id, false)
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
    let start_time = std::time::Instant::now();

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

    let auth_header = req
        .headers()
        .get(hyper::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let credential_header = req
        .headers()
        .get("X-AgentControl-Credential").or_else(|| req.headers().get("X-AgentWall-Credential"))
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let scope_header = req
        .headers()
        .get("X-AgentControl-Credential-Scope").or_else(|| req.headers().get("X-AgentControl-Scope")).or_else(|| req.headers().get("X-AgentWall-Credential-Scope"))
        .or_else(|| req.headers().get("X-AgentControl-Scope").or_else(|| req.headers().get("X-AgentWall-Scope")))
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
            ));
        }
    };

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
            ));
        }
    };

    if !is_anthropic_protocol {
        normalize_inbound_openai_messages(&mut body);
    }

    let is_streaming = body.get("stream").and_then(|v| v.as_bool()).unwrap_or(false);
    let req_uuid = uuid::Uuid::new_v4().to_string();

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
            ));
        }
    };

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
                                m == "*" || m == &model || (m.ends_with('*') && model.starts_with(m.trim_end_matches('*')))
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
                            emit_llm_telemetry(&state, &session, &model, control_plane_proto::redact::RawDecision::Denied);
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
                dirs::home_dir().map(|h| h.join("agentcontrol-policy.yaml")).unwrap_or_default(),
                dirs::home_dir().map(|h| h.join(".agentcontrol/agentcontrol-policy.yaml")).unwrap_or_default(),
                std::path::PathBuf::from(r"C:\Windows\System32\config\systemprofile\.agentcontrol\agentcontrol-policy.yaml"),
                std::path::PathBuf::from(r"C:\Program Files\AgentControl\agentcontrol-policy.yaml"),
            ];

            for p in &candidate_paths {
                if p.exists() {
                    if let crate::policy::loader::PolicyLoadResult::Loaded { policy, .. } = crate::policy::loader::load_policy(p, None) {
                        if let Ok(mut w) = state.policy.write() {
                            *w = Some(policy.clone());
                            state.policy_loaded.store(true, std::sync::atomic::Ordering::SeqCst);
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
                                    m == "*" || m == &model || (m.ends_with('*') && model.starts_with(m.trim_end_matches('*')))
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
                                emit_llm_telemetry(&state, &session, &model, control_plane_proto::redact::RawDecision::Denied);
                                return Ok(make_error_response_with_protocol(
                                    StatusCode::FORBIDDEN,
                                    "agentcontrol",
                                    "model_not_allowed",
                                    &format!("Model '{}' is not allowed by policy", model),
                                    None,
                                    is_streaming,
                                    &req_uuid,
                                    is_anthropic_protocol,
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
                emit_llm_telemetry(&state, &session, &model, control_plane_proto::redact::RawDecision::Denied);
                return Ok(make_error_response_with_protocol(
                    StatusCode::FORBIDDEN,
                    "agentcontrol",
                    "no_active_policy",
                    "No active policy configured on the gateway",
                    None,
                    is_streaming,
                    &req_uuid,
                    is_anthropic_protocol,
                ));
            }
        }
    };

    if provider_rule.action == "deny" {
        emit_llm_telemetry(&state, &session, &model, control_plane_proto::redact::RawDecision::Denied);
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
                    emit_llm_telemetry(&state, &session, &model, control_plane_proto::redact::RawDecision::Denied);
                    return Ok(make_error_response_with_protocol(
                        StatusCode::FORBIDDEN,
                        "agentcontrol",
                        "virtual_key_policy_denied",
                        &format!("Virtual key policy violation: {}", reason),
                        None,
                        is_streaming,
                        &req_uuid,
                        is_anthropic_protocol,
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
            project_ref: session.identity_sub.clone().unwrap_or_else(|| "default".to_string()),
            model: model.clone(),
            protocol: if is_anthropic_protocol || provider_name == "anthropic" {
                "anthropic_messages".to_string()
            } else {
                "openai_chat_completions".to_string()
            },
            stream: is_streaming,
            llm_mode: Some(llm_mode.clone()),
            input_token_estimate: Some(input_est),
            max_output_tokens: Some(max_output),
            virtual_key: incoming_virtual_key,
            payload: body.clone(),
        };

        if is_streaming {
            match broker.invoke_brokered_stream(&broker_req).await {
                Ok(upstream_resp) => {
                    let status = StatusCode::from_u16(upstream_resp.status().as_u16()).unwrap_or(StatusCode::OK);

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
                        let formatted_msg = format!("Upstream broker returned HTTP {}: {}", status.as_u16(), err_msg);
                        return Ok(make_error_response_with_protocol(
                            status,
                            "upstream_provider",
                            &format!("upstream_http_{}", status.as_u16()),
                            &formatted_msg,
                            upstream_err_json,
                            is_streaming,
                            &req_uuid,
                            is_anthropic_protocol,
                        ));
                    }

                    emit_llm_telemetry(&state, &session, &model, control_plane_proto::redact::RawDecision::Allowed);
                    let mut stream = upstream_resp.bytes_stream();
                    let (tx, rx) = tokio::sync::mpsc::channel::<Result<hyper::body::Frame<Bytes>, hyper::Error>>(64);
                    let req_uuid_for_broker_stream = req_uuid.clone();
                    let is_anthropic_for_broker_stream = is_anthropic_protocol;
                    tokio::spawn(async move {
                        let mut byte_buffer = Vec::<u8>::new();
                        let mut has_emitted_content = false;
                        while let Some(chunk_res) = stream.next().await {
                            match chunk_res {
                                Ok(chunk) => {
                                    byte_buffer.extend_from_slice(&chunk);
                                    while let Some((pos, delim_len)) = find_sse_event_boundary(&byte_buffer) {
                                        let event_bytes = byte_buffer[..pos].to_vec();
                                        byte_buffer.drain(..pos + delim_len);
                                        let text = String::from_utf8_lossy(&event_bytes);
                                        if let Some(clean_event) = sanitize_sse_block(&text) {
                                            has_emitted_content = true;
                                            if tx.send(Ok(hyper::body::Frame::data(Bytes::from(clean_event)))).await.is_err() {
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
                                let _ = tx.send(Ok(hyper::body::Frame::data(Bytes::from(clean_event)))).await;
                            }
                        }
                        if !has_emitted_content {
                            let payload = if is_anthropic_for_broker_stream {
                                let err_chunk = serde_json::json!({
                                    "type": "error",
                                    "error": {
                                        "type": "api_error",
                                        "message": "[AgentControl Gateway] Upstream broker completed stream without content deltas"
                                    }
                                });
                                format!("event: error\ndata: {}\n\n", serde_json::to_string(&err_chunk).unwrap_or_default())
                            } else {
                                let err_chunk = serde_json::json!({
                                    "error": {
                                        "message": "[AgentControl Gateway] Upstream broker completed stream without content deltas",
                                        "type": "gateway_stream_error",
                                        "code": "empty_stream",
                                        "request_id": req_uuid_for_broker_stream
                                    }
                                });
                                format!("data: {}\n\ndata: [DONE]\n\n", serde_json::to_string(&err_chunk).unwrap_or_default())
                            };
                            let _ = tx.send(Ok(hyper::body::Frame::data(Bytes::from(payload)))).await;
                        }
                    });

                    let stream_body = http_body_util::BodyExt::boxed(http_body_util::StreamBody::new(tokio_stream::wrappers::ReceiverStream::new(rx)));
                    let resp_builder = Response::builder()
                        .status(status)
                        .header(hyper::header::CONTENT_TYPE, "text/event-stream; charset=utf-8")
                        .header(hyper::header::CACHE_CONTROL, "no-cache, no-transform")
                        .header(hyper::header::CONNECTION, "keep-alive")
                        .header("X-Accel-Buffering", "no");

                    return Ok(resp_builder.body(stream_body).unwrap());
                }
                Err(e) => {
                    return Ok(make_error_response_with_protocol(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "agentcontrol",
                        "broker_stream_failed",
                        &format!("Central broker streaming failed (fail-closed): {}", e),
                        None,
                        is_streaming,
                        &req_uuid,
                        is_anthropic_protocol,
                    ));
                }
            }
        } else {
            match broker.invoke_brokered_llm(&broker_req).await {
                Ok(brokered_resp) => {
                    emit_llm_telemetry(&state, &session, &model, control_plane_proto::redact::RawDecision::Allowed);
                    let resp_bytes = serde_json::to_vec(&brokered_resp.response).unwrap_or_default();
                    let mut builder = Response::builder().status(StatusCode::OK);
                    builder = builder.header(hyper::header::CONTENT_TYPE, "application/json");
                    return Ok(builder.body(full_to_box_body(Full::new(Bytes::from(resp_bytes)))).unwrap());
                }
                Err(e) => {
                    return Ok(make_error_response_with_protocol(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "agentcontrol",
                        "broker_request_failed",
                        &format!("Central broker request failed (fail-closed): {}", e),
                        None,
                        is_streaming,
                        &req_uuid,
                        is_anthropic_protocol,
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
            "google" | "gemini" => get_env_or_dotenv("GEMINI_API_KEY").or_else(|| get_env_or_dotenv("GOOGLE_API_KEY")),
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
            ));
        }
    };

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
                .or_else(|| crate::identity::device::DeviceIdentity::load_or_create().ok().map(|id| id.device_id))
                .or_else(|| std::env::var("AGENTCONTROL_DEVICE_ID").ok())
                .or_else(|| std::env::var("GATEWAY_ID").ok())
                .unwrap_or_else(|| session.session_id.clone());

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
            };

            let auth_url = format!("{}/api/v2/spend/authorize", hub_base.trim_end_matches('/'));
            let mut req_builder = state.http_client.post(&auth_url);
            if let Some(ref sec) = gateway_secret {
                req_builder = req_builder.header("Authorization", format!("Bearer {}", sec));
            }

            match req_builder.json(&auth_req).send().await {
                Ok(resp) => {
                    if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
                        emit_llm_telemetry(&state, &session, &model, control_plane_proto::redact::RawDecision::Denied);
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
                        ));
                    } else if resp.status().is_success() {
                        if let Ok(allow_resp) =
                            resp.json::<crate::spend::types::SpendV2AuthorizeResp>().await
                        {
                            active_reservation_id = allow_resp.reservation_id;
                        }
                    } else if state.centralized_mode {
                        let msg = format!("Spend authorization preflight returned non-success status: {}", resp.status());
                        return Ok(make_error_response_with_protocol(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "agentcontrol",
                            "spend_governance_denied",
                            &msg,
                            None,
                            is_streaming,
                            &req_uuid,
                            is_anthropic_protocol,
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
                        ));
                    }
                }
            }
        }
    }

    // ADR-010: Inject include_usage stream options for OpenAI streaming
    if (!is_anthropic_protocol || provider_name == "openai") && (provider_name == "openai"
        || provider_name == "google"
        || provider_name == "gemini")
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
                                })
                                .collect();

                            match strat.select(&candidates, state.provider_router.as_ref()) {
                                crate::proxy::routing::RoutingDecision::Selected(dep) => {
                                    routed_endpoint = Some(dep.endpoint_url);
                                    break;
                                }
                                crate::proxy::routing::RoutingDecision::NoEligibleDeployment { reason } => {
                                    eprintln!(
                                        "[routing] No eligible deployment in model group {}: {}",
                                        grp.name,
                                        reason
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
    let (target_endpoint, upstream_headers, req_body_bytes) = if !is_anthropic_protocol && provider_name == "anthropic" {
        // OpenAI client -> Anthropic upstream transformation
        let norm_req = match crate::proxy::transformer::NormalizedLLMRequest::from_openai_value(&body) {
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
                ));
            }
        };
        let base_url = std::env::var("ANTHROPIC_BASE_URL").ok();
        match crate::proxy::transformer::anthropic::AnthropicTransformer
            .transform_request(&norm_req, &api_key, base_url.as_deref())
        {
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
            "google" | "gemini" => std::env::var("GEMINI_BASE_URL")
                .unwrap_or_else(|_| "https://generativelanguage.googleapis.com/v1beta/openai".to_string()),
            _ => std::env::var("OPENAI_BASE_URL")
                .unwrap_or_else(|_| "https://api.openai.com".to_string()),
        };
        let ep = format!("{}/v1/chat/completions", base_url.trim_end_matches('/'));
        let mut hdrs = hyper::HeaderMap::new();
        hdrs.insert(hyper::header::CONTENT_TYPE, "application/json".parse().unwrap());
        hdrs.insert(hyper::header::AUTHORIZATION, format!("Bearer {}", api_key).parse().unwrap());
        let bytes = Bytes::from(serde_json::to_vec(&openai_body).unwrap_or_default());
        (ep, hdrs, bytes)
    } else if provider_name == "anthropic" {
        // Native Anthropic client -> Anthropic upstream
        let base_url = std::env::var("ANTHROPIC_BASE_URL")
            .unwrap_or_else(|_| "https://api.anthropic.com".to_string());
        let ep = format!("{}/v1/messages", base_url.trim_end_matches('/'));
        let mut hdrs = hyper::HeaderMap::new();
        hdrs.insert(hyper::header::CONTENT_TYPE, "application/json".parse().unwrap());
        hdrs.insert("x-api-key".parse::<hyper::header::HeaderName>().unwrap(), api_key.parse().unwrap());
        hdrs.insert("anthropic-version".parse::<hyper::header::HeaderName>().unwrap(), "2023-06-01".parse().unwrap());
        let bytes = Bytes::from(serde_json::to_vec(&body).unwrap_or_default());
        (ep, hdrs, bytes)
    } else {
        // Native OpenAI client -> OpenAI / Gemini / Groq upstream
        let base_url = match provider_name.as_str() {
            "google" | "gemini" => std::env::var("GEMINI_BASE_URL")
                .unwrap_or_else(|_| "https://generativelanguage.googleapis.com/v1beta/openai".to_string()),
            _ => std::env::var("OPENAI_BASE_URL")
                .unwrap_or_else(|_| "https://api.openai.com".to_string()),
        };
        let ep = if let Some(routed) = routed_endpoint {
            routed
        } else {
            format!("{}/v1/chat/completions", base_url.trim_end_matches('/'))
        };
        let mut hdrs = hyper::HeaderMap::new();
        hdrs.insert(hyper::header::CONTENT_TYPE, "application/json".parse().unwrap());
        hdrs.insert(hyper::header::AUTHORIZATION, format!("Bearer {}", api_key).parse().unwrap());
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
            ));
        }
    };

    let req_start = std::time::Instant::now();
    match state.http_client.execute(req_to_send).await {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                state.provider_router.record_success(&target_endpoint, req_start.elapsed());
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
                            format!("HTTP {} {}", status.as_u16(), status.canonical_reason().unwrap_or("Error"))
                        } else {
                            s.to_string()
                        }
                    });

                let formatted_msg = format!("Upstream {} returned HTTP {}: {}", provider_name.to_uppercase(), status.as_u16(), err_msg);

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
                            release_builder = release_builder.header("Authorization", format!("Bearer {}", sec));
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
                ));
            }

            if is_streaming {
                let mut stream = resp.bytes_stream();
                let (tx, rx) = tokio::sync::mpsc::channel::<Result<hyper::body::Frame<Bytes>, hyper::Error>>(64);

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

                tokio::spawn(async move {
                    let mut accumulated_chars = 0usize;
                    let mut prompt_tokens_val = input_est;
                    let mut completion_tokens_val = 0i64;
                    let mut cached_tokens_val = 0i64;
                    let mut total_tokens_val = None;
                    let mut found_provider_usage = false;
                    let mut has_emitted_content_or_tool = false;
                    let mut byte_buffer = Vec::<u8>::new();

                    let is_cross_to_openai = !is_anthropic_protocol_clone && provider_name_clone == "anthropic";
                    let is_cross_to_anthropic = is_anthropic_protocol_clone && provider_name_clone != "anthropic";
                    let anthropic_transformer = crate::proxy::transformer::anthropic::AnthropicTransformer;

                    while let Some(chunk_res) = stream.next().await {
                        match chunk_res {
                            Ok(chunk) => {
                                byte_buffer.extend_from_slice(&chunk);
                                while let Some((pos, delim_len)) = find_sse_event_boundary(&byte_buffer) {
                                    let event_bytes = byte_buffer[..pos].to_vec();
                                    byte_buffer.drain(..pos + delim_len);

                                    if is_cross_to_openai {
                                        if let Ok(Some(openai_chunks)) = anthropic_transformer.normalize_stream_chunk(&event_bytes) {
                                            for line in openai_chunks.lines() {
                                                let trimmed = line.trim();
                                                if let Some(data_str) = trimmed.strip_prefix("data: ") {
                                                    if let Ok(cj) = serde_json::from_str::<Value>(data_str.trim()) {
                                                        if let Some(choices) = cj.get("choices").and_then(|v| v.as_array()) {
                                                            for c in choices {
                                                                if let Some(delta) = c.get("delta") {
                                                                    if let Some(txt) = delta.get("content").and_then(|v| v.as_str()) {
                                                                        if !txt.is_empty() {
                                                                            accumulated_chars += txt.len();
                                                                            has_emitted_content_or_tool = true;
                                                                        }
                                                                    }
                                                                    if delta.get("tool_calls").is_some() {
                                                                        has_emitted_content_or_tool = true;
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            if tx.send(Ok(hyper::body::Frame::data(Bytes::from(openai_chunks)))).await.is_err() {
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
                                                    let _ = tx.send(Ok(hyper::body::Frame::data(Bytes::from(term)))).await;
                                                    continue;
                                                }
                                                if let Ok(cj) = serde_json::from_str::<Value>(data_trimmed) {
                                                    if let Some(choices) = cj.get("choices").and_then(|v| v.as_array()) {
                                                        for c in choices {
                                                            if let Some(delta) = c.get("delta") {
                                                                if let Some(content) = delta.get("content").and_then(|v| v.as_str()) {
                                                                    if !content.is_empty() {
                                                                        accumulated_chars += content.len();
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
                                                    if let Ok(chunk_json) = serde_json::from_str::<Value>(data_trimmed) {
                                                        if let Some(usage) = chunk_json.get("usage") {
                                                            found_provider_usage = true;
                                                            if let Some(pt) = usage.get("prompt_tokens").or_else(|| usage.get("input_tokens")).and_then(|v| v.as_i64()) {
                                                                prompt_tokens_val = pt;
                                                            }
                                                            if let Some(ct) = usage.get("completion_tokens").or_else(|| usage.get("output_tokens")).and_then(|v| v.as_i64()) {
                                                                completion_tokens_val = ct;
                                                            }
                                                            if let Some(details) = usage.get("prompt_tokens_details") {
                                                                if let Some(c) = details.get("cached_tokens").and_then(|v| v.as_i64()) {
                                                                    cached_tokens_val = c;
                                                                }
                                                            }
                                                            if let Some(tt) = usage.get("total_tokens").and_then(|v| v.as_u64()) {
                                                                total_tokens_val = Some(tt);
                                                            }
                                                        }
                                                        if let Some(choices) = chunk_json.get("choices").and_then(|v| v.as_array()) {
                                                            for choice in choices {
                                                                if let Some(delta) = choice.get("delta") {
                                                                    if let Some(content) = delta.get("content").and_then(|v| v.as_str()) {
                                                                        if !content.is_empty() {
                                                                            accumulated_chars += content.len();
                                                                            has_emitted_content_or_tool = true;
                                                                        }
                                                                    }
                                                                    if delta.get("tool_calls").is_some() {
                                                                        has_emitted_content_or_tool = true;
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        if let Some(delta) = chunk_json.get("delta") {
                                                            if let Some(t) = delta.get("text").and_then(|v| v.as_str()) {
                                                                if !t.is_empty() {
                                                                    accumulated_chars += t.len();
                                                                    has_emitted_content_or_tool = true;
                                                                }
                                                            }
                                                        }
                                                        if chunk_json.get("content_block").and_then(|b| b.get("type")).and_then(|v| v.as_str()) == Some("tool_use") {
                                                            has_emitted_content_or_tool = true;
                                                        }
                                                    }
                                                }
                                            }
                                        }

                                        if let Some(clean_block) = sanitize_sse_block(&text) {
                                            if tx.send(Ok(hyper::body::Frame::data(Bytes::from(clean_block)))).await.is_err() {
                                                return;
                                            }
                                        }
                                    }
                                }
                            }
                            Err(_) => break,
                        }
                    }

                    if !byte_buffer.is_empty() {
                        let text = String::from_utf8_lossy(&byte_buffer);
                        if let Some(clean_block) = sanitize_sse_block(&text) {
                            let _ = tx.send(Ok(hyper::body::Frame::data(Bytes::from(clean_block)))).await;
                        }
                    }

                    // Empty assistant message defense:
                    // If stream completed and 0 text deltas and 0 tool calls were emitted, inject explicit error
                    if !has_emitted_content_or_tool {
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
                            let _ = tx.send(Ok(hyper::body::Frame::data(Bytes::from(err_event)))).await;
                        } else {
                            let err_chunk = serde_json::json!({
                                "error": {
                                    "message": "[AgentControl Gateway] Upstream model completed turn without output deltas",
                                    "type": "gateway_stream_error",
                                    "code": "empty_stream"
                                }
                            });
                            let payload = format!("data: {}\n\ndata: [DONE]\n\n", serde_json::to_string(&err_chunk).unwrap_or_default());
                            let _ = tx.send(Ok(hyper::body::Frame::data(Bytes::from(payload)))).await;
                        }
                    }

                    if !found_provider_usage {
                        if completion_tokens_val == 0 && accumulated_chars > 0 {
                            completion_tokens_val = (accumulated_chars as i64 / 4) + 1;
                        }
                    }
                    if total_tokens_val.is_none() && (prompt_tokens_val > 0 || completion_tokens_val > 0) {
                        total_tokens_val = Some((prompt_tokens_val + completion_tokens_val) as u64);
                    }
                    if let Some(tt) = total_tokens_val {
                        session_clone.tokens_used.fetch_add(tt, std::sync::atomic::Ordering::Relaxed);
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
                                usage_source: Some(if found_provider_usage { "provider_reported".to_string() } else { "character_estimate".to_string() }),
                                status: 200,
                                request_hash: req_uuid_clone.clone(),
                            };
                            let settle_url = format!("{}/api/v2/spend/reservations/{}/settle", hub_base.trim_end_matches('/'), res_id);
                            let mut settle_builder = state_clone.http_client.post(&settle_url);
                            if let Some(ref sec) = gateway_secret_clone {
                                settle_builder = settle_builder.header("Authorization", format!("Bearer {}", sec));
                            }
                            let _ = settle_builder.json(&settle_req).send().await;
                        }
                    }

                    emit_llm_telemetry(&state_clone, &session_clone, &model_clone, control_plane_proto::redact::RawDecision::Allowed);
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

                let stream_body = http_body_util::BodyExt::boxed(http_body_util::StreamBody::new(tokio_stream::wrappers::ReceiverStream::new(rx)));
                let resp = Response::builder()
                    .status(StatusCode::OK)
                    .header(hyper::header::CONTENT_TYPE, "text/event-stream; charset=utf-8")
                    .header(hyper::header::CACHE_CONTROL, "no-cache, no-transform")
                    .header(hyper::header::CONNECTION, "keep-alive")
                    .header("X-Accel-Buffering", "no")
                    .header("X-AgentControl-Origin", "upstream_provider")
                    .header("X-AgentControl-Verdict", "allowed")
                    .header("X-AgentControl-Request-ID", &req_uuid)
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
                    if let Ok(normalized) = crate::proxy::transformer::anthropic::AnthropicTransformer
                        .normalize_response(status.as_u16(), &headers, &resp_bytes)
                    {
                        final_resp_bytes = Bytes::from(serde_json::to_vec(&normalized).unwrap_or_default());
                        if let Some(usage) = normalized.get("usage") {
                            prompt_tokens_val = usage.get("prompt_tokens").and_then(|v| v.as_i64()).unwrap_or(0);
                            completion_tokens_val = usage.get("completion_tokens").and_then(|v| v.as_i64()).unwrap_or(0);
                            if let Some(tt) = usage.get("total_tokens").and_then(|v| v.as_u64()) {
                                total_tokens = Some(tt);
                                session.tokens_used.fetch_add(tt, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                    }
                } else if is_anthropic_protocol && provider_name != "anthropic" {
                    // Normalize OpenAI JSON response to Anthropic format
                    if let Ok(resp_json) = serde_json::from_slice::<Value>(&resp_bytes) {
                        let mut text_content = String::new();
                        if let Some(choices) = resp_json.get("choices").and_then(|v| v.as_array()) {
                            if let Some(first) = choices.first() {
                                if let Some(content) = first.get("message").and_then(|m| m.get("content")).and_then(|v| v.as_str()) {
                                    text_content = content.to_string();
                                }
                            }
                        }
                        if text_content.is_empty() {
                            text_content = "*(AgentControl Gateway: Upstream model returned empty output)*".to_string();
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
                        final_resp_bytes = Bytes::from(serde_json::to_vec(&anthropic_resp).unwrap_or_default());
                    }
                } else if let Ok(mut resp_json) = serde_json::from_slice::<Value>(&resp_bytes) {
                    if !is_anthropic_protocol {
                        if let Some(choices) = resp_json.get_mut("choices").and_then(|v| v.as_array_mut()) {
                            if let Some(first) = choices.first_mut() {
                                let has_content = first.get("message").and_then(|m| m.get("content")).and_then(|v| v.as_str()).map(|s| !s.is_empty()).unwrap_or(false);
                                let has_tools = first.get("message").and_then(|m| m.get("tool_calls")).is_some();
                                if !has_content && !has_tools {
                                    if let Some(msg) = first.get_mut("message") {
                                        msg["content"] = json!("*(AgentControl Gateway: Upstream model returned empty output)*");
                                    }
                                    final_resp_bytes = Bytes::from(serde_json::to_vec(&resp_json).unwrap_or_default());
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
                            cached_tokens_val = prompt_details.get("cached_tokens").and_then(|v| v.as_i64()).unwrap_or(0);
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
                        };
                        let settle_url = format!("{}/api/v2/spend/reservations/{}/settle", hub_base.trim_end_matches('/'), res_id);
                        let mut settle_builder = state.http_client.post(&settle_url);
                        if let Some(ref sec) = gateway_secret {
                            settle_builder = settle_builder.header("Authorization", format!("Bearer {}", sec));
                        }
                        let _ = settle_builder.json(&settle_req).send().await;
                    }
                }

                emit_llm_telemetry(&state, &session, &model, control_plane_proto::redact::RawDecision::Allowed);
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

                let mut builder = Response::builder().status(status);
                builder = builder
                    .header(hyper::header::CONTENT_TYPE, "application/json")
                    .header("X-AgentControl-Origin", "upstream_provider")
                    .header("X-AgentControl-Verdict", "allowed")
                    .header("X-AgentControl-Request-ID", &req_uuid);
                Ok(builder.body(full_to_box_body(Full::new(final_resp_bytes))).unwrap())
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
                        release_builder = release_builder.header("Authorization", format!("Bearer {}", sec));
                    }
                    let _ = release_builder.json(&release_req).send().await;
                }
            }

            let msg = format!("Failed to connect to upstream LLM provider '{}': {}", provider_name, e);
            Ok(make_error_response_with_protocol(
                StatusCode::BAD_GATEWAY,
                "agentcontrol",
                "upstream_connection_failed",
                &msg,
                None,
                is_streaming,
                &req_uuid,
                is_anthropic_protocol,
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
        assert_eq!(infer_provider_from_model("claude-3-5-sonnet-20241022"), "anthropic");
        assert_eq!(infer_provider_from_model("claude-3-7-sonnet-20250219"), "anthropic");
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
            true, // is_anthropic_protocol
        );
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("Content-Type").unwrap(), "text/event-stream; charset=utf-8");
        assert_eq!(resp.headers().get("X-AgentControl-Verdict").unwrap(), "blocked");
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
        assert_eq!(resp.headers().get("X-AgentControl-Origin").unwrap(), "agentcontrol");
        assert_eq!(resp.headers().get("X-AgentControl-Verdict").unwrap(), "blocked");
        assert_eq!(resp.headers().get("X-AgentControl-Request-ID").unwrap(), "req-123");
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
        assert_eq!(resp.headers().get("X-AgentControl-Origin").unwrap(), "upstream_provider");
        assert_eq!(resp.headers().get("X-AgentControl-Verdict").unwrap(), "upstream_error");
        assert_eq!(resp.headers().get("Content-Type").unwrap(), "text/event-stream; charset=utf-8");
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
        assert_eq!(redacted.decision, control_plane_proto::event::RedactedDecision::Allowed);
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
        assert_eq!(msgs.len(), 4, "Tool result should split into separate tool message + user text message");

        // [0] user
        assert_eq!(msgs[0]["role"], "user");
        assert_eq!(msgs[0]["content"], "Please read file");

        // [1] assistant with tool_calls
        assert_eq!(msgs[1]["role"], "assistant");
        let tool_calls = msgs[1]["tool_calls"].as_array().expect("Must have tool_calls array");
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
        assert!(is_internal_agentcontrol_key("sk-vex-3abcdef1234567890abcdef1234567890"));
        assert!(is_internal_agentcontrol_key("Bearer sk-vex-3abcdef1234567890abcdef1234567890"));
        assert!(is_internal_agentcontrol_key("vex_token_abc123"));
        assert!(is_internal_agentcontrol_key("vexa_secret_xyz789"));
        assert!(is_internal_agentcontrol_key("sk-agentcontrol-managed-sentinel"));
        assert!(is_internal_agentcontrol_key("Bearer agentcontrol-managed"));

        // Upstream provider keys should NOT be flagged as internal keys
        assert!(!is_internal_agentcontrol_key("sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"));
        assert!(!is_internal_agentcontrol_key("Bearer sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"));
        assert!(!is_internal_agentcontrol_key("sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890"));
        assert!(!is_internal_agentcontrol_key("AIzaSyD1234567890abcdefghijklmnopqrstuv"));
    }
}
