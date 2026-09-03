use crate::proxy::handler::ProxyState;
use crate::proxy::server::{full_to_box_body, BoxBody};
use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use serde_json::{json, Value};
use sha2::Digest;
use std::sync::Arc;

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
    } else if std::env::var("ANTHROPIC_API_KEY").is_ok() && std::env::var("OPENAI_API_KEY").is_err() {
        "anthropic".to_string()
    } else if std::env::var("GEMINI_API_KEY").is_ok() && std::env::var("OPENAI_API_KEY").is_err() {
        "google".to_string()
    } else {
        std::env::var("DEFAULT_LLM_PROVIDER").unwrap_or_else(|_| "openai".to_string())
    }
}

/// Sanitizes an individual SSE line, stripping broker-internal fields (`obfuscation`)
/// and ensuring clean standard SSE formatting with `\n\n` delimiters.
pub(crate) fn sanitize_sse_line(line: &str) -> Option<String> {
    let line_trimmed = line.trim();
    if line_trimmed.is_empty() {
        return None;
    }
    if line_trimmed == "data: [DONE]" || line_trimmed == "data:[DONE]" {
        return Some("data: [DONE]\n\n".to_string());
    }
    if let Some(data_str) = line_trimmed.strip_prefix("data: ") {
        let trimmed_data = data_str.trim();
        if trimmed_data == "[DONE]" {
            return Some("data: [DONE]\n\n".to_string());
        }
        if let Ok(mut json_val) = serde_json::from_str::<serde_json::Value>(trimmed_data) {
            if let Some(obj) = json_val.as_object_mut() {
                obj.remove("obfuscation");
            }
            if let Ok(clean_json) = serde_json::to_string(&json_val) {
                return Some(format!("data: {}\n\n", clean_json));
            }
        }
        return Some(format!("data: {}\n\n", trimmed_data));
    } else if let Some(data_str) = line_trimmed.strip_prefix("data:") {
        let trimmed_data = data_str.trim();
        if trimmed_data == "[DONE]" {
            return Some("data: [DONE]\n\n".to_string());
        }
        if let Ok(mut json_val) = serde_json::from_str::<serde_json::Value>(trimmed_data) {
            if let Some(obj) = json_val.as_object_mut() {
                obj.remove("obfuscation");
            }
            if let Ok(clean_json) = serde_json::to_string(&json_val) {
                return Some(format!("data: {}\n\n", clean_json));
            }
        }
        return Some(format!("data: {}\n\n", trimmed_data));
    }
    if line_trimmed.starts_with(':') {
        return Some(format!("{}\n\n", line_trimmed));
    }
    Some(format!("{}\n\n", line_trimmed))
}

/// Robust Server-Sent Events (SSE) stream sanitizer and normalizer.
/// Strips broker-internal fields (like `obfuscation`), standardizes CRLF/LF line endings,
/// preserves event framing, keep-alives, and `data: [DONE]`, ensuring strict compliance
/// with OpenAI / Anthropic / Cline SDK parsers.
#[allow(dead_code)]
pub(crate) fn clean_sse_stream(raw_bytes: &[u8]) -> Vec<u8> {
    let text = match std::str::from_utf8(raw_bytes) {
        Ok(t) => t,
        Err(_) => return raw_bytes.to_vec(),
    };

    // Normalize CRLF to LF
    let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
    let mut out = String::with_capacity(normalized.len() + 64);

    for line in normalized.lines() {
        if let Some(clean_line) = sanitize_sse_line(line) {
            out.push_str(&clean_line);
        }
    }

    if out.is_empty() {
        raw_bytes.to_vec()
    } else {
        out.into_bytes()
    }
}

/// Helper to construct a standardized error response adhering to OpenAI error format with clear origin tagging
/// ("agentcontrol" vs "upstream_provider") and optional SSE streaming error framing so IDE streaming clients
/// (Roo Code, Cursor, Cline) display the diagnostic error directly in chat instead of failing with "Model Response Incomplete".
pub(crate) fn make_error_response(
    status: StatusCode,
    origin: &'static str, // "agentcontrol" or "upstream_provider"
    error_code: &str,
    message: &str,
    details: Option<serde_json::Value>,
    is_streaming: bool,
    req_id: &str,
) -> Response<BoxBody> {
    let mut err_obj = serde_json::json!({
        "origin": origin,
        "type": if origin == "agentcontrol" { "agentcontrol_error" } else { "upstream_provider_error" },
        "code": error_code,
        "message": format!("[{}] {}", if origin == "agentcontrol" { "AgentControl Gateway" } else { "Upstream Provider" }, message),
    });

    if let Some(d) = details {
        err_obj["details"] = d;
    }

    let json_body = serde_json::json!({ "error": err_obj });
    let json_bytes = serde_json::to_vec(&json_body).unwrap_or_default();

    if is_streaming {
        // Build SSE stream chunk containing the diagnostic error so streaming IDE clients (Roo Code, Cursor)
        // render the diagnostic message directly in the chat UI
        let sse_content = format!("\n⚠️ **[{}]**: {}\n", if origin == "agentcontrol" { "AgentControl Gateway" } else { "Upstream Provider Error" }, message);
        let sse_chunk = serde_json::json!({
            "id": format!("err-{}", req_id),
            "object": "chat.completion.chunk",
            "created": chrono::Utc::now().timestamp(),
            "choices": [{
                "index": 0,
                "delta": {
                    "content": sse_content
                },
                "finish_reason": "error"
            }],
            "error": err_obj
        });

        let sse_payload = format!("data: {}\n\ndata: [DONE]\n\n", serde_json::to_string(&sse_chunk).unwrap_or_default());
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<hyper::body::Frame<Bytes>, hyper::Error>>(2);
        let _ = tx.try_send(Ok(hyper::body::Frame::data(Bytes::from(sse_payload))));
        let stream_body = http_body_util::BodyExt::boxed(http_body_util::StreamBody::new(tokio_stream::wrappers::ReceiverStream::new(rx)));

        Response::builder()
            .status(StatusCode::OK) // 200 OK so SSE stream parser in IDE consumes it
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
                    ("claude-3-5-sonnet-20241022", "anthropic"),
                    ("claude-3-5-haiku-20241022", "anthropic"),
                    ("claude-3-opus-20240229", "anthropic"),
                    ("gemini-1.5-pro", "google"),
                    ("gemini-1.5-flash", "google"),
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
            let err = serde_json::json!({
                "error": {"code": "unauthorized", "message": err_msg}
            });
            return Ok(crate::proxy::server::json_response(status, &err));
        }
    };

    if req.method() != hyper::Method::POST {
        return Ok(crate::proxy::server::json_response(
            StatusCode::METHOD_NOT_ALLOWED,
            &serde_json::json!({"error": "Method Not Allowed"}),
        ));
    }

    use http_body_util::BodyExt;
    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return Ok(crate::proxy::server::json_response(
                StatusCode::BAD_REQUEST,
                &serde_json::json!({"error": "Bad Request"}),
            ))
        }
    };

    let mut body: Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(_) => {
            return Ok(crate::proxy::server::json_response(
                StatusCode::BAD_REQUEST,
                &serde_json::json!({"error": "Invalid JSON"}),
            ))
        }
    };

    let is_streaming = body.get("stream").and_then(|v| v.as_bool()).unwrap_or(false);
    let req_uuid = uuid::Uuid::new_v4().to_string();

    let model = match body.get("model").and_then(|v| v.as_str()) {
        Some(m) => m.to_string(),
        None => {
            return Ok(make_error_response(
                StatusCode::BAD_REQUEST,
                "agentcontrol",
                "missing_model_field",
                "Missing 'model' field in request body",
                None,
                is_streaming,
                &req_uuid,
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
                            return Ok(crate::proxy::server::json_response(
                                StatusCode::FORBIDDEN,
                                &serde_json::json!({"error": format!("Model '{}' is not allowed by policy", model)}),
                            ));
                        }
                    }
                } else {
                    return Ok(crate::proxy::server::json_response(
                        StatusCode::FORBIDDEN,
                        &serde_json::json!({"error": "LLM providers not configured"}),
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
                                return Ok(crate::proxy::server::json_response(
                                    StatusCode::FORBIDDEN,
                                    &serde_json::json!({"error": format!("Model '{}' is not allowed by policy", model)}),
                                ));
                            }
                        }
                    } else {
                        return Ok(crate::proxy::server::json_response(
                            StatusCode::FORBIDDEN,
                            &serde_json::json!({"error": "LLM providers not configured"}),
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
                return Ok(make_error_response(
                    StatusCode::FORBIDDEN,
                    "agentcontrol",
                    "no_active_policy",
                    "No active policy configured on the gateway",
                    None,
                    is_streaming,
                    &req_uuid,
                ));
            }
        }
    };

    if provider_rule.action == "deny" {
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
        return Ok(make_error_response(
            StatusCode::FORBIDDEN,
            "agentcontrol",
            "policy_denied",
            &format!("Model '{}' is denied by policy rule", model),
            None,
            is_streaming,
            &req_uuid,
        ));
    }

    let provider_name = if provider_name == "default" {
        infer_provider_from_model(&model)
    } else {
        provider_name
    };

    let llm_mode = std::env::var("AGENTCONTROL_LLM_MODE")
        .unwrap_or_else(|_| if state.centralized_mode { "central_enforce".to_string() } else { "local_compat".to_string() });

    let input_est = estimate_input_tokens(&body);

    // ── 1. Centralized Modes (Zero Local Key Custody) ──────────────────────────
    if llm_mode == "central_enforce" || llm_mode == "central_shadow" {
        let hub_url = std::env::var("DASHBOARD_API_URL").ok();
        let broker = crate::proxy::broker_client::BrokerClient::new(hub_url);

        let max_output = body
            .get("max_tokens")
            .or_else(|| body.get("max_completion_tokens"))
            .and_then(|v| v.as_i64())
            .unwrap_or(2048);

        let broker_req = crate::proxy::broker_client::BrokerLLMRequest {
            schema_version: "3.0".to_string(),
            request_id: req_uuid.clone(),
            provider: provider_name.clone(),
            project_ref: session.identity_sub.clone().unwrap_or_else(|| "default".to_string()),
            model: model.clone(),
            protocol: if provider_name == "anthropic" {
                "anthropic_messages".to_string()
            } else {
                "openai_chat_completions".to_string()
            },
            stream: is_streaming,
            llm_mode: Some(llm_mode.clone()),
            input_token_estimate: Some(input_est),
            max_output_tokens: Some(max_output),
            payload: body.clone(),
        };

        if is_streaming {
            match broker.invoke_brokered_stream(&broker_req).await {
                Ok(upstream_resp) => {
                    let status = StatusCode::from_u16(upstream_resp.status().as_u16()).unwrap_or(StatusCode::OK);

                    if !status.is_success() {
                        let raw_bytes = upstream_resp.bytes().await.unwrap_or_default();
                        let mut resp_builder = Response::builder().status(status);
                        resp_builder = resp_builder.header(hyper::header::CONTENT_TYPE, "application/json");
                        return Ok(resp_builder.body(full_to_box_body(Full::new(raw_bytes))).unwrap());
                    }

                    let mut stream = upstream_resp.bytes_stream();
                    let (tx, rx) = tokio::sync::mpsc::channel::<Result<hyper::body::Frame<Bytes>, hyper::Error>>(64);
                    tokio::spawn(async move {
                        let mut buffer = String::new();
                        while let Some(chunk_res) = stream.next().await {
                            match chunk_res {
                                Ok(chunk) => {
                                    if let Ok(text) = std::str::from_utf8(&chunk) {
                                        buffer.push_str(text);
                                        while let Some(pos) = buffer.find('\n') {
                                            let line = buffer[..pos].to_string();
                                            buffer = buffer[pos + 1..].to_string();
                                            if let Some(clean_event) = sanitize_sse_line(&line) {
                                                if tx.send(Ok(hyper::body::Frame::data(Bytes::from(clean_event)))).await.is_err() {
                                                    return;
                                                }
                                            }
                                        }
                                    }
                                }
                                Err(_) => {
                                    break;
                                }
                            }
                        }
                        if !buffer.trim().is_empty() {
                            if let Some(clean_event) = sanitize_sse_line(&buffer) {
                                let _ = tx.send(Ok(hyper::body::Frame::data(Bytes::from(clean_event)))).await;
                            }
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
                    return Ok(make_error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "agentcontrol",
                        "broker_stream_failed",
                        &format!("Central broker streaming failed (fail-closed): {}", e),
                        None,
                        is_streaming,
                        &req_uuid,
                    ));
                }
            }
        } else {
            match broker.invoke_brokered_llm(&broker_req).await {
                Ok(brokered_resp) => {
                    let resp_bytes = serde_json::to_vec(&brokered_resp.response).unwrap_or_default();
                    let mut builder = Response::builder().status(StatusCode::OK);
                    builder = builder.header(hyper::header::CONTENT_TYPE, "application/json");
                    return Ok(builder.body(full_to_box_body(Full::new(Bytes::from(resp_bytes)))).unwrap());
                }
                Err(e) => {
                    return Ok(make_error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "agentcontrol",
                        "broker_request_failed",
                        &format!("Central broker request failed (fail-closed): {}", e),
                        None,
                        is_streaming,
                        &req_uuid,
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
            "openai" => std::env::var("OPENAI_API_KEY").ok(),
            "anthropic" => std::env::var("ANTHROPIC_API_KEY").ok(),
            "google" | "gemini" => std::env::var("GEMINI_API_KEY").ok().or_else(|| std::env::var("GOOGLE_API_KEY").ok()),
            _ => None,
        })
        .or_else(|| {
            auth_header.as_deref().and_then(|h| {
                let token = h.strip_prefix("Bearer ").unwrap_or(h).trim();
                if !token.is_empty() && (token.starts_with("sk-") || token.starts_with("AIza") || token.len() > 15) {
                    Some(token.to_string())
                } else {
                    None
                }
            })
        }) {
        Some(k) => k,
        None => {
            let msg = format!(
                "API key for provider '{}' is not configured on the gateway (set {}_API_KEY environment variable or configure in Dashboard)",
                provider_name,
                provider_name.to_uppercase()
            );
            return Ok(make_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "agentcontrol",
                "missing_provider_api_key",
                &msg,
                None,
                is_streaming,
                &req_uuid,
            ));
        }
    };

    // ── Preflight Spend Authorization (Optional in local_compat) ──────────────
    let hub_url = std::env::var("DASHBOARD_API_URL").ok();
    let mut active_reservation_id: Option<String> = None;
    let gateway_secret = std::env::var("GATEWAY_SECRET").ok();

    if state.centralized_mode || hub_url.is_some() {
        if hub_url.is_none() {
            if state.centralized_mode {
                return Ok(make_error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "agentcontrol",
                    "spend_governance_unreachable",
                    "Centralized enforce mode requires DASHBOARD_API_URL for spend preflight governance",
                    None,
                    is_streaming,
                    &req_uuid,
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

            let auth_req = crate::spend::types::SpendV2AuthorizeReq {
                gateway_id: Some(session.session_id.clone()),
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

                        return Ok(make_error_response(
                            StatusCode::TOO_MANY_REQUESTS,
                            "agentcontrol",
                            &reason_code,
                            &msg,
                            Some(deny_body),
                            is_streaming,
                            &req_uuid,
                        ));
                    } else if resp.status().is_success() {
                        if let Ok(allow_resp) =
                            resp.json::<crate::spend::types::SpendV2AuthorizeResp>().await
                        {
                            active_reservation_id = allow_resp.reservation_id;
                        }
                    } else if state.centralized_mode {
                        let msg = format!("Spend authorization preflight returned non-success status: {}", resp.status());
                        return Ok(make_error_response(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "agentcontrol",
                            "spend_governance_denied",
                            &msg,
                            None,
                            is_streaming,
                            &req_uuid,
                        ));
                    }
                }
                Err(e) => {
                    if state.centralized_mode {
                        let msg = format!("Spend authorization preflight failed: {}", e);
                        return Ok(make_error_response(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "agentcontrol",
                            "spend_governance_unreachable",
                            &msg,
                            None,
                            is_streaming,
                            &req_uuid,
                        ));
                    }
                }
            }
        }
    }

    // ADR-010: Inject include_usage stream options for OpenAI streaming
    if provider_name == "openai"
        || provider_name == "google"
        || provider_name == "gemini"
    {
        if let Some(obj) = body.as_object_mut() {
            if obj.get("stream").and_then(|v| v.as_bool()).unwrap_or(false) {
                obj.insert("stream_options".to_string(), json!({"include_usage": true}));
            }
        }
    }

    // Build upstream request — client authorization headers stripped automatically
    let req_builder = if provider_name == "anthropic" {
        let base_url = std::env::var("ANTHROPIC_BASE_URL")
            .unwrap_or_else(|_| "https://api.anthropic.com".to_string());
        state
            .http_client
            .post(format!("{}/v1/messages", base_url.trim_end_matches('/')))
            .header("x-api-key", &api_key)
            .header("anthropic-version", "2023-06-01")
            .header(hyper::header::CONTENT_TYPE, "application/json")
    } else {
        let base_url = match provider_name.as_str() {
            "openai" => std::env::var("OPENAI_BASE_URL")
                .unwrap_or_else(|_| "https://api.openai.com".to_string()),
            "google" | "gemini" => std::env::var("GEMINI_BASE_URL")
                .unwrap_or_else(|_| "https://generativelanguage.googleapis.com/v1beta/openai".to_string()),
            _ => std::env::var("OPENAI_BASE_URL")
                .unwrap_or_else(|_| "https://api.openai.com".to_string()),
        };
        state
            .http_client
            .post(format!("{}/v1/chat/completions", base_url.trim_end_matches('/')))
            .header(hyper::header::AUTHORIZATION, format!("Bearer {}", api_key))
            .header(hyper::header::CONTENT_TYPE, "application/json")
    };

    let req_to_send = match req_builder
        .body(reqwest::Body::from(serde_json::to_vec(&body).unwrap()))
        .build()
    {
        Ok(r) => r,
        Err(_) => {
            return Ok(crate::proxy::server::json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &serde_json::json!({"error": "Failed to build request"}),
            ))
        }
    };

    match state.http_client.execute(req_to_send).await {
        Ok(resp) => {
            let status = resp.status();

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

                return Ok(make_error_response(
                    status,
                    "upstream_provider",
                    &format!("upstream_http_{}", status.as_u16()),
                    &formatted_msg,
                    upstream_err_json,
                    is_streaming,
                    &req_uuid,
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

                tokio::spawn(async move {
                    let mut accumulated_chars = 0usize;
                    let mut prompt_tokens_val = input_est;
                    let mut completion_tokens_val = 0i64;
                    let mut cached_tokens_val = 0i64;
                    let mut total_tokens_val = None;
                    let mut found_provider_usage = false;
                    let mut buffer = String::new();

                    while let Some(chunk_res) = stream.next().await {
                        match chunk_res {
                            Ok(chunk) => {
                                if let Ok(text) = std::str::from_utf8(&chunk) {
                                    buffer.push_str(text);
                                    while let Some(pos) = buffer.find('\n') {
                                        let line = buffer[..pos].to_string();
                                        buffer = buffer[pos + 1..].to_string();

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
                                                                    accumulated_chars += content.len();
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }

                                        if let Some(clean_event) = sanitize_sse_line(&line) {
                                            if tx.send(Ok(hyper::body::Frame::data(Bytes::from(clean_event)))).await.is_err() {
                                                return;
                                            }
                                        }
                                    }
                                }
                            }
                            Err(_) => {
                                break;
                            }
                        }
                    }

                    if !buffer.trim().is_empty() {
                        if let Some(clean_event) = sanitize_sse_line(&buffer) {
                            let _ = tx.send(Ok(hyper::body::Frame::data(Bytes::from(clean_event)))).await;
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
                let resp_bytes = resp.bytes().await.unwrap_or_default();
                let mut total_tokens = None;
                let mut prompt_tokens_val = 0i64;
                let mut completion_tokens_val = 0i64;
                let mut cached_tokens_val = 0i64;
                let is_estimated = false;
                let usage_source = "provider_reported".to_string();

                if let Ok(resp_json) = serde_json::from_slice::<Value>(&resp_bytes) {
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
                Ok(builder.body(full_to_box_body(Full::new(resp_bytes))).unwrap())
            }
        }
        Err(e) => {
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
            Ok(make_error_response(
                StatusCode::BAD_GATEWAY,
                "agentcontrol",
                "upstream_connection_failed",
                &msg,
                None,
                is_streaming,
                &req_uuid,
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
        assert_eq!(infer_provider_from_model("claude-3-5-sonnet-20241022"), "anthropic");
        assert_eq!(infer_provider_from_model("gemini-1.5-pro"), "google");
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
}
