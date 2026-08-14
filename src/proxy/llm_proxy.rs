use crate::proxy::handler::ProxyState;
use bytes::Bytes;
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

pub async fn handle_request(
    req: Request<Incoming>,
    state: Arc<ProxyState>,
    client_ip: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let start_time = std::time::Instant::now();

    // Extract authorization header & credential header from incoming agent request
    let auth_header = req
        .headers()
        .get(hyper::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let credential_header = req
        .headers()
        .get("X-AgentWall-Credential")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let scope_header = req
        .headers()
        .get("X-AgentWall-Credential-Scope")
        .or_else(|| req.headers().get("X-AgentWall-Scope"))
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

    let model = match body.get("model").and_then(|v| v.as_str()) {
        Some(m) => m.to_string(),
        None => {
            return Ok(crate::proxy::server::json_response(
                StatusCode::BAD_REQUEST,
                &serde_json::json!({"error": "Missing 'model' field"}),
            ))
        }
    };

    // Evaluate LLM policy
    let (provider_rule, provider_name) = match session.policy.as_ref() {
        Some(policy) => {
            if let Some(llm_config) = &policy.llm {
                if let Some(providers) = &llm_config.providers {
                    let mut matched = None;
                    for provider in providers {
                        if let Some(models) = &provider.models {
                            if models.iter().any(|m| m == "*" || m == &model) {
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
                return Ok(crate::proxy::server::json_response(
                    StatusCode::FORBIDDEN,
                    &serde_json::json!({"error": "LLM policy not configured"}),
                ));
            }
        }
        None => {
            return Ok(crate::proxy::server::json_response(
                StatusCode::FORBIDDEN,
                &serde_json::json!({"error": "No active policy"}),
            ))
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
        return Ok(crate::proxy::server::json_response(
            StatusCode::FORBIDDEN,
            &serde_json::json!({"error": format!("Model '{}' is denied by policy", model)}),
        ));
    }

    // Centrally-managed provider key injection (FR-005 / US-007)
    let api_key = match state.provider_keys.get(&provider_name) {
        Some(k) => k.clone(),
        None => {
            return Ok(crate::proxy::server::json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &serde_json::json!({"error": format!("API key for provider '{}' is not configured on the gateway", provider_name)}),
            ))
        }
    };

    // ── Preflight Spend Authorization (SMB Spend v2 Central Ledger) ──────────
    let hub_url = std::env::var("DASHBOARD_API_URL").ok();
    let mut active_reservation_id: Option<String> = None;
    let req_uuid = uuid::Uuid::new_v4().to_string();

    if let Some(ref hub_base) = hub_url {
        let input_est = estimate_input_tokens(&body);
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
        if let Ok(resp) = state.http_client.post(&auth_url).json(&auth_req).send().await {
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

                return Ok(crate::proxy::server::json_response(
                    StatusCode::TOO_MANY_REQUESTS,
                    &serde_json::json!({
                        "error": {
                            "code": deny_body.get("reason_code").and_then(|v| v.as_str()).unwrap_or("spend_budget_exhausted"),
                            "message": "LLM spend budget exceeded or preflight authorization denied",
                            "scope": deny_body.get("disclosure_safe_scope"),
                            "reset_at": deny_body.get("reset_at")
                        }
                    }),
                ));
            } else if resp.status().is_success() {
                if let Ok(allow_resp) =
                    resp.json::<crate::spend::types::SpendV2AuthorizeResp>().await
                {
                    active_reservation_id = allow_resp.reservation_id;
                }
            }
        }
    }

    // ADR-010: Inject include_usage stream options for OpenAI streaming
    if provider_name == "openai"
        || provider_name == "groq"
        || provider_name == "together"
        || provider_name == "mistral"
    {
        if let Some(obj) = body.as_object_mut() {
            if obj.get("stream").and_then(|v| v.as_bool()).unwrap_or(false) {
                obj.insert("stream_options".to_string(), json!({"include_usage": true}));
            }
        }
    }

    // Build upstream request — client authorization headers stripped automatically
    let req_builder = if provider_name == "anthropic" {
        state
            .http_client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &api_key)
            .header("anthropic-version", "2023-06-01")
            .header(hyper::header::CONTENT_TYPE, "application/json")
    } else {
        let base_url = match provider_name.as_str() {
            "openai" => "https://api.openai.com",
            "groq" => "https://api.groq.com/openai",
            "together" => "https://api.together.xyz",
            "mistral" => "https://api.mistral.ai",
            _ => {
                return Ok(crate::proxy::server::json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &serde_json::json!({"error": format!("Unknown provider: {}", provider_name)}),
                ))
            }
        };
        state
            .http_client
            .post(format!("{}/v1/chat/completions", base_url))
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
            let resp_bytes = resp.bytes().await.unwrap_or_default();

            let mut total_tokens = None;
            let mut prompt_tokens_val = 0i64;
            let mut completion_tokens_val = 0i64;
            let mut cached_tokens_val = 0i64;

            if let Ok(resp_json) = serde_json::from_slice::<Value>(&resp_bytes) {
                if let Some(usage) = resp_json.get("usage") {
                    prompt_tokens_val = usage.get("prompt_tokens").and_then(|v| v.as_i64()).unwrap_or(0);
                    completion_tokens_val = usage.get("completion_tokens").and_then(|v| v.as_i64()).unwrap_or(0);
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

            // ── Postflight Spend Settlement / Release ────────────────────────
            if let Some(ref hub_base) = hub_url {
                if let Some(ref res_id) = active_reservation_id {
                    if status.is_success() {
                        let settle_req = crate::spend::types::SpendV2SettleReq {
                            request_id: req_uuid.clone(),
                            idempotency_key: format!("settle-{}", req_uuid),
                            provider_request_id: None,
                            input_tokens: prompt_tokens_val,
                            output_tokens: completion_tokens_val,
                            cached_input_tokens: cached_tokens_val,
                            is_estimated: false,
                            status: status.as_u16() as i32,
                            request_hash: req_uuid.clone(),
                        };
                        let settle_url = format!(
                            "{}/api/v2/spend/reservations/{}/settle",
                            hub_base.trim_end_matches('/'),
                            res_id
                        );
                        let _ = state
                            .http_client
                            .post(&settle_url)
                            .json(&settle_req)
                            .send()
                            .await;
                    } else {
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
                        let _ = state
                            .http_client
                            .post(&release_url)
                            .json(&release_req)
                            .send()
                            .await;
                    }
                }
            }

            // Write HMAC audit log entry for proxied request (US-008 / FR-006)
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

            let mut builder = Response::builder().status(status);
            builder = builder.header(hyper::header::CONTENT_TYPE, "application/json");

            Ok(builder.body(Full::new(resp_bytes)).unwrap())
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
                    let _ = state
                        .http_client
                        .post(&release_url)
                        .json(&release_req)
                        .send()
                        .await;
                }
            }

            Ok(crate::proxy::server::json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &serde_json::json!({"error": format!("Upstream request failed: {}", e)}),
            ))
        }
    }
}
