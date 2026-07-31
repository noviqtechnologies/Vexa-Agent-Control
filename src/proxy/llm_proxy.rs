use std::sync::Arc;
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use crate::proxy::handler::ProxyState;
use serde_json::{json, Value};

pub async fn handle_request(
    req: Request<Incoming>,
    state: Arc<ProxyState>,
    client_ip: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let start_time = std::time::Instant::now();

    // Extract authorization header & credential header from incoming agent request
    let auth_header = req.headers().get(hyper::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let credential_header = req.headers().get("X-AgentWall-Credential")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let scope_header = req.headers().get("X-AgentWall-Credential-Scope")
        .or_else(|| req.headers().get("X-AgentWall-Scope"))
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let session = match crate::proxy::server::resolve_session(&state, auth_header.as_deref(), credential_header.as_deref(), scope_header.as_deref(), client_ip).await {
        Ok(s) => s,
        Err((status, err_msg)) => {
            let err = serde_json::json!({
                "error": {"code": "unauthorized", "message": err_msg}
            });
            return Ok(crate::proxy::server::json_response(status, &err));
        }
    };

    if req.method() != hyper::Method::POST {
        return Ok(crate::proxy::server::json_response(StatusCode::METHOD_NOT_ALLOWED, &serde_json::json!({"error": "Method Not Allowed"})));
    }

    use http_body_util::BodyExt;
    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => return Ok(crate::proxy::server::json_response(StatusCode::BAD_REQUEST, &serde_json::json!({"error": "Bad Request"}))),
    };

    let mut body: Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(_) => return Ok(crate::proxy::server::json_response(StatusCode::BAD_REQUEST, &serde_json::json!({"error": "Invalid JSON"}))),
    };

    let model = match body.get("model").and_then(|v| v.as_str()) {
        Some(m) => m.to_string(),
        None => return Ok(crate::proxy::server::json_response(StatusCode::BAD_REQUEST, &serde_json::json!({"error": "Missing 'model' field"}))),
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
                            let _ = state.audit_logger.write_entry(
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
                            ).await;
                            return Ok(crate::proxy::server::json_response(StatusCode::FORBIDDEN, &serde_json::json!({"error": format!("Model '{}' is not allowed by policy", model)})));
                        }
                    }
                } else {
                    return Ok(crate::proxy::server::json_response(StatusCode::FORBIDDEN, &serde_json::json!({"error": "LLM providers not configured"})));
                }
            } else {
                return Ok(crate::proxy::server::json_response(StatusCode::FORBIDDEN, &serde_json::json!({"error": "LLM policy not configured"})));
            }
        },
        None => return Ok(crate::proxy::server::json_response(StatusCode::FORBIDDEN, &serde_json::json!({"error": "No active policy"}))),
    };

    if provider_rule.action == "deny" {
        let _ = state.audit_logger.write_entry(
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
        ).await;
        return Ok(crate::proxy::server::json_response(StatusCode::FORBIDDEN, &serde_json::json!({"error": format!("Model '{}' is denied by policy", model)})));
    }

    // Centrally-managed provider key injection (FR-005 / US-007)
    let api_key = match state.provider_keys.get(&provider_name) {
        Some(k) => k.clone(),
        None => return Ok(crate::proxy::server::json_response(StatusCode::SERVICE_UNAVAILABLE, &serde_json::json!({"error": format!("API key for provider '{}' is not configured on the gateway", provider_name)}))),
    };

    // ADR-010: Inject include_usage stream options for OpenAI streaming
    if provider_name == "openai" || provider_name == "groq" || provider_name == "together" || provider_name == "mistral" {
        if let Some(obj) = body.as_object_mut() {
            if obj.get("stream").and_then(|v| v.as_bool()).unwrap_or(false) {
                obj.insert("stream_options".to_string(), json!({"include_usage": true}));
            }
        }
    }

    // Build upstream request — client authorization headers stripped automatically
    let req_builder = if provider_name == "anthropic" {
        state.http_client.post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &api_key)
            .header("anthropic-version", "2023-06-01")
            .header(hyper::header::CONTENT_TYPE, "application/json")
    } else {
        let base_url = match provider_name.as_str() {
            "openai" => "https://api.openai.com",
            "groq" => "https://api.groq.com/openai",
            "together" => "https://api.together.xyz",
            "mistral" => "https://api.mistral.ai",
            _ => return Ok(crate::proxy::server::json_response(StatusCode::INTERNAL_SERVER_ERROR, &serde_json::json!({"error": format!("Unknown provider: {}", provider_name)}))),
        };
        state.http_client.post(format!("{}/v1/chat/completions", base_url))
            .header(hyper::header::AUTHORIZATION, format!("Bearer {}", api_key))
            .header(hyper::header::CONTENT_TYPE, "application/json")
    };

    let req_to_send = match req_builder
        .body(reqwest::Body::from(serde_json::to_vec(&body).unwrap()))
        .build()
    {
        Ok(r) => r,
        Err(_) => return Ok(crate::proxy::server::json_response(StatusCode::INTERNAL_SERVER_ERROR, &serde_json::json!({"error": "Failed to build request"}))),
    };

    match state.http_client.execute(req_to_send).await {
        Ok(resp) => {
            let status = resp.status();
            let resp_bytes = resp.bytes().await.unwrap_or_default();
            
            let mut total_tokens = None;
            if let Ok(resp_json) = serde_json::from_slice::<Value>(&resp_bytes) {
                if let Some(usage) = resp_json.get("usage") {
                    if let Some(tt) = usage.get("total_tokens").and_then(|v| v.as_u64()) {
                        total_tokens = Some(tt);
                        session.tokens_used.fetch_add(tt, std::sync::atomic::Ordering::Relaxed);
                        if let Some(ledger) = &state.spend_ledger {
                            let agent_id = session.identity_sub.clone().unwrap_or_else(|| session.session_id.clone());
                            let _ = ledger.check_and_increment(agent_id, session.identity_groups.clone(), tt).await;
                        }
                    }
                }
            }

            // Write HMAC audit log entry for proxied request (US-008 / FR-006)
            let _ = state.audit_logger.write_entry(
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
            ).await;

            let mut builder = Response::builder().status(status);
            builder = builder.header(hyper::header::CONTENT_TYPE, "application/json");
            
            Ok(builder.body(Full::new(Bytes::from(resp_bytes))).unwrap())
        }
        Err(e) => {
            Ok(crate::proxy::server::json_response(StatusCode::INTERNAL_SERVER_ERROR, &serde_json::json!({"error": format!("Upstream request failed: {}", e)})))
        }
    }
}

