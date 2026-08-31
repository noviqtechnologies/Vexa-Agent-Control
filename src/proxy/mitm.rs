//! MITM TLS Interception Engine for LLM Governance & Spend Tracking (FR-MITM).
//!
//! Decrypts client-side TLS connections on allowlisted LLM domains (e.g. `api2.cursor.sh`),
//! parses prompt tokens, enforces preflight spend budgets, performs DLP scanning on outbound
//! prompts, streams response chunks in real-time without buffering, and settles financial spend.

use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

use crate::ca::CaManager;
use crate::logging::{self, Level};
use crate::proxy::db::EgressEvent;
use crate::proxy::handler::ProxyState;
use crate::proxy::llm_proxy::make_error_response;

type BoxedBody = BoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;

/// Helper to convert Full<Bytes> to BoxedBody
fn full_to_boxed_body(body: Full<Bytes>) -> BoxedBody {
    body.map_err(|e: std::convert::Infallible| -> Box<dyn std::error::Error + Send + Sync> { match e {} })
        .boxed()
}

/// Engine for intercepting, decrypting, inspecting, and forwarding LLM HTTPS traffic.
#[derive(Clone)]
pub struct MitmEngine {
    pub ca_manager: Arc<CaManager>,
    pub state: Arc<ProxyState>,
}

impl MitmEngine {
    pub fn new(ca_manager: Arc<CaManager>, state: Arc<ProxyState>) -> Self {
        Self { ca_manager, state }
    }

    /// Handles an upgraded CONNECT tunnel by terminating TLS with dynamic leaf certs,
    /// serving plaintext HTTP requests, and proxying to upstream HTTPS servers.
    pub async fn handle_tunnel(
        &self,
        upgraded: hyper::upgrade::Upgraded,
        target_host: String,
        target_port: u16,
        session_id: String,
        identity_sub: Option<String>,
        identity_groups: Vec<String>,
        client_ip: String,
    ) {
        let server_config = match self.ca_manager.get_or_create_server_config(&target_host) {
            Ok(cfg) => cfg,
            Err(e) => {
                logging::log_event(
                    Level::Error,
                    "mitm_leaf_cert_failed",
                    serde_json::json!({
                        "target_host": &target_host,
                        "error": e.to_string(),
                    }),
                );
                return;
            }
        };

        let acceptor = TlsAcceptor::from(server_config);
        let client_io = TokioIo::new(upgraded);
        let tls_stream = match acceptor.accept(client_io).await {
            Ok(s) => s,
            Err(e) => {
                logging::log_event(
                    Level::Warn,
                    "mitm_tls_handshake_failed",
                    serde_json::json!({
                        "target_host": &target_host,
                        "client_ip": &client_ip,
                        "error": e.to_string(),
                    }),
                );
                return;
            }
        };

        let io = TokioIo::new(tls_stream);
        let state = self.state.clone();
        let target_host_clone = target_host.clone();
        let sid = session_id.clone();
        let isub = identity_sub.clone();
        let igroups = identity_groups.clone();

        let service = service_fn(move |req: Request<Incoming>| {
            let state = state.clone();
            let target_host = target_host_clone.clone();
            let sid = sid.clone();
            let isub = isub.clone();
            let igroups = igroups.clone();
            let client_ip = client_ip.clone();

            async move {
                let res = handle_mitm_http_request(
                    req,
                    state,
                    &target_host,
                    target_port,
                    &sid,
                    isub.as_deref(),
                    &igroups,
                    &client_ip,
                )
                .await;

                match res {
                    Ok(resp) => Ok::<_, hyper::Error>(resp),
                    Err(e) => {
                        let err_resp = make_error_response(
                            StatusCode::BAD_GATEWAY,
                            "agentcontrol",
                            "upstream_gateway_error",
                            &format!("MITM gateway error: {}", e),
                            None,
                            false,
                            &sid,
                        );
                        Ok::<_, hyper::Error>(err_resp.map(full_to_boxed_body))
                    }
                }
            }
        });

        if let Err(e) = hyper::server::conn::http1::Builder::new()
            .serve_connection(io, service)
            .await
        {
            logging::log_event(
                Level::Debug,
                "mitm_connection_closed",
                serde_json::json!({
                    "target_host": target_host,
                    "error": e.to_string(),
                }),
            );
        }
    }
}

/// Dispatches an intercepted plaintext HTTP request, evaluates DLP/Spend, and forwards upstream with live streaming.
async fn handle_mitm_http_request(
    req: Request<Incoming>,
    state: Arc<ProxyState>,
    target_host: &str,
    target_port: u16,
    session_id: &str,
    identity_sub: Option<&str>,
    identity_groups: &[String],
    _client_ip: &str,
) -> Result<Response<BoxedBody>, Box<dyn std::error::Error + Send + Sync>> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let start_time = std::time::Instant::now();
    let timestamp_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
    let session_id_str = session_id.to_string();

    let path_and_query = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    let upstream_url = format!("https://{}:{}{}", target_host, target_port, path_and_query);

    // Collect request headers — strip hop-by-hop and encoding headers to avoid compression mismatch
    let mut req_headers = reqwest::header::HeaderMap::new();
    for (k, v) in req.headers() {
        if k != hyper::header::HOST
            && k != hyper::header::TRANSFER_ENCODING
            && k != hyper::header::CONTENT_LENGTH
            && k != hyper::header::CONNECTION
            && k != hyper::header::UPGRADE
            && k != hyper::header::ACCEPT_ENCODING
            && k != "proxy-connection"
            && k != "keep-alive"
        {
            req_headers.insert(k.clone(), v.clone());
        }
    }
    req_headers.insert(reqwest::header::HOST, target_host.parse()?);

    let mut body_bytes = match req.collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => Bytes::new(),
    };

    let body_str = String::from_utf8_lossy(&body_bytes);

    // --- Centralized Key Injection: Detect sentinel key ---
    let auth_header_str = req_headers
        .get(reqwest::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let is_sentinel_key = auth_header_str
        .as_deref()
        .map(|h| h.contains("sk-agentcontrol-managed") || h.contains("agentcontrol-managed"))
        .unwrap_or(false);

    let is_byok_mode = is_sentinel_key;

    // 1. Content-Aware DLP & Secret Detection
    let combined_content = format!("{} {}", path_and_query, body_str);
    let dlp_findings = state.dlp_scanner.scan_content(&combined_content);
    let mut dlp_findings_json = None;

    if !dlp_findings.is_empty() {
        let findings_json = serde_json::json!({
            "findings": dlp_findings.iter().map(|f| format!("{}: {}", f.category.as_str(), f.preview)).collect::<Vec<_>>()
        });
        dlp_findings_json = Some(findings_json.to_string());

        if !state.shadow_mode.load(std::sync::atomic::Ordering::Relaxed) {
            let critical = dlp_findings
                .iter()
                .any(|f| f.category != crate::policy::dlp::SecretCategory::EnvVar);
            if critical {
                let err_res = make_error_response(
                    StatusCode::FORBIDDEN,
                    "agentcontrol",
                    "dlp_secret_violation",
                    &format!("Blocked by DLP policy: {}", dlp_findings[0].pattern_name),
                    Some(findings_json),
                    false,
                    &session_id_str,
                );

                let event = EgressEvent {
                    timestamp_ns,
                    session_id: session_id_str,
                    transport: "mitm_https".to_string(),
                    method: Some(method.to_string()),
                    target_host: target_host.to_string(),
                    target_port: Some(target_port as i64),
                    url_path: Some(path_and_query.to_string()),
                    request_headers: None,
                    request_body: None,
                    request_body_hash: None,
                    response_status: Some(403),
                    response_body: None,
                    response_body_hash: None,
                    dlp_findings: dlp_findings_json,
                    injection_findings: None,
                    latency_ms: Some(start_time.elapsed().as_secs_f64() * 1000.0),
                    verdict: Some("deny".to_string()),
                    semantic_anomaly_score: None,
                    identity_context: None,
                    source: Some("cursor_ide_mitm".to_string()),
                    policy_rule: Some("DLP-SECRET-BLOCK".to_string()),
                };
                let _ = state.db_manager.insert(event).await;

                return Ok(err_res.map(full_to_boxed_body));
            }
        }
    }

    // 2. Pre-flight Spend Cap Evaluation & Model Detection
    let mut model_name = "gpt-4o".to_string();
    let mut estimated_prompt_tokens = (body_bytes.len() as u64 / 4).max(15);

    if let Ok(json_body) = serde_json::from_str::<serde_json::Value>(&body_str) {
        if let Some(m) = json_body.get("model").and_then(|v| v.as_str()) {
            model_name = m.to_string();
        } else if let Some(m) = json_body.get("modelName").and_then(|v| v.as_str()) {
            model_name = m.to_string();
        }

        // Estimate tokens
        if let Some(messages) = json_body.get("messages").and_then(|v| v.as_array()) {
            let mut calculated = 0u64;
            for msg in messages {
                if let Some(content) = msg.get("content").and_then(|v| v.as_str()) {
                    calculated += (content.len() as u64 / 4) + 2;
                }
            }
            if calculated > 0 {
                estimated_prompt_tokens = calculated;
            }
        } else if let Some(prompt) = json_body.get("prompt").and_then(|v| v.as_str()) {
            estimated_prompt_tokens = (prompt.len() as u64 / 4) + 2;
        }

        if let Some(ledger) = &state.spend_ledger {
            let agent_id = identity_sub
                .map(|s| s.to_string())
                .unwrap_or_else(|| "anonymous".to_string());
            let groups = identity_groups.to_vec();

            let check_res = ledger.check_and_increment(agent_id, groups, 0).await;
            if let crate::spend::SpendCheckResult::BudgetExhausted {
                cap_cents,
                spent_cents,
            } = check_res
            {
                let err_res = make_error_response(
                    StatusCode::FORBIDDEN,
                    "agentcontrol",
                    "budget_exhausted",
                    &format!(
                        "Spend cap exhausted (Limit: ${:.2}, Spent: ${:.2})",
                        cap_cents as f64 / 100.0,
                        spent_cents as f64 / 100.0
                    ),
                    None,
                    false,
                    &session_id_str,
                );

                let event = EgressEvent {
                    timestamp_ns,
                    session_id: session_id_str,
                    transport: "mitm_https".to_string(),
                    method: Some(method.to_string()),
                    target_host: target_host.to_string(),
                    target_port: Some(target_port as i64),
                    url_path: Some(path_and_query.to_string()),
                    request_headers: None,
                    request_body: None,
                    request_body_hash: None,
                    response_status: Some(403),
                    response_body: None,
                    response_body_hash: None,
                    dlp_findings: None,
                    injection_findings: None,
                    latency_ms: Some(start_time.elapsed().as_secs_f64() * 1000.0),
                    verdict: Some("deny".to_string()),
                    semantic_anomaly_score: None,
                    identity_context: None,
                    source: Some("cursor_ide_mitm".to_string()),
                    policy_rule: Some("SPEND-CAP-EXCEEDED".to_string()),
                };
                let _ = state.db_manager.insert(event).await;

                return Ok(err_res.map(full_to_boxed_body));
            }
        }
    } else {
        // Extract model name from raw binary/connect-rpc protobuf payload.
        let model_patterns: &[(&str, &str)] = &[
            // Grok family (xAI)
            ("grok-3-mini", "grok-3-mini"),
            ("grok-3-medium", "grok-3-medium"),
            ("grok-3", "grok-3"),
            ("grok-2", "grok-2"),
            // DeepSeek family
            ("deepseek-r1", "deepseek-r1"),
            ("deepseek-v3", "deepseek-v3"),
            ("deepseek-coder", "deepseek-coder"),
            // OpenAI reasoning models
            ("o3-mini", "o3-mini"),
            ("o3-pro", "o3-pro"),
            ("o3", "o3"),
            ("o1-mini", "o1-mini"),
            ("o1-pro", "o1-pro"),
            ("o1", "o1"),
            // Gemini family
            ("gemini-2.5-pro", "gemini-2.5-pro"),
            ("gemini-2.5-flash", "gemini-2.5-flash"),
            ("gemini-2.0-flash", "gemini-2.0-flash"),
            ("gemini-1.5-pro", "gemini-1.5-pro"),
            // Claude family
            ("claude-sonnet-4", "claude-sonnet-4"),
            ("claude-3-7-sonnet", "claude-3-7-sonnet"),
            ("claude-3-5-sonnet", "claude-3-5-sonnet"),
            ("claude-3-5-haiku", "claude-3-5-haiku"),
            ("claude-3-haiku", "claude-3-haiku"),
            ("claude-3-opus", "claude-3-opus"),
            // GPT family
            ("gpt-4.1", "gpt-4.1"),
            ("gpt-4o-mini", "gpt-4o-mini"),
            ("gpt-4o", "gpt-4o"),
            ("gpt-4-turbo", "gpt-4-turbo"),
            ("gpt-4", "gpt-4"),
            // Cursor native models
            ("cursor-small", "cursor-small"),
            ("cursor-fast", "cursor-fast"),
        ];
        for (needle, name) in model_patterns {
            if body_str.contains(needle) {
                model_name = name.to_string();
                break;
            }
        }
    }

    // --- Model Allowlist & Fallback Enforcement ---
    if is_byok_mode {
        let allowed_models_guard = state.allowed_models.read().unwrap();
        if let Some(allowed) = allowed_models_guard.as_ref() {
            if !allowed.is_empty()
                && !allowed
                    .iter()
                    .any(|m| model_name.eq_ignore_ascii_case(m) || model_name.contains(m))
            {
                let enforcement = state.model_enforcement.read().unwrap().clone();
                if enforcement == "fallback" {
                    let default_guard = state.default_model.read().unwrap();
                    let fallback = default_guard
                        .clone()
                        .unwrap_or_else(|| "gpt-4o-mini".to_string());

                    println!(
                        "⚠ Model '{}' not in allowlist → fallback to '{}'",
                        model_name, fallback
                    );
                    logging::log_event(
                        Level::Warn,
                        "model_fallback_applied",
                        serde_json::json!({
                            "requested_model": model_name,
                            "fallback_model": fallback,
                            "target_host": target_host,
                        }),
                    );

                    if let Ok(mut json_body) =
                        serde_json::from_slice::<serde_json::Value>(&body_bytes)
                    {
                        json_body["model"] = serde_json::json!(fallback);
                        if let Ok(new_bytes) = serde_json::to_vec(&json_body) {
                            body_bytes = bytes::Bytes::from(new_bytes);
                        }
                    }
                    model_name = fallback;
                } else {
                    let err_msg = format!(
                        "Model '{}' is not permitted by your organization. Allowed models: {}",
                        model_name,
                        allowed.join(", ")
                    );
                    println!("🚫 Blocked model '{}' — not in allowlist", model_name);

                    let err_res = make_error_response(
                        StatusCode::FORBIDDEN,
                        "agentcontrol",
                        "model_not_allowed",
                        &err_msg,
                        None,
                        false,
                        &session_id_str,
                    );
                    return Ok(err_res.map(full_to_boxed_body));
                }
            }
        }
    }

    // --- Centralized Key Injection: Swap sentinel → real org key ---
    if is_byok_mode {
        let provider = match target_host {
            h if h.contains("openai.com") => "openai",
            h if h.contains("anthropic.com") => "anthropic",
            h if h.contains("googleapis.com") => "google",
            h if h.contains("openrouter.ai") => "openrouter",
            _ => "openai",
        };

        if let Some(real_key) = state.provider_keys.get(provider) {
            if provider == "anthropic" {
                req_headers.remove(reqwest::header::AUTHORIZATION);
                if let Ok(val) = real_key.value().parse() {
                    req_headers.insert(
                        reqwest::header::HeaderName::from_static("x-api-key"),
                        val,
                    );
                }
            } else if let Ok(val) = format!("Bearer {}", real_key.value()).parse() {
                req_headers.insert(reqwest::header::AUTHORIZATION, val);
            }

            println!("🔑 Injected centralized {} key from Control Hub", provider);
            logging::log_event(
                Level::Info,
                "centralized_key_injected",
                serde_json::json!({
                    "provider": provider,
                    "target_host": target_host,
                    "model": model_name,
                }),
            );
        } else {
            let err_msg = format!(
                "No centralized API key for provider '{}' configured in Control Hub. Contact your administrator to add the key in LLM Providers settings.",
                provider
            );
            println!(
                "❌ No centralized key for provider '{}' — request blocked",
                provider
            );

            let err_res = make_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "agentcontrol",
                "no_centralized_key",
                &err_msg,
                None,
                false,
                &session_id_str,
            );
            return Ok(err_res.map(full_to_boxed_body));
        }
    }

    // 3. Forward to Upstream Server with Streaming
    let reqwest_method = reqwest::Method::from_bytes(method.as_str().as_bytes())?;
    let upstream_req = state
        .http_client
        .request(reqwest_method, &upstream_url)
        .headers(req_headers)
        .body(body_bytes);

    let upstream_res = match upstream_req.send().await {
        Ok(res) => res,
        Err(e) => {
            let err_res = make_error_response(
                StatusCode::BAD_GATEWAY,
                "upstream_provider",
                "upstream_connection_failed",
                &format!("Failed to connect to upstream {}: {}", upstream_url, e),
                None,
                false,
                &session_id_str,
            );
            return Ok(err_res.map(full_to_boxed_body));
        }
    };

    let status = upstream_res.status();
    let mut builder = Response::builder().status(status.as_u16());
    for (k, v) in upstream_res.headers() {
        if k != hyper::header::TRANSFER_ENCODING
            && k != hyper::header::CONTENT_LENGTH
            && k != hyper::header::CONTENT_ENCODING
            && k != hyper::header::CONNECTION
            && k != hyper::header::UPGRADE
            && k != "keep-alive"
            && k != "proxy-connection"
        {
            builder = builder.header(k, v);
        }
    }

    // 4. Stream response chunks directly without buffering
    let stream = upstream_res.bytes_stream().map(|chunk_res| {
        chunk_res
            .map(Frame::data)
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })
    });
    let body = BodyExt::boxed(StreamBody::new(stream));

    // 5. Post-flight Spend Settlement & Console Output
    let prompt_tokens = estimated_prompt_tokens;
    let completion_tokens = 50u64; // base estimate for active stream

    let exact_cents = if let Some(pricing) = &state.pricing_table {
        pricing.estimate_cents(&model_name, prompt_tokens, completion_tokens).max(1)
    } else {
        (prompt_tokens * 3 / 1000).max(1) // Fallback calculation: ~$0.003 per 1k tokens
    };

    if let Some(ledger) = &state.spend_ledger {
        let agent_id = identity_sub
            .map(|s| s.to_string())
            .unwrap_or_else(|| "anonymous".to_string());
        let groups = identity_groups.to_vec();
        let ledger_clone = ledger.clone();

        tokio::spawn(async move {
            let _ = ledger_clone
                .check_and_increment(agent_id, groups, exact_cents)
                .await;
        });
    }

    if prompt_tokens >= state.min_tokens {
        println!(
            "✔ Intercepted Cursor IDE ({}) -> Model: {} | Prompt: ~{} tokens | Est. Cost: ${:.4}",
            target_host,
            model_name,
            prompt_tokens,
            exact_cents as f64 / 100.0
        );

        logging::log_event(
            Level::Info,
            "mitm_llm_spend_captured",
            serde_json::json!({
                "target_host": target_host,
                "model": model_name,
                "prompt_tokens": prompt_tokens,
                "estimated_cost_cents": exact_cents,
            }),
        );
    }

    // Log Egress Event
    let event = EgressEvent {
        timestamp_ns,
        session_id: session_id_str,
        transport: "mitm_https".to_string(),
        method: Some(method.to_string()),
        target_host: target_host.to_string(),
        target_port: Some(target_port as i64),
        url_path: Some(path_and_query.to_string()),
        request_headers: None,
        request_body: None,
        request_body_hash: None,
        response_status: Some(status.as_u16() as i64),
        response_body: None,
        response_body_hash: None,
        dlp_findings: dlp_findings_json,
        injection_findings: None,
        latency_ms: Some(start_time.elapsed().as_secs_f64() * 1000.0),
        verdict: Some("allow".to_string()),
        semantic_anomaly_score: None,
        identity_context: None,
        source: Some("cursor_ide_mitm".to_string()),
        policy_rule: Some("DEFAULT-ALLOW".to_string()),
    };
    if let Ok(json_str) = serde_json::to_string(&event) {
        let _ = state.event_tx.send(json_str);
    }
    let _ = state.db_manager.insert(event).await;

    Ok(builder.body(body)?)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_sentinel_key_detection() {
        let sentinel1 = "Bearer sk-agentcontrol-managed";
        let sentinel2 = "Bearer agentcontrol-managed";
        let normal_key = "Bearer sk-proj-1234567890abcdef";

        assert!(sentinel1.contains("sk-agentcontrol-managed") || sentinel1.contains("agentcontrol-managed"));
        assert!(sentinel2.contains("sk-agentcontrol-managed") || sentinel2.contains("agentcontrol-managed"));
        assert!(!normal_key.contains("agentcontrol-managed"));
    }

    #[test]
    fn test_model_pattern_priority() {
        let model_patterns: &[(&str, &str)] = &[
            ("grok-3-mini", "grok-3-mini"),
            ("grok-3-medium", "grok-3-medium"),
            ("grok-3", "grok-3"),
            ("grok-2", "grok-2"),
            ("deepseek-r1", "deepseek-r1"),
            ("o3-mini", "o3-mini"),
            ("gpt-4o", "gpt-4o"),
        ];

        // Payload with both grok-3-medium and gpt-4o capability string
        let payload = "cursor_proto_grok-3-medium_metadata_gpt-4o_fallback";
        let mut matched = "gpt-4o".to_string();
        for (needle, name) in model_patterns {
            if payload.contains(needle) {
                matched = name.to_string();
                break;
            }
        }
        assert_eq!(matched, "grok-3-medium");
    }

    #[test]
    fn test_model_allowlist_matching() {
        let allowed = ["gpt-4o".to_string(), "gpt-4o-mini".to_string(), "claude-3-5-sonnet".to_string()];

        let model1 = "gpt-4o";
        let model2 = "gpt-4o-mini";
        let model3 = "o3-pro";

        assert!(allowed.iter().any(|m| model1.eq_ignore_ascii_case(m) || model1.contains(m)));
        assert!(allowed.iter().any(|m| model2.eq_ignore_ascii_case(m) || model2.contains(m)));
        assert!(!allowed.iter().any(|m| model3.eq_ignore_ascii_case(m) || model3.contains(m)));
    }
}
