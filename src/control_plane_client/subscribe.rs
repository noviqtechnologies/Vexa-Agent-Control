//! Server-Sent Events (SSE) subscriber client for real-time remote policy pushes from Control Plane.

use eventsource_stream::Eventsource;
use futures_util::StreamExt;
use std::sync::Arc;

use crate::logging::{self, Level};
use crate::policy::loader::load_policy_from_str;

/// Subscribes to the Hub's SSE endpoint to receive real-time policy updates.
///
/// Runs an infinite event loop with automatic reconnect handling. On receipt of `policy_update`
/// events, parses and validates the policy string and updates the thread-safe `ProxyState`.
///
/// # Arguments
/// * `dashboard_url` - Control plane hub base HTTP URL.
/// * `secret` - Authentication Bearer token for the control plane.
/// * `state` - Shared atomic application state to update when new policy versions arrive.
pub async fn start_policy_subscriber(
    dashboard_url: String,
    secret: String,
    state: Arc<crate::proxy::handler::ProxyState>,
) {
    let clean_base = dashboard_url.trim_end_matches('/');
    let client = crate::policy::remote::build_device_http_client(std::time::Duration::from_secs(30));

    loop {
        let device_token_opt = crate::identity::device::load_device_token()
            .or_else(|| std::env::var("AGENT_ID").ok());

        // Determine effective endpoint and auth token
        let (url, auth_bearer) = if !secret.is_empty() {
            (format!("{}/api/v1/policy/subscribe", clean_base), Some(secret.clone()))
        } else if let Some(tok) = device_token_opt {
            (format!("{}/api/v2/device/policy/subscribe", clean_base), Some(tok))
        } else {
            // Attempt mTLS device endpoint
            (format!("{}/api/v2/device/policy/subscribe", clean_base), None)
        };

        let mut req = client.get(&url);
        if let Some(ref bearer) = auth_bearer {
            req = req.header("Authorization", format!("Bearer {}", bearer));
        }

        let resp_res = req.send().await;

        match resp_res {
            Ok(resp) => {
                let status = resp.status();
                if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
                    let err_body = resp.text().await.unwrap_or_default();
                    logging::log_event(
                        Level::Error,
                        "tenant_auth_failed",
                        serde_json::json!({
                            "url": &url,
                            "status": status.as_u16(),
                            "reason": "sse_subscription_unauthorized",
                            "body": err_body,
                        }),
                    );
                    // Do NOT treat unauthorized stream as started. Back off before retry.
                    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                    continue;
                }

                if !status.is_success() {
                    let err_body = resp.text().await.unwrap_or_default();
                    logging::log_event(
                        Level::Warn,
                        "sse_connection_error",
                        serde_json::json!({
                            "url": &url,
                            "status": status.as_u16(),
                            "body": err_body,
                        }),
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue;
                }

                logging::log_event(
                    Level::Info,
                    "sse_subscriber_started",
                    serde_json::json!({"url": url}),
                );

                let mut stream = resp.bytes_stream().eventsource();
                while let Some(event_res) = stream.next().await {
                    match event_res {
                        Ok(message) => {
                            if message.event == "policy_update" {
                                logging::log_event(
                                    Level::Info,
                                    "sse_policy_update_received",
                                    serde_json::json!({}),
                                );

                                match load_policy_from_str(&message.data, None) {
                                    crate::policy::loader::PolicyLoadResult::Loaded {
                                        policy,
                                        raw_hash,
                                        ..
                                    } => {
                                        let mut w = state.policy.write().unwrap();
                                        *w = Some(policy);
                                        state
                                            .policy_loaded
                                            .store(true, std::sync::atomic::Ordering::SeqCst);
                                        logging::log_event(
                                            Level::Info,
                                            "policy_reloaded_from_hub",
                                            serde_json::json!({"hash": raw_hash}),
                                        );
                                    }
                                    crate::policy::loader::PolicyLoadResult::Degraded {
                                        reason,
                                    } => {
                                        logging::log_event(
                                            Level::Warn,
                                            "policy_push_degraded",
                                            serde_json::json!({"reason": reason}),
                                        );
                                    }
                                    crate::policy::loader::PolicyLoadResult::Fatal { error } => {
                                        logging::log_event(
                                            Level::Error,
                                            "policy_push_fatal",
                                            serde_json::json!({"error": error.to_string()}),
                                        );
                                    }
                                }
                            } else if message.event == "provider_keys_update" {
                                logging::log_event(
                                    Level::Info,
                                    "sse_provider_keys_update_received",
                                    serde_json::json!({}),
                                );

                                if let Ok(payload) = serde_json::from_str::<serde_json::Value>(&message.data) {
                                    if let Some(providers) = payload.get("providers").and_then(|v| v.as_object()) {
                                        for (provider, key_val) in providers {
                                            if let Some(key) = key_val.as_str() {
                                                let prev_hash = state.provider_keys.get(provider).map(|k| {
                                                    use sha2::{Digest, Sha256};
                                                    let mut hasher = Sha256::new();
                                                    hasher.update(k.value().as_bytes());
                                                    format!("sha256:{}", hex::encode(hasher.finalize()))
                                                });

                                                if key.is_empty() {
                                                    state.provider_keys.remove(provider);
                                                } else {
                                                    state.provider_keys.insert(provider.clone(), key.to_string());
                                                }

                                                logging::log_event(
                                                    Level::Info,
                                                    "provider_key_rotated",
                                                    serde_json::json!({
                                                        "provider": provider,
                                                        "key_prefix": crate::policy::dlp::truncated_preview(key),
                                                        "previous_key_hash": prev_hash,
                                                        "rotation_source": "hub_push",
                                                    }),
                                                );
                                            }
                                        }
                                    }

                                    if let Some(mode) = payload.get("cursor_mode").and_then(|v| v.as_str()) {
                                        *state.cursor_mode.write().unwrap() = mode.to_string();
                                    }
                                    if let Some(models) = payload.get("allowed_models").and_then(|v| v.as_array()) {
                                        let model_list: Vec<String> = models
                                            .iter()
                                            .filter_map(|m| m.as_str().map(String::from))
                                            .collect();
                                        *state.allowed_models.write().unwrap() = Some(model_list);
                                    }
                                    if let Some(dm) = payload.get("default_model").and_then(|v| v.as_str()) {
                                        *state.default_model.write().unwrap() = Some(dm.to_string());
                                    }
                                    if let Some(enf) = payload.get("model_enforcement").and_then(|v| v.as_str()) {
                                        *state.model_enforcement.write().unwrap() = enf.to_string();
                                    }

                                    let is_byok = state.cursor_mode.read().unwrap().as_str() == "byok";
                                    if is_byok && !state.provider_keys.is_empty() {
                                        let _ = crate::wrap::generic_ide::apply_centralized_cursor_config(true);
                                    }

                                    logging::log_event(
                                        Level::Info,
                                        "provider_keys_synced",
                                        serde_json::json!({
                                            "providers_count": state.provider_keys.len(),
                                            "cursor_mode": state.cursor_mode.read().unwrap().clone(),
                                        }),
                                    );
                                }
                            } else if message.event == "ping" {
                                // Keep-alive, ignore
                            } else {
                                logging::log_event(
                                    Level::Info,
                                    "sse_unknown_event",
                                    serde_json::json!({"event": message.event}),
                                );
                            }
                        }
                        Err(err) => {
                            logging::log_event(
                                Level::Error,
                                "sse_connection_error",
                                serde_json::json!({"error": err.to_string()}),
                            );
                            break;
                        }
                    }
                }
            }
            Err(err) => {
                logging::log_event(
                    Level::Error,
                    "sse_connection_error",
                    serde_json::json!({"error": err.to_string()}),
                );
            }
        }

        // Reconnect after delay
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}
