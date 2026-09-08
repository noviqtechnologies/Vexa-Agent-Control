//! Pull-based provider keys & routing desired-state reconciler (REQ-DSM-004 / REQ-DSM-005 / REQ-DSM-006).
//!
//! Provides periodic convergence polling with instant wake-up triggers on SSE push,
//! idempotent in-memory hot-swapping, and direct acknowledgment back to the Control Hub.

use crate::logging::{self, Level};
use crate::proxy::handler::ProxyState;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

#[derive(Deserialize, Debug, Clone)]
pub struct ActiveProviderKeysPayload {
    pub assignment_id: Option<String>,
    pub payload_hash: String,
    pub cursor_mode: Option<String>,
    pub virtual_key: Option<String>,
    pub default_model: Option<String>,
    pub allowed_models: Option<Vec<String>>,
    pub model_enforcement: Option<bool>,
    pub provider_keys: Option<std::collections::HashMap<String, String>>,
}

#[derive(Serialize, Debug)]
pub struct AssignmentAckPayload<'a> {
    pub assignment_id: &'a str,
    pub state: &'a str,
    pub payload_hash: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<&'a str>,
}

/// Helper to send an assignment acknowledgment back to the Control Hub (REQ-DSM-006).
pub async fn send_assignment_ack(
    hub_url: &str,
    assignment_id: &str,
    state: &str,
    payload_hash: &str,
) -> Result<(), String> {
    let clean_base = hub_url.trim_end_matches('/');
    let client = crate::policy::remote::build_device_http_client(Duration::from_secs(10));
    let device_token = crate::identity::device::load_device_token()
        .or_else(|| std::env::var("GATEWAY_SECRET").ok())
        .unwrap_or_default();

    let ack_payload = AssignmentAckPayload {
        assignment_id,
        state,
        payload_hash,
        error_message: None,
    };

    // Try primary device endpoint
    let url = format!("{}/api/v2/device/assignments/{}/ack", clean_base, assignment_id);
    let mut req = client
        .post(&url)
        .header("Content-Type", "application/json")
        .json(&ack_payload);

    if !device_token.is_empty() {
        req = req.header("Authorization", format!("Bearer {}", device_token));
    }

    match req.send().await {
        Ok(resp) if resp.status().is_success() => Ok(()),
        Ok(resp) => {
            // Fallback to gateway-broker route if available
            let fallback_url = format!("{}/api/v3/gateway-broker/assignments/{}/ack", clean_base, assignment_id);
            let mut fb_req = client
                .post(&fallback_url)
                .header("Content-Type", "application/json")
                .json(&ack_payload);
            if !device_token.is_empty() {
                fb_req = fb_req.header("Authorization", format!("Bearer {}", device_token));
            }
            if let Ok(fb_resp) = fb_req.send().await {
                if fb_resp.status().is_success() {
                    return Ok(());
                }
            }
            Err(format!("Assignment ACK failed with status: {}", resp.status()))
        }
        Err(e) => Err(format!("Network error sending assignment ACK: {}", e)),
    }
}

/// Fetches active provider keys & routing desired state from Control Hub.
pub async fn fetch_active_provider_keys(
    hub_url: &str,
) -> Result<Option<ActiveProviderKeysPayload>, String> {
    let clean_base = hub_url.trim_end_matches('/');
    let client = crate::policy::remote::build_device_http_client(Duration::from_secs(10));
    let device_token = crate::identity::device::load_device_token()
        .or_else(|| std::env::var("GATEWAY_SECRET").ok());

    let v2_url = format!("{}/api/v2/device/provider-keys/active", clean_base);
    let mut req = client.get(&v2_url);
    if let Some(ref tok) = device_token {
        req = req.header("Authorization", format!("Bearer {}", tok));
    }

    match req.send().await {
        Ok(resp) if resp.status().is_success() => {
            let payload: ActiveProviderKeysPayload = resp
                .json()
                .await
                .map_err(|e| format!("Failed to parse active provider keys JSON: {}", e))?;
            Ok(Some(payload))
        }
        Ok(resp) if resp.status() == reqwest::StatusCode::NOT_FOUND => {
            // Try gateway-broker fallback
            let fb_url = format!("{}/api/v3/gateway-broker/provider-keys/active", clean_base);
            let mut fb_req = client.get(&fb_url);
            if let Some(ref tok) = device_token {
                fb_req = fb_req.header("Authorization", format!("Bearer {}", tok));
            }
            if let Ok(fb_resp) = fb_req.send().await {
                if fb_resp.status().is_success() {
                    let payload: ActiveProviderKeysPayload = fb_resp
                        .json()
                        .await
                        .map_err(|e| format!("Failed to parse fallback provider keys JSON: {}", e))?;
                    return Ok(Some(payload));
                }
            }
            Ok(None)
        }
        Ok(resp) => Err(format!("HTTP {} fetching active provider keys", resp.status())),
        Err(e) => Err(format!("Failed to connect to Control Hub: {}", e)),
    }
}

/// Runs the background provider keys reconciler loop.
///
/// Wakes up on either:
/// 1. Regular interval (`interval_secs`) - convergence safety net
/// 2. Incoming notification signal on `wake_rx` - fast-path push from SSE (REQ-DSM-005)
pub async fn start_provider_keys_poll(
    state: Arc<ProxyState>,
    hub_url: String,
    interval_secs: u64,
    mut wake_rx: tokio::sync::mpsc::Receiver<()>,
) {
    let mut last_hash: Option<String> = None;
    let sleep_dur = Duration::from_secs(if interval_secs == 0 { 60 } else { interval_secs });

    loop {
        tokio::select! {
            _ = tokio::time::sleep(sleep_dur) => {},
            Some(_) = wake_rx.recv() => {
                logging::log_event(
                    Level::Info,
                    "provider_keys_poll_woken_by_sse",
                    serde_json::json!({ "source": "sse_push_hint" }),
                );
            }
        }

        match fetch_active_provider_keys(&hub_url).await {
            Ok(Some(payload)) => {
                if last_hash.as_deref() == Some(&payload.payload_hash) {
                    continue;
                }

                logging::log_event(
                    Level::Info,
                    "provider_keys_reconciling",
                    serde_json::json!({
                        "previous_hash": last_hash,
                        "new_hash": &payload.payload_hash,
                        "assignment_id": &payload.assignment_id,
                    }),
                );

                // 1. Hot-swap provider keys in memory
                if let Some(ref keys) = payload.provider_keys {
                    for (prov, k) in keys {
                        if k.is_empty() {
                            state.provider_keys.remove(prov);
                        } else {
                            state.provider_keys.insert(prov.clone(), k.clone());
                        }
                    }
                }

                // 2. Hot-swap cursor mode
                if let Some(ref mode) = payload.cursor_mode {
                    if let Ok(mut lock) = state.cursor_mode.write() {
                        *lock = mode.clone();
                    }
                }

                // 3. Hot-swap model routing rules
                if let Some(ref models) = payload.allowed_models {
                    if let Ok(mut lock) = state.allowed_models.write() {
                        *lock = Some(models.clone());
                    }
                }
                if let Some(ref def_model) = payload.default_model {
                    if let Ok(mut lock) = state.default_model.write() {
                        *lock = Some(def_model.clone());
                    }
                }

                // 4. Send Acknowledgment back to Control Hub (REQ-DSM-006)
                if let Some(ref asgn_id) = payload.assignment_id {
                    let ack_res = send_assignment_ack(
                        &hub_url,
                        asgn_id,
                        "applied",
                        &payload.payload_hash,
                    ).await;

                    if let Err(ack_err) = ack_res {
                        logging::log_event(
                            Level::Warn,
                            "assignment_ack_failed",
                            serde_json::json!({ "assignment_id": asgn_id, "error": ack_err }),
                        );
                    } else {
                        logging::log_event(
                            Level::Info,
                            "assignment_ack_sent",
                            serde_json::json!({ "assignment_id": asgn_id, "state": "applied" }),
                        );
                    }
                }

                last_hash = Some(payload.payload_hash);
            }
            Ok(None) => {}
            Err(e) => {
                logging::log_event(
                    Level::Warn,
                    "provider_keys_poll_failed",
                    serde_json::json!({ "error": &e }),
                );
            }
        }
    }
}
