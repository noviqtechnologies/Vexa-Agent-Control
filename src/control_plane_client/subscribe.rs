//! Server-Sent Events (SSE) subscriber client for real-time remote policy pushes from Control Plane.

use futures_util::StreamExt;
use reqwest_eventsource::{Event, EventSource};
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
    let url = format!("{}/api/v1/policy/subscribe", dashboard_url.trim_end_matches('/'));

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(0)) // No timeout for SSE
        .build()
        .expect("Failed to build HTTP client for SSE");

    loop {
        let req = client.get(&url).header("Authorization", format!("Bearer {}", secret));
        let mut event_source = EventSource::new(req).unwrap();

        logging::log_event(
            Level::Info,
            "sse_subscriber_started",
            serde_json::json!({"url": url}),
        );

        while let Some(event) = event_source.next().await {
            match event {
                Ok(Event::Open) => {
                    logging::log_event(
                        Level::Info,
                        "sse_connection_opened",
                        serde_json::json!({"url": url}),
                    );
                }
                Ok(Event::Message(message)) => {
                    if message.event == "policy_update" {
                        logging::log_event(
                            Level::Info,
                            "sse_policy_update_received",
                            serde_json::json!({}),
                        );
                        
                        match load_policy_from_str(&message.data, None) {
                            crate::policy::loader::PolicyLoadResult::Loaded { policy, raw_hash, .. } => {
                                let mut w = state.policy.write().unwrap();
                                *w = Some(policy);
                                state.policy_loaded.store(true, std::sync::atomic::Ordering::SeqCst);
                                logging::log_event(
                                    Level::Info,
                                    "policy_reloaded_from_hub",
                                    serde_json::json!({"hash": raw_hash}),
                                );
                            }
                            crate::policy::loader::PolicyLoadResult::Degraded { reason } => {
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
                    event_source.close();
                    break;
                }
            }
        }

        // Reconnect after delay
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}
