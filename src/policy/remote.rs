//! Remote policy loader — fetches the active policy YAML from the dashboard API.
//!
//! # Architecture
//! The dashboard API is the single source of truth for policy. On startup and
//! every POLICY_POLL_INTERVAL_SECS seconds, the gateway calls:
//!
//!   GET {DASHBOARD_API_URL}/api/v1/policy/active
//!   Authorization: Bearer {POLICY_READ_SECRET}
//!
//! The response contains a JSON body `{ "content": "<yaml>" }`.
//! The YAML is compiled via `load_policy_from_str` and hot-swapped into the
//! shared `ProxyState.policy` RwLock — same path used by SIGHUP reload.
//!
//! # Fallback behaviour
//! If the API is unreachable at startup, the gateway logs a warning and falls
//! back to `--policy <file>` (if provided) or Safe Mode. This ensures the
//! gateway never silently fails to start because the dashboard is temporarily
//! unavailable during a rolling deployment.

use crate::logging::{self, Level};
use crate::policy::loader::{load_policy_from_str, PolicyLoadResult};
use serde::Deserialize;

/// JSON shape returned by GET /api/v1/policy/active
#[derive(Deserialize, Debug)]
pub struct RemotePolicy {
    /// Semantic version string set by the admin (e.g. "v1.0.0")
    pub version: Option<String>,
    /// Raw YAML policy content stored in PostgreSQL
    pub content: Option<String>,
}

/// Fetch the active policy YAML from the dashboard API.
///
/// Returns `Ok(Some(yaml_string))` when a policy exists in the DB.
/// Returns `Ok(None)` when no active policy has been saved yet.
/// Returns `Err(message)` on network / auth failures.
pub async fn fetch_policy_yaml(
    dashboard_url: &str,
    policy_read_secret: Option<&str>,
) -> Result<Option<String>, String> {
    let url = format!("{}/api/v1/policy/active", dashboard_url.trim_end_matches('/'));

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

    let mut req = client.get(&url);

    // Authenticate with the shared policy-read secret
    if let Some(secret) = policy_read_secret {
        req = req.header("Authorization", format!("Bearer {}", secret));
    }

    let resp = req
        .send()
        .await
        .map_err(|e| format!("Network error fetching policy from {}: {}", url, e))?;

    let status = resp.status();

    if status == reqwest::StatusCode::NOT_FOUND || status == reqwest::StatusCode::NO_CONTENT {
        // Dashboard returned 404/204 — no policy saved yet, not an error
        return Ok(None);
    }

    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!(
            "Dashboard API returned HTTP {} for {}: {}",
            status, url, body
        ));
    }

    let remote: RemotePolicy = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse policy JSON from dashboard API: {}", e))?;

    // Empty content field — treat as no policy
    match remote.content {
        Some(yaml) if !yaml.trim().is_empty() => Ok(Some(yaml)),
        _ => Ok(None),
    }
}

/// Fetch policy from the dashboard API and compile it.
///
/// Returns `PolicyLoadResult::Loaded` on success,
/// `PolicyLoadResult::Degraded` when no active policy exists,
/// `PolicyLoadResult::Fatal` on an unrecoverable compile error.
pub async fn load_remote_policy(
    dashboard_url: &str,
    policy_read_secret: Option<&str>,
) -> PolicyLoadResult {
    match fetch_policy_yaml(dashboard_url, policy_read_secret).await {
        Ok(Some(yaml)) => {
            logging::log_event(
                Level::Info,
                "policy_fetch_remote",
                serde_json::json!({
                    "source": "dashboard_api",
                    "url": dashboard_url,
                    "yaml_bytes": yaml.len()
                }),
            );
            // Compile using the same path as the file loader (FR-103)
            load_policy_from_str(&yaml, None)
        }
        Ok(None) => {
            logging::log_event(
                Level::Warn,
                "policy_fetch_remote_empty",
                serde_json::json!({
                    "source": "dashboard_api",
                    "reason": "No active policy in DB — falling back"
                }),
            );
            PolicyLoadResult::Degraded {
                reason: "No active policy found in dashboard database".to_string(),
            }
        }
        Err(e) => {
            logging::log_event(
                Level::Error,
                "policy_fetch_remote_failed",
                serde_json::json!({ "error": &e }),
            );
            PolicyLoadResult::Degraded { reason: e }
        }
    }
}

/// Background polling task. Runs indefinitely, waking every `interval_secs`
/// seconds to check whether the policy version has changed.
///
/// When a new version is detected, it fetches, compiles, and hot-swaps the
/// policy into `state.policy` using the existing RwLock mechanism (same as
/// the SIGHUP and POST /reload paths).
pub async fn start_policy_poll(
    state: std::sync::Arc<crate::proxy::handler::ProxyState>,
    dashboard_url: String,
    policy_read_secret: Option<String>,
    interval_secs: u64,
) {
    // Track the last loaded version so we only recompile on actual changes
    let mut last_version: Option<String> = None;

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;

        // Fetch raw YAML + version from dashboard API
        let yaml_result = fetch_policy_yaml(&dashboard_url, policy_read_secret.as_deref()).await;

        let yaml = match yaml_result {
            Ok(Some(y)) => y,
            Ok(None) => {
                // No active policy in DB — nothing to update
                continue;
            }
            Err(e) => {
                logging::log_event(
                    Level::Warn,
                    "policy_poll_fetch_failed",
                    serde_json::json!({ "error": &e }),
                );
                continue;
            }
        };

        // Compute a quick hash to detect changes without re-parsing
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(yaml.as_bytes());
        let version_hash = format!("sha256:{}", hex::encode(h.finalize()));

        if last_version.as_deref() == Some(&version_hash) {
            // Policy unchanged — skip recompile
            continue;
        }

        // Policy changed — compile and hot-swap
        let reload_start = std::time::Instant::now();
        let result = tokio::task::spawn_blocking({
            let yaml_clone = yaml.clone();
            move || load_policy_from_str(&yaml_clone, None)
        })
        .await;

        match result {
            Ok(PolicyLoadResult::Loaded { policy, raw_hash, warnings }) => {
                match state.policy.write() {
                    Ok(mut guard) => {
                        *guard = Some(policy);
                        state
                            .policy_loaded
                            .store(true, std::sync::atomic::Ordering::SeqCst);
                        last_version = Some(version_hash);

                        let elapsed_ms = reload_start.elapsed().as_secs_f64() * 1000.0;
                        logging::log_event(
                            Level::Info,
                            "policy_reloaded_remote",
                            serde_json::json!({
                                "source": "dashboard_api",
                                "hash": &raw_hash,
                                "warnings": &warnings,
                                "elapsed_ms": elapsed_ms,
                            }),
                        );

                        // Broadcast SSE event so any live dashboard connections update
                        let _ = state.event_tx.send(format!(
                            "event: policy_reloaded\ndata: {{\"hash\":\"{}\"}}\n\n",
                            raw_hash
                        ));
                    }
                    Err(_) => {
                        logging::log_event(
                            Level::Error,
                            "policy_poll_reload_failed",
                            serde_json::json!({ "error": "Policy RwLock poisoned" }),
                        );
                    }
                }
            }
            Ok(PolicyLoadResult::Fatal { error }) => {
                logging::log_event(
                    Level::Error,
                    "policy_poll_compile_failed",
                    serde_json::json!({ "error": error.to_string() }),
                );
                // Keep enforcing the last good policy — do not update last_version
            }
            Ok(PolicyLoadResult::Degraded { reason }) => {
                logging::log_event(
                    Level::Warn,
                    "policy_poll_degraded",
                    serde_json::json!({ "reason": &reason }),
                );
            }
            Err(join_err) => {
                logging::log_event(
                    Level::Error,
                    "policy_poll_task_panic",
                    serde_json::json!({ "error": join_err.to_string() }),
                );
            }
        }
    }
}
