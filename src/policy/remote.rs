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
use crate::policy::engine::CompiledPolicy;
use crate::policy::loader::{load_policy_from_str, PolicyLoadResult};
use crate::policy::signed::{verify_signed_bundle, SignedPolicyBundle};
use crate::policy::trust::PolicyTrustProfile;
use colored::Colorize;
use serde::Deserialize;

/// JSON shape returned by GET /api/v1/policy/active or /api/v2/device/policy/active
#[derive(Deserialize, Debug)]
pub struct RemotePolicy {
    /// Semantic version string set by the admin (e.g. "v1.0.0")
    pub version: Option<String>,
    /// Raw YAML policy content stored in PostgreSQL
    pub content: Option<String>,
}

fn apply_device_identity(mut builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    // Look for device cert and key in ~/.agentcontrol, ~/.agentwall, or Windows ProgramData
    let mut candidate_dirs = Vec::new();
    if let Some(home_dir) = dirs::home_dir() {
        candidate_dirs.push(home_dir.join(".agentcontrol"));
        candidate_dirs.push(home_dir.join(".agentwall"));
    }
    #[cfg(windows)]
    {
        candidate_dirs.push(std::path::PathBuf::from(r"C:\ProgramData\AgentControl"));
    }

    for dir in candidate_dirs {
        let cert_path = dir.join("device_cert.pem");
        let key_path = dir.join("device_key.pem");
        if cert_path.exists() && key_path.exists() {
            if let (Ok(cert_bytes), Ok(key_bytes)) =
                (std::fs::read(&cert_path), std::fs::read(&key_path))
            {
                let mut combined = cert_bytes;
                combined.extend_from_slice(b"\n");
                combined.extend_from_slice(&key_bytes);
                if let Ok(identity) = reqwest::Identity::from_pem(&combined) {
                    builder = builder.identity(identity);
                    break;
                }
            }
        }
    }

    builder
}

/// Helper to construct a Reqwest client with mTLS device identity if available.
pub fn build_device_http_client(timeout: std::time::Duration) -> reqwest::Client {
    let builder = reqwest::Client::builder().no_proxy().timeout(timeout);
    apply_device_identity(builder).build().unwrap_or_default()
}

/// Helper to construct a Reqwest client for long-lived SSE streaming without request timeout.
pub fn build_device_sse_client() -> reqwest::Client {
    let builder = reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(std::time::Duration::from_secs(10))
        .tcp_keepalive(Some(std::time::Duration::from_secs(15)));
    apply_device_identity(builder).build().unwrap_or_default()
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
    let clean_base = dashboard_url.trim_end_matches('/');
    let client = build_device_http_client(std::time::Duration::from_secs(10));

    // 1. Try device-authenticated endpoint (/api/v2/device/policy/active)
    let device_token_opt =
        crate::identity::device::load_device_token().or_else(|| std::env::var("AGENT_ID").ok());

    let v2_url = format!("{}/api/v2/device/policy/active", clean_base);
    let mut req_v2 = client.get(&v2_url);
    if let Some(ref tok) = device_token_opt {
        req_v2 = req_v2.header("Authorization", format!("Bearer {}", tok));
    }

    if let Ok(resp_v2) = req_v2.send().await {
        let status = resp_v2.status();
        if status.is_success() {
            let remote: RemotePolicy = resp_v2
                .json()
                .await
                .map_err(|e| format!("Failed to parse policy JSON from dashboard API: {}", e))?;
            return match remote.content {
                Some(yaml) if !yaml.trim().is_empty() => Ok(Some(yaml)),
                _ => Ok(None),
            };
        } else if status == reqwest::StatusCode::NOT_FOUND
            || status == reqwest::StatusCode::NO_CONTENT
        {
            return Ok(None);
        } else if status == reqwest::StatusCode::UNAUTHORIZED
            || status == reqwest::StatusCode::FORBIDDEN
        {
            // Log typed auth failure if device credentials were tried
            if device_token_opt.is_some() {
                let body = resp_v2.text().await.unwrap_or_default();
                logging::log_event(
                    Level::Error,
                    "tenant_auth_failed",
                    serde_json::json!({
                        "url": &v2_url,
                        "status": status.as_u16(),
                        "reason": "device_policy_fetch_unauthorized",
                        "body": &body,
                    }),
                );
            }
        }
    }

    // 2. Fall back to /api/v1/policy/active (legacy secret or general endpoint)
    let url = format!("{}/api/v1/policy/active", clean_base);
    let mut req = client.get(&url);

    if let Some(secret) = policy_read_secret {
        req = req.header("Authorization", format!("Bearer {}", secret));
    } else if let Some(ref tok) = device_token_opt {
        req = req.header("Authorization", format!("Bearer {}", tok));
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

    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        let body = resp.text().await.unwrap_or_default();
        logging::log_event(
            Level::Error,
            "tenant_auth_failed",
            serde_json::json!({
                "url": &url,
                "status": status.as_u16(),
                "reason": "policy_fetch_unauthorized",
                "body": &body,
            }),
        );
        return Err(format!(
            "tenant_auth_failed: Dashboard API returned HTTP {} for {}: {}",
            status, url, body
        ));
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

/// Fetch the active signed policy bundle from the dashboard API.
///
/// Returns `Ok(Some(SignedPolicyBundle))` when an active bundle exists.
/// Returns `Ok(None)` when no active bundle has been saved yet (404/204).
/// Returns `Err(message)` on network, auth, or parsing failures.
pub async fn fetch_policy_bundle(
    dashboard_url: &str,
    policy_read_secret: Option<&str>,
) -> Result<Option<SignedPolicyBundle>, String> {
    let clean_base = dashboard_url.trim_end_matches('/');
    let client = build_device_http_client(std::time::Duration::from_secs(10));

    let device_token_opt =
        crate::identity::device::load_device_token().or_else(|| std::env::var("AGENT_ID").ok());

    // 1. Try device-authenticated endpoint (/api/v2/device/policy/bundle)
    let v2_url = format!("{}/api/v2/device/policy/bundle", clean_base);
    let mut req_v2 = client.get(&v2_url);
    if let Some(ref tok) = device_token_opt {
        req_v2 = req_v2.header("Authorization", format!("Bearer {}", tok));
    }

    if let Ok(resp_v2) = req_v2.send().await {
        let status = resp_v2.status();
        if status.is_success() {
            let bundle: SignedPolicyBundle = resp_v2.json().await.map_err(|e| {
                format!("Failed to parse SignedPolicyBundle from {}: {}", v2_url, e)
            })?;
            return Ok(Some(bundle));
        } else if status == reqwest::StatusCode::NOT_FOUND
            || status == reqwest::StatusCode::NO_CONTENT
        {
            return Ok(None);
        } else if status == reqwest::StatusCode::UNAUTHORIZED
            || status == reqwest::StatusCode::FORBIDDEN
        {
            if device_token_opt.is_some() {
                let body = resp_v2.text().await.unwrap_or_default();
                logging::log_event(
                    Level::Error,
                    "tenant_auth_failed",
                    serde_json::json!({
                        "url": &v2_url,
                        "status": status.as_u16(),
                        "reason": "device_policy_bundle_fetch_unauthorized",
                        "body": &body,
                    }),
                );
            }
        }
    }

    // 2. Try /api/v1/policy/bundle (secret or device token)
    let url = format!("{}/api/v1/policy/bundle", clean_base);
    let mut req = client.get(&url);

    if let Some(secret) = policy_read_secret {
        req = req.header("Authorization", format!("Bearer {}", secret));
    } else if let Some(ref tok) = device_token_opt {
        req = req.header("Authorization", format!("Bearer {}", tok));
    }

    let resp = req
        .send()
        .await
        .map_err(|e| format!("Network error fetching policy bundle from {}: {}", url, e))?;

    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND || status == reqwest::StatusCode::NO_CONTENT {
        return Ok(None);
    }

    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        let body = resp.text().await.unwrap_or_default();
        logging::log_event(
            Level::Error,
            "tenant_auth_failed",
            serde_json::json!({
                "url": &url,
                "status": status.as_u16(),
                "reason": "policy_bundle_fetch_unauthorized",
                "body": &body,
            }),
        );
        return Err(format!(
            "tenant_auth_failed: Dashboard API returned HTTP {} for {}: {}",
            status, url, body
        ));
    }

    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!(
            "Dashboard API returned HTTP {} for {}: {}",
            status, url, body
        ));
    }

    let bundle: SignedPolicyBundle = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse SignedPolicyBundle from {}: {}", url, e))?;

    Ok(Some(bundle))
}

/// Path to local offline cached policy: `~/.agentcontrol/cached_policy.yaml`
/// Authenticated and signed policy cache envelope (Gate 5).
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct AuthenticatedPolicyCache {
    pub schema_version: u32,
    pub version_hash: String,
    pub timestamp: u64,
    pub yaml_content: String,
    pub hmac_signature: String,
}

pub fn cached_policy_envelope_path() -> Option<std::path::PathBuf> {
    dirs::home_dir().map(|h| h.join(".agentcontrol").join("cached_policy.json"))
}

pub fn resolve_cache_secret(require_explicit: bool) -> Result<String, String> {
    if let Some(tok) = crate::identity::device::load_device_token() {
        return Ok(tok);
    }
    if let Ok(sec) = std::env::var("POLICY_READ_SECRET") {
        return Ok(sec);
    }
    if let Ok(sec) = std::env::var("AGENTCONTROL_SESSION_SECRET") {
        return Ok(sec);
    }
    if require_explicit {
        return Err("Offline policy cache authentication failed: no device token or explicit secret configured in managed mode".to_string());
    }
    logging::log_event(
        Level::Warn,
        "cache_hmac_insecure_fallback",
        serde_json::json!({
            "warning": "Using insecure fallback secret for policy cache HMAC. Not allowed in managed mode."
        }),
    );
    Ok("agentcontrol-offline-policy-cache-secret".to_string())
}

pub fn compute_cache_hmac(version_hash: &str, timestamp: u64, yaml: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let require_explicit = std::env::var("AGENTCONTROL_MANAGED_MODE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let secret = match resolve_cache_secret(require_explicit) {
        Ok(s) => s,
        Err(e) => {
            logging::log_event(
                Level::Error,
                "cached_policy_secret_missing",
                serde_json::json!({ "error": e }),
            );
            return String::new();
        }
    };

    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(version_hash.as_bytes());
    mac.update(&timestamp.to_be_bytes());
    mac.update(yaml.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Save validated policy and its cryptographic signature to authenticated local cache
pub fn save_cached_policy(yaml: &str, raw_hash: &str) {
    if let Some(path) = cached_policy_envelope_path() {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let sig = compute_cache_hmac(raw_hash, ts, yaml);
        if sig.is_empty() {
            logging::log_event(
                Level::Error,
                "cached_policy_save_aborted",
                serde_json::json!({ "reason": "HMAC secret unavailable in managed mode" }),
            );
            return;
        }
        let envelope = AuthenticatedPolicyCache {
            schema_version: 1,
            version_hash: raw_hash.to_string(),
            timestamp: ts,
            yaml_content: yaml.to_string(),
            hmac_signature: sig,
        };

        if let Ok(bytes) = serde_json::to_vec_pretty(&envelope) {
            let _ = crate::wrap::journal::write_file_durable(&path, &bytes);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            }
        }
    }
}

/// Load and cryptographically verify cached policy from local disk
pub fn load_cached_policy() -> Option<(String, String)> {
    let path = cached_policy_envelope_path()?;
    if path.exists() {
        if let Ok(data) = std::fs::read(&path) {
            if let Ok(envelope) = serde_json::from_slice::<AuthenticatedPolicyCache>(&data) {
                // 1. Verify content SHA256 matches raw_hash
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(envelope.yaml_content.as_bytes());
                let computed_hash = format!("sha256:{}", hex::encode(hasher.finalize()));
                if envelope.version_hash.trim() != computed_hash
                    && envelope.version_hash.trim() != &computed_hash[7..]
                {
                    logging::log_event(
                        Level::Error,
                        "cached_policy_hash_mismatch",
                        serde_json::json!({
                            "saved_hash": envelope.version_hash,
                            "computed_hash": computed_hash,
                        }),
                    );
                    return None;
                }

                // 2. Verify HMAC cryptographic signature
                let expected_sig = compute_cache_hmac(
                    &envelope.version_hash,
                    envelope.timestamp,
                    &envelope.yaml_content,
                );
                if envelope.hmac_signature == expected_sig {
                    return Some((envelope.yaml_content, computed_hash));
                } else {
                    logging::log_event(
                        Level::Error,
                        "cached_policy_signature_invalid",
                        serde_json::json!({
                            "reason": "HMAC signature mismatch on cached policy envelope",
                        }),
                    );
                    return None;
                }
            }
        }
    }
    None
}

/// Path to local offline cached signed bundle: `~/.agentcontrol/cached_policy_bundle.json`
pub fn cached_policy_bundle_path() -> Option<std::path::PathBuf> {
    dirs::home_dir().map(|h| h.join(".agentcontrol").join("cached_policy_bundle.json"))
}

/// Save cryptographically verified signed bundle to local offline storage
pub fn save_cached_policy_bundle(bundle: &SignedPolicyBundle) {
    if let Some(path) = cached_policy_bundle_path() {
        if let Ok(bytes) = serde_json::to_vec_pretty(bundle) {
            let _ = crate::wrap::journal::write_file_durable(&path, &bytes);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            }
        }
    }
}

/// Load and cryptographically verify cached policy bundle from local disk
pub fn load_cached_policy_bundle(
    trusted_keys: Option<&[String]>,
) -> Option<(SignedPolicyBundle, CompiledPolicy)> {
    let path = cached_policy_bundle_path()?;
    if path.exists() {
        if let Ok(data) = std::fs::read(&path) {
            if let Ok(bundle) = serde_json::from_slice::<SignedPolicyBundle>(&data) {
                match verify_signed_bundle(&bundle, trusted_keys) {
                    Ok(compiled) => return Some((bundle, compiled)),
                    Err(e) => {
                        logging::log_event(
                            Level::Error,
                            "cached_signed_bundle_verification_failed",
                            serde_json::json!({
                                "error": e.to_string(),
                                "policy_id": &bundle.policy_id,
                                "revision": bundle.policy_revision,
                            }),
                        );
                    }
                }
            }
        }
    }
    None
}

/// Persisted state for anti-rollback verification across gateway restarts.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct MonotonicPolicyState {
    pub highest_revision: u64,
    pub last_updated_epoch_secs: u64,
    #[serde(default)]
    pub policy_hash: Option<String>,
}

/// Directory for local agentcontrol state files.
pub fn agentcontrol_state_dir() -> std::path::PathBuf {
    if let Ok(d) = std::env::var("AGENTCONTROL_STATE_DIR") {
        return std::path::PathBuf::from(d);
    }
    dirs::home_dir()
        .map(|h| h.join(".agentcontrol"))
        .unwrap_or_else(|| std::env::temp_dir().join(".agentcontrol"))
}

/// Path to local anti-rollback monotonic state file: `~/.agentcontrol/policy.state`
pub fn policy_state_file_path() -> std::path::PathBuf {
    agentcontrol_state_dir().join("policy.state")
}

/// Load the highest persisted policy revision from disk. Returns 0 if absent or unreadable.
pub fn load_persisted_monotonic_revision() -> u64 {
    let path = policy_state_file_path();
    if !path.exists() {
        return 0;
    }
    if let Ok(bytes) = std::fs::read(&path) {
        if let Ok(state) = serde_json::from_slice::<MonotonicPolicyState>(&bytes) {
            return state.highest_revision;
        }
    }
    0
}

/// Persist an accepted policy revision monotonically to `policy.state`.
/// Fails if `revision` is strictly lower than the currently persisted revision.
pub fn persist_monotonic_revision(
    revision: u64,
    policy_hash: Option<&str>,
) -> Result<(), std::io::Error> {
    let current = load_persisted_monotonic_revision();
    if revision < current {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "Anti-rollback violation: cannot persist revision {} lower than current persisted revision {}",
                revision, current
            ),
        ));
    }
    let path = policy_state_file_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let state = MonotonicPolicyState {
        highest_revision: revision,
        last_updated_epoch_secs: ts,
        policy_hash: policy_hash.map(|s| s.to_string()),
    };
    if let Ok(bytes) = serde_json::to_vec_pretty(&state) {
        let _ = crate::wrap::journal::write_file_durable(&path, &bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
    }
    Ok(())
}

/// Fetch policy from the dashboard API and compile it, applying the active PolicyTrustProfile.
///
/// In `Managed` profile:
/// - Requests a `SignedPolicyBundle` from `/api/v2/device/policy/bundle` or `/api/v1/policy/bundle`
/// - Cryptographically verifies the Ed25519 signature against the configured trusted keyring
/// - Validates anti-rollback revision monotonicity if enabled
/// - On network/API failure, falls back strictly to the verified local signed bundle cache
/// - NEVER accepts raw unsigned YAML in managed mode
///
/// In `Development` profile:
/// - Attempts to fetch and verify a signed bundle if present
/// - Falls back to raw YAML via `fetch_policy_yaml` if no signed bundle is available
pub async fn load_remote_policy_with_trust(
    dashboard_url: &str,
    policy_read_secret: Option<&str>,
    trust_profile: &PolicyTrustProfile,
) -> PolicyLoadResult {
    if trust_profile.is_managed() {
        let trusted_keys = trust_profile.trusted_keys();
        let trusted_keys_slice = trusted_keys.as_deref();

        match fetch_policy_bundle(dashboard_url, policy_read_secret).await {
            Ok(Some(bundle)) => {
                logging::log_event(
                    Level::Info,
                    "policy_bundle_fetch_remote",
                    serde_json::json!({
                        "source": "dashboard_api",
                        "url": dashboard_url,
                        "policy_id": &bundle.policy_id,
                        "revision": bundle.policy_revision,
                        "signer_public_key": &bundle.public_key,
                    }),
                );

                // Verify cryptographic signature and compile
                match verify_signed_bundle(&bundle, trusted_keys_slice) {
                    Ok(compiled) => {
                        // Check monotonicity against persisted disk state
                        if let PolicyTrustProfile::Managed {
                            require_revision_monotonicity: true,
                            ..
                        } = trust_profile
                        {
                            let persisted_rev = load_persisted_monotonic_revision();
                            if bundle.policy_revision < persisted_rev {
                                let err_msg = format!(
                                    "Anti-rollback violation: received policy revision {} is older than persisted revision {}",
                                    bundle.policy_revision, persisted_rev
                                );
                                logging::log_event(
                                    Level::Error,
                                    "policy_rollback_detected",
                                    serde_json::json!({ "error": &err_msg }),
                                );
                                return PolicyLoadResult::Fatal {
                                    error:
                                        crate::policy::loader::PolicyLoadError::VerificationFailed(
                                            err_msg,
                                        ),
                                };
                            }
                        }

                        // Compute raw_hash for telemetry/logging
                        use sha2::{Digest, Sha256};
                        let mut h = Sha256::new();
                        h.update(bundle.policy_yaml.as_bytes());
                        let raw_hash = format!("sha256:{}", hex::encode(h.finalize()));

                        // Persist verified signed bundle, cache, and monotonic revision
                        save_cached_policy_bundle(&bundle);
                        save_cached_policy(&bundle.policy_yaml, &raw_hash);
                        let _ = persist_monotonic_revision(bundle.policy_revision, Some(&raw_hash));

                        PolicyLoadResult::Loaded {
                            policy: compiled,
                            raw_hash,
                            warnings: vec![],
                        }
                    }
                    Err(verify_err) => {
                        let err_msg = format!(
                            "Cryptographic policy bundle verification failed: {}",
                            verify_err
                        );
                        logging::log_event(
                            Level::Error,
                            "policy_bundle_verify_failed",
                            serde_json::json!({ "error": &err_msg, "url": dashboard_url }),
                        );

                        // Try to recover from cached signed bundle
                        if let Some((cached_bundle, cached_compiled)) =
                            load_cached_policy_bundle(trusted_keys_slice)
                        {
                            eprintln!(
                                "{} [POLICY:OFFLINE_CACHE_ACTIVE] Verification failed for remote bundle; activating verified cached bundle (rev {})",
                                colored::Colorize::yellow("⚠").bold(),
                                cached_bundle.policy_revision
                            );
                            let raw_hash = format!("rev:{}", cached_bundle.policy_revision);
                            return PolicyLoadResult::Loaded {
                                policy: cached_compiled,
                                raw_hash,
                                warnings: vec![format!(
                                    "Remote bundle verification failed: {}. Falling back to cached signed bundle.",
                                    verify_err
                                )],
                            };
                        }

                        // NEVER fallback to raw unsigned YAML in managed mode
                        PolicyLoadResult::Fatal {
                            error: crate::policy::loader::PolicyLoadError::VerificationFailed(
                                err_msg,
                            ),
                        }
                    }
                }
            }
            Ok(None) => {
                logging::log_event(
                    Level::Warn,
                    "policy_bundle_fetch_remote_empty",
                    serde_json::json!({
                        "source": "dashboard_api",
                        "reason": "No active policy bundle in DB — checking cache"
                    }),
                );
                // In managed mode, check cached signed bundle
                if let Some((cached_bundle, cached_compiled)) =
                    load_cached_policy_bundle(trusted_keys_slice)
                {
                    let raw_hash = format!("rev:{}", cached_bundle.policy_revision);
                    return PolicyLoadResult::Loaded {
                        policy: cached_compiled,
                        raw_hash,
                        warnings: vec![
                            "No active remote policy bundle; using verified cached bundle."
                                .to_string(),
                        ],
                    };
                }
                PolicyLoadResult::Degraded {
                    reason: "No active policy bundle found in dashboard database".to_string(),
                }
            }
            Err(e) => {
                logging::log_event(
                    Level::Error,
                    "policy_bundle_fetch_remote_failed",
                    serde_json::json!({ "error": &e }),
                );
                // Check offline cached signed bundle
                if let Some((cached_bundle, cached_compiled)) =
                    load_cached_policy_bundle(trusted_keys_slice)
                {
                    eprintln!(
                        "{} [POLICY:OFFLINE_CACHE_ACTIVE] Dashboard API unreachable; using verified cached bundle (rev {})",
                        colored::Colorize::yellow("⚠").bold(),
                        cached_bundle.policy_revision
                    );
                    let raw_hash = format!("rev:{}", cached_bundle.policy_revision);
                    return PolicyLoadResult::Loaded {
                        policy: cached_compiled,
                        raw_hash,
                        warnings: vec![format!(
                            "Dashboard API unreachable ({}). Using cached signed bundle.",
                            e
                        )],
                    };
                }
                PolicyLoadResult::Degraded { reason: e }
            }
        }
    } else {
        // Development profile: try bundle first, then fall back to raw YAML
        if let Ok(Some(bundle)) = fetch_policy_bundle(dashboard_url, policy_read_secret).await {
            // Verify signature without key restrictions in dev mode
            if let Ok(compiled) = verify_signed_bundle(&bundle, None) {
                use sha2::{Digest, Sha256};
                let mut h = Sha256::new();
                h.update(bundle.policy_yaml.as_bytes());
                let raw_hash = format!("sha256:{}", hex::encode(h.finalize()));
                save_cached_policy_bundle(&bundle);
                save_cached_policy(&bundle.policy_yaml, &raw_hash);
                return PolicyLoadResult::Loaded {
                    policy: compiled,
                    raw_hash,
                    warnings: vec![],
                };
            }
        }

        // Fallback to raw YAML in development mode
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
                let res = load_policy_from_str(&yaml, None);
                if let PolicyLoadResult::Loaded { ref raw_hash, .. } = res {
                    save_cached_policy(&yaml, raw_hash);
                }
                res
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
                if let Some((cached_yaml, cached_hash)) = load_cached_policy() {
                    eprintln!(
                        "{} [POLICY:OFFLINE_CACHE_ACTIVE] Using verified cached policy ({})",
                        colored::Colorize::yellow("⚠").bold(),
                        colored::Colorize::cyan(cached_hash.as_str())
                    );
                    logging::log_event(
                        Level::Warn,
                        "policy_offline_cache_activated",
                        serde_json::json!({
                            "hash": cached_hash,
                            "fallback_reason": e,
                        }),
                    );
                    return load_policy_from_str(&cached_yaml, None);
                }
                PolicyLoadResult::Degraded { reason: e }
            }
        }
    }
}

/// Fetch policy from the dashboard API and compile it using default or environment PolicyTrustProfile.
pub async fn load_remote_policy(
    dashboard_url: &str,
    policy_read_secret: Option<&str>,
) -> PolicyLoadResult {
    let trust_profile = PolicyTrustProfile::from_env();
    load_remote_policy_with_trust(dashboard_url, policy_read_secret, &trust_profile).await
}

/// Background polling task. Runs indefinitely, waking every `interval_secs`
/// seconds to check whether the policy version has changed.
///
/// In Managed mode: polls signed bundles and verifies cryptographic signatures against keyring.
/// In Development mode: polls raw YAML or bundles and hot-swaps on change.
pub async fn start_policy_poll(
    state: std::sync::Arc<crate::proxy::handler::ProxyState>,
    dashboard_url: String,
    policy_read_secret: Option<String>,
    interval_secs: u64,
) {
    let mut last_version: Option<String> = None;
    let mut last_revision: u64 = 0;

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;

        if state.policy_trust_profile.is_managed() {
            let trusted_keys = state.policy_trust_profile.trusted_keys();
            let bundle_result =
                fetch_policy_bundle(&dashboard_url, policy_read_secret.as_deref()).await;

            let bundle = match bundle_result {
                Ok(Some(b)) => b,
                Ok(None) => continue,
                Err(e) => {
                    logging::log_event(
                        Level::Warn,
                        "policy_poll_bundle_fetch_failed",
                        serde_json::json!({ "error": &e }),
                    );
                    continue;
                }
            };

            // Quick check if revision is unchanged
            if bundle.policy_revision == last_revision && last_version.is_some() {
                continue;
            }

            // Monotonicity check against persisted disk state and memory
            if let PolicyTrustProfile::Managed {
                require_revision_monotonicity: true,
                ..
            } = state.policy_trust_profile
            {
                let persisted_rev = load_persisted_monotonic_revision().max(last_revision);
                if bundle.policy_revision < persisted_rev {
                    logging::log_event(
                        Level::Error,
                        "policy_poll_rollback_rejected",
                        serde_json::json!({
                            "persisted_revision": persisted_rev,
                            "received_revision": bundle.policy_revision,
                        }),
                    );
                    continue;
                }
            }

            // Verify signature against keyring
            match verify_signed_bundle(&bundle, trusted_keys.as_deref()) {
                Ok(compiled) => {
                    let _ = persist_monotonic_revision(
                        bundle.policy_revision,
                        Some(&bundle.policy_yaml),
                    );
                    state.update_policy(Some(compiled));
                    last_revision = bundle.policy_revision;
                    last_version = Some(format!("rev:{}", bundle.policy_revision));

                    save_cached_policy_bundle(&bundle);

                    logging::log_event(
                        Level::Info,
                        "policy_reloaded_remote_bundle",
                        serde_json::json!({
                            "policy_id": &bundle.policy_id,
                            "revision": bundle.policy_revision,
                            "signer": &bundle.public_key,
                        }),
                    );

                    let _ = state.event_tx.send(format!(
                        "event: policy_reloaded\ndata: {{\"revision\":{}}}\n\n",
                        bundle.policy_revision
                    ));
                }
                Err(e) => {
                    logging::log_event(
                        Level::Error,
                        "policy_poll_verify_failed",
                        serde_json::json!({ "error": e.to_string() }),
                    );
                }
            }
        } else {
            // Development mode: try bundle, then fall back to raw YAML
            let yaml_result =
                fetch_policy_yaml(&dashboard_url, policy_read_secret.as_deref()).await;

            let yaml = match yaml_result {
                Ok(Some(y)) => y,
                Ok(None) => continue,
                Err(e) => {
                    logging::log_event(
                        Level::Warn,
                        "policy_poll_fetch_failed",
                        serde_json::json!({ "error": &e }),
                    );
                    continue;
                }
            };

            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(yaml.as_bytes());
            let version_hash = format!("sha256:{}", hex::encode(h.finalize()));

            if last_version.as_deref() == Some(&version_hash) {
                continue;
            }

            let reload_start = std::time::Instant::now();
            let result = tokio::task::spawn_blocking({
                let yaml_clone = yaml.clone();
                move || load_policy_from_str(&yaml_clone, None)
            })
            .await;

            match result {
                Ok(PolicyLoadResult::Loaded {
                    policy,
                    raw_hash,
                    warnings,
                }) => {
                    state.update_policy(Some(policy));
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

                    let _ = state.event_tx.send(format!(
                        "event: policy_reloaded\ndata: {{\"hash\":\"{}\"}}\n\n",
                        raw_hash
                    ));
                }
                Ok(PolicyLoadResult::Fatal { error }) => {
                    logging::log_event(
                        Level::Error,
                        "policy_poll_compile_failed",
                        serde_json::json!({ "error": error.to_string() }),
                    );
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
}
