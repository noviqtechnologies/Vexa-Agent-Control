//! File-system watcher for the `--policy` YAML file.
//!
//! When the gateway is started with `--policy <path>`, this background task
//! uses the `notify` crate to watch the parent directory for modifications to
//! the specified file and hot-swaps the in-memory policy without any restart.
//!
//! ## Design
//! - Watches the **parent directory** (not the file inode) to survive atomic
//!   editor writes that use temp-file + rename (same pattern as `wrap/watch.rs`).
//! - 300ms debounce window to coalesce rapid multi-event writes.
//! - SHA-256 hash comparison to skip redundant reloads when file content is
//!   unchanged (e.g. editor auto-saves with no edits).
//! - Uses `load_policy()` for validation before swapping — an invalid policy
//!   file does NOT replace the last known-good in-memory policy.
//! - Last-write-wins: concurrent updates from SSE (control plane push) and
//!   the file watcher both apply immediately; whichever arrives last takes effect.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

use crate::logging::{self, Level};
use crate::policy::loader::{load_policy, PolicyLoadResult};

/// Debounce window — wait this long after the last FS event before reloading.
const DEBOUNCE_MS: u64 = 300;

/// Spawn a background file-system watcher that hot-reloads `policy_path` into
/// `state.policy` whenever the file changes on disk.
///
/// Returns immediately; the watcher runs in a background `tokio::task`.
pub fn start_policy_file_watcher(
    policy_path: String,
    state: Arc<crate::proxy::handler::ProxyState>,
) {
    tokio::spawn(async move {
        run_watcher(policy_path, state).await;
    });
}

async fn run_watcher(policy_path: String, state: Arc<crate::proxy::handler::ProxyState>) {
    let path = PathBuf::from(&policy_path);

    let watch_dir = match path.parent() {
        Some(p) if p != Path::new("") => p.to_path_buf(),
        _ => PathBuf::from("."),
    };

    let filename = match path.file_name() {
        Some(n) => n.to_os_string(),
        None => {
            logging::log_event(
                Level::Error,
                "policy_file_watch_error",
                serde_json::json!({
                    "error": "Invalid policy path — cannot extract filename",
                    "path": &policy_path,
                }),
            );
            return;
        }
    };

    // Compute the initial file hash so we skip the first spurious self-trigger.
    let mut last_hash: Option<String> = compute_file_hash(&path);

    // Channel for receiving raw FS events from the notify watcher.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<notify::Result<Event>>(64);

    let mut watcher = match RecommendedWatcher::new(
        move |res| {
            let _ = tx.blocking_send(res);
        },
        notify::Config::default(),
    ) {
        Ok(w) => w,
        Err(e) => {
            logging::log_event(
                Level::Error,
                "policy_file_watch_error",
                serde_json::json!({
                    "error": format!("Failed to create file watcher: {}", e),
                    "path": &policy_path,
                }),
            );
            return;
        }
    };

    if let Err(e) = watcher.watch(&watch_dir, RecursiveMode::NonRecursive) {
        logging::log_event(
            Level::Error,
            "policy_file_watch_error",
            serde_json::json!({
                "error": format!("Failed to watch directory: {}", e),
                "dir": watch_dir.display().to_string(),
            }),
        );
        return;
    }

    logging::log_event(
        Level::Info,
        "policy_file_watch_started",
        serde_json::json!({
            "path": &policy_path,
            "dir": watch_dir.display().to_string(),
        }),
    );

    // Debounce state: record the time of the last relevant event.
    let mut pending_since: Option<Instant> = None;

    loop {
        // Poll with a short timeout so we can fire the debounce when it expires.
        let timeout = match pending_since {
            Some(t) => {
                let elapsed = t.elapsed();
                let debounce = Duration::from_millis(DEBOUNCE_MS);
                if elapsed >= debounce {
                    // Debounce window elapsed — handle immediately.
                    handle_change(&path, &mut last_hash, &state).await;
                    pending_since = None;
                    Duration::from_millis(DEBOUNCE_MS)
                } else {
                    debounce - elapsed
                }
            }
            None => Duration::from_millis(DEBOUNCE_MS),
        };

        match tokio::time::timeout(timeout, rx.recv()).await {
            Ok(Some(Ok(event))) => {
                // Filter to only modify/create/rename events on our target file.
                let is_relevant = matches!(
                    event.kind,
                    EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)
                ) && event.paths.iter().any(|p| {
                    p.file_name() == Some(filename.as_os_str())
                });

                if is_relevant {
                    // Start or reset the debounce window.
                    pending_since = Some(Instant::now());
                }
            }
            Ok(Some(Err(e))) => {
                logging::log_event(
                    Level::Warn,
                    "policy_file_watch_error",
                    serde_json::json!({"error": e.to_string()}),
                );
            }
            Ok(None) => {
                // Channel closed — watcher was dropped. Exit.
                logging::log_event(
                    Level::Warn,
                    "policy_file_watch_stopped",
                    serde_json::json!({"reason": "notify channel closed"}),
                );
                break;
            }
            Err(_) => {
                // Timeout — check debounce expiry (handled at top of loop).
            }
        }
    }
}

/// Hash-check and hot-swap the policy from `path` into `state`.
///
/// Skips compilation when the file content hasn't changed since the last reload.
/// Does NOT replace the in-memory policy if the new file fails to compile —
/// the last known-good policy remains in effect.
async fn handle_change(
    path: &Path,
    last_hash: &mut Option<String>,
    state: &Arc<crate::proxy::handler::ProxyState>,
) {
    let new_hash = compute_file_hash(path);

    // Skip if content is identical to last load (editor auto-save no-op).
    if new_hash.is_some() && new_hash == *last_hash {
        return;
    }

    logging::log_event(
        Level::Info,
        "policy_file_changed",
        serde_json::json!({
            "path": path.display().to_string(),
        }),
    );

    let path_clone = path.to_path_buf();
    let reload_result = tokio::task::spawn_blocking(move || load_policy(&path_clone, None)).await;

    match reload_result {
        Ok(PolicyLoadResult::Loaded {
            policy,
            raw_hash,
            warnings,
        }) => {
            match state.policy.write() {
                Ok(mut guard) => {
                    *guard = Some(policy);
                    state
                        .policy_loaded
                        .store(true, std::sync::atomic::Ordering::SeqCst);
                    // Update our tracked hash only on success.
                    *last_hash = new_hash;

                    logging::log_event(
                        Level::Info,
                        "policy_reloaded_file_watch",
                        serde_json::json!({
                            "path": path.display().to_string(),
                            "hash": &raw_hash,
                            "warnings": &warnings,
                        }),
                    );

                    // Broadcast SSE event so the local dashboard updates live.
                    let sse_event = serde_json::json!({
                        "event": "policy_reloaded",
                        "source": "file_watch",
                        "hash": &raw_hash,
                    });
                    if let Ok(s) = serde_json::to_string(&sse_event) {
                        let _ = state.event_tx.send(s);
                    }
                }
                Err(_) => {
                    logging::log_event(
                        Level::Error,
                        "policy_file_watch_error",
                        serde_json::json!({"error": "Policy RwLock poisoned during file-watch reload"}),
                    );
                }
            }
        }
        Ok(PolicyLoadResult::Degraded { reason }) => {
            // Policy file exists but failed to parse — keep old policy, log warning.
            logging::log_event(
                Level::Warn,
                "policy_file_watch_degraded",
                serde_json::json!({
                    "path": path.display().to_string(),
                    "reason": &reason,
                    "action": "retaining last known-good policy",
                }),
            );
        }
        Ok(PolicyLoadResult::Fatal { error }) => {
            // Hard compile error — keep old policy, log error.
            logging::log_event(
                Level::Error,
                "policy_file_watch_error",
                serde_json::json!({
                    "path": path.display().to_string(),
                    "error": error.to_string(),
                    "action": "retaining last known-good policy",
                }),
            );
        }
        Err(join_err) => {
            logging::log_event(
                Level::Error,
                "policy_file_watch_error",
                serde_json::json!({
                    "error": join_err.to_string(),
                }),
            );
        }
    }
}

/// Compute a SHA-256 hex digest of a file's contents.
/// Returns `None` if the file cannot be read (e.g. mid-write or deleted).
fn compute_file_hash(path: &Path) -> Option<String> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path).ok()?;
    let mut h = Sha256::new();
    h.update(&bytes);
    Some(format!("sha256:{}", hex::encode(h.finalize())))
}
