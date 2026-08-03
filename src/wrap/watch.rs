//! `agentwall watch` — event-driven daemon that auto-wraps MCP server entries.
//!
//! ## Design decisions
//!
//! - **Watch the parent directory, not the file path.** `atomic_write()` in
//!   `generic_ide.rs` replaces the config file via a temp-file + `fs::rename`.
//!   On some OS/backend combinations, watching a specific inode silently stops
//!   receiving events after the first rename (the original inode is gone).
//!   Watching the parent directory and filtering events to the exact filename
//!   avoids this entirely.
//!
//! - **Call `wrap_generic` / `wrap_claude` directly** (not `run_wrap_target`).
//!   The `run_wrap_target` path is CLI-exit-code-oriented (prints summaries,
//!   returns `i32`). The daemon needs the `Result<WrapResult, WrapError>`
//!   directly so it can distinguish `AlreadyWrapped` (no-op, debug only) from
//!   real failures without spamming stderr on every self-triggered check.
//!
//! - **Self-write filtering via SHA-256.** After each daemon-triggered wrap the
//!   hash of the written content is stored. On the next event the file is
//!   re-hashed: if it matches the last own hash the event is suppressed.
//!   Additionally, `.agentwall-tmp` and `agentwall-backup-*` filenames are
//!   always suppressed regardless of hash.
//!
//! - **300ms debounce.** Editors (and `atomic_write` itself) often emit multiple
//!   rapid events for a single logical write. We wait until no new event arrives
//!   for 300ms before acting.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use colored::*;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

use super::{claude, config_path, generic_ide, WrapError};
use crate::cli::WatchTarget;

// ─── Constants ────────────────────────────────────────────────────────────────

/// Debounce window: wait this long after the last event before acting.
const DEBOUNCE_MS: u64 = 300;

/// Targets that have verified, correct config paths.
/// All others are known-wrong or hypothetical guesses.
const VERIFIED_TARGETS: &[VerifiedTarget] = &[VerifiedTarget::Claude];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerifiedTarget {
    Claude,
}

// ─── Public entry point ────────────────────────────────────────────────────────

/// Run the watch daemon.
///
/// `all` — if true, watch only the single verified target (Claude Desktop).
/// `target` — if Some, watch that specific target (may be unverified).
///
/// Returns 0 on clean shutdown (Ctrl-C), non-zero on startup error.
pub fn run_watch(all: bool, target: Option<WatchTarget>) -> i32 {
    // Resolve the set of (name, path, is_verified, claude_flags) to watch.
    let active = match resolve_active_targets(all, target) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("{} {}", "✖".red(), msg);
            return 1;
        }
    };

    if active.is_empty() {
        eprintln!(
            "{} No targets selected. Use --all to watch verified targets, \
             or specify a target subcommand (e.g. agentwall watch claude).",
            "✖".red()
        );
        return 1;
    }

    // Print startup information.
    println!();
    println!(
        "{} {}",
        "●".green().bold(),
        "AgentWall Watch — daemon starting".bold().white()
    );
    println!("{}", "─".repeat(70).dimmed());
    for at in &active {
        let verified_label = if at.verified {
            "[verified]".green().to_string()
        } else {
            "[unverified]".yellow().bold().to_string()
        };
        println!(
            "  {} {} {}  {}",
            "→".dimmed(),
            at.name.cyan(),
            verified_label,
            at.config_path.display().to_string().dimmed()
        );
    }
    println!("{}", "─".repeat(70).dimmed());
    println!(
        "  {} IDEs load mcpServers at startup. After each auto-wrap, {}.",
        "ℹ".blue(),
        "restart the IDE to apply changes".yellow()
    );
    println!("  {} Press {} to stop.", "ℹ".blue(), "Ctrl-C".bold());
    println!();

    // Set up per-target last-own-hash store (suppresses self-write re-triggers).
    // Key: canonical config path string.
    let own_hashes: Arc<Mutex<HashMap<String, [u8; 32]>>> = Arc::new(Mutex::new(HashMap::new()));

    // Channel for FS events from notify.
    let (tx, rx) = std::sync::mpsc::channel::<Result<Event, notify::Error>>();

    // Create a single watcher and register each target's *parent directory*.
    let mut watcher = match RecommendedWatcher::new(tx, notify::Config::default()) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("{} Failed to create filesystem watcher: {}", "✖".red(), e);
            return 1;
        }
    };

    // Map: canonical parent-dir path → list of (config_path, active_target_index)
    // Multiple targets could share a parent dir (unlikely but handled).
    let mut dir_to_targets: HashMap<PathBuf, Vec<usize>> = HashMap::new();
    for (i, at) in active.iter().enumerate() {
        let parent = match at.config_path.parent() {
            Some(p) => p.to_path_buf(),
            None => {
                eprintln!(
                    "{} Cannot determine parent directory for {}: {}",
                    "⚠".yellow(),
                    at.name,
                    at.config_path.display()
                );
                continue;
            }
        };
        // Create the directory if it doesn't exist yet (so watch registration
        // works even before the IDE first creates its config file).
        if !parent.exists() {
            if let Err(e) = std::fs::create_dir_all(&parent) {
                eprintln!(
                    "{} Cannot create parent dir {} for {}: {}",
                    "⚠".yellow(),
                    parent.display(),
                    at.name,
                    e
                );
            }
        }
        if let Err(e) = watcher.watch(&parent, RecursiveMode::NonRecursive) {
            eprintln!(
                "{} Cannot watch directory {} for {}: {}",
                "⚠".yellow(),
                parent.display(),
                at.name,
                e
            );
        }
        dir_to_targets.entry(parent).or_default().push(i);
    }

    // Set up Ctrl-C handler.
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let stop_clone = Arc::clone(&stop);
        if let Err(e) = ctrlc::set_handler(move || {
            stop_clone.store(true, std::sync::atomic::Ordering::SeqCst);
        }) {
            eprintln!(
                "{} Failed to install Ctrl-C handler: {}. Kill the process manually.",
                "⚠".yellow(),
                e
            );
        }
    }

    // Debounce state: config_path_string → (last_event_instant, pending)
    let mut debounce: HashMap<String, Instant> = HashMap::new();

    println!(
        "{} Daemon running — waiting for config changes…",
        "●".green()
    );

    loop {
        if stop.load(std::sync::atomic::Ordering::SeqCst) {
            println!("\n{} Received Ctrl-C — shutting down.", "●".yellow());
            break;
        }

        // Non-blocking receive with 50ms timeout so we can poll the stop flag.
        let event_result = rx.recv_timeout(Duration::from_millis(50));
        let now = Instant::now();

        match event_result {
            Ok(Ok(event)) => {
                handle_event(
                    &event,
                    &active,
                    &dir_to_targets,
                    &own_hashes,
                    &mut debounce,
                    now,
                );
            }
            Ok(Err(e)) => {
                eprintln!("{} Watcher error: {}", "⚠".yellow(), e);
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                // No event — fall through to debounce flush below.
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                eprintln!("{} Watcher channel closed unexpectedly.", "⚠".yellow());
                return 1;
            }
        }

        // Flush any debounced entries that have expired.
        flush_debounce(&mut debounce, &active, &own_hashes, now);
    }

    0
}

// ─── Internal types ────────────────────────────────────────────────────────────

/// Everything the daemon needs to know about one watched target.
#[derive(Debug, Clone)]
struct ActiveTarget {
    name: &'static str,
    config_path: PathBuf,
    verified: bool,
    /// Claude-specific flags (None for generic targets).
    claude_flags: Option<ClaudeFlags>,
}

#[derive(Debug, Clone)]
struct ClaudeFlags {
    scan_responses: bool,
    #[allow(dead_code)]
    block_on_secrets: bool,
}

// ─── Target resolution ────────────────────────────────────────────────────────

fn resolve_active_targets(
    all: bool,
    target: Option<WatchTarget>,
) -> Result<Vec<ActiveTarget>, String> {
    match (all, target) {
        // Explicit target always wins over --all.
        (_, Some(t)) => resolve_single_target(t),
        // --all: only verified targets.
        (true, None) => resolve_all_verified(),
        // Neither: error — caller will print usage.
        (false, None) => Ok(vec![]),
    }
}

fn resolve_all_verified() -> Result<Vec<ActiveTarget>, String> {
    // Only VERIFIED_TARGETS are included. Currently just Claude.
    let _ = VERIFIED_TARGETS; // suppress unused warning
    let path = config_path::claude_config_path()
        .map_err(|e| format!("Cannot resolve Claude Desktop config path: {}", e))?;
    Ok(vec![ActiveTarget {
        name: "Claude Desktop",
        config_path: path,
        verified: true,
        claude_flags: Some(ClaudeFlags {
            scan_responses: false,
            block_on_secrets: false,
        }),
    }])
}

fn resolve_single_target(target: WatchTarget) -> Result<Vec<ActiveTarget>, String> {
    match target {
        WatchTarget::Claude {
            scan_responses,
            block_on_secrets,
        } => {
            let path = config_path::claude_config_path()
                .map_err(|e| format!("Cannot resolve Claude Desktop config path: {}", e))?;
            Ok(vec![ActiveTarget {
                name: "Claude Desktop",
                config_path: path,
                verified: true,
                claude_flags: Some(ClaudeFlags {
                    scan_responses,
                    block_on_secrets,
                }),
            }])
        }
        WatchTarget::Cursor => make_unverified("Cursor", config_path::cursor_config_path()),
        WatchTarget::Vscode => make_unverified("VS Code", config_path::vscode_config_path()),
        WatchTarget::Jetbrains => {
            make_unverified("JetBrains", config_path::jetbrains_config_path())
        }
        WatchTarget::Zed => make_unverified("Zed", config_path::zed_config_path()),
        WatchTarget::Cline => make_unverified("Cline", config_path::cline_config_path()),
        WatchTarget::Opencode => make_unverified("OpenCode", config_path::opencode_config_path()),
        WatchTarget::Antigravity => {
            make_unverified("Antigravity", config_path::antigravity_config_path())
        }
    }
}

fn make_unverified(
    name: &'static str,
    result: Result<PathBuf, WrapError>,
) -> Result<Vec<ActiveTarget>, String> {
    eprintln!(
        "{} {} path is unverified — this may be watching the wrong file.",
        "⚠".yellow().bold(),
        name
    );
    let path = result.map_err(|e| format!("Cannot resolve {} config path: {}", name, e))?;
    Ok(vec![ActiveTarget {
        name,
        config_path: path,
        verified: false,
        claude_flags: None,
    }])
}

// ─── Event handling ────────────────────────────────────────────────────────────

fn handle_event(
    event: &Event,
    active: &[ActiveTarget],
    dir_to_targets: &HashMap<PathBuf, Vec<usize>>,
    own_hashes: &Arc<Mutex<HashMap<String, [u8; 32]>>>,
    debounce: &mut HashMap<String, Instant>,
    now: Instant,
) {
    // Only care about create/modify/rename events (not access/metadata).
    match event.kind {
        EventKind::Create(_) | EventKind::Modify(_) => {}
        // `atomic_write` ends with rename — surfaces as a Rename(To) or
        // as a Remove+Create pair on some platforms. Treat all of them.
        EventKind::Remove(_) => {}
        _ => return,
    }

    for path in &event.paths {
        // Always suppress agentwall's own temp/backup files.
        let filename = match path.file_name().and_then(|f| f.to_str()) {
            Some(f) => f,
            None => continue,
        };
        if filename.ends_with(".agentwall-tmp") || filename.contains("agentwall-backup-") {
            continue;
        }

        // Find which active target(s) this path matches.
        let parent = match path.parent() {
            Some(p) => p.to_path_buf(),
            None => continue,
        };
        let indices = match dir_to_targets.get(&parent) {
            Some(v) => v,
            None => continue,
        };

        for &idx in indices {
            let at = &active[idx];
            // Must match the exact config filename.
            if path != &at.config_path {
                continue;
            }

            let key = at.config_path.display().to_string();

            // Self-write check: if current file hash matches our last write, suppress.
            if path.exists() {
                if let Ok(contents) = std::fs::read(path) {
                    let hash = sha256(&contents);
                    let guard = own_hashes.lock().unwrap();
                    if guard.get(&key) == Some(&hash) {
                        continue;
                    }
                }
            }

            // Arm or reset debounce timer.
            debounce.insert(key, now);
        }
    }
}

// ─── Debounce flush ───────────────────────────────────────────────────────────

/// Check all pending debounce entries and fire any that have expired.
fn flush_debounce(
    debounce: &mut HashMap<String, Instant>,
    active: &[ActiveTarget],
    own_hashes: &Arc<Mutex<HashMap<String, [u8; 32]>>>,
    now: Instant,
) {
    let window = Duration::from_millis(DEBOUNCE_MS);
    let fired: Vec<String> = debounce
        .iter()
        .filter(|(_, t)| now.duration_since(**t) >= window)
        .map(|(k, _)| k.clone())
        .collect();

    for key in fired {
        debounce.remove(&key);

        // Find the matching active target.
        let at = match active
            .iter()
            .find(|t| t.config_path.display().to_string() == key)
        {
            Some(t) => t,
            None => continue,
        };

        do_wrap(at, own_hashes);
    }
}

// ─── Wrap dispatch ────────────────────────────────────────────────────────────

fn do_wrap(at: &ActiveTarget, own_hashes: &Arc<Mutex<HashMap<String, [u8; 32]>>>) {
    let config_path = &at.config_path;

    // JSON-validate before calling wrap (skip mid-write partial files).
    if config_path.exists() {
        match std::fs::read_to_string(config_path) {
            Err(_e) => {
                return;
            }
            Ok(raw) => {
                if serde_json::from_str::<serde_json::Value>(&raw).is_err() {
                    return;
                }
            }
        }
    } else {
        return;
    }

    let wrap_result = if let Some(flags) = &at.claude_flags {
        // Call wrap_claude directly (returns Result<WrapResult, WrapError>).
        claude::wrap_claude(false, flags.scan_responses)
    } else {
        // Generic IDE: call wrap_generic directly.
        generic_ide::wrap_generic(at.name, config_path.clone(), false)
    };

    match wrap_result {
        Ok(result) => {
            println!(
                "{} [watch] Wrapped {} MCP server(s) in {} — restart {} to apply.",
                "✔".green().bold(),
                result.servers_wrapped,
                at.name.cyan(),
                at.name
            );

            // Record the hash of what we just wrote so the next event is suppressed.
            if let Ok(written) = std::fs::read(&result.config_path) {
                let hash = sha256(&written);
                let key = result.config_path.display().to_string();
                own_hashes.lock().unwrap().insert(key, hash);
            }

            super::status::gather_and_send_mcp_servers_snapshot();
        }
        Err(WrapError::AlreadyWrapped) => {
            // No-op (all servers already protected)
        }
        Err(WrapError::NoMcpServers) => {
            // No mcpServers in config, nothing to wrap
        }
        Err(e) => {
            eprintln!("{} [watch] Error wrapping {}: {}", "✖".red(), at.name, e);
        }
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}
