//! Structured cross-platform file and stderr JSON logging — exact event names per PRD §5.4

use chrono::Utc;
use serde_json::json;
use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

static SPEND_ONLY: AtomicBool = AtomicBool::new(false);
static FILE_LOGGING_ENABLED: AtomicBool = AtomicBool::new(true);

const MAX_LOG_FILE_SIZE_BYTES: u64 = 10 * 1024 * 1024; // 10 MB
const MAX_ARCHIVED_LOG_FILES: usize = 5;
const MAX_BUFFERED_ERRORS: usize = 500;

static LOG_FILE_MUTEX: Mutex<()> = Mutex::new(());
static CLIENT_ERROR_BUFFER: Mutex<Option<VecDeque<serde_json::Value>>> = Mutex::new(None);


/// Enable or disable spend-only logging mode
pub fn set_spend_only(enabled: bool) {
    SPEND_ONLY.store(enabled, Ordering::Relaxed);
}

/// Check if spend-only logging mode is active
pub fn is_spend_only() -> bool {
    SPEND_ONLY.load(Ordering::Relaxed)
}

/// Enable or disable writing logs to persistent disk file
pub fn set_file_logging(enabled: bool) {
    FILE_LOGGING_ENABLED.store(enabled, Ordering::Relaxed);
}

/// Check if file logging is active
pub fn is_file_logging() -> bool {
    FILE_LOGGING_ENABLED.load(Ordering::Relaxed)
}

/// Resolves the standard OS-specific log directory according to platform standards.
/// - Windows: `%LOCALAPPDATA%\AgentControl\logs` (or `%USERPROFILE%\.agentcontrol\logs`)
/// - macOS: `~/Library/Logs/AgentControl`
/// - Linux: `~/.local/state/agentcontrol/logs` (or `~/.agentcontrol/logs`)
pub fn get_log_dir() -> PathBuf {
    if let Ok(override_dir) = std::env::var("AGENTCONTROL_LOG_DIR") {
        if !override_dir.trim().is_empty() {
            return PathBuf::from(override_dir.trim());
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Some(local_app_data) = dirs::data_local_dir() {
            return local_app_data.join("AgentControl").join("logs");
        }
        if let Some(home) = dirs::home_dir() {
            return home.join(".agentcontrol").join("logs");
        }
        PathBuf::from(r"C:\ProgramData\AgentControl\logs")
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(home) = dirs::home_dir() {
            return home.join("Library").join("Logs").join("AgentControl");
        }
        PathBuf::from("/Library/Logs/AgentControl")
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        if let Some(home) = dirs::home_dir() {
            return home.join(".local").join("state").join("agentcontrol").join("logs");
        }
        PathBuf::from("/var/log/agentcontrol")
    }
}

/// Resolves the default persistent log file path (`agentcontrol.jsonl`)
pub fn get_log_file_path() -> PathBuf {
    get_log_dir().join("agentcontrol.jsonl")
}

/// Log levels matching PRD spec
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Debug,
    Info,
    Warn,
    Error,
}

impl Level {
    /// Returns the static string representation (`"debug"`, `"info"`, `"warn"`, `"error"`) of the log level.
    pub fn as_str(&self) -> &'static str {
        match self {
            Level::Debug => "debug",
            Level::Info => "info",
            Level::Warn => "warn",
            Level::Error => "error",
        }
    }
}

/// Recursively scrubs sensitive API keys, Authorization headers, and Bearer tokens.
pub fn sanitize_log_value(val: &serde_json::Value) -> serde_json::Value {
    match val {
        serde_json::Value::String(s) => {
            serde_json::Value::String(sanitize_secret_string(s))
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(sanitize_log_value).collect())
        }
        serde_json::Value::Object(map) => {
            let mut cleaned = serde_json::Map::new();
            for (k, v) in map {
                let lower_k = k.to_ascii_lowercase();
                if lower_k.contains("authorization")
                    || lower_k.contains("api_key")
                    || lower_k.contains("apikey")
                    || lower_k.contains("secret")
                    || lower_k.contains("token")
                    || lower_k == "master_key"
                {
                    if let serde_json::Value::String(str_val) = v {
                        cleaned.insert(k.clone(), serde_json::Value::String(mask_secret(str_val)));
                    } else {
                        cleaned.insert(k.clone(), sanitize_log_value(v));
                    }
                } else {
                    cleaned.insert(k.clone(), sanitize_log_value(v));
                }
            }
            serde_json::Value::Object(cleaned)
        }
        _ => val.clone(),
    }
}

fn mask_secret(s: &str) -> String {
    if s.len() <= 8 {
        "[REDACTED]".to_string()
    } else {
        format!("{}[REDACTED]{}", &s[..4], &s[s.len() - 4..])
    }
}

fn sanitize_secret_string(s: &str) -> String {
    // Mask Bearer tokens
    if s.contains("Bearer ") {
        let parts: Vec<&str> = s.split("Bearer ").collect();
        let mut out = parts[0].to_string();
        for p in &parts[1..] {
            let token_end = p.find(|c: char| c.is_whitespace() || c == '"' || c == ',' || c == '\'').unwrap_or(p.len());
            let token = &p[..token_end];
            let rest = &p[token_end..];
            out.push_str("Bearer ");
            out.push_str(&mask_secret(token));
            out.push_str(rest);
        }
        return out;
    }
    // Mask sk- keys
    if s.starts_with("sk-") || s.starts_with("sk_") || s.starts_with("vex_") || s.starts_with("ghp_") {
        return mask_secret(s);
    }
    s.to_string()
}

/// Rotate log file if it exceeds MAX_LOG_FILE_SIZE_BYTES
fn rotate_log_file_if_needed(file_path: &Path) {
    if let Ok(metadata) = fs::metadata(file_path) {
        if metadata.len() >= MAX_LOG_FILE_SIZE_BYTES {
            let parent = file_path.parent().unwrap_or_else(|| Path::new("."));
            let timestamp = Utc::now().format("%Y%m%d-%H%M%S");
            let archived_name = format!("agentcontrol.{}.jsonl", timestamp);
            let archived_path = parent.join(archived_name);
            let _ = fs::rename(file_path, archived_path);

            // Cleanup old archived log files beyond MAX_ARCHIVED_LOG_FILES
            if let Ok(entries) = fs::read_dir(parent) {
                let mut log_files: Vec<PathBuf> = entries
                    .filter_map(|e| e.ok().map(|ent| ent.path()))
                    .filter(|p| {
                        p.file_name()
                            .and_then(|n| n.to_str())
                            .map(|s| s.starts_with("agentcontrol.") && s.ends_with(".jsonl") && s != "agentcontrol.jsonl")
                            .unwrap_or(false)
                    })
                    .collect();

                log_files.sort();
                if log_files.len() > MAX_ARCHIVED_LOG_FILES {
                    for old_file in &log_files[..log_files.len() - MAX_ARCHIVED_LOG_FILES] {
                        let _ = fs::remove_file(old_file);
                    }
                }
            }
        }
    }
}


/// Append a sanitized line to the local disk log file
fn write_to_log_file(line: &str) {
    if !is_file_logging() {
        return;
    }

    let file_path = get_log_file_path();
    let _guard = LOG_FILE_MUTEX.lock();

    if let Some(parent) = file_path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    rotate_log_file_if_needed(&file_path);

    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&file_path) {
        let _ = writeln!(file, "{}", line);
    }
}

/// Buffers warning/error logs for asynchronous remote shipping to the Control Plane Hub
fn buffer_error_for_shipping(log_obj: serde_json::Value) {
    if let Ok(mut buf_guard) = CLIENT_ERROR_BUFFER.lock() {
        let buffer = buf_guard.get_or_insert_with(|| VecDeque::with_capacity(MAX_BUFFERED_ERRORS));
        if buffer.len() >= MAX_BUFFERED_ERRORS {
            buffer.pop_front();
        }
        buffer.push_back(log_obj);
    }
}

/// Drains all buffered error events for batch transmission to the Control Plane
pub fn drain_client_error_buffer() -> Vec<serde_json::Value> {
    if let Ok(mut buf_guard) = CLIENT_ERROR_BUFFER.lock() {
        if let Some(buffer) = buf_guard.as_mut() {
            return buffer.drain(..).collect();
        }
    }
    Vec::new()
}

/// Emit a structured JSON log line to both stderr and the persistent disk file.
/// All fields are merged into the top-level object alongside ts, level, event.
pub fn log_event(level: Level, event: &str, fields: serde_json::Value) {
    if matches!(level, Level::Debug) {
        let debug_enabled = std::env::var("RUST_LOG")
            .map(|v| {
                let s = v.to_ascii_lowercase();
                s.contains("debug") || s.contains("trace")
            })
            .unwrap_or(false)
            || std::env::var("AGENTCONTROL_DEBUG")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
        if !debug_enabled {
            return;
        }
    }

    if is_spend_only() {
        // Only emit spend-related events when spend-only mode is enabled, except critical errors
        let is_spend_event = event == "mitm_llm_spend_captured"
            || event == "spend_limit_exceeded"
            || event == "spend_cap_warning"
            || event == "budget_exhausted"
            || matches!(level, Level::Error);
        if !is_spend_event {
            return;
        }
    }

    let sanitized_fields = sanitize_log_value(&fields);
    let mut obj = match sanitized_fields {
        serde_json::Value::Object(map) => map,
        _ => serde_json::Map::new(),
    };
    obj.insert("ts".to_string(), json!(Utc::now().to_rfc3339()));
    obj.insert("level".to_string(), json!(level.as_str()));
    obj.insert("event".to_string(), json!(event));

    // Ensure deterministic key order: ts, level, event first, then rest
    let ordered = json!({
        "ts": obj.remove("ts").unwrap(),
        "level": obj.remove("level").unwrap(),
        "event": obj.remove("event").unwrap(),
    });

    let mut final_obj = match ordered {
        serde_json::Value::Object(map) => map,
        _ => unreachable!(),
    };
    for (k, v) in obj {
        final_obj.insert(k, v);
    }

    let final_val = serde_json::Value::Object(final_obj);
    let line = serde_json::to_string(&final_val).unwrap_or_else(|_| "{}".to_string());

    // 1. Output to interactive terminal (stderr)
    let _ = writeln!(std::io::stderr(), "{}", line);

    // 2. Output to persistent rotating disk log file
    write_to_log_file(&line);

    // 3. Buffer errors and warnings for remote control plane ingestion
    if matches!(level, Level::Warn | Level::Error) {
        buffer_error_for_shipping(final_val);
    }
}

// Convenience macros
#[macro_export]
macro_rules! log_info {
    ($event:expr, $($fields:tt)*) => {
        $crate::logging::log_event($crate::logging::Level::Info, $event, serde_json::json!({$($fields)*}))
    };
}

#[macro_export]
macro_rules! log_warn {
    ($event:expr, $($fields:tt)*) => {
        $crate::logging::log_event($crate::logging::Level::Warn, $event, serde_json::json!({$($fields)*}))
    };
}

#[macro_export]
macro_rules! log_error {
    ($event:expr, $($fields:tt)*) => {
        $crate::logging::log_event($crate::logging::Level::Error, $event, serde_json::json!({$($fields)*}))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spend_only_mode_and_filtering() {
        set_spend_only(false);
        assert!(!is_spend_only());

        set_spend_only(true);
        assert!(is_spend_only());

        // Non-spend event should be filtered out without panic
        log_event(
            Level::Info,
            "firewall_enabled",
            serde_json::json!({"action": "PivotError"}),
        );
        // Spend event should pass
        log_event(
            Level::Info,
            "mitm_llm_spend_captured",
            serde_json::json!({"prompt_tokens": 100}),
        );

        set_spend_only(false);
        assert!(!is_spend_only());
    }

    #[test]
    fn test_log_dir_resolution() {
        let dir = get_log_dir();
        assert!(!dir.as_os_str().is_empty());
        let file_path = get_log_file_path();
        assert!(file_path.ends_with("agentcontrol.jsonl"));
    }

    #[test]
    fn test_secret_sanitization() {
        let input = serde_json::json!({
            "authorization": "Bearer sk-1234567890abcdef",
            "api_key": "sk-secret-key-123456",
            "safe_field": "hello world",
            "nested": {
                "user_token": "token_abc123xyz",
                "normal": 42
            }
        });

        let cleaned = sanitize_log_value(&input);
        let cleaned_str = serde_json::to_string(&cleaned).unwrap();

        assert!(!cleaned_str.contains("sk-1234567890abcdef"));
        assert!(!cleaned_str.contains("sk-secret-key-123456"));
        assert!(cleaned_str.contains("[REDACTED]"));
        assert!(cleaned_str.contains("hello world"));
    }

    #[test]
    fn test_error_buffering_and_drain() {
        log_event(
            Level::Error,
            "stream_disconnected_before_completion",
            serde_json::json!({
                "error_code": "STREAM_CLOSED_PREMATURELY",
                "request_id": "test-req-123"
            }),
        );

        let drained = drain_client_error_buffer();
        assert!(!drained.is_empty());
        let found = drained.iter().any(|item| {
            item.get("event")
                .and_then(|v| v.as_str())
                .map(|e| e == "stream_disconnected_before_completion")
                .unwrap_or(false)
        });
        assert!(found);
    }
}

