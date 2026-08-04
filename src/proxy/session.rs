//! Multi-tenant agent session context and isolation manager (FR-101)

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use regex::Regex;
use uuid::Uuid;

use crate::policy::engine::CompiledPolicy;
pub use crate::proxy::handler::ToolCallFingerprint;
use crate::proxy::handler::RateLimiter;

/// Fix 3: Maximum lifetime of an idle session in the DashMap.
/// Sessions older than this are evicted lazily on the next new session creation.
/// 4 hours is generous for most agent workflows while preventing unbounded growth.
pub const SESSION_TTL_SECS: u64 = 4 * 60 * 60; // 4 hours

/// Stateful sliding window tracker for evaluating multi-step sequence rules (<1ms overhead)
#[derive(Clone, Debug)]
pub struct SlidingWindowTracker {
    pub window_size: usize,
    pub history: VecDeque<ToolCallFingerprint>,
}

impl SlidingWindowTracker {
    pub fn new(window_size: usize) -> Self {
        Self {
            window_size: if window_size == 0 { 10 } else { window_size },
            history: VecDeque::new(),
        }
    }

    pub fn push(&mut self, fingerprint: ToolCallFingerprint) {
        if self.history.len() >= self.window_size {
            self.history.pop_front();
        }
        self.history.push_back(fingerprint);
    }

    pub fn contains_tool(&self, tool_name: &str) -> bool {
        self.history.iter().any(|f| f.tool_name == tool_name)
    }

    pub fn count_tool(&self, tool_name: &str) -> usize {
        self.history.iter().filter(|f| f.tool_name == tool_name).count()
    }

    pub fn contains_tool_matching_param(&self, tool_name: &str, param_regex: &str) -> bool {
        let Ok(re) = Regex::new(param_regex) else {
            return false;
        };
        self.history.iter().any(|f| {
            if f.tool_name == tool_name {
                let args_str = f.raw_args.to_string();
                re.is_match(&args_str)
            } else {
                false
            }
        })
    }

    pub fn contains_any_tool_matching_param(&self, tools: &[String], param_regex: Option<&str>) -> bool {
        self.history.iter().any(|f| {
            if tools.iter().any(|t| t == &f.tool_name) {
                if let Some(re_str) = param_regex {
                    if let Ok(re) = Regex::new(re_str) {
                        let args_str = f.raw_args.to_string();
                        re.is_match(&args_str)
                    } else {
                        true
                    }
                } else {
                    true
                }
            } else {
                false
            }
        })
    }
}

/// A completely isolated context for a single active AI agent session.
/// Enforces absolute isolation of rate limiting, cycle detection, policy contexts, and logs (FR-101).
pub struct SessionContext {
    /// Unique session UUID generated dynamically by the gateway
    pub session_id: String,

    /// Optional authenticated subject identity from Okta/Entra ID OIDC claim
    pub identity_sub: Option<String>,

    /// Optional authenticated email identity from Okta/Entra ID OIDC claim
    pub identity_email: Option<String>,

    /// FR-112: Authenticated groups extracted from OIDC claim via group_claim_key
    pub identity_groups: Vec<String>,

    /// The frozen compiled policy context active at the moment of session initiation.
    /// This ensures that policy hot-reloads do not disrupt in-flight sessions (FR-106).
    pub policy: Option<CompiledPolicy>,

    /// Isolated token-bucket rate limiter for this specific session context
    pub rate_limiter: RateLimiter,

    /// Isolated sliding window of tool call fingerprints for cycle detection / loop prevention
    pub tool_history: Mutex<Vec<ToolCallFingerprint>>,

    /// Sliding window tracker for multi-step sequence rule evaluation
    pub sliding_window: Mutex<SlidingWindowTracker>,

    /// The precise timestamp when this session was initialized
    pub start_time: Instant,

    /// Isolated client remote IP address (FR-201)
    pub request_ip: Option<String>,

    /// FR-22: Active credential presented by the agent for scoping.
    pub active_credential_id: Option<String>,

    /// FR-103: Active agent credential scope header sent via X-AgentWall-Credential-Scope.
    pub agent_scope_header: Option<String>,

    /// FR-102: Total tokens consumed in this session for spend cap enforcement.
    pub tokens_used: std::sync::atomic::AtomicU64,
}

impl SessionContext {
    /// Create a new isolated session context bound to a validated OIDC identity or client token.
    /// Freezes the active policy rules at session startup to protect in-flight workflows (FR-106).
    pub fn new(
        identity_sub: Option<String>,
        identity_email: Option<String>,
        identity_groups: Vec<String>,
        active_policy: Option<CompiledPolicy>,
        request_ip: Option<String>,
        active_credential_id: Option<String>,
    ) -> Self {
        Self::new_with_scope(
            identity_sub,
            identity_email,
            identity_groups,
            active_policy,
            request_ip,
            active_credential_id,
            None,
        )
    }

    pub fn new_with_scope(
        identity_sub: Option<String>,
        identity_email: Option<String>,
        identity_groups: Vec<String>,
        active_policy: Option<CompiledPolicy>,
        request_ip: Option<String>,
        active_credential_id: Option<String>,
        agent_scope_header: Option<String>,
    ) -> Self {
        let session_id = Uuid::new_v4().to_string();
        let start_time = Instant::now();

        // Resolve rate limit. Check if policy specifies a default session rate limit
        let limit = active_policy
            .as_ref()
            .map(|p| p.max_calls_per_second)
            .unwrap_or(0);

        Self {
            session_id,
            identity_sub,
            identity_email,
            identity_groups,
            policy: active_policy,
            rate_limiter: RateLimiter::new(limit),
            tool_history: Mutex::new(Vec::new()),
            sliding_window: Mutex::new(SlidingWindowTracker::new(10)),
            start_time,
            request_ip,
            active_credential_id,
            agent_scope_header,
            tokens_used: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Fix 3: Returns true if the session has exceeded SESSION_TTL_SECS since creation.
    /// Used by the lazy eviction logic in `server.rs:evict_expired_sessions()`.
    pub fn is_expired(&self) -> bool {
        self.start_time.elapsed() > Duration::from_secs(SESSION_TTL_SECS)
    }
}

#[cfg(test)]
mod session_window_tests {
    use super::*;

    #[test]
    fn test_sliding_window_push_eviction_and_containment() {
        let mut tracker = SlidingWindowTracker::new(3);
        tracker.push(ToolCallFingerprint::new("read_file", &serde_json::json!({"path": ".env"})));
        tracker.push(ToolCallFingerprint::new("view_file", &serde_json::json!({"path": "config.json"})));
        tracker.push(ToolCallFingerprint::new("list_dir", &serde_json::json!({"path": "/"})));

        assert_eq!(tracker.history.len(), 3);
        assert!(tracker.contains_tool("read_file"));

        // Push 4th item -> oldest (read_file) must be evicted
        tracker.push(ToolCallFingerprint::new("write_file", &serde_json::json!({"path": "out.txt"})));
        assert_eq!(tracker.history.len(), 3);
        assert!(!tracker.contains_tool("read_file"));
        assert!(tracker.contains_tool("write_file"));
    }

    #[test]
    fn test_sliding_window_tool_frequency_counting() {
        let mut tracker = SlidingWindowTracker::new(5);
        tracker.push(ToolCallFingerprint::new("read_file", &serde_json::json!({"path": "a.txt"})));
        tracker.push(ToolCallFingerprint::new("read_file", &serde_json::json!({"path": "b.txt"})));
        tracker.push(ToolCallFingerprint::new("bash", &serde_json::json!({"cmd": "ls"})));

        assert_eq!(tracker.count_tool("read_file"), 2);
        assert_eq!(tracker.count_tool("bash"), 1);
        assert_eq!(tracker.count_tool("http_post"), 0);
    }
}

