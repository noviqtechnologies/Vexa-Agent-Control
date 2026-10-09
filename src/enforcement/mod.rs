//! Cross-platform security enforcement engine and sandbox boundary.
//!
//! Provides deterministic isolation and fail-closed process management across
//! Linux, macOS, and Windows. Under the Enterprise Threat Model, this module
//! prevents unmanaged subshells and rogue agents from bypassing gateway policies.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Operational enforcement mode for agent execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnforcementMode {
    /// Cooperative developer mode: Injects proxy environment variables.
    /// Fast and non-intrusive for everyday developer workflows.
    Cooperative,
    /// Strict enterprise mode: Strips raw credentials from child environment,
    /// enforces loopback-only communication, activates fail-closed watchdog.
    Strict,
}

impl Default for EnforcementMode {
    fn default() -> Self {
        Self::Cooperative
    }
}

impl EnforcementMode {
    pub fn from_str_opt(s: &str) -> Self {
        match s.to_lowercase().trim() {
            "strict" | "enterprise" | "hardened" => Self::Strict,
            _ => Self::Cooperative,
        }
    }

    pub fn is_strict(&self) -> bool {
        matches!(self, Self::Strict)
    }
}

/// Failure disposition when the security gateway proxy becomes unreachable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProxyFailurePolicy {
    /// Fail-closed: immediately terminate child processes if gateway fails.
    FailClosed,
    /// Fail-open: allow unmonitored execution (strictly for local offline debugging).
    FailOpen,
}

impl Default for ProxyFailurePolicy {
    fn default() -> Self {
        Self::FailClosed
    }
}

/// Known provider credential environment keys stripped in Strict mode.
pub const SENSITIVE_CREDENTIAL_ENV_VARS: &[&str] = &[
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "AZURE_OPENAI_API_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "DEEPSEEK_API_KEY",
    "GROQ_API_KEY",
    "MISTRAL_API_KEY",
    "COHERE_API_KEY",
    "GOOGLE_API_KEY",
    "GEMINI_API_KEY",
    "REPLICATE_API_TOKEN",
    "GITHUB_TOKEN",
    "GH_TOKEN",
];

/// Sanitizes process environment variables according to the enforcement mode.
pub fn sanitize_environment(
    cmd: &mut Command,
    mode: EnforcementMode,
    gateway_port: u16,
    session_token: Option<&str>,
) -> HashSet<String> {
    let mut stripped = HashSet::new();

    // Standard proxy redirect configuration
    let proxy_url = format!("http://127.0.0.1:{}", gateway_port);
    cmd.env("HTTP_PROXY", &proxy_url);
    cmd.env("HTTPS_PROXY", &proxy_url);
    cmd.env("ALL_PROXY", &proxy_url);
    cmd.env("http_proxy", &proxy_url);
    cmd.env("https_proxy", &proxy_url);
    cmd.env("all_proxy", &proxy_url);

    // Provider base URL redirection to local gateway
    cmd.env("OPENAI_BASE_URL", format!("{}/v1", proxy_url));
    cmd.env("ANTHROPIC_BASE_URL", proxy_url.clone());
    cmd.env("AZURE_OPENAI_ENDPOINT", proxy_url.clone());

    if let Some(token) = session_token {
        cmd.env("AGENTCONTROL_SESSION_TOKEN", token);
        // Provide dummy synthetic key to satisfy client SDK format validators
        cmd.env("OPENAI_API_KEY", format!("agentcontrol-session-{}", token));
        cmd.env(
            "ANTHROPIC_API_KEY",
            format!("agentcontrol-session-{}", token),
        );
    }

    if mode.is_strict() {
        for &var in SENSITIVE_CREDENTIAL_ENV_VARS {
            if std::env::var(var).is_ok() {
                // If not providing synthetic key, remove completely
                if session_token.is_none()
                    || (var != "OPENAI_API_KEY" && var != "ANTHROPIC_API_KEY")
                {
                    cmd.env_remove(var);
                    stripped.insert(var.to_string());
                }
            }
        }
    }

    stripped
}

/// Fail-closed process watchdog guard.
pub struct ProcessWatchdog {
    child_pid: u32,
    active: Arc<AtomicBool>,
    failure_policy: ProxyFailurePolicy,
}

impl ProcessWatchdog {
    /// Spawns a new watchdog guarding the given child process PID.
    pub fn new(child_pid: u32, failure_policy: ProxyFailurePolicy) -> Self {
        Self {
            child_pid,
            active: Arc::new(AtomicBool::new(true)),
            failure_policy,
        }
    }

    /// Terminates the monitored child process hierarchy immediately across OS types.
    pub fn terminate_child(&self) {
        if self.child_pid == 0 {
            return;
        }

        #[cfg(windows)]
        {
            // /F = Forcefully terminate, /T = Tree (all children spawned by process)
            let _ = Command::new("taskkill")
                .args(["/F", "/T", "/PID", &self.child_pid.to_string()])
                .output();
        }

        #[cfg(unix)]
        {
            // Try process group kill first, then fallback to direct PID kill
            let pid_str = self.child_pid.to_string();
            let _ = Command::new("kill")
                .args(["-9", &format!("-{}", pid_str)])
                .output();
            let _ = Command::new("kill").args(["-9", &pid_str]).output();
        }
    }

    /// Triggers fail-closed shutdown if policy mandates.
    pub fn on_gateway_failure(&self) {
        if self.failure_policy == ProxyFailurePolicy::FailClosed {
            self.terminate_child();
        }
    }

    /// Stops watchdog monitoring gracefully.
    pub fn disarm(&self) {
        self.active.store(false, Ordering::SeqCst);
    }
}

impl Drop for ProcessWatchdog {
    fn drop(&mut self) {
        if self.active.load(Ordering::SeqCst)
            && self.failure_policy == ProxyFailurePolicy::FailClosed
        {
            self.terminate_child();
        }
    }
}

/// Dual-stack IPv4 / IPv6 network address validation.
pub struct DualStackBoundary;

impl DualStackBoundary {
    /// Verifies if a given socket address is strictly loopback (IPv4 or IPv6).
    pub fn is_loopback(addr: &SocketAddr) -> bool {
        match addr.ip() {
            IpAddr::V4(v4) => v4.is_loopback(),
            IpAddr::V6(v6) => v6.is_loopback(),
        }
    }

    /// Checks if an IPv6 address represents an attempted IPv4-mapped loopback bypass.
    pub fn is_ipv4_mapped_loopback(addr: &Ipv6Addr) -> bool {
        if let Some(v4) = addr.to_ipv4_mapped() {
            v4.is_loopback()
        } else {
            false
        }
    }

    /// Returns standard dual-stack loopback candidate addresses.
    pub fn candidate_loopback_addrs(port: u16) -> Vec<SocketAddr> {
        vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port),
        ]
    }
}

/// Heuristic DNS tunneling and exfiltration detector.
pub struct DnsExfiltrationGuard;

impl DnsExfiltrationGuard {
    /// Evaluates if a domain query exhibits hallmarks of DNS tunneling.
    /// (e.g., abnormally long labels, excessive entropy, hex-encoded payloads).
    pub fn inspect_query(domain: &str) -> Result<(), &'static str> {
        let clean = domain.trim().trim_end_matches('.');
        if clean.len() > 253 {
            return Err("Domain name exceeds maximum RFC 1035 length (253 octets)");
        }

        for label in clean.split('.') {
            if label.len() > 63 {
                return Err("DNS label exceeds 63 characters (RFC 1035 violation)");
            }

            // Detect base32/hex encoded data chunks often used in DNS tunneling
            if label.len() >= 32 && label.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(
                    "DNS label contains high-entropy hex payload indicative of exfiltration",
                );
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enforcement_mode_parsing() {
        assert_eq!(
            EnforcementMode::from_str_opt("strict"),
            EnforcementMode::Strict
        );
        assert_eq!(
            EnforcementMode::from_str_opt("enterprise"),
            EnforcementMode::Strict
        );
        assert_eq!(
            EnforcementMode::from_str_opt("cooperative"),
            EnforcementMode::Cooperative
        );
        assert_eq!(
            EnforcementMode::from_str_opt("default"),
            EnforcementMode::Cooperative
        );
    }

    #[test]
    fn test_sanitize_environment_strips_sensitive_keys_in_strict() {
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "test-secret-key-1234");
        std::env::set_var("GITHUB_TOKEN", "ghp_testtoken");

        let mut cmd = Command::new("dummy");
        let stripped =
            sanitize_environment(&mut cmd, EnforcementMode::Strict, 8080, Some("sess-123"));

        assert!(stripped.contains("AWS_SECRET_ACCESS_KEY"));
        assert!(stripped.contains("GITHUB_TOKEN"));
    }

    #[test]
    fn test_dual_stack_boundary_recognizes_v4_and_v6_loopback() {
        let v4: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let v6: SocketAddr = "[::1]:8080".parse().unwrap();
        let ext: SocketAddr = "8.8.8.8:53".parse().unwrap();

        assert!(DualStackBoundary::is_loopback(&v4));
        assert!(DualStackBoundary::is_loopback(&v6));
        assert!(!DualStackBoundary::is_loopback(&ext));
    }

    #[test]
    fn test_dns_exfiltration_guard() {
        // Legitimate domain
        assert!(DnsExfiltrationGuard::inspect_query("api.openai.com").is_ok());
        assert!(DnsExfiltrationGuard::inspect_query("hub.vexasec.io").is_ok());

        // Tunneling hex exfiltration
        let tunnel = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6.evil.attacker.com";
        assert!(DnsExfiltrationGuard::inspect_query(tunnel).is_err());
    }
}
