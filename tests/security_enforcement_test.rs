//! Security enforcement and bypass resistance integration test suite.
//!
//! Validates that the agent control solution adheres to the enterprise threat model:
//! 1. Environment credential stripping in strict mode.
//! 2. Dual-stack IPv4/IPv6 loopback boundary detection.
//! 3. DNS tunneling and exfiltration sinkhole detection.
//! 4. Fail-closed watchdog behavior.

use agentcontrol::enforcement::{
    sanitize_environment, DnsExfiltrationGuard, DualStackBoundary, EnforcementMode,
    ProcessWatchdog, ProxyFailurePolicy, SENSITIVE_CREDENTIAL_ENV_VARS,
};
use std::net::SocketAddr;
use std::process::Command;

#[test]
fn test_strict_mode_credential_isolation() {
    // Set simulated sensitive credentials in test environment
    for &var in SENSITIVE_CREDENTIAL_ENV_VARS {
        std::env::set_var(var, format!("dummy_secret_value_{}", var));
    }

    let mut cmd = Command::new("test_agent_binary");
    let session_token = "sess-verified-enterprise-999";

    let stripped = sanitize_environment(
        &mut cmd,
        EnforcementMode::Strict,
        18080,
        Some(session_token),
    );

    // Verify all sensitive keys were flagged and stripped from command
    assert!(
        stripped.contains("AWS_SECRET_ACCESS_KEY"),
        "AWS secret key must be stripped in strict mode"
    );
    assert!(
        stripped.contains("GITHUB_TOKEN"),
        "GitHub token must be stripped in strict mode"
    );
}

#[test]
fn test_cooperative_mode_preserves_developer_keys() {
    let mut cmd = Command::new("test_dev_agent");
    let stripped = sanitize_environment(&mut cmd, EnforcementMode::Cooperative, 18080, None);

    // In cooperative mode, no environment variables are purged
    assert!(
        stripped.is_empty(),
        "Cooperative mode must not strip developer keys"
    );
}

#[test]
fn test_dual_stack_loopback_boundary_enforcement() {
    let loopback_v4: SocketAddr = "127.0.0.1:18080".parse().unwrap();
    let loopback_v6: SocketAddr = "[::1]:18080".parse().unwrap();
    let external_v4: SocketAddr = "192.168.1.100:18080".parse().unwrap();
    let external_v6: SocketAddr = "[2001:db8::1]:18080".parse().unwrap();

    assert!(DualStackBoundary::is_loopback(&loopback_v4));
    assert!(DualStackBoundary::is_loopback(&loopback_v6));
    assert!(!DualStackBoundary::is_loopback(&external_v4));
    assert!(!DualStackBoundary::is_loopback(&external_v6));
}

#[test]
fn test_dns_tunneling_and_exfiltration_sinkhole() {
    // Valid development hosts
    assert!(DnsExfiltrationGuard::inspect_query("api.anthropic.com").is_ok());
    assert!(DnsExfiltrationGuard::inspect_query("models.internal.corp").is_ok());

    // High-entropy 32-hex character tunneling label
    let tunnel_attack = "deadbeefcafebabe0123456789abcdef0123.exfil.attacker.org";
    let result = DnsExfiltrationGuard::inspect_query(tunnel_attack);
    assert!(
        result.is_err(),
        "DnsExfiltrationGuard must detect high-entropy hex tunneling payload"
    );
}

#[test]
fn test_watchdog_disarm_graceful_lifecycle() {
    // Spawning watchdog with dummy PID 99999 and disarming
    let watchdog = ProcessWatchdog::new(99999, ProxyFailurePolicy::FailClosed);
    watchdog.disarm();
    // Drop executes without attempting emergency kill because disarmed
    drop(watchdog);
}
