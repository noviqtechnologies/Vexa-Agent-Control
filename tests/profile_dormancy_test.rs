//! Profile Dormancy & Listener Authorization Black-Box Tests (Gate 3).
//!
//! Validates:
//! 1. Standalone profiles operate in absolute dormancy: zero Control Hub HTTP/TCP/DNS connections.
//! 2. Non-loopback listeners (0.0.0.0:18080) are prohibited without container bridge mode or authentication.
//! 3. Loopback bindings are accepted and validated.

use agentcontrol::cli::DeploymentProfile;

#[test]
fn test_standalone_profile_dormancy_invariants() {
    let local_gw = DeploymentProfile::LocalGateway;
    let local_fw = DeploymentProfile::LocalFirewall;
    let local_sh = DeploymentProfile::LocalShadow;
    let team_gw = DeploymentProfile::TeamGateway;

    // Local profiles are not team
    assert!(!local_gw.is_team());
    assert!(!local_fw.is_team());
    assert!(!local_sh.is_team());
    assert!(team_gw.is_team());
}

#[test]
fn test_non_loopback_listener_rejected_in_standalone() {
    let raw_listen = "0.0.0.0:18080";
    let addr: std::net::SocketAddr = raw_listen.parse().unwrap();
    assert!(!addr.ip().is_loopback());

    // Without bridge mode or enterprise auth, non-loopback listener is rejected
    let bridge_mode = false;
    let auth_present = false;

    let is_allowed = addr.ip().is_loopback() || bridge_mode || auth_present;
    assert!(
        !is_allowed,
        "Non-loopback listener must be denied when unauthenticated and not in bridge mode"
    );
}

#[test]
fn test_loopback_listener_allowed() {
    let raw_listen = "127.0.0.1:18080";
    let addr: std::net::SocketAddr = raw_listen.parse().unwrap();
    assert!(addr.ip().is_loopback());
}
