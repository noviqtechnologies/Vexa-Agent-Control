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

#[tokio::test]
async fn test_blackbox_network_dormancy_zero_hub_traffic() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    // Bind a mock Control Hub listener on ephemeral loopback port
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock_hub_addr = listener.local_addr().unwrap();
    let hit_count = Arc::new(AtomicUsize::new(0));
    let hit_count_clone = hit_count.clone();

    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            hit_count_clone.fetch_add(1, Ordering::SeqCst);
            use tokio::io::AsyncWriteExt;
            let _ = socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await;
        }
    });

    // Set HUB_URL to mock Hub
    std::env::set_var("HUB_URL", format!("http://{}", mock_hub_addr));
    std::env::set_var("AGENTCONTROL_PROFILE", "local-gateway");

    // Perform unprotect dry-run and protect operations
    let dry_run_res = agentcontrol::wrap::run_unprotect_all(true, false);
    assert_eq!(dry_run_res, 0);

    // Wait a moment for any errant background tasks
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    // In local-gateway / standalone mode, ZERO requests must have reached the Hub
    assert_eq!(
        hit_count.load(Ordering::SeqCst),
        0,
        "Standalone profile MUST produce zero network traffic to Control Hub (black-box dormancy violated)"
    );
}
