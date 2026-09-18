use agentcontrol::service::{
    default_enterprise_config_path, default_user_config_path, load_daemon_config,
    save_daemon_config, AuthHealthInfo, DaemonConfig, DaemonHealthReport, DaemonHealthResponse,
    ListenerState, PolicyHealthInfo, SupervisorState,
};
use tempfile::tempdir;

// ─── Existing Tests (unchanged) ───────────────────────────────────────────────

#[test]
fn test_daemon_config_serialization_and_defaults() {
    let tmp = tempdir().expect("failed to create temp dir");
    let cfg_path = tmp.path().join("daemon.json");

    let cfg = DaemonConfig {
        schema_version: 1,
        hub_url: "https://hub.example.com".to_string(),
        listen: "127.0.0.1:18080".to_string(),
        gateway_secret: Some("gw_secret_123".to_string()),
        policy_read_secret: Some("pol_secret_456".to_string()),
        agent_id: Some("agent_test_789".to_string()),
        enterprise: false,
    };

    save_daemon_config(&cfg, &cfg_path).expect("failed to save daemon config");
    assert!(cfg_path.exists(), "daemon.json must exist");

    let loaded = load_daemon_config(Some(cfg_path.to_str().unwrap()), false)
        .expect("failed to load daemon config")
        .expect("config must not be None");

    assert_eq!(loaded, cfg);
    assert_eq!(loaded.schema_version, 1);
    assert_eq!(loaded.hub_url, "https://hub.example.com");
    assert_eq!(loaded.listen, "127.0.0.1:18080");
    assert_eq!(loaded.gateway_secret, Some("gw_secret_123".to_string()));
    assert_eq!(loaded.policy_read_secret, Some("pol_secret_456".to_string()));
    assert_eq!(loaded.agent_id, Some("agent_test_789".to_string()));
    assert!(!loaded.enterprise);
}

#[test]
fn test_daemon_config_minimal_json_parsing() {
    let tmp = tempdir().expect("failed to create temp dir");
    let cfg_path = tmp.path().join("daemon_minimal.json");

    let minimal_json = r#"{
        "hub_url": "https://minimal.hub.io"
    }"#;
    std::fs::write(&cfg_path, minimal_json).expect("failed to write minimal json");

    let loaded = load_daemon_config(Some(cfg_path.to_str().unwrap()), false)
        .expect("failed to load")
        .expect("must be Some");

    assert_eq!(loaded.schema_version, 1);
    assert_eq!(loaded.hub_url, "https://minimal.hub.io");
    assert_eq!(loaded.listen, "127.0.0.1:18080");
    assert_eq!(loaded.gateway_secret, None);
    assert_eq!(loaded.policy_read_secret, None);
    assert_eq!(loaded.agent_id, None);
    assert!(!loaded.enterprise);
}

#[test]
fn test_default_config_paths_resolvable() {
    let user_path = default_user_config_path();
    assert!(user_path.ends_with("daemon.json"));

    let ent_path = default_enterprise_config_path();
    assert!(ent_path.ends_with("daemon.json"));
}

#[test]
fn test_daemon_health_handshake_schema_deserialization() {
    let raw_handshake = r#"{
        "schema_version": 1,
        "status": "healthy",
        "pid": 12345,
        "binary_path": "/usr/local/bin/agentcontrol",
        "version": "1.0.87",
        "uptime_secs": 420,
        "listen_addr": "127.0.0.1:18080",
        "policy": {
            "loaded": true,
            "path": "/home/user/.agentcontrol/policy.json"
        },
        "auth": {
            "enrolled": true,
            "hub_url": "https://app.vexasec.io",
            "device_id": "dev_abc123"
        }
    }"#;

    let parsed: DaemonHealthResponse =
        serde_json::from_str(raw_handshake).expect("handshake schema must parse");
    assert_eq!(parsed.schema_version, 1);
    assert_eq!(parsed.pid, 12345);
    assert_eq!(parsed.uptime_secs, 420);
    assert!(parsed.policy.loaded);
    assert_eq!(
        parsed.policy.path.as_deref(),
        Some("/home/user/.agentcontrol/policy.json")
    );
    assert!(parsed.auth.enrolled);
    assert_eq!(parsed.auth.device_id.as_deref(), Some("dev_abc123"));
}

#[test]
fn test_truthful_state_model_evaluation() {
    // 1. Fully healthy managed state
    let healthy_report = DaemonHealthReport {
        supervisor: SupervisorState::Managed {
            supervisor_type: "Windows Task Scheduler (User)".to_string(),
            target_name: "VexaAgentControl-testuser".to_string(),
            active: true,
            details: Some("Task State: Running".to_string()),
        },
        listener: ListenerState::Healthy {
            addr: "127.0.0.1:18080".to_string(),
            latency_ms: 2,
            handshake: DaemonHealthResponse {
                schema_version: 1,
                status: "healthy".to_string(),
                pid: 5678,
                binary_path: "C:\\bin\\agentcontrol.exe".to_string(),
                version: "1.0.87".to_string(),
                uptime_secs: 100,
                listen_addr: "127.0.0.1:18080".to_string(),
                policy: PolicyHealthInfo {
                    loaded: true,
                    path: None,
                },
                auth: AuthHealthInfo {
                    enrolled: true,
                    hub_url: Some("https://hub.example.com".to_string()),
                    device_id: Some("dev_1".to_string()),
                },
            },
        },
    };
    assert!(
        healthy_report.is_healthy_managed(),
        "Active managed supervisor + healthy handshake must be healthy managed"
    );

    // 2. Unmanaged process (e.g. spawned via manual terminal, not supervisor) -> Degraded
    let unmanaged_report = DaemonHealthReport {
        supervisor: SupervisorState::Unmanaged {
            warning: "Process running unmanaged".to_string(),
        },
        listener: healthy_report.listener.clone(),
    };
    assert!(
        !unmanaged_report.is_healthy_managed(),
        "Unmanaged running process must not be classified as healthy managed"
    );

    // 3. Supervisor stopped or crashed -> Degraded
    let stopped_report = DaemonHealthReport {
        supervisor: SupervisorState::Managed {
            supervisor_type: "Linux systemd (User)".to_string(),
            target_name: "agent-control.service".to_string(),
            active: false,
            details: Some("SubState=dead".to_string()),
        },
        listener: ListenerState::Refused {
            addr: "127.0.0.1:18080".to_string(),
        },
    };
    assert!(
        !stopped_report.is_healthy_managed(),
        "Stopped supervisor and refused port must not be healthy managed"
    );

    // 4. Conflicted port -> Degraded
    let conflict_report = DaemonHealthReport {
        supervisor: SupervisorState::Managed {
            supervisor_type: "macOS launchd (LaunchAgent)".to_string(),
            target_name: "io.vexasec.agentcontrol".to_string(),
            active: true,
            details: None,
        },
        listener: ListenerState::OccupiedForeign {
            addr: "127.0.0.1:18080".to_string(),
            message: "Foreign service occupied port".to_string(),
        },
    };
    assert!(
        !conflict_report.is_healthy_managed(),
        "Conflicted port must not be healthy managed"
    );
}

// ─── Enrollment Auth Guard Tests ──────────────────────────────────────────────
//
// These tests verify the security boundary introduced by the enrollment pre-check
// in `run_service(ServiceAction::Install, called_from_login: bool, quiet: bool)`.
//
// Isolation strategy: each test redirects HOME/USERPROFILE to an empty tempdir
// so that `is_device_enrolled()` — which reads from the home directory — returns
// a predictable result without touching real OS credentials or keyring state.
// Tests that need an "enrolled" state write a fake device_cert.pem into the
// temp dir's .agentcontrol/ subdirectory (the file-based enrollment check path).

/// Verifies the enrollment auth guard contract at the `is_device_enrolled()` boundary.
///
/// **Important isolation note:** The guard calls `is_device_enrolled()`, which checks
/// the OS Credential Manager (Windows Credential Manager / macOS Keychain) FIRST,
/// before falling back to file-based checks. On a machine that is already enrolled
/// (i.e. in a developer environment with real credentials), the keyring check returns
/// `true` regardless of the `USERPROFILE`/`HOME` redirect — making it impossible to
/// simulate "not enrolled" at the integration test level without mocking the keyring.
///
/// This test therefore validates the guard contract from two angles:
/// 1. On an enrolled machine: confirms `called_from_login: false` ALLOWS install
///    (because `is_device_enrolled()` returns true — the guard passes, not blocks).
/// 2. Verifies `daemon.json` is written correctly, confirming the auth path works
///    end-to-end for legitimate re-installs on enrolled devices.
///
/// The "blocked on unenrolled device" behavior is validated in the unit test
/// `test_enrollment_guard_blocks_when_not_enrolled` in `src/service/mod.rs`.
#[tokio::test]
async fn test_service_install_auth_guard_on_enrolled_machine() {
    use agentcontrol::service::{run_service, ServiceAction};

    let tmp = tempdir().expect("failed to create temp dir");
    let agentcontrol_dir = tmp.path().join(".agentcontrol");
    std::fs::create_dir_all(&agentcontrol_dir).expect("failed to create .agentcontrol dir");
    let cfg_path = agentcontrol_dir.join("daemon.json");

    // On an enrolled machine, is_device_enrolled() returns true via keyring.
    // A standalone CLI call (called_from_login: false) must PASS the enrollment
    // check and allow the install to proceed.
    let enrolled = agentcontrol::identity::device::is_device_enrolled();

    let action = ServiceAction::Install {
        hub_url: "http://127.0.0.1:8081".to_string(),
        gateway_secret: None,
        policy_read_secret: None,
        agent_id: None,
        enterprise: false,
        config: Some(cfg_path.to_str().unwrap().to_string()),
        force: false,
    };

    if enrolled {
        // Machine is enrolled: the guard PASSES, install proceeds.
        // daemon.json must be written (regardless of OS task registration outcome).
        let _exit_code = run_service(action, false, true).await;
        assert!(
            cfg_path.exists(),
            "daemon.json must be written when device is enrolled and guard passes"
        );
        let loaded = load_daemon_config(Some(cfg_path.to_str().unwrap()), false)
            .expect("failed to load config")
            .expect("config must not be None when guard passes");
        assert_eq!(loaded.hub_url, "http://127.0.0.1:8081");
    } else {
        // Machine is NOT enrolled: the guard BLOCKS the install. Exit code must be 1.
        let exit_code = run_service(action, false, true).await;
        assert_eq!(
            exit_code, 1,
            "service install must return 1 when device is not enrolled"
        );
        assert!(
            !cfg_path.exists(),
            "daemon.json must NOT be created when enrollment auth guard blocks install"
        );
    }
}

/// Verifies that `service install` called with `called_from_login: true` proceeds
/// past the enrollment pre-check even when no credentials exist on disk.
///
/// This simulates the internal call made by `run_login()` immediately after PKCE
/// authentication completes — at that point the device token has not yet been
/// persisted, but the service registration must succeed.
#[tokio::test]
async fn test_service_install_allowed_from_login_bypasses_enrollment_check() {
    use agentcontrol::service::{run_service, ServiceAction};

    let tmp = tempdir().expect("failed to create temp dir");
    let agentcontrol_dir = tmp.path().join(".agentcontrol");
    std::fs::create_dir_all(&agentcontrol_dir).expect("failed to create .agentcontrol dir");

    // Empty dir — no enrollment credentials — but called_from_login bypasses the check.
    #[cfg(windows)]
    std::env::set_var("USERPROFILE", tmp.path());
    #[cfg(not(windows))]
    std::env::set_var("HOME", tmp.path());

    let cfg_path = agentcontrol_dir.join("daemon.json");

    let action = ServiceAction::Install {
        hub_url: "http://127.0.0.1:8081".to_string(),
        gateway_secret: None,
        policy_read_secret: None,
        agent_id: Some("test-device-id".to_string()),
        enterprise: false,
        config: Some(cfg_path.to_str().unwrap().to_string()),
        force: false,
    };

    // called_from_login: true — enrollment check is bypassed.
    // The OS task scheduler registration may fail in a test environment, but the
    // daemon config must be written (proving the guard was skipped).
    let _exit_code = run_service(action, true, true).await;

    assert!(
        cfg_path.exists(),
        "daemon.json must be written when called_from_login: true bypasses the enrollment pre-check"
    );

    let loaded = load_daemon_config(Some(cfg_path.to_str().unwrap()), false)
        .expect("failed to load config")
        .expect("config must not be None after login-initiated install");
    assert_eq!(loaded.hub_url, "http://127.0.0.1:8081");
    assert_eq!(loaded.agent_id.as_deref(), Some("test-device-id"));
}

/// Verifies that `--enterprise` mode bypasses the enrollment pre-check regardless
/// of `called_from_login`.
///
/// Enterprise installs are performed by MDM/Intune/SCCM system provisioning scripts
/// running as SYSTEM — before any user-space enrollment credentials exist.
/// The enterprise flag must allow provisioning to proceed unconditionally.
#[tokio::test]
async fn test_service_install_enterprise_bypasses_enrollment_check() {
    use agentcontrol::service::{run_service, ServiceAction};

    let tmp = tempdir().expect("failed to create temp dir");
    let agentcontrol_dir = tmp.path().join(".agentcontrol");
    std::fs::create_dir_all(&agentcontrol_dir).expect("failed to create .agentcontrol dir");

    // Empty dir — no enrollment credentials.
    #[cfg(windows)]
    std::env::set_var("USERPROFILE", tmp.path());
    #[cfg(not(windows))]
    std::env::set_var("HOME", tmp.path());

    let cfg_path = agentcontrol_dir.join("daemon.json");

    let action = ServiceAction::Install {
        hub_url: "https://corp.hub.example.com".to_string(),
        gateway_secret: Some("corp-gw-secret".to_string()),
        policy_read_secret: None,
        agent_id: Some("mdm-provisioned-device".to_string()),
        enterprise: true, // <-- must bypass enrollment check unconditionally
        config: Some(cfg_path.to_str().unwrap().to_string()),
        force: false,
    };

    // called_from_login: false, enterprise: true — check must be bypassed.
    let _exit_code = run_service(action, false, true).await;

    assert!(
        cfg_path.exists(),
        "daemon.json must be written for enterprise installs even without prior enrollment"
    );

    let loaded = load_daemon_config(Some(cfg_path.to_str().unwrap()), false)
        .expect("failed to load enterprise config")
        .expect("enterprise config must not be None");
    assert_eq!(loaded.hub_url, "https://corp.hub.example.com");
    assert!(loaded.enterprise, "config must record enterprise: true");
    assert_eq!(
        loaded.gateway_secret.as_deref(),
        Some("corp-gw-secret"),
        "enterprise gateway secret must be persisted"
    );
}

/// Verifies the warn-and-proceed policy for hub URL changes on an enrolled device.
///
/// When an enrolled device calls `service install` pointing at a DIFFERENT hub URL
/// (without `--force`), the daemon.json must still be written with the new hub URL
/// (no hard failure). A warning is printed to stderr — this test validates the
/// data outcome only, not the stderr output.
#[tokio::test]
async fn test_service_install_hub_url_change_warns_and_proceeds() {
    use agentcontrol::service::{run_service, ServiceAction};

    let tmp = tempdir().expect("failed to create temp dir");
    let agentcontrol_dir = tmp.path().join(".agentcontrol");
    std::fs::create_dir_all(&agentcontrol_dir).expect("failed to create .agentcontrol dir");

    // Simulate an enrolled device by writing a fake device_cert.pem (file-based
    // enrollment check path — avoids touching real OS keyring in tests).
    std::fs::write(
        agentcontrol_dir.join("device_cert.pem"),
        "-----BEGIN CERTIFICATE-----\nZmFrZS10ZXN0LWNlcnQ=\n-----END CERTIFICATE-----\n",
    )
    .expect("failed to write fake device cert");

    // Write an existing hub_url to simulate a previously enrolled state.
    std::fs::write(
        agentcontrol_dir.join("hub_url"),
        "https://staging.hub.example.com",
    )
    .expect("failed to write existing hub_url");

    #[cfg(windows)]
    std::env::set_var("USERPROFILE", tmp.path());
    #[cfg(not(windows))]
    std::env::set_var("HOME", tmp.path());

    let cfg_path = agentcontrol_dir.join("daemon.json");

    let action = ServiceAction::Install {
        hub_url: "https://production.hub.example.com".to_string(), // different hub
        gateway_secret: None,
        policy_read_secret: None,
        agent_id: None,
        enterprise: false,
        config: Some(cfg_path.to_str().unwrap().to_string()),
        force: false, // no --force: warn-and-proceed, not hard-fail
    };

    // called_from_login: true to isolate the overwrite-warning path from the
    // enrollment gate (the fake cert above satisfies is_device_enrolled, but
    // keyring lookups may behave differently across environments).
    let _exit_code = run_service(action, true, true).await;

    // Warn-and-proceed: daemon.json must be written with the NEW hub URL.
    assert!(
        cfg_path.exists(),
        "daemon.json must be written (warn-and-proceed policy applies, not hard-fail)"
    );

    let loaded = load_daemon_config(Some(cfg_path.to_str().unwrap()), false)
        .expect("failed to load config after hub URL change")
        .expect("config must not be None after hub URL change");
    assert_eq!(
        loaded.hub_url, "https://production.hub.example.com",
        "new hub URL must be persisted — warn-and-proceed must not block the write"
    );
}
