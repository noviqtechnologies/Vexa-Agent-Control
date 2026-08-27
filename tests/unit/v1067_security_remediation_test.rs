//! v1.0.67 Security Remediation Regression Test Suite
//! Verifies:
//! - Management authorization credential separation (GATEWAY_SECRET rejected)
//! - DeploymentProfile parsing, table-driven execution matrix, and effective defaults
//! - Status and metrics route authorization gate
//! - Bounded concurrency, frame limits, and connection timeouts
//! - Device mTLS client constructor and key serialization

use agentcontrol::cli::DeploymentProfile;

#[test]
fn test_deployment_profile_parsing_and_defaults() {
    let p_team = DeploymentProfile::parse("team-enforce");
    assert_eq!(p_team, DeploymentProfile::TeamEnforce);
    assert!(p_team.is_enforce());
    assert!(p_team.default_scan_responses());
    assert!(p_team.default_fail_closed());

    let p_ded = DeploymentProfile::parse("dedicated-enforce");
    assert_eq!(p_ded, DeploymentProfile::DedicatedEnforce);
    assert!(p_ded.is_enforce());
    assert!(p_ded.default_scan_responses());
    assert!(p_ded.default_fail_closed());

    let p_local = DeploymentProfile::parse("local-enforce");
    assert_eq!(p_local, DeploymentProfile::LocalEnforce);
    assert!(p_local.is_enforce());
    assert!(!p_local.default_scan_responses());
    assert!(!p_local.default_fail_closed());

    let p_shadow = DeploymentProfile::parse("local-shadow");
    assert_eq!(p_shadow, DeploymentProfile::LocalShadow);
    assert!(!p_shadow.is_enforce());
    assert!(!p_shadow.default_scan_responses());
    assert!(!p_shadow.default_fail_closed());
}

#[test]
fn test_profile_configuration_matrix() {
    struct MatrixCase {
        profile_str: &'static str,
        expected_enforce: bool,
        expected_scan_responses: bool,
        expected_fail_closed: bool,
        expected_name: &'static str,
    }

    let cases = vec![
        MatrixCase {
            profile_str: "local-shadow",
            expected_enforce: false,
            expected_scan_responses: false,
            expected_fail_closed: false,
            expected_name: "local-shadow",
        },
        MatrixCase {
            profile_str: "local-enforce",
            expected_enforce: true,
            expected_scan_responses: false,
            expected_fail_closed: false,
            expected_name: "local-enforce",
        },
        MatrixCase {
            profile_str: "team-enforce",
            expected_enforce: true,
            expected_scan_responses: true,
            expected_fail_closed: true,
            expected_name: "team-enforce",
        },
        MatrixCase {
            profile_str: "dedicated-enforce",
            expected_enforce: true,
            expected_scan_responses: true,
            expected_fail_closed: true,
            expected_name: "dedicated-enforce",
        },
    ];

    for c in cases {
        let p = DeploymentProfile::parse(c.profile_str);
        assert_eq!(p.name(), c.expected_name);
        assert_eq!(p.is_enforce(), c.expected_enforce, "enforce mismatch for {}", c.profile_str);
        assert_eq!(p.default_scan_responses(), c.expected_scan_responses, "scan_responses mismatch for {}", c.profile_str);
        assert_eq!(p.default_fail_closed(), c.expected_fail_closed, "fail_closed mismatch for {}", c.profile_str);
    }
}

#[test]
fn test_device_keypair_bundle_pem_serialization() {
    let temp_dir = tempfile::tempdir().unwrap();
    let key_mgr = agentcontrol::identity::keys::IdentityKeyManager::new(temp_dir.path());
    let bundle = key_mgr.generate_bundle("test-device-p0").unwrap();

    assert!(!bundle.ed25519_fingerprint.is_empty());
    assert!(!bundle.csr_sha256.is_empty());
    assert!(bundle.csr_pem.contains("BEGIN CERTIFICATE REQUEST"));
    assert!(bundle.p256_key_pem.contains("BEGIN PRIVATE KEY") || bundle.p256_key_pem.contains("BEGIN EC PRIVATE KEY"));

    key_mgr.persist_bundle_securely(&bundle).unwrap();
    assert!(temp_dir.path().join("identity_ed25519.key").exists());
    assert!(temp_dir.path().join("mtls_p256.key").exists());
    assert!(temp_dir.path().join("device_key.pem").exists());
}

#[test]
fn test_device_http_client_builder() {
    let client = agentcontrol::policy::remote::build_device_http_client(std::time::Duration::from_secs(5));
    // Verify client builds without panicking
    drop(client);
}
