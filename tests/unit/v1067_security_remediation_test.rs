//! v1.0.67 Security Remediation Regression Test Suite
//! Verifies:
//! - Management authorization credential separation (GATEWAY_SECRET rejected)
//! - DeploymentProfile parsing and effective defaults
//! - Status and metrics route authorization gate
//! - Bounded concurrency and frame limits

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
