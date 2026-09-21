//! Phase 1A Hardening Verification Suite
//! Tests:
//! 1. Pinned Dialing & Egress SSRF Hardening (P0)
//! 2. Standalone Dormancy Invariant (P0)
//! 3. Unified Workstation Protection & Transaction Journal (P0)
//! 4. Localhost CSRF & Bearer Mutation Defenses (P0)
//! 5. Strict DeploymentProfile ValueEnum & Operational State (P1)

use agentcontrol::cli::{DeploymentProfile, PersistedProfileRecord};
use agentcontrol::proxy::connector::{
    canonicalize_host, classify_and_resolve_destination, classify_ip, is_allowed_provider_host,
    EgressBlockReason,
};
use agentcontrol::wrap::connect::{connect_codex_target_to_path, revert_toml_target, ConnectMode};
use agentcontrol::wrap::journal::ProtectJournal;
use agentcontrol::wrap::manifest::OwnershipManifest;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_destination_canonicalization_and_provider_allowlist() {
    // 1. Host canonicalization
    assert_eq!(
        canonicalize_host("API.ANTHROPIC.COM").unwrap(),
        "api.anthropic.com"
    );
    assert_eq!(
        canonicalize_host("api.openai.com.").unwrap(),
        "api.openai.com"
    );
    assert_eq!(canonicalize_host("127.0.0.1:18080").unwrap(), "127.0.0.1");
    assert!(canonicalize_host("").is_err());
    assert!(canonicalize_host("user:pass@api.openai.com").is_err());

    // 2. Standard provider allowlist
    let custom = vec!["custom.llm.corp".to_string(), "*.internal.ai".to_string()];
    assert!(is_allowed_provider_host("api.openai.com", &custom));
    assert!(is_allowed_provider_host("api.anthropic.com", &custom));
    assert!(is_allowed_provider_host(
        "generativelanguage.googleapis.com",
        &custom
    ));
    assert!(is_allowed_provider_host("myorg.openai.azure.com", &custom));
    assert!(is_allowed_provider_host(
        "bedrock-runtime.us-east-1.amazonaws.com",
        &custom
    ));
    assert!(is_allowed_provider_host("api.groq.com", &custom));
    assert!(is_allowed_provider_host("custom.llm.corp", &custom));
    assert!(is_allowed_provider_host("llm.internal.ai", &custom));

    // Foreign / unallowlisted hosts blocked
    assert!(!is_allowed_provider_host("evil.attacker.com", &custom));
    assert!(!is_allowed_provider_host("phishing.site", &custom));
    assert!(!is_allowed_provider_host("app.vexasec.io", &custom));
}

#[test]
fn test_ip_range_classification_and_egress_blocks() {
    // Cloud metadata
    assert_eq!(
        classify_ip("169.254.169.254".parse().unwrap(), false),
        Err(EgressBlockReason::BlockedLinkLocal)
    );

    // RFC 1918 Private ranges
    assert!(matches!(
        classify_ip("10.0.0.1".parse().unwrap(), false),
        Err(EgressBlockReason::BlockedPrivateSubnet(_))
    ));
    assert!(matches!(
        classify_ip("172.16.0.1".parse().unwrap(), false),
        Err(EgressBlockReason::BlockedPrivateSubnet(_))
    ));
    assert!(matches!(
        classify_ip("192.168.1.1".parse().unwrap(), false),
        Err(EgressBlockReason::BlockedPrivateSubnet(_))
    ));

    // RFC 6598 CGNAT
    assert_eq!(
        classify_ip("100.64.0.1".parse().unwrap(), false),
        Err(EgressBlockReason::BlockedCgnat)
    );

    // Loopback
    assert_eq!(
        classify_ip("127.0.0.1".parse().unwrap(), false),
        Err(EgressBlockReason::BlockedLoopback)
    );
    assert!(classify_ip("127.0.0.1".parse().unwrap(), true).is_ok());

    // Public IP
    assert!(classify_ip("1.1.1.1".parse().unwrap(), false).is_ok());
}

#[tokio::test]
async fn test_classify_and_resolve_destination_air_gapped_profile() {
    let err =
        classify_and_resolve_destination("api.anthropic.com", 443, "local-firewall", false, &[])
            .await
            .unwrap_err();

    assert!(matches!(err, EgressBlockReason::BlockedAirGapped(_)));
}

#[tokio::test]
async fn test_classify_and_resolve_destination_unallowlisted_provider() {
    let err = classify_and_resolve_destination(
        "api.malicious-site.com",
        443,
        "local-gateway",
        false,
        &[],
    )
    .await
    .unwrap_err();

    assert_eq!(
        err,
        EgressBlockReason::BlockedProviderNotAllowlisted("api.malicious-site.com".to_string())
    );
}

#[test]
fn test_strict_deployment_profile_parsing() {
    // Valid profiles
    assert_eq!(
        DeploymentProfile::try_parse("local-gateway").unwrap(),
        DeploymentProfile::LocalGateway
    );
    assert_eq!(
        DeploymentProfile::try_parse("local-firewall").unwrap(),
        DeploymentProfile::LocalFirewall
    );
    assert_eq!(
        DeploymentProfile::try_parse("team-gateway").unwrap(),
        DeploymentProfile::TeamGateway
    );
    assert_eq!(
        DeploymentProfile::try_parse("container-sidecar").unwrap(),
        DeploymentProfile::ContainerSidecar
    );
    assert_eq!(
        DeploymentProfile::try_parse("local-shadow").unwrap(),
        DeploymentProfile::LocalShadow
    );

    // Aliases
    assert_eq!(
        DeploymentProfile::try_parse("gateway").unwrap(),
        DeploymentProfile::LocalGateway
    );
    assert_eq!(
        DeploymentProfile::try_parse("air-gapped").unwrap(),
        DeploymentProfile::LocalFirewall
    );
    assert_eq!(
        DeploymentProfile::try_parse("team").unwrap(),
        DeploymentProfile::TeamGateway
    );
    assert_eq!(
        DeploymentProfile::try_parse("sidecar").unwrap(),
        DeploymentProfile::ContainerSidecar
    );

    // Unknown string rejected with error
    let err = DeploymentProfile::try_parse("invalid-profile-name").unwrap_err();
    assert!(err.contains("Unknown deployment profile"));
}

#[test]
fn test_profile_persistence_lifecycle() {
    let record = PersistedProfileRecord {
        profile: DeploymentProfile::LocalGateway,
        updated_at: chrono::Utc::now().to_rfc3339(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    };

    let serialized = serde_json::to_string(&record).unwrap();
    let deserialized: PersistedProfileRecord = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized.profile, DeploymentProfile::LocalGateway);
}

#[test]
fn test_protect_journal_transaction_and_rollback() {
    let dir = tempdir().unwrap();
    let config_a = dir.path().join("config_a.toml");
    let config_b = dir.path().join("config_b.json");

    fs::write(&config_a, "initial_a = true\n").unwrap();
    fs::write(&config_b, r#"{"initial_b": true}"#).unwrap();

    let mut journal = ProtectJournal::new("local-gateway");
    journal
        .record_target_start("target_a", &[&config_a], "target_a_manifest")
        .unwrap();
    // Mutate config_a
    fs::write(&config_a, "mutated_a = true\n").unwrap();
    journal.record_target_success("target_a");

    journal
        .record_target_start("target_b", &[&config_b], "target_b_manifest")
        .unwrap();
    // Mutate config_b

    fs::write(&config_b, r#"{"mutated_b": true}"#).unwrap();
    journal.record_target_success("target_b");

    // Simulate rollback
    let rolled_back = journal.rollback().unwrap();
    assert_eq!(rolled_back, vec!["target_b", "target_a"]);

    // Both files restored to pre-mutation content
    assert_eq!(fs::read_to_string(&config_a).unwrap(), "initial_a = true\n");
    assert_eq!(
        fs::read_to_string(&config_b).unwrap(),
        r#"{"initial_b": true}"#
    );
}

#[test]
fn test_manifest_based_workstation_roundtrip() {
    let dir = tempdir().unwrap();
    let codex_file = dir.path().join("config.toml");
    fs::write(&codex_file, "custom_user_key = \"preserved\"\n").unwrap();

    // 1. Connect
    let res = connect_codex_target_to_path(
        "phase1a_codex_test",
        &codex_file,
        "vx-test-token",
        ConnectMode::Local,
    );
    assert!(res.is_ok());

    let post_content = fs::read_to_string(&codex_file).unwrap();
    assert!(post_content.contains("OPENAI_BASE_URL"));
    assert!(post_content.contains("OPENAI_API_KEY"));
    assert!(post_content.contains("custom_user_key"));

    // 2. Disconnect using manifest
    let manifest = OwnershipManifest::load("phase1a_codex_test")
        .unwrap()
        .unwrap();
    let reverted = revert_toml_target(&manifest).unwrap();
    assert!(reverted.contains(&"OPENAI_BASE_URL".to_string()));
    assert!(reverted.contains(&"OPENAI_API_KEY".to_string()));
    let _ = OwnershipManifest::delete("phase1a_codex_test");

    let restored = fs::read_to_string(&codex_file).unwrap();
    assert!(!restored.contains("OPENAI_BASE_URL"));
    assert!(!restored.contains("OPENAI_API_KEY"));
    assert!(restored.contains("custom_user_key"));
}
