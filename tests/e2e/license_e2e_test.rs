//! End-to-End Enterprise & Team License Validation Tests
//!
//! Verifies cross-engine feature flag compatibility and canonical aliasing
//! between Go control plane and Rust gateway.

use agentcontrol::license::generate::generate_license;
use agentcontrol::license::validator::LicenseValidator;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::SigningKey;
use rand::RngCore;
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn test_license_e2e_canonical_spend_v2_aliasing() {
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    let key_pkcs8 = signing_key.to_pkcs8_der().unwrap();

    let mut key_file = NamedTempFile::new().unwrap();
    key_file.write_all(key_pkcs8.as_bytes()).unwrap();

    // 1. Generate license containing spend_v2 (matching Go issuer output)
    let token = generate_license(
        "acme-org",
        "team",
        25,
        30,
        key_file.path(),
        Some(vec!["spend_v2".to_string(), "siem_export".to_string()]),
    )
    .expect("generate license");

    let validator = LicenseValidator::from_public_key_bytes(&verifying_key.to_bytes());
    let validated = validator.validate(&token).expect("validate license token");

    assert_eq!(validated.org_id, "acme-org");
    // Verifies aliasing: spend_v2 satisfies spend_caps requirement in Rust gateway
    assert!(validator.has_feature(&validated, "spend_caps"));
    assert!(validator.has_feature(&validated, "spend_v2"));
    // Verifies aliasing: siem_export satisfies siem_aggregation requirement
    assert!(validator.has_feature(&validated, "siem_aggregation"));
    assert!(validator.has_feature(&validated, "siem_export"));
    assert!(!validator.has_feature(&validated, "unlicensed_feature"));
}

#[test]
fn test_license_e2e_enterprise_default_tier_features() {
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    let key_pkcs8 = signing_key.to_pkcs8_der().unwrap();

    let mut key_file = NamedTempFile::new().unwrap();
    key_file.write_all(key_pkcs8.as_bytes()).unwrap();

    // 2. Generate default Enterprise tier license
    let token = generate_license(
        "enterprise-corp",
        "enterprise",
        100,
        365,
        key_file.path(),
        None,
    )
    .expect("generate enterprise license");

    let validator = LicenseValidator::from_public_key_bytes(&verifying_key.to_bytes());
    let validated = validator.validate(&token).expect("validate token");

    assert_eq!(validated.org_id, "enterprise-corp");
    assert!(validator.has_feature(&validated, "spend_caps"));
    assert!(validator.has_feature(&validated, "siem_aggregation"));
    assert!(validator.has_feature(&validated, "airgap_oidc"));
    assert!(validator.has_feature(&validated, "compliance_reports"));
    assert!(validator.has_feature(&validated, "group_policies"));
    assert!(validator.has_feature(&validated, "device_governance"));
}

#[test]
fn test_license_e2e_wildcard_grants_all_features() {
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    let key_pkcs8 = signing_key.to_pkcs8_der().unwrap();

    let mut key_file = NamedTempFile::new().unwrap();
    key_file.write_all(key_pkcs8.as_bytes()).unwrap();

    let token = generate_license(
        "admin-root",
        "enterprise",
        1000,
        30,
        key_file.path(),
        Some(vec!["*".to_string()]),
    )
    .expect("generate wildcard license");

    let validator = LicenseValidator::from_public_key_bytes(&verifying_key.to_bytes());
    let validated = validator.validate(&token).expect("validate token");

    assert!(validator.has_feature(&validated, "any_custom_feature_123"));
    assert!(validator.has_feature(&validated, "spend_caps"));
}
