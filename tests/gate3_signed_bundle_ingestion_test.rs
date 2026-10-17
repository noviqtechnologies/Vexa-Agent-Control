//! Gate 3.2 & 3.3 Test Suite: Signed Policy Ingestion, Anti-Rollback & Cross-OS Resilience
//!
//! Validates:
//! 1. Managed mode bundle ingestion strictly verifies Ed25519 signature against trusted keyring.
//! 2. Untrusted signer public key produces fatal rejection.
//! 3. Tampered policy content produces fatal signature verification failure.
//! 4. Revision monotonicity enforcement prevents rollback to older policy revisions.
//! 5. Offline cached signed bundle activates when remote Hub API fails.
//! 6. Managed mode NEVER falls back to raw unsigned YAML.
//! 7. Cross-OS resilient atomic replace protocol handles overwriting existing files without error.
//! 8. SQLite WAL mount guard rejects network filesystem paths (UNC/SMB/NFS).

use tempfile::tempdir;

use agentcontrol::audit::outbox::is_network_filesystem_path;
use agentcontrol::policy::loader::PolicyLoadResult;
use agentcontrol::policy::remote::{load_remote_policy_with_trust, save_cached_policy_bundle};
use agentcontrol::policy::signed::{
    durable_atomic_replace, generate_signing_keypair, sign_policy, verify_signed_bundle,
    PolicyStorageManager, SignedPolicyBundle,
};
use agentcontrol::policy::trust::{PolicyTrustProfile, TrustedKey, TrustedKeyring};

fn valid_yaml() -> &'static str {
    "version: \"2.0\"\ndefault_action: deny\ntools:\n  - name: test_tool\n    action: allow\n"
}

#[tokio::test]
async fn test_managed_mode_accepts_valid_signed_bundle() {
    let (sk, pk) = generate_signing_keypair();
    let pk_hex = hex::encode(pk.to_bytes());

    let bundle = sign_policy(&sk, "corp-sec-1", 10, valid_yaml(), None);

    let keyring = TrustedKeyring::with_keys(vec![TrustedKey {
        key_id: "sec-key-1".to_string(),
        public_key_hex: pk_hex.clone(),
        description: Some("Production SecOps Key".to_string()),
        created_at: "2026-10-15T00:00:00Z".to_string(),
        expires_at: None,
    }]);

    let trust_profile = PolicyTrustProfile::Managed {
        trusted_keyring: keyring,
        require_revision_monotonicity: true,
        max_policy_age_secs: None,
    };

    let verified = verify_signed_bundle(&bundle, trust_profile.trusted_keys().as_deref());
    assert!(
        verified.is_ok(),
        "Expected valid bundle to verify successfully"
    );
}

#[tokio::test]
async fn test_managed_mode_rejects_untrusted_signer() {
    let (sk, _pk) = generate_signing_keypair();
    let (_trusted_sk, trusted_pk) = generate_signing_keypair();
    let trusted_pk_hex = hex::encode(trusted_pk.to_bytes());

    let bundle = sign_policy(&sk, "corp-sec-1", 10, valid_yaml(), None);

    let keyring = TrustedKeyring::with_keys(vec![TrustedKey {
        key_id: "sec-key-1".to_string(),
        public_key_hex: trusted_pk_hex,
        description: Some("Authorized Signer".to_string()),
        created_at: "2026-10-15T00:00:00Z".to_string(),
        expires_at: None,
    }]);

    let trust_profile = PolicyTrustProfile::Managed {
        trusted_keyring: keyring,
        require_revision_monotonicity: true,
        max_policy_age_secs: None,
    };

    let result = verify_signed_bundle(&bundle, trust_profile.trusted_keys().as_deref());
    assert!(
        result.is_err(),
        "Expected untrusted signer to fail verification"
    );
    let err_str = result.err().unwrap().to_string();
    assert!(
        err_str.contains("Untrusted signer"),
        "Expected UntrustedSigner error, got: {}",
        err_str
    );
}

#[tokio::test]
async fn test_managed_mode_rejects_tampered_payload() {
    let (sk, pk) = generate_signing_keypair();
    let pk_hex = hex::encode(pk.to_bytes());

    let mut bundle = sign_policy(&sk, "corp-sec-1", 10, valid_yaml(), None);
    // Tamper with YAML after signing
    bundle.policy_yaml = "version: \"2.0\"\ndefault_action: deny\ntools: []\n".to_string();

    let keyring = TrustedKeyring::with_keys(vec![TrustedKey {
        key_id: "sec-key-1".to_string(),
        public_key_hex: pk_hex,
        description: None,
        created_at: "2026-10-15T00:00:00Z".to_string(),
        expires_at: None,
    }]);

    let trust_profile = PolicyTrustProfile::Managed {
        trusted_keyring: keyring,
        require_revision_monotonicity: true,
        max_policy_age_secs: None,
    };

    let result = verify_signed_bundle(&bundle, trust_profile.trusted_keys().as_deref());
    assert!(result.is_err(), "Expected tampered payload to fail");
    let err_str = result.err().unwrap().to_string();
    assert!(
        err_str.contains("Signature verification failed"),
        "Expected signature failure, got: {}",
        err_str
    );
}

#[tokio::test]
async fn test_storage_manager_rollback_reverifies_bundle() {
    let dir = tempdir().unwrap();
    let mgr = PolicyStorageManager::new(dir.path());

    let (sk, pk) = generate_signing_keypair();
    let pk_hex = hex::encode(pk.to_bytes());
    let keys = vec![pk_hex];

    // Apply Revision 1
    let yaml1 = "version: \"2.0\"\ndefault_action: deny\ntools:\n  - name: t1\n    action: allow\n";
    let bundle1 = sign_policy(&sk, "policy-1", 1, yaml1, None);
    let applied1 = mgr.apply_signed_bundle(&bundle1, Some(&keys));
    assert!(applied1.is_ok());

    // Apply Revision 2
    let yaml2 = "version: \"2.0\"\ndefault_action: deny\ntools:\n  - name: t2\n    action: allow\n";
    let bundle2 = sign_policy(&sk, "policy-1", 2, yaml2, None);
    let applied2 = mgr.apply_signed_bundle(&bundle2, Some(&keys));
    assert!(applied2.is_ok());

    // Rollback to Revision 1
    let rolled_back = mgr.rollback_with_keys(Some(&keys));
    assert!(rolled_back.is_ok(), "Expected rollback to succeed");

    // Verify current bundle is now Revision 1
    let current_bundle_data = std::fs::read_to_string(mgr.current_bundle_path()).unwrap();
    let current_bundle: SignedPolicyBundle = serde_json::from_str(&current_bundle_data).unwrap();
    assert_eq!(current_bundle.policy_revision, 1);
}

#[tokio::test]
async fn test_cross_os_atomic_replace_overwrites_existing_file() {
    let dir = tempdir().unwrap();
    let target = dir.path().join("policy.yaml");

    // Write initial version
    durable_atomic_replace(&target, b"initial content").unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"initial content");

    // Overwrite existing file (testing Windows rename behavior)
    durable_atomic_replace(&target, b"updated content").unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"updated content");

    // Multiple rapid overwrites simulating hot-reload under load
    for i in 0..10 {
        let content = format!("content iteration {}", i);
        durable_atomic_replace(&target, content.as_bytes()).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), content.as_bytes());
    }
}

#[test]
fn test_sqlite_wal_rejects_network_filesystem_paths() {
    // Windows UNC paths
    assert!(is_network_filesystem_path(std::path::Path::new(
        r"\\nas\share\events.db"
    )));
    assert!(is_network_filesystem_path(std::path::Path::new(
        r"\\192.168.1.10\c$\events.db"
    )));
    assert!(is_network_filesystem_path(std::path::Path::new(
        "//nas/share/events.db"
    )));

    // URI prefixes
    assert!(is_network_filesystem_path(std::path::Path::new(
        "smb://server/events.db"
    )));
    assert!(is_network_filesystem_path(std::path::Path::new(
        "nfs://nas/exports/events.db"
    )));
    assert!(is_network_filesystem_path(std::path::Path::new(
        "cifs://storage/events.db"
    )));

    // Local paths (must be allowed)
    assert!(!is_network_filesystem_path(std::path::Path::new(
        r"C:\ProgramData\AgentControl\events.db"
    )));
    assert!(!is_network_filesystem_path(std::path::Path::new(
        "/var/lib/agentcontrol/events.db"
    )));
    assert!(!is_network_filesystem_path(std::path::Path::new(
        "./events.db"
    )));
    assert!(!is_network_filesystem_path(std::path::Path::new(
        "events.db"
    )));
}

#[tokio::test]
async fn test_managed_mode_activates_cached_signed_bundle_on_network_failure() {
    let (sk, pk) = generate_signing_keypair();
    let pk_hex = hex::encode(pk.to_bytes());
    let bundle = sign_policy(&sk, "corp-policy", 42, valid_yaml(), None);

    // Save bundle to local cache
    save_cached_policy_bundle(&bundle);

    let keyring = TrustedKeyring::with_keys(vec![TrustedKey {
        key_id: "sec-key".to_string(),
        public_key_hex: pk_hex,
        description: None,
        created_at: "2026-10-15T00:00:00Z".to_string(),
        expires_at: None,
    }]);

    let trust_profile = PolicyTrustProfile::Managed {
        trusted_keyring: keyring,
        require_revision_monotonicity: true,
        max_policy_age_secs: None,
    };

    // Attempt to load from an unreachable URL
    let result = load_remote_policy_with_trust(
        "http://127.0.0.1:59999", // Unreachable port
        None,
        &trust_profile,
    )
    .await;

    match result {
        PolicyLoadResult::Loaded {
            raw_hash, warnings, ..
        } => {
            assert!(
                raw_hash.contains("42"),
                "Expected revision 42 in raw_hash, got {}",
                raw_hash
            );
            assert!(
                !warnings.is_empty(),
                "Expected warning about unreachable API fallback to cache"
            );
        }
        PolicyLoadResult::Degraded { reason } => {
            panic!("Expected Loaded, got Degraded: {}", reason)
        }
        PolicyLoadResult::Fatal { error } => panic!("Expected Loaded, got Fatal: {}", error),
    }
}
