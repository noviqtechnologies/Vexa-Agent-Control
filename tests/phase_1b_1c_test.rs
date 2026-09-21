//! Automated integration tests for Phase 1B and 1C (Team Upgrade, Offline Cache, Dual-Store Maintenance).

use agentcontrol::audit::logger::{AuditEntry, ZERO_HMAC};
use agentcontrol::audit::maintenance::{run_backup, run_verify_db};
use agentcontrol::audit::verifier::{verify_chain, verify_chain_with_secret, VerifyResult};
use agentcontrol::cli::{load_persisted_profile, save_persisted_profile, DeploymentProfile};
use agentcontrol::policy::remote::{load_cached_policy, save_cached_policy};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fs;
use tempfile::tempdir;

type HmacSha256 = Hmac<Sha256>;

#[test]
fn test_profile_state_machine_transitions() {
    // 1. Initial LocalGateway profile
    assert!(save_persisted_profile(DeploymentProfile::LocalGateway).is_ok());
    let loaded = load_persisted_profile();
    assert_eq!(loaded, Some(DeploymentProfile::LocalGateway));

    // 2. Transition to TeamGateway (simulate login / enroll)
    assert!(save_persisted_profile(DeploymentProfile::TeamGateway).is_ok());
    let loaded = load_persisted_profile();
    assert_eq!(loaded, Some(DeploymentProfile::TeamGateway));

    // 3. Transition back to LocalGateway (simulate logout)
    assert!(save_persisted_profile(DeploymentProfile::LocalGateway).is_ok());
    let loaded = load_persisted_profile();
    assert_eq!(loaded, Some(DeploymentProfile::LocalGateway));
}

#[test]
fn test_offline_cached_policy_integrity() {
    let yaml = "version: '2.0'\ndefault_action: deny\nrules: []\n";
    let hash = "sha256:abcd1234efgh5678";

    // Save policy to cache
    save_cached_policy(yaml, hash);

    // Compute expected hash
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(yaml.as_bytes());
    let expected_hash = format!("sha256:{}", hex::encode(hasher.finalize()));

    // When hash file matches actual content hash:
    save_cached_policy(yaml, &expected_hash);
    let loaded = load_cached_policy();
    assert!(loaded.is_some());
    let (loaded_yaml, loaded_hash) = loaded.unwrap();
    assert_eq!(loaded_yaml, yaml);
    assert_eq!(loaded_hash, expected_hash);

    // When content is tampered with:
    save_cached_policy("tampered content: evil", &expected_hash);
    let tampered = load_cached_policy();
    assert!(
        tampered.is_none(),
        "Tampered policy must fail hash verification"
    );
}

#[test]
fn test_audit_hmac_chain_verification_and_tamper_detection() {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let secret = b"super-secret-hmac-key-32-bytes!!";

    let mut prev_hmac = ZERO_HMAC.to_string();
    let mut lines = Vec::new();

    // Generate 5 cryptographically valid chained entries
    for i in 0..5 {
        let mut entry = AuditEntry {
            ts: "2026-09-20T12:00:00Z".to_string(),
            session_id: "test-session".to_string(),
            event: "tool_allow".to_string(),
            tool_name: Some(format!("tool_{}", i)),
            params_hash: None,
            params: None,
            reason: None,
            latency_ms: Some(1.2),
            identity_sub: Some("dev@acme.com".to_string()),
            identity_email: Some("dev@acme.com".to_string()),
            policy_hash: None,
            request_ip: Some("127.0.0.1".to_string()),
            matched_group_id: None,
            entry_index: i,
            prev_hmac: prev_hmac.clone(),
            hmac: None,
        };

        let canonical = serde_json::to_string(&entry).unwrap();
        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(canonical.as_bytes());
        let hmac_hex = hex::encode(mac.finalize().into_bytes());
        entry.hmac = Some(hmac_hex.clone());
        prev_hmac = hmac_hex;

        lines.push(serde_json::to_string(&entry).unwrap());
    }

    fs::write(&log_path, lines.join("\n")).unwrap();

    // 1. Verify chain consistency without secret
    match verify_chain(&log_path) {
        VerifyResult::Valid { entry_count } => assert_eq!(entry_count, 5),
        other => panic!("Expected valid chain, got: {:?}", other),
    }

    // 2. Verify with full HMAC secret recomputation
    match verify_chain_with_secret(&log_path, secret) {
        VerifyResult::Valid { entry_count } => assert_eq!(entry_count, 5),
        other => panic!("Expected valid HMAC verification, got: {:?}", other),
    }

    // 3. Tamper with entry 2
    let mut tampered_entry: AuditEntry = serde_json::from_str(&lines[2]).unwrap();
    tampered_entry.reason = Some("tampered field injected".to_string());
    lines[2] = serde_json::to_string(&tampered_entry).unwrap();
    fs::write(&log_path, lines.join("\n")).unwrap();

    // 4. Verify HMAC recomputation catches single-field payload modification
    match verify_chain_with_secret(&log_path, secret) {
        VerifyResult::Invalid {
            entry_index,
            reason,
        } => {
            assert_eq!(entry_index, 2);
            assert!(reason.contains("HMAC mismatch"));
        }
        other => panic!("Expected tamper detection at entry 2, got: {:?}", other),
    }
}

#[test]
fn test_dual_store_backup_and_sqlite_vacuum() {
    let backup_dir = tempdir().unwrap();
    let dest = backup_dir.path().join("test_backup");

    // Run backup
    let code = run_backup(Some(dest.clone()));
    assert_eq!(code, 0);

    // Verify directory exists
    assert!(dest.exists());

    // Create an isolated test SQLite database and verify it with run_verify_db
    let test_db = backup_dir.path().join("verified_events.db");
    let conn = rusqlite::Connection::open(&test_db).unwrap();
    conn.execute("CREATE TABLE test_tab (id INTEGER PRIMARY KEY);", [])
        .unwrap();
    drop(conn);

    let verify_code = run_verify_db(
        Some(backup_dir.path().join("nonexistent_audit.jsonl")),
        Some(test_db),
    );
    assert_eq!(verify_code, 0);
}
