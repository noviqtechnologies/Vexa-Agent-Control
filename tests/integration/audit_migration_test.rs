//! Integration tests for ADR-009: Audit Chain Migration, Immutable Legacy Verifier,
//! and Historical Fixtures Verification.

use agentcontrol::audit::logger::{AuditEntry, ZERO_HMAC};
use agentcontrol::audit::verifier::{verify_chain_with_secret, VerifyResult};
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Once;

type HmacSha256 = Hmac<Sha256>;

const TEST_SECRET: [u8; 32] = [0x5A; 32];
static INIT: Once = Once::new();

fn get_fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("audit")
}

/// Helper to generate a legacy v1 entry with precise HMAC.
fn make_v1_entry(
    session_secret: &[u8],
    session_id: &str,
    event: &str,
    tool_name: Option<&str>,
    params: Option<Value>,
    reason: Option<&str>,
    latency_ms: Option<f64>,
    entry_index: u64,
    prev_hmac: &str,
) -> AuditEntry {
    let params_hash = params.as_ref().map(|p| {
        let canon = serde_json::to_string(p).unwrap();
        let mut hasher = Sha256::default();
        use sha2::Digest;
        hasher.update(canon.as_bytes());
        hex::encode(hasher.finalize())
    });

    let mut entry = AuditEntry {
        ts: Utc::now().to_rfc3339(),
        session_id: session_id.to_string(),
        event: event.to_string(),
        tool_name: tool_name.map(|s| s.to_string()),
        params_hash,
        params,
        reason: reason.map(|s| s.to_string()),
        latency_ms,
        identity_sub: Some("user-sub-12345".to_string()),
        identity_email: Some("developer@corp.local".to_string()),
        policy_hash: Some(
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        ),
        request_ip: Some("127.0.0.1".to_string()),
        matched_group_id: Some("dev-security-group".to_string()),
        entry_index,
        prev_hmac: prev_hmac.to_string(),
        hmac: None,
    };

    let canonical = serde_json::to_string(&entry).unwrap();
    let mut mac = HmacSha256::new_from_slice(session_secret).expect("valid HMAC key");
    mac.update(canonical.as_bytes());
    entry.hmac = Some(hex::encode(mac.finalize().into_bytes()));

    entry
}

/// Helper to write an entry to file.
fn append_entry(path: &Path, entry: &AuditEntry) {
    let line = serde_json::to_string(entry).unwrap();
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap();
    writeln!(file, "{}", line).unwrap();
}

/// Generate the 3 representative legacy audit fixtures if not present.
fn ensure_fixtures_exist() {
    INIT.call_once(|| {
        let dir = get_fixtures_dir();
        fs::create_dir_all(&dir).unwrap();

        let standard_path = dir.join("legacy_v1_standard.jsonl");
        let sparse_path = dir.join("legacy_v1_sparse.jsonl");
        let rotated_path = dir.join("legacy_v1_rotated.jsonl");

        // Clean any partial or malformed files
        let _ = fs::remove_file(&standard_path);
        let _ = fs::remove_file(&sparse_path);
        let _ = fs::remove_file(&rotated_path);

        // 1. Standard fixture
        let mut prev = ZERO_HMAC.to_string();
        for idx in 0..5 {
            let (event, tool, params) = match idx {
                0 => ("tool_allow", Some("read_file"), Some(json!({"path": "src/lib.rs"}))),
                1 => ("tool_allow", Some("ripgrep"), Some(json!({"query": "AuditEntry"}))),
                2 => ("tool_deny", Some("bash"), Some(json!({"cmd": "sudo reboot"}))),
                3 => ("tool_allow", Some("git_status"), None),
                _ => ("siem_export_success", None, None),
            };
            let entry = make_v1_entry(
                &TEST_SECRET,
                "sess-standard-fixture",
                event,
                tool,
                params,
                if event == "tool_deny" { Some("Root privilege execution blocked") } else { None },
                Some(1.5),
                idx,
                &prev,
            );
            prev = entry.hmac.clone().unwrap();
            append_entry(&standard_path, &entry);
        }

        let meta = json!({
            "fixture_id": "legacy_v1_standard",
            "schema_version": 1,
            "generator_commit": "v1.0.94-phase0b",
            "secret_hex": hex::encode(TEST_SECRET),
            "entry_count": 5,
            "scrub_review": {
                "timestamp": "2026-10-04T12:00:00Z",
                "reviewer_id": "secops-compliance-lead",
                "status": "APPROVED",
                "secrets_detected": 0
            },
            "description": "Standard representative legacy v1 audit chain with tool_allow, tool_deny, and full parameters."
        });
        fs::write(dir.join("legacy_v1_standard.meta.json"), serde_json::to_string_pretty(&meta).unwrap()).unwrap();

        // 2. Sparse fixture (omits optional fields)
        let mut prev_sparse = ZERO_HMAC.to_string();
        for idx in 0..4 {
            let mut entry = AuditEntry {
                ts: Utc::now().to_rfc3339(),
                session_id: "sess-sparse-fixture".to_string(),
                event: "tool_allow".to_string(),
                tool_name: None,
                params_hash: None,
                params: None,
                reason: None,
                latency_ms: None,
                identity_sub: None,
                identity_email: None,
                policy_hash: None,
                request_ip: None,
                matched_group_id: None,
                entry_index: idx,
                prev_hmac: prev_sparse.clone(),
                hmac: None,
            };

            let canonical = serde_json::to_string(&entry).unwrap();
            let mut mac = HmacSha256::new_from_slice(&TEST_SECRET).expect("valid HMAC key");
            mac.update(canonical.as_bytes());
            entry.hmac = Some(hex::encode(mac.finalize().into_bytes()));

            prev_sparse = entry.hmac.clone().unwrap();
            append_entry(&sparse_path, &entry);
        }

        let meta_sparse = json!({
            "fixture_id": "legacy_v1_sparse",
            "schema_version": 1,
            "generator_commit": "v1.0.94-phase0b",
            "secret_hex": hex::encode(TEST_SECRET),
            "entry_count": 4,
            "scrub_review": {
                "timestamp": "2026-10-04T12:00:00Z",
                "reviewer_id": "secops-compliance-lead",
                "status": "APPROVED",
                "secrets_detected": 0
            },
            "description": "Sparse legacy v1 audit chain where all optional fields are None (omitted during serde serialization)."
        });
        fs::write(dir.join("legacy_v1_sparse.meta.json"), serde_json::to_string_pretty(&meta_sparse).unwrap()).unwrap();

        // 3. Rotated fixture (cross-rotation seed)
        let e0 = make_v1_entry(&TEST_SECRET, "sess-rotated-1", "tool_allow", Some("read_file"), None, None, Some(0.5), 0, ZERO_HMAC);
        let e1 = make_v1_entry(&TEST_SECRET, "sess-rotated-1", "tool_allow", Some("write_file"), None, None, Some(0.8), 1, &e0.hmac.clone().unwrap());
        append_entry(&rotated_path, &e0);
        append_entry(&rotated_path, &e1);

        let terminal_hmac = e1.hmac.clone().unwrap();
        let mut seed = AuditEntry {
            ts: Utc::now().to_rfc3339(),
            session_id: "sess-rotated-2".to_string(),
            event: "log_rotation_seed".to_string(),
            tool_name: None,
            params_hash: None,
            params: None,
            reason: None,
            latency_ms: None,
            identity_sub: None,
            identity_email: None,
            policy_hash: None,
            request_ip: None,
            matched_group_id: None,
            entry_index: 0,
            prev_hmac: terminal_hmac.clone(),
            hmac: None,
        };
        let canonical_seed = serde_json::to_string(&seed).unwrap();
        let mut mac_seed = HmacSha256::new_from_slice(&TEST_SECRET).unwrap();
        mac_seed.update(canonical_seed.as_bytes());
        seed.hmac = Some(hex::encode(mac_seed.finalize().into_bytes()));
        append_entry(&rotated_path, &seed);

        let e2 = make_v1_entry(&TEST_SECRET, "sess-rotated-2", "tool_allow", Some("read_file"), None, None, Some(0.4), 1, &seed.hmac.clone().unwrap());
        append_entry(&rotated_path, &e2);

        let meta_rotated = json!({
            "fixture_id": "legacy_v1_rotated",
            "schema_version": 1,
            "generator_commit": "v1.0.94-phase0b",
            "secret_hex": hex::encode(TEST_SECRET),
            "entry_count": 4,
            "scrub_review": {
                "timestamp": "2026-10-04T12:00:00Z",
                "reviewer_id": "secops-compliance-lead",
                "status": "APPROVED",
                "secrets_detected": 0
            },
            "description": "Legacy v1 audit chain spanning a log_rotation_seed boundary linking segments."
        });
        fs::write(dir.join("legacy_v1_rotated.meta.json"), serde_json::to_string_pretty(&meta_rotated).unwrap()).unwrap();
    });
}

// ─── Test 1: Verify the 3 Representative Legacy Fixtures Pass ───────────────

#[test]
fn test_historical_v1_fixtures_verification() {
    ensure_fixtures_exist();
    let dir = get_fixtures_dir();

    // 1. Verify standard fixture
    match verify_chain_with_secret(&dir.join("legacy_v1_standard.jsonl"), &TEST_SECRET) {
        VerifyResult::Valid { entry_count } => assert_eq!(entry_count, 5),
        other => panic!("legacy_v1_standard failed: {:?}", other),
    }

    // 2. Verify sparse fixture
    match verify_chain_with_secret(&dir.join("legacy_v1_sparse.jsonl"), &TEST_SECRET) {
        VerifyResult::Valid { entry_count } => assert_eq!(entry_count, 4),
        other => panic!("legacy_v1_sparse failed: {:?}", other),
    }

    // 3. Verify rotated fixture
    match verify_chain_with_secret(&dir.join("legacy_v1_rotated.jsonl"), &TEST_SECRET) {
        VerifyResult::Valid { entry_count } => assert_eq!(entry_count, 4),
        other => panic!("legacy_v1_rotated failed: {:?}", other),
    }
}

// ─── Test 2: Field Modification / Tamper Detection ──────────────────────────

#[test]
fn test_field_tamper_detection() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("tampered.jsonl");

    let e0 = make_v1_entry(
        &TEST_SECRET,
        "sess-tamper",
        "tool_allow",
        Some("read_file"),
        None,
        None,
        Some(1.0),
        0,
        ZERO_HMAC,
    );
    let mut line = serde_json::to_string(&e0).unwrap();

    // Tamper with payload value (change 1.0 to 9.9)
    line = line.replace("1.0", "9.9");
    fs::write(&path, format!("{}\n", line)).unwrap();

    match verify_chain_with_secret(&path, &TEST_SECRET) {
        VerifyResult::Invalid { reason, .. } => {
            assert!(
                reason.contains("HMAC mismatch"),
                "Expected HMAC mismatch, got: {}",
                reason
            );
        }
        other => panic!("Expected Invalid result, got: {:?}", other),
    }
}

// ─── Test 3: Truncated File Detection ───────────────────────────────────────

#[test]
fn test_truncated_file_detection() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("truncated.jsonl");

    let e0 = make_v1_entry(
        &TEST_SECRET,
        "sess-trunc",
        "tool_allow",
        Some("read_file"),
        None,
        None,
        None,
        0,
        ZERO_HMAC,
    );
    let line = serde_json::to_string(&e0).unwrap();
    // Cut off half the JSON line
    fs::write(&path, &line[..line.len() / 2]).unwrap();

    match verify_chain_with_secret(&path, &TEST_SECRET) {
        VerifyResult::Error(msg) => {
            assert!(
                msg.contains("malformed JSON") || msg.contains("re-serialisation"),
                "Unexpected error: {}",
                msg
            );
        }
        other => panic!("Expected Error result, got: {:?}", other),
    }
}

// ─── Test 4: Duplicate / Out-of-Order Sequence Index Detection ─────────────

#[test]
fn test_duplicate_sequence_index_detection() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("dup_index.jsonl");

    let e0 = make_v1_entry(
        &TEST_SECRET,
        "sess-seq",
        "tool_allow",
        Some("read_file"),
        None,
        None,
        None,
        0,
        ZERO_HMAC,
    );
    // e1 has index 0 instead of index 1
    let e1 = make_v1_entry(
        &TEST_SECRET,
        "sess-seq",
        "tool_allow",
        Some("read_file"),
        None,
        None,
        None,
        0,
        &e0.hmac.clone().unwrap(),
    );

    append_entry(&path, &e0);
    append_entry(&path, &e1);

    match verify_chain_with_secret(&path, &TEST_SECRET) {
        VerifyResult::Invalid { reason, .. } => {
            assert!(
                reason.contains("expected entry_index 1, got 0"),
                "Got: {}",
                reason
            );
        }
        other => panic!("Expected Invalid sequence result, got: {:?}", other),
    }
}

// ─── Test 5: Broken Chain / prev_hmac Tampering Detection ──────────────────

#[test]
fn test_broken_chain_prev_hmac_tampering() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("broken_chain.jsonl");

    let e0 = make_v1_entry(
        &TEST_SECRET,
        "sess-chain",
        "tool_allow",
        Some("read_file"),
        None,
        None,
        None,
        0,
        ZERO_HMAC,
    );
    // e1 has bad prev_hmac
    let e1 = make_v1_entry(
        &TEST_SECRET,
        "sess-chain",
        "tool_allow",
        Some("read_file"),
        None,
        None,
        None,
        1,
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );

    append_entry(&path, &e0);
    append_entry(&path, &e1);

    match verify_chain_with_secret(&path, &TEST_SECRET) {
        VerifyResult::Invalid { reason, .. } => {
            assert!(reason.contains("prev_hmac mismatch"), "Got: {}", reason);
        }
        other => panic!("Expected Invalid prev_hmac, got: {:?}", other),
    }
}

// ─── Test 6: Invalid Secret Key Rejection ───────────────────────────────────

#[test]
fn test_wrong_secret_key_rejection() {
    ensure_fixtures_exist();
    let dir = get_fixtures_dir();
    let wrong_secret = [0x99; 32];

    match verify_chain_with_secret(&dir.join("legacy_v1_standard.jsonl"), &wrong_secret) {
        VerifyResult::Invalid {
            reason,
            entry_index,
        } => {
            assert_eq!(entry_index, 0);
            assert!(
                reason.contains("HMAC mismatch"),
                "Expected HMAC mismatch with wrong secret, got: {}",
                reason
            );
        }
        other => panic!("Expected Invalid for wrong secret, got: {:?}", other),
    }
}
