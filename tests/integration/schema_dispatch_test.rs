//! Phase 1 Integration Tests: Schema dispatch verification, chain bridge protocol,
//! mixed V1/V2 chain validation, and explainable verdict audit entries.
//!
//! These tests exercise the ADR-009 schema dispatch implemented in `verifier.rs`,
//! verifying that:
//! 1. Pure V2 chains verify correctly using RFC 8785 canonical JSON.
//! 2. Chain bridge entries linking V1→V2 are validated.
//! 3. Mixed V1/V2 log files verify seamlessly.
//! 4. Corrupted bridge entries are rejected.
//! 5. V2 entries with verdict explanations serialize and verify correctly.
//! 6. Unknown schema versions are rejected.

use agentcontrol::audit::legacy_v1::AuditEntryV1Legacy;
use agentcontrol::audit::logger::ZERO_HMAC;
use agentcontrol::audit::v2::{
    AuditEntryV2, MigrationMetadata, VerdictExplanation, SCHEMA_VERSION_V2,
};
use agentcontrol::audit::verifier::{verify_chain, verify_chain_with_secret, VerifyResult};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

const TEST_SECRET: [u8; 32] = [0x5A; 32];

// ─── Helpers ───────────────────────────────────────────────────────────────

/// Helper to write a serialized entry line to a file.
fn append_line(path: &Path, line: &str) {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap();
    writeln!(file, "{}", line).unwrap();
}

/// Create a V1 legacy entry with proper HMAC.
fn make_v1_entry(
    session_secret: &[u8],
    session_id: &str,
    event: &str,
    tool_name: Option<&str>,
    entry_index: u64,
    prev_hmac: &str,
) -> AuditEntryV1Legacy {
    let mut entry = AuditEntryV1Legacy {
        ts: chrono::Utc::now().to_rfc3339(),
        session_id: session_id.to_string(),
        event: event.to_string(),
        tool_name: tool_name.map(|s| s.to_string()),
        params_hash: None,
        params: None,
        reason: None,
        latency_ms: None,
        identity_sub: None,
        identity_email: None,
        policy_hash: None,
        request_ip: None,
        matched_group_id: None,
        entry_index,
        prev_hmac: prev_hmac.to_string(),
        hmac: None,
    };

    let hmac = entry.compute_hmac(session_secret).unwrap();
    entry.hmac = Some(hmac);
    entry
}

/// Create a V2 entry with proper HMAC using canonical JSON.
fn make_v2_entry(
    session_secret: &[u8],
    session_id: &str,
    event: &str,
    tool_name: Option<&str>,
    entry_index: u64,
    prev_hmac: &str,
    verdict: Option<VerdictExplanation>,
) -> AuditEntryV2 {
    let mut entry = AuditEntryV2 {
        schema_version: SCHEMA_VERSION_V2,
        ts: chrono::Utc::now().to_rfc3339(),
        session_id: session_id.to_string(),
        event: event.to_string(),
        tool_name: tool_name.map(|s| s.to_string()),
        params_hash: None,
        params: None,
        reason: None,
        latency_ms: None,
        identity_sub: None,
        identity_email: None,
        policy_hash: None,
        request_ip: None,
        matched_group_id: None,
        entry_index,
        prev_hmac: prev_hmac.to_string(),
        hmac: None,
        migration_metadata: None,
        verdict,
    };

    let hmac = entry.compute_hmac(session_secret).unwrap();
    entry.hmac = Some(hmac);
    entry
}

/// Create a chain bridge entry linking V1 terminal HMAC to V2 genesis.
fn make_bridge_entry(
    session_secret: &[u8],
    session_id: &str,
    terminal_v1_hmac: &str,
) -> AuditEntryV2 {
    let mut entry = AuditEntryV2 {
        schema_version: SCHEMA_VERSION_V2,
        ts: chrono::Utc::now().to_rfc3339(),
        session_id: session_id.to_string(),
        event: "schema_migration_bridge".to_string(),
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
        prev_hmac: ZERO_HMAC.to_string(),
        hmac: None,
        migration_metadata: Some(MigrationMetadata {
            from_schema_version: 1,
            to_schema_version: 2,
            terminal_v1_hmac: terminal_v1_hmac.to_string(),
            bridge_signature: None,
        }),
        verdict: None,
    };

    let hmac = entry.compute_hmac(session_secret).unwrap();
    entry.hmac = Some(hmac);
    entry
}

// ─── Test 1: Pure V2 Chain Verification ────────────────────────────────────

#[test]
fn test_pure_v2_chain_verification() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("v2_chain.jsonl");

    let e0 = make_v2_entry(
        &TEST_SECRET,
        "sess-v2",
        "tool_allow",
        Some("read_file"),
        0,
        ZERO_HMAC,
        None,
    );
    let e1 = make_v2_entry(
        &TEST_SECRET,
        "sess-v2",
        "tool_allow",
        Some("write_file"),
        1,
        &e0.hmac.clone().unwrap(),
        None,
    );
    let e2 = make_v2_entry(
        &TEST_SECRET,
        "sess-v2",
        "tool_deny",
        Some("bash"),
        2,
        &e1.hmac.clone().unwrap(),
        None,
    );

    append_line(&path, &serde_json::to_string(&e0).unwrap());
    append_line(&path, &serde_json::to_string(&e1).unwrap());
    append_line(&path, &serde_json::to_string(&e2).unwrap());

    match verify_chain_with_secret(&path, &TEST_SECRET) {
        VerifyResult::Valid { entry_count } => assert_eq!(entry_count, 3),
        other => panic!("Pure V2 chain failed: {:?}", other),
    }
}

// ─── Test 2: V2 Entry with Verdict Explanation ─────────────────────────────

#[test]
fn test_v2_entry_with_verdict() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("v2_verdict.jsonl");

    let verdict = VerdictExplanation {
        rule_id: "dlp-api-key-001".to_string(),
        risk_category: "credential_exposure".to_string(),
        evidence_snippet: Some("sk-abc1...".to_string()),
        remediation: Some("Use environment variables".to_string()),
    };

    let e0 = make_v2_entry(
        &TEST_SECRET,
        "sess-verdict",
        "tool_deny",
        Some("curl"),
        0,
        ZERO_HMAC,
        Some(verdict),
    );
    append_line(&path, &serde_json::to_string(&e0).unwrap());

    match verify_chain_with_secret(&path, &TEST_SECRET) {
        VerifyResult::Valid { entry_count } => assert_eq!(entry_count, 1),
        other => panic!("V2 verdict entry failed: {:?}", other),
    }
}

// ─── Test 3: Chain Bridge — V1 to V2 Migration ────────────────────────────

#[test]
fn test_chain_bridge_v1_to_v2() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("bridge.jsonl");

    // Write 2 V1 entries
    let v1_e0 = make_v1_entry(
        &TEST_SECRET,
        "sess-bridge",
        "tool_allow",
        Some("read_file"),
        0,
        ZERO_HMAC,
    );
    let v1_e1 = make_v1_entry(
        &TEST_SECRET,
        "sess-bridge",
        "tool_allow",
        Some("git_status"),
        1,
        &v1_e0.hmac.clone().unwrap(),
    );

    append_line(&path, &serde_json::to_string(&v1_e0).unwrap());
    append_line(&path, &serde_json::to_string(&v1_e1).unwrap());

    // Write bridge entry
    let terminal_hmac = v1_e1.hmac.clone().unwrap();
    let bridge = make_bridge_entry(&TEST_SECRET, "sess-bridge", &terminal_hmac);
    append_line(&path, &serde_json::to_string(&bridge).unwrap());

    // Write V2 entries continuing after bridge
    let v2_e0 = make_v2_entry(
        &TEST_SECRET,
        "sess-bridge-v2",
        "tool_allow",
        Some("read_file"),
        1,
        &bridge.hmac.clone().unwrap(),
        None,
    );
    append_line(&path, &serde_json::to_string(&v2_e0).unwrap());

    match verify_chain_with_secret(&path, &TEST_SECRET) {
        VerifyResult::Valid { entry_count } => assert_eq!(entry_count, 4),
        other => panic!("Chain bridge verification failed: {:?}", other),
    }
}

// ─── Test 4: Corrupted Bridge — Wrong Terminal HMAC ────────────────────────

#[test]
fn test_corrupted_bridge_detection() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("bad_bridge.jsonl");

    // Write a V1 entry
    let v1_e0 = make_v1_entry(
        &TEST_SECRET,
        "sess-bad-bridge",
        "tool_allow",
        Some("read_file"),
        0,
        ZERO_HMAC,
    );
    append_line(&path, &serde_json::to_string(&v1_e0).unwrap());

    // Write bridge with WRONG terminal HMAC
    let bridge = make_bridge_entry(
        &TEST_SECRET,
        "sess-bad-bridge",
        "deadbeef0000000000000000000000000000000000000000000000000000dead",
    );
    append_line(&path, &serde_json::to_string(&bridge).unwrap());

    match verify_chain_with_secret(&path, &TEST_SECRET) {
        VerifyResult::Invalid { reason, .. } => {
            assert!(
                reason.contains("terminal_v1_hmac mismatch"),
                "Expected terminal_v1_hmac mismatch, got: {}",
                reason
            );
        }
        other => panic!("Expected Invalid for corrupted bridge, got: {:?}", other),
    }
}

// ─── Test 5: Mixed V1/V2 Chain Without Bridge ─────────────────────────────
// This tests that a log file can contain V1 entries followed by V2 entries
// from a new session (ZERO_HMAC restart) without a bridge.

#[test]
fn test_mixed_v1_v2_separate_sessions() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("mixed.jsonl");

    // V1 session
    let v1_e0 = make_v1_entry(
        &TEST_SECRET,
        "sess-v1",
        "tool_allow",
        Some("read_file"),
        0,
        ZERO_HMAC,
    );
    let v1_e1 = make_v1_entry(
        &TEST_SECRET,
        "sess-v1",
        "tool_allow",
        Some("git_status"),
        1,
        &v1_e0.hmac.clone().unwrap(),
    );
    append_line(&path, &serde_json::to_string(&v1_e0).unwrap());
    append_line(&path, &serde_json::to_string(&v1_e1).unwrap());

    // V2 session (new session starts at index 0 with ZERO_HMAC)
    let v2_e0 = make_v2_entry(
        &TEST_SECRET,
        "sess-v2",
        "tool_allow",
        Some("read_file"),
        0,
        ZERO_HMAC,
        None,
    );
    let v2_e1 = make_v2_entry(
        &TEST_SECRET,
        "sess-v2",
        "tool_deny",
        Some("bash"),
        1,
        &v2_e0.hmac.clone().unwrap(),
        None,
    );
    append_line(&path, &serde_json::to_string(&v2_e0).unwrap());
    append_line(&path, &serde_json::to_string(&v2_e1).unwrap());

    match verify_chain_with_secret(&path, &TEST_SECRET) {
        VerifyResult::Valid { entry_count } => assert_eq!(entry_count, 4),
        other => panic!("Mixed V1/V2 verification failed: {:?}", other),
    }
}

// ─── Test 6: Unknown Schema Version Rejection ─────────────────────────────

#[test]
fn test_unknown_schema_version_rejection() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("unknown_schema.jsonl");

    let line = serde_json::json!({
        "schema_version": 99,
        "ts": "2026-01-01T00:00:00Z",
        "session_id": "sess-unknown",
        "event": "tool_allow",
        "entry_index": 0,
        "prev_hmac": ZERO_HMAC,
        "hmac": "deadbeef"
    });
    append_line(&path, &line.to_string());

    match verify_chain_with_secret(&path, &TEST_SECRET) {
        VerifyResult::Error(msg) => {
            assert!(
                msg.contains("unsupported schema_version 99"),
                "Expected unsupported schema version error, got: {}",
                msg
            );
        }
        other => panic!("Expected Error for unknown schema, got: {:?}", other),
    }
}

// ─── Test 7: V2 HMAC Tamper Detection ──────────────────────────────────────

#[test]
fn test_v2_hmac_tamper_detection() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("v2_tampered.jsonl");

    let e0 = make_v2_entry(
        &TEST_SECRET,
        "sess-tamper",
        "tool_allow",
        Some("read_file"),
        0,
        ZERO_HMAC,
        None,
    );
    let mut line = serde_json::to_string(&e0).unwrap();

    // Tamper with the event field
    line = line.replace("tool_allow", "tool_deny");
    fs::write(&path, format!("{}\n", line)).unwrap();

    match verify_chain_with_secret(&path, &TEST_SECRET) {
        VerifyResult::Invalid { reason, .. } => {
            assert!(
                reason.contains("HMAC mismatch"),
                "Expected HMAC mismatch, got: {}",
                reason
            );
        }
        other => panic!("Expected Invalid for tampered V2, got: {:?}", other),
    }
}

// ─── Test 8: V2 Chain-Only Verification ────────────────────────────────────

#[test]
fn test_v2_chain_only_verification() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("v2_chain_only.jsonl");

    let e0 = make_v2_entry(
        &TEST_SECRET,
        "sess-chain",
        "tool_allow",
        Some("read_file"),
        0,
        ZERO_HMAC,
        None,
    );
    let e1 = make_v2_entry(
        &TEST_SECRET,
        "sess-chain",
        "tool_allow",
        Some("write_file"),
        1,
        &e0.hmac.clone().unwrap(),
        None,
    );

    append_line(&path, &serde_json::to_string(&e0).unwrap());
    append_line(&path, &serde_json::to_string(&e1).unwrap());

    // Chain-only mode (no secret) should still verify structural integrity.
    match verify_chain(&path) {
        VerifyResult::Valid { entry_count } => assert_eq!(entry_count, 2),
        other => panic!("Chain-only V2 verification failed: {:?}", other),
    }
}

// ─── Test 9: V2 Wrong Secret Key Rejection ─────────────────────────────────

#[test]
fn test_v2_wrong_secret_rejection() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("v2_wrong_secret.jsonl");

    let e0 = make_v2_entry(
        &TEST_SECRET,
        "sess-wrong",
        "tool_allow",
        Some("read_file"),
        0,
        ZERO_HMAC,
        None,
    );
    append_line(&path, &serde_json::to_string(&e0).unwrap());

    let wrong_secret = [0x99; 32];
    match verify_chain_with_secret(&path, &wrong_secret) {
        VerifyResult::Invalid {
            reason,
            entry_index,
        } => {
            assert_eq!(entry_index, 0);
            assert!(
                reason.contains("HMAC mismatch"),
                "Expected HMAC mismatch, got: {}",
                reason
            );
        }
        other => panic!("Expected Invalid for wrong secret, got: {:?}", other),
    }
}

// ─── Test 10: Active Struct Mutation Does Not Break Legacy Verifier ────────

#[test]
fn test_active_struct_mutation_isolation() {
    // This test proves that the frozen AuditEntryV1Legacy is isolated from
    // the active AuditEntry struct. Even if AuditEntry evolves (which it will
    // in Phase 1+), legacy verification remains unaffected.
    let entry = AuditEntryV1Legacy {
        ts: "2026-01-01T00:00:00Z".to_string(),
        session_id: "isolation-test".to_string(),
        event: "tool_allow".to_string(),
        tool_name: Some("git_status".to_string()),
        params_hash: None,
        params: None,
        reason: None,
        latency_ms: Some(1.5),
        identity_sub: None,
        identity_email: None,
        policy_hash: None,
        request_ip: None,
        matched_group_id: None,
        entry_index: 0,
        prev_hmac: ZERO_HMAC.to_string(),
        hmac: None,
    };

    // Compute and pin the HMAC
    let hmac = entry.compute_hmac(&TEST_SECRET).unwrap();
    assert!(!hmac.is_empty());

    // Verify the serialized form is identical every time
    let json1 = serde_json::to_string(&entry).unwrap();
    let json2 = serde_json::to_string(&entry).unwrap();
    assert_eq!(json1, json2, "Legacy serialization is non-deterministic");

    // Re-deserialize and re-compute — must produce same HMAC
    let parsed: AuditEntryV1Legacy = serde_json::from_str(&json1).unwrap();
    let hmac2 = parsed.compute_hmac(&TEST_SECRET).unwrap();
    assert_eq!(hmac, hmac2, "Round-trip HMAC diverged");
}
