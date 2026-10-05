# ADR-009: Audit Chain Migration, Immutable Legacy Verifier, and Chain Bridge Protocol

**Status:** APPROVED (Phase 0a Baseline)  
**Date:** 2026-10-04  
**Author:** Architecture Team  
**Governing Standard:** [Plan Review Feedback v4](file:///C:/Users/wasim/.gemini/antigravity-ide/brain/9469605e-81c2-40a5-9567-198d8ebbf4c0/plan_review_feedback_v4.md)

---

## 1. Context & Technical Diagnosis

In [`verifier.rs` L199-L216](file:///c:/AgentWall/agentwall/src/audit/verifier.rs#L199-L216), audit verification recomputes entry HMACs by stripping `hmac: None`, re-serializing the struct to string via `serde_json::to_string()`, and updating HMAC-SHA256:

```rust
// verifier.rs (current implementation)
let stored_hmac = entry.hmac.clone().unwrap_or_default();
let mut verify_entry = entry.clone();
verify_entry.hmac = None;
let canonical = serde_json::to_string(&verify_entry)?;
```

### The Re-Serialization Vulnerability
`serde_json::to_string()` produces JSON bytes dependent on:
1. Rust struct field declaration order.
2. Exact struct field names and serde rename attributes.
3. Struct field data types (e.g. `f64` representation of float values).
4. Behavior of `#[serde(skip_serializing_if = "Option::is_none")]`.
5. Serde minor release formatting changes.

If the active `AuditEntry` struct evolves by adding, renaming, or reordering fields, or if types change, **the re-serialized JSON string will diverge from historical bytes**, causing cryptographic verification of valid historical logs to fail.

The suggestion in earlier reviews to verify legacy entries against the "current `AuditEntry` struct" was fundamentally incorrect. **The current working struct is precisely what must not be used to verify historical entries.**

---

## 2. Decision: Immutable Frozen Legacy Type & Schema Dispatch

### 2.1 The Frozen Legacy Type: `AuditEntryV1Legacy`

We establish an immutable, permanently frozen type in `src/audit/legacy_v1.rs`:

```rust
/// Permanently frozen historical schema for legacy entries (where schema_version is absent).
/// NEVER add, reorder, rename, or modify fields or attributes in this struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntryV1Legacy {
    pub ts: String,
    pub session_id: String,
    pub event: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_group_id: Option<String>,
    pub entry_index: u64,
    pub prev_hmac: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hmac: Option<String>,
}
```

### 2.2 Verifier Schema Dispatch

The verifier in [`src/audit/verifier.rs`](file:///c:/AgentWall/agentwall/src/audit/verifier.rs) dispatches line verification:

```
Raw JSON Line
     │
     ▼
Inspect `schema_version`
     │
     ├── Missing ───────────────► Deserialize into `AuditEntryV1Legacy`
     │                            • Verify using legacy re-serialization
     │
     ├── `schema_version == 2` ─► Deserialize into `AuditEntryV2`
     │                            • Verify using RFC 8785 Canonical JSON bytes
     │
     └── `schema_version > 2` ──► Dispatch to registered verifier or REJECT
```

### 2.3 Schema V2: Canonical RFC 8785 Byte Serialization
All new audit entries generated in Phase 1 and beyond must include:
- `schema_version: 2`
- Serialization conforms to **RFC 8785 (JSON Canonicalization Scheme - JCS)**.
- Fields are canonically sorted by UTF-16 code units prior to serialization, making HMAC calculation independent of Rust struct declaration order.

### 2.4 Chain Bridge Protocol
When a running gateway transitions schemas or migrates chains:
1. The old chain segment terminates normally.
2. A special bridge entry is written to start the new chain:
   ```json
   {
     "schema_version": 2,
     "entry_index": 0,
     "event": "schema_migration_bridge",
     "prev_hmac": "0000000000000000000000000000000000000000000000000000000000000000",
     "migration_metadata": {
       "from_schema_version": 1,
       "to_schema_version": 2,
       "terminal_v1_hmac": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
       "bridge_signature": "hmac_of_bridge_entry"
     }
   }
   ```
3. The verifier validates that `terminal_v1_hmac` matches the previous v1 chain's final record before accepting the new v2 genesis block.

---

## 3. Mandatory CI Migration Test Matrix

The test suite in `tests/integration/audit_migration_test.rs` must execute and pass:
1. `test_historical_v1_fixtures_pass`: Proves valid legacy files verify without modification.
2. `test_active_struct_mutation_does_not_break_legacy_verifier`: Mutating active application structs leaves `AuditEntryV1Legacy` verification intact.
3. `test_field_reordering_detection`: Proves legacy verifier rejects tampered field order in legacy files.
4. `test_field_renaming_detection`: Proves renaming a field breaks HMAC as expected.
5. `test_type_change_detection`: Proves integer to float type changes trigger verification failure.
6. `test_serde_json_compatibility`: Pinned comparison verifies serde serialization stability.
7. `test_chain_bridge_verification`: Validates seamless chain verification across migration boundaries.
8. `test_corrupted_bridge_detection`: Rejects invalid terminal HMAC in bridge entries.
9. `test_mixed_v1_v2_chain`: Verifies contiguous logs containing v1 and v2 records.
10. `test_truncated_file_detection`: Flags truncated files with missing closing entries.
11. `test_duplicate_sequence_index`: Rejects replay of identical entry indexes.
12. `test_forked_chain_detection`: Rejects branching logs.
