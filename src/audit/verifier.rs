//! Audit log HMAC chain verification (`agentwall verify-log`).
//!
//! ## Schema Dispatch Architecture (ADR-009)
//!
//! The verifier inspects each JSON line for a `schema_version` field:
//!
//! - **Missing** → Legacy V1 entry: deserialize into `AuditEntryV1Legacy`
//!   (frozen struct) and verify using legacy re-serialization HMAC.
//!
//! - **`schema_version == 2`** → V2 entry: deserialize into `AuditEntryV2`
//!   and verify using RFC 8785 canonical JSON HMAC.
//!
//! - **`schema_version > 2`** → Reject with `VerifyResult::Error`.
//!
//! Two verification modes are available:
//!
//! - **Chain-only** (`verify_chain`): checks that every entry's `prev_hmac`
//!   matches the prior entry's `hmac` and that `entry_index` is monotonically
//!   increasing. No secret required — useful for offline / forensic review.
//!
//! - **Full HMAC** (`verify_chain_with_secret`): additionally recomputes each
//!   entry's HMAC from scratch using the session secret and confirms it matches
//!   the stored value.  Detects any byte-level modification to the payload.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io::{BufRead, BufReader};
use std::path::Path;

use super::legacy_v1::AuditEntryV1Legacy;
use super::logger::{AuditEntry, ZERO_HMAC};
use super::v2::AuditEntryV2;

type HmacSha256 = Hmac<Sha256>;

/// Result of a chain verification run.
#[derive(Debug)]
pub enum VerifyResult {
    /// All entries are intact.
    Valid { entry_count: u64 },
    /// A break in the chain was detected at this entry index.
    Invalid { entry_index: u64, reason: String },
    /// A file-level error prevented verification.
    Error(String),
}

// ─── Schema Detection ──────────────────────────────────────────────────────

/// Detected schema version from a raw JSON line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SchemaVersion {
    /// No `schema_version` field present — legacy V1 entry.
    V1Legacy,
    /// `schema_version == 2` — V2 canonical RFC 8785 entry.
    V2,
    /// Unknown future version — must be rejected.
    Unknown(u32),
}

/// Inspect a raw JSON line to determine the schema version without full deserialization.
fn detect_schema_version(line: &str) -> SchemaVersion {
    // Fast path: parse as generic JSON Value and check for schema_version field.
    if let Ok(obj) = serde_json::from_str::<serde_json::Value>(line) {
        if let Some(ver) = obj.get("schema_version") {
            if let Some(n) = ver.as_u64() {
                return match n {
                    2 => SchemaVersion::V2,
                    other => SchemaVersion::Unknown(other as u32),
                };
            }
        }
    }
    SchemaVersion::V1Legacy
}

// ─── Parsed Entry Envelope ─────────────────────────────────────────────────

/// A parsed audit entry with schema-aware metadata extracted for chain verification.
struct ParsedEntry {
    entry_index: u64,
    prev_hmac: String,
    stored_hmac: String,
    event: String,
    schema: SchemaVersion,
    /// For V1 entries, holds the deserialized legacy struct for HMAC recomputation.
    v1_entry: Option<AuditEntryV1Legacy>,
    /// For V2 entries, holds the deserialized V2 struct for HMAC recomputation.
    v2_entry: Option<AuditEntryV2>,
    /// For V1 entries via the current AuditEntry (used in chain-only mode).
    current_entry: Option<AuditEntry>,
}

// ─── Helpers ───────────────────────────────────────────────────────────────

/// Parse a JSONL line into a `ParsedEntry` with schema dispatch.
/// Returns `None` for blank lines; `Err` for unparseable lines.
fn parse_line_dispatched(line: &str, line_num: usize) -> Result<Option<ParsedEntry>, String> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    let schema = detect_schema_version(trimmed);

    match schema {
        SchemaVersion::V1Legacy => {
            // Try legacy frozen struct first for HMAC fidelity.
            let v1_result = serde_json::from_str::<AuditEntryV1Legacy>(trimmed);
            let current_result = serde_json::from_str::<AuditEntry>(trimmed);

            match (v1_result, current_result) {
                (Ok(v1), Ok(current)) => Ok(Some(ParsedEntry {
                    entry_index: v1.entry_index,
                    prev_hmac: v1.prev_hmac.clone(),
                    stored_hmac: v1.hmac.clone().unwrap_or_default(),
                    event: v1.event.clone(),
                    schema,
                    v1_entry: Some(v1),
                    v2_entry: None,
                    current_entry: Some(current),
                })),
                (Ok(v1), Err(_)) => Ok(Some(ParsedEntry {
                    entry_index: v1.entry_index,
                    prev_hmac: v1.prev_hmac.clone(),
                    stored_hmac: v1.hmac.clone().unwrap_or_default(),
                    event: v1.event.clone(),
                    schema,
                    v1_entry: Some(v1),
                    v2_entry: None,
                    current_entry: None,
                })),
                (Err(_), Ok(current)) => {
                    // Fallback: current struct parses but legacy doesn't.
                    // This can happen if current struct has evolved. Use streaming.
                    Ok(Some(ParsedEntry {
                        entry_index: current.entry_index,
                        prev_hmac: current.prev_hmac.clone(),
                        stored_hmac: current.hmac.clone().unwrap_or_default(),
                        event: current.event.clone(),
                        schema,
                        v1_entry: None,
                        v2_entry: None,
                        current_entry: Some(current),
                    }))
                }
                (Err(_), Err(_)) => {
                    // Try streaming parser as crash-recovery fallback.
                    let mut stream = serde_json::Deserializer::from_str(trimmed)
                        .into_iter::<AuditEntry>();
                    if let Some(Ok(e)) = stream.next() {
                        return Ok(Some(ParsedEntry {
                            entry_index: e.entry_index,
                            prev_hmac: e.prev_hmac.clone(),
                            stored_hmac: e.hmac.clone().unwrap_or_default(),
                            event: e.event.clone(),
                            schema,
                            v1_entry: None,
                            v2_entry: None,
                            current_entry: Some(e),
                        }));
                    }
                    Err(format!("malformed JSON at line {}: {}", line_num + 1, trimmed))
                }
            }
        }
        SchemaVersion::V2 => {
            match serde_json::from_str::<AuditEntryV2>(trimmed) {
                Ok(v2) => Ok(Some(ParsedEntry {
                    entry_index: v2.entry_index,
                    prev_hmac: v2.prev_hmac.clone(),
                    stored_hmac: v2.hmac.clone().unwrap_or_default(),
                    event: v2.event.clone(),
                    schema,
                    v1_entry: None,
                    v2_entry: Some(v2),
                    current_entry: None,
                })),
                Err(e) => Err(format!(
                    "malformed V2 JSON at line {}: {} ({})",
                    line_num + 1, e, trimmed
                )),
            }
        }
        SchemaVersion::Unknown(ver) => {
            Err(format!(
                "unsupported schema_version {} at line {}",
                ver,
                line_num + 1
            ))
        }
    }
}

/// Advance the chain cursor over a `log_rotation_seed` entry.
///
/// A rotation seed carries `prev_hmac` = HMAC of the last entry in the
/// archived file, providing continuity across log rotation boundaries.
fn handle_rotation_seed(prev_hmac_field: &str, count: &mut u64, prev_hmac: &mut String) {
    // Reset the per-file sequence counter.
    *count = 0;
    // The seed's own prev_hmac is the bridge from the old file.
    *prev_hmac = prev_hmac_field.to_string();
}

/// Parse a JSONL line into an `AuditEntry`, tolerating trailing whitespace.
/// Returns `None` for blank lines; `Err` for unparseable lines.
/// (Preserved for backward compatibility with chain-only verification.)
fn parse_line(line: &str, line_num: usize) -> Result<Option<AuditEntry>, String> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    // Fast path: strict parse.
    if let Ok(e) = serde_json::from_str::<AuditEntry>(trimmed) {
        return Ok(Some(e));
    }

    // Slow path: streaming parser recovers the first object from a line that
    // has unexpected trailing bytes (e.g. double-written entries during crash).
    let mut stream = serde_json::Deserializer::from_str(trimmed).into_iter::<AuditEntry>();
    if let Some(Ok(e)) = stream.next() {
        return Ok(Some(e));
    }

    Err(format!(
        "malformed JSON at line {}: {}",
        line_num + 1,
        trimmed
    ))
}

// ─── Public API ────────────────────────────────────────────────────────────

/// Verify the HMAC chain consistency of an audit log without the session secret.
///
/// Checks:
/// - Every `prev_hmac` matches the prior entry's `hmac`.
/// - `entry_index` is monotonically increasing within each file segment.
///
/// **Cannot** detect modification of a single entry where both the payload
/// and the stored `hmac` field are changed — use `verify_chain_with_secret`
/// for that level of assurance.
pub fn verify_chain(log_path: &Path) -> VerifyResult {
    let file = match std::fs::File::open(log_path) {
        Ok(f) => f,
        Err(e) => return VerifyResult::Error(format!("cannot open log file: {}", e)),
    };

    let reader = BufReader::new(file);
    let mut prev_hmac = ZERO_HMAC.to_string();
    let mut count: u64 = 0;
    let mut total_entries: u64 = 0;

    for (line_num, raw) in reader.lines().enumerate() {
        let raw = match raw {
            Ok(l) => l,
            Err(e) => {
                return VerifyResult::Error(format!("read error at line {}: {}", line_num + 1, e));
            }
        };

        let entry = match parse_line(&raw, line_num) {
            Ok(None) => continue,
            Ok(Some(e)) => e,
            Err(msg) => return VerifyResult::Error(msg),
        };

        // Rotation seed or new daemon session segment resets the per-segment index counter.
        if entry.event == "log_rotation_seed" {
            handle_rotation_seed(&entry.prev_hmac, &mut count, &mut prev_hmac);
        } else if entry.event == "schema_migration_bridge" {
            // Schema migration bridge resets the chain for the new schema.
            count = 0;
            prev_hmac = ZERO_HMAC.to_string();
        } else if entry.entry_index == 0 && entry.prev_hmac == ZERO_HMAC {
            // First entry or new session segment initialized with ZERO_HMAC sentinel.
            count = 0;
            prev_hmac = ZERO_HMAC.to_string();
        }

        if entry.entry_index != count {
            return VerifyResult::Invalid {
                entry_index: entry.entry_index,
                reason: format!("expected entry_index {}, got {}", count, entry.entry_index),
            };
        }

        if entry.prev_hmac != prev_hmac {
            return VerifyResult::Invalid {
                entry_index: entry.entry_index,
                reason: format!("prev_hmac mismatch at entry {}", entry.entry_index),
            };
        }

        prev_hmac = entry.hmac.unwrap_or_default();
        count += 1;
        total_entries += 1;
    }

    if total_entries == 0 {
        return VerifyResult::Error("log file contains no audit entries".to_string());
    }

    VerifyResult::Valid {
        entry_count: total_entries,
    }
}

/// Verify the HMAC chain with full HMAC recomputation using the session secret.
///
/// In addition to the chain-consistency checks performed by `verify_chain`, this
/// function recomputes each entry's HMAC from its canonical JSON and confirms it
/// matches the stored value.  Any single-byte modification to any field — including
/// `ts`, `reason`, `identity_sub`, `policy_hash`, etc. — is detected.
///
/// ## Schema Dispatch (ADR-009)
///
/// - **V1 Legacy** entries (no `schema_version` field): HMAC is recomputed using
///   the frozen `AuditEntryV1Legacy` struct with `serde_json::to_string` (field
///   order dependent — which is why the struct is frozen).
///
/// - **V2** entries (`schema_version == 2`): HMAC is recomputed using RFC 8785
///   canonical JSON (key-sorted), independent of struct field order.
///
/// - **Chain Bridge** entries (`event == "schema_migration_bridge"`): The verifier
///   validates that `terminal_v1_hmac` matches the previous chain's final HMAC
///   before accepting the V2 genesis block.
pub fn verify_chain_with_secret(log_path: &Path, session_secret: &[u8]) -> VerifyResult {
    let file = match std::fs::File::open(log_path) {
        Ok(f) => f,
        Err(e) => return VerifyResult::Error(format!("cannot open log file: {}", e)),
    };

    let reader = BufReader::new(file);
    let mut prev_hmac = ZERO_HMAC.to_string();
    let mut count: u64 = 0;
    let mut total_entries: u64 = 0;

    for (line_num, raw) in reader.lines().enumerate() {
        let raw = match raw {
            Ok(l) => l,
            Err(e) => {
                return VerifyResult::Error(format!("read error at line {}: {}", line_num + 1, e));
            }
        };

        let parsed = match parse_line_dispatched(&raw, line_num) {
            Ok(None) => continue,
            Ok(Some(p)) => p,
            Err(msg) => return VerifyResult::Error(msg),
        };

        // ── Handle chain resets ──────────────────────────────────────────
        if parsed.event == "log_rotation_seed" {
            handle_rotation_seed(&parsed.prev_hmac, &mut count, &mut prev_hmac);
        } else if parsed.event == "schema_migration_bridge" {
            // Validate that the bridge's terminal_v1_hmac matches the previous chain.
            if let Some(ref v2) = parsed.v2_entry {
                if let Some(ref meta) = v2.migration_metadata {
                    if meta.terminal_v1_hmac != prev_hmac {
                        return VerifyResult::Invalid {
                            entry_index: parsed.entry_index,
                            reason: format!(
                                "chain bridge terminal_v1_hmac mismatch: expected {}, got {}",
                                prev_hmac, meta.terminal_v1_hmac
                            ),
                        };
                    }
                }
            }
            // Bridge resets the chain.
            count = 0;
            prev_hmac = ZERO_HMAC.to_string();
        } else if parsed.entry_index == 0 && parsed.prev_hmac == ZERO_HMAC {
            count = 0;
            prev_hmac = ZERO_HMAC.to_string();
        }

        // ── Sequence index check ─────────────────────────────────────────
        if parsed.entry_index != count {
            return VerifyResult::Invalid {
                entry_index: parsed.entry_index,
                reason: format!("expected entry_index {}, got {}", count, parsed.entry_index),
            };
        }

        // ── Chain link check ─────────────────────────────────────────────
        if parsed.prev_hmac != prev_hmac {
            return VerifyResult::Invalid {
                entry_index: parsed.entry_index,
                reason: format!("prev_hmac mismatch at entry {}", parsed.entry_index),
            };
        }

        // ── HMAC recomputation with schema dispatch ──────────────────────
        let computed_hmac = match parsed.schema {
            SchemaVersion::V1Legacy => {
                if let Some(ref v1) = parsed.v1_entry {
                    // Use the frozen legacy struct for deterministic HMAC recomputation.
                    match v1.compute_hmac(session_secret) {
                        Ok(h) => h,
                        Err(e) => {
                            return VerifyResult::Error(format!(
                                "V1 HMAC computation error at entry {}: {}",
                                count, e
                            ));
                        }
                    }
                } else if let Some(ref current) = parsed.current_entry {
                    // Fallback: use the current AuditEntry struct (pre-migration compatibility).
                    let mut verify_entry = current.clone();
                    verify_entry.hmac = None;
                    let canonical = match serde_json::to_string(&verify_entry) {
                        Ok(s) => s,
                        Err(e) => {
                            return VerifyResult::Error(format!(
                                "re-serialisation error at entry {}: {}",
                                count, e
                            ));
                        }
                    };
                    let mut mac = HmacSha256::new_from_slice(session_secret)
                        .expect("HMAC key length is valid");
                    mac.update(canonical.as_bytes());
                    hex::encode(mac.finalize().into_bytes())
                } else {
                    return VerifyResult::Error(format!(
                        "no parseable struct for V1 entry at line {}",
                        line_num + 1
                    ));
                }
            }
            SchemaVersion::V2 => {
                if let Some(ref v2) = parsed.v2_entry {
                    match v2.compute_hmac(session_secret) {
                        Ok(h) => h,
                        Err(e) => {
                            return VerifyResult::Error(format!(
                                "V2 HMAC computation error at entry {}: {}",
                                count, e
                            ));
                        }
                    }
                } else {
                    return VerifyResult::Error(format!(
                        "no parseable V2 struct at line {}",
                        line_num + 1
                    ));
                }
            }
            SchemaVersion::Unknown(ver) => {
                return VerifyResult::Error(format!(
                    "unsupported schema_version {} at entry {}",
                    ver, count
                ));
            }
        };

        if computed_hmac != parsed.stored_hmac {
            return VerifyResult::Invalid {
                entry_index: parsed.entry_index,
                reason: format!(
                    "HMAC mismatch at entry {} — payload has been modified (stored {}, computed {})",
                    parsed.entry_index, parsed.stored_hmac, computed_hmac
                ),
            };
        }

        prev_hmac = parsed.stored_hmac;
        count += 1;
        total_entries += 1;
    }

    if total_entries == 0 {
        return VerifyResult::Error("log file contains no audit entries".to_string());
    }

    VerifyResult::Valid {
        entry_count: total_entries,
    }
}

// ─── Unit Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_version_detection_missing() {
        let line = r#"{"ts":"2026-01-01","session_id":"s1","event":"tool_allow","entry_index":0,"prev_hmac":"00"}"#;
        assert_eq!(detect_schema_version(line), SchemaVersion::V1Legacy);
    }

    #[test]
    fn test_schema_version_detection_v2() {
        let line = r#"{"schema_version":2,"ts":"2026-01-01","session_id":"s1","event":"tool_allow","entry_index":0,"prev_hmac":"00"}"#;
        assert_eq!(detect_schema_version(line), SchemaVersion::V2);
    }

    #[test]
    fn test_schema_version_detection_unknown() {
        let line = r#"{"schema_version":99,"ts":"2026-01-01"}"#;
        assert_eq!(detect_schema_version(line), SchemaVersion::Unknown(99));
    }
}
