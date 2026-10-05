//! Integration tests validating the 8 Phase 0a canonical trace scenario fixtures.
//! Conforms to ADR-002: Canonical Event Envelope Schema and Decoupled Data Model.

use std::fs;
use std::path::PathBuf;
use serde_json::Value;

#[test]
fn test_all_eight_phase_0a_trace_fixtures_conformance() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixtures_dir = manifest_dir.join("tests").join("fixtures").join("traces");

    let fixture_filenames = [
        "trace-01-success.json",
        "trace-02-blocked.json",
        "trace-03-redacted.json",
        "trace-04-hitl-flow.json",
        "trace-05-provider-failure.json",
        "trace-06-streaming-tokens.json",
        "trace-07-nested-spans.json",
        "trace-08-legacy-correlation.json",
    ];

    for filename in &fixture_filenames {
        let fixture_path = fixtures_dir.join(filename);
        assert!(
            fixture_path.exists(),
            "Fixture file must exist: {:?}",
            fixture_path
        );

        let content = fs::read_to_string(&fixture_path)
            .unwrap_or_else(|e| panic!("Failed to read fixture {:?}: {}", fixture_path, e));

        let v: Value = serde_json::from_str(&content)
            .unwrap_or_else(|e| panic!("Fixture {:?} must be valid JSON: {}", filename, e));

        // 1. Validate envelope top-level fields
        assert_eq!(
            v["envelope_version"].as_str().unwrap(),
            "1.0.0",
            "Envelope version must be 1.0.0 in {}",
            filename
        );
        assert!(
            v["event_id"].as_str().unwrap().starts_with("01925b3a-"),
            "event_id must be valid UUID in {}",
            filename
        );
        assert!(
            v["timestamp"].as_str().is_some(),
            "timestamp must be string in {}",
            filename
        );

        // 2. Validate correlation block
        let corr = &v["correlation"];
        assert!(corr["trace_id"].as_str().is_some(), "trace_id required in {}", filename);
        assert!(corr["run_id"].as_str().is_some(), "run_id required in {}", filename);
        assert!(corr["span_id"].as_str().is_some(), "span_id required in {}", filename);
        assert!(corr["session_id"].as_str().is_some(), "session_id required in {}", filename);
        assert!(corr["audit_entry_index"].as_u64().is_some(), "audit_entry_index required in {}", filename);

        // 3. Validate provenance block
        let prov = &v["provenance"];
        assert!(prov["data_freshness"].as_str().is_some(), "provenance.data_freshness required in {}", filename);
        assert!(prov["evidence_source"].as_str().is_some(), "provenance.evidence_source required in {}", filename);
        assert!(prov["confidence"].as_str().is_some(), "provenance.confidence required in {}", filename);

        // 4. Validate event_type & payload
        let event_type = v["event_type"].as_str().expect("event_type must be string");
        assert!(
            matches!(
                event_type,
                "tool_execution" | "policy_verdict" | "dlp_finding" | "hitl_decision" | "llm_generation"
            ),
            "Unrecognized event_type: {} in {}",
            event_type,
            filename
        );
        assert!(v["payload"].is_object(), "payload must be an object in {}", filename);
    }
}
