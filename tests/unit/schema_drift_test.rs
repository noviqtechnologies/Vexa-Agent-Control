//! Unit tests for FR-601: MCP Schema-Drift Detection

use agentwall::policy::schema::SchemaDriftConfig;
use agentwall::policy::schema_drift::{DriftAction, DriftResult, SchemaDriftDetector};
use serde_json::json;

#[test]
fn test_baseline_recording_on_first_discovery() {
    let detector = SchemaDriftDetector::default();
    let catalog = json!({
        "result": {
            "tools": [
                {
                    "name": "calculate",
                    "description": "Performs arithmetic operations",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "expr": { "type": "string" }
                        },
                        "required": ["expr"]
                    }
                }
            ]
        }
    });

    let res = detector.evaluate_catalog("math_mcp", &catalog, None);
    match res {
        DriftResult::BaselineRecorded {
            server_name,
            tool_count,
            catalog_hash,
        } => {
            assert_eq!(server_name, "math_mcp");
            assert_eq!(tool_count, 1);
            assert_ne!(catalog_hash, 0);
        }
        other => panic!("Expected BaselineRecorded, got {:?}", other),
    }

    assert!(detector.has_baseline("math_mcp"));
}

#[test]
fn test_match_on_identical_catalog() {
    let detector = SchemaDriftDetector::default();
    let catalog = json!({
        "result": {
            "tools": [
                {
                    "name": "search",
                    "description": "Web search tool",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "query": { "type": "string" } }
                    }
                },
                {
                    "name": "fetch",
                    "description": "Fetch webpage content",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "url": { "type": "string" } }
                    }
                }
            ]
        }
    });

    let _ = detector.evaluate_catalog("web_mcp", &catalog, None);

    let res = detector.evaluate_catalog("web_mcp", &catalog, None);
    match res {
        DriftResult::Match { server_name, .. } => {
            assert_eq!(server_name, "web_mcp");
        }
        other => panic!("Expected Match, got {:?}", other),
    }
}

#[test]
fn test_drift_detected_on_added_tool() {
    let detector = SchemaDriftDetector::default();
    let initial_catalog = json!({
        "result": {
            "tools": [
                {
                    "name": "read_doc",
                    "description": "Read documentation",
                    "inputSchema": { "type": "object" }
                }
            ]
        }
    });

    let modified_catalog = json!({
        "result": {
            "tools": [
                {
                    "name": "read_doc",
                    "description": "Read documentation",
                    "inputSchema": { "type": "object" }
                },
                {
                    "name": "write_doc",
                    "description": "Write documentation",
                    "inputSchema": { "type": "object" }
                }
            ]
        }
    });

    let _ = detector.evaluate_catalog("docs_mcp", &initial_catalog, None);

    let config = SchemaDriftConfig {
        enabled: true,
        action: "warn".to_string(),
        baseline_path: None,
    };

    let res = detector.evaluate_catalog("docs_mcp", &modified_catalog, Some(&config));
    match res {
        DriftResult::Drift {
            server_name,
            added_tools,
            removed_tools,
            modified_tools,
            action,
            ..
        } => {
            assert_eq!(server_name, "docs_mcp");
            assert_eq!(added_tools, vec!["write_doc".to_string()]);
            assert!(removed_tools.is_empty());
            assert!(modified_tools.is_empty());
            assert_eq!(action, DriftAction::Warn);
        }
        other => panic!("Expected Drift, got {:?}", other),
    }
}

#[test]
fn test_drift_detected_on_modified_schema_and_description() {
    let detector = SchemaDriftDetector::default();
    let initial_catalog = json!({
        "result": {
            "tools": [
                {
                    "name": "execute_sql",
                    "description": "Run select query only",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "query": { "type": "string" } }
                    }
                }
            ]
        }
    });

    let modified_catalog = json!({
        "result": {
            "tools": [
                {
                    "name": "execute_sql",
                    "description": "Run arbitrary database commands (MODIFIED)",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "query": { "type": "string" },
                            "allow_drop": { "type": "boolean" }
                        }
                    }
                }
            ]
        }
    });

    let _ = detector.evaluate_catalog("sql_mcp", &initial_catalog, None);

    let config = SchemaDriftConfig {
        enabled: true,
        action: "block".to_string(),
        baseline_path: None,
    };

    let res = detector.evaluate_catalog("sql_mcp", &modified_catalog, Some(&config));
    match res {
        DriftResult::Drift {
            server_name,
            added_tools,
            removed_tools,
            modified_tools,
            action,
            ..
        } => {
            assert_eq!(server_name, "sql_mcp");
            assert!(added_tools.is_empty());
            assert!(removed_tools.is_empty());
            assert_eq!(modified_tools, vec!["execute_sql".to_string()]);
            assert_eq!(action, DriftAction::Block);
        }
        other => panic!("Expected Drift, got {:?}", other),
    }
}

#[test]
fn test_drift_detected_on_removed_tool() {
    let detector = SchemaDriftDetector::default();
    let initial_catalog = json!({
        "result": {
            "tools": [
                { "name": "tool_a", "description": "A", "inputSchema": {} },
                { "name": "tool_b", "description": "B", "inputSchema": {} }
            ]
        }
    });

    let modified_catalog = json!({
        "result": {
            "tools": [
                { "name": "tool_a", "description": "A", "inputSchema": {} }
            ]
        }
    });

    let _ = detector.evaluate_catalog("multi_tool_mcp", &initial_catalog, None);

    let res = detector.evaluate_catalog("multi_tool_mcp", &modified_catalog, None);
    match res {
        DriftResult::Drift { removed_tools, .. } => {
            assert_eq!(removed_tools, vec!["tool_b".to_string()]);
        }
        other => panic!("Expected Drift, got {:?}", other),
    }
}

#[test]
fn test_drift_disabled_behavior() {
    let detector = SchemaDriftDetector::default();
    let catalog = json!({
        "result": { "tools": [{ "name": "noop", "description": "none", "inputSchema": {} }] }
    });

    let config = SchemaDriftConfig {
        enabled: false,
        action: "warn".to_string(),
        baseline_path: None,
    };

    let res = detector.evaluate_catalog("disabled_mcp", &catalog, Some(&config));
    assert_eq!(res, DriftResult::Disabled);
}

#[test]
fn test_baseline_persistence_roundtrip() {
    let temp_dir = tempfile::tempdir().unwrap();
    let baseline_file = temp_dir.path().join("schema_baselines.json");

    let detector1 = SchemaDriftDetector::new(Some(baseline_file.clone()));
    let catalog = json!({
        "result": {
            "tools": [
                {
                    "name": "persisted_tool",
                    "description": "Persistent description",
                    "inputSchema": { "type": "object" }
                }
            ]
        }
    });

    let _ = detector1.evaluate_catalog("persisted_server", &catalog, None);
    assert!(baseline_file.exists());

    // Second detector instance loads existing baselines from disk
    let detector2 = SchemaDriftDetector::new(Some(baseline_file));
    assert!(detector2.has_baseline("persisted_server"));

    // Evaluation with identical catalog on new detector returns Match
    let res = detector2.evaluate_catalog("persisted_server", &catalog, None);
    match res {
        DriftResult::Match { server_name, .. } => {
            assert_eq!(server_name, "persisted_server");
        }
        other => panic!("Expected Match on reloaded detector, got {:?}", other),
    }
}
