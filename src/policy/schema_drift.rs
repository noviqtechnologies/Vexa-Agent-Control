//! FR-601: MCP Schema-Drift Detection (ADR-011)
//!
//! Hashes the MCP tool catalog (tool names, descriptions, parameter schemas)
//! on initial discovery per server (`tools/list` response) and detects
//! subsequent catalog tampering / "rug pull" modifications across connection sessions.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use super::schema::SchemaDriftConfig;

/// Summary of a single tool definition inside an MCP tool catalog.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolSummary {
    pub name: String,
    pub description_hash: u64,
    pub schema_hash: u64,
}

/// Baseline hash representation for an MCP server's catalog.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SchemaCatalogHash {
    pub server_name: String,
    pub catalog_hash: u64,
    pub tool_count: usize,
    pub tools: Vec<ToolSummary>,
    pub recorded_at: DateTime<Utc>,
}

/// Action to perform when schema drift is detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftAction {
    Block,
    Warn,
    DowngradeScore,
}

impl DriftAction {
    pub fn from_str_action(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "block" | "deny" => DriftAction::Block,
            "downgrade_score" | "downgrade" => DriftAction::DowngradeScore,
            _ => DriftAction::Warn,
        }
    }
}

/// Evaluation verdict for a `tools/list` response.
#[derive(Debug, Clone, PartialEq)]
pub enum DriftResult {
    /// Initial session: baseline catalog recorded.
    BaselineRecorded {
        server_name: String,
        catalog_hash: u64,
        tool_count: usize,
    },
    /// Catalog matches the recorded baseline perfectly.
    Match {
        server_name: String,
        catalog_hash: u64,
    },
    /// Schema drift detected against recorded baseline.
    Drift {
        server_name: String,
        baseline_hash: u64,
        current_hash: u64,
        added_tools: Vec<String>,
        removed_tools: Vec<String>,
        modified_tools: Vec<String>,
        action: DriftAction,
    },
    /// Schema drift detection is disabled.
    Disabled,
}

/// Thread-safe cross-session MCP Schema-Drift Detector.
pub struct SchemaDriftDetector {
    baselines: RwLock<HashMap<String, SchemaCatalogHash>>,
    baseline_path: Option<PathBuf>,
}

impl Default for SchemaDriftDetector {
    fn default() -> Self {
        Self::new(None)
    }
}

impl SchemaDriftDetector {
    /// Initialize a new detector with optional persistent storage path.
    pub fn new(baseline_path: Option<PathBuf>) -> Self {
        let mut baselines = HashMap::new();
        if let Some(ref path) = baseline_path {
            if path.exists() {
                if let Ok(loaded) = Self::load_from_disk(path) {
                    baselines = loaded;
                }
            }
        }

        Self {
            baselines: RwLock::new(baselines),
            baseline_path,
        }
    }

    /// Helper to compute canonical hash of a serde_json Value.
    pub fn canonical_hash(val: &Value) -> u64 {
        let canonical_str = canonicalize_json(val);
        let mut hasher = DefaultHasher::new();
        canonical_str.hash(&mut hasher);
        hasher.finish()
    }

    /// Extract tools and compute deterministic catalog hash from a `tools/list` response.
    pub fn compute_catalog_hash(server_name: &str, response: &Value) -> SchemaCatalogHash {
        let empty_vec = Vec::new();
        let tools_array = response
            .get("result")
            .and_then(|r| r.get("tools"))
            .and_then(|t| t.as_array())
            .or_else(|| response.get("tools").and_then(|t| t.as_array()))
            .unwrap_or(&empty_vec);

        let mut tool_summaries = Vec::new();

        for tool in tools_array {
            let name = tool
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string();

            let description_hash = tool
                .get("description")
                .map(Self::canonical_hash)
                .unwrap_or(0);

            let schema_hash = tool
                .get("inputSchema")
                .or_else(|| tool.get("parameters"))
                .map(Self::canonical_hash)
                .unwrap_or(0);

            tool_summaries.push(ToolSummary {
                name,
                description_hash,
                schema_hash,
            });
        }

        // Sort by tool name for deterministic ordering
        tool_summaries.sort_by(|a, b| a.name.cmp(&b.name));

        let mut hasher = DefaultHasher::new();
        for t in &tool_summaries {
            t.name.hash(&mut hasher);
            t.description_hash.hash(&mut hasher);
            t.schema_hash.hash(&mut hasher);
        }
        let catalog_hash = hasher.finish();

        SchemaCatalogHash {
            server_name: server_name.to_string(),
            catalog_hash,
            tool_count: tool_summaries.len(),
            tools: tool_summaries,
            recorded_at: Utc::now(),
        }
    }

    /// Evaluate an incoming `tools/list` response against stored baselines.
    pub fn evaluate_catalog(
        &self,
        server_name: &str,
        response: &Value,
        config: Option<&SchemaDriftConfig>,
    ) -> DriftResult {
        // If config is present and disabled, skip
        if let Some(cfg) = config {
            if !cfg.enabled {
                return DriftResult::Disabled;
            }
        }

        let current = Self::compute_catalog_hash(server_name, response);
        let action = config
            .map(|c| DriftAction::from_str_action(&c.action))
            .unwrap_or(DriftAction::Warn);

        // Read lock check
        {
            let baselines = self.baselines.read().unwrap();
            if let Some(baseline) = baselines.get(server_name) {
                if baseline.catalog_hash == current.catalog_hash {
                    return DriftResult::Match {
                        server_name: server_name.to_string(),
                        catalog_hash: current.catalog_hash,
                    };
                } else {
                    // Compute diff diagnostics
                    let (added, removed, modified) = diff_catalogs(baseline, &current);
                    return DriftResult::Drift {
                        server_name: server_name.to_string(),
                        baseline_hash: baseline.catalog_hash,
                        current_hash: current.catalog_hash,
                        added_tools: added,
                        removed_tools: removed,
                        modified_tools: modified,
                        action,
                    };
                }
            }
        }

        // Write lock to record baseline
        {
            let mut baselines = self.baselines.write().unwrap();
            baselines.insert(server_name.to_string(), current.clone());
        }

        // Persist if path configured
        if let Some(ref path) = self.baseline_path {
            let baselines = self.baselines.read().unwrap();
            let _ = Self::save_to_disk(path, &baselines);
        }

        DriftResult::BaselineRecorded {
            server_name: server_name.to_string(),
            catalog_hash: current.catalog_hash,
            tool_count: current.tool_count,
        }
    }

    /// Check if a baseline is registered for a given server name.
    pub fn has_baseline(&self, server_name: &str) -> bool {
        self.baselines.read().unwrap().contains_key(server_name)
    }

    /// Reset or clear recorded baselines.
    pub fn clear(&self) {
        self.baselines.write().unwrap().clear();
    }

    /// Save baseline map to disk atomically.
    fn save_to_disk(
        path: &Path,
        baselines: &HashMap<String, SchemaCatalogHash>,
    ) -> Result<(), String> {
        let json = serde_json::to_string_pretty(baselines)
            .map_err(|e| format!("Serialization error: {}", e))?;

        let temp_path = path.with_extension(format!("tmp.{}", std::process::id()));
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        std::fs::write(&temp_path, json).map_err(|e| format!("Write error: {}", e))?;
        std::fs::rename(&temp_path, path).map_err(|e| format!("Rename error: {}", e))?;
        Ok(())
    }

    /// Load baseline map from disk.
    fn load_from_disk(path: &Path) -> Result<HashMap<String, SchemaCatalogHash>, String> {
        let content = std::fs::read_to_string(path).map_err(|e| format!("Read error: {}", e))?;
        serde_json::from_str(&content).map_err(|e| format!("Deserialization error: {}", e))
    }
}

/// Compute added, removed, and modified tools between two catalog snapshots.
fn diff_catalogs(
    baseline: &SchemaCatalogHash,
    current: &SchemaCatalogHash,
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut modified = Vec::new();

    let base_map: HashMap<&str, &ToolSummary> = baseline
        .tools
        .iter()
        .map(|t| (t.name.as_str(), t))
        .collect();
    let curr_map: HashMap<&str, &ToolSummary> =
        current.tools.iter().map(|t| (t.name.as_str(), t)).collect();

    for (name, curr_tool) in &curr_map {
        if let Some(base_tool) = base_map.get(name) {
            if base_tool.description_hash != curr_tool.description_hash
                || base_tool.schema_hash != curr_tool.schema_hash
            {
                modified.push(name.to_string());
            }
        } else {
            added.push(name.to_string());
        }
    }

    for name in base_map.keys() {
        if !curr_map.contains_key(name) {
            removed.push(name.to_string());
        }
    }

    added.sort();
    removed.sort();
    modified.sort();

    (added, removed, modified)
}

/// Canonicalize JSON value into sorted key representation.
fn canonicalize_json(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let entries: Vec<String> = keys
                .iter()
                .map(|k| format!("{:?}:{}", k, canonicalize_json(&map[*k])))
                .collect();
            format!("{{{}}}", entries.join(","))
        }
        Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(canonicalize_json).collect();
            format!("[{}]", items.join(","))
        }
        _ => value.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_schema_drift_baseline_recording_and_matching() {
        let detector = SchemaDriftDetector::default();
        let tools_response = json!({
            "result": {
                "tools": [
                    {
                        "name": "read_file",
                        "description": "Read file from disk",
                        "inputSchema": {
                            "type": "object",
                            "properties": { "path": { "type": "string" } },
                            "required": ["path"]
                        }
                    },
                    {
                        "name": "list_directory",
                        "description": "List files in directory",
                        "inputSchema": {
                            "type": "object",
                            "properties": { "dir": { "type": "string" } }
                        }
                    }
                ]
            }
        });

        // 1. Initial evaluation records baseline
        let res1 = detector.evaluate_catalog("fs_server", &tools_response, None);
        match res1 {
            DriftResult::BaselineRecorded {
                server_name,
                tool_count,
                ..
            } => {
                assert_eq!(server_name, "fs_server");
                assert_eq!(tool_count, 2);
            }
            other => panic!("Expected BaselineRecorded, got {:?}", other),
        }

        // 2. Same catalog matches
        let res2 = detector.evaluate_catalog("fs_server", &tools_response, None);
        match res2 {
            DriftResult::Match { server_name, .. } => {
                assert_eq!(server_name, "fs_server");
            }
            other => panic!("Expected Match, got {:?}", other),
        }
    }

    #[test]
    fn test_schema_drift_detection_on_modified_schema() {
        let detector = SchemaDriftDetector::default();
        let initial_response = json!({
            "result": {
                "tools": [
                    {
                        "name": "execute_query",
                        "description": "Run read-only query",
                        "inputSchema": { "type": "object", "properties": { "sql": { "type": "string" } } }
                    }
                ]
            }
        });

        let modified_response = json!({
            "result": {
                "tools": [
                    {
                        "name": "execute_query",
                        "description": "Run arbitrary query or command", // modified description
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "sql": { "type": "string" },
                                "admin_override": { "type": "boolean" } // modified schema
                            }
                        }
                    },
                    {
                        "name": "drop_table", // added tool
                        "description": "Drop table from db",
                        "inputSchema": { "type": "object" }
                    }
                ]
            }
        });

        let _ = detector.evaluate_catalog("db_server", &initial_response, None);

        let cfg = SchemaDriftConfig {
            enabled: true,
            action: "block".to_string(),
            baseline_path: None,
        };

        let res = detector.evaluate_catalog("db_server", &modified_response, Some(&cfg));
        match res {
            DriftResult::Drift {
                server_name,
                added_tools,
                removed_tools,
                modified_tools,
                action,
                ..
            } => {
                assert_eq!(server_name, "db_server");
                assert_eq!(action, DriftAction::Block);
                assert_eq!(added_tools, vec!["drop_table".to_string()]);
                assert!(removed_tools.is_empty());
                assert_eq!(modified_tools, vec!["execute_query".to_string()]);
            }
            other => panic!("Expected Drift, got {:?}", other),
        }
    }
}
