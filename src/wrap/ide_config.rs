use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdeConfigStatus {
    pub name: String,
    pub installed: bool,
    pub config_path: Option<String>,
    pub proxy_configured: bool,
    pub configured_base_url: Option<String>,
    pub mcp_wrapped: bool,
    pub compliance_state: String,
    pub last_healed_at: Option<String>,
}

/// Resolves user settings.json path for Cursor across Windows, macOS, and Linux
pub fn cursor_settings_path() -> Option<PathBuf> {
    match std::env::consts::OS {
        "windows" => dirs::data_dir().map(|d| d.join("Cursor\\User\\settings.json")),
        "macos" => dirs::home_dir().map(|h| h.join("Library/Application Support/Cursor/User/settings.json")),
        "linux" => dirs::config_dir().map(|d| d.join("Cursor/User/settings.json")),
        _ => None,
    }
}

/// Resolves user settings.json path for VS Code across Windows, macOS, and Linux
pub fn vscode_settings_path() -> Option<PathBuf> {
    match std::env::consts::OS {
        "windows" => dirs::data_dir().map(|d| d.join("Code\\User\\settings.json")),
        "macos" => dirs::home_dir().map(|h| h.join("Library/Application Support/Code/User/settings.json")),
        "linux" => dirs::config_dir().map(|d| d.join("Code/User/settings.json")),
        _ => None,
    }
}

/// Resolves settings path for Zed Editor
pub fn zed_settings_path() -> Option<PathBuf> {
    match std::env::consts::OS {
        "windows" => dirs::data_local_dir().map(|d| d.join("Zed\\settings.json")),
        "macos" | "linux" => dirs::config_dir().map(|d| d.join("zed/settings.json")),
        _ => None,
    }
}

/// Resolves config path for Windsurf / Codeium
pub fn windsurf_settings_path() -> Option<PathBuf> {
    match std::env::consts::OS {
        "windows" => dirs::data_dir().map(|d| d.join("Windsurf\\User\\settings.json")),
        "macos" => dirs::home_dir().map(|h| h.join("Library/Application Support/Windsurf/User/settings.json")),
        "linux" => dirs::config_dir().map(|d| d.join("Windsurf/User/settings.json")),
        _ => None,
    }
}

/// Reads JSON file, preserves all keys, ensures proxy URL is set, and writes back atomically.
pub fn ensure_json_proxy_setting(
    file_path: &Path,
    key_path: &[&str],
    proxy_url: &str,
    api_key_override: Option<(&str, &str)>,
) -> Result<bool, String> {
    if let Some(parent) = file_path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    let mut doc: Value = if file_path.exists() {
        let content = fs::read_to_string(file_path)
            .map_err(|e| format!("Failed to read {}: {}", file_path.display(), e))?;
        serde_json::from_str(&content).unwrap_or_else(|_| json!({}))
    } else {
        json!({})
    };

    if !doc.is_object() {
        doc = json!({});
    }

    let obj = doc.as_object_mut().ok_or("Expected JSON object")?;

    // Check if key already has expected value
    let mut current_val = None;
    if key_path.len() == 1 {
        current_val = obj.get(key_path[0]).and_then(|v| v.as_str());
    }

    let needs_update = current_val != Some(proxy_url);

    if needs_update {
        if key_path.len() == 1 {
            obj.insert(key_path[0].to_string(), Value::String(proxy_url.to_string()));
        }

        if let Some((k, v)) = api_key_override {
            obj.insert(k.to_string(), Value::String(v.to_string()));
        }

        // Atomic write via temp file
        let tmp_path = file_path.with_extension(format!("tmp.{}", std::process::id()));
        let serialized = serde_json::to_string_pretty(&doc)
            .map_err(|e| format!("JSON serialization error: {}", e))?;

        fs::write(&tmp_path, serialized)
            .map_err(|e| format!("Failed to write tmp config: {}", e))?;

        fs::rename(&tmp_path, file_path)
            .map_err(|e| format!("Failed to atomically rename config: {}", e))?;

        return Ok(true);
    }

    Ok(false)
}

/// Enforces AgentWall proxy configuration across a named IDE target
pub fn enforce_ide_target(name: &str, proxy_url: &str) -> Result<IdeConfigStatus, String> {
    let mut status = IdeConfigStatus {
        name: name.to_string(),
        installed: false,
        config_path: None,
        proxy_configured: false,
        configured_base_url: None,
        mcp_wrapped: false,
        compliance_state: "NOT_INSTALLED".to_string(),
        last_healed_at: None,
    };

    let path_opt = match name {
        "cursor" => cursor_settings_path(),
        "vscode" => vscode_settings_path(),
        "zed" => zed_settings_path(),
        "windsurf" => windsurf_settings_path(),
        _ => None,
    };

    if let Some(path) = path_opt {
        status.config_path = Some(path.to_string_lossy().to_string());
        status.installed = path.parent().map(|p| p.exists()).unwrap_or(false) || path.exists();

        if status.installed {
            let key_spec = match name {
                "cursor" => ("cursor.models.openaiBaseUrl", Some(("cursor.models.apiKey", "agentwall-local-key"))),
                "vscode" => ("cline.baseUrl", None),
                "zed" => ("language_models.openai.api_url", None),
                "windsurf" => ("openai.baseUrl", None),
                _ => ("openai.baseUrl", None),
            };

            let updated = ensure_json_proxy_setting(&path, &[key_spec.0], proxy_url, key_spec.1)?;
            if updated {
                status.last_healed_at = Some(chrono::Utc::now().to_rfc3339());
            }

            status.proxy_configured = true;
            status.configured_base_url = Some(proxy_url.to_string());
            status.compliance_state = "COMPLIANT".to_string();
        }
    }

    Ok(status)
}

/// Evaluates compliance state of all major IDEs
pub fn scan_all_ides(expected_proxy_url: &str) -> Vec<IdeConfigStatus> {
    let targets = vec!["cursor", "vscode", "zed", "windsurf"];
    let mut results = Vec::new();

    for target in targets {
        if let Ok(status) = enforce_ide_target(target, expected_proxy_url) {
            results.push(status);
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_ensure_json_proxy_setting() {
        let dir = tempdir().unwrap();
        let config_file = dir.path().join("settings.json");

        // 1. Initial write to empty file
        let updated = ensure_json_proxy_setting(
            &config_file,
            &["cursor.models.openaiBaseUrl"],
            "http://127.0.0.1:8080/v1",
            Some(("cursor.models.apiKey", "dummy-key")),
        )
        .unwrap();

        assert!(updated);
        assert!(config_file.exists());

        // 2. Read content and verify JSON
        let content = fs::read_to_string(&config_file).unwrap();
        let parsed: Value = serde_json::from_str(&content).unwrap();
        assert_eq!(
            parsed["cursor.models.openaiBaseUrl"],
            "http://127.0.0.1:8080/v1"
        );
        assert_eq!(parsed["cursor.models.apiKey"], "dummy-key");

        // 3. Re-run without changes (idempotency check)
        let updated_second = ensure_json_proxy_setting(
            &config_file,
            &["cursor.models.openaiBaseUrl"],
            "http://127.0.0.1:8080/v1",
            Some(("cursor.models.apiKey", "dummy-key")),
        )
        .unwrap();
        assert!(!updated_second);
    }
}
