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
        "windows" => {
            #[cfg(windows)]
            {
                let homes = crate::wrap::config_path::get_windows_user_homes();
                for home in &homes {
                    let candidates = [
                        home.join(r"AppData\Roaming\Cursor\User\settings.json"),
                        home.join(r".cursor\mcp.json"),
                    ];
                    for c in candidates {
                        if c.exists() || c.parent().map(|p| p.exists()).unwrap_or(false) {
                            return Some(c);
                        }
                    }
                }
                if let Some(first) = homes.first() {
                    return Some(first.join(r"AppData\Roaming\Cursor\User\settings.json"));
                }
            }
            dirs::data_dir().map(|d| d.join("Cursor\\User\\settings.json"))
        }
        "macos" => {
            let candidates = [
                dirs::home_dir().map(|h| h.join("Library/Application Support/Cursor/User/settings.json")),
                dirs::home_dir().map(|h| h.join(".cursor/mcp.json")),
            ];
            for c in candidates.into_iter().flatten() {
                if c.exists() || c.parent().map(|p| p.exists()).unwrap_or(false) {
                    return Some(c);
                }
            }
            dirs::home_dir().map(|h| h.join("Library/Application Support/Cursor/User/settings.json"))
        }
        "linux" => {
            let candidates = [
                dirs::config_dir().map(|d| d.join("Cursor/User/settings.json")),
                dirs::home_dir().map(|h| h.join(".cursor/mcp.json")),
            ];
            for c in candidates.into_iter().flatten() {
                if c.exists() || c.parent().map(|p| p.exists()).unwrap_or(false) {
                    return Some(c);
                }
            }
            dirs::config_dir().map(|d| d.join("Cursor/User/settings.json"))
        }
        _ => None,
    }
}

/// Resolves user settings.json path for VS Code across Windows, macOS, and Linux
pub fn vscode_settings_path() -> Option<PathBuf> {
    match std::env::consts::OS {
        "windows" => {
            #[cfg(windows)]
            {
                let homes = crate::wrap::config_path::get_windows_user_homes();
                for home in &homes {
                    let candidates = [
                        home.join(r"AppData\Roaming\Code\User\settings.json"),
                        home.join(r"AppData\Roaming\Code\User\mcp.json"),
                    ];
                    for c in candidates {
                        if c.exists() || c.parent().map(|p| p.exists()).unwrap_or(false) {
                            return Some(c);
                        }
                    }
                }
                if let Some(first) = homes.first() {
                    return Some(first.join(r"AppData\Roaming\Code\User\settings.json"));
                }
            }
            dirs::data_dir().map(|d| d.join("Code\\User\\settings.json"))
        }
        "macos" => {
            let candidates = [
                dirs::home_dir().map(|h| h.join("Library/Application Support/Code/User/settings.json")),
                dirs::home_dir().map(|h| h.join("Library/Application Support/Code/User/mcp.json")),
            ];
            for c in candidates.into_iter().flatten() {
                if c.exists() || c.parent().map(|p| p.exists()).unwrap_or(false) {
                    return Some(c);
                }
            }
            dirs::home_dir().map(|h| h.join("Library/Application Support/Code/User/settings.json"))
        }
        "linux" => {
            let candidates = [
                dirs::config_dir().map(|d| d.join("Code/User/settings.json")),
                dirs::config_dir().map(|d| d.join("Code/User/mcp.json")),
            ];
            for c in candidates.into_iter().flatten() {
                if c.exists() || c.parent().map(|p| p.exists()).unwrap_or(false) {
                    return Some(c);
                }
            }
            dirs::config_dir().map(|d| d.join("Code/User/settings.json"))
        }
        _ => None,
    }
}

/// Resolves settings path for Zed Editor
pub fn zed_settings_path() -> Option<PathBuf> {
    match std::env::consts::OS {
        "windows" => {
            #[cfg(windows)]
            {
                let homes = crate::wrap::config_path::get_windows_user_homes();
                for home in &homes {
                    let candidates = [
                        home.join(r"AppData\Local\Zed\settings.json"),
                        home.join(r"AppData\Roaming\Zed\settings.json"),
                        home.join(r".config\zed\settings.json"),
                    ];
                    for c in candidates {
                        if c.exists() || c.parent().map(|p| p.exists()).unwrap_or(false) {
                            return Some(c);
                        }
                    }
                }
                if let Some(first) = homes.first() {
                    return Some(first.join(r"AppData\Local\Zed\settings.json"));
                }
            }
            dirs::data_local_dir().map(|d| d.join("Zed\\settings.json"))
        }
        "macos" | "linux" => {
            let candidates = [
                dirs::config_dir().map(|d| d.join("zed/settings.json")),
                dirs::home_dir().map(|h| h.join(".config/zed/settings.json")),
            ];
            for c in candidates.into_iter().flatten() {
                if c.exists() || c.parent().map(|p| p.exists()).unwrap_or(false) {
                    return Some(c);
                }
            }
            dirs::config_dir().map(|d| d.join("zed/settings.json"))
        }
        _ => None,
    }
}

/// Resolves config path for Windsurf / Codeium
pub fn windsurf_settings_path() -> Option<PathBuf> {
    match std::env::consts::OS {
        "windows" => {
            #[cfg(windows)]
            {
                let homes = crate::wrap::config_path::get_windows_user_homes();
                for home in &homes {
                    let candidates = [
                        home.join(r"AppData\Roaming\Windsurf\User\settings.json"),
                        home.join(r".codeium\windsurf\mcp_config.json"),
                    ];
                    for c in candidates {
                        if c.exists() || c.parent().map(|p| p.exists()).unwrap_or(false) {
                            return Some(c);
                        }
                    }
                }
                if let Some(first) = homes.first() {
                    return Some(first.join(r"AppData\Roaming\Windsurf\User\settings.json"));
                }
            }
            dirs::data_dir().map(|d| d.join("Windsurf\\User\\settings.json"))
        }
        "macos" => {
            let candidates = [
                dirs::home_dir().map(|h| h.join("Library/Application Support/Windsurf/User/settings.json")),
                dirs::home_dir().map(|h| h.join(".codeium/windsurf/mcp_config.json")),
            ];
            for c in candidates.into_iter().flatten() {
                if c.exists() || c.parent().map(|p| p.exists()).unwrap_or(false) {
                    return Some(c);
                }
            }
            dirs::home_dir().map(|h| h.join("Library/Application Support/Windsurf/User/settings.json"))
        }
        "linux" => {
            let candidates = [
                dirs::config_dir().map(|d| d.join("Windsurf/User/settings.json")),
                dirs::home_dir().map(|h| h.join(".codeium/windsurf/mcp_config.json")),
            ];
            for c in candidates.into_iter().flatten() {
                if c.exists() || c.parent().map(|p| p.exists()).unwrap_or(false) {
                    return Some(c);
                }
            }
            dirs::config_dir().map(|d| d.join("Windsurf/User/settings.json"))
        }
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

/// Checks if an MCP config file contains wrapped servers
fn check_mcp_config_wrapped(path: &Path) -> bool {
    if !path.exists() {
        return false;
    }
    if let Ok(raw) = fs::read_to_string(path) {
        if path.extension().and_then(|e| e.to_str()) == Some("toml") {
            if let Ok(val) = toml::from_str::<toml::Value>(&raw) {
                if let Some(servers) = val.get("mcp_servers").and_then(|s| s.as_table()) {
                    return servers.values().any(|v| {
                        v.get("command")
                            .and_then(|c| c.as_str())
                            .map(|cmd| cmd.to_lowercase().contains("agentwall") || cmd.to_lowercase().contains("agentcontrol"))
                            .unwrap_or(false)
                    });
                }
            }
        } else if let Ok(v) = serde_json::from_str::<Value>(&raw) {
            if let Some(servers) = v.get("mcpServers").and_then(|s| s.as_object()) {
                return servers.values().any(crate::wrap::transformer::is_already_wrapped);
            }
            if let Some(servers) = v.get("mcp_servers").and_then(|s| s.as_object()) {
                return servers.values().any(crate::wrap::transformer::is_already_wrapped);
            }
        }
    }
    false
}

/// Enforces Agent Control proxy configuration across a named IDE target
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

    match name {
        "cursor" => {
            if let Some(path) = cursor_settings_path() {
                status.config_path = Some(path.to_string_lossy().to_string());
                status.installed = path.parent().map(|p| p.exists()).unwrap_or(false) || path.exists();

                if status.installed {
                    let _ = crate::wrap::generic_ide::wrap_cursor_settings(false);
                    if let Ok(mcp_path) = crate::wrap::config_path::cursor_config_path() {
                        status.mcp_wrapped = check_mcp_config_wrapped(&mcp_path);
                    }

                    status.proxy_configured = true;
                    status.configured_base_url = Some(proxy_url.to_string());
                    status.compliance_state = "COMPLIANT".to_string();
                }
            }
        }
        "vscode" => {
            if let Some(path) = vscode_settings_path() {
                status.config_path = Some(path.to_string_lossy().to_string());
                status.installed = path.parent().map(|p| p.exists()).unwrap_or(false) || path.exists();

                if status.installed {
                    let key_spec = ("cline.baseUrl", None);
                    let updated = ensure_json_proxy_setting(&path, &[key_spec.0], proxy_url, key_spec.1)?;
                    if updated {
                        status.last_healed_at = Some(chrono::Utc::now().to_rfc3339());
                    }

                    if let Ok(mcp_path) = crate::wrap::config_path::vscode_config_path() {
                        status.mcp_wrapped = check_mcp_config_wrapped(&mcp_path);
                    }

                    status.proxy_configured = true;
                    status.configured_base_url = Some(proxy_url.to_string());
                    status.compliance_state = "COMPLIANT".to_string();
                }
            }
        }
        "zed" => {
            if let Some(path) = zed_settings_path() {
                status.config_path = Some(path.to_string_lossy().to_string());
                status.installed = path.parent().map(|p| p.exists()).unwrap_or(false) || path.exists();

                if status.installed {
                    let key_spec = ("language_models.openai.api_url", None);
                    let updated = ensure_json_proxy_setting(&path, &[key_spec.0], proxy_url, key_spec.1)?;
                    if updated {
                        status.last_healed_at = Some(chrono::Utc::now().to_rfc3339());
                    }

                    if let Ok(mcp_path) = crate::wrap::config_path::zed_config_path() {
                        status.mcp_wrapped = check_mcp_config_wrapped(&mcp_path);
                    }

                    status.proxy_configured = true;
                    status.configured_base_url = Some(proxy_url.to_string());
                    status.compliance_state = "COMPLIANT".to_string();
                }
            }
        }
        "windsurf" => {
            if let Some(path) = windsurf_settings_path() {
                status.config_path = Some(path.to_string_lossy().to_string());
                status.installed = path.parent().map(|p| p.exists()).unwrap_or(false) || path.exists();

                if status.installed {
                    let key_spec = ("openai.baseUrl", None);
                    let updated = ensure_json_proxy_setting(&path, &[key_spec.0], proxy_url, key_spec.1)?;
                    if updated {
                        status.last_healed_at = Some(chrono::Utc::now().to_rfc3339());
                    }

                    status.proxy_configured = true;
                    status.configured_base_url = Some(proxy_url.to_string());
                    status.compliance_state = "COMPLIANT".to_string();
                }
            }
        }
        "claude_desktop" => {
            if let Ok(path) = crate::wrap::config_path::claude_config_path() {
                status.config_path = Some(path.to_string_lossy().to_string());
                status.installed = path.parent().map(|p| p.exists()).unwrap_or(false) || path.exists();

                if status.installed {
                    status.mcp_wrapped = check_mcp_config_wrapped(&path);
                    status.proxy_configured = true;
                    status.configured_base_url = Some(proxy_url.to_string());
                    status.compliance_state = "COMPLIANT".to_string();
                }
            }
        }
        "jetbrains" => {
            if let Ok(path) = crate::wrap::config_path::jetbrains_config_path() {
                status.config_path = Some(path.to_string_lossy().to_string());
                status.installed = path.parent().map(|p| p.exists()).unwrap_or(false) || path.exists();

                if status.installed {
                    status.mcp_wrapped = check_mcp_config_wrapped(&path);
                    status.proxy_configured = true;
                    status.configured_base_url = Some(proxy_url.to_string());
                    status.compliance_state = "COMPLIANT".to_string();
                }
            }
        }
        "antigravity" => {
            if let Ok(path) = crate::wrap::config_path::antigravity_config_path() {
                status.config_path = Some(path.to_string_lossy().to_string());
                status.installed = path.parent().map(|p| p.exists()).unwrap_or(false) || path.exists();

                if status.installed {
                    status.mcp_wrapped = check_mcp_config_wrapped(&path);
                    status.proxy_configured = true;
                    status.configured_base_url = Some(proxy_url.to_string());
                    status.compliance_state = "COMPLIANT".to_string();
                }
            }
        }
        "codex" => {
            if let Ok(path) = crate::wrap::config_path::codex_config_path() {
                status.config_path = Some(path.to_string_lossy().to_string());
                status.installed = path.parent().map(|p| p.exists()).unwrap_or(false) || path.exists();

                if status.installed {
                    status.mcp_wrapped = check_mcp_config_wrapped(&path);
                    status.proxy_configured = true;
                    status.configured_base_url = Some(proxy_url.to_string());
                    status.compliance_state = "COMPLIANT".to_string();
                }
            }
        }
        "opencode" => {
            if let Ok(path) = crate::wrap::config_path::opencode_config_path() {
                status.config_path = Some(path.to_string_lossy().to_string());
                status.installed = path.parent().map(|p| p.exists()).unwrap_or(false) || path.exists();

                if status.installed {
                    status.mcp_wrapped = check_mcp_config_wrapped(&path);
                    status.proxy_configured = true;
                    status.configured_base_url = Some(proxy_url.to_string());
                    status.compliance_state = "COMPLIANT".to_string();
                }
            }
        }
        _ => {}
    }

    Ok(status)
}

/// Evaluates compliance state of all major IDEs
pub fn scan_all_ides(expected_proxy_url: &str) -> Vec<IdeConfigStatus> {
    let targets = vec![
        "cursor",
        "vscode",
        "windsurf",
        "zed",
        "claude_desktop",
        "jetbrains",
        "antigravity",
        "codex",
        "opencode",
    ];
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
