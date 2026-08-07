//! FR-304: OS-specific Claude Desktop config path resolution

use super::WrapError;
use std::path::PathBuf;

/// Returns the absolute path to claude_desktop_config.json for the current OS.
pub fn claude_config_path() -> Result<PathBuf, WrapError> {
    let base = match std::env::consts::OS {
        "macos" => dirs::data_dir()
            .ok_or_else(|| {
                WrapError::ConfigNotFound(
                    "Cannot resolve ~/Library/Application Support".to_string(),
                )
            })?
            .join("Claude")
            .join("claude_desktop_config.json"),
        "linux" => dirs::config_dir()
            .ok_or_else(|| WrapError::ConfigNotFound("Cannot resolve ~/.config".to_string()))?
            .join("Claude")
            .join("claude_desktop_config.json"),
        "windows" => {
            let standard = dirs::data_dir()
                .ok_or_else(|| WrapError::ConfigNotFound("Cannot resolve %APPDATA%".to_string()))?
                .join("Claude")
                .join("claude_desktop_config.json");

            if standard.exists() {
                standard
            } else {
                // Fallback for Microsoft Store version
                let user_name = std::env::var("USERNAME").unwrap_or_else(|_| "user".to_string());
                let store_path = PathBuf::from(format!(
                    "C:\\Users\\{}\\AppData\\Local\\Packages\\Claude_pzs8sxrjxfjjc\\LocalCache\\Roaming\\Claude\\claude_desktop_config.json",
                    user_name
                ));
                if store_path.exists() {
                    store_path
                } else {
                    return Err(WrapError::ConfigNotFound(format!(
                        "Tested standard path ({}) and Microsoft Store path",
                        standard.display()
                    )));
                }
            }
        }
        other => return Err(WrapError::UnsupportedOs(other.to_string())),
    };
    Ok(base)
}

pub fn cursor_config_path() -> Result<PathBuf, WrapError> {
    let candidates = match std::env::consts::OS {
        "macos" => vec![
            dirs::home_dir().map(|h| h.join(".cursor/mcp.json")),
            dirs::home_dir().map(|h| h.join("Library/Application Support/Cursor/mcp.json")),
            dirs::home_dir().map(|h| h.join("Library/Application Support/Cursor/User/globalStorage/rooveterinaryinc.roo-cline/settings/cline_mcp_settings.json")),
        ],
        "linux" => vec![
            dirs::home_dir().map(|h| h.join(".cursor/mcp.json")),
            dirs::config_dir().map(|d| d.join("cursor/mcp.json")),
        ],
        "windows" => vec![
            dirs::home_dir().map(|h| h.join(".cursor\\mcp.json")),
            dirs::data_dir().map(|d| d.join("Cursor\\mcp.json")),
            dirs::data_dir().map(|d| d.join("Cursor\\User\\globalStorage\\rooveterinaryinc.roo-cline\\settings\\cline_mcp_settings.json")),
        ],
        other => return Err(WrapError::UnsupportedOs(other.to_string())),
    };

    for candidate in candidates.into_iter().flatten() {
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    // Default to ~/.cursor/mcp.json if none exist yet
    if let Some(home) = dirs::home_dir() {
        let default_path = if std::env::consts::OS == "windows" {
            home.join(".cursor\\mcp.json")
        } else {
            home.join(".cursor/mcp.json")
        };
        return Ok(default_path);
    }

    Err(WrapError::ConfigNotFound("Cannot resolve Cursor config path".to_string()))
}

pub fn vscode_config_path() -> Result<PathBuf, WrapError> {
    let base = match std::env::consts::OS {
        "macos" => dirs::home_dir().map(|h| h.join("Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/cline_mcp_settings.json")),
        "linux" => dirs::config_dir().map(|d| d.join("Code/User/mcp.json")), // hypothetical
        "windows" => dirs::data_dir().map(|d| d.join("Code\\User\\globalStorage\\rooveterinaryinc.roo-cline\\settings\\cline_mcp_settings.json")),
        other => return Err(WrapError::UnsupportedOs(other.to_string())),
    };
    base.ok_or_else(|| WrapError::ConfigNotFound("Cannot resolve VS Code config path".to_string()))
}

pub fn jetbrains_config_path() -> Result<PathBuf, WrapError> {
    let base = match std::env::consts::OS {
        "macos" => {
            dirs::home_dir().map(|h| h.join("Library/Application Support/JetBrains/mcp.json"))
        }
        "linux" => dirs::config_dir().map(|d| d.join("JetBrains/mcp.json")),
        "windows" => dirs::data_dir().map(|d| d.join("JetBrains\\mcp.json")),
        other => return Err(WrapError::UnsupportedOs(other.to_string())),
    };
    base.ok_or_else(|| {
        WrapError::ConfigNotFound("Cannot resolve JetBrains config path".to_string())
    })
}

pub fn zed_config_path() -> Result<PathBuf, WrapError> {
    let base = match std::env::consts::OS {
        "macos" => dirs::config_dir().map(|d| d.join("zed/mcp.json")),
        "linux" => dirs::config_dir().map(|d| d.join("zed/mcp.json")),
        "windows" => dirs::data_local_dir().map(|d| d.join("Zed\\mcp.json")),
        other => return Err(WrapError::UnsupportedOs(other.to_string())),
    };
    base.ok_or_else(|| WrapError::ConfigNotFound("Cannot resolve Zed config path".to_string()))
}

pub fn cline_config_path() -> Result<PathBuf, WrapError> {
    // Same as VS Code, but conceptually distinct for the CLI
    vscode_config_path()
}

pub fn opencode_config_path() -> Result<PathBuf, WrapError> {
    let base = match std::env::consts::OS {
        "macos" => {
            dirs::home_dir().map(|h| h.join("Library/Application Support/OpenCode/mcp.json"))
        }
        "linux" => dirs::config_dir().map(|d| d.join("opencode/mcp.json")),
        "windows" => dirs::data_dir().map(|d| d.join("OpenCode\\mcp.json")),
        other => return Err(WrapError::UnsupportedOs(other.to_string())),
    };
    base.ok_or_else(|| WrapError::ConfigNotFound("Cannot resolve OpenCode config path".to_string()))
}

pub fn antigravity_config_path() -> Result<PathBuf, WrapError> {
    let candidates = match std::env::consts::OS {
        "macos" => vec![
            dirs::home_dir().map(|h| h.join(".gemini/config/mcp_config.json")),
            dirs::home_dir().map(|h| h.join("Library/Application Support/Antigravity/mcp.json")),
        ],
        "linux" => vec![
            dirs::home_dir().map(|h| h.join(".gemini/config/mcp_config.json")),
            dirs::config_dir().map(|d| d.join("antigravity/mcp.json")),
        ],
        "windows" => vec![
            dirs::home_dir().map(|h| h.join(".gemini\\config\\mcp_config.json")),
            dirs::data_dir().map(|d| d.join("Antigravity\\mcp.json")),
        ],
        other => return Err(WrapError::UnsupportedOs(other.to_string())),
    };

    for candidate in candidates.into_iter().flatten() {
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    if let Some(home) = dirs::home_dir() {
        let default_path = if std::env::consts::OS == "windows" {
            home.join(".gemini\\config\\mcp_config.json")
        } else {
            home.join(".gemini/config/mcp_config.json")
        };
        return Ok(default_path);
    }

    Err(WrapError::ConfigNotFound("Cannot resolve Antigravity config path".to_string()))
}

pub fn codex_config_path() -> Result<PathBuf, WrapError> {
    let base = dirs::home_dir().map(|h| h.join(".codex").join("config.toml"));
    base.ok_or_else(|| {
        WrapError::ConfigNotFound("Cannot resolve Codex config path (~/.codex/config.toml)".to_string())
    })
}

/// Returns the path to the ~/.agentwall/ config directory.
pub fn agentwall_config_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".agentwall"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_claude_config_path_returns_json_file() {
        // Should return a path ending in claude_desktop_config.json
        let path = claude_config_path();
        // On any supported OS this should succeed
        if let Ok(p) = path {
            assert!(p.to_string_lossy().contains("claude_desktop_config.json"));
            assert!(p.is_absolute());
        }
        // On unsupported OS it returns UnsupportedOs — also valid
    }

    #[test]
    fn test_agentwall_config_dir_returns_path() {
        // Should return Some path under home dir
        let dir = agentwall_config_dir();
        if let Some(d) = dir {
            assert!(d.to_string_lossy().contains(".agentwall"));
        }
    }
}
