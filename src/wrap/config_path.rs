//! FR-304: OS-specific Claude Desktop and IDE config path resolution

use super::WrapError;
use std::path::PathBuf;

/// Helper on Windows to resolve human user profile home directories (C:\Users\<user>).
/// Ensures that when running as a Windows Service (Session 0 under SYSTEM),
/// IDE configs in developer accounts are properly discovered.
#[cfg(windows)]
pub fn get_windows_user_homes() -> Vec<PathBuf> {
    let mut homes = Vec::new();

    // 1. If dirs::home_dir() is a real human user profile (not systemprofile), add it first
    if let Some(h) = dirs::home_dir() {
        let s = h.to_string_lossy().to_lowercase();
        if !s.contains(r"system32\config\systemprofile") && !s.contains(r"windows\system32") {
            homes.push(h);
        }
    }

    // 2. Enumerate C:\Users\*
    let users_dir = PathBuf::from(r"C:\Users");
    if users_dir.exists() {
        if let Ok(entries) = std::fs::read_dir(&users_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let name = entry.file_name().to_string_lossy().to_lowercase();
                    if name != "public"
                        && name != "default"
                        && name != "default user"
                        && name != "all users"
                        && !name.starts_with("default.")
                    {
                        if !homes.contains(&path) {
                            homes.push(path);
                        }
                    }
                }
            }
        }
    }

    // 3. Fallback to dirs::home_dir() if empty
    if homes.is_empty() {
        if let Some(h) = dirs::home_dir() {
            homes.push(h);
        }
    }

    homes
}

/// Returns the absolute path to claude_desktop_config.json for the current OS.
pub fn claude_config_path() -> Result<PathBuf, WrapError> {
    match std::env::consts::OS {
        "macos" => {
            let p = dirs::data_dir()
                .ok_or_else(|| {
                    WrapError::ConfigNotFound(
                        "Cannot resolve ~/Library/Application Support".to_string(),
                    )
                })?
                .join("Claude")
                .join("claude_desktop_config.json");
            Ok(p)
        }
        "linux" => {
            let p = dirs::config_dir()
                .ok_or_else(|| WrapError::ConfigNotFound("Cannot resolve ~/.config".to_string()))?
                .join("Claude")
                .join("claude_desktop_config.json");
            Ok(p)
        }
        "windows" => {
            #[cfg(windows)]
            {
                let homes = get_windows_user_homes();
                for home in &homes {
                    let standard = home.join(r"AppData\Roaming\Claude\claude_desktop_config.json");
                    if standard.exists() {
                        return Ok(standard);
                    }
                    let store = home.join(r"AppData\Local\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\claude_desktop_config.json");
                    if store.exists() {
                        return Ok(store);
                    }
                }
                if let Some(first) = homes.first() {
                    return Ok(first.join(r"AppData\Roaming\Claude\claude_desktop_config.json"));
                }
            }
            let standard = dirs::data_dir()
                .ok_or_else(|| WrapError::ConfigNotFound("Cannot resolve %APPDATA%".to_string()))?
                .join("Claude")
                .join("claude_desktop_config.json");
            Ok(standard)
        }
        other => Err(WrapError::UnsupportedOs(other.to_string())),
    }
}

pub fn cursor_config_path() -> Result<PathBuf, WrapError> {
    match std::env::consts::OS {
        "macos" => {
            let candidates = vec![
                dirs::home_dir().map(|h| h.join(".cursor/mcp.json")),
                dirs::home_dir().map(|h| h.join("Library/Application Support/Cursor/mcp.json")),
                dirs::home_dir().map(|h| h.join("Library/Application Support/Cursor/User/globalStorage/rooveterinaryinc.roo-cline/settings/cline_mcp_settings.json")),
            ];
            for candidate in candidates.into_iter().flatten() {
                if candidate.exists() {
                    return Ok(candidate);
                }
            }
            if let Some(home) = dirs::home_dir() {
                return Ok(home.join(".cursor/mcp.json"));
            }
            Err(WrapError::ConfigNotFound("Cannot resolve Cursor config path".to_string()))
        }
        "linux" => {
            let candidates = vec![
                dirs::home_dir().map(|h| h.join(".cursor/mcp.json")),
                dirs::config_dir().map(|d| d.join("cursor/mcp.json")),
            ];
            for candidate in candidates.into_iter().flatten() {
                if candidate.exists() {
                    return Ok(candidate);
                }
            }
            if let Some(home) = dirs::home_dir() {
                return Ok(home.join(".cursor/mcp.json"));
            }
            Err(WrapError::ConfigNotFound("Cannot resolve Cursor config path".to_string()))
        }
        "windows" => {
            #[cfg(windows)]
            {
                let homes = get_windows_user_homes();
                for home in &homes {
                    let candidates = [
                        home.join(r".cursor\mcp.json"),
                        home.join(r"AppData\Roaming\Cursor\mcp.json"),
                        home.join(r"AppData\Roaming\Cursor\User\globalStorage\rooveterinaryinc.roo-cline\settings\cline_mcp_settings.json"),
                        home.join(r"AppData\Roaming\Cursor\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json"),
                    ];
                    for c in candidates {
                        if c.exists() {
                            return Ok(c);
                        }
                    }
                }
                if let Some(first) = homes.first() {
                    return Ok(first.join(r".cursor\mcp.json"));
                }
            }
            if let Some(home) = dirs::home_dir() {
                return Ok(home.join(r".cursor\mcp.json"));
            }
            Err(WrapError::ConfigNotFound("Cannot resolve Cursor config path".to_string()))
        }
        other => Err(WrapError::UnsupportedOs(other.to_string())),
    }
}

pub fn vscode_config_path() -> Result<PathBuf, WrapError> {
    match std::env::consts::OS {
        "macos" => {
            let base = dirs::home_dir().map(|h| h.join("Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/cline_mcp_settings.json"));
            base.ok_or_else(|| WrapError::ConfigNotFound("Cannot resolve VS Code config path".to_string()))
        }
        "linux" => {
            let base = dirs::config_dir().map(|d| d.join("Code/User/mcp.json"));
            base.ok_or_else(|| WrapError::ConfigNotFound("Cannot resolve VS Code config path".to_string()))
        }
        "windows" => {
            #[cfg(windows)]
            {
                let homes = get_windows_user_homes();
                for home in &homes {
                    let candidates = [
                        home.join(r"AppData\Roaming\Code\User\globalStorage\rooveterinaryinc.roo-cline\settings\cline_mcp_settings.json"),
                        home.join(r"AppData\Roaming\Code\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json"),
                        home.join(r"AppData\Roaming\Code\User\settings.json"),
                        home.join(r"AppData\Roaming\Code\User\mcp.json"),
                    ];
                    for c in candidates {
                        if c.exists() {
                            return Ok(c);
                        }
                    }
                }
                if let Some(first) = homes.first() {
                    return Ok(first.join(r"AppData\Roaming\Code\User\globalStorage\rooveterinaryinc.roo-cline\settings\cline_mcp_settings.json"));
                }
            }
            let base = dirs::data_dir().map(|d| d.join(r"Code\User\globalStorage\rooveterinaryinc.roo-cline\settings\cline_mcp_settings.json"));
            base.ok_or_else(|| WrapError::ConfigNotFound("Cannot resolve VS Code config path".to_string()))
        }
        other => Err(WrapError::UnsupportedOs(other.to_string())),
    }
}

pub fn jetbrains_config_path() -> Result<PathBuf, WrapError> {
    match std::env::consts::OS {
        "macos" => {
            let base = dirs::home_dir().map(|h| h.join("Library/Application Support/JetBrains/mcp.json"));
            base.ok_or_else(|| WrapError::ConfigNotFound("Cannot resolve JetBrains config path".to_string()))
        }
        "linux" => {
            let base = dirs::config_dir().map(|d| d.join("JetBrains/mcp.json"));
            base.ok_or_else(|| WrapError::ConfigNotFound("Cannot resolve JetBrains config path".to_string()))
        }
        "windows" => {
            #[cfg(windows)]
            {
                let homes = get_windows_user_homes();
                for home in &homes {
                    let candidate = home.join(r"AppData\Roaming\JetBrains\mcp.json");
                    if candidate.exists() {
                        return Ok(candidate);
                    }
                }
                if let Some(first) = homes.first() {
                    return Ok(first.join(r"AppData\Roaming\JetBrains\mcp.json"));
                }
            }
            let base = dirs::data_dir().map(|d| d.join(r"JetBrains\mcp.json"));
            base.ok_or_else(|| WrapError::ConfigNotFound("Cannot resolve JetBrains config path".to_string()))
        }
        other => Err(WrapError::UnsupportedOs(other.to_string())),
    }
}

pub fn zed_config_path() -> Result<PathBuf, WrapError> {
    match std::env::consts::OS {
        "macos" => {
            let base = dirs::config_dir().map(|d| d.join("zed/mcp.json"));
            base.ok_or_else(|| WrapError::ConfigNotFound("Cannot resolve Zed config path".to_string()))
        }
        "linux" => {
            let base = dirs::config_dir().map(|d| d.join("zed/mcp.json"));
            base.ok_or_else(|| WrapError::ConfigNotFound("Cannot resolve Zed config path".to_string()))
        }
        "windows" => {
            #[cfg(windows)]
            {
                let homes = get_windows_user_homes();
                for home in &homes {
                    let candidates = [
                        home.join(r"AppData\Local\Zed\mcp.json"),
                        home.join(r"AppData\Roaming\Zed\settings.json"),
                        home.join(r".config\zed\settings.json"),
                    ];
                    for c in candidates {
                        if c.exists() {
                            return Ok(c);
                        }
                    }
                }
                if let Some(first) = homes.first() {
                    return Ok(first.join(r"AppData\Local\Zed\mcp.json"));
                }
            }
            let base = dirs::data_local_dir().map(|d| d.join(r"Zed\mcp.json"));
            base.ok_or_else(|| WrapError::ConfigNotFound("Cannot resolve Zed config path".to_string()))
        }
        other => Err(WrapError::UnsupportedOs(other.to_string())),
    }
}

pub fn cline_config_path() -> Result<PathBuf, WrapError> {
    vscode_config_path()
}

pub fn opencode_config_path() -> Result<PathBuf, WrapError> {
    match std::env::consts::OS {
        "macos" => {
            let base = dirs::home_dir().map(|h| h.join("Library/Application Support/OpenCode/mcp.json"));
            base.ok_or_else(|| WrapError::ConfigNotFound("Cannot resolve OpenCode config path".to_string()))
        }
        "linux" => {
            let base = dirs::config_dir().map(|d| d.join("opencode/mcp.json"));
            base.ok_or_else(|| WrapError::ConfigNotFound("Cannot resolve OpenCode config path".to_string()))
        }
        "windows" => {
            #[cfg(windows)]
            {
                let homes = get_windows_user_homes();
                for home in &homes {
                    let candidates = [
                        home.join(r"AppData\Roaming\OpenCode\mcp.json"),
                        home.join(r".opencode\mcp.json"),
                    ];
                    for c in candidates {
                        if c.exists() {
                            return Ok(c);
                        }
                    }
                }
                if let Some(first) = homes.first() {
                    return Ok(first.join(r"AppData\Roaming\OpenCode\mcp.json"));
                }
            }
            let base = dirs::data_dir().map(|d| d.join(r"OpenCode\mcp.json"));
            base.ok_or_else(|| WrapError::ConfigNotFound("Cannot resolve OpenCode config path".to_string()))
        }
        other => Err(WrapError::UnsupportedOs(other.to_string())),
    }
}

pub fn antigravity_config_path() -> Result<PathBuf, WrapError> {
    match std::env::consts::OS {
        "macos" => {
            let candidates = vec![
                dirs::home_dir().map(|h| h.join(".gemini/config/mcp_config.json")),
                dirs::home_dir().map(|h| h.join("Library/Application Support/Antigravity/mcp.json")),
            ];
            for candidate in candidates.into_iter().flatten() {
                if candidate.exists() {
                    return Ok(candidate);
                }
            }
            if let Some(home) = dirs::home_dir() {
                return Ok(home.join(".gemini/config/mcp_config.json"));
            }
            Err(WrapError::ConfigNotFound("Cannot resolve Antigravity config path".to_string()))
        }
        "linux" => {
            let candidates = vec![
                dirs::home_dir().map(|h| h.join(".gemini/config/mcp_config.json")),
                dirs::config_dir().map(|d| d.join("antigravity/mcp.json")),
            ];
            for candidate in candidates.into_iter().flatten() {
                if candidate.exists() {
                    return Ok(candidate);
                }
            }
            if let Some(home) = dirs::home_dir() {
                return Ok(home.join(".gemini/config/mcp_config.json"));
            }
            Err(WrapError::ConfigNotFound("Cannot resolve Antigravity config path".to_string()))
        }
        "windows" => {
            #[cfg(windows)]
            {
                let homes = get_windows_user_homes();
                for home in &homes {
                    let candidates = [
                        home.join(r".gemini\config\mcp_config.json"),
                        home.join(r"AppData\Roaming\Antigravity\mcp.json"),
                        home.join(r"AppData\Local\Antigravity\mcp.json"),
                    ];
                    for c in candidates {
                        if c.exists() {
                            return Ok(c);
                        }
                    }
                }
                if let Some(first) = homes.first() {
                    return Ok(first.join(r".gemini\config\mcp_config.json"));
                }
            }
            if let Some(home) = dirs::home_dir() {
                return Ok(home.join(r".gemini\config\mcp_config.json"));
            }
            Err(WrapError::ConfigNotFound("Cannot resolve Antigravity config path".to_string()))
        }
        other => Err(WrapError::UnsupportedOs(other.to_string())),
    }
}

pub fn codex_config_path() -> Result<PathBuf, WrapError> {
    match std::env::consts::OS {
        "windows" => {
            #[cfg(windows)]
            {
                let homes = get_windows_user_homes();
                for home in &homes {
                    let candidate = home.join(r".codex\config.toml");
                    if candidate.exists() {
                        return Ok(candidate);
                    }
                }
                if let Some(first) = homes.first() {
                    return Ok(first.join(r".codex\config.toml"));
                }
            }
            let base = dirs::home_dir().map(|h| h.join(r".codex\config.toml"));
            base.ok_or_else(|| WrapError::ConfigNotFound("Cannot resolve Codex config path".to_string()))
        }
        _ => {
            let base = dirs::home_dir().map(|h| h.join(".codex").join("config.toml"));
            base.ok_or_else(|| {
                WrapError::ConfigNotFound(
                    "Cannot resolve Codex config path (~/.codex/config.toml)".to_string(),
                )
            })
        }
    }
}

/// Returns the path to the ~/.agent-control/ config directory (with fallback to ~/.agentcontrol/).
pub fn agent_control_config_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        let homes = get_windows_user_homes();
        for home in &homes {
            let new_dir = home.join(".agent-control");
            let old_dir = home.join(".agentcontrol");
            if new_dir.exists() {
                return Some(new_dir);
            }
            if old_dir.exists() {
                return Some(old_dir);
            }
        }
        if let Some(first) = homes.first() {
            return Some(first.join(".agent-control"));
        }
    }

    dirs::home_dir().map(|h| {
        let new_dir = h.join(".agent-control");
        let old_dir = h.join(".agentcontrol");
        if old_dir.exists() && !new_dir.exists() {
            old_dir
        } else {
            new_dir
        }
    })
}

/// Backward-compatible alias for agent_control_config_dir.
pub fn agentwall_config_dir() -> Option<PathBuf> {
    agent_control_config_dir()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_claude_config_path_returns_json_file() {
        let path = claude_config_path();
        if let Ok(p) = path {
            assert!(p.to_string_lossy().contains("claude_desktop_config.json"));
            assert!(p.is_absolute());
        }
    }

    #[test]
    fn test_agentwall_config_dir_returns_path() {
        let dir = agent_control_config_dir();
        assert!(dir.is_some());
    }
}

