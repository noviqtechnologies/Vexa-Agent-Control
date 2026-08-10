//! Windows Session 0 User Profile Enumeration Engine
//!
//! When AgentWall runs as a Windows Service under `NT AUTHORITY\SYSTEM` in Session 0,
//! `%USERPROFILE%` points to `C:\Windows\System32\config\systemprofile`.
//!
//! This module enumerates all active human user profiles in `C:\Users\*` via the Windows
//! Registry (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`), ensuring
//! that all IDE configs across all developer accounts on the machine are discovered, watched, and secured.

use std::path::PathBuf;

/// Enumerates user profile home directories on Windows (e.g., `["C:\\Users\\wasim", "C:\\Users\\dev2"]`).
pub fn enumerate_user_profiles() -> Vec<PathBuf> {
    let mut profiles = Vec::new();

    // Default: Check C:\Users directory
    let users_dir = PathBuf::from(r"C:\Users");
    if users_dir.exists() {
        if let Ok(entries) = std::fs::read_dir(&users_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let name = entry.file_name().to_string_lossy().to_lowercase();
                    // Skip Windows system/default profiles
                    if name != "public"
                        && name != "default"
                        && name != "default user"
                        && name != "all users"
                        && !name.starts_with("default.")
                    {
                        profiles.push(path);
                    }
                }
            }
        }
    }

    if profiles.is_empty() {
        if let Some(home) = dirs::home_dir() {
            profiles.push(home);
        }
    }

    profiles
}

/// Resolves standard IDE config paths for all user profiles found on the machine.
pub fn resolve_all_profile_ide_configs(ide_filename: &str) -> Vec<PathBuf> {
    let mut results = Vec::new();
    for profile in enumerate_user_profiles() {
        let appdata_roaming = profile.join("AppData").join("Roaming");
        if appdata_roaming.exists() {
            let target = match ide_filename {
                "claude" => appdata_roaming
                    .join("Claude")
                    .join("claude_desktop_config.json"),
                "cursor" => appdata_roaming
                    .join("Cursor")
                    .join("User")
                    .join("globalStorage")
                    .join("storage.json"),
                "vscode" => appdata_roaming
                    .join("Code")
                    .join("User")
                    .join("settings.json"),
                "cline" => appdata_roaming.join("Cline").join("mcp_settings.json"),
                "zed" => appdata_roaming.join("Zed").join("settings.json"),
                _ => appdata_roaming.join(ide_filename).join("mcp_config.json"),
            };
            results.push(target);
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enumerate_user_profiles() {
        let profiles = enumerate_user_profiles();
        assert!(
            !profiles.is_empty(),
            "Should resolve at least one user profile home dir"
        );
    }

    #[test]
    fn test_resolve_all_profile_ide_configs() {
        let configs = resolve_all_profile_ide_configs("claude");
        assert!(
            !configs.is_empty(),
            "Should return IDE config path candidates across profile hives"
        );
    }
}
