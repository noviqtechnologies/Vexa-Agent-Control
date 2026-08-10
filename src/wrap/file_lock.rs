//! OS-native immutable file locking engine.
//!
//! Provides read-only permissions and OS-specific immutable file attributes:
//! - Linux: `chmod 0444` + `chattr +i`
//! - macOS: `chmod 0444` + `chflags uchg`
//! - Windows: `attrib +R` + `icacls deny write`

use colored::*;
use std::path::Path;
use std::process::Command;

/// Apply read-only permissions and OS-native immutable file locks.
pub fn lock_config_file(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Err(format!("path {} does not exist", path.display()));
    }

    let path_str = path.display().to_string();

    #[cfg(unix)]
    {
        // 1. POSIX read-only permissions (0444)
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o444);
            let _ = std::fs::set_permissions(path, perms);
        }

        #[cfg(target_os = "macos")]
        {
            // BSD chflags uchg (user immutable flag)
            let output = Command::new("chflags").args(["uchg", &path_str]).output();
            if let Err(e) = output {
                eprintln!(
                    "{} Failed to apply chflags uchg on {}: {}",
                    "⚠".yellow(),
                    path_str,
                    e
                );
            }
        }

        #[cfg(target_os = "linux")]
        {
            // Linux chattr +i (immutable attribute)
            let output = Command::new("chattr").args(["+i", &path_str]).output();
            if let Err(e) = output {
                eprintln!(
                    "{} Failed to apply chattr +i on {}: {}",
                    "⚠".yellow(),
                    path_str,
                    e
                );
            }
        }
    }

    #[cfg(windows)]
    {
        // Set read-only attribute via attrib +R
        let _ = Command::new("attrib").args(["+R", &path_str]).output();

        // Win32 icacls: Deny Write to Everyone (*S-1-1-0)
        let output = Command::new("icacls")
            .args([&path_str, "/deny", "*S-1-1-0:(W)"])
            .output();
        if let Err(e) = output {
            eprintln!(
                "{} Failed to apply icacls deny write on {}: {}",
                "⚠".yellow(),
                path_str,
                e
            );
        }
    }

    Ok(())
}

/// Temporarily unlock a config file to allow authorized AgentWall re-wrapping.
pub fn unlock_config_file(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }

    let path_str = path.display().to_string();

    #[cfg(unix)]
    {
        #[cfg(target_os = "macos")]
        {
            let _ = Command::new("chflags").args(["nouchg", &path_str]).output();
        }

        #[cfg(target_os = "linux")]
        {
            let _ = Command::new("chattr").args(["-i", &path_str]).output();
        }

        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o644);
            let _ = std::fs::set_permissions(path, perms);
        }
    }

    #[cfg(windows)]
    {
        let _ = Command::new("attrib").args(["-R", &path_str]).output();
        let _ = Command::new("icacls")
            .args([&path_str, "/remove:d", "*S-1-1-0"])
            .output();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_lock_and_unlock_config_file() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();

        assert!(lock_config_file(path).is_ok());
        assert!(unlock_config_file(path).is_ok());
    }
}
