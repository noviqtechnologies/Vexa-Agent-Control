//! Secure Cross-Platform Credential Storage Abstraction (REQ-SEC-002, REQ-SEC-003)
//!
//! Provides a tiered credential storage engine:
//! 1. Native OS Keyring (`keyring-rs`) under service `io.vexasec.agentcontrol`.
//! 2. Headless Linux mode: Strict POSIX file permissions `0600` (parent `0700`).
//! 3. Windows file fallback: Restricted user file under `%LOCALAPPDATA%\AgentControl\credentials.token`.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

pub const SERVICE_NAME: &str = "io.vexasec.agentcontrol";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageType {
    OsKeyring,
    StrictPermFile,
    WindowsUserFallback,
}

impl StorageType {
    pub fn description(&self) -> &'static str {
        match self {
            Self::OsKeyring => "OS Native Keyring / Credential Vault",
            Self::StrictPermFile => "STRICT_PERM_FILE (Headless Mode; Filesystem Access Control Only)",
            Self::WindowsUserFallback => "Windows User Application Data Store",
        }
    }
}

pub struct CredentialStore;

impl CredentialStore {
    /// Save a secret credential for a given key identifier.
    pub fn set(key: &str, secret: &str) -> Result<(), String> {
        // First try OS Keyring
        if let Ok(entry) = keyring::Entry::new(SERVICE_NAME, key) {
            if entry.set_password(secret).is_ok() {
                return Ok(());
            }
        }

        // Fallback to strict permission user file
        Self::set_fallback_file(key, secret)
    }

    /// Retrieve a secret credential for a given key identifier.
    pub fn get(key: &str) -> Result<Option<String>, String> {
        // First try OS Keyring
        if let Ok(entry) = keyring::Entry::new(SERVICE_NAME, key) {
            if let Ok(secret) = entry.get_password() {
                return Ok(Some(secret));
            }
        }

        // Fallback to strict permission user file
        Self::get_fallback_file(key)
    }

    /// Delete a secret credential.
    pub fn delete(key: &str) -> Result<(), String> {
        if let Ok(entry) = keyring::Entry::new(SERVICE_NAME, key) {
            let _ = entry.delete_password();
        }
        Self::delete_fallback_file(key)
    }

    /// Detect current active storage type.
    pub fn active_storage_type(key: &str) -> StorageType {
        if let Ok(entry) = keyring::Entry::new(SERVICE_NAME, key) {
            if entry.get_password().is_ok() {
                return StorageType::OsKeyring;
            }
        }
        #[cfg(windows)]
        {
            StorageType::WindowsUserFallback
        }
        #[cfg(not(windows))]
        {
            StorageType::StrictPermFile
        }
    }

    fn fallback_path(key: &str) -> Result<PathBuf, String> {
        #[cfg(windows)]
        {
            let base = dirs::data_local_dir()
                .or_else(dirs::home_dir)
                .ok_or_else(|| "Could not resolve local app data or home directory".to_string())?;
            let dir = base.join("AgentControl");
            let _ = fs::create_dir_all(&dir);
            Ok(dir.join(format!("{}.token", key)))
        }
        #[cfg(not(windows))]
        {
            let base = dirs::config_dir()
                .or_else(dirs::home_dir)
                .ok_or_else(|| "Could not resolve config or home directory".to_string())?;
            let dir = base.join("agentcontrol");
            let _ = fs::create_dir_all(&dir);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
            }
            Ok(dir.join(format!("{}.token", key)))
        }
    }

    fn set_fallback_file(key: &str, secret: &str) -> Result<(), String> {
        let path = Self::fallback_path(key)?;
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .map_err(|e| format!("failed to open credential file: {}", e))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("failed to set strict file permissions 0600: {}", e))?;
        }

        file.write_all(secret.as_bytes())
            .map_err(|e| format!("failed to write credential file: {}", e))?;

        Ok(())
    }

    fn get_fallback_file(key: &str) -> Result<Option<String>, String> {
        let path = Self::fallback_path(key)?;
        if !path.exists() {
            // Also check legacy ~/.agentcontrol/<key> for migration
            if let Some(home) = dirs::home_dir() {
                let legacy_path = home.join(".agentcontrol").join(key);
                if legacy_path.exists() {
                    if let Ok(content) = fs::read_to_string(&legacy_path) {
                        let trimmed = content.trim().to_string();
                        if !trimmed.is_empty() {
                            return Ok(Some(trimmed));
                        }
                    }
                }
            }
            return Ok(None);
        }
        let content = fs::read_to_string(&path)
            .map_err(|e| format!("failed to read credential file: {}", e))?;
        let trimmed = content.trim().to_string();
        if trimmed.is_empty() {
            Ok(None)
        } else {
            Ok(Some(trimmed))
        }
    }

    fn delete_fallback_file(key: &str) -> Result<(), String> {
        let path = Self::fallback_path(key)?;
        if path.exists() {
            let _ = fs::remove_file(path);
        }
        if let Some(home) = dirs::home_dir() {
            let legacy_path = home.join(".agentcontrol").join(key);
            if legacy_path.exists() {
                let _ = fs::remove_file(legacy_path);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_store_roundtrip() {
        let test_key = "test_device_token_xyz";
        let test_secret = "eyJhbGciOiJFZERTQSI...test_payload";

        let set_res = CredentialStore::set(test_key, test_secret);
        assert!(set_res.is_ok(), "Failed to set credential: {:?}", set_res);

        let retrieved = CredentialStore::get(test_key);
        assert!(retrieved.is_ok());
        assert_eq!(retrieved.unwrap(), Some(test_secret.to_string()));

        let del_res = CredentialStore::delete(test_key);
        assert!(del_res.is_ok());

        let after_delete = CredentialStore::get(test_key);
        assert!(after_delete.is_ok());
        assert_eq!(after_delete.unwrap(), None);
    }
}

