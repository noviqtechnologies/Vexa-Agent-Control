//! Cross-platform OS trust store integration for Vexa Agent Control Root CA (FR-304).
//!
//! Provides non-elevated user-level certificate store installation and uninstallation
//! across Windows, macOS, and Linux.

use std::fmt;
use std::path::Path;
use std::process::Command;

pub const CA_COMMON_NAME: &str = "Vexa AgentControl Local CA";

#[derive(Debug)]
pub enum TrustStoreError {
    Io(std::io::Error),
    CommandFailed { cmd: String, output: String },
    UnsupportedOs(String),
}

impl fmt::Display for TrustStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {}", e),
            Self::CommandFailed { cmd, output } => {
                write!(f, "Trust store command failed ({}): {}", cmd, output)
            }
            Self::UnsupportedOs(os) => write!(f, "Unsupported OS: {}", os),
        }
    }
}

impl std::error::Error for TrustStoreError {}

impl From<std::io::Error> for TrustStoreError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Installs the local Root CA certificate into the current user's OS trust store.
/// Does not require Administrator / sudo elevation on Windows or macOS.
pub fn install_ca_to_trust_store(ca_cert_path: &Path) -> Result<(), TrustStoreError> {
    let path_str = ca_cert_path.to_string_lossy().to_string();

    #[cfg(target_os = "windows")]
    {
        // Use CurrentUser Root Store: does NOT require Administrator elevation.
        let output = Command::new("certutil")
            .args(["-addstore", "-user", "Root", &path_str])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            return Err(TrustStoreError::CommandFailed {
                cmd: format!("certutil -addstore -user Root \"{}\"", path_str),
                output: if !stderr.is_empty() { stderr } else { stdout },
            });
        }
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        // Use the user's login keychain to avoid requiring sudo.
        if let Some(home) = dirs::home_dir() {
            let keychain = home.join("Library/Keychains/login.keychain-db");
            let keychain_str = if keychain.exists() {
                keychain.to_string_lossy().to_string()
            } else {
                home.join("Library/Keychains/login.keychain")
                    .to_string_lossy()
                    .to_string()
            };

            let output = Command::new("security")
                .args([
                    "add-trusted-cert",
                    "-d",
                    "-r",
                    "trustRoot",
                    "-k",
                    &keychain_str,
                    &path_str,
                ])
                .output()?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                return Err(TrustStoreError::CommandFailed {
                    cmd: format!("security add-trusted-cert ... \"{}\"", path_str),
                    output: stderr,
                });
            }
            return Ok(());
        }
        return Err(TrustStoreError::UnsupportedOs("Cannot resolve macOS home directory".to_string()));
    }

    #[cfg(target_os = "linux")]
    {
        // Check if NSS DB exists for Chrome / Chromium / Electron
        if let Some(home) = dirs::home_dir() {
            let nss_dir = home.join(".pki/nssdb");
            if nss_dir.exists() {
                let _ = Command::new("certutil")
                    .args([
                        "-d",
                        &format!("sql:{}", nss_dir.display()),
                        "-A",
                        "-t",
                        "C,,",
                        "-n",
                        CA_COMMON_NAME,
                        "-i",
                        &path_str,
                    ])
                    .output();
            }
        }

        // If system certificates directory is writable or running as root
        let sys_ca_dir = Path::new("/usr/local/share/ca-certificates");
        if sys_ca_dir.exists() {
            let target_cert = sys_ca_dir.join("agentcontrol-ca.crt");
            if std::fs::copy(ca_cert_path, &target_cert).is_ok() {
                let _ = Command::new("update-ca-certificates").output();
                return Ok(());
            }
        }

        Ok(())
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        Err(TrustStoreError::UnsupportedOs(std::env::consts::OS.to_string()))
    }
}

/// Uninstalls the local Root CA certificate from the OS trust store.
pub fn uninstall_ca_from_trust_store() -> Result<(), TrustStoreError> {
    #[cfg(target_os = "windows")]
    {
        let output = Command::new("certutil")
            .args(["-delstore", "-user", "Root", CA_COMMON_NAME])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            // If cert wasn't found, treat as successful idempotent deletion
            if stderr.contains("not found") || stderr.contains("0x80070002") {
                return Ok(());
            }
        }
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(home) = dirs::home_dir() {
            let keychain = home.join("Library/Keychains/login.keychain-db");
            let keychain_str = if keychain.exists() {
                keychain.to_string_lossy().to_string()
            } else {
                home.join("Library/Keychains/login.keychain")
                    .to_string_lossy()
                    .to_string()
            };

            let _ = Command::new("security")
                .args(["delete-certificate", "-c", CA_COMMON_NAME, &keychain_str])
                .output();
        }
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        if let Some(home) = dirs::home_dir() {
            let nss_dir = home.join(".pki/nssdb");
            if nss_dir.exists() {
                let _ = Command::new("certutil")
                    .args([
                        "-d",
                        &format!("sql:{}", nss_dir.display()),
                        "-D",
                        "-n",
                        CA_COMMON_NAME,
                    ])
                    .output();
            }
        }

        let sys_cert = Path::new("/usr/local/share/ca-certificates/agentcontrol-ca.crt");
        if sys_cert.exists() {
            let _ = std::fs::remove_file(sys_cert);
            let _ = Command::new("update-ca-certificates").output();
        }
        Ok(())
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        Err(TrustStoreError::UnsupportedOs(std::env::consts::OS.to_string()))
    }
}

/// Checks whether the Vexa AgentControl Local CA is installed in the current OS trust store.
pub fn is_ca_installed() -> bool {
    #[cfg(target_os = "windows")]
    {
        let output = Command::new("certutil")
            .args(["-verifystore", "-user", "Root", CA_COMMON_NAME])
            .output();

        match output {
            Ok(out) => out.status.success(),
            Err(_) => false,
        }
    }

    #[cfg(target_os = "macos")]
    {
        let output = Command::new("security")
            .args(["find-certificate", "-c", CA_COMMON_NAME])
            .output();

        match output {
            Ok(out) => out.status.success(),
            Err(_) => false,
        }
    }

    #[cfg(target_os = "linux")]
    {
        let sys_cert = Path::new("/usr/local/share/ca-certificates/agentcontrol-ca.crt");
        if sys_cert.exists() {
            return true;
        }
        if let Some(home) = dirs::home_dir() {
            let ca_file = home.join(".agentcontrol/ca/agentcontrol-ca.pem");
            return ca_file.exists();
        }
        false
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        false
    }
}
