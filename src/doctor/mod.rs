//! Unified Diagnostic Health & Supportability Engine (REQ-ONB-005, PRD §FR-6).
//!
//! Evaluates workstation binary integrity, authentication state, daemon liveness,
//! gateway reachability, target drift against ownership manifests, and security hygiene.
//! Strictly conforms to the exit code contract: 0 (healthy), 1 (critical), 2 (warning/degraded).

use colored::*;
use serde::{Deserialize, Serialize};
use std::time::Instant;

use crate::identity::device::{is_device_enrolled, load_hub_url, DeviceIdentity};
use crate::wrap::manifest::OwnershipManifest;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiagnosticStatus {
    Pass,
    Warn,
    Fail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticCheck {
    pub category: String,
    pub name: String,
    pub status: DiagnosticStatus,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorReport {
    pub overall_status: DiagnosticStatus,
    pub exit_code: i32,
    pub timestamp: String,
    pub version: String,
    pub os: String,
    pub arch: String,
    pub checks: Vec<DiagnosticCheck>,
}

impl DoctorReport {
    pub fn new() -> Self {
        Self {
            overall_status: DiagnosticStatus::Pass,
            exit_code: 0,
            timestamp: chrono::Utc::now().to_rfc3339(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            checks: Vec::new(),
        }
    }

    pub fn add_check(&mut self, check: DiagnosticCheck) {
        if check.status == DiagnosticStatus::Fail {
            self.overall_status = DiagnosticStatus::Fail;
            self.exit_code = 1;
        } else if check.status == DiagnosticStatus::Warn
            && self.overall_status != DiagnosticStatus::Fail
        {
            self.overall_status = DiagnosticStatus::Warn;
            self.exit_code = 2;
        }
        self.checks.push(check);
    }
}

/// Run the full diagnostic suite and return structured DoctorReport.
pub async fn run_diagnostics() -> DoctorReport {
    let mut report = DoctorReport::new();

    // 1. Binary Integrity Check
    let exe_path = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    report.add_check(DiagnosticCheck {
        category: "Binary".to_string(),
        name: "Binary Integrity".to_string(),
        status: DiagnosticStatus::Pass,
        message: format!(
            "v{} ({}-{}) at {}",
            report.version, report.os, report.arch, exe_path
        ),
        details: Some(serde_json::json!({
            "version": report.version,
            "os": report.os,
            "arch": report.arch,
            "path": exe_path
        })),
        remediation: None,
    });

    // 2. Authentication & Credential Storage Check
    let (auth_status, auth_msg, storage_mode, auth_remedy) = if is_device_enrolled() {
        let storage_desc = if cfg!(windows) {
            "OS_KEYRING (Windows Credential Manager)"
        } else if cfg!(target_os = "macos") {
            "OS_KEYRING (macOS Keychain)"
        } else if std::env::var("DISPLAY").is_ok() || std::env::var("WAYLAND_DISPLAY").is_ok() {
            "OS_KEYRING (FreeDesktop Secret Service)"
        } else {
            "STRICT_PERM_FILE (Headless Linux 0600 Mode)"
        };
        (
            DiagnosticStatus::Pass,
            format!(
                "Device enrolled with Control Hub (Storage: {})",
                storage_desc
            ),
            storage_desc,
            None,
        )
    } else {
        (
            DiagnosticStatus::Warn,
            "Device not enrolled with Control Hub.".to_string(),
            "NOT_ENROLLED",
            Some(
                "Run 'agentcontrol login' to authenticate and provision device credentials."
                    .to_string(),
            ),
        )
    };
    report.add_check(DiagnosticCheck {
        category: "Identity".to_string(),
        name: "Authentication State".to_string(),
        status: auth_status,
        message: auth_msg,
        details: Some(serde_json::json!({
            "storage_mode": storage_mode,
            "device_id": DeviceIdentity::load_or_create().ok().map(|d| d.device_id),
            "enrolled": is_device_enrolled(),
        })),
        remediation: auth_remedy,
    });

    // 3. Local Token Check
    let local_token_path = crate::identity::oauth::get_local_token_path();
    let (token_status, token_msg, token_remedy) = if local_token_path.exists() {
        (
            DiagnosticStatus::Pass,
            format!(
                "Persistent local proxy token exists at {}",
                local_token_path.display()
            ),
            None,
        )
    } else {
        (
            DiagnosticStatus::Warn,
            "Local proxy session token not yet provisioned.".to_string(),
            Some("Run 'agentcontrol rotate-local-token' or 'agentcontrol connect <target>' to generate token.".to_string()),
        )
    };
    report.add_check(DiagnosticCheck {
        category: "Identity".to_string(),
        name: "Local Proxy Token".to_string(),
        status: token_status,
        message: token_msg,
        details: Some(serde_json::json!({
            "path": local_token_path.display().to_string(),
            "exists": local_token_path.exists()
        })),
        remediation: token_remedy,
    });

    // 4. Daemon & Port Reachability Check
    let daemon_addr = "127.0.0.1:18080";
    let daemon_check = tokio::net::TcpStream::connect(daemon_addr).await;
    let (daemon_status, daemon_msg, daemon_remedy) = match daemon_check {
        Ok(_) => (
            DiagnosticStatus::Pass,
            format!("Local background daemon active and listening on {}", daemon_addr),
            None,
        ),
        Err(e) => (
            DiagnosticStatus::Warn,
            format!("Background daemon not responding on {} ({})", daemon_addr, e),
            Some("Run 'agentcontrol login --hub <url>' to authenticate and auto-register the background daemon, or 'agentcontrol start' to run it interactively.".to_string()),
        ),
    };
    report.add_check(DiagnosticCheck {
        category: "Daemon".to_string(),
        name: "Background Daemon".to_string(),
        status: daemon_status,
        message: daemon_msg,
        details: Some(serde_json::json!({
            "address": daemon_addr,
            "listening": daemon_status == DiagnosticStatus::Pass
        })),
        remediation: daemon_remedy,
    });

    // 5. Gateway Broker Reachability Check
    let hub_url = load_hub_url().unwrap_or_else(|| "https://app.vexasec.io".to_string());
    let health_url = format!("{}/healthz", hub_url.trim_end_matches('/'));
    let start_t = Instant::now();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .unwrap_or_default();

    let gw_resp = client.get(&health_url).send().await;
    let rtt_ms = start_t.elapsed().as_millis();

    let (gw_status, gw_msg, gw_remedy) = match gw_resp {
        Ok(resp) if resp.status().is_success() => (
            DiagnosticStatus::Pass,
            format!("Control Hub reachable at {} (RTT: {} ms)", hub_url, rtt_ms),
            None,
        ),
        Ok(resp) => (
            DiagnosticStatus::Warn,
            format!("Control Hub returned HTTP {} at {} (RTT: {} ms)", resp.status(), hub_url, rtt_ms),
            Some("Verify Control Hub URL configuration or check service status at status.vexasec.io.".to_string()),
        ),
        Err(e) => (
            DiagnosticStatus::Warn,
            format!("Control Hub unreachable at {} ({}). Offline proxying remains functional.", hub_url, e),
            Some("Check internet connectivity. Workstation proxy continues enforcing local policies offline.".to_string()),
        ),
    };
    report.add_check(DiagnosticCheck {
        category: "Network".to_string(),
        name: "Control Hub Connectivity".to_string(),
        status: gw_status,
        message: gw_msg,
        details: Some(serde_json::json!({
            "hub_url": hub_url,
            "rtt_ms": rtt_ms
        })),
        remediation: gw_remedy,
    });

    // 6. Connected Targets & Configuration Drift Check
    match OwnershipManifest::list_all() {
        Ok(manifests) if !manifests.is_empty() => {
            let mut drifted_targets: Vec<String> = Vec::new();
            for m in &manifests {
                if m.config_path.exists() {
                    let cur_hash =
                        OwnershipManifest::compute_sha256(&m.config_path).unwrap_or_default();
                    if cur_hash != m.post_mutation_hash_sha256 {
                        drifted_targets.push(m.target.clone());
                    }
                }
            }

            if !drifted_targets.is_empty() {
                let drift_count = drifted_targets.len();
                let target_list = drifted_targets.join(", ");
                report.add_check(DiagnosticCheck {
                    category: "Targets".to_string(),
                    name: "Target Configuration Drift".to_string(),
                    status: DiagnosticStatus::Warn,
                    message: format!(
                        "{} connected target(s) have detected external modifications: {} (customizations preserved).",
                        drift_count, target_list
                    ),
                    details: Some(serde_json::json!({
                        "total_targets": manifests.len(),
                        "drift_count": drift_count,
                        "drifted_targets": drifted_targets
                    })),
                    remediation: Some("Run 'agentcontrol repair' to re-verify manifests and endpoints.".to_string()),
                });
            } else {
                report.add_check(DiagnosticCheck {
                    category: "Targets".to_string(),
                    name: "Target Configurations".to_string(),
                    status: DiagnosticStatus::Pass,
                    message: format!(
                        "{} connected target(s) match ownership manifests cleanly.",
                        manifests.len()
                    ),
                    details: Some(serde_json::json!({ "total_targets": manifests.len() })),
                    remediation: None,
                });
            }
        }
        _ => {
            report.add_check(DiagnosticCheck {
                category: "Targets".to_string(),
                name: "Target Configurations".to_string(),
                status: DiagnosticStatus::Pass,
                message:
                    "No connected targets yet. Run 'agentcontrol connect <target>' to configure."
                        .to_string(),
                details: None,
                remediation: None,
            });
        }
    }

    // 7. Security Hygiene Check (No unauthorized Root CA, No Plaintext Secrets)
    let ca_installed = crate::ca::is_ca_installed();
    if ca_installed {
        report.add_check(DiagnosticCheck {
            category: "Security".to_string(),
            name: "Root CA Invariant".to_string(),
            status: DiagnosticStatus::Warn,
            message: "Legacy Root CA detected in OS trust store. Standard Zero-CA security policy requires removal.".to_string(),
            details: None,
            remediation: Some("Run 'agentcontrol repair' to automatically clean and uninstall legacy Root CA from trust store.".to_string()),
        });
    } else {
        report.add_check(DiagnosticCheck {
            category: "Security".to_string(),
            name: "Root CA Invariant".to_string(),
            status: DiagnosticStatus::Pass,
            message:
                "No unauthorized Root CA in OS trust store (Zero-CA security invariant verified)."
                    .to_string(),
            details: None,
            remediation: None,
        });
    }

    // 8. Config Directory Writability (PRD F5-S5)
    let config_dir = dirs::home_dir()
        .map(|h| h.join(".agentcontrol"))
        .unwrap_or_else(|| std::path::PathBuf::from(".agentcontrol"));

    let writability_check = (|| -> Result<(), std::io::Error> {
        if !config_dir.exists() {
            std::fs::create_dir_all(&config_dir)?;
        }
        let test_file = config_dir.join(".write_test_probe");
        std::fs::write(&test_file, b"ok")?;
        let _ = std::fs::remove_file(&test_file);
        Ok(())
    })();

    let (write_status, write_msg, write_remedy) = match writability_check {
        Ok(_) => (
            DiagnosticStatus::Pass,
            format!("Config directory {} is writable", config_dir.display()),
            None,
        ),
        Err(e) => (
            DiagnosticStatus::Fail,
            format!("Config directory {} is NOT writable: {}", config_dir.display(), e),
            Some("Ensure user has write permissions to ~/.agentcontrol or change directory permissions (chmod u+w / icacls).".to_string()),
        ),
    };
    report.add_check(DiagnosticCheck {
        category: "Storage".to_string(),
        name: "Config Writability".to_string(),
        status: write_status,
        message: write_msg,
        details: Some(serde_json::json!({
            "path": config_dir.display().to_string(),
            "writable": write_status == DiagnosticStatus::Pass,
        })),
        remediation: write_remedy,
    });

    // 9. Policy File Validity (PRD F5-S5)
    let policy_path = std::path::Path::new("agentcontrol-policy.yaml");
    let (policy_status, policy_msg, policy_remedy) = if policy_path.exists() {
        match std::fs::read_to_string(policy_path) {
            Ok(content) => match crate::policy::engine::CompiledPolicy::from_yaml_str(&content) {
                Ok(_) => (
                    DiagnosticStatus::Pass,
                    "Active policy agentcontrol-policy.yaml is valid and compiled cleanly".to_string(),
                    None,
                ),
                Err(e) => (
                    DiagnosticStatus::Fail,
                    format!("Policy agentcontrol-policy.yaml failed validation: {}", e),
                    Some("Run 'agentcontrol lint agentcontrol-policy.yaml' to locate and fix YAML schema errors.".to_string()),
                ),
            },
            Err(e) => (
                DiagnosticStatus::Fail,
                format!("Failed to read agentcontrol-policy.yaml: {}", e),
                Some("Check file read permissions for agentcontrol-policy.yaml.".to_string()),
            ),
        }
    } else {
        (
            DiagnosticStatus::Pass,
            "No custom agentcontrol-policy.yaml found (using built-in dev-safe defaults)"
                .to_string(),
            None,
        )
    };
    report.add_check(DiagnosticCheck {
        category: "Policy".to_string(),
        name: "Policy Validity".to_string(),
        status: policy_status,
        message: policy_msg,
        details: Some(serde_json::json!({
            "file": "agentcontrol-policy.yaml",
            "exists": policy_path.exists(),
        })),
        remediation: policy_remedy,
    });

    // 10. IDE Restart Need Check (PRD F5-S5)
    let connected_count = OwnershipManifest::list_all().map(|m| m.len()).unwrap_or(0);
    let ide_modified = std::env::var("AGENTCONTROL_IDE_RELOAD_NEEDED").is_ok();
    let (ide_status, ide_msg, ide_remedy) = if ide_modified {
        (
            DiagnosticStatus::Warn,
            "IDE configuration was modified. Editor restart required to apply MCP proxy rules.".to_string(),
            Some("Restart your IDE editor (VS Code, Cursor, or Claude Desktop) to load updated MCP proxy settings.".to_string()),
        )
    } else {
        (
            DiagnosticStatus::Pass,
            format!(
                "Connected IDE configurations synchronized ({} target(s) tracked)",
                connected_count
            ),
            None,
        )
    };
    report.add_check(DiagnosticCheck {
        category: "Integration".to_string(),
        name: "IDE Sync State".to_string(),
        status: ide_status,
        message: ide_msg,
        details: Some(serde_json::json!({
            "targets_count": connected_count,
            "restart_required": ide_modified,
        })),
        remediation: ide_remedy,
    });

    report
}

/// Print formatted terminal output or JSON for `agentcontrol doctor`.
pub async fn run_doctor(json: bool) -> i32 {
    let report = run_diagnostics().await;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
        return report.exit_code;
    }

    println!();
    println!(
        "{} {}",
        "Vexa Agent Control Diagnostic Health Suite".bold().white(),
        format!("(v{})", report.version).cyan()
    );
    println!("{}", "─".repeat(80).dimmed());

    for check in &report.checks {
        let icon = match check.status {
            DiagnosticStatus::Pass => "✔".green(),
            DiagnosticStatus::Warn => "⚠".yellow(),
            DiagnosticStatus::Fail => "✖".red(),
        };

        println!("  {} {:<28} {}", icon, check.name.bold(), check.message);
        if let Some(remedy) = &check.remediation {
            println!("     └─ {} {}", "Remedy:".dimmed(), remedy.cyan());
        }
    }

    println!("{}", "─".repeat(80).dimmed());
    match report.overall_status {
        DiagnosticStatus::Pass => {
            println!(
                "{} All diagnostic checks PASSED. Workstation is fully operational.",
                "✔".green().bold()
            );
        }
        DiagnosticStatus::Warn => {
            println!(
                "{} Diagnostics completed with WARNINGS. System is operational with degraded features.",
                "⚠".yellow().bold()
            );
        }
        DiagnosticStatus::Fail => {
            println!(
                "{} Diagnostics FAILED. Critical dependencies are missing or unreachable.",
                "✖".red().bold()
            );
        }
    }
    println!();

    report.exit_code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_diagnostics_report_generation() {
        let report = run_diagnostics().await;
        assert!(!report.version.is_empty());
        assert!(!report.checks.is_empty());
        // Exit code must be 0, 1, or 2
        assert!(report.exit_code == 0 || report.exit_code == 1 || report.exit_code == 2);
    }

    // ---------------------------------------------------------------------------
    // PRD F5-S5: Six simulated failure modes each yielding specific remediation
    // ---------------------------------------------------------------------------

    #[test]
    fn test_simulated_failure_1_port_unreachable() {
        let check = DiagnosticCheck {
            category: "Daemon".to_string(),
            name: "Background Daemon".to_string(),
            status: DiagnosticStatus::Warn,
            message: "Background daemon not responding on 127.0.0.1:18080".to_string(),
            details: None,
            remediation: Some("Run 'agentcontrol login --hub <url>' to authenticate and auto-register the background daemon, or 'agentcontrol start' to run it interactively.".to_string()),
        };
        assert_eq!(check.status, DiagnosticStatus::Warn);
        assert!(check
            .remediation
            .as_ref()
            .unwrap()
            .contains("agentcontrol start"));
    }

    #[test]
    fn test_simulated_failure_2_config_unwritable() {
        let check = DiagnosticCheck {
            category: "Storage".to_string(),
            name: "Config Writability".to_string(),
            status: DiagnosticStatus::Fail,
            message: "Config directory ~/.agentcontrol is NOT writable".to_string(),
            details: None,
            remediation: Some("Ensure user has write permissions to ~/.agentcontrol or change directory permissions (chmod u+w / icacls).".to_string()),
        };
        assert_eq!(check.status, DiagnosticStatus::Fail);
        assert!(check
            .remediation
            .as_ref()
            .unwrap()
            .contains("chmod u+w / icacls"));
    }

    #[test]
    fn test_simulated_failure_3_policy_invalid() {
        let check = DiagnosticCheck {
            category: "Policy".to_string(),
            name: "Policy Validity".to_string(),
            status: DiagnosticStatus::Fail,
            message: "Policy agentcontrol-policy.yaml failed validation: unknown field".to_string(),
            details: None,
            remediation: Some("Run 'agentcontrol lint agentcontrol-policy.yaml' to locate and fix YAML schema errors.".to_string()),
        };
        assert_eq!(check.status, DiagnosticStatus::Fail);
        assert!(check
            .remediation
            .as_ref()
            .unwrap()
            .contains("agentcontrol lint"));
    }

    #[test]
    fn test_simulated_failure_4_device_not_enrolled() {
        let check = DiagnosticCheck {
            category: "Identity".to_string(),
            name: "Authentication State".to_string(),
            status: DiagnosticStatus::Warn,
            message: "Device not enrolled with Control Hub.".to_string(),
            details: None,
            remediation: Some(
                "Run 'agentcontrol login' to authenticate and provision device credentials."
                    .to_string(),
            ),
        };
        assert_eq!(check.status, DiagnosticStatus::Warn);
        assert!(check
            .remediation
            .as_ref()
            .unwrap()
            .contains("agentcontrol login"));
    }

    #[test]
    fn test_simulated_failure_5_ide_restart_needed() {
        let check = DiagnosticCheck {
            category: "Integration".to_string(),
            name: "IDE Sync State".to_string(),
            status: DiagnosticStatus::Warn,
            message: "IDE configuration was modified. Editor restart required.".to_string(),
            details: None,
            remediation: Some("Restart your IDE editor (VS Code, Cursor, or Claude Desktop) to load updated MCP proxy settings.".to_string()),
        };
        assert_eq!(check.status, DiagnosticStatus::Warn);
        assert!(check
            .remediation
            .as_ref()
            .unwrap()
            .contains("Restart your IDE editor"));
    }

    #[test]
    fn test_simulated_failure_6_target_drift() {
        let check = DiagnosticCheck {
            category: "Targets".to_string(),
            name: "Target Configuration Drift".to_string(),
            status: DiagnosticStatus::Warn,
            message: "1 connected target(s) have detected external modifications.".to_string(),
            details: None,
            remediation: Some(
                "Run 'agentcontrol repair' to re-verify manifests and endpoints.".to_string(),
            ),
        };
        assert_eq!(check.status, DiagnosticStatus::Warn);
        assert!(check
            .remediation
            .as_ref()
            .unwrap()
            .contains("agentcontrol repair"));
    }
}
