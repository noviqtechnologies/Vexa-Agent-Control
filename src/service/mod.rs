//! OS Service Manager integration module — handles systemd (Linux), launchd (macOS), and SCM (Windows).

pub mod linux;
pub mod macos;
pub mod windows;
pub mod windows_profiles;
pub mod eventlog;

use colored::*;
use std::env;

#[derive(Debug)]
pub enum ServiceAction {
    Install {
        hub_url: String,
        gateway_secret: Option<String>,
        policy_read_secret: Option<String>,
        agent_id: Option<String>,
    },
    Uninstall,
    Status,
}

pub fn run_service(action: ServiceAction) -> i32 {
    let current_exe = match env::current_exe() {
        Ok(path) => path.display().to_string(),
        Err(e) => {
            eprintln!("{} Failed to resolve binary path: {}", "✖".red(), e);
            return 1;
        }
    };

    match action {
        ServiceAction::Install {
            hub_url,
            gateway_secret,
            policy_read_secret,
            agent_id,
        } => {
            println!(
                "{} Installing Agent Control Persistent Sentry Daemon",
                "●".green().bold()
            );
            println!("  Binary path: {}", current_exe.cyan());
            println!("  Hub URL: {}", hub_url.cyan());

            let gw_sec = gateway_secret.as_deref().unwrap_or("");
            let pol_sec = policy_read_secret.as_deref().unwrap_or("");

            let res = if cfg!(target_os = "windows") {
                windows::install_windows_service(
                    &current_exe,
                    &hub_url,
                    gw_sec,
                    pol_sec,
                    agent_id.as_deref(),
                )
            } else if cfg!(target_os = "macos") {
                macos::install_macos_service(
                    &current_exe,
                    &hub_url,
                    gw_sec,
                    pol_sec,
                    agent_id.as_deref(),
                )
            } else {
                linux::install_linux_service(
                    &current_exe,
                    &hub_url,
                    gw_sec,
                    pol_sec,
                    agent_id.as_deref(),
                )
            };

            match res {
                Ok(_) => 0,
                Err(e) => {
                    eprintln!("{} Service installation failed: {}", "✖".red(), e);
                    1
                }
            }
        }
        ServiceAction::Uninstall => {
            println!(
                "{} Uninstalling Agent Control Persistent Sentry Daemon...",
                "●".yellow().bold()
            );

            let res = if cfg!(target_os = "windows") {
                windows::uninstall_windows_service()
            } else if cfg!(target_os = "macos") {
                macos::uninstall_macos_service()
            } else {
                linux::uninstall_linux_service()
            };

            match res {
                Ok(_) => 0,
                Err(e) => {
                    eprintln!("{} Service uninstallation failed: {}", "✖".red(), e);
                    1
                }
            }
        }
        ServiceAction::Status => {
            println!("{} Agent Control Service Daemon Status", "●".green().bold());
            println!("  OS Target: {}", std::env::consts::OS.cyan());
            println!("  Arch: {}", std::env::consts::ARCH.cyan());
            println!("  Binary: {}", current_exe.dimmed());

            if cfg!(target_os = "windows") {
                println!("  Service Name: AgentControlSentry (Windows SCM)");
                println!("  Profile Scan Engine: Windows Session 0 Multi-User Hives Enabled");
            } else if cfg!(target_os = "macos") {
                println!("  Service Target: LaunchDaemon / LaunchAgent (io.vexasec.agentcontrol)");
            } else {
                println!("  Service Target: systemd (agent-control.service)");
            }

            0
        }
    }
}
