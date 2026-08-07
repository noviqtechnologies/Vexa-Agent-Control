//! OS Service Manager integration module — handles systemd (Linux), launchd (macOS), and SCM (Windows).

pub mod linux;
pub mod macos;
pub mod windows;
pub mod windows_profiles;

use colored::*;
use std::env;

#[derive(Debug)]
pub enum ServiceAction {
    Install {
        hub_url: String,
        gateway_secret: String,
        policy_read_secret: String,
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
        } => {
            println!("{} Installing AgentWall Persistent Sentry Daemon", "●".green().bold());
            println!("  Binary path: {}", current_exe.cyan());
            println!("  Hub URL: {}", hub_url.cyan());

            let res = if cfg!(target_os = "windows") {
                windows::install_windows_service(&current_exe, &hub_url, &gateway_secret, &policy_read_secret)
            } else if cfg!(target_os = "macos") {
                macos::install_macos_service(&current_exe, &hub_url, &gateway_secret, &policy_read_secret)
            } else {
                linux::install_linux_service(&current_exe, &hub_url, &gateway_secret, &policy_read_secret)
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
            println!("{} Uninstalling AgentWall Persistent Sentry Daemon...", "●".yellow().bold());

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
            println!("{} AgentWall Service Daemon Status", "●".green().bold());
            println!("  OS Target: {}", std::env::consts::OS.cyan());
            println!("  Arch: {}", std::env::consts::ARCH.cyan());
            println!("  Binary: {}", current_exe.dimmed());

            if cfg!(target_os = "windows") {
                println!("  Service Name: AgentWallSentry (Windows SCM)");
                println!("  Profile Scan Engine: Windows Session 0 Multi-User Hives Enabled");
            } else if cfg!(target_os = "macos") {
                println!("  Service Target: LaunchDaemon / LaunchAgent (io.vexasec.agentwall)");
            } else {
                println!("  Service Target: systemd (agentwall.service)");
            }

            0
        }
    }
}
