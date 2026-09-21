//! Linux Systemd Service Installer module.
//!
//! Installs as a system-level service (root/enterprise) or user-level service (~/.config/systemd/user/)
//! when running without root. Adheres strictly to the single authoritative supervisor model.

use super::SupervisorState;
use colored::*;
use std::fs;
use std::path::Path;
use std::process::Command;

fn is_root() -> bool {
    #[cfg(unix)]
    unsafe {
        libc::getuid() == 0
    }
    #[cfg(not(unix))]
    {
        false
    }
}

pub fn install_linux_service(
    bin_path: &str,
    _hub_url: &str,
    _gateway_secret: &str,
    _policy_read_secret: &str,
    _agent_id: Option<&str>,
    enterprise: bool,
    config_path: &Path,
    _quiet: bool,
) -> Result<(), String> {
    let use_user_systemd = !enterprise && !is_root();

    let (unit_path, systemctl_args_base) = if use_user_systemd {
        let user_dir = dirs::config_dir()
            .map(|d| d.join("systemd/user"))
            .unwrap_or_else(|| {
                dirs::home_dir()
                    .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
                    .join(".config/systemd/user")
            });
        let _ = fs::create_dir_all(&user_dir);
        (user_dir.join("agent-control.service"), vec!["--user"])
    } else {
        (
            std::path::PathBuf::from("/etc/systemd/system/agent-control.service"),
            vec![],
        )
    };

    // 1. Scoped Pre-Cleanup: Remove legacy agentwall services and legacy XDG autostart entries
    clean_legacy_artifacts();

    // 2. Generate clean systemd unit definition passing --config flag
    let config_path_str = config_path.display().to_string();
    let service_content = format!(
        r#"[Unit]
Description=Agent Control Sentry Endpoint Security Service
Documentation=https://github.com/noviqtechnologies/Vexa-Agent-Control
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart={bin} start --config {config}
Restart=always
RestartSec=5s
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=default.target
"#,
        bin = bin_path,
        config = config_path_str,
    );

    fs::write(&unit_path, service_content).map_err(|e| {
        format!(
            "failed to write systemd unit file{}: {}",
            if !use_user_systemd {
                " (try running with sudo or without --enterprise)"
            } else {
                ""
            },
            e
        )
    })?;

    // 3. Reload systemd daemon
    let mut reload_args = systemctl_args_base.clone();
    reload_args.push("daemon-reload");
    let reload = Command::new("systemctl").args(&reload_args).output();
    if let Ok(out) = reload {
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            if !_quiet {
                eprintln!(
                    "  {} systemctl daemon-reload warning: {}",
                    "⚠".yellow(),
                    stderr.trim()
                );
            }
        }
    }

    // 4. Enable and start service
    let mut enable_args = systemctl_args_base.clone();
    enable_args.extend_from_slice(&["enable", "--now", "agent-control"]);
    let enable = Command::new("systemctl")
        .args(&enable_args)
        .output()
        .map_err(|e| format!("failed to execute systemctl enable --now: {}", e))?;

    if !enable.status.success() {
        let stderr = String::from_utf8_lossy(&enable.stderr);
        return Err(format!("systemctl enable --now failed: {}", stderr.trim()));
    }

    // 5. If user-scope, manage and check loginctl linger
    if use_user_systemd {
        let _ = Command::new("loginctl").arg("enable-linger").output();
        if let Ok(out) = Command::new("loginctl")
            .args(["show-user", &get_user_name(), "--property=Linger"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if stdout.contains("Linger=no") && !_quiet {
                println!(
                    "  {} User lingering is currently disabled. Daemon may pause upon session logout.\n     To enable background persistence across SSH/GUI logouts: 'loginctl enable-linger'",
                    "ℹ".cyan()
                );
            }
        }
    }

    Ok(())
}

pub fn inspect_linux_service() -> SupervisorState {
    // 1. Check user systemd scope
    if let Ok(out) = Command::new("systemctl")
        .args([
            "--user",
            "show",
            "agent-control",
            "--property=ActiveState,SubState,MainPID",
        ])
        .output()
    {
        if out.status.success() {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if stdout.contains("ActiveState=active") {
                let pid = stdout
                    .lines()
                    .find(|l| l.starts_with("MainPID="))
                    .and_then(|l| l.strip_prefix("MainPID="))
                    .and_then(|p| p.trim().parse::<u32>().ok())
                    .filter(|&p| p > 0);
                return SupervisorState::Managed {
                    supervisor_type: "Linux systemd (User)".to_string(),
                    target_name: "agent-control.service".to_string(),
                    active: true,
                    details: Some(format!("MainPID: {:?}", pid)),
                };
            } else if stdout.contains("ActiveState=")
                && !stdout.contains("ActiveState=inactive\nSubState=dead")
            {
                let substate = stdout
                    .lines()
                    .find(|l| l.starts_with("SubState="))
                    .unwrap_or("SubState=unknown");
                return SupervisorState::Managed {
                    supervisor_type: "Linux systemd (User)".to_string(),
                    target_name: "agent-control.service".to_string(),
                    active: false,
                    details: Some(substate.to_string()),
                };
            }
        }
    }

    // 2. Check system systemd scope
    if let Ok(out) = Command::new("systemctl")
        .args([
            "show",
            "agent-control",
            "--property=ActiveState,SubState,MainPID",
        ])
        .output()
    {
        if out.status.success() {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if stdout.contains("ActiveState=active") {
                let pid = stdout
                    .lines()
                    .find(|l| l.starts_with("MainPID="))
                    .and_then(|l| l.strip_prefix("MainPID="))
                    .and_then(|p| p.trim().parse::<u32>().ok())
                    .filter(|&p| p > 0);
                return SupervisorState::Managed {
                    supervisor_type: "Linux systemd (System)".to_string(),
                    target_name: "agent-control.service".to_string(),
                    active: true,
                    details: Some(format!("MainPID: {:?}", pid)),
                };
            } else if stdout.contains("ActiveState=")
                && !stdout.contains("ActiveState=inactive\nSubState=dead")
            {
                let substate = stdout
                    .lines()
                    .find(|l| l.starts_with("SubState="))
                    .unwrap_or("SubState=unknown");
                return SupervisorState::Managed {
                    supervisor_type: "Linux systemd (System)".to_string(),
                    target_name: "agent-control.service".to_string(),
                    active: false,
                    details: Some(substate.to_string()),
                };
            }
        }
    }

    SupervisorState::NotInstalled
}

pub fn uninstall_linux_service() -> Result<(), String> {
    // 1. Stop and disable both user and system unit scopes
    for user_flag in &[vec!["--user"], vec![]] {
        let mut stop_args = user_flag.clone();
        stop_args.extend_from_slice(&["stop", "agent-control"]);
        let _ = Command::new("systemctl").args(&stop_args).output();

        let mut disable_args = user_flag.clone();
        disable_args.extend_from_slice(&["disable", "agent-control"]);
        let _ = Command::new("systemctl").args(&disable_args).output();
    }

    // 2. Remove unit files
    let unit_paths = [
        "/etc/systemd/system/agent-control.service".to_string(),
        "/etc/systemd/system/agentwall.service".to_string(),
        dirs::config_dir()
            .map(|d| {
                d.join("systemd/user/agent-control.service")
                    .display()
                    .to_string()
            })
            .unwrap_or_default(),
        dirs::home_dir()
            .map(|h| {
                h.join(".config/systemd/user/agent-control.service")
                    .display()
                    .to_string()
            })
            .unwrap_or_default(),
    ];

    for path in &unit_paths {
        if !path.is_empty() && Path::new(path).exists() {
            let _ = fs::remove_file(path);
        }
    }

    // 3. Clean legacy desktop and process artifacts
    clean_legacy_artifacts();
    let _ = Command::new("pkill").args(["-x", "agentcontrol"]).output();

    // 4. Reload systemd
    let _ = Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .output();
    let _ = Command::new("systemctl").arg("daemon-reload").output();

    println!(
        "{} Agent Control Linux systemd service uninstalled.",
        "✔".green().bold()
    );
    Ok(())
}

fn clean_legacy_artifacts() {
    let legacy_desktop = dirs::config_dir()
        .map(|d| d.join("autostart/io.vexasec.agentcontrol.desktop"))
        .or_else(|| {
            dirs::home_dir().map(|h| h.join(".config/autostart/io.vexasec.agentcontrol.desktop"))
        });

    if let Some(path) = legacy_desktop {
        if path.exists() {
            let _ = fs::remove_file(&path);
        }
    }
}

fn get_user_name() -> String {
    std::env::var("USER").unwrap_or_else(|_| "user".to_string())
}
