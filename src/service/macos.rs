//! macOS launchd Service Installer module.
//!
//! Installs as a LaunchDaemon (system-level, boot-time) or LaunchAgent (user-level, login-time).
//! Adheres strictly to the single-authoritative-supervisor architecture with zero overlapping crontab/nohup fallbacks.

use colored::*;
use std::fs;
use std::path::Path;
use std::process::Command;
use super::SupervisorState;

#[cfg(unix)]
fn get_current_uid() -> u32 {
    unsafe { libc::getuid() }
}

#[cfg(not(unix))]
fn get_current_uid() -> u32 {
    501
}

fn is_root() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::getuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

pub fn install_macos_service(
    bin_path: &str,
    _hub_url: &str,
    _gateway_secret: &str,
    _policy_read_secret: &str,
    _agent_id: Option<&str>,
    enterprise: bool,
    config_path: &Path,
    _quiet: bool,
) -> Result<(), String> {
    let is_daemon = enterprise || is_root();

    // Determine target plist path and log paths
    let (target_path, log_dir) = if is_daemon {
        (
            std::path::PathBuf::from("/Library/LaunchDaemons/io.vexasec.agentcontrol.plist"),
            std::path::PathBuf::from("/Library/Logs/AgentControl"),
        )
    } else {
        let user_plist = dirs::home_dir()
            .map(|h| h.join("Library/LaunchAgents/io.vexasec.agentcontrol.plist"))
            .unwrap_or_else(|| std::path::PathBuf::from("/Library/LaunchDaemons/io.vexasec.agentcontrol.plist"));
        let user_logs = dirs::home_dir()
            .map(|h| h.join("Library/Logs/AgentControl"))
            .unwrap_or_else(|| std::path::PathBuf::from("/tmp/agentcontrol-logs"));
        (user_plist, user_logs)
    };

    let _ = fs::create_dir_all(&log_dir);
    if let Some(parent) = target_path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    let stdout_log = log_dir.join("agent-control.log").display().to_string();
    let stderr_log = log_dir.join("agent-control-error.log").display().to_string();

    // 1. Scoped Pre-Cleanup: Remove legacy crontab entries and unregister legacy plists
    clean_legacy_crontab();
    let _ = Command::new("launchctl")
        .args(["bootout", "system/io.vexasec.agentwall"])
        .output();
    let _ = Command::new("launchctl")
        .args(["unload", "-w", "/Library/LaunchDaemons/io.vexasec.agentwall.plist"])
        .output();

    // 2. Generate clean plist definition passing --config flag
    let config_path_str = config_path.display().to_string();
    let plist_content = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>io.vexasec.agentcontrol</string>
    <key>ProgramArguments</key>
    <array>
        <string>{bin}</string>
        <string>start</string>
        <string>--config</string>
        <string>{config}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>ThrottleInterval</key>
    <integer>5</integer>
    <key>StandardOutPath</key>
    <string>{stdout}</string>
    <key>StandardErrorPath</key>
    <string>{stderr}</string>
</dict>
</plist>
"#,
        bin = bin_path,
        config = config_path_str,
        stdout = stdout_log,
        stderr = stderr_log,
    );

    fs::write(&target_path, plist_content)
        .map_err(|e| format!("failed to write launchd plist file: {}", e))?;

    let target_str = target_path.display().to_string();
    let uid = get_current_uid();

    // 3. Register and activate with modern domain-targeted launchctl
    if is_daemon {
        let _ = Command::new("launchctl").args(["bootout", "system/io.vexasec.agentcontrol"]).output();
        let _ = Command::new("launchctl").args(["unload", "-w", &target_str]).output();

        let bootstrap_out = Command::new("launchctl")
            .args(["bootstrap", "system", &target_str])
            .output();

        match bootstrap_out {
            Ok(o) if o.status.success() => {},
            _ => {
                // Fallback to load -w for legacy macOS
                let _ = Command::new("launchctl").args(["load", "-w", &target_str]).output();
            }
        }
    } else {
        let domain = format!("gui/{}", uid);
        let service_target = format!("gui/{}/io.vexasec.agentcontrol", uid);

        let _ = Command::new("launchctl").args(["bootout", &service_target]).output();
        let _ = Command::new("launchctl").args(["unload", "-w", &target_str]).output();

        let bootstrap_out = Command::new("launchctl")
            .args(["bootstrap", &domain, &target_str])
            .output();

        match bootstrap_out {
            Ok(o) if o.status.success() => {},
            _ => {
                // Fallback to load -w for legacy macOS
                let _ = Command::new("launchctl").args(["load", "-w", &target_str]).output();
            }
        }
    }

    Ok(())
}

pub fn inspect_macos_service() -> SupervisorState {
    let uid = get_current_uid();
    let user_target = format!("gui/{}/io.vexasec.agentcontrol", uid);

    // 1. Check user LaunchAgent via modern launchctl print
    if let Ok(out) = Command::new("launchctl").args(["print", &user_target]).output() {
        if out.status.success() {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let pid = stdout.lines()
                .find(|l| l.trim().starts_with("pid = "))
                .and_then(|l| l.trim().strip_prefix("pid = "))
                .and_then(|p| p.trim().parse::<u32>().ok());
            let state_line = stdout.lines().find(|l| l.trim().starts_with("state = ")).unwrap_or("state = active");
            return SupervisorState::Managed {
                supervisor_type: "macOS launchd (LaunchAgent)".to_string(),
                target_name: "io.vexasec.agentcontrol".to_string(),
                active: pid.is_some() || stdout.contains("state = running"),
                details: Some(format!("PID: {:?}, {}", pid, state_line.trim())),
            };
        }
    }

    // 2. Check system LaunchDaemon via modern launchctl print
    if let Ok(out) = Command::new("launchctl").args(["print", "system/io.vexasec.agentcontrol"]).output() {
        if out.status.success() {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let pid = stdout.lines()
                .find(|l| l.trim().starts_with("pid = "))
                .and_then(|l| l.trim().strip_prefix("pid = "))
                .and_then(|p| p.trim().parse::<u32>().ok());
            return SupervisorState::Managed {
                supervisor_type: "macOS launchd (LaunchDaemon)".to_string(),
                target_name: "io.vexasec.agentcontrol".to_string(),
                active: pid.is_some() || stdout.contains("state = running"),
                details: Some(format!("PID: {:?}", pid)),
            };
        }
    }

    // 3. Fallback to launchctl list
    if let Ok(out) = Command::new("launchctl").args(["list"]).output() {
        let stdout = String::from_utf8_lossy(&out.stdout);
        for line in stdout.lines() {
            if line.contains("io.vexasec.agentcontrol") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                let pid = parts.first().and_then(|p| p.parse::<u32>().ok());
                return SupervisorState::Managed {
                    supervisor_type: "macOS launchd".to_string(),
                    target_name: "io.vexasec.agentcontrol".to_string(),
                    active: pid.is_some(),
                    details: Some(format!("PID: {:?}", pid)),
                };
            }
        }
    }

    SupervisorState::NotInstalled
}

pub fn uninstall_macos_service() -> Result<(), String> {
    let uid = get_current_uid();
    let user_target = format!("gui/{}/io.vexasec.agentcontrol", uid);

    let daemon_plist = "/Library/LaunchDaemons/io.vexasec.agentcontrol.plist";
    let agent_plist = dirs::home_dir().map(|h| h.join("Library/LaunchAgents/io.vexasec.agentcontrol.plist"));

    // Bootout / Unload current targets
    let _ = Command::new("launchctl").args(["bootout", &user_target]).output();
    let _ = Command::new("launchctl").args(["bootout", "system/io.vexasec.agentcontrol"]).output();

    if std::path::Path::new(daemon_plist).exists() {
        let _ = Command::new("launchctl").args(["unload", "-w", daemon_plist]).output();
        let _ = fs::remove_file(daemon_plist);
    }

    if let Some(path) = &agent_plist {
        if path.exists() {
            let _ = Command::new("launchctl").args(["unload", "-w", &path.display().to_string()]).output();
            let _ = fs::remove_file(path);
        }
    }

    // Clean up legacy plists
    let legacy_daemon = "/Library/LaunchDaemons/io.vexasec.agentwall.plist";
    let legacy_agent = dirs::home_dir().map(|h| h.join("Library/LaunchAgents/io.vexasec.agentwall.plist"));

    if std::path::Path::new(legacy_daemon).exists() {
        let _ = Command::new("launchctl").args(["unload", "-w", legacy_daemon]).output();
        let _ = fs::remove_file(legacy_daemon);
    }
    if let Some(path) = legacy_agent {
        if path.exists() {
            let _ = Command::new("launchctl").args(["unload", "-w", &path.display().to_string()]).output();
            let _ = fs::remove_file(path);
        }
    }

    // Clean up legacy crontab
    clean_legacy_crontab();

    // Kill running process
    let _ = Command::new("pkill").args(["-x", "agentcontrol"]).output();

    println!(
        "{} Agent Control macOS service uninstalled.",
        "✔".green().bold()
    );
    Ok(())
}

fn clean_legacy_crontab() {
    let cron_marker = "agentcontrol";
    let existing_cron = Command::new("crontab").arg("-l").output().ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();
    if existing_cron.contains(cron_marker) || existing_cron.contains("agentwall") {
        let cleaned: String = existing_cron
            .lines()
            .filter(|l| !l.contains("agentcontrol") && !l.contains("agentwall"))
            .map(|l| format!("{}\n", l))
            .collect();
        let _ = Command::new("sh")
            .arg("-c")
            .arg(format!("echo '{}' | crontab -", cleaned.replace('\'', "'\\''")))
            .output();
    }
}
