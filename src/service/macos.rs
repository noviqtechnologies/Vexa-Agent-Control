//! macOS LaunchDaemon / LaunchAgent Service Installer module.

use std::fs;
use std::process::Command;
use colored::*;

pub fn install_macos_service(
    bin_path: &str,
    hub_url: &str,
    gateway_secret: &str,
    policy_read_secret: &str,
) -> Result<(), String> {
    let plist_content = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>io.vexasec.agentwall</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
        <string>start</string>
        <string>--centralized</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>EnvironmentVariables</key>
    <dict>
        <key>DASHBOARD_API_URL</key>
        <string>{}</string>
        <key>GATEWAY_SECRET</key>
        <string>{}</string>
        <key>POLICY_READ_SECRET</key>
        <string>{}</string>
    </dict>
</dict>
</plist>
"#,
        bin_path, hub_url, gateway_secret, policy_read_secret
    );

    let daemon_plist = "/Library/LaunchDaemons/io.vexasec.agentwall.plist";
    let agent_plist = dirs::home_dir()
        .map(|h| h.join("Library/LaunchAgents/io.vexasec.agentwall.plist"))
        .unwrap_or_else(|| std::path::PathBuf::from(daemon_plist));

    let (target_path, is_daemon) = if fs::metadata("/Library/LaunchDaemons").is_ok() && is_root() {
        (std::path::PathBuf::from(daemon_plist), true)
    } else {
        if let Some(parent) = agent_plist.parent() {
            let _ = fs::create_dir_all(parent);
        }
        (agent_plist, false)
    };

    println!("  Writing macOS launchd plist to {}", target_path.display().to_string().cyan());
    fs::write(&target_path, plist_content)
        .map_err(|e| format!("failed to write launchd plist file: {}", e))?;

    let load_res = Command::new("launchctl")
        .args(["load", "-w", &target_path.display().to_string()])
        .output();

    if let Err(e) = load_res {
        return Err(format!("failed to execute launchctl load: {}", e));
    }

    let mode_str = if is_daemon { "LaunchDaemon" } else { "LaunchAgent" };
    println!("{} AgentWall macOS {} installed and loaded!", "✔".green().bold(), mode_str);
    Ok(())
}

pub fn uninstall_macos_service() -> Result<(), String> {
    let daemon_plist = "/Library/LaunchDaemons/io.vexasec.agentwall.plist";
    let agent_plist = dirs::home_dir()
        .map(|h| h.join("Library/LaunchAgents/io.vexasec.agentwall.plist"));

    if std::path::Path::new(daemon_plist).exists() {
        let _ = Command::new("launchctl").args(["unload", "-w", daemon_plist]).output();
        let _ = fs::remove_file(daemon_plist);
    }

    if let Some(path) = agent_plist {
        if path.exists() {
            let _ = Command::new("launchctl").args(["unload", "-w", &path.display().to_string()]).output();
            let _ = fs::remove_file(path);
        }
    }

    println!("{} AgentWall macOS service uninstalled.", "✔".green().bold());
    Ok(())
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
