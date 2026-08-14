//! macOS LaunchDaemon / LaunchAgent Service Installer module.

use colored::*;
use std::fs;
use std::process::Command;

pub fn install_macos_service(
    bin_path: &str,
    hub_url: &str,
    _gateway_secret: &str,
    _policy_read_secret: &str,
    agent_id: Option<&str>,
) -> Result<(), String> {
    // Build optional AGENT_ID plist entry
    let agent_id_plist = agent_id
        .map(|id| {
            format!(
                "        <key>AGENT_ID</key>\n        <string>{}</string>\n",
                id
            )
        })
        .unwrap_or_default();

    let plist_content = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>io.vexasec.agentcontrol</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
        <string>start</string>
        <string>--centralized</string>
        <string>--listen</string>
        <string>127.0.0.1:8080</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>EnvironmentVariables</key>
    <dict>
        <key>DASHBOARD_API_URL</key>
        <string>{}</string>
{}    </dict>
</dict>
</plist>
"#,
        bin_path, hub_url, agent_id_plist
    );

    let daemon_plist = "/Library/LaunchDaemons/io.vexasec.agentcontrol.plist";
    let agent_plist = dirs::home_dir()
        .map(|h| h.join("Library/LaunchAgents/io.vexasec.agentcontrol.plist"))
        .unwrap_or_else(|| std::path::PathBuf::from(daemon_plist));

    let (target_path, is_daemon) = if fs::metadata("/Library/LaunchDaemons").is_ok() && is_root() {
        (std::path::PathBuf::from(daemon_plist), true)
    } else {
        if let Some(parent) = agent_plist.parent() {
            let _ = fs::create_dir_all(parent);
        }
        (agent_plist, false)
    };

    println!(
        "  Writing macOS launchd plist to {}",
        target_path.display().to_string().cyan()
    );
    fs::write(&target_path, plist_content)
        .map_err(|e| format!("failed to write launchd plist file: {}", e))?;

    let load_res = Command::new("launchctl")
        .args(["load", "-w", &target_path.display().to_string()])
        .output();

    if let Err(e) = load_res {
        return Err(format!("failed to execute launchctl load: {}", e));
    }

    let mode_str = if is_daemon {
        "LaunchDaemon"
    } else {
        "LaunchAgent"
    };
    println!(
        "{} Agent Control macOS {} installed and loaded!",
        "✔".green().bold(),
        mode_str
    );
    Ok(())
}

pub fn uninstall_macos_service() -> Result<(), String> {
    let daemon_plist = "/Library/LaunchDaemons/io.vexasec.agentcontrol.plist";
    let agent_plist =
        dirs::home_dir().map(|h| h.join("Library/LaunchAgents/io.vexasec.agentcontrol.plist"));

    if std::path::Path::new(daemon_plist).exists() {
        let _ = Command::new("launchctl")
            .args(["unload", "-w", daemon_plist])
            .output();
        let _ = fs::remove_file(daemon_plist);
    }

    if let Some(path) = &agent_plist {
        if path.exists() {
            let _ = Command::new("launchctl")
                .args(["unload", "-w", &path.display().to_string()])
                .output();
            let _ = fs::remove_file(path);
        }
    }

    // Clean up legacy io.vexasec.agentwall plists if present
    let legacy_daemon = "/Library/LaunchDaemons/io.vexasec.agentwall.plist";
    let legacy_agent =
        dirs::home_dir().map(|h| h.join("Library/LaunchAgents/io.vexasec.agentwall.plist"));

    if std::path::Path::new(legacy_daemon).exists() {
        let _ = Command::new("launchctl")
            .args(["unload", "-w", legacy_daemon])
            .output();
        let _ = fs::remove_file(legacy_daemon);
    }
    if let Some(path) = legacy_agent {
        if path.exists() {
            let _ = Command::new("launchctl")
                .args(["unload", "-w", &path.display().to_string()])
                .output();
            let _ = fs::remove_file(path);
        }
    }

    println!(
        "{} Agent Control macOS service uninstalled.",
        "✔".green().bold()
    );
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
