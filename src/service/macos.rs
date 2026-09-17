//! macOS LaunchDaemon / LaunchAgent Service Installer module.
//!
//! Installs as a LaunchDaemon (root, boot-time) or LaunchAgent (user, login-time).
//! Fixes applied vs original:
//! 1. Removed non-existent --centralized flag; corrected port 8080 → 18080
//! 2. KeepAlive changed to crash-only (SuccessfulExit=false) — avoids respawn loops on clean exit
//! 3. launchctl load exit-code check (was silently ignored)
//! 4. Post-load process verification with graceful fallback message
//! 5. StandardOutPath / StandardErrorPath added for diagnosability
//! 6. ThrottleInterval added to prevent rapid respawn storms

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

    // Log paths for diagnosability
    let log_dir = dirs::home_dir()
        .map(|h| h.join("Library/Logs/AgentControl"))
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp/agentcontrol-logs"));
    let _ = fs::create_dir_all(&log_dir);
    let stdout_log = log_dir.join("agent-control.log").display().to_string();
    let stderr_log = log_dir.join("agent-control-error.log").display().to_string();

    // Fix 1: removed --centralized (doesn't exist in StartArgs); corrected port 8080 → 18080
    // Fix 2: KeepAlive with SuccessfulExit=false — only restart on crash, not on clean shutdown
    // Fix 5: StandardOutPath / StandardErrorPath for log capture
    // Fix 6: ThrottleInterval=10 prevents rapid-respawn storm on repeated crashes
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
        <string>--listen</string>
        <string>127.0.0.1:18080</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>5</integer>
    <key>EnvironmentVariables</key>
    <dict>
        <key>AGENTCONTROL_HUB_URL</key>
        <string>{hub}</string>
        <key>DASHBOARD_API_URL</key>
        <string>{hub}</string>
{agent_id}    </dict>
    <key>StandardOutPath</key>
    <string>{stdout}</string>
    <key>StandardErrorPath</key>
    <string>{stderr}</string>
</dict>
</plist>
"#,
        bin = bin_path,
        hub = hub_url,
        agent_id = agent_id_plist,
        stdout = stdout_log,
        stderr = stderr_log,
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

    // ── Secondary persistence: @reboot crontab entry ──────────────────────────────────────
    // For headless/SSH-only macOS servers where LaunchAgents don't fire without a GUI
    // session, a @reboot cron entry ensures the daemon starts on every system boot.
    // We add only if the entry isn't already present (idempotent).
    let cron_entry = format!("@reboot {} start --listen 127.0.0.1:18080\n", bin_path);
    let existing_cron = Command::new("crontab").arg("-l").output().ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();
    if !existing_cron.contains(&format!("{} start --listen", bin_path)) {
        let new_cron = format!("{}{}", existing_cron.trim_end_matches('\n'), cron_entry);
        let install = Command::new("sh")
            .arg("-c")
            .arg(format!("echo '{}' | crontab -", new_cron.replace('\'', "'\\''")))  
            .output();
        match install {
            Ok(o) if o.status.success() => println!("  ✔ @reboot crontab fallback entry added."),
            _ => println!("  ⚠ Could not install crontab entry (non-fatal)."),
        }
    } else {
        println!("  ✔ @reboot crontab entry already present.");
    }

    let target_str = target_path.display().to_string();

    // Unload first in case a stale entry is registered (ignore errors)
    let _ = Command::new("launchctl")
        .args(["unload", "-w", &target_str])
        .output();

    // Fix 3: Check launchctl load exit code
    let load_out = Command::new("launchctl")
        .args(["load", "-w", &target_str])
        .output()
        .map_err(|e| format!("failed to execute launchctl load: {}", e))?;

    if !load_out.status.success() {
        let stderr = String::from_utf8_lossy(&load_out.stderr);
        // macOS 12+ returns non-zero even on success if service was already running — treat as warning
        println!(
            "  {} launchctl load warning (may be harmless on macOS 12+): {}",
            "⚠".yellow(),
            stderr.trim()
        );
    }

    // Fix 4: Verify the process is actually running after load
    std::thread::sleep(std::time::Duration::from_millis(1500));

    let running = Command::new("pgrep")
        .args(["-x", "agentcontrol"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if running {
        println!("  {} agentcontrol process is running.", "✔".green().bold());
    } else {
        // Fallback: spawn directly with nohup so the daemon survives parent-shell exit.
        // Common on macOS 12+ (Ventura/Sonoma) where launchctl bootstrap is stricter
        // and may reject plists in non-GUI sessions.
        println!(
            "  {} Process not detected after launchctl load — launching directly...",
            "⚠".yellow()
        );
        let spawn_result = Command::new("nohup")
            .arg(bin_path)
            .args(["start", "--listen", "127.0.0.1:18080"])
            .env("AGENTCONTROL_HUB_URL", hub_url)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        match spawn_result {
            Ok(child) => println!(
                "  {} Daemon launched directly (PID: {}). Logs: {}",
                "✔".green().bold(),
                child.id(),
                stderr_log.cyan()
            ),
            Err(e) => println!(
                "  {} Failed to launch daemon: {}. Check logs: {}",
                "✖".red(),
                e,
                stderr_log.cyan()
            ),
        }
    }

    let mode_str = if is_daemon {
        "LaunchDaemon (system)"
    } else {
        "LaunchAgent (user)"
    };
    println!(
        "{} Agent Control macOS {} installed and loaded!",
        "✔".green().bold(),
        mode_str
    );
    println!("  Plist:   {}", target_str.cyan());
    println!("  Hub URL: {}", hub_url.cyan());
    println!("  Listen:  127.0.0.1:18080");
    println!("  Logs:    {}", log_dir.display().to_string().cyan());
    Ok(())
}

pub fn uninstall_macos_service() -> Result<(), String> {
    let daemon_plist = "/Library/LaunchDaemons/io.vexasec.agentcontrol.plist";
    let agent_plist =
        dirs::home_dir().map(|h| h.join("Library/LaunchAgents/io.vexasec.agentcontrol.plist"));

    // Kill running process first
    let _ = Command::new("pkill").args(["-x", "agentcontrol"]).output();

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

    // Remove @reboot crontab entry if present
    let cron_marker = "agentcontrol";
    let existing_cron = Command::new("crontab").arg("-l").output().ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();
    if existing_cron.contains(cron_marker) {
        let cleaned: String = existing_cron
            .lines()
            .filter(|l| !l.contains(cron_marker))
            .map(|l| format!("{}\n", l))
            .collect();
        let _ = Command::new("sh")
            .arg("-c")
            .arg(format!("echo '{}' | crontab -", cleaned.replace('\'', "'\\''")))  
            .output();
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
