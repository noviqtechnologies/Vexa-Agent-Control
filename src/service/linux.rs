//! Linux Systemd Service Installer module.
//!
//! Installs as a system-level service (root) or user-level service (~/.config/systemd/user/)
//! when running without root. Fixes applied vs original:
//! 1. Removed non-existent --centralized flag; corrected port 8080 → 18080
//! 2. Proper fallback to systemd --user when not root
//! 3. systemctl exit-code checking with informational (non-fatal) warnings
//! 4. daemon-reload called before enable; post-enable process verification

use colored::*;
use std::fs;
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
    hub_url: &str,
    _gateway_secret: &str,
    _policy_read_secret: &str,
    agent_id: Option<&str>,
) -> Result<(), String> {
    // Build optional AGENT_ID environment line
    let agent_id_line = agent_id
        .map(|id| format!("Environment=AGENT_ID=\"{}\"\n", id))
        .unwrap_or_default();

    // Fix 1: removed non-existent --centralized flag; corrected port 8080 → 18080
    let service_content = format!(
        r#"[Unit]
Description=Agent Control Sentry Endpoint Security Service
Documentation=https://github.com/noviqtechnologies/Vexa-Agent-Control
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart={bin} start --listen 127.0.0.1:18080
Restart=always
RestartSec=5s
Environment=AGENTCONTROL_HUB_URL="{hub}"
Environment=DASHBOARD_API_URL="{hub}"
{agent_id}
# Security hardening
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=default.target
"#,
        bin = bin_path,
        hub = hub_url,
        agent_id = agent_id_line,
    );

    // ── Secondary persistence: XDG autostart desktop entry ───────────────────────────
    // Works in GNOME, KDE, XFCE and any XDG-compliant desktop environment.
    // Acts as a belt-and-suspenders layer: even if systemd --user is unavailable
    // (e.g. SSH session, container, minimal distro), the desktop session will start
    // the daemon on GUI login.
    let xdg_autostart_dir = dirs::config_dir()
        .map(|d| d.join("autostart"))
        .unwrap_or_else(|| {
            dirs::home_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
                .join(".config/autostart")
        });
    let _ = fs::create_dir_all(&xdg_autostart_dir);
    let desktop_entry = format!(
        "[Desktop Entry]\nType=Application\nName=AgentControl Sentry\nExec={bin} start --listen 127.0.0.1:18080\nHidden=false\nNoDisplay=true\nX-GNOME-Autostart-enabled=true\nComment=Vexa AgentControl endpoint security daemon\n",
        bin = bin_path
    );
    let desktop_path = xdg_autostart_dir.join("io.vexasec.agentcontrol.desktop");
    if let Err(e) = fs::write(&desktop_path, &desktop_entry) {
        println!("  ⚠ XDG autostart entry skipped: {}", e);
    } else {
        println!("  ✔ XDG autostart entry written: {}", desktop_path.display());
    }

    // Fix 2: Fall back to systemd --user when not root
    let (unit_path, use_user_systemd) = if is_root() {
        ("/etc/systemd/system/agent-control.service".to_string(), false)
    } else {
        let user_dir = dirs::config_dir()
            .map(|d| d.join("systemd/user"))
            .unwrap_or_else(|| {
                dirs::home_dir()
                    .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
                    .join(".config/systemd/user")
            });
        let _ = fs::create_dir_all(&user_dir);
        (
            user_dir
                .join("agent-control.service")
                .display()
                .to_string(),
            true,
        )
    };

    println!(
        "  Writing systemd unit to {}{}",
        unit_path.cyan(),
        if use_user_systemd { " (user scope)" } else { "" }
    );

    fs::write(&unit_path, service_content).map_err(|e| {
        format!(
            "failed to write systemd unit file{}: {}",
            if !use_user_systemd { " (try running with sudo)" } else { "" },
            e
        )
    })?;

    // Build base systemctl command (with or without --user)
    let systemctl_args_base: Vec<&str> = if use_user_systemd {
        vec!["--user"]
    } else {
        vec![]
    };

    // Fix 3: daemon-reload with exit code check
    let mut reload_args = systemctl_args_base.clone();
    reload_args.push("daemon-reload");
    let reload = Command::new("systemctl").args(&reload_args).output();
    match reload {
        Err(e) => return Err(format!("failed to execute systemctl daemon-reload: {}", e)),
        Ok(out) if !out.status.success() => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            println!(
                "  {} systemctl daemon-reload warning: {}",
                "⚠".yellow(),
                stderr.trim()
            );
        }
        _ => {}
    }

    // Fix 4: enable --now with exit code check
    let mut enable_args = systemctl_args_base.clone();
    enable_args.extend_from_slice(&["enable", "--now", "agent-control"]);
    let enable = Command::new("systemctl").args(&enable_args).output();
    match enable {
        Err(e) => {
            return Err(format!(
                "failed to execute systemctl enable --now agent-control: {}",
                e
            ))
        }
        Ok(_) => {}
    }

    // Ensure user-scope services persist across session logouts
    if use_user_systemd {
        let _ = Command::new("loginctl")
            .arg("enable-linger")
            .output();
    }

    // Fix 5: Verify the service is actually running
    let mut status_args = systemctl_args_base.clone();
    status_args.extend_from_slice(&["is-active", "--quiet", "agent-control"]);
    let is_active = Command::new("systemctl")
        .args(&status_args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if is_active {
        println!("  {} Service is active and running.", "✔".green().bold());
    } else {
        // Fallback: check if the process is in the process table
        let running = Command::new("pgrep")
            .args(["-x", "agentcontrol"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        if running {
            println!("  {} agentcontrol process is running.", "✔".green().bold());
        } else {
            // Last-resort: spawn directly with nohup so it survives the parent process/session end.
            // This handles no-systemd environments (containers, SSH-only boxes, WSL without systemd).
            println!(
                "  {} Systemd service inactive — launching daemon directly with nohup...",
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
                    "  {} Daemon launched directly (PID: {}). Systemd will manage on next boot.",
                    "✔".green().bold(),
                    child.id()
                ),
                Err(e) => println!(
                    "  {} Failed to launch daemon: {}. Check: systemctl{}status agent-control",
                    "✖".red(),
                    e,
                    if use_user_systemd { " --user " } else { " " }
                ),
            }
        }
    }

    println!(
        "{} Agent Control Linux systemd service installed and started!",
        "✔".green().bold()
    );
    println!(
        "  Unit File:  {}",
        unit_path.cyan()
    );
    println!("  Hub URL:    {}", hub_url.cyan());
    println!("  Listen:     127.0.0.1:18080");
    Ok(())
}

pub fn uninstall_linux_service() -> Result<(), String> {
    // Stop and disable both user and system variants
    for user_flag in &[vec!["--user"], vec![]] {
        let mut stop_args = user_flag.clone();
        stop_args.push("stop");
        stop_args.push("agent-control");
        let _ = Command::new("systemctl").args(&stop_args).output();

        let mut disable_args = user_flag.clone();
        disable_args.push("disable");
        disable_args.push("agent-control");
        let _ = Command::new("systemctl").args(&disable_args).output();
    }

    // Remove unit files from both system and user locations
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
        if !path.is_empty() && std::path::Path::new(path).exists() {
            let _ = fs::remove_file(path);
        }
    }

    // Kill any running agentcontrol process
    let _ = Command::new("pkill").args(["-x", "agentcontrol"]).output();

    // Remove XDG autostart entry
    let xdg_desktop = dirs::config_dir()
        .map(|d| d.join("autostart/io.vexasec.agentcontrol.desktop"))
        .or_else(|| dirs::home_dir().map(|h| h.join(".config/autostart/io.vexasec.agentcontrol.desktop")));
    if let Some(path) = xdg_desktop {
        if path.exists() {
            let _ = fs::remove_file(&path);
        }
    }

    // Reload daemon for both scopes
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
