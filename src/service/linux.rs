//! Linux Systemd Service Installer module.

use colored::*;
use std::fs;
use std::process::Command;

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

    let service_content = format!(
        r#"[Unit]
Description=AgentWall Sentry Endpoint Security Service
After=network.target

[Service]
Type=simple
ExecStart={} start --centralized --listen 127.0.0.1:8080
Restart=always
RestartSec=5s
Environment=DASHBOARD_API_URL="{}"
{}
[Install]
WantedBy=multi-user.target
"#,
        bin_path, hub_url, agent_id_line
    );

    let unit_path = "/etc/systemd/system/agentwall.service";
    println!("  Writing systemd unit to {}", unit_path.cyan());

    fs::write(unit_path, service_content).map_err(|e| {
        format!(
            "failed to write systemd unit file (root permissions required?): {}",
            e
        )
    })?;

    let reload = Command::new("systemctl").arg("daemon-reload").output();
    if let Err(e) = reload {
        return Err(format!("failed to execute systemctl daemon-reload: {}", e));
    }

    let enable = Command::new("systemctl")
        .args(["enable", "--now", "agentwall"])
        .output();
    if let Err(e) = enable {
        return Err(format!(
            "failed to execute systemctl enable --now agentwall: {}",
            e
        ));
    }

    println!(
        "{} AgentWall Linux systemd service installed and started!",
        "✔".green().bold()
    );
    Ok(())
}

pub fn uninstall_linux_service() -> Result<(), String> {
    let _ = Command::new("systemctl")
        .args(["stop", "agentwall"])
        .output();
    let _ = Command::new("systemctl")
        .args(["disable", "agentwall"])
        .output();

    let unit_path = "/etc/systemd/system/agentwall.service";
    if std::path::Path::new(unit_path).exists() {
        let _ = fs::remove_file(unit_path);
    }
    let _ = Command::new("systemctl").arg("daemon-reload").output();

    println!(
        "{} AgentWall Linux systemd service uninstalled.",
        "✔".green().bold()
    );
    Ok(())
}
