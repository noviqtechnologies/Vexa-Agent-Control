//! Periodic background heartbeat emitter (Sprint 4).
//!
//! Transmits OS metadata, IDE config SHA-256 hashes, wrapped MCP server counts,
//! and uptime to `POST /api/v1/ingest/heartbeat` every 60 seconds.

use colored::*;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Serialize)]
pub struct HeartbeatPayload {
    pub device_id: String,
    pub hostname: String,
    pub os_arch: String,
    pub agentcontrol_version: String,
    pub agentwall_version: String,
    pub daemon_status: String,
    pub ide_checksums: HashMap<String, String>,
    pub mcp_servers_total: usize,
    pub mcp_servers_wrapped: usize,
    pub uptime_seconds: u64,
}

/// Computes SHA-256 checksums for all existing watched IDE config files.
pub fn compute_ide_checksums() -> (HashMap<String, String>, usize, usize) {
    let mut checksums = HashMap::new();
    let mut total_servers = 0;
    let mut wrapped_servers = 0;

    let targets = [
        (
            "claude_desktop",
            crate::wrap::config_path::claude_config_path(),
        ),
        ("cursor", crate::wrap::config_path::cursor_config_path()),
        ("codex", crate::wrap::config_path::codex_config_path()),
        ("vscode", crate::wrap::config_path::vscode_config_path()),
        (
            "jetbrains",
            crate::wrap::config_path::jetbrains_config_path(),
        ),
        ("zed", crate::wrap::config_path::zed_config_path()),
        ("cline", crate::wrap::config_path::cline_config_path()),
        ("opencode", crate::wrap::config_path::opencode_config_path()),
        (
            "antigravity",
            crate::wrap::config_path::antigravity_config_path(),
        ),
    ];

    for (name, path_res) in targets {
        if let Ok(path) = path_res {
            if path.exists() {
                if let Ok(bytes) = std::fs::read(&path) {
                    let mut hasher = Sha256::new();
                    hasher.update(&bytes);
                    let hash_hex = format!("sha256:{}", hex::encode(hasher.finalize()));
                    checksums.insert(name.to_string(), hash_hex);

                    if let Ok(raw) = String::from_utf8(bytes) {
                        if path.extension().and_then(|e| e.to_str()) == Some("toml") {
                            if let Ok(val) = toml::from_str::<toml::Value>(&raw) {
                                if let Some(servers) =
                                    val.get("mcp_servers").and_then(|s| s.as_table())
                                {
                                    total_servers += servers.len();
                                    wrapped_servers += servers
                                        .values()
                                        .filter(|v| {
                                            v.get("command")
                                                .and_then(|c| c.as_str())
                                                .map(|cmd| cmd.to_lowercase().contains("agentwall"))
                                                .unwrap_or(false)
                                        })
                                        .count();
                                }
                            }
                        } else if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
                            if let Some(servers) = v.get("mcpServers").and_then(|s| s.as_object()) {
                                total_servers += servers.len();
                                wrapped_servers += servers
                                    .values()
                                    .filter(|srv| crate::wrap::transformer::is_already_wrapped(srv))
                                    .count();
                            }
                        }
                    }
                }
            }
        }
    }

    (checksums, total_servers, wrapped_servers)
}

/// Background async task that runs a 60-second periodic heartbeat loop.
pub async fn start_heartbeat_loop(interval_secs: u64) {
    let start_time = Instant::now();
    let interval_duration = Duration::from_secs(interval_secs.max(10));
    let mut interval = tokio::time::interval(interval_duration);

    println!(
        "{} Starting background device heartbeat loop (interval: {}s)",
        "●".green().bold(),
        interval_secs
    );

    let device_identity = crate::identity::device::DeviceIdentity::load_or_create().ok();
    let device_id = crate::identity::device::load_device_token()
        .or_else(|| device_identity.as_ref().map(|id| id.device_id.clone()))
        .unwrap_or_else(|| "gw-default".to_string());

    let hostname = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "localhost".to_string());

    let os_arch = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
    let pkg_ver = env!("CARGO_PKG_VERSION").to_string();

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build();

    let client = match client {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "{} Failed to build HTTP client for heartbeat: {}",
                "⚠".yellow(),
                e
            );
            return;
        }
    };

    loop {
        interval.tick().await;

        // Periodic fleet MCP server snapshot sync
        crate::wrap::status::gather_and_send_mcp_servers_snapshot();

        let (checksums, total_servers, wrapped_servers) = compute_ide_checksums();
        let uptime_seconds = start_time.elapsed().as_secs();

        let payload = HeartbeatPayload {
            device_id: device_id.clone(),
            hostname: hostname.clone(),
            os_arch: os_arch.clone(),
            agentcontrol_version: pkg_ver.clone(),
            agentwall_version: pkg_ver.clone(),
            daemon_status: "ACTIVE_ENFORCING".to_string(),
            ide_checksums: checksums,
            mcp_servers_total: total_servers,
            mcp_servers_wrapped: wrapped_servers,
            uptime_seconds,
        };

        let base_url = std::env::var("AGENTCONTROL_HUB_URL")
            .or_else(|_| std::env::var("AGENTWALL_HUB_URL"))
            .or_else(|_| std::env::var("DASHBOARD_API_URL"))
            .unwrap_or_else(|_| "https://console.vexasec.io".to_string());

        let heartbeat_url = format!("{}/api/v1/ingest/heartbeat", base_url.trim_end_matches('/'));

        let mut req = client.post(&heartbeat_url).json(&payload);

        // Attach Gateway Secret in Authorization header for Control Hub ingest endpoint.
        // Prioritizes enrolled device_token, then explicit GATEWAY_SECRET (ignoring dev placeholder), and lastly fallback.
        let auth_token = if let Some(token) = crate::identity::device::load_device_token() {
            token
        } else if let Ok(secret) = std::env::var("GATEWAY_SECRET") {
            let s = secret.trim().to_string();
            if !s.is_empty() && s != "local-dev-shared-secret-change-me" {
                s
            } else {
                "local-dev-shared-secret-change-me".to_string()
            }
        } else {
            "local-dev-shared-secret-change-me".to_string()
        };

        req = req.header("Authorization", format!("Bearer {}", auth_token));

        match req.send().await {
            Ok(res) if res.status().is_success() => {
                crate::service::eventlog::log_info(
                    1001,
                    &format!("Heartbeat accepted cleanly by Hub ({}) for device {}", base_url, device_id),
                );
            }
            Ok(res) => {
                let status = res.status().as_u16();
                crate::logging::log_event(
                    crate::logging::Level::Warn,
                    "heartbeat_rejected",
                    serde_json::json!({"status": status}),
                );
                crate::service::eventlog::log_warn(
                    1002,
                    &format!("Heartbeat rejected by Hub ({}) with HTTP status: {}", base_url, status),
                );
            }
            Err(e) => {
                let err_str = e.to_string();
                crate::logging::log_event(
                    crate::logging::Level::Warn,
                    "heartbeat_failed",
                    serde_json::json!({"error": &err_str}),
                );
                crate::service::eventlog::log_error(
                    1003,
                    &format!("Failed to connect to Hub ({}) for heartbeat: {}", base_url, err_str),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_ide_checksums() {
        let (checksums, _total, _wrapped) = compute_ide_checksums();
        // Should execute cleanly without panic
        let _ = checksums.len();
    }
}
