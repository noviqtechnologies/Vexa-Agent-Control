//! OS Service Manager integration module — handles systemd (Linux), launchd (macOS), and SCM/Task Scheduler (Windows).

pub mod eventlog;
pub mod linux;
pub mod macos;
pub mod windows;
pub mod windows_profiles;

use colored::*;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Cross-platform daemon configuration stored in `daemon.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DaemonConfig {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    pub hub_url: String,
    #[serde(default = "default_listen_addr")]
    pub listen: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_read_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub enterprise: bool,
}

fn default_schema_version() -> u32 {
    1
}

fn default_listen_addr() -> String {
    "127.0.0.1:18080".to_string()
}

/// Returns the standard user configuration directory `~/.agentcontrol`.
pub fn get_user_config_dir() -> PathBuf {
    dirs::home_dir()
        .map(|h| h.join(".agentcontrol"))
        .unwrap_or_else(|| PathBuf::from(".agentcontrol"))
}

/// Returns default user daemon configuration path: `~/.agentcontrol/daemon.json`.
pub fn default_user_config_path() -> PathBuf {
    get_user_config_dir().join("daemon.json")
}

/// Returns default enterprise/system daemon configuration path:
/// - Windows: `%PROGRAMDATA%\VexaAgentControl\daemon.json`
/// - macOS: `/Library/Application Support/AgentControl/daemon.json`
/// - Linux: `/etc/agentcontrol/daemon.json`
pub fn default_enterprise_config_path() -> PathBuf {
    #[cfg(windows)]
    {
        let program_data = env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
        PathBuf::from(program_data).join("VexaAgentControl").join("daemon.json")
    }
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Application Support/AgentControl/daemon.json")
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        PathBuf::from("/etc/agentcontrol/daemon.json")
    }
}

/// Saves daemon configuration to disk with strict secure permissions (0600 on Unix).
pub fn save_daemon_config(config: &DaemonConfig, path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    let json_str = serde_json::to_string_pretty(config)
        .map_err(|e| format!("Failed to serialize daemon configuration: {}", e))?;

    fs::write(path, json_str)
        .map_err(|e| format!("Failed to write daemon config to {}: {}", path.display(), e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

/// Loads daemon configuration from explicit path or default user/enterprise locations.
pub fn load_daemon_config(custom_path: Option<&str>, enterprise: bool) -> Result<Option<DaemonConfig>, String> {
    let candidate = if let Some(p) = custom_path {
        PathBuf::from(p)
    } else if enterprise {
        default_enterprise_config_path()
    } else {
        default_user_config_path()
    };

    if !candidate.exists() {
        return Ok(None);
    }

    let content = fs::read_to_string(&candidate)
        .map_err(|e| format!("Failed to read config from {}: {}", candidate.display(), e))?;

    let parsed: DaemonConfig = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse config from {}: {}", candidate.display(), e))?;

    Ok(Some(parsed))
}

// ─── Health Handshake & Truthful State Model ──────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonHealthResponse {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    pub status: String,
    pub pid: u32,
    pub binary_path: String,
    pub version: String,
    pub uptime_secs: u64,
    pub listen_addr: String,
    #[serde(default)]
    pub policy: PolicyHealthInfo,
    #[serde(default)]
    pub auth: AuthHealthInfo,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyHealthInfo {
    pub loaded: bool,
    pub path: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthHealthInfo {
    pub enrolled: bool,
    pub hub_url: Option<String>,
    pub device_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum SupervisorState {
    Managed {
        supervisor_type: String,
        target_name: String,
        active: bool,
        details: Option<String>,
    },
    Unmanaged {
        warning: String,
    },
    NotInstalled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum ListenerState {
    Healthy {
        addr: String,
        latency_ms: u64,
        handshake: DaemonHealthResponse,
    },
    OccupiedForeign {
        addr: String,
        message: String,
    },
    Refused {
        addr: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DaemonHealthReport {
    pub supervisor: SupervisorState,
    pub listener: ListenerState,
}

impl DaemonHealthReport {
    pub fn is_healthy_managed(&self) -> bool {
        matches!(&self.supervisor, SupervisorState::Managed { active: true, .. })
            && matches!(&self.listener, ListenerState::Healthy { .. })
    }
}

/// Performs an authenticated local health handshake against `http://<listen_addr>/api/v1/health`.
pub async fn query_local_health(listen_addr: &str) -> ListenerState {
    let url = if listen_addr.starts_with("http://") || listen_addr.starts_with("https://") {
        format!("{}/api/v1/health", listen_addr.trim_end_matches('/'))
    } else {
        format!("http://{}/api/v1/health", listen_addr.trim_end_matches('/'))
    };

    let start = std::time::Instant::now();
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_millis(1500))
        .build()
    {
        Ok(c) => c,
        Err(_) => return ListenerState::Refused { addr: listen_addr.to_string() },
    };

    let mut req = client.get(&url);
    if let Ok(token) = crate::identity::oauth::get_or_create_local_token() {
        req = req.header("Authorization", format!("Bearer {}", token));
    }

    match req.send().await {
        Ok(resp) => {
            let latency_ms = start.elapsed().as_millis() as u64;
            if resp.status().is_success() {
                match resp.json::<DaemonHealthResponse>().await {
                    Ok(handshake) => ListenerState::Healthy {
                        addr: listen_addr.to_string(),
                        latency_ms,
                        handshake,
                    },
                    Err(e) => ListenerState::OccupiedForeign {
                        addr: listen_addr.to_string(),
                        message: format!("HTTP endpoint answered but returned invalid handshake schema: {}", e),
                    },
                }
            } else {
                ListenerState::OccupiedForeign {
                    addr: listen_addr.to_string(),
                    message: format!("HTTP endpoint returned status code {}", resp.status()),
                }
            }
        }
        Err(_) => {
            // TCP connect test
            let tcp_target = listen_addr.trim_start_matches("http://").trim_start_matches("https://");
            if tokio::net::TcpStream::connect(tcp_target).await.is_ok() {
                ListenerState::OccupiedForeign {
                    addr: listen_addr.to_string(),
                    message: "Port is open but not responding to Agent Control health handshake".to_string(),
                }
            } else {
                ListenerState::Refused {
                    addr: listen_addr.to_string(),
                }
            }
        }
    }
}

/// Inspects supervisor and daemon health across the current OS.
pub async fn inspect_service_health() -> DaemonHealthReport {
    let listen_addr = "127.0.0.1:18080";
    let listener = query_local_health(listen_addr).await;

    let mut supervisor = if cfg!(windows) {
        #[cfg(windows)]
        {
            windows::inspect_windows_service()
        }
        #[cfg(not(windows))]
        {
            SupervisorState::NotInstalled
        }
    } else if cfg!(target_os = "macos") {
        #[cfg(target_os = "macos")]
        {
            macos::inspect_macos_service()
        }
        #[cfg(not(target_os = "macos"))]
        {
            SupervisorState::NotInstalled
        }
    } else {
        #[cfg(target_os = "linux")]
        {
            linux::inspect_linux_service()
        }
        #[cfg(not(target_os = "linux"))]
        {
            SupervisorState::NotInstalled
        }
    };

    if supervisor == SupervisorState::NotInstalled && matches!(&listener, ListenerState::Healthy { .. }) {
        supervisor = SupervisorState::Unmanaged {
            warning: "Daemon process is running interactively or detached, but is not managed by an authoritative OS supervisor.".to_string(),
        };
    }

    DaemonHealthReport {
        supervisor,
        listener,
    }
}

// ─── CLI Service Commands Execution ──────────────────────────────────────────

#[derive(Debug)]
pub enum ServiceAction {
    Install {
        hub_url: String,
        gateway_secret: Option<String>,
        policy_read_secret: Option<String>,
        agent_id: Option<String>,
        enterprise: bool,
        config: Option<String>,
        /// Allow overwriting an existing enrolled hub URL without an error.
        force: bool,
    },
    Uninstall,
    Status,
}

/// Run a service management action.
///
/// `called_from_login` must be set to `true` only when invoked internally from
/// `run_login()` after successful PKCE authentication. It bypasses the enrollment
/// pre-check because the device is in the process of being enrolled — credentials
/// do not yet exist on disk at the point the service is registered.
///
/// `quiet` suppresses all informational `println!` output. Used by `run_login()` so
/// the service registration runs silently in the background and the login command
/// owns the entire UX output. Only errors are printed when quiet=true.
pub async fn run_service(action: ServiceAction, called_from_login: bool, quiet: bool) -> i32 {
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
            enterprise,
            config,
            force,
        } => {
            // ── Enrollment pre-check ─────────────────────────────────────────
            // Standalone `service install` requires prior authentication unless:
            //   a) called internally from run_login() (called_from_login = true)
            //   b) enterprise mode with OS-level admin privileges (MDM / Intune provisioning)
            if !called_from_login && !enterprise {
                if !crate::identity::device::is_device_enrolled() {
                    eprintln!(
                        "{} Workstation is not enrolled. Authenticate first:",
                        "✖".red().bold()
                    );
                    eprintln!(
                        "    {}",
                        "agentcontrol login --hub <control-hub-url>".cyan()
                    );
                    eprintln!(
                        "  Authentication automatically registers the background service."
                    );
                    return 1;
                }
            }

            // ── Hub URL overwrite warning ─────────────────────────────────────
            // If the device is already enrolled and the caller is requesting a
            // different hub URL, warn before overwriting. Use --force to suppress.
            if !called_from_login && !force {
                if let Some(existing_hub) = crate::identity::device::load_hub_url() {
                    let clean_new = hub_url.trim_end_matches('/');
                    let clean_existing = existing_hub.trim_end_matches('/');
                    if !clean_new.eq_ignore_ascii_case(clean_existing) {
                        eprintln!(
                            "{} Hub URL is changing from {} to {}.",
                            "⚠".yellow().bold(),
                            clean_existing.yellow(),
                            clean_new.yellow()
                        );
                        eprintln!(
                            "  Daemon will be re-pointed. Pass {} to suppress this warning.",
                            "--force".cyan()
                        );
                    }
                }
            }

            let _ = crate::identity::device::save_hub_url(&hub_url);

            // 1. Stage self-contained configuration file
            let config_path = if let Some(ref p) = config {
                PathBuf::from(p)
            } else if enterprise {
                default_enterprise_config_path()
            } else {
                default_user_config_path()
            };

            let daemon_cfg = DaemonConfig {
                schema_version: 1,
                hub_url: hub_url.clone(),
                listen: "127.0.0.1:18080".to_string(),
                gateway_secret: gateway_secret.clone(),
                policy_read_secret: policy_read_secret.clone(),
                agent_id: agent_id.clone(),
                enterprise,
            };

            if let Err(e) = save_daemon_config(&daemon_cfg, &config_path) {
                eprintln!("{} Failed to write daemon configuration: {}", "✖".red(), e);
                return 1;
            }

            let gw_sec = gateway_secret.as_deref().unwrap_or("");
            let pol_sec = policy_read_secret.as_deref().unwrap_or("");

            let res = if cfg!(target_os = "windows") {
                windows::install_windows_service(
                    &current_exe,
                    &hub_url,
                    gw_sec,
                    pol_sec,
                    agent_id.as_deref(),
                    enterprise,
                    &config_path,
                    quiet,
                )
            } else if cfg!(target_os = "macos") {
                macos::install_macos_service(
                    &current_exe,
                    &hub_url,
                    gw_sec,
                    pol_sec,
                    agent_id.as_deref(),
                    enterprise,
                    &config_path,
                    quiet,
                )
            } else {
                linux::install_linux_service(
                    &current_exe,
                    &hub_url,
                    gw_sec,
                    pol_sec,
                    agent_id.as_deref(),
                    enterprise,
                    &config_path,
                    quiet,
                )
            };

            match res {
                Ok(_) => {
                    if !quiet {
                        let startup_desc = if enterprise {
                            if cfg!(target_os = "windows") {
                                "Enabled (Windows SCM service: AgentControlSentry)"
                            } else if cfg!(target_os = "macos") {
                                "Enabled (macOS LaunchDaemon: io.vexasec.agentcontrol)"
                            } else {
                                "Enabled (systemd system service: agent-control)"
                            }
                        } else {
                            if cfg!(target_os = "windows") {
                                "Enabled (starts automatically at user logon)"
                            } else if cfg!(target_os = "macos") {
                                "Enabled (macOS LaunchAgent: io.vexasec.agentcontrol)"
                            } else {
                                "Enabled (systemd user service: agent-control)"
                            }
                        };
                        println!("\n{} Background service installed successfully!", "✔".green().bold());
                        println!("  Hub URL:   {}", hub_url.cyan());
                        println!("  Startup:   {}", startup_desc);
                        println!("\nTo check service health and activity, run:");
                        println!("  {}", "agentcontrol service status".bold());
                    }
                    0
                }
                Err(e) => {
                    if quiet {
                        // Called from login: show a concise, non-alarming warning.
                        // The login summary will still report success — the daemon
                        // will start on next user session login via HKCU\Run.
                        eprintln!(
                            "  {} Background daemon registration encountered an issue (will retry on next login).",
                            "⚠".yellow()
                        );
                        let _ = e; // log internally if tracing is added
                    } else {
                        eprintln!("\n{} Service installation failed: {}", "✖".red().bold(), e);
                    }
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
                Ok(_) => {
                    println!("{} Uninstallation complete.", "✔".green().bold());
                    0
                }
                Err(e) => {
                    eprintln!("{} Service uninstallation failed: {}", "✖".red(), e);
                    1
                }
            }
        }
        ServiceAction::Status => {
            let report = inspect_service_health().await;
            print_service_status(&report);
            if report.is_healthy_managed() {
                0
            } else {
                1
            }
        }
    }
}

/// Renders a clean, concise, cross-platform service status report.
pub fn print_service_status(report: &DaemonHealthReport) {
    println!("\n{} Vexa Agent Control Service Status", "●".green().bold());
    println!("────────────────────────────────────────────────────────────────────────────────");

    // 1. Supervisor / Service Manager
    match &report.supervisor {
        SupervisorState::Managed { supervisor_type, active, .. } => {
            let status_badge = if *active { "Active".green().bold() } else { "Stopped".yellow().bold() };
            println!("  Service Manager:    {} ({})", supervisor_type.cyan(), status_badge);
        }
        SupervisorState::Unmanaged { warning } => {
            println!("  Service Manager:    {} ({})", "Unmanaged / Standalone".yellow().bold(), warning.yellow());
        }
        SupervisorState::NotInstalled => {
            println!("  Service Manager:    {} (Run '{}' to install)", "Not Installed".red().bold(), "agentcontrol service install".cyan());
        }
    }

    // 2. Process, Binding & Policy
    match &report.listener {
        ListenerState::Healthy { addr, latency_ms, handshake } => {
            println!("  Daemon Process:     PID {} (v{}, uptime: {}s)", handshake.pid.to_string().green(), handshake.version.green(), handshake.uptime_secs);
            println!("  Local Endpoint:     http://{} ({}ms RTT)", addr.green(), latency_ms);
            let pol_badge = if handshake.policy.loaded { "ACTIVE".green() } else { "LOCAL SAFE MODE".yellow() };
            let pol_info = handshake.policy.path.as_deref().unwrap_or("standalone");
            println!("  Policy Mode:        {} ({})", pol_badge, pol_info);
            let auth_badge = if handshake.auth.enrolled { "ENROLLED".green() } else { "STANDALONE".yellow() };
            let hub_info = handshake.auth.hub_url.as_deref().unwrap_or("none");
            println!("  Hub Connection:     {} ({})", auth_badge, hub_info);
        }
        ListenerState::OccupiedForeign { addr, message } => {
            println!("  Local Endpoint:     http://{} ({})", addr.red(), "CONFLICTED".red().bold());
            println!("  ⚠ Conflict:         {}", message.red());
        }
        ListenerState::Refused { addr } => {
            println!("  Local Endpoint:     http://{} ({})", addr.yellow(), "NOT RUNNING".yellow().bold());
        }
    }
    println!("────────────────────────────────────────────────────────────────────────────────");

    if report.is_healthy_managed() {
        println!("{} Status: HEALTHY (Daemon is running and supervised)", "✔".green().bold());
    } else if matches!(&report.listener, ListenerState::Healthy { .. }) {
        println!("{} Status: RUNNING (Process is active, not managed by OS service manager)", "ℹ".cyan().bold());
    } else {
        println!("{} Status: STOPPED (Daemon is not responding on 127.0.0.1:18080)", "✖".red().bold());
    }
}

