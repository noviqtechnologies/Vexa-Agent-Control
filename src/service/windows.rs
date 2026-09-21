//! Windows Service Control Manager (SCM) Installer module.

#[cfg(windows)]
use super::SupervisorState;
#[cfg(windows)]
use colored::*;
use std::path::Path;

#[cfg(windows)]
fn sanitize_url(url: &str) -> String {
    let mut s = url.trim().to_string();
    while s.starts_with("http://http://") {
        s = s.replacen("http://http://", "http://", 1);
    }
    while s.starts_with("https://https://") {
        s = s.replacen("https://https://", "https://", 1);
    }
    while s.starts_with("http://https://") {
        s = s.replacen("http://https://", "https://", 1);
    }
    while s.starts_with("https://http://") {
        s = s.replacen("https://http://", "http://", 1);
    }
    s.trim_end_matches('/').to_string()
}

#[cfg(windows)]
pub fn is_elevated_admin() -> bool {
    let output = std::process::Command::new("net")
        .args(&["session"])
        .output();
    match output {
        Ok(out) => out.status.success(),
        Err(_) => false,
    }
}

#[cfg(windows)]
pub fn install_windows_service(
    bin_path: &str,
    hub_url: &str,
    _gateway_secret: &str,
    _policy_read_secret: &str,
    agent_id: Option<&str>,
    enterprise: bool,
    config_path: &Path,
    quiet: bool,
) -> Result<(), String> {
    let clean_hub_url = sanitize_url(hub_url);

    if enterprise {
        if !is_elevated_admin() {
            return Err("Enterprise mode requires Administrator privileges. Run from an elevated terminal or use standard per-user mode ('agentcontrol service install').".to_string());
        }
        return install_windows_scm(bin_path, &clean_hub_url, config_path);
    }

    // Standard User Mode: Per-user Scheduled Task
    install_windows_user_task(bin_path, &clean_hub_url, agent_id, config_path, quiet)
}

#[cfg(windows)]
fn install_windows_user_task(
    bin_path: &str,
    _clean_hub_url: &str,
    _agent_id: Option<&str>,
    config_path: &Path,
    _quiet: bool,
) -> Result<(), String> {
    let username = std::env::var("USERNAME").unwrap_or_else(|_| "user".to_string());
    let task_name = format!("VexaAgentControl-{}", username);

    // 1. Scoped Pre-Cleanup: Remove legacy HKCU\Run entry and legacy task name
    let _ = std::process::Command::new("powershell")
        .args(&[
            "-NoProfile", "-NonInteractive", "-Command",
            "Remove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'VexaAgentControl' -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName 'VexaAgentControl' -Confirm:$false -ErrorAction SilentlyContinue"
        ])
        .output();

    // 2. Try registering Scheduled Task first
    let task_xml_path = crate::service::get_user_config_dir().join("task.xml");
    let xml_content = format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Vexa Agent Control Sentry Endpoint Security Background Daemon</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT30S</Interval>
      <Count>9999</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{bin}</Command>
      <Arguments>start --config &quot;{config}&quot;</Arguments>
    </Exec>
  </Actions>
</Task>
"#,
        bin = bin_path,
        config = config_path.display(),
    );

    let _ = std::fs::create_dir_all(crate::service::get_user_config_dir());
    let _ = std::fs::write(&task_xml_path, xml_content);

    let ps_task_reg = format!(
        "$ErrorActionPreference = 'Stop'; Register-ScheduledTask -Xml (Get-Content -Raw -Encoding UTF8 '{}') -TaskName '{}' -Force; Start-ScheduledTask -TaskName '{}'",
        task_xml_path.display(),
        task_name,
        task_name,
    );

    let task_res = std::process::Command::new("powershell")
        .args(&["-NoProfile", "-NonInteractive", "-Command", &ps_task_reg])
        .output();

    match task_res {
        Ok(out) if out.status.success() => {}
        _ => {
            // If Task Scheduler denied access, register User Startup (HKCU\Run) which is zero-admin
            let bin_escaped = bin_path.replace('\'', "''");
            let config_escaped = config_path.display().to_string().replace('\'', "''");
            let reg_value = format!("\"{}\" start --config \"{}\"", bin_escaped, config_escaped);

            let ps_reg_cmd = format!(
                "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'VexaAgentControl' -Value '{}'",
                reg_value
            );
            let reg_out = std::process::Command::new("powershell")
                .args(&["-NoProfile", "-NonInteractive", "-Command", &ps_reg_cmd])
                .output()
                .map_err(|e| format!("Failed to configure Windows User Startup: {}", e))?;

            if !reg_out.status.success() {
                let err = String::from_utf8_lossy(&reg_out.stderr);
                return Err(format!(
                    "Windows User Startup registration failed: {}",
                    err.trim()
                ));
            }
        }
    }

    // Launch daemon immediately as a fully detached, hidden background process.
    // CREATE_NO_WINDOW (0x08000000): no console window is created or inherited.
    // DETACHED_PROCESS  (0x00000008): severs the child from the parent's console entirely,
    // so closing the installer terminal does NOT kill the daemon.
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        let _ = std::process::Command::new(bin_path)
            .args(&["start", "--config", &config_path.to_string_lossy()])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS)
            .spawn();
    }

    std::thread::sleep(std::time::Duration::from_millis(800));

    Ok(())
}

#[cfg(windows)]
fn install_windows_scm(
    bin_path: &str,
    _clean_hub_url: &str,
    config_path: &Path,
) -> Result<(), String> {
    let bin_with_args = format!(
        "\"{}\" start --config \"{}\"",
        bin_path,
        config_path.display()
    );

    let sc_output = std::process::Command::new("sc.exe")
        .args(&[
            "create",
            "AgentControlSentry",
            &format!("binPath= {}", bin_with_args),
            "start= auto",
            "DisplayName= Vexa Agent Control Security Sentry",
        ])
        .output()
        .map_err(|e| format!("Failed to execute sc.exe: {}", e))?;

    if !sc_output.status.success() {
        let err = String::from_utf8_lossy(&sc_output.stderr);
        if !err.contains("already exists") {
            return Err(format!("sc.exe create failed: {}", err.trim()));
        }
    }

    // Configure recovery actions
    let _ = std::process::Command::new("sc.exe")
        .args(&[
            "failure",
            "AgentControlSentry",
            "reset= 86400",
            "actions= restart/10000/restart/30000/restart/60000",
        ])
        .output();

    let _ = std::process::Command::new("sc.exe")
        .args(&["start", "AgentControlSentry"])
        .output();

    Ok(())
}

#[cfg(windows)]
pub fn inspect_windows_service() -> SupervisorState {
    let username = std::env::var("USERNAME").unwrap_or_else(|_| "user".to_string());
    let task_name = format!("VexaAgentControl-{}", username);

    // 1. Check Scheduled Task
    let ps_check = format!("$t = Get-ScheduledTask -TaskName '{}' -ErrorAction SilentlyContinue; if ($t) {{ Write-Output \"EXISTS:$($t.State)\" }} else {{ Write-Output 'NONE' }}", task_name);
    if let Ok(output) = std::process::Command::new("powershell")
        .args(&["-NoProfile", "-NonInteractive", "-Command", &ps_check])
        .output()
    {
        let res = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if res.starts_with("EXISTS:") {
            let state_str = res.trim_start_matches("EXISTS:").trim();
            let is_running = state_str.eq_ignore_ascii_case("Running");
            if is_running {
                return SupervisorState::Managed {
                    supervisor_type: "Windows Task Scheduler (User)".to_string(),
                    target_name: task_name,
                    active: true,
                    details: Some(format!("Task State: {}", state_str)),
                };
            }
        }
    }

    // 2. Check SCM Service
    if let Ok(output) = std::process::Command::new("sc.exe")
        .args(&["query", "AgentControlSentry"])
        .output()
    {
        let res = String::from_utf8_lossy(&output.stdout);
        if res.contains("STATE") {
            let is_running = res.contains("RUNNING");
            if is_running {
                return SupervisorState::Managed {
                    supervisor_type: "Windows SCM Service".to_string(),
                    target_name: "AgentControlSentry".to_string(),
                    active: true,
                    details: Some("State: RUNNING".to_string()),
                };
            }
        }
    }

    // 3. Check Windows User Logon Startup (HKCU\Run)
    if let Ok(output) = std::process::Command::new("powershell")
        .args(&["-NoProfile", "-NonInteractive", "-Command", "$r = Get-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'VexaAgentControl' -ErrorAction SilentlyContinue; if ($r) { Write-Output 'EXISTS' } else { Write-Output 'NONE' }"])
        .output()
    {
        let res = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if res == "EXISTS" {
            let proc_running = std::process::Command::new("powershell")
                .args(&["-NoProfile", "-NonInteractive", "-Command", "$p = Get-Process agentcontrol -ErrorAction SilentlyContinue; if ($p) { Write-Output \"PID:$($p.Id[0])\" } else { Write-Output 'NONE' }"])
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_default();

            let (is_running, pid_detail) = if proc_running.starts_with("PID:") {
                (true, Some(proc_running))
            } else {
                (false, Some("Not currently executing (starts on user logon)".to_string()))
            };

            return SupervisorState::Managed {
                supervisor_type: "Windows User Startup (HKCU\\Run)".to_string(),
                target_name: "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\VexaAgentControl".to_string(),
                active: is_running,
                details: pid_detail,
            };
        }
    }

    SupervisorState::NotInstalled
}

#[cfg(not(windows))]
pub fn install_windows_service(
    _bin_path: &str,
    _hub_url: &str,
    _gateway_secret: &str,
    _policy_read_secret: &str,
    _agent_id: Option<&str>,
    _enterprise: bool,
    _config_path: &Path,
    _quiet: bool,
) -> Result<(), String> {
    Err("Windows background agent installation is only supported on Windows OS.".to_string())
}

#[cfg(windows)]
pub fn uninstall_windows_service() -> Result<(), String> {
    let username = std::env::var("USERNAME").unwrap_or_else(|_| "user".to_string());
    let task_name = format!("VexaAgentControl-{}", username);

    // 1. Stop and Unregister Scheduled Tasks
    let ps_delete = format!(
        "Stop-ScheduledTask -TaskName '{}' -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName '{}' -Confirm:$false -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName 'VexaAgentControl' -Confirm:$false -ErrorAction SilentlyContinue",
        task_name, task_name
    );
    let _ = std::process::Command::new("powershell")
        .args(&["-NoProfile", "-NonInteractive", "-Command", &ps_delete])
        .output();

    // 2. Stop and delete SCM service if present
    let _ = std::process::Command::new("sc.exe")
        .args(&["stop", "AgentControlSentry"])
        .output();
    let _ = std::process::Command::new("sc.exe")
        .args(&["delete", "AgentControlSentry"])
        .output();

    // 3. Remove exact legacy HKCU\Run entry
    let _ = std::process::Command::new("powershell")
        .args(&["-NoProfile", "-NonInteractive", "-Command",
            "Remove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'VexaAgentControl' -ErrorAction SilentlyContinue"])
        .output();

    // 4. Scoped Process Termination: Stop other running agentcontrol.exe instances (excluding current uninstaller PID)
    let current_pid = std::process::id();
    let ps_kill = format!(
        "Get-Process agentcontrol -ErrorAction SilentlyContinue | Where-Object {{ $_.Id -ne {} }} | Stop-Process -Force -ErrorAction SilentlyContinue",
        current_pid
    );
    let _ = std::process::Command::new("powershell")
        .args(&["-NoProfile", "-NonInteractive", "-Command", &ps_kill])
        .output();

    println!(
        "{} Agent Control background task uninstalled cleanly.",
        "✔".green().bold()
    );
    Ok(())
}

#[cfg(windows)]
pub fn ensure_eventlog_registered() {
    let _ = std::process::Command::new("reg")
        .args(&[
            "add",
            r"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\AgentControlSentry",
            "/v",
            "EventMessageFile",
            "/t",
            "REG_EXPAND_SZ",
            "/d",
            r"%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\EventLogMessages.dll;%SystemRoot%\Microsoft.NET\Framework\v4.0.30319\EventLogMessages.dll",
            "/f",
        ])
        .output();
    let _ = std::process::Command::new("reg")
        .args(&[
            "add",
            r"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\AgentControlSentry",
            "/v",
            "TypesSupported",
            "/t",
            "REG_DWORD",
            "/d",
            "7",
            "/f",
        ])
        .output();
}

#[cfg(not(windows))]
pub fn ensure_eventlog_registered() {}

#[cfg(not(windows))]
pub fn uninstall_windows_service() -> Result<(), String> {
    Err("Windows SCM service uninstallation is only supported on Windows OS.".to_string())
}

#[cfg(windows)]
pub mod service_dispatcher_handler {
    use std::ffi::OsString;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;
    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    };

    define_windows_service!(ffi_service_main, my_service_main);

    static SHUTDOWN_FLAG: AtomicBool = AtomicBool::new(false);
    static SERVICE_RUNNER: std::sync::Mutex<Option<Box<dyn FnOnce() -> i32 + Send + 'static>>> =
        std::sync::Mutex::new(None);
    static EXIT_CODE: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

    pub fn is_shutdown_requested() -> bool {
        SHUTDOWN_FLAG.load(Ordering::Relaxed)
    }

    fn my_service_main(_arguments: Vec<OsString>) {
        let event_handler = move |control_event| -> ServiceControlHandlerResult {
            match control_event {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    SHUTDOWN_FLAG.store(true, Ordering::SeqCst);
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        };

        let status_handle =
            match service_control_handler::register("AgentControlSentry", event_handler) {
                Ok(handle) => handle,
                Err(_) => match service_control_handler::register("AgentWallSentry", event_handler)
                {
                    Ok(handle) => handle,
                    Err(_) => return,
                },
            };

        let _ = status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        });

        // Sync developer profile credentials to SYSTEM profile if missing
        let system_agentcontrol =
            std::path::PathBuf::from(r"C:\Windows\System32\config\systemprofile\.agentcontrol");
        if !system_agentcontrol.join("device_token").exists() {
            for profile in crate::service::windows_profiles::enumerate_user_profiles() {
                let user_agentcontrol = profile.join(".agentcontrol");
                if user_agentcontrol.join("device_token").exists() {
                    let _ = std::fs::create_dir_all(&system_agentcontrol);
                    if let Ok(entries) = std::fs::read_dir(&user_agentcontrol) {
                        for entry in entries.flatten() {
                            let path = entry.path();
                            if path.is_file() {
                                let dest = system_agentcontrol.join(entry.file_name());
                                let _ = std::fs::copy(&path, dest);
                            }
                        }
                    }
                    break;
                }
            }
        }

        // Auto-heal/register EventLog Application source in registry (runs as SYSTEM)
        super::ensure_eventlog_registered();

        crate::service::eventlog::log_info(
            2004,
            "AgentControlSentry Windows SCM service started and active.",
        );

        if let Ok(mut guard) = SERVICE_RUNNER.lock() {
            if let Some(runner) = guard.take() {
                let code = runner();
                EXIT_CODE.store(code, Ordering::SeqCst);
            }
        }

        crate::service::eventlog::log_info(
            2005,
            "AgentControlSentry Windows SCM service stopping.",
        );

        let _ = status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        });
    }

    pub fn try_register_scm_runner<F>(run_fn: F) -> bool
    where
        F: FnOnce() -> i32 + Send + 'static,
    {
        if let Ok(mut guard) = SERVICE_RUNNER.lock() {
            *guard = Some(Box::new(run_fn));
            true
        } else {
            false
        }
    }

    pub fn try_start_and_wait() -> Result<i32, windows_service::Error> {
        if let Err(_) = service_dispatcher::start("AgentControlSentry", ffi_service_main) {
            service_dispatcher::start("AgentWallSentry", ffi_service_main)?;
        }
        Ok(EXIT_CODE.load(Ordering::SeqCst))
    }

    pub fn start_and_wait() -> i32 {
        match try_start_and_wait() {
            Ok(code) => code,
            Err(_) => 1,
        }
    }

    pub fn run_service<F>(run_fn: F) -> Result<i32, windows_service::Error>
    where
        F: FnOnce() -> i32 + Send + 'static,
    {
        if let Ok(mut guard) = SERVICE_RUNNER.lock() {
            *guard = Some(Box::new(run_fn));
        }
        if let Err(_) = service_dispatcher::start("AgentControlSentry", ffi_service_main) {
            service_dispatcher::start("AgentWallSentry", ffi_service_main)?;
        }
        Ok(EXIT_CODE.load(Ordering::SeqCst))
    }
}

#[cfg(windows)]
pub fn run_as_windows_service_if_present<F>(run_fn: F) -> Option<i32>
where
    F: FnOnce() -> i32 + Send + 'static,
{
    match service_dispatcher_handler::run_service(run_fn) {
        Ok(code) => Some(code),
        Err(_) => None,
    }
}

#[cfg(not(windows))]
pub fn run_as_windows_service_if_present<F>(_run_fn: F) -> Option<i32>
where
    F: FnOnce() -> i32 + Send + 'static,
{
    None
}
