//! Windows Service Control Manager (SCM) Installer module.

#[cfg(windows)]
use colored::*;
#[cfg(windows)]
use std::os::windows::process::CommandExt;

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
pub fn install_windows_service(
    bin_path: &str,
    hub_url: &str,
    _gateway_secret: &str,
    _policy_read_secret: &str,
    agent_id: Option<&str>,
) -> Result<(), String> {
    let clean_hub_url = sanitize_url(hub_url);

    println!("  Registering per-user background agent via Task Scheduler...");

    // Per-user task name avoids conflicts with tasks created under a different elevation context
    let username = std::env::var("USERNAME").unwrap_or_else(|_| "user".to_string());
    let task_name = format!("VexaAgentControl-{}", username);

    // The schtasks /TR command cannot set environment variables directly.
    // Use cmd /C to set AGENTCONTROL_HUB_URL before launching so the daemon
    // knows which hub to connect to. Also sets AGENTCONTROL_LISTEN.
    let task_run_cmd = format!(
        "cmd /C \"set AGENTCONTROL_HUB_URL={} && \"{}\" start --listen 127.0.0.1:18080\"",
        clean_hub_url, bin_path
    );

    // Primary: use PowerShell Register-ScheduledTask (works for current user, no elevation needed).
    // We pass AGENTCONTROL_HUB_URL via the EnvironmentVariables setting instead of a fragile
    // cmd /C "set VAR=... && binary.exe" wrapper which breaks on paths that contain spaces.
    // Two triggers: AtLogOn (persistent) + AtStartup (fallback) so the task runs at next system boot.
    let bin_escaped = bin_path.replace('\'', "''"); // PowerShell single-quote escape
    let ps_register = format!(
        r#"$action = New-ScheduledTaskAction -Execute '{bin}' -Argument 'start --listen 127.0.0.1:18080'; $env_setting = New-ScheduledTaskSettingsSet -ExecutionTimeLimit 0 -MultipleInstances IgnoreNew -StartWhenAvailable; $trigger_logon = New-ScheduledTaskTrigger -AtLogOn; $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited; $task = New-ScheduledTask -Action $action -Trigger $trigger_logon -Settings $env_setting -Principal $principal; Register-ScheduledTask -TaskName '{task}' -InputObject $task -Force; $td = Get-ScheduledTask -TaskName '{task}'; $td.Triggers[0].Delay = 'PT0S'; Set-ScheduledTask -TaskName '{task}' -InputObject $td -ErrorAction SilentlyContinue; $env_path = [System.Environment]::ExpandEnvironmentVariables('%APPDATA%\Microsoft\Windows\Task Scheduler'); try {{ $xml = Export-ScheduledTask -TaskName '{task}'; $xml = $xml -replace '<EnvironmentVariables/>', '<EnvironmentVariables><EnvironmentVariable><Name>AGENTCONTROL_HUB_URL</Name><Value>{hub}</Value></EnvironmentVariable></EnvironmentVariables>'; Register-ScheduledTask -Xml $xml -TaskName '{task}' -Force }} catch {{ }}"#,
        bin = bin_escaped,
        task = task_name,
        hub = clean_hub_url,
    );

    let ps_output = std::process::Command::new("powershell")
        .args(&["-NoProfile", "-NonInteractive", "-Command", &ps_register])
        .output();

    let registered = match ps_output {
        Ok(ref out) if out.status.success() => {
            println!("  {} Task registered via PowerShell.", "✔".green());
            true
        }
        Ok(ref out) => {
            let err = String::from_utf8_lossy(&out.stderr);
            println!("  ⚠ PowerShell register failed ({}), falling back to schtasks...", err.trim().lines().next().unwrap_or(""));
            false
        }
        Err(ref e) => {
            println!("  ⚠ PowerShell not available ({}), falling back to schtasks...", e);
            false
        }
    };

    if !registered {
        // Fallback: schtasks /Create
        let create_output = std::process::Command::new("schtasks")
            .args(&[
                "/Create",
                "/TN", &task_name,
                "/TR", &task_run_cmd,
                "/SC", "ONLOGON",
                "/RL", "LIMITED",
                "/IT",
                "/F",
            ])
            .output()
            .map_err(|e| format!("failed to execute schtasks: {}", e))?;

        if !create_output.status.success() {
            let err = String::from_utf8_lossy(&create_output.stderr);
            println!(
                "  ⚠ Task Scheduler registration skipped ({}) — using HKCU\\Run logon persistence.",
                err.trim()
            );
        }
    }

    // ── Secondary persistence: HKCU\Run registry key ─────────────────────────────────────────
    // Ensures daemon launches at logon even when Task Scheduler denies immediate Start-ScheduledTask
    // (common when task was registered under a different elevation context).
    // No admin rights required; HKCU is always writable by the current user.
    let reg_run_value = format!("\"{}\" start --listen 127.0.0.1:18080", bin_path);
    let reg_ps = format!(
        "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'VexaAgentControl' -Value '{}' -Force",
        reg_run_value.replace('\'', "''")
    );
    let _ = std::process::Command::new("powershell")
        .args(&["-NoProfile", "-NonInteractive", "-Command", &reg_ps])
        .output();
    println!("  {} Logon persistence via HKCU\\Run registry key set.", "✔".green());

    // ── Immediate start: try Task Scheduler first, then spawn directly ────────────────────────
    let run_result = std::process::Command::new("powershell")
        .args(&["-NoProfile", "-NonInteractive", "-Command",
            &format!("Start-ScheduledTask -TaskName '{}'", task_name)])
        .output();

    if let Err(ref e) = run_result {
        println!("  {} schtasks /Run failed: {} — will start process directly", "⚠".yellow(), e);
    }

    // Wait briefly and verify the process actually started
    std::thread::sleep(std::time::Duration::from_millis(1500));

    let running = std::process::Command::new("tasklist")
        .args(&["/FI", "IMAGENAME eq agentcontrol.exe", "/NH", "/FO", "CSV"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("agentcontrol.exe"))
        .unwrap_or(false);

    if !running {
        // Fallback: spawn directly with DETACHED_PROCESS | CREATE_NO_WINDOW so the daemon
        // lives independently of the spawning parent shell (survives session boundary).
        println!("  {} Task did not start via scheduler — launching daemon directly...", "⚠".yellow());
        let spawn_result = std::process::Command::new(bin_path)
            .args(&["start", "--listen", "127.0.0.1:18080"])
            .env("AGENTCONTROL_HUB_URL", &clean_hub_url)
            .creation_flags(0x00000008 | 0x08000000) // DETACHED_PROCESS | CREATE_NO_WINDOW
            .spawn();

        match spawn_result {
            Ok(child) => println!(
                "  {} Daemon launched directly (PID: {})",
                "✔".green().bold(),
                child.id()
            ),
            Err(e) => println!("  {} Failed to launch daemon directly: {}", "✖".red(), e),
        }
    } else {
        println!("  {} Background daemon is running.", "✔".green().bold());
    }

    println!(
        "{} Agent Control per-user background agent installed successfully!",
        "✔".green().bold()
    );
    println!("  Task Name:          {}", task_name.cyan());
    println!("  Execution Level:    Standard User (/RL LIMITED, No Admin Elevation)");
    println!("  Hub URL:            {}", clean_hub_url.cyan());
    println!("  Listener Binding:   127.0.0.1:18080 (Loopback Only)");
    if let Some(id) = agent_id {
        println!("  Device Principal:   {}", id);
    }

    Ok(())
}

#[cfg(not(windows))]
pub fn install_windows_service(
    _bin_path: &str,
    _hub_url: &str,
    _gateway_secret: &str,
    _policy_read_secret: &str,
    _agent_id: Option<&str>,
) -> Result<(), String> {
    Err("Windows background agent installation is only supported on Windows OS.".to_string())
}

#[cfg(windows)]
pub fn uninstall_windows_service() -> Result<(), String> {
    let username = std::env::var("USERNAME").unwrap_or_else(|_| "user".to_string());
    let task_name = format!("VexaAgentControl-{}", username);

    // Primary: use PowerShell Unregister-ScheduledTask (works for current user without elevation)
    let ps_delete = format!("Unregister-ScheduledTask -TaskName '{}' -Confirm:$false -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName 'VexaAgentControl' -Confirm:$false -ErrorAction SilentlyContinue", task_name);
    let _ = std::process::Command::new("powershell")
        .args(&["-NoProfile", "-NonInteractive", "-Command", &ps_delete])
        .output();

    // Also terminate any running instance
    let _ = std::process::Command::new("powershell")
        .args(&["-NoProfile", "-NonInteractive", "-Command",
            "Get-Process agentcontrol -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue"])
        .output();

    // Fallback: schtasks /Delete
    let _ = std::process::Command::new("schtasks")
        .args(&["/End", "/TN", "VexaAgentControl"])
        .output();
    let _ = std::process::Command::new("schtasks")
        .args(&["/Delete", "/TN", "VexaAgentControl", "/F"])
        .output();

    // Clean up legacy SCM services if they were ever installed by admin
    use std::ffi::OsStr;
    use windows_service::{service::*, service_manager::*};

    if let Ok(manager) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT) {
        if let Ok(service) = manager.open_service(
            OsStr::new("AgentControlSentry"),
            ServiceAccess::STOP | ServiceAccess::DELETE,
        ) {
            let _ = service.stop();
            let _ = service.delete();
        }
        if let Ok(service) = manager.open_service(
            OsStr::new("AgentWallSentry"),
            ServiceAccess::STOP | ServiceAccess::DELETE,
        ) {
            let _ = service.stop();
            let _ = service.delete();
        }
    }

    // Remove HKCU\Run registry entry (secondary persistence added by install)
    let _ = std::process::Command::new("powershell")
        .args(&["-NoProfile", "-NonInteractive", "-Command",
            "Remove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'VexaAgentControl' -ErrorAction SilentlyContinue"])
        .output();

    println!(
        "{} Agent Control user background task uninstalled.",
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
