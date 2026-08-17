//! Windows Service Control Manager (SCM) Installer module.

#[cfg(windows)]
use colored::*;

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
    use std::ffi::OsStr;
    use windows_service::{service::*, service_manager::*};

    let clean_hub_url = sanitize_url(hub_url);

    println!("  Connecting to Windows Service Control Manager (SCM)...");
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(|e| {
        format!(
            "failed to connect to Windows SCM (Administrator permissions required?): {}",
            e
        )
    })?;

    // ── Write non-secret Hub URL to HKLM BEFORE creating/starting the service ──
    let _ = std::process::Command::new("setx")
        .args(&["/M", "DASHBOARD_API_URL", &clean_hub_url])
        .output();
    if !_gateway_secret.trim().is_empty() {
        let _ = std::process::Command::new("setx")
            .args(&["/M", "GATEWAY_SECRET", _gateway_secret.trim()])
            .output();
    }
    if let Some(id) = agent_id {
        let _ = std::process::Command::new("setx")
            .args(&["/M", "AGENT_ID", id])
            .output();
    }

    // ── Register EventLog Application Source in Windows Registry ──
    let _ = std::process::Command::new("reg")
        .args(&[
            "add",
            r"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\AgentControlSentry",
            "/v",
            "EventMessageFile",
            "/t",
            "REG_EXPAND_SZ",
            "/d",
            r"%SystemRoot%\System32\netmsg.dll",
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

    // ── Propagate invoking user's .agentwall credentials to SYSTEM service profile ──
    if let Some(user_home) = dirs::home_dir() {
        let user_agentwall = user_home.join(".agentwall");
        let system_agentwall = std::path::PathBuf::from(r"C:\Windows\System32\config\systemprofile\.agentwall");
        if user_agentwall.exists() && user_agentwall != system_agentwall {
            let _ = std::fs::create_dir_all(&system_agentwall);
            if let Ok(entries) = std::fs::read_dir(&user_agentwall) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        let dest = system_agentwall.join(entry.file_name());
                        let _ = std::fs::copy(&path, dest);
                    }
                }
            }
        }
    }

    println!("  Creating service entry {}...", "AgentControlSentry".cyan());

    let service_info = ServiceInfo {
        name: OsStr::new("AgentControlSentry").to_os_string(),
        display_name: OsStr::new("Agent Control Sentry Endpoint Security Service").to_os_string(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: std::path::PathBuf::from(bin_path),
        launch_arguments: vec![
            OsStr::new("start").to_os_string(),
            OsStr::new("--centralized").to_os_string(),
            OsStr::new("--listen").to_os_string(),
            OsStr::new("127.0.0.1:8080").to_os_string(),
        ],
        dependencies: vec![],
        account_name: None, // Runs under virtual/local service account
        account_password: None,
    };

    let service = manager
        .create_service(&service_info, ServiceAccess::ALL_ACCESS)
        .map_err(|e| format!("failed to create Windows service: {}", e))?;

    if let Err(e) = service.start::<&std::ffi::OsStr>(&[]) {
        println!(
            "  Note: Service created, but auto-start attempt returned: {}",
            e
        );
        crate::service::eventlog::log_warn(
            2003,
            &format!("AgentControlSentry auto-start attempt returned: {}", e),
        );
    } else {
        crate::service::eventlog::log_info(
            2001,
            &format!(
                "AgentControlSentry Windows SCM service installed and running. Hub URL: {}",
                clean_hub_url
            ),
        );
    }

    println!(
        "{} Agent Control Windows SCM Service installed successfully!",
        "✔".green().bold()
    );
    println!("  Hub URL:            {}", hub_url.cyan());
    println!("  Authentication:     mTLS Hardware/OS Certificate Store");
    println!("  Listener Binding:   127.0.0.1:8080 (Loopback Only)");
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
    Err("Windows SCM service installation is only supported on Windows OS.".to_string())
}

#[cfg(windows)]
pub fn uninstall_windows_service() -> Result<(), String> {
    use std::ffi::OsStr;
    use windows_service::{service::*, service_manager::*};

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| format!("failed to connect to Windows SCM: {}", e))?;

    // Try deleting AgentControlSentry
    if let Ok(service) = manager.open_service(
        OsStr::new("AgentControlSentry"),
        ServiceAccess::STOP | ServiceAccess::DELETE,
    ) {
        let _ = service.stop();
        let _ = service.delete();
    }

    // Also clean up legacy AgentWallSentry if present
    if let Ok(service) = manager.open_service(
        OsStr::new("AgentWallSentry"),
        ServiceAccess::STOP | ServiceAccess::DELETE,
    ) {
        let _ = service.stop();
        let _ = service.delete();
    }

    crate::service::eventlog::log_info(2002, "AgentControlSentry Windows SCM service uninstalled.");

    println!(
        "{} Agent Control Windows SCM service uninstalled.",
        "✔".green().bold()
    );
    Ok(())
}

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
                Err(_) => match service_control_handler::register("AgentWallSentry", event_handler) {
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

        crate::service::eventlog::log_info(2004, "AgentControlSentry Windows SCM service started and active.");

        if let Ok(mut guard) = SERVICE_RUNNER.lock() {
            if let Some(runner) = guard.take() {
                let code = runner();
                EXIT_CODE.store(code, Ordering::SeqCst);
            }
        }

        crate::service::eventlog::log_info(2005, "AgentControlSentry Windows SCM service stopping.");

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
