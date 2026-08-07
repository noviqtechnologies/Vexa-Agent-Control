//! Windows Service Control Manager (SCM) Installer module.

#[cfg(windows)]
use colored::*;

#[cfg(windows)]
pub fn install_windows_service(
    bin_path: &str,
    hub_url: &str,
    gateway_secret: &str,
    policy_read_secret: &str,
) -> Result<(), String> {
    use std::ffi::OsStr;
    use windows_service::{
        service::*,
        service_manager::*,
    };

    println!("  Connecting to Windows Service Control Manager (SCM)...");
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    ).map_err(|e| format!("failed to connect to Windows SCM (Administrator permissions required?): {}", e))?;

    println!("  Creating service entry {}...", "AgentWallSentry".cyan());

    let service_info = ServiceInfo {
        name: OsStr::new("AgentWallSentry").to_os_string(),
        display_name: OsStr::new("AgentWall Sentry Endpoint Security Service").to_os_string(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: std::path::PathBuf::from(bin_path),
        launch_arguments: vec![
            OsStr::new("start").to_os_string(),
            OsStr::new("--centralized").to_os_string(),
        ],
        dependencies: vec![],
        account_name: None, // Runs under NT AUTHORITY\SYSTEM
        account_password: None,
    };

    let _service = manager.create_service(
        &service_info,
        ServiceAccess::ALL_ACCESS,
    ).map_err(|e| format!("failed to create Windows service: {}", e))?;

    println!("{} AgentWall Windows SCM Service installed successfully!", "✔".green().bold());
    println!("  To set persistent environment variables for System service:");
    println!("    setx /M DASHBOARD_API_URL \"{}\"", hub_url);
    println!("    setx /M GATEWAY_SECRET \"{}\"", gateway_secret);
    println!("    setx /M POLICY_READ_SECRET \"{}\"", policy_read_secret);

    Ok(())
}

#[cfg(not(windows))]
pub fn install_windows_service(
    _bin_path: &str,
    _hub_url: &str,
    _gateway_secret: &str,
    _policy_read_secret: &str,
) -> Result<(), String> {
    Err("Windows SCM service installation is only supported on Windows OS.".to_string())
}

#[cfg(windows)]
pub fn uninstall_windows_service() -> Result<(), String> {
    use std::ffi::OsStr;
    use windows_service::{
        service::*,
        service_manager::*,
    };

    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT,
    ).map_err(|e| format!("failed to connect to Windows SCM: {}", e))?;

    let service = manager.open_service(
        OsStr::new("AgentWallSentry"),
        ServiceAccess::STOP | ServiceAccess::DELETE,
    ).map_err(|e| format!("failed to open AgentWallSentry service: {}", e))?;

    let _ = service.stop();
    service.delete().map_err(|e| format!("failed to delete Windows service: {}", e))?;

    println!("{} AgentWall Windows SCM service uninstalled.", "✔".green().bold());
    Ok(())
}

#[cfg(not(windows))]
pub fn uninstall_windows_service() -> Result<(), String> {
    Err("Windows SCM service uninstallation is only supported on Windows OS.".to_string())
}
