//! IDE wrapping and MCP server proxy interception management subsystem (FR-304).
//!
//! Intercepts MCP server configurations across supported AI IDEs (Claude Desktop, Cursor,
//! VS Code, JetBrains, Zed, Cline, OpenCode, Antigravity) to route tool execution through Agent Control.

pub mod backup;
pub mod claude;
pub mod config_path;
pub mod connect;
pub mod file_lock;
pub mod generic_ide;
pub mod ide_config;
pub mod journal;
pub mod manifest;
pub mod status;
pub mod transformer;
pub mod watch;

pub use connect::{ConnectMode, ConnectTarget, run_connect, run_disconnect};

use crate::cli::{UnwrapTarget, WatchTarget, WrapTarget};
use colored::*;

/// Errors from wrap/unwrap operations.
#[derive(Debug)]
pub enum WrapError {
    UnsupportedOs(String),
    ConfigNotFound(String),
    InvalidJson(String),
    Io(std::io::Error),
    AlreadyWrapped,
    NoBinaryPath(String),
    NoBackupFound,
    NoMcpServers,
}

impl std::fmt::Display for WrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedOs(os) => write!(f, "Unsupported OS: {}", os),
            Self::ConfigNotFound(p) => write!(f, "Config not found at {}.", p),
            Self::InvalidJson(e) => write!(f, "Config is not valid JSON: {}. Not modifying.", e),
            Self::Io(e) => write!(f, "I/O error: {}", e),
            Self::AlreadyWrapped => write!(
                f,
                "Already wrapped. Run unwrap first if you want to re-wrap."
            ),
            Self::NoBinaryPath(e) => write!(f, "Could not resolve agentwall binary path: {}", e),
            Self::NoBackupFound => write!(
                f,
                "No backup found. Use --force to see manual cleanup instructions."
            ),
            Self::NoMcpServers => write!(f, "No MCP servers found in config. Nothing to wrap."),
        }
    }
}

impl From<std::io::Error> for WrapError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Helper to strip comments (// and /* */) and trailing commas from JSONC (e.g. Zed / VS Code / Cursor configs)
pub fn strip_json_comments(input: &str) -> String {
    let mut cleaned = String::new();
    let mut in_string = false;
    let mut escaped = false;
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if in_string {
            if escaped {
                escaped = false;
            } else if chars[i] == '\\' {
                escaped = true;
            } else if chars[i] == '"' {
                in_string = false;
            }
            cleaned.push(chars[i]);
            i += 1;
        } else {
            if chars[i] == '"' {
                in_string = true;
                cleaned.push(chars[i]);
                i += 1;
            } else if i + 1 < chars.len() && chars[i] == '/' && chars[i + 1] == '/' {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            } else if i + 1 < chars.len() && chars[i] == '/' && chars[i + 1] == '*' {
                i += 2;
                while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                    i += 1;
                }
                i += 2;
            } else {
                cleaned.push(chars[i]);
                i += 1;
            }
        }
    }
    let mut res = String::new();
    let mut in_str = false;
    let mut esc = false;
    let clean_chars: Vec<char> = cleaned.chars().collect();
    let mut j = 0;
    while j < clean_chars.len() {
        if in_str {
            if esc {
                esc = false;
            } else if clean_chars[j] == '\\' {
                esc = true;
            } else if clean_chars[j] == '"' {
                in_str = false;
            }
            res.push(clean_chars[j]);
            j += 1;
        } else {
            if clean_chars[j] == '"' {
                in_str = true;
                res.push(clean_chars[j]);
                j += 1;
            } else if clean_chars[j] == ',' {
                let mut k = j + 1;
                while k < clean_chars.len() && clean_chars[k].is_whitespace() {
                    k += 1;
                }
                if k < clean_chars.len() && (clean_chars[k] == '}' || clean_chars[k] == ']') {
                    j += 1;
                } else {
                    res.push(clean_chars[j]);
                    j += 1;
                }
            } else {
                res.push(clean_chars[j]);
                j += 1;
            }
        }
    }
    res
}

/// Executes the `agentcontrol wrap` command for a specific IDE target.
///
/// # Arguments
/// * `target` - Target IDE configuration enum variant.
///
/// # Returns
/// Exit code: `0` on success, `2` on error.
pub fn run_wrap_target(target: &WrapTarget) -> i32 {
    let result = match target {
        WrapTarget::Claude {
            dry_run,
            scan_responses,
            block_on_secrets: _,
        } => claude::wrap_claude(*dry_run, *scan_responses).map(|r| claude::print_wrap_summary(&r)),
        WrapTarget::Cursor { dry_run } => config_path::cursor_config_path()
            .and_then(|p| generic_ide::wrap_generic("Cursor", p, *dry_run))
            .map(|r| generic_ide::print_wrap_summary_generic("Cursor", &r)),
        WrapTarget::Vscode { dry_run } => config_path::vscode_config_path()
            .and_then(|p| generic_ide::wrap_generic("VS Code", p, *dry_run))
            .map(|r| generic_ide::print_wrap_summary_generic("VS Code", &r)),
        WrapTarget::Jetbrains { dry_run } => config_path::jetbrains_config_path()
            .and_then(|p| generic_ide::wrap_generic("JetBrains", p, *dry_run))
            .map(|r| generic_ide::print_wrap_summary_generic("JetBrains", &r)),
        WrapTarget::Zed { dry_run } => config_path::zed_config_path()
            .and_then(|p| generic_ide::wrap_generic("Zed", p, *dry_run))
            .map(|r| generic_ide::print_wrap_summary_generic("Zed", &r)),
        WrapTarget::Cline { dry_run } => config_path::cline_config_path()
            .and_then(|p| generic_ide::wrap_generic("Cline", p, *dry_run))
            .map(|r| generic_ide::print_wrap_summary_generic("Cline", &r)),
        WrapTarget::Opencode { dry_run } => config_path::opencode_config_path()
            .and_then(|p| generic_ide::wrap_generic("OpenCode", p, *dry_run))
            .map(|r| generic_ide::print_wrap_summary_generic("OpenCode", &r)),
        WrapTarget::Antigravity { dry_run } => config_path::antigravity_config_path()
            .and_then(|p| generic_ide::wrap_generic("Antigravity", p, *dry_run))
            .map(|r| generic_ide::print_wrap_summary_generic("Antigravity", &r)),
        WrapTarget::Codex { dry_run } => config_path::codex_config_path()
            .and_then(|p| generic_ide::wrap_generic("Codex", p, *dry_run))
            .map(|r| generic_ide::print_wrap_summary_generic("Codex", &r)),
    };

    match result {
        Ok(_) => 0,
        Err(WrapError::ConfigNotFound(path)) => {
            // For single target commands, inform user.
            eprintln!("{} Config file not found: {}", "ℹ".blue(), path);
            1
        }
        Err(e) => {
            eprintln!("Error wrapping IDE: {}", e);
            2
        }
    }
}

/// Executes wrapping for all supported IDE targets.
pub fn run_wrap_all(dry_run: bool, scan_responses: bool) -> i32 {
    let targets = vec![
        (
            "Claude Desktop",
            WrapTarget::Claude {
                dry_run,
                scan_responses,
                block_on_secrets: false,
            },
        ),
        ("Cursor", WrapTarget::Cursor { dry_run }),
        ("Codex", WrapTarget::Codex { dry_run }),
        ("VS Code", WrapTarget::Vscode { dry_run }),
        ("JetBrains", WrapTarget::Jetbrains { dry_run }),
        ("Zed", WrapTarget::Zed { dry_run }),
        ("Cline", WrapTarget::Cline { dry_run }),
        ("OpenCode", WrapTarget::Opencode { dry_run }),
        ("Antigravity", WrapTarget::Antigravity { dry_run }),
    ];

    let mut wrapped_count = 0;
    let mut already_wrapped_count = 0;

    for (name, target) in targets {
        let path_opt = match name {
            "Claude Desktop" => config_path::claude_config_path().ok(),
            "Cursor" => config_path::cursor_config_path().ok(),
            "Codex" => config_path::codex_config_path().ok(),
            "VS Code" => config_path::vscode_config_path().ok(),
            "JetBrains" => config_path::jetbrains_config_path().ok(),
            "Zed" => config_path::zed_config_path().ok(),
            "Cline" => config_path::cline_config_path().ok(),
            "OpenCode" => config_path::opencode_config_path().ok(),
            "Antigravity" => config_path::antigravity_config_path().ok(),
            _ => None,
        };

        let res = match &target {
            WrapTarget::Claude {
                dry_run,
                scan_responses,
                ..
            } => claude::wrap_claude(*dry_run, *scan_responses),
            WrapTarget::Cursor { dry_run } => config_path::cursor_config_path()
                .and_then(|p| generic_ide::wrap_generic("Cursor", p, *dry_run)),
            WrapTarget::Codex { dry_run } => config_path::codex_config_path()
                .and_then(|p| generic_ide::wrap_generic("Codex", p, *dry_run)),
            WrapTarget::Vscode { dry_run } => config_path::vscode_config_path()
                .and_then(|p| generic_ide::wrap_generic("VS Code", p, *dry_run)),
            WrapTarget::Jetbrains { dry_run } => config_path::jetbrains_config_path()
                .and_then(|p| generic_ide::wrap_generic("JetBrains", p, *dry_run)),
            WrapTarget::Zed { dry_run } => config_path::zed_config_path()
                .and_then(|p| generic_ide::wrap_generic("Zed", p, *dry_run)),
            WrapTarget::Cline { dry_run } => config_path::cline_config_path()
                .and_then(|p| generic_ide::wrap_generic("Cline", p, *dry_run)),
            WrapTarget::Opencode { dry_run } => config_path::opencode_config_path()
                .and_then(|p| generic_ide::wrap_generic("OpenCode", p, *dry_run)),
            WrapTarget::Antigravity { dry_run } => config_path::antigravity_config_path()
                .and_then(|p| generic_ide::wrap_generic("Antigravity", p, *dry_run)),
        };

        let path_str = path_opt
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        match res {
            Ok(r) => {
                wrapped_count += 1;
                println!(
                    "    ↳ {:<16} {} [{}]",
                    name.bold(),
                    path_str.dimmed(),
                    if dry_run {
                        "READY TO WRAP".yellow().to_string()
                    } else {
                        format!("WRAPPED & PROTECTED ({})", r.servers_wrapped)
                            .green()
                            .bold()
                            .to_string()
                    }
                );
            }
            Err(WrapError::AlreadyWrapped) => {
                already_wrapped_count += 1;
                println!(
                    "    ↳ {:<16} {} [{}]",
                    name.bold(),
                    path_str.dimmed(),
                    "WRAPPED & PROTECTED".green().bold()
                );
            }
            Err(WrapError::NoMcpServers) => {
                println!(
                    "    ↳ {:<16} {} [{}]",
                    name.bold(),
                    path_str.dimmed(),
                    "NO MCP SERVERS CONFIGURED".dimmed()
                );
            }
            Err(WrapError::ConfigNotFound(_)) => {
                // Not installed on system
            }
            Err(e) => {
                eprintln!("  ✖ {}: {}", name.red(), e);
            }
        }
    }

    if wrapped_count == 0 && already_wrapped_count == 0 {
        println!();
        println!("  ℹ 0 clients wrapped. No supported AI IDE configurations with active MCP servers were detected.");
        println!("  ℹ To route custom agents or CLI tools through the gateway, set:");
        println!("    export AGENTCONTROL_PROXY_URL=http://127.0.0.1:18080");
        println!("    export HTTP_PROXY=http://127.0.0.1:18080");
    }
    0
}

/// Executes the `agentcontrol unwrap` command for a specific IDE target.
///
/// # Arguments
/// * `target` - Target IDE unwrap configuration enum variant.
///
/// # Returns
/// Exit code: `0` on success, `2` on error.
pub fn run_unwrap_target(target: &UnwrapTarget) -> i32 {
    let result = match target {
        UnwrapTarget::Claude { force } => {
            claude::unwrap_claude(*force).map(|r| claude::print_unwrap_summary(&r))
        }
        UnwrapTarget::Cursor { force } => config_path::cursor_config_path()
            .and_then(|p| generic_ide::unwrap_generic("Cursor", p, *force))
            .map(|r| generic_ide::print_unwrap_summary_generic("Cursor", &r)),
        UnwrapTarget::Vscode { force } => config_path::vscode_config_path()
            .and_then(|p| generic_ide::unwrap_generic("VS Code", p, *force))
            .map(|r| generic_ide::print_unwrap_summary_generic("VS Code", &r)),
        UnwrapTarget::Jetbrains { force } => config_path::jetbrains_config_path()
            .and_then(|p| generic_ide::unwrap_generic("JetBrains", p, *force))
            .map(|r| generic_ide::print_unwrap_summary_generic("JetBrains", &r)),
        UnwrapTarget::Zed { force } => config_path::zed_config_path()
            .and_then(|p| generic_ide::unwrap_generic("Zed", p, *force))
            .map(|r| generic_ide::print_unwrap_summary_generic("Zed", &r)),
        UnwrapTarget::Cline { force } => config_path::cline_config_path()
            .and_then(|p| generic_ide::unwrap_generic("Cline", p, *force))
            .map(|r| generic_ide::print_unwrap_summary_generic("Cline", &r)),
        UnwrapTarget::Opencode { force } => config_path::opencode_config_path()
            .and_then(|p| generic_ide::unwrap_generic("OpenCode", p, *force))
            .map(|r| generic_ide::print_unwrap_summary_generic("OpenCode", &r)),
        UnwrapTarget::Antigravity { force } => config_path::antigravity_config_path()
            .and_then(|p| generic_ide::unwrap_generic("Antigravity", p, *force))
            .map(|r| generic_ide::print_unwrap_summary_generic("Antigravity", &r)),
        UnwrapTarget::Codex { force } => config_path::codex_config_path()
            .and_then(|p| generic_ide::unwrap_generic("Codex", p, *force))
            .map(|r| generic_ide::print_unwrap_summary_generic("Codex", &r)),
    };

    match result {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("Error unwrapping IDE: {}", e);
            2
        }
    }
}

/// Run `agentcontrol status` — inspect targets, capability vectors, and traffic freshness.
pub fn run_status(json: bool) -> i32 {
    status::print_all_targets(json);
    0
}

/// Run `agentcontrol watch` — start the event-driven wrap daemon.
pub fn run_watch(all: bool, target: Option<WatchTarget>) -> i32 {
    watch::run_watch(all, target)
}

/// Executes `agentcontrol unprotect` — restores configurations across all supported IDE targets from manifests with backup fallback (FR-1.4).
pub fn run_unprotect_all(dry_run: bool, force: bool) -> i32 {
    println!(
        "{} Unprotecting all IDE configurations...",
        "●".cyan().bold()
    );
    if dry_run {
        println!(
            "  ℹ [DRY RUN] Previewing unprotect across all IDE targets (no disk modifications)."
        );
    }

    // 1. Recover from stale transaction journal if present
    let _ = journal::ProtectJournal::recover_if_stale();

    let mut disconnected_count = 0;
    let mut err_count = 0;

    // 2. Disconnect any manifest-managed targets (System B - primary)
    let manifests = manifest::OwnershipManifest::list_all().unwrap_or_default();
    let mut manifest_targets = std::collections::HashSet::new();

    for m in &manifests {
        manifest_targets.insert(m.target.clone());
        if let Some(target) = ConnectTarget::from_target_name(&m.target) {
            if dry_run {
                println!(
                    "  ℹ {}: Would revert managed keys from ownership manifest",
                    target.display_name().bold()
                );
                disconnected_count += 1;
            } else {
                let code = connect::run_disconnect(target);
                if code == 0 {
                    disconnected_count += 1;
                } else {
                    err_count += 1;
                }
            }
        } else {
            if dry_run {
                println!("  ℹ {}: Would revert manifest", m.target.bold());
                disconnected_count += 1;
            } else {
                let is_toml = m.config_path.extension().and_then(|e| e.to_str()) == Some("toml");
                let res = if is_toml {
                    connect::revert_toml_target(m)
                } else {
                    connect::revert_json_target(m)
                };
                match res {
                    Ok(keys) => {
                        let _ = manifest::OwnershipManifest::delete(&m.target);
                        println!(
                            "  ✔ {}: Reverted managed keys: {}",
                            m.target.bold(),
                            keys.join(", ").cyan()
                        );
                        disconnected_count += 1;
                    }
                    Err(e) => {
                        eprintln!("  ✖ {}: {}", m.target.red(), e);
                        err_count += 1;
                    }
                }
            }
        }
    }

    // 3. Fallback: Legacy .bak restore for any targets not covered by manifests (System A)
    let legacy_targets = vec![
        ("Claude Desktop", UnwrapTarget::Claude { force }),
        ("Cursor", UnwrapTarget::Cursor { force }),
        ("Codex", UnwrapTarget::Codex { force }),
        ("VS Code", UnwrapTarget::Vscode { force }),
        ("JetBrains", UnwrapTarget::Jetbrains { force }),
        ("Zed", UnwrapTarget::Zed { force }),
        ("Cline", UnwrapTarget::Cline { force }),
        ("OpenCode", UnwrapTarget::Opencode { force }),
        ("Antigravity", UnwrapTarget::Antigravity { force }),
    ];

    let mut legacy_restored = 0;
    for (name, target) in legacy_targets {
        let t_str = name.to_lowercase().replace(' ', "-");
        if manifest_targets.contains(&t_str) || manifest_targets.contains(&name.to_lowercase()) {
            continue;
        }

        let res = match &target {
            UnwrapTarget::Claude { force } => claude::unwrap_claude(*force),
            UnwrapTarget::Cursor { force } => config_path::cursor_config_path()
                .and_then(|p| generic_ide::unwrap_generic("Cursor", p, *force)),
            UnwrapTarget::Codex { force } => config_path::codex_config_path()
                .and_then(|p| generic_ide::unwrap_generic("Codex", p, *force)),
            UnwrapTarget::Vscode { force } => config_path::vscode_config_path()
                .and_then(|p| generic_ide::unwrap_generic("VS Code", p, *force)),
            UnwrapTarget::Jetbrains { force } => config_path::jetbrains_config_path()
                .and_then(|p| generic_ide::unwrap_generic("JetBrains", p, *force)),
            UnwrapTarget::Zed { force } => config_path::zed_config_path()
                .and_then(|p| generic_ide::unwrap_generic("Zed", p, *force)),
            UnwrapTarget::Cline { force } => config_path::cline_config_path()
                .and_then(|p| generic_ide::unwrap_generic("Cline", p, *force)),
            UnwrapTarget::Opencode { force } => config_path::opencode_config_path()
                .and_then(|p| generic_ide::unwrap_generic("OpenCode", p, *force)),
            UnwrapTarget::Antigravity { force } => config_path::antigravity_config_path()
                .and_then(|p| generic_ide::unwrap_generic("Antigravity", p, *force)),
        };

        match res {
            Ok(r) => {
                legacy_restored += 1;
                println!(
                    "  ✔ {}: Restored config from legacy backup {}",
                    name.bold(),
                    r.backup_path.display().to_string().cyan()
                );
            }
            Err(WrapError::NoBackupFound) | Err(WrapError::ConfigNotFound(_)) => {}
            Err(e) => {
                err_count += 1;
                eprintln!("  ✖ {}: {}", name.red(), e);
            }
        }
    }

    println!();
    println!(
        "✔ Disconnected: {}, Legacy Restored: {}, Errors: {}",
        disconnected_count.to_string().bold(),
        legacy_restored.to_string().cyan(),
        err_count.to_string().red()
    );
    if err_count > 0 {
        1
    } else {
        0
    }
}

/// Helper to open a URL in the user's default web browser across OS platforms and WSL environments.
pub fn open_browser(url: &str) -> std::io::Result<()> {
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("rundll32")
            .args(["url.dll,FileProtocolHandler", url])
            .spawn()?;
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open").arg(url).spawn()?;
    }
    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    {
        // Detect WSL environment
        if let Ok(version) = std::fs::read_to_string("/proc/version") {
            let v_lower = version.to_lowercase();
            if v_lower.contains("microsoft") || v_lower.contains("wsl") {
                if std::process::Command::new("wslview")
                    .arg(url)
                    .spawn()
                    .is_ok()
                {
                    return Ok(());
                }
                if std::process::Command::new("/mnt/c/Windows/System32/cmd.exe")
                    .args(["/c", "start", "", url])
                    .spawn()
                    .is_ok()
                {
                    return Ok(());
                }
            }
        }

        // Headless container check: if DISPLAY and WAYLAND_DISPLAY are empty, skip browser launch silently
        let is_headless =
            std::env::var("DISPLAY").is_err() && std::env::var("WAYLAND_DISPLAY").is_err();
        if is_headless {
            return Ok(());
        }

        std::process::Command::new("xdg-open").arg(url).spawn()?;
    }
    Ok(())
}

fn check_listener_available_or_running(listen: &str) -> Result<(), String> {
    match std::net::TcpListener::bind(listen) {
        Ok(listener) => {
            drop(listener);
            Ok(())
        }
        Err(e) => {
            if e.kind() == std::io::ErrorKind::AddrInUse {
                if let Ok(addr) = listen.parse::<std::net::SocketAddr>() {
                    if std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(500)).is_ok() {
                        return Ok(());
                    }
                }
                Err(format!(
                    "Port {} is already in use by another process that is not responding. Refusing to modify IDE configurations.",
                    listen
                ))
            } else {
                Err(format!(
                    "Cannot bind to {}: {}. Refusing to modify IDE configurations.",
                    listen, e
                ))
            }
        }
    }
}

/// Executes `agentcontrol protect` — Automated discovery, transactional wrapping, and gateway startup (FR-1.1, FR-1.2, FR-1.3).
pub fn run_protect_orchestration(
    dry_run: bool,
    no_browser: bool,
    listen: &str,
    _mcp_url: &str,
    enforce: bool,
    policy: &str,
) -> i32 {
    // Step 0: Check and recover from any stale uncommitted transaction
    if let Err(e) = journal::ProtectJournal::recover_if_stale() {
        eprintln!("\n  {} Failed to recover stale protect journal: {}", "✘".red().bold(), e);
        return 1;
    }

    // Step 1: Pre-flight check listener availability BEFORE touching any client configurations
    if !dry_run {
        if let Err(e) = check_listener_available_or_running(listen) {
            eprintln!("\n  {} Pre-flight check failed: {}", "✘".red().bold(), e);
            eprintln!("  Actionable fix: Free up the address or specify a different listener via --listen <IP:PORT>.");
            return 1;
        }
    }

    // Step 2: Ensure baseline policy exists and is valid BEFORE mutating client configurations
    let policy_path = std::path::Path::new(policy);
    if !policy_path.exists() {
        if !dry_run {
            let default_policy_str = crate::generate_policy::generate_default_baseline_policy();

            // Validate that generated policy compiles
            if let crate::policy::loader::PolicyLoadResult::Fatal { error } =
                crate::policy::loader::load_policy_from_str(&default_policy_str, None)
            {
                eprintln!(
                    "\n  {} Failed to compile baseline policy: {}",
                    "✘".red().bold(),
                    error
                );
                return 1;
            }

            // Ensure parent directory exists
            if let Some(parent) = policy_path.parent() {
                if !parent.as_os_str().is_empty() && !parent.exists() {
                    if let Err(e) = std::fs::create_dir_all(parent) {
                        eprintln!(
                            "\n  {} Failed to create policy directory {:?}: {}",
                            "✘".red().bold(),
                            parent,
                            e
                        );
                        return 1;
                    }
                }
            }

            // Atomic write: write to temp file then rename
            let tmp_path = policy_path.with_extension("tmp");
            if let Err(e) = std::fs::write(&tmp_path, default_policy_str.as_bytes()) {
                eprintln!(
                    "\n  {} Failed to write baseline policy to {:?}: {}",
                    "✘".red().bold(),
                    policy_path,
                    e
                );
                return 1;
            }
            if let Err(e) = std::fs::rename(&tmp_path, policy_path) {
                eprintln!(
                    "\n  {} Failed to atomically commit policy to {:?}: {}",
                    "✘".red().bold(),
                    policy_path,
                    e
                );
                let _ = std::fs::remove_file(&tmp_path);
                return 1;
            }
        }
    } else {
        // If policy exists, verify it can be read and parsed
        match std::fs::read_to_string(policy_path) {
            Ok(content) => {
                if let crate::policy::loader::PolicyLoadResult::Fatal { error } =
                    crate::policy::loader::load_policy_from_str(&content, None)
                {
                    eprintln!(
                        "\n  {} Existing policy at {:?} is invalid: {}",
                        "✘".red().bold(),
                        policy_path,
                        error
                    );
                    return 1;
                }
            }
            Err(e) => {
                eprintln!(
                    "\n  {} Failed to read existing policy at {:?}: {}",
                    "✘".red().bold(),
                    policy_path,
                    e
                );
                return 1;
            }
        }
    }

    // Step 3: Discover installed AI clients
    println!(
        "\n  {} Discovering and Protecting Workstation Clients:",
        "✔".green().bold()
    );

    let detected_targets: Vec<ConnectTarget> = connect::ALL_CONNECT_TARGETS
        .iter()
        .copied()
        .filter(|t| connect::is_target_installed(*t))
        .collect();

    if detected_targets.is_empty() {
        println!("    ℹ 0 supported AI clients detected on workstation.");
        println!("    ℹ Supported: Cursor, Claude Desktop, Claude Code (CLI), Codex, Antigravity, VS Code (Continue).");
        println!("    ℹ To route custom agents or CLI tools through the gateway, set:");
        println!("      export AGENTCONTROL_PROXY_URL=http://127.0.0.1:18080");
        println!("      export HTTP_PROXY=http://127.0.0.1:18080");
    } else if dry_run {
        for target in &detected_targets {
            let path = connect::get_target_config_path(*target)
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "unknown".to_string());
            println!("    ℹ [DRY RUN] Would protect {}: config at {}", target.display_name().bold(), path.cyan());
        }
    } else {
        let local_token = crate::identity::oauth::get_or_create_local_token()
            .unwrap_or_else(|_| "vx-local-session".to_string());
        let mut journal = journal::ProtectJournal::new("local-gateway");

        for target in &detected_targets {
            let config_path = match connect::get_target_config_path(*target) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("    ✖ {}: {}", target.display_name().red(), e);
                    continue;
                }
            };

            journal.record_target_start(target.as_str(), &config_path, target.as_str());
            if let Err(e) = journal.save() {
                eprintln!("    ✖ Failed to update protection journal: {}", e);
                eprintln!("    Aborting protection to ensure fail-closed integrity.");
                let _ = journal.rollback();
                return 1;
            }

            match connect::connect_target(*target, &local_token, connect::ConnectMode::Local) {
                Ok(res) => {
                    connect::print_connect_summary(*target, &res);
                    journal.record_target_success(target.as_str());
                    if let Err(e) = journal.save() {
                        eprintln!("    ✖ Failed to save protection journal progress: {}", e);
                    }
                }
                Err(e) => {
                    eprintln!(
                        "\n  {} Failed to configure {}: {}",
                        "✘".red().bold(),
                        target.display_name(),
                        e
                    );
                    eprintln!("  {} Rolling back all workstation modifications (fail-closed)...", "⚡".yellow());
                    match journal.rollback() {
                        Ok(reverted) => {
                            eprintln!("  ✔ Successfully rolled back: {}", reverted.join(", ").cyan());
                        }
                        Err(rb_err) => {
                            eprintln!("  ✖ Rollback error: {}", rb_err.red());
                        }
                    }
                    return 1;
                }
            }
        }

        // All targets configured successfully! Commit transaction by deleting the journal.
        let _ = journal.delete();
    }

    println!("\n  {} Gateway Runtime Status:", "📊".cyan().bold());
    println!(
        "    • Mode: {}",
        if enforce {
            "Active Enforcement (Default Deny / DLP / Injection Blocking)"
                .green()
                .bold()
        } else {
            "Observation / Shadow Mode (Audit Only)".yellow().bold()
        }
    );
    println!("    • Policy: {}", policy.cyan());
    println!(
        "    • Live Dashboard: {}",
        format!("http://{}", listen).cyan().underline()
    );
    println!(
        "    • Verification: Run '{}' in another terminal to perform live smoke tests",
        "agentcontrol verify".bold().cyan()
    );

    if dry_run {
        println!(
            "\n  {} Dry run completed. No files modified and gateway not started.\n",
            "ℹ".blue().bold()
        );
        return 0;
    }

    println!(
        "\n  {} Starting Local Security Gateway on {}...\n",
        "⚡".yellow().bold(),
        listen
    );

    if !no_browser {
        let dash_url = format!("http://{}", listen);
        let _ = open_browser(&dash_url);
    }

    0
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_json_comments_and_trailing_commas() {
        let raw = r#"// Zed settings
//
// Comment header
{
  /* Block comment */
  "context_servers": {
    "mcp-server-github": {
      "enabled": true,
      "remote": false,
      "settings": {
        "token": "secret//not-a-comment",
      },
    },
  },
  "theme": {
    "mode": "dark",
    "light": "One Light",
    "dark": "One Dark",
  },
}"#;
        let cleaned = strip_json_comments(raw);
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&cleaned);
        assert!(
            parsed.is_ok(),
            "Failed to parse stripped JSONC: {:?}",
            parsed.err()
        );
        let val = parsed.unwrap();
        assert_eq!(val["context_servers"]["mcp-server-github"]["enabled"], true);
        assert_eq!(
            val["context_servers"]["mcp-server-github"]["settings"]["token"],
            "secret//not-a-comment"
        );
        assert_eq!(val["theme"]["mode"], "dark");
    }
}
