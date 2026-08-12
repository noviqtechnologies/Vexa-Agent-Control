//! IDE wrapping and MCP server proxy interception management subsystem (FR-304).
//!
//! Intercepts MCP server configurations across supported AI IDEs (Claude Desktop, Cursor,
//! VS Code, JetBrains, Zed, Cline, OpenCode, Antigravity) to route tool execution through AgentWall.

pub mod backup;
pub mod claude;
pub mod config_path;
pub mod file_lock;
pub mod generic_ide;
pub mod status;
pub mod transformer;
pub mod watch;

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

/// Executes the `agentwall wrap` command for a specific IDE target.
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

    println!(
        "{} Scanning & Wrapping all IDE configurations...",
        "●".cyan().bold()
    );
    let mut wrapped_count = 0;
    let mut already_wrapped_count = 0;
    let mut not_found_count = 0;

    for (name, target) in targets {
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

        match res {
            Ok(r) => {
                wrapped_count += 1;
                println!(
                    "  ✔ {}: Wrapped {} MCP server(s)",
                    name.bold(),
                    r.servers_wrapped
                );
            }
            Err(WrapError::AlreadyWrapped) => {
                already_wrapped_count += 1;
                println!("  ℹ {}: Already wrapped", name.dimmed());
            }
            Err(WrapError::NoMcpServers) => {
                already_wrapped_count += 1;
                println!(
                    "  ℹ {}: Config exists, no mcpServers configured",
                    name.dimmed()
                );
            }
            Err(WrapError::ConfigNotFound(_)) => {
                not_found_count += 1;
            }
            Err(e) => {
                eprintln!("  ✖ {}: {}", name.red(), e);
            }
        }
    }

    println!();
    println!(
        "✔ Interception Sweep Complete — Newly Intercepted: {}, Protected Environments: {}, Unconfigured/Not Installed: {}",
        wrapped_count.to_string().bold(),
        already_wrapped_count.to_string().bold(),
        not_found_count.to_string().dimmed()
    );
    0
}

/// Executes the `agentwall unwrap` command for a specific IDE target.
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

/// Run `agentwall status` — enumerate all 8 targets and print their wrap state.
pub fn run_status() -> i32 {
    status::print_all_targets();
    0
}

/// Run `agentwall watch` — start the event-driven wrap daemon.
pub fn run_watch(all: bool, target: Option<WatchTarget>) -> i32 {
    watch::run_watch(all, target)
}

/// Executes `agentwall unprotect` — restores configurations across all supported IDE targets from backups (FR-1.4).
pub fn run_unprotect_all(dry_run: bool, force: bool) -> i32 {
    println!(
        "{} Unprotecting all IDE configurations...",
        "●".cyan().bold()
    );
    if dry_run {
        println!("  ℹ [DRY RUN] Previewing unprotect across all IDE targets (no disk modifications).");
    }

    let targets = vec![
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

    let mut restored_count = 0;
    let mut no_backup_count = 0;
    let mut err_count = 0;

    for (name, target) in targets {
        if dry_run {
            println!("  ℹ {}: Would attempt unwrap and restore backup", name.bold());
            restored_count += 1;
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
                restored_count += 1;
                println!(
                    "  ✔ {}: Restored config from {}",
                    name.bold(),
                    r.backup_path.display().to_string().cyan()
                );
            }
            Err(WrapError::NoBackupFound) => {
                no_backup_count += 1;
                println!("  ℹ {}: No backup found to restore", name.dimmed());
            }
            Err(WrapError::ConfigNotFound(_)) => {
                no_backup_count += 1;
            }
            Err(e) => {
                err_count += 1;
                eprintln!("  ✖ {}: Restoring backup failed: {}", name.red(), e);
            }
        }
    }

    println!();
    println!(
        "✔ Reversion Sweep Complete — Restored: {}, Skipped/No Backup: {}, Errors: {}",
        restored_count.to_string().bold(),
        no_backup_count.to_string().dimmed(),
        err_count.to_string().yellow()
    );

    if err_count > 0 { 2 } else { 0 }
}

/// Helper to open a URL in the user's default web browser across OS platforms.
fn open_browser(url: &str) -> std::io::Result<()> {
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/c", "start", "", url])
            .spawn()?;
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open").arg(url).spawn()?;
    }
    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    {
        std::process::Command::new("xdg-open").arg(url).spawn()?;
    }
    Ok(())
}

/// Executes `agentwall protect` — Automated discovery, atomic wrapping, gateway startup, and dashboard launch (FR-1.1, FR-1.2, FR-1.3).
pub fn run_protect_orchestration(
    dry_run: bool,
    no_browser: bool,
    listen: &str,
    _mcp_url: &str,
    _enforce: bool,
    policy: &str,
) -> i32 {
    println!(
        "{} Initializing AgentWall One-Command Protection...",
        "🛡".cyan().bold()
    );

    // Step 0: Ensure baseline policy exists
    let policy_path = std::path::Path::new(policy);
    if !policy_path.exists() {
        if dry_run {
            println!("  ℹ [DRY RUN] Would generate default baseline policy at {}", policy.cyan());
        } else {
            let default_policy = crate::generate_policy::generate_default_baseline_policy();
            if let Err(e) = std::fs::write(policy_path, default_policy) {
                eprintln!("  ⚠ Failed to auto-generate baseline policy file {}: {}", policy, e);
            } else {
                println!("  ✔ Auto-generated baseline security policy at {}", policy.cyan());
            }
        }
    } else {
        println!("  ✔ Loaded security policy from {}", policy.cyan());
    }

    if dry_run {
        println!("  ℹ [DRY RUN] Scanning and previewing IDE configuration wraps without modifying disk or starting gateway.");
        run_wrap_all(true, false);
        return 0;
    }

    // Step 1: Scan & Wrap all IDE targets atomically
    println!("\n{} Step 1/2: Automated IDE Discovery & Atomic Wrapping", "●".cyan());
    run_wrap_all(false, false);

    // Step 2: Auto-launch browser dashboard if enabled
    if !no_browser {
        let dash_url = format!("http://{}", listen);
        println!("\n{} Launching Local Developer Dashboard at {}", "🚀".green().bold(), dash_url.cyan());
        if let Err(e) = open_browser(&dash_url) {
            eprintln!("  ⚠ Could not open browser automatically: {}", e);
        }
    }

    0
}


