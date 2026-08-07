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
    };

    match result {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("Error wrapping IDE: {}", e);
            2
        }
    }
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
