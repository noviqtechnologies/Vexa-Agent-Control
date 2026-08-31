//! IDE wrapping and MCP server proxy interception management subsystem (FR-304).
//!
//! Intercepts MCP server configurations across supported AI IDEs (Claude Desktop, Cursor,
//! VS Code, JetBrains, Zed, Cline, OpenCode, Antigravity) to route tool execution through Agent Control.

pub mod backup;
pub mod claude;
pub mod config_path;
pub mod file_lock;
pub mod generic_ide;
pub mod ide_config;
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
                    if dry_run { "READY TO WRAP".yellow().to_string() } else { format!("WRAPPED & PROTECTED ({})", r.servers_wrapped).green().bold().to_string() }
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
        println!("    export AGENTCONTROL_PROXY_URL=http://127.0.0.1:8080");
        println!("    export HTTP_PROXY=http://127.0.0.1:8080");
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

/// Run `agentcontrol status` — enumerate all 8 targets and print their wrap state.
pub fn run_status() -> i32 {
    status::print_all_targets();
    0
}

/// Run `agentcontrol watch` — start the event-driven wrap daemon.
pub fn run_watch(all: bool, target: Option<WatchTarget>) -> i32 {
    watch::run_watch(all, target)
}

/// Executes `agentcontrol unprotect` — restores configurations across all supported IDE targets from backups (FR-1.4).
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
            }
            Err(WrapError::ConfigNotFound(_)) => {
                // Not installed, skip
            }
            Err(e) => {
                err_count += 1;
                eprintln!("  ✖ {}: {}", name.red(), e);
            }
        }
    }

    println!();
    println!(
        "✔ Restored: {}, No Backups Needed: {}, Errors: {}",
        restored_count.to_string().bold(),
        no_backup_count.to_string().dimmed(),
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
        // Detect WSL environment
        if let Ok(version) = std::fs::read_to_string("/proc/version") {
            let v_lower = version.to_lowercase();
            if v_lower.contains("microsoft") || v_lower.contains("wsl") {
                if std::process::Command::new("wslview").arg(url).spawn().is_ok() {
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
        let is_headless = std::env::var("DISPLAY").is_err() && std::env::var("WAYLAND_DISPLAY").is_err();
        if is_headless {
            return Ok(());
        }

        std::process::Command::new("xdg-open").arg(url).spawn()?;
    }
    Ok(())
}

/// Executes `agentcontrol protect` — Automated discovery, atomic wrapping, gateway startup, and dashboard launch (FR-1.1, FR-1.2, FR-1.3).
pub fn run_protect_orchestration(
    dry_run: bool,
    no_browser: bool,
    listen: &str,
    _mcp_url: &str,
    enforce: bool,
    policy: &str,
) -> i32 {
    // Step 0: Ensure baseline policy exists and is valid BEFORE mutating client configurations
    let policy_path = std::path::Path::new(policy);
    if !policy_path.exists() {
        if !dry_run {
            let default_policy_str = crate::generate_policy::generate_default_baseline_policy();
            
            // Validate that generated policy compiles
            if let crate::policy::loader::PolicyLoadResult::Fatal { error } =
                crate::policy::loader::load_policy_from_str(&default_policy_str, None)
            {
                eprintln!("\n  {} Failed to compile baseline policy: {}", "✘".red().bold(), error);
                return 1;
            }

            // Ensure parent directory exists
            if let Some(parent) = policy_path.parent() {
                if !parent.as_os_str().is_empty() && !parent.exists() {
                    if let Err(e) = std::fs::create_dir_all(parent) {
                        eprintln!("\n  {} Failed to create policy directory {:?}: {}", "✘".red().bold(), parent, e);
                        return 1;
                    }
                }
            }

            // Atomic write: write to temp file then rename
            let tmp_path = policy_path.with_extension("tmp");
            if let Err(e) = std::fs::write(&tmp_path, default_policy_str.as_bytes()) {
                eprintln!("\n  {} Failed to write baseline policy to {:?}: {}", "✘".red().bold(), policy_path, e);
                return 1;
            }
            if let Err(e) = std::fs::rename(&tmp_path, policy_path) {
                eprintln!("\n  {} Failed to atomically commit policy to {:?}: {}", "✘".red().bold(), policy_path, e);
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
                    eprintln!("\n  {} Existing policy at {:?} is invalid: {}", "✘".red().bold(), policy_path, error);
                    return 1;
                }
            }
            Err(e) => {
                eprintln!("\n  {} Failed to read existing policy at {:?}: {}", "✘".red().bold(), policy_path, e);
                return 1;
            }
        }
    }

    println!("\n  {} Discovered & Wrapped MCP Configurations:", "✔".green().bold());
    run_wrap_all(dry_run, false);

    // Initialize local Root CA for LLM interception
    if !dry_run {
        if let Ok(ca_mgr) = crate::ca::CaManager::init_or_load(None) {
            let ca_cert_path = ca_mgr.ca_dir.join("agentcontrol-ca.pem");
            if !crate::ca::is_ca_installed() {
                let _ = crate::ca::install_ca_to_trust_store(&ca_cert_path);
            }
            std::env::set_var("NODE_EXTRA_CA_CERTS", &ca_cert_path);
            #[cfg(target_os = "windows")]
            {
                let path_str = ca_cert_path.to_string_lossy().to_string();
                let _ = std::process::Command::new("powershell")
                    .args([
                        "-NoProfile",
                        "-Command",
                        &format!(
                            "[Environment]::SetEnvironmentVariable('NODE_EXTRA_CA_CERTS', '{}', 'User')",
                            path_str
                        ),
                    ])
                    .output();
            }
        }
    }

    println!("\n  {} Gateway Runtime Status:", "📊".cyan().bold());
    println!("    • Mode: {}", if enforce { "Active Enforcement (Default Deny / DLP / Injection Blocking)".green().bold() } else { "Observation / Shadow Mode (Audit Only)".yellow().bold() });
    println!("    • Policy: {}", policy.cyan());
    println!("    • Live Dashboard: {}", format!("http://{}", listen).cyan().underline());
    println!("    • Verification: Run '{}' in another terminal to perform live smoke tests", "agentcontrol verify".bold().cyan());

    if dry_run {
        println!("\n  {} Dry run completed. No files modified and gateway not started.\n", "ℹ".blue().bold());
        return 0;
    }

    println!("\n  {} Starting Local Security Gateway on {}...\n", "⚡".yellow().bold(), listen);

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
        assert!(parsed.is_ok(), "Failed to parse stripped JSONC: {:?}", parsed.err());
        let val = parsed.unwrap();
        assert_eq!(val["context_servers"]["mcp-server-github"]["enabled"], true);
        assert_eq!(val["context_servers"]["mcp-server-github"]["settings"]["token"], "secret//not-a-comment");
        assert_eq!(val["theme"]["mode"], "dark");
    }
}


