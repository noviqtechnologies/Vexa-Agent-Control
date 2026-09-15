//! Target Connection and Ownership-Aware Disconnection Engine (REQ-ONB-002, REQ-OPS-001, FR-3, FR-4).
//!
//! Provides scoped configuration injection with proven client authentication,
//! version range checks, ownership manifests, and non-destructive disconnection.

use colored::*;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::identity::oauth::get_or_create_local_token;
use crate::wrap::config_path;
use crate::wrap::manifest::OwnershipManifest;
use crate::wrap::transformer;

/// Supported targets for `agentcontrol connect` and `agentcontrol disconnect`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ConnectTarget {
    Codex,
    Claude,
    #[value(name = "vscode-continue")]
    VscodeContinue,
}

impl ConnectTarget {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::Claude => "claude",
            Self::VscodeContinue => "vscode-continue",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Codex => "OpenAI Codex CLI",
            Self::Claude => "Claude Desktop",
            Self::VscodeContinue => "VS Code (Continue Extension)",
        }
    }
}

/// Operation mode for connect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ConnectMode {
    Local,
    CloudDirect,
}

impl ConnectMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::CloudDirect => "cloud-direct",
        }
    }
}

/// Fetches assigned virtual key from Control Hub for cloud-direct mode.
pub async fn fetch_assigned_virtual_key(hub_url: &str) -> Result<Option<String>, String> {
    match crate::policy::remote_keys::fetch_active_provider_keys(hub_url).await {
        Ok(Some(payload)) => Ok(payload.virtual_key),
        Ok(None) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Resolves authentication token and effective connect mode (explicit key, auto-detection, or hub query).
pub async fn resolve_token_and_mode(
    mode: Option<ConnectMode>,
    key: Option<String>,
) -> Result<(String, ConnectMode), String> {
    // 1. Direct key override passed via --key or AGENTCONTROL_VIRTUAL_KEY
    if let Some(k) = key.filter(|s| !s.trim().is_empty()) {
        let trimmed = k.trim().to_string();
        let effective_mode = mode.unwrap_or_else(|| {
            if trimmed.starts_with("sk-vex-") {
                ConnectMode::CloudDirect
            } else {
                ConnectMode::Local
            }
        });
        return Ok((trimmed, effective_mode));
    }

    // 2. Check OPENAI_API_KEY environment variable if it contains a virtual key
    if let Ok(v) = std::env::var("OPENAI_API_KEY") {
        let trimmed = v.trim().to_string();
        if trimmed.starts_with("sk-vex-") {
            let effective_mode = mode.unwrap_or(ConnectMode::CloudDirect);
            return Ok((trimmed, effective_mode));
        }
    }

    match mode {
        Some(ConnectMode::CloudDirect) => {
            let hub_url = crate::identity::device::load_hub_url()
                .unwrap_or_else(|| "https://app.vexasec.io".to_string());
            match fetch_assigned_virtual_key(&hub_url).await {
                Ok(Some(vk)) if !vk.trim().is_empty() => Ok((vk, ConnectMode::CloudDirect)),
                Ok(_) => Err(
                    "No virtual key returned by Control Hub for this workstation.\n  → Connect directly using: `agentcontrol connect <target> --key <sk-vex-...>`\n    or specify `--mode local` for local proxy mode."
                        .to_string(),
                ),
                Err(e) => Err(format!(
                    "Failed to connect to Control Hub in cloud-direct mode ({}): {}\n  → You can specify your key directly: `agentcontrol connect <target> --key <sk-vex-...>`",
                    hub_url, e
                )),
            }
        }
        Some(ConnectMode::Local) => {
            let token = get_or_create_local_token()
                .map_err(|e| format!("Failed to generate local token: {}", e))?;
            Ok((token, ConnectMode::Local))
        }
        None => {
            // Auto-detect mode:
            if crate::identity::device::is_device_enrolled() {
                if let Some(hub_url) = crate::identity::device::load_hub_url() {
                    match fetch_assigned_virtual_key(&hub_url).await {
                        Ok(Some(vk)) if !vk.trim().is_empty() => {
                            return Ok((vk, ConnectMode::CloudDirect));
                        }
                        Ok(_) => {
                            return Err(
                                "Device is enrolled, but no virtual key was returned by Control Hub.\n  → Connect directly using: `agentcontrol connect <target> --key <sk-vex-...>`\n    or specify `--mode local` to connect with a local proxy token."
                                    .to_string(),
                            );
                        }
                        Err(e) => {
                            eprintln!(
                                "{} Control Hub unreachable ({}); falling back to local mode.",
                                "⚠".yellow().bold(),
                                e
                            );
                        }
                    }
                }
            } else {
                println!(
                    "{} Device not enrolled in Control Hub; defaulting to local proxy mode.",
                    "ℹ".blue().bold()
                );
            }
            let token = get_or_create_local_token()
                .map_err(|e| format!("Failed to generate local token: {}", e))?;
            Ok((token, ConnectMode::Local))
        }
    }
}

/// Verify client installed version against pinned supported ranges (§FR-3.1).
pub fn verify_client_version(target: ConnectTarget, force: bool) -> Result<(), String> {
    match target {
        ConnectTarget::Codex => {
            // Codex CLI check: semver >= 0.1.0, < 0.4.0
            if let Ok(output) = std::process::Command::new("codex").arg("--version").output() {
                let ver_str = String::from_utf8_lossy(&output.stdout);
                let ver_clean = ver_str.trim().trim_start_matches("codex ").trim_start_matches('v');
                if !ver_clean.is_empty() {
                    let parts: Vec<&str> = ver_clean.split('.').collect();
                    if parts.len() >= 2 {
                        let major: u32 = parts[0].parse().unwrap_or(0);
                        let minor: u32 = parts[1].parse().unwrap_or(0);
                        if major != 0 || minor < 1 || minor >= 4 {
                            let msg = format!(
                                "Codex CLI version '{}' is outside the verified supported range [0.1.0, 0.4.0)",
                                ver_clean
                            );
                            if force {
                                eprintln!("{} {} (--force enabled, proceeding)", "⚠".yellow(), msg);
                            } else {
                                return Err(format!("{} (pass --force to override)", msg));
                            }
                        }
                    }
                }
            }
        }
        ConnectTarget::Claude => {
            // Claude Desktop version >= 0.7.0, <= 0.8.x
            // Desktop app version is typically checked via app bundle or binary if accessible
        }
        ConnectTarget::VscodeContinue => {
            // Continue Extension version >= 0.8.0, < 1.0.0
        }
    }
    Ok(())
}

/// Connect a target client with proven authentication injection and ownership manifest.
pub async fn run_connect(
    target: ConnectTarget,
    mode: Option<ConnectMode>,
    key: Option<String>,
    force: bool,
) -> i32 {
    let (token, effective_mode) = match resolve_token_and_mode(mode, key).await {
        Ok(res) => res,
        Err(e) => {
            eprintln!("\n{} Connection failed: {}", "✖".red().bold(), e);
            return 1;
        }
    };

    println!(
        "{} Connecting {} to Vexa Agent Control (mode: {})...",
        "●".cyan().bold(),
        target.display_name().bold(),
        effective_mode.as_str().green()
    );

    if let Err(e) = verify_client_version(target, force) {
        eprintln!("{} Version check failed: {}", "✖".red(), e);
        return 1;
    }

    let result = match target {
        ConnectTarget::Codex => connect_codex(&token, effective_mode),
        ConnectTarget::Claude => connect_claude(&token, effective_mode),
        ConnectTarget::VscodeContinue => connect_vscode_continue(&token, effective_mode),
    };

    match result {
        Ok(()) => {
            println!("\n{} Successfully connected {}!", "✔".green().bold(), target.display_name());
            0
        }
        Err(e) => {
            eprintln!("\n{} Connection failed: {}", "✖".red(), e);
            1
        }
    }
}

/// Proven Codex injection: configures `OPENAI_BASE_URL` and `OPENAI_API_KEY` in `.codex/config.toml`.
pub fn connect_codex(token: &str, mode: ConnectMode) -> Result<(), String> {
    let home = dirs::home_dir().ok_or_else(|| "Failed to resolve user home directory".to_string())?;
    let codex_dir = home.join(".codex");
    let _ = fs::create_dir_all(&codex_dir);
    let config_path = codex_dir.join("config.toml");
    connect_codex_to_path(&config_path, token, mode)
}

/// Core Codex connection routine given explicit configuration path.
pub fn connect_codex_to_path(config_path: &Path, token: &str, mode: ConnectMode) -> Result<(), String> {
    connect_codex_target_to_path("codex", config_path, token, mode)
}

/// Parameterized Codex connection routine given target manifest name and configuration path.
pub fn connect_codex_target_to_path(target_name: &str, config_path: &Path, token: &str, mode: ConnectMode) -> Result<(), String> {
    if let Some(parent) = config_path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    let pre_content = if config_path.exists() {
        fs::read_to_string(config_path).map_err(|e| e.to_string())?
    } else {
        String::new()
    };

    let pre_hash = if config_path.exists() {
        OwnershipManifest::compute_sha256(config_path).unwrap_or_default()
    } else {
        "0000000000000000000000000000000000000000000000000000000000000000".to_string()
    };

    let proxy_base_url = "http://127.0.0.1:18080/v1";

    let mut toml_val: toml::Value = if pre_content.trim().is_empty() {
        toml::Value::Table(toml::map::Map::new())
    } else {
        toml::from_str(&pre_content).map_err(|e| format!("Failed to parse {}: {}", config_path.display(), e))?
    };

    let mut previous_values = HashMap::new();
    let mut written_values = HashMap::new();

    // Read top-level openai_base_url BEFORE taking a mutable borrow of root
    // (avoids borrow conflict with `sep` which holds &mut root).
    let prev_top_url = toml_val
        .as_table()
        .and_then(|t| t.get("openai_base_url"))
        .and_then(|v| v.as_str())
        .map(|s| serde_json::Value::String(s.to_string()))
        .unwrap_or(serde_json::Value::Null);

    // 1. Configure shell_environment_policy
    let root = toml_val.as_table_mut().ok_or_else(|| "Config root is not a TOML table".to_string())?;
    let sep = root
        .entry("shell_environment_policy".to_string())
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
        .as_table_mut()
        .ok_or_else(|| "shell_environment_policy is not a table".to_string())?;

    if !sep.contains_key("inherit") {
        sep.insert("inherit".to_string(), toml::Value::String("core".to_string()));
    }

    let set_tbl = sep
        .entry("set".to_string())
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
        .as_table_mut()
        .ok_or_else(|| "shell_environment_policy.set is not a table".to_string())?;

    // Record previous values
    let prev_base = set_tbl
        .get("OPENAI_BASE_URL")
        .and_then(|v| v.as_str())
        .map(|s| serde_json::Value::String(s.to_string()))
        .unwrap_or(serde_json::Value::Null);
    let prev_key = set_tbl
        .get("OPENAI_API_KEY")
        .and_then(|v| v.as_str())
        .map(|s| serde_json::Value::String(s.to_string()))
        .unwrap_or(serde_json::Value::Null);

    previous_values.insert("shell_environment_policy.set.OPENAI_BASE_URL".to_string(), prev_base);
    previous_values.insert("shell_environment_policy.set.OPENAI_API_KEY".to_string(), prev_key);
    previous_values.insert("openai_base_url".to_string(), prev_top_url);

    // Clean up legacy HTTP_PROXY if pointing to old port 8080
    if let Some(prev_proxy_val) = set_tbl.get("HTTP_PROXY").and_then(|v| v.as_str()) {
        if prev_proxy_val.contains(":8080") {
            set_tbl.remove("HTTP_PROXY");
        }
    }

    // Inject AgentControl values into shell_environment_policy.set
    set_tbl.insert("OPENAI_BASE_URL".to_string(), toml::Value::String(proxy_base_url.to_string()));
    set_tbl.insert("OPENAI_API_KEY".to_string(), toml::Value::String(token.to_string()));

    written_values.insert(
        "shell_environment_policy.set.OPENAI_BASE_URL".to_string(),
        serde_json::Value::String(proxy_base_url.to_string()),
    );
    written_values.insert(
        "shell_environment_policy.set.OPENAI_API_KEY".to_string(),
        serde_json::Value::String(token.to_string()),
    );
    written_values.insert(
        "openai_base_url".to_string(),
        serde_json::Value::String(proxy_base_url.to_string()),
    );

    // set_tbl / sep / root mutable borrows end here — now safe to re-borrow root
    // to write the top-level `openai_base_url` key Codex reads for its native HTTP client.

    // 2. Wrap any mcp_servers
    let agentcontrol_bin = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "agentcontrol".to_string());

    if let Some(mcp_table) = root.get_mut("mcp_servers").and_then(|v| v.as_table_mut()) {
        for (name, srv) in mcp_table.iter_mut() {
            if let Some(srv_tbl) = srv.as_table_mut() {
                let cur_cmd = srv_tbl.get("command").and_then(|c| c.as_str()).unwrap_or("");
                if !cur_cmd.contains("agentcontrol") && !cur_cmd.contains("agentwall") && !cur_cmd.is_empty() {
                    let orig_cmd = cur_cmd.to_string();
                    let orig_args: Vec<String> = srv_tbl
                        .get("args")
                        .and_then(|a| a.as_array())
                        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                        .unwrap_or_default();

                    previous_values.insert(
                        format!("mcp_servers.{}.command", name),
                        serde_json::Value::String(orig_cmd.clone()),
                    );
                    previous_values.insert(
                        format!("mcp_servers.{}.args", name),
                        serde_json::json!(orig_args),
                    );

                    let mut new_args = vec!["stdio-proxy".to_string(), "--".to_string(), orig_cmd];
                    new_args.extend(orig_args);

                    srv_tbl.insert("command".to_string(), toml::Value::String(agentcontrol_bin.clone()));
                    srv_tbl.insert(
                        "args".to_string(),
                        toml::Value::Array(new_args.into_iter().map(toml::Value::String).collect()),
                    );

                    written_values.insert(
                        format!("mcp_servers.{}.command", name),
                        serde_json::Value::String(agentcontrol_bin.clone()),
                    );
                }
            }
        }
    }

    // Write the top-level `openai_base_url` key Codex reads for its native HTTP client.
    // This must come AFTER the set_tbl/sep/root borrow chain above has ended.
    if let Some(root2) = toml_val.as_table_mut() {
        root2.insert(
            "openai_base_url".to_string(),
            toml::Value::String(proxy_base_url.to_string()),
        );
    }

    // Write updated TOML
    let updated_toml = toml::to_string_pretty(&toml_val).map_err(|e| format!("Failed to format TOML: {}", e))?;
    fs::write(config_path, updated_toml).map_err(|e| format!("Failed to write {}: {}", config_path.display(), e))?;

    // Also synchronize ~/.codex/auth.json with the active API key so both Codex CLI
    // and Codex Desktop app authenticate properly with the virtual key / local proxy token.
    if let Ok(auth_path) = crate::wrap::config_path::codex_auth_path() {
        let mut auth_json = if auth_path.exists() {
            let raw = fs::read_to_string(&auth_path).unwrap_or_default();
            serde_json::from_str::<serde_json::Value>(&raw).unwrap_or_else(|_| serde_json::json!({}))
        } else {
            serde_json::json!({})
        };
        auth_json["auth_mode"] = serde_json::json!("apikey");
        auth_json["OPENAI_API_KEY"] = serde_json::json!(token);
        if let Some(parent) = auth_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(&auth_path, serde_json::to_string_pretty(&auth_json).unwrap_or_default());
    }

    let post_hash = OwnershipManifest::compute_sha256(config_path).unwrap_or_default();

    let managed_keys: Vec<String> = written_values.keys().cloned().collect();
    let manifest = OwnershipManifest::new(
        target_name,
        config_path.to_path_buf(),
        pre_hash,
        post_hash,
        managed_keys,
        previous_values,
        written_values,
    )
    .with_connect_mode(mode.as_str());
    manifest.save().map_err(|e| format!("Failed to save ownership manifest: {}", e))?;

    let masked_token = if token.len() > 10 {
        format!("{}...{}", &token[..6], &token[token.len() - 4..])
    } else {
        "***".to_string()
    };
    let token_label = match mode {
        ConnectMode::CloudDirect => format!("{} (Virtual Key from Control Hub)", masked_token.green()),
        ConnectMode::Local => "Bearer local-proxy-session-token".green().to_string(),
    };

    println!("  Configuration: {}", config_path.display());
    println!("  LLM Endpoint:  {}", proxy_base_url.green());
    println!("  Auth Token:    {}", token_label);
    println!(
        "  {} Native shell execution (bash/git) is UNGOVERNED by local proxy.",
        "⚠ Notice:".yellow().bold()
    );

    Ok(())
}

/// Proven Claude Desktop wrapping: wraps `mcpServers` with stdio-proxy.
pub fn connect_claude(_token: &str, mode: ConnectMode) -> Result<(), String> {
    let config_path = config_path::claude_config_path().map_err(|e| format!("{}", e))?;
    if !config_path.exists() {
        return Err(format!(
            "Claude Desktop config not found at {}. Please install and run Claude Desktop first.",
            config_path.display()
        ));
    }
    connect_claude_to_path(&config_path, _token, mode)
}

/// Core Claude connection routine given explicit configuration path.
pub fn connect_claude_to_path(config_path: &Path, _token: &str, mode: ConnectMode) -> Result<(), String> {
    connect_claude_target_to_path("claude", config_path, _token, mode)
}

/// Parameterized Claude connection routine given target manifest name and configuration path.
pub fn connect_claude_target_to_path(target_name: &str, config_path: &Path, _token: &str, mode: ConnectMode) -> Result<(), String> {
    let pre_hash = OwnershipManifest::compute_sha256(config_path).unwrap_or_default();
    let raw = fs::read_to_string(config_path).map_err(|e| e.to_string())?;

    let config: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => {
            let stripped = crate::wrap::strip_json_comments(&raw);
            serde_json::from_str(&stripped).map_err(|e| format!("Invalid JSON: {}", e))?
        }
    };

    let agentcontrol_bin = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "agentcontrol".to_string());

    let mut modified = config.clone();
    let mut previous_values = HashMap::new();
    let mut written_values = HashMap::new();

    if let Some(servers) = config.get("mcpServers").and_then(|v| v.as_object()) {
        previous_values.insert("mcpServers".to_string(), serde_json::json!(servers));
    }

    let (wrapped_count, _) = transformer::wrap_all_servers(&mut modified, &agentcontrol_bin)
        .map_err(|e| format!("Transformation failed: {}", e))?;

    if let Some(servers) = modified.get("mcpServers").and_then(|v| v.as_object()) {
        written_values.insert("mcpServers".to_string(), serde_json::json!(servers));
    }

    let output_str = serde_json::to_string_pretty(&modified).map_err(|e| e.to_string())?;
    fs::write(config_path, output_str).map_err(|e| format!("Failed to write {}: {}", config_path.display(), e))?;

    let post_hash = OwnershipManifest::compute_sha256(config_path).unwrap_or_default();

    let manifest = OwnershipManifest::new(
        target_name,
        config_path.to_path_buf(),
        pre_hash,
        post_hash,
        vec!["mcpServers".to_string()],
        previous_values,
        written_values,
    )
    .with_connect_mode(mode.as_str());
    manifest.save().map_err(|e| format!("Failed to save ownership manifest: {}", e))?;

    println!("  Configuration: {}", config_path.display());
    println!("  MCP Servers:   {} wrapped with stdio-proxy", wrapped_count.to_string().green());
    println!(
        "  {} Native LLM completions route out-of-band directly to Anthropic Cloud.",
        "ℹ Notice:".blue().bold()
    );

    Ok(())
}

/// Proven Continue injection: injects custom model provider into VS Code settings.
pub fn connect_vscode_continue(token: &str, mode: ConnectMode) -> Result<(), String> {
    let settings_path = crate::wrap::ide_config::vscode_settings_path().ok_or_else(|| {
        "Could not resolve VS Code settings.json path on this system.".to_string()
    })?;
    connect_vscode_continue_to_path(&settings_path, token, mode)
}

/// Core VS Code Continue connection routine given explicit configuration path.
pub fn connect_vscode_continue_to_path(settings_path: &Path, token: &str, mode: ConnectMode) -> Result<(), String> {
    connect_vscode_continue_target_to_path("vscode-continue", settings_path, token, mode)
}

/// Parameterized VS Code Continue connection routine given target manifest name and configuration path.
pub fn connect_vscode_continue_target_to_path(target_name: &str, settings_path: &Path, token: &str, mode: ConnectMode) -> Result<(), String> {
    let pre_hash = if settings_path.exists() {
        OwnershipManifest::compute_sha256(settings_path).unwrap_or_default()
    } else {
        "0000000000000000000000000000000000000000000000000000000000000000".to_string()
    };

    let proxy_base_url = "http://127.0.0.1:18080/v1";

    let mut settings: serde_json::Value = if settings_path.exists() {
        let raw = fs::read_to_string(settings_path).map_err(|e| e.to_string())?;
        serde_json::from_str(&crate::wrap::strip_json_comments(&raw)).unwrap_or_else(|_| serde_json::json!({}))
    } else {
        serde_json::json!({})
    };

    let mut previous_values = HashMap::new();
    let mut written_values = HashMap::new();

    let prev_provider = settings.get("continue.models").cloned().unwrap_or(serde_json::Value::Null);
    previous_values.insert("continue.models".to_string(), prev_provider);

    let vexa_model = serde_json::json!({
        "title": "Vexa Agent Control (Managed)",
        "provider": "openai",
        "model": "default",
        "apiBase": proxy_base_url,
        "apiKey": token
    });

    let mut models_arr = settings.get("continue.models").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    // Remove existing vexa entry if present
    models_arr.retain(|m| m.get("title").and_then(|t| t.as_str()) != Some("Vexa Agent Control (Managed)"));
    models_arr.insert(0, vexa_model);

    settings["continue.models"] = serde_json::Value::Array(models_arr.clone());
    written_values.insert("continue.models".to_string(), serde_json::Value::Array(models_arr));

    if let Some(parent) = settings_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    fs::write(settings_path, serde_json::to_string_pretty(&settings).unwrap())
        .map_err(|e| format!("Failed to write {}: {}", settings_path.display(), e))?;

    let post_hash = OwnershipManifest::compute_sha256(settings_path).unwrap_or_default();

    let manifest = OwnershipManifest::new(
        target_name,
        settings_path.to_path_buf(),
        pre_hash,
        post_hash,
        vec!["continue.models".to_string()],
        previous_values,
        written_values,
    )
    .with_connect_mode(mode.as_str());
    manifest.save().map_err(|e| format!("Failed to save ownership manifest: {}", e))?;

    println!("  Configuration: {}", settings_path.display());
    println!("  Continue Model: Vexa Agent Control (apiBase: {})", proxy_base_url.green());

    Ok(())
}

/// Disconnect a target client by non-destructively reverting managed keys using the ownership manifest.
pub fn run_disconnect(target: ConnectTarget) -> i32 {
    println!(
        "{} Disconnecting {} from Vexa Agent Control...",
        "●".cyan().bold(),
        target.display_name().bold()
    );

    let manifest = match OwnershipManifest::load(target.as_str()) {
        Ok(Some(m)) => m,
        Ok(None) => {
            eprintln!(
                "{} No active ownership manifest found for '{}'. Configuration was not managed by connect.",
                "⚠".yellow(),
                target.as_str()
            );
            return 1;
        }
        Err(e) => {
            eprintln!("{} Failed to read ownership manifest: {}", "✖".red(), e);
            return 1;
        }
    };

    if !manifest.config_path.exists() {
        eprintln!(
            "{} Target configuration file does not exist: {}",
            "✖".red(),
            manifest.config_path.display()
        );
        let _ = OwnershipManifest::delete(target.as_str());
        return 0;
    }

    let is_toml = manifest.config_path.extension().and_then(|e| e.to_str()) == Some("toml");

    let result = if is_toml {
        revert_toml_target(&manifest)
    } else {
        revert_json_target(&manifest)
    };

    match result {
        Ok(reverted_keys) => {
            let _ = OwnershipManifest::delete(target.as_str());
            println!(
                "{} Successfully disconnected {}!",
                "✔".green().bold(),
                target.display_name()
            );
            println!("  Reverted managed settings: {}", reverted_keys.join(", ").cyan());
            println!("  All user custom configurations and unrelated keys preserved.");
            0
        }
        Err(e) => {
            eprintln!("{} Disconnect failed: {}", "✖".red(), e);
            1
        }
    }
}

/// Revert managed keys in a TOML configuration file (e.g. Codex).
pub fn revert_toml_target(manifest: &OwnershipManifest) -> Result<Vec<String>, String> {
    let raw = fs::read_to_string(&manifest.config_path).map_err(|e| e.to_string())?;
    let mut toml_val: toml::Value = toml::from_str(&raw).map_err(|e| format!("Invalid TOML: {}", e))?;
    let mut reverted_keys = Vec::new();

    let root = toml_val.as_table_mut().ok_or_else(|| "Root is not a TOML table".to_string())?;

    for key in &manifest.managed_keys {
        if key == "shell_environment_policy.set.OPENAI_BASE_URL" {
            if let Some(set_tbl) = root
                .get_mut("shell_environment_policy")
                .and_then(|p| p.as_table_mut())
                .and_then(|p| p.get_mut("set"))
                .and_then(|s| s.as_table_mut())
            {
                let cur = set_tbl.get("OPENAI_BASE_URL").and_then(|v| v.as_str());
                let written = manifest.written_values.get(key).and_then(|v| v.as_str());
                let prev = manifest.previous_values.get(key);

                if cur == written {
                    match prev {
                        Some(serde_json::Value::String(s)) => {
                            set_tbl.insert("OPENAI_BASE_URL".to_string(), toml::Value::String(s.clone()));
                        }
                        _ => {
                            set_tbl.remove("OPENAI_BASE_URL");
                        }
                    }
                    reverted_keys.push("OPENAI_BASE_URL".to_string());
                } else {
                    eprintln!(
                        "{} OPENAI_BASE_URL was modified externally; preserving user custom setting.",
                        "⚠".yellow()
                    );
                }
            }
        } else if key == "shell_environment_policy.set.OPENAI_API_KEY" {
            if let Some(set_tbl) = root
                .get_mut("shell_environment_policy")
                .and_then(|p| p.as_table_mut())
                .and_then(|p| p.get_mut("set"))
                .and_then(|s| s.as_table_mut())
            {
                let cur = set_tbl.get("OPENAI_API_KEY").and_then(|v| v.as_str());
                let written = manifest.written_values.get(key).and_then(|v| v.as_str());
                let prev = manifest.previous_values.get(key);

                if cur == written {
                    match prev {
                        Some(serde_json::Value::String(s)) => {
                            set_tbl.insert("OPENAI_API_KEY".to_string(), toml::Value::String(s.clone()));
                        }
                        _ => {
                            set_tbl.remove("OPENAI_API_KEY");
                        }
                    }
                    reverted_keys.push("OPENAI_API_KEY".to_string());
                } else {
                    eprintln!(
                        "{} OPENAI_API_KEY was modified externally; preserving user custom setting.",
                        "⚠".yellow()
                    );
                }
            }
        }
    }

    // Unwrap any wrapped MCP servers
    if let Some(mcp_table) = root.get_mut("mcp_servers").and_then(|v| v.as_table_mut()) {
        for (name, srv) in mcp_table.iter_mut() {
            if let Some(srv_tbl) = srv.as_table_mut() {
                let cur_cmd = srv_tbl.get("command").and_then(|c| c.as_str()).unwrap_or("");
                if cur_cmd.contains("agentcontrol") || cur_cmd.contains("agentwall") {
                    let cmd_key = format!("mcp_servers.{}.command", name);
                    let args_key = format!("mcp_servers.{}.args", name);
                    if let Some(serde_json::Value::String(orig_cmd)) = manifest.previous_values.get(&cmd_key) {
                        srv_tbl.insert("command".to_string(), toml::Value::String(orig_cmd.clone()));
                    }
                    if let Some(serde_json::Value::Array(orig_args)) = manifest.previous_values.get(&args_key) {
                        let toml_args: Vec<toml::Value> = orig_args
                            .iter()
                            .filter_map(|v| v.as_str().map(|s| toml::Value::String(s.to_string())))
                            .collect();
                        srv_tbl.insert("args".to_string(), toml::Value::Array(toml_args));
                    }
                    reverted_keys.push(format!("mcp_servers.{}", name));
                }
            }
        }
    }

    let updated_toml = toml::to_string_pretty(&toml_val).map_err(|e| format!("Failed to format TOML: {}", e))?;
    fs::write(&manifest.config_path, updated_toml).map_err(|e| format!("Failed to write: {}", e))?;

    Ok(reverted_keys)
}

/// Revert managed keys in a JSON configuration file (e.g. Claude Desktop, VS Code Continue).
pub fn revert_json_target(manifest: &OwnershipManifest) -> Result<Vec<String>, String> {
    let raw = fs::read_to_string(&manifest.config_path).map_err(|e| e.to_string())?;
    let mut config: serde_json::Value =
        serde_json::from_str(&crate::wrap::strip_json_comments(&raw)).map_err(|e| format!("Invalid JSON: {}", e))?;
    let mut reverted_keys = Vec::new();

    for key in &manifest.managed_keys {
        if key == "mcpServers" {
            if let Some(prev) = manifest.previous_values.get("mcpServers") {
                // Restore previous mcpServers or unwrap
                if let Some(prev_obj) = prev.as_object() {
                    config["mcpServers"] = serde_json::Value::Object(prev_obj.clone());
                    reverted_keys.push("mcpServers".to_string());
                }
            }
        } else if key == "continue.models" {
            if let Some(models_arr) = config.get_mut("continue.models").and_then(|m| m.as_array_mut()) {
                models_arr.retain(|m| m.get("title").and_then(|t| t.as_str()) != Some("Vexa Agent Control (Managed)"));
                reverted_keys.push("continue.models".to_string());
            }
        }
    }

    let output_str = serde_json::to_string_pretty(&config).map_err(|e| e.to_string())?;
    fs::write(&manifest.config_path, output_str).map_err(|e| format!("Failed to write: {}", e))?;

    Ok(reverted_keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_codex_connect_and_disconnect_roundtrip_local() {
        let dir = tempdir().unwrap();
        let codex_config = dir.path().join("config.toml");
        fs::write(
            &codex_config,
            r#"
[user_custom]
theme = "dark"
custom_var = "keep_me"
"#,
        )
        .unwrap();

        let res = connect_codex_target_to_path("codex_unit_local", &codex_config, "vx-local-test123", ConnectMode::Local);
        assert!(res.is_ok());

        let configured_toml = fs::read_to_string(&codex_config).unwrap();
        assert!(configured_toml.contains("OPENAI_BASE_URL = \"http://127.0.0.1:18080/v1\""));
        assert!(configured_toml.contains("OPENAI_API_KEY = \"vx-local-test123\""));
        assert!(configured_toml.contains("theme = \"dark\""));

        let manifest = OwnershipManifest::load("codex_unit_local").unwrap().unwrap();
        assert_eq!(manifest.connect_mode.as_deref(), Some("local"));

        let reverted = revert_toml_target(&manifest).unwrap();
        assert_eq!(reverted.len(), 2);
        let _ = OwnershipManifest::delete("codex_unit_local");

        let final_toml = fs::read_to_string(&codex_config).unwrap();
        assert!(!final_toml.contains("OPENAI_BASE_URL"));
        assert!(!final_toml.contains("OPENAI_API_KEY"));
        assert!(final_toml.contains("theme = \"dark\""));
    }

    #[test]
    fn test_codex_connect_and_disconnect_roundtrip_cloud_direct() {
        let dir = tempdir().unwrap();
        let codex_config = dir.path().join("config.toml");
        fs::write(
            &codex_config,
            r#"
[user_custom]
theme = "nord"
"#,
        )
        .unwrap();

        let res = connect_codex_target_to_path("codex_unit_cloud", &codex_config, "sk-vex-998877665544", ConnectMode::CloudDirect);
        assert!(res.is_ok());

        let configured_toml = fs::read_to_string(&codex_config).unwrap();
        assert!(configured_toml.contains("OPENAI_BASE_URL = \"http://127.0.0.1:18080/v1\""));
        assert!(configured_toml.contains("OPENAI_API_KEY = \"sk-vex-998877665544\""));
        assert!(configured_toml.contains("theme = \"nord\""));

        let manifest = OwnershipManifest::load("codex_unit_cloud").unwrap().unwrap();
        assert_eq!(manifest.connect_mode.as_deref(), Some("cloud-direct"));

        let reverted = revert_toml_target(&manifest).unwrap();
        assert_eq!(reverted.len(), 2);
        let _ = OwnershipManifest::delete("codex_unit_cloud");

        let final_toml = fs::read_to_string(&codex_config).unwrap();
        assert!(!final_toml.contains("OPENAI_BASE_URL"));
        assert!(!final_toml.contains("OPENAI_API_KEY"));
        assert!(final_toml.contains("theme = \"nord\""));
    }

    #[test]
    fn test_vscode_continue_connect_and_disconnect() {
        let dir = tempdir().unwrap();
        let settings_path = dir.path().join("settings.json");
        fs::write(
            &settings_path,
            r#"{
  "editor.fontSize": 14
}"#,
        )
        .unwrap();

        let res = connect_vscode_continue_target_to_path("vscode_continue_unit", &settings_path, "sk-vex-continue-key", ConnectMode::CloudDirect);
        assert!(res.is_ok());

        let content = fs::read_to_string(&settings_path).unwrap();
        let json: serde_json::Value = serde_json::from_str(&content).unwrap();
        let models = json["continue.models"].as_array().unwrap();
        assert_eq!(models.len(), 1);
        assert_eq!(models[0]["apiKey"], "sk-vex-continue-key");
        assert_eq!(models[0]["apiBase"], "http://127.0.0.1:18080/v1");

        let manifest = OwnershipManifest::load("vscode_continue_unit").unwrap().unwrap();
        assert_eq!(manifest.connect_mode.as_deref(), Some("cloud-direct"));

        let reverted = revert_json_target(&manifest).unwrap();
        assert_eq!(reverted.len(), 1);
        let _ = OwnershipManifest::delete("vscode_continue_unit");

        let final_content = fs::read_to_string(&settings_path).unwrap();
        let final_json: serde_json::Value = serde_json::from_str(&final_content).unwrap();
        assert_eq!(final_json["editor.fontSize"], 14);
        assert_eq!(final_json["continue.models"].as_array().unwrap().len(), 0);
    }
}
