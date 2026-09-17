use std::fs;
use std::sync::Mutex;
use tempfile::tempdir;
use agentcontrol::wrap::connect::{
    connect_antigravity_to_path, connect_claude_code_to_path, connect_claude_to_path,
    connect_codex_to_path, connect_cursor_to_path, connect_vscode_continue_to_path,
    revert_json_target, revert_toml_target, ConnectMode,
};
use agentcontrol::wrap::manifest::OwnershipManifest;

static TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn test_codex_cloud_direct_virtual_key_injection_and_manifest() {
    let _guard = TEST_LOCK.lock().unwrap();
    let tmp = tempdir().unwrap();
    let config_path = tmp.path().join("config.toml");

    let initial_toml = r#"model = "gpt-4o"
theme = "dracula"
"#;
    fs::write(&config_path, initial_toml).unwrap();

    let virtual_key = "sk-vex-1c91080d59c774a331c3006d219bbd1071335ed8cb646078";
    let res = connect_codex_to_path(&config_path, virtual_key, ConnectMode::CloudDirect);
    assert!(res.is_ok(), "connect_codex_to_path failed: {:?}", res);

    let updated_toml = fs::read_to_string(&config_path).unwrap();
    assert!(
        updated_toml.contains(&format!("OPENAI_API_KEY = \"{}\"", virtual_key)),
        "Config TOML does not contain virtual key. Found:\n{}",
        updated_toml
    );
    assert!(
        updated_toml.contains("OPENAI_BASE_URL = \"http://127.0.0.1:18080/v1\""),
        "Config TOML does not contain base URL. Found:\n{}",
        updated_toml
    );
    assert!(
        updated_toml.contains("theme = \"dracula\""),
        "User custom setting 'theme' lost!"
    );

    // Verify manifest
    let manifest = OwnershipManifest::load("codex").unwrap().expect("Manifest not found");
    assert_eq!(manifest.connect_mode.as_deref(), Some("cloud-direct"));
    assert_eq!(
        manifest.written_values.get("shell_environment_policy.set.OPENAI_API_KEY"),
        Some(&serde_json::Value::String(virtual_key.to_string()))
    );

    // Revert
    let reverted = revert_toml_target(&manifest).unwrap();
    assert!(reverted.contains(&"OPENAI_BASE_URL".to_string()));
    assert!(reverted.contains(&"OPENAI_API_KEY".to_string()));
    let _ = OwnershipManifest::delete("codex");

    let final_toml = fs::read_to_string(&config_path).unwrap();
    assert!(!final_toml.contains(virtual_key));
    assert!(!final_toml.contains("OPENAI_BASE_URL"));
    assert!(final_toml.contains("theme = \"dracula\""));
}

#[test]
fn test_codex_local_mode_token_injection() {
    let _guard = TEST_LOCK.lock().unwrap();
    let tmp = tempdir().unwrap();
    let config_path = tmp.path().join("config.toml");

    let initial_toml = r#"custom_key = "value""#;
    fs::write(&config_path, initial_toml).unwrap();

    let local_token = "vx-local-bdf6e55479349f47c1417bb8edfff22a58fbb75c83a46aac62675f9255fdc086";
    let res = connect_codex_to_path(&config_path, local_token, ConnectMode::Local);
    assert!(res.is_ok());

    let updated_toml = fs::read_to_string(&config_path).unwrap();
    assert!(updated_toml.contains(&format!("OPENAI_API_KEY = \"{}\"", local_token)));
    assert!(updated_toml.contains("OPENAI_BASE_URL = \"http://127.0.0.1:18080/v1\""));

    let manifest = OwnershipManifest::load("codex").unwrap().expect("Manifest not found");
    assert_eq!(manifest.connect_mode.as_deref(), Some("local"));

    let reverted = revert_toml_target(&manifest).unwrap();
    assert!(reverted.contains(&"OPENAI_BASE_URL".to_string()));
    assert!(reverted.contains(&"OPENAI_API_KEY".to_string()));
    let _ = OwnershipManifest::delete("codex");

    let final_toml = fs::read_to_string(&config_path).unwrap();
    assert!(!final_toml.contains(local_token));
    assert!(final_toml.contains("custom_key = \"value\""));
}

#[test]
fn test_claude_cloud_direct_injects_api_url_and_key_and_reverts() {
    let _guard = TEST_LOCK.lock().unwrap();
    let tmp = tempdir().unwrap();
    let config_path = tmp.path().join("claude_desktop_config.json");

    let initial_json = r#"{
  "mcpServers": {
    "git": {
      "command": "uvx",
      "args": ["mcp-server-git"]
    }
  },
  "user_preference": "custom_val"
}"#;
    fs::write(&config_path, initial_json).unwrap();

    let virtual_key = "sk-vex-claude-test-key-123456";
    let res = connect_claude_to_path(&config_path, virtual_key, ConnectMode::CloudDirect);
    assert!(res.is_ok(), "connect_claude_to_path failed: {:?}", res);

    let content = fs::read_to_string(&config_path).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(json["user_preference"], "custom_val");

    // MCP server command should be wrapped
    let git_cmd = json["mcpServers"]["git"]["command"].as_str().unwrap();
    assert!(git_cmd.contains("agentcontrol") || git_cmd.contains("agentwall"));

    let manifest = OwnershipManifest::load("claude").unwrap().expect("Manifest not found");
    assert_eq!(manifest.connect_mode.as_deref(), Some("cloud-direct"));

    let reverted = revert_json_target(&manifest).unwrap();
    assert!(reverted.contains(&"mcpServers".to_string()));
    let _ = OwnershipManifest::delete("claude");

    let final_content = fs::read_to_string(&config_path).unwrap();
    let final_json: serde_json::Value = serde_json::from_str(&final_content).unwrap();
    assert_eq!(final_json["user_preference"], "custom_val");
    assert_eq!(final_json["mcpServers"]["git"]["command"], "uvx");
}

#[test]
fn test_claude_local_mode_token_injection() {
    let _guard = TEST_LOCK.lock().unwrap();
    let tmp = tempdir().unwrap();
    let config_path = tmp.path().join("claude_desktop_config.json");

    let initial_json = r#"{
  "mcpServers": {
    "calc": {
      "command": "python",
      "args": ["calc.py"]
    }
  },
  "theme": "dark"
}"#;
    fs::write(&config_path, initial_json).unwrap();

    let local_token = "vx-local-claude-token-987654";
    let res = connect_claude_to_path(&config_path, local_token, ConnectMode::Local);
    assert!(res.is_ok());

    let content = fs::read_to_string(&config_path).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(json["theme"], "dark");
    let calc_cmd = json["mcpServers"]["calc"]["command"].as_str().unwrap();
    assert!(calc_cmd.contains("agentcontrol") || calc_cmd.contains("agentwall"));

    let manifest = OwnershipManifest::load("claude").unwrap().expect("Manifest not found");
    assert_eq!(manifest.connect_mode.as_deref(), Some("local"));

    let reverted = revert_json_target(&manifest).unwrap();
    assert!(reverted.contains(&"mcpServers".to_string()));
    let _ = OwnershipManifest::delete("claude");

    let final_content = fs::read_to_string(&config_path).unwrap();
    let final_json: serde_json::Value = serde_json::from_str(&final_content).unwrap();
    assert_eq!(final_json["theme"], "dark");
    assert_eq!(final_json["mcpServers"]["calc"]["command"], "python");
}

#[test]
fn test_cursor_cloud_direct_and_revert() {
    let _guard = TEST_LOCK.lock().unwrap();
    let tmp = tempdir().unwrap();
    let settings_path = tmp.path().join("settings.json");

    let initial_settings = r#"{
  "editor.fontSize": 15,
  "cursor.general.disableHttp2": false
}"#;
    fs::write(&settings_path, initial_settings).unwrap();

    let virtual_key = "sk-vex-cursor-test-key-554433";
    let res = connect_cursor_to_path(&settings_path, virtual_key, ConnectMode::CloudDirect);
    assert!(res.is_ok(), "connect_cursor_to_path failed: {:?}", res);

    let content = fs::read_to_string(&settings_path).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(json["http.proxy"], "http://127.0.0.1:18080");
    assert_eq!(json["cursor.general.disableHttp2"], true);
    assert_eq!(json["cursor.general.openaiApiKey"], virtual_key);
    assert_eq!(json["editor.fontSize"], 15);

    let manifest = OwnershipManifest::load("cursor").unwrap().expect("Manifest not found");
    assert_eq!(manifest.connect_mode.as_deref(), Some("cloud-direct"));

    let reverted = revert_json_target(&manifest).unwrap();
    assert!(reverted.contains(&"http.proxy".to_string()));
    assert!(reverted.contains(&"cursor.general.disableHttp2".to_string()));
    assert!(reverted.contains(&"cursor.general.openaiApiKey".to_string()));
    let _ = OwnershipManifest::delete("cursor");

    let final_content = fs::read_to_string(&settings_path).unwrap();
    let final_json: serde_json::Value = serde_json::from_str(&final_content).unwrap();
    assert!(final_json.get("http.proxy").is_none());
    assert!(final_json.get("cursor.general.openaiApiKey").is_none());
    assert_eq!(final_json["cursor.general.disableHttp2"], false); // restored original value
    assert_eq!(final_json["editor.fontSize"], 15);
}

#[test]
fn test_antigravity_cloud_direct_and_revert() {
    let _guard = TEST_LOCK.lock().unwrap();
    let tmp = tempdir().unwrap();
    let config_path = tmp.path().join("mcp_config.json");

    let initial_config = r#"{
  "mcpServers": {
    "calculator": {
      "command": "python",
      "args": ["calc.py"]
    }
  },
  "customKey": "preserved"
}"#;
    fs::write(&config_path, initial_config).unwrap();

    let virtual_key = "sk-vex-antigravity-key-778899";
    let res = connect_antigravity_to_path(&config_path, virtual_key, ConnectMode::CloudDirect);
    assert!(res.is_ok(), "connect_antigravity_to_path failed: {:?}", res);

    let content = fs::read_to_string(&config_path).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(json["proxy_url"], "http://127.0.0.1:18080/v1");
    assert_eq!(json["api_key"], virtual_key);
    assert_eq!(json["antigravity.proxy.baseUrl"], "http://127.0.0.1:18080/v1");
    assert_eq!(json["antigravity.proxy.apiKey"], virtual_key);
    assert_eq!(json["customKey"], "preserved");

    // MCP server command should be wrapped
    let calc_cmd = json["mcpServers"]["calculator"]["command"].as_str().unwrap();
    assert!(calc_cmd.contains("agentcontrol") || calc_cmd.contains("agentwall"));

    let manifest = OwnershipManifest::load("antigravity").unwrap().expect("Manifest not found");
    assert_eq!(manifest.connect_mode.as_deref(), Some("cloud-direct"));

    let reverted = revert_json_target(&manifest).unwrap();
    assert!(reverted.contains(&"proxy_url".to_string()));
    assert!(reverted.contains(&"api_key".to_string()));
    assert!(reverted.contains(&"mcpServers".to_string()));
    let _ = OwnershipManifest::delete("antigravity");

    let final_content = fs::read_to_string(&config_path).unwrap();
    let final_json: serde_json::Value = serde_json::from_str(&final_content).unwrap();
    assert!(final_json.get("proxy_url").is_none());
    assert!(final_json.get("api_key").is_none());
    assert_eq!(final_json["customKey"], "preserved");
    assert_eq!(final_json["mcpServers"]["calculator"]["command"], "python");
}

#[test]
fn test_vscode_continue_cloud_direct_virtual_key() {
    let _guard = TEST_LOCK.lock().unwrap();
    let tmp = tempdir().unwrap();
    let settings_path = tmp.path().join("settings.json");

    let initial_settings = r#"{
  "workbench.colorTheme": "Default Dark Modern"
}"#;
    fs::write(&settings_path, initial_settings).unwrap();

    let virtual_key = "sk-vex-continue-virtual-key-9999";
    let res = connect_vscode_continue_to_path(&settings_path, virtual_key, ConnectMode::CloudDirect);
    assert!(res.is_ok());

    let raw = fs::read_to_string(&settings_path).unwrap();
    let json: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let models = json["continue.models"].as_array().expect("continue.models missing");
    assert_eq!(models.len(), 1);
    assert_eq!(models[0]["apiKey"], virtual_key);
    assert_eq!(models[0]["apiBase"], "http://127.0.0.1:18080/v1");

    let manifest = OwnershipManifest::load("vscode-continue").unwrap().expect("Manifest not found");
    assert_eq!(manifest.connect_mode.as_deref(), Some("cloud-direct"));

    let reverted = revert_json_target(&manifest).unwrap();
    assert_eq!(reverted.len(), 1);
    let _ = OwnershipManifest::delete("vscode-continue");

    let final_raw = fs::read_to_string(&settings_path).unwrap();
    let final_json: serde_json::Value = serde_json::from_str(&final_raw).unwrap();
    assert_eq!(final_json["workbench.colorTheme"], "Default Dark Modern");
    assert_eq!(final_json["continue.models"].as_array().unwrap().len(), 0);
}

// ─── Claude Code (CLI) Tests ───────────────────────────────────────────────────

#[test]
fn test_claude_code_local_mode_token_injection() {
    let _guard = TEST_LOCK.lock().unwrap();
    let tmp = tempdir().unwrap();
    let settings_path = tmp.path().join("settings.json");

    // Pre-existing settings with user customizations
    let initial = serde_json::json!({
        "theme": "dark",
        "model": "claude-opus-4-5"
    });
    fs::write(&settings_path, serde_json::to_string_pretty(&initial).unwrap()).unwrap();

    let local_token = "vx-local-aabbccdd11223344556677889900aabbccdd11223344556677889900aabbccdd";
    let res = connect_claude_code_to_path(&settings_path, local_token, ConnectMode::Local);
    assert!(res.is_ok(), "connect_claude_code_to_path failed: {:?}", res);

    let updated: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&settings_path).unwrap()).unwrap();

    // Verify env block written
    assert_eq!(
        updated["env"]["ANTHROPIC_BASE_URL"],
        "http://127.0.0.1:18080",
        "ANTHROPIC_BASE_URL not injected"
    );
    assert_eq!(
        updated["env"]["ANTHROPIC_API_KEY"],
        local_token,
        "ANTHROPIC_API_KEY not injected"
    );
    // User settings preserved
    assert_eq!(updated["theme"], "dark", "User 'theme' setting lost!");
    assert_eq!(updated["model"], "claude-opus-4-5", "User 'model' setting lost!");

    // Manifest created
    let manifest = OwnershipManifest::load("claude-code").unwrap().expect("Manifest not found");
    assert_eq!(manifest.connect_mode.as_deref(), Some("local"));
    assert_eq!(
        manifest.written_values.get("env.ANTHROPIC_API_KEY"),
        Some(&serde_json::Value::String(local_token.to_string()))
    );

    // Revert
    let reverted = revert_json_target(&manifest).unwrap();
    assert!(reverted.contains(&"env.ANTHROPIC_BASE_URL".to_string()));
    assert!(reverted.contains(&"env.ANTHROPIC_API_KEY".to_string()));
    let _ = OwnershipManifest::delete("claude-code");

    let final_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&settings_path).unwrap()).unwrap();
    // env keys removed (null → absent)
    assert!(final_json.get("env").and_then(|e| e.get("ANTHROPIC_BASE_URL")).is_none());
    assert!(final_json.get("env").and_then(|e| e.get("ANTHROPIC_API_KEY")).is_none());
    // User settings survive
    assert_eq!(final_json["theme"], "dark");
}

#[test]
fn test_claude_code_cloud_direct_virtual_key() {
    let _guard = TEST_LOCK.lock().unwrap();
    let tmp = tempdir().unwrap();
    let settings_path = tmp.path().join("settings.json");

    // Start with empty settings
    fs::write(&settings_path, "{}").unwrap();

    let virtual_key = "sk-vex-deadbeef00112233445566778899aabbccddeeff00112233445566778899aabb";
    let res = connect_claude_code_to_path(&settings_path, virtual_key, ConnectMode::CloudDirect);
    assert!(res.is_ok(), "connect_claude_code_to_path cloud-direct failed: {:?}", res);

    let updated: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&settings_path).unwrap()).unwrap();

    assert_eq!(updated["env"]["ANTHROPIC_BASE_URL"], "http://127.0.0.1:18080");
    assert_eq!(updated["env"]["ANTHROPIC_API_KEY"], virtual_key);

    // ConnectResult shows llm_endpoint_injected = true
    let result = res.unwrap();
    assert!(result.llm_endpoint_injected);
    assert_eq!(result.proxy_url, "http://127.0.0.1:18080");

    // Manifest mode is cloud-direct
    let manifest = OwnershipManifest::load("claude-code").unwrap().expect("Manifest not found");
    assert_eq!(manifest.connect_mode.as_deref(), Some("cloud-direct"));
    let _ = OwnershipManifest::delete("claude-code");
}

#[test]
fn test_claude_code_connect_preserves_existing_env_and_user_keys() {
    let _guard = TEST_LOCK.lock().unwrap();
    let tmp = tempdir().unwrap();
    let settings_path = tmp.path().join("settings.json");

    // User already has other env vars and keys
    let initial = serde_json::json!({
        "customSetting": true,
        "env": {
            "MY_CUSTOM_VAR": "hello",
            "DEBUG": "1"
        }
    });
    fs::write(&settings_path, serde_json::to_string_pretty(&initial).unwrap()).unwrap();

    let token = "sk-vex-cafebabe00112233445566778899aabbccddeeff";
    let res = connect_claude_code_to_path(&settings_path, token, ConnectMode::Local);
    assert!(res.is_ok());

    let updated: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&settings_path).unwrap()).unwrap();

    // Vexa values injected
    assert_eq!(updated["env"]["ANTHROPIC_BASE_URL"], "http://127.0.0.1:18080");
    assert_eq!(updated["env"]["ANTHROPIC_API_KEY"], token);
    // Existing env vars preserved
    assert_eq!(updated["env"]["MY_CUSTOM_VAR"], "hello", "User env var lost!");
    assert_eq!(updated["env"]["DEBUG"], "1", "User DEBUG env var lost!");
    // Other user settings preserved
    assert_eq!(updated["customSetting"], true, "User customSetting lost!");

    let _ = OwnershipManifest::delete("claude-code");
}
