use std::collections::HashMap;
use std::fs;
use tempfile::tempdir;
use agentcontrol::wrap::connect::{revert_json_target, revert_toml_target};
use agentcontrol::wrap::manifest::OwnershipManifest;

#[test]
fn test_codex_manifest_reversal_preserves_user_settings() {
    let tmp = tempdir().unwrap();
    let config_path = tmp.path().join("config.toml");

    let initial_toml = r#"model = "gpt-4o"
theme = "solarized"

[mcp_servers.custom_db]
command = "node"
args = ["server.js", "--port", "5432"]
"#;
    fs::write(&config_path, initial_toml).unwrap();
    let pre_hash = OwnershipManifest::compute_sha256(&config_path).unwrap();

    // 1. Simulate Connect
    let mut toml_val: toml::Value = toml::from_str(initial_toml).unwrap();
    let root = toml_val.as_table_mut().unwrap();

    let mut set_table = toml::Table::new();
    set_table.insert(
        "OPENAI_BASE_URL".to_string(),
        toml::Value::String("http://127.0.0.1:18080/v1".to_string()),
    );
    set_table.insert(
        "OPENAI_API_KEY".to_string(),
        toml::Value::String("agentcontrol-local-token".to_string()),
    );

    let mut env_policy = toml::Table::new();
    env_policy.insert("set".to_string(), toml::Value::Table(set_table));
    root.insert("shell_environment_policy".to_string(), toml::Value::Table(env_policy));

    // Wrap MCP server
    let srv = root
        .get_mut("mcp_servers")
        .unwrap()
        .as_table_mut()
        .unwrap()
        .get_mut("custom_db")
        .unwrap()
        .as_table_mut()
        .unwrap();
    srv.insert(
        "command".to_string(),
        toml::Value::String("agentcontrol".to_string()),
    );
    srv.insert(
        "args".to_string(),
        toml::Value::Array(vec![
            toml::Value::String("stdio-proxy".to_string()),
            toml::Value::String("--".to_string()),
            toml::Value::String("node".to_string()),
            toml::Value::String("server.js".to_string()),
            toml::Value::String("--port".to_string()),
            toml::Value::String("5432".to_string()),
        ]),
    );

    fs::write(&config_path, toml::to_string_pretty(&toml_val).unwrap()).unwrap();
    let post_hash = OwnershipManifest::compute_sha256(&config_path).unwrap();

    let mut previous_values = HashMap::new();
    previous_values.insert(
        "mcp_servers.custom_db.command".to_string(),
        serde_json::Value::String("node".to_string()),
    );
    previous_values.insert(
        "mcp_servers.custom_db.args".to_string(),
        serde_json::json!(["server.js", "--port", "5432"]),
    );

    let mut written_values = HashMap::new();
    written_values.insert(
        "shell_environment_policy.set.OPENAI_BASE_URL".to_string(),
        serde_json::Value::String("http://127.0.0.1:18080/v1".to_string()),
    );
    written_values.insert(
        "shell_environment_policy.set.OPENAI_API_KEY".to_string(),
        serde_json::Value::String("agentcontrol-local-token".to_string()),
    );
    written_values.insert(
        "mcp_servers.custom_db.command".to_string(),
        serde_json::Value::String("agentcontrol".to_string()),
    );

    let managed_keys = vec![
        "shell_environment_policy.set.OPENAI_BASE_URL".to_string(),
        "shell_environment_policy.set.OPENAI_API_KEY".to_string(),
        "mcp_servers.custom_db.command".to_string(),
    ];

    let manifest = OwnershipManifest::new(
        "codex",
        config_path.clone(),
        pre_hash,
        post_hash,
        managed_keys,
        previous_values,
        written_values,
    );

    // 2. Simulate User Modifying Independent Settings while connected
    let connected_raw = fs::read_to_string(&config_path).unwrap();
    let mut modified_toml: toml::Value = toml::from_str(&connected_raw).unwrap();
    let mod_root = modified_toml.as_table_mut().unwrap();
    mod_root.insert("model".to_string(), toml::Value::String("o3-mini".to_string()));
    mod_root.insert("user_custom_tool".to_string(), toml::Value::Boolean(true));
    fs::write(&config_path, toml::to_string_pretty(&modified_toml).unwrap()).unwrap();

    // 3. Disconnect: Ownership-aware rollback
    let reverted = revert_toml_target(&manifest).unwrap();
    assert!(reverted.contains(&"OPENAI_BASE_URL".to_string()));
    assert!(reverted.contains(&"OPENAI_API_KEY".to_string()));
    assert!(reverted.contains(&"mcp_servers.custom_db".to_string()));

    // 4. Invariant Verification
    let final_raw = fs::read_to_string(&config_path).unwrap();
    let final_toml: toml::Value = toml::from_str(&final_raw).unwrap();
    let final_root = final_toml.as_table().unwrap();

    // User customizations must be preserved!
    assert_eq!(final_root.get("model").unwrap().as_str().unwrap(), "o3-mini");
    assert_eq!(final_root.get("theme").unwrap().as_str().unwrap(), "solarized");
    assert_eq!(
        final_root.get("user_custom_tool").unwrap().as_bool().unwrap(),
        true
    );

    // Managed keys must be reverted
    if let Some(env_pol) = final_root.get("shell_environment_policy") {
        if let Some(set_tbl) = env_pol.get("set") {
            assert!(set_tbl.get("OPENAI_BASE_URL").is_none());
            assert!(set_tbl.get("OPENAI_API_KEY").is_none());
        }
    }

    // MCP server command and args must be restored
    let db_srv = final_root
        .get("mcp_servers")
        .unwrap()
        .get("custom_db")
        .unwrap();
    assert_eq!(db_srv.get("command").unwrap().as_str().unwrap(), "node");
    let args: Vec<&str> = db_srv
        .get("args")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(args, vec!["server.js", "--port", "5432"]);
}

#[test]
fn test_claude_manifest_reversal_preserves_user_settings() {
    let tmp = tempdir().unwrap();
    let config_path = tmp.path().join("claude_desktop_config.json");

    let initial_json = serde_json::json!({
        "mcpServers": {
            "sqlite": {
                "command": "uvx",
                "args": ["mcp-server-sqlite", "--db-path", "/data/app.db"]
            }
        },
        "userPreferences": {
            "fontSize": 14,
            "theme": "dark"
        }
    });
    fs::write(&config_path, serde_json::to_string_pretty(&initial_json).unwrap()).unwrap();
    let pre_hash = OwnershipManifest::compute_sha256(&config_path).unwrap();

    // 1. Simulate Connect wrapping
    let mut wrapped_json = initial_json.clone();
    wrapped_json["mcpServers"]["sqlite"]["command"] = serde_json::Value::String("agentcontrol".to_string());
    wrapped_json["mcpServers"]["sqlite"]["args"] = serde_json::json!([
        "stdio-proxy",
        "--",
        "uvx",
        "mcp-server-sqlite",
        "--db-path",
        "/data/app.db"
    ]);
    fs::write(&config_path, serde_json::to_string_pretty(&wrapped_json).unwrap()).unwrap();
    let post_hash = OwnershipManifest::compute_sha256(&config_path).unwrap();

    let mut previous_values = HashMap::new();
    previous_values.insert("mcpServers".to_string(), initial_json["mcpServers"].clone());

    let mut written_values = HashMap::new();
    written_values.insert("mcpServers".to_string(), wrapped_json["mcpServers"].clone());

    let manifest = OwnershipManifest::new(
        "claude",
        config_path.clone(),
        pre_hash,
        post_hash,
        vec!["mcpServers".to_string()],
        previous_values,
        written_values,
    );

    // 2. User adds custom plugin while connected
    let connected_raw = fs::read_to_string(&config_path).unwrap();
    let mut modified_json: serde_json::Value = serde_json::from_str(&connected_raw).unwrap();
    modified_json["customExtensions"] = serde_json::json!({"autoSave": true});
    fs::write(&config_path, serde_json::to_string_pretty(&modified_json).unwrap()).unwrap();

    // 3. Disconnect
    let reverted = revert_json_target(&manifest).unwrap();
    assert!(reverted.contains(&"mcpServers".to_string()));

    // 4. Verify user custom extensions preserved and mcpServers restored
    let final_raw = fs::read_to_string(&config_path).unwrap();
    let final_json: serde_json::Value = serde_json::from_str(&final_raw).unwrap();

    assert_eq!(
        final_json["customExtensions"]["autoSave"],
        serde_json::Value::Bool(true)
    );
    assert_eq!(
        final_json["userPreferences"]["theme"],
        serde_json::Value::String("dark".to_string())
    );
    assert_eq!(
        final_json["mcpServers"]["sqlite"]["command"],
        serde_json::Value::String("uvx".to_string())
    );
    assert_eq!(
        final_json["mcpServers"]["sqlite"]["args"],
        serde_json::json!(["mcp-server-sqlite", "--db-path", "/data/app.db"])
    );
}

#[test]
fn test_cursor_manifest_reversal_preserves_user_settings() {
    let tmp = tempdir().unwrap();
    let config_path = tmp.path().join("settings.json");

    let initial_json = serde_json::json!({
        "editor.fontSize": 14,
        "cursor.general.disableHttp2": false
    });
    fs::write(&config_path, serde_json::to_string_pretty(&initial_json).unwrap()).unwrap();
    let pre_hash = OwnershipManifest::compute_sha256(&config_path).unwrap();

    let mut connected_json = initial_json.clone();
    connected_json["http.proxy"] = serde_json::json!("http://127.0.0.1:18080");
    connected_json["cursor.general.disableHttp2"] = serde_json::json!(true);
    connected_json["cursor.general.openaiApiKey"] = serde_json::json!("sk-vex-cursor-123");
    fs::write(&config_path, serde_json::to_string_pretty(&connected_json).unwrap()).unwrap();
    let post_hash = OwnershipManifest::compute_sha256(&config_path).unwrap();

    let mut previous_values = HashMap::new();
    previous_values.insert("http.proxy".to_string(), serde_json::Value::Null);
    previous_values.insert("cursor.general.disableHttp2".to_string(), serde_json::json!(false));
    previous_values.insert("cursor.general.openaiApiKey".to_string(), serde_json::Value::Null);

    let mut written_values = HashMap::new();
    written_values.insert("http.proxy".to_string(), serde_json::json!("http://127.0.0.1:18080"));
    written_values.insert("cursor.general.disableHttp2".to_string(), serde_json::json!(true));
    written_values.insert("cursor.general.openaiApiKey".to_string(), serde_json::json!("sk-vex-cursor-123"));

    let manifest = OwnershipManifest::new(
        "cursor",
        config_path.clone(),
        pre_hash,
        post_hash,
        vec![
            "http.proxy".to_string(),
            "cursor.general.disableHttp2".to_string(),
            "cursor.general.openaiApiKey".to_string(),
        ],
        previous_values,
        written_values,
    );

    // User changes font size while connected
    let mut active: serde_json::Value = serde_json::from_str(&fs::read_to_string(&config_path).unwrap()).unwrap();
    active["editor.fontSize"] = serde_json::json!(16);
    fs::write(&config_path, serde_json::to_string_pretty(&active).unwrap()).unwrap();

    let reverted = revert_json_target(&manifest).unwrap();
    assert!(reverted.contains(&"http.proxy".to_string()));
    assert!(reverted.contains(&"cursor.general.disableHttp2".to_string()));
    assert!(reverted.contains(&"cursor.general.openaiApiKey".to_string()));

    let final_json: serde_json::Value = serde_json::from_str(&fs::read_to_string(&config_path).unwrap()).unwrap();
    assert_eq!(final_json["editor.fontSize"], 16);
    assert_eq!(final_json["cursor.general.disableHttp2"], false);
    assert_eq!(final_json.get("http.proxy"), None);
    assert_eq!(final_json.get("cursor.general.openaiApiKey"), None);
}

#[test]
fn test_antigravity_manifest_reversal_preserves_user_settings() {
    let tmp = tempdir().unwrap();
    let config_path = tmp.path().join("mcp_config.json");

    let initial_json = serde_json::json!({
        "mcpServers": {
            "fetcher": {
                "command": "python",
                "args": ["fetch.py"]
            }
        },
        "customFlag": 42
    });
    fs::write(&config_path, serde_json::to_string_pretty(&initial_json).unwrap()).unwrap();
    let pre_hash = OwnershipManifest::compute_sha256(&config_path).unwrap();

    let mut connected_json = initial_json.clone();
    connected_json["proxy_url"] = serde_json::json!("http://127.0.0.1:18080/v1");
    connected_json["api_key"] = serde_json::json!("sk-vex-anti-456");
    connected_json["antigravity.proxy.baseUrl"] = serde_json::json!("http://127.0.0.1:18080/v1");
    connected_json["antigravity.proxy.apiKey"] = serde_json::json!("sk-vex-anti-456");
    connected_json["mcpServers"]["fetcher"]["command"] = serde_json::json!("agentcontrol");
    connected_json["mcpServers"]["fetcher"]["args"] = serde_json::json!(["stdio-proxy", "--", "python", "fetch.py"]);
    fs::write(&config_path, serde_json::to_string_pretty(&connected_json).unwrap()).unwrap();
    let post_hash = OwnershipManifest::compute_sha256(&config_path).unwrap();

    let mut previous_values = HashMap::new();
    previous_values.insert("proxy_url".to_string(), serde_json::Value::Null);
    previous_values.insert("api_key".to_string(), serde_json::Value::Null);
    previous_values.insert("antigravity.proxy.baseUrl".to_string(), serde_json::Value::Null);
    previous_values.insert("antigravity.proxy.apiKey".to_string(), serde_json::Value::Null);
    previous_values.insert("mcpServers".to_string(), initial_json["mcpServers"].clone());

    let mut written_values = HashMap::new();
    written_values.insert("proxy_url".to_string(), serde_json::json!("http://127.0.0.1:18080/v1"));
    written_values.insert("api_key".to_string(), serde_json::json!("sk-vex-anti-456"));
    written_values.insert("antigravity.proxy.baseUrl".to_string(), serde_json::json!("http://127.0.0.1:18080/v1"));
    written_values.insert("antigravity.proxy.apiKey".to_string(), serde_json::json!("sk-vex-anti-456"));
    written_values.insert("mcpServers".to_string(), connected_json["mcpServers"].clone());

    let manifest = OwnershipManifest::new(
        "antigravity",
        config_path.clone(),
        pre_hash,
        post_hash,
        vec![
            "proxy_url".to_string(),
            "api_key".to_string(),
            "antigravity.proxy.baseUrl".to_string(),
            "antigravity.proxy.apiKey".to_string(),
            "mcpServers".to_string(),
        ],
        previous_values,
        written_values,
    );

    let reverted = revert_json_target(&manifest).unwrap();
    assert!(reverted.contains(&"proxy_url".to_string()));
    assert!(reverted.contains(&"api_key".to_string()));
    assert!(reverted.contains(&"mcpServers".to_string()));

    let final_json: serde_json::Value = serde_json::from_str(&fs::read_to_string(&config_path).unwrap()).unwrap();
    assert_eq!(final_json["customFlag"], 42);
    assert_eq!(final_json.get("proxy_url"), None);
    assert_eq!(final_json.get("api_key"), None);
    assert_eq!(final_json["mcpServers"]["fetcher"]["command"], "python");
    assert_eq!(final_json["mcpServers"]["fetcher"]["args"], serde_json::json!(["fetch.py"]));
}

// ─── Claude Code (CLI) Manifest Reversal Tests ────────────────────────────────

#[test]
fn test_claude_code_manifest_reversal_preserves_user_settings() {
    use agentcontrol::wrap::connect::connect_claude_code_to_path;
    use agentcontrol::wrap::connect::ConnectMode;

    let tmp = tempdir().unwrap();
    let settings_path = tmp.path().join("settings.json");

    // Simulate user's existing ~/.claude/settings.json
    let initial = serde_json::json!({
        "userPreference": "vim-mode",
        "env": {
            "MY_API_KEY": "user-custom-key",
            "CUSTOM_FLAG": "true"
        }
    });
    fs::write(&settings_path, serde_json::to_string_pretty(&initial).unwrap()).unwrap();

    // Connect
    let token = "sk-vex-reversal-test-aabb1122334455667788990011223344";
    let res = connect_claude_code_to_path(&settings_path, token, ConnectMode::Local);
    assert!(res.is_ok(), "connect_claude_code_to_path failed: {:?}", res);

    let after_connect: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&settings_path).unwrap()).unwrap();

    // Verify injected
    assert_eq!(after_connect["env"]["ANTHROPIC_BASE_URL"], "http://127.0.0.1:18080");
    assert_eq!(after_connect["env"]["ANTHROPIC_API_KEY"], token);
    // Existing user env vars untouched
    assert_eq!(after_connect["env"]["MY_API_KEY"], "user-custom-key");
    assert_eq!(after_connect["env"]["CUSTOM_FLAG"], "true");
    assert_eq!(after_connect["userPreference"], "vim-mode");

    // Revert via manifest
    let manifest = OwnershipManifest::load("claude-code").unwrap().expect("Manifest not found");
    let reverted_keys = revert_json_target(&manifest).unwrap();
    let _ = OwnershipManifest::delete("claude-code");

    assert!(reverted_keys.contains(&"env.ANTHROPIC_BASE_URL".to_string()));
    assert!(reverted_keys.contains(&"env.ANTHROPIC_API_KEY".to_string()));

    let final_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&settings_path).unwrap()).unwrap();

    // Vexa keys removed (reverted to null → absent from JSON)
    assert!(final_json["env"].get("ANTHROPIC_BASE_URL").is_none(),
        "ANTHROPIC_BASE_URL should be removed after disconnect");
    assert!(final_json["env"].get("ANTHROPIC_API_KEY").is_none(),
        "ANTHROPIC_API_KEY should be removed after disconnect");

    // User's existing env vars must survive
    assert_eq!(final_json["env"]["MY_API_KEY"], "user-custom-key",
        "User MY_API_KEY lost after disconnect!");
    assert_eq!(final_json["env"]["CUSTOM_FLAG"], "true",
        "User CUSTOM_FLAG lost after disconnect!");
    assert_eq!(final_json["userPreference"], "vim-mode",
        "User userPreference lost after disconnect!");
}

