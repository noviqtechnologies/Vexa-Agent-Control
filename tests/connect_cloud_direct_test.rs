use std::fs;
use std::sync::Mutex;
use tempfile::tempdir;
use agentcontrol::wrap::connect::{
    connect_codex_to_path, connect_vscode_continue_to_path, revert_json_target,
    revert_toml_target, ConnectMode,
};
use agentcontrol::wrap::manifest::OwnershipManifest;

static CODEX_TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn test_codex_cloud_direct_virtual_key_injection_and_manifest() {
    let _guard = CODEX_TEST_LOCK.lock().unwrap();
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
    assert_eq!(reverted.len(), 2);

    let final_toml = fs::read_to_string(&config_path).unwrap();
    assert!(!final_toml.contains(virtual_key));
    assert!(!final_toml.contains("OPENAI_BASE_URL"));
    assert!(final_toml.contains("theme = \"dracula\""));
}

#[test]
fn test_codex_local_mode_token_injection() {
    let _guard = CODEX_TEST_LOCK.lock().unwrap();
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
    assert_eq!(reverted.len(), 2);

    let final_toml = fs::read_to_string(&config_path).unwrap();
    assert!(!final_toml.contains(local_token));
    assert!(final_toml.contains("custom_key = \"value\""));
}

#[test]
fn test_vscode_continue_cloud_direct_virtual_key() {
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

    let final_raw = fs::read_to_string(&settings_path).unwrap();
    let final_json: serde_json::Value = serde_json::from_str(&final_raw).unwrap();
    assert_eq!(final_json["workbench.colorTheme"], "Default Dark Modern");
    assert_eq!(final_json["continue.models"].as_array().unwrap().len(), 0);
}
