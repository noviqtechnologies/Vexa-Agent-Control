use agentcontrol::ca::{is_interceptable_host, CaManager};
use std::fs;
use std::sync::Arc;

#[test]
fn test_ca_generation_and_leaf_issuance() {
    let temp_dir = tempfile::tempdir().unwrap();
    let ca_mgr = CaManager::init_or_load(Some(temp_dir.path().to_path_buf())).unwrap();

    // Verify Root CA files are created on disk
    let cert_path = temp_dir.path().join("agentcontrol-ca.pem");
    let key_path = temp_dir.path().join("agentcontrol-ca.key");
    assert!(cert_path.exists(), "agentcontrol-ca.pem should exist");
    assert!(key_path.exists(), "agentcontrol-ca.key should exist");

    // Verify dynamic leaf cert generation for Cursor API
    let config1 = ca_mgr
        .get_or_create_server_config("api2.cursor.sh")
        .expect("Should generate ServerConfig for api2.cursor.sh");

    // Second call should return cached instance
    let config2 = ca_mgr
        .get_or_create_server_config("api2.cursor.sh")
        .expect("Should return cached ServerConfig");

    assert!(Arc::ptr_eq(&config1, &config2), "Leaf config should be cached in memory");
}

#[test]
fn test_allowlisted_domain_interception() {
    // Should intercept
    assert!(is_interceptable_host("api2.cursor.sh", None));
    assert!(is_interceptable_host("api.cursor.sh", None));
    assert!(is_interceptable_host("sub.api.cursor.sh", None));
    assert!(is_interceptable_host("api.openai.com", None));
    assert!(is_interceptable_host("api.anthropic.com", None));
    assert!(is_interceptable_host("generativelanguage.googleapis.com", None));
    assert!(is_interceptable_host("openrouter.ai", None));

    // Should NOT intercept (fast blind TCP tunneling preserved)
    assert!(!is_interceptable_host("github.com", None));
    assert!(!is_interceptable_host("registry.npmjs.org", None));
    assert!(!is_interceptable_host("crates.io", None));
    assert!(!is_interceptable_host("internal.company.corp", None));
}

#[test]
fn test_custom_domain_interception() {
    let custom = vec!["custom-ai.internal.corp".to_string(), "*.internal-llm.net".to_string()];
    assert!(is_interceptable_host("custom-ai.internal.corp", Some(&custom)));
    assert!(is_interceptable_host("gateway.internal-llm.net", Some(&custom)));
    assert!(!is_interceptable_host("google.com", Some(&custom)));
}

#[test]
fn test_cursor_settings_lifecycle_mock() {
    let temp_dir = tempfile::tempdir().unwrap();
    let settings_path = temp_dir.path().join("settings.json");

    let original_content = r#"{
  // Developer custom settings
  "editor.fontSize": 14,
  "workbench.colorTheme": "Default Dark Modern"
}"#;
    fs::write(&settings_path, original_content).unwrap();

    // Verify manual modification simulation
    let raw = fs::read_to_string(&settings_path).unwrap();
    let stripped = agentcontrol::wrap::strip_json_comments(&raw);
    let mut parsed: serde_json::Value = serde_json::from_str(&stripped).unwrap();

    parsed["http.proxy"] = serde_json::json!("http://127.0.0.1:8080");
    parsed["cursor.general.disableHttp2"] = serde_json::json!(true);

    let modified_str = serde_json::to_string_pretty(&parsed).unwrap();
    fs::write(&settings_path, &modified_str).unwrap();

    let read_back: serde_json::Value = serde_json::from_str(&fs::read_to_string(&settings_path).unwrap()).unwrap();
    assert_eq!(read_back["http.proxy"], "http://127.0.0.1:8080");
    assert_eq!(read_back["cursor.general.disableHttp2"], true);
    assert_eq!(read_back["editor.fontSize"], 14);
}
