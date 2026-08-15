//! Sentry & IDE Configuration Auto-Enforcement Tests

use agentwall::wrap::ide_config::{ensure_json_proxy_setting, IdeConfigStatus};
use serde_json::Value;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_cursor_config_injection_and_tamper_healing() {
    let dir = tempdir().unwrap();
    let cursor_settings = dir.path().join("settings.json");

    // Pre-populate with other user settings (themes, fonts)
    let initial_user_config = r#"{
        "editor.fontSize": 14,
        "workbench.colorTheme": "One Dark Pro",
        "cursor.general.telemetry": false
    }"#;
    fs::write(&cursor_settings, initial_user_config).unwrap();

    // 1. Sentry Enforces Proxy URL
    let updated = ensure_json_proxy_setting(
        &cursor_settings,
        &["cursor.models.openaiBaseUrl"],
        "http://127.0.0.1:8080/v1",
        Some(("cursor.models.apiKey", "agentwall-local-key")),
    )
    .unwrap();

    assert!(updated, "Expected config to be updated");

    // Verify proxy URL was injected and other keys preserved
    let content = fs::read_to_string(&cursor_settings).unwrap();
    let parsed: Value = serde_json::from_str(&content).unwrap();

    assert_eq!(
        parsed["cursor.models.openaiBaseUrl"],
        "http://127.0.0.1:8080/v1"
    );
    assert_eq!(parsed["cursor.models.apiKey"], "agentwall-local-key");
    assert_eq!(parsed["editor.fontSize"], 14);
    assert_eq!(parsed["workbench.colorTheme"], "One Dark Pro");

    // 2. Simulate developer tampering: developer changes Base URL to bypass
    fs::write(
        &cursor_settings,
        r#"{
            "editor.fontSize": 14,
            "cursor.models.openaiBaseUrl": "https://api.openai.com"
        }"#,
    )
    .unwrap();

    // 3. Sentry Self-Healing detects drift and restores proxy
    let healed = ensure_json_proxy_setting(
        &cursor_settings,
        &["cursor.models.openaiBaseUrl"],
        "http://127.0.0.1:8080/v1",
        Some(("cursor.models.apiKey", "agentwall-local-key")),
    )
    .unwrap();

    assert!(healed, "Expected self-healing to trigger");

    let healed_content = fs::read_to_string(&cursor_settings).unwrap();
    let healed_parsed: Value = serde_json::from_str(&healed_content).unwrap();
    assert_eq!(
        healed_parsed["cursor.models.openaiBaseUrl"],
        "http://127.0.0.1:8080/v1"
    );
}

#[test]
fn test_ide_config_status_structure() {
    let status = IdeConfigStatus {
        name: "cursor".to_string(),
        installed: true,
        config_path: Some("/test/path/settings.json".to_string()),
        proxy_configured: true,
        configured_base_url: Some("http://127.0.0.1:8080/v1".to_string()),
        mcp_wrapped: true,
        compliance_state: "COMPLIANT".to_string(),
        last_healed_at: None,
    };

    assert_eq!(status.compliance_state, "COMPLIANT");
    assert!(status.proxy_configured);
}
