use agentcontrol::wrap::connect::{resolve_token_and_mode, ConnectMode};

#[tokio::test]
async fn test_explicit_key_parameter_injects_directly() {
    let key = "sk-vex-direct-pass-key-12345".to_string();
    let res = resolve_token_and_mode(None, Some(key.clone())).await;
    assert!(res.is_ok());
    let (token, mode) = res.unwrap();
    assert_eq!(token, key);
    assert_eq!(mode, ConnectMode::CloudDirect);
}

#[tokio::test]
async fn test_explicit_local_mode_always_succeeds() {
    let res = resolve_token_and_mode(Some(ConnectMode::Local), None).await;
    assert!(res.is_ok());
    let (token, mode) = res.unwrap();
    assert_eq!(mode, ConnectMode::Local);
    assert!(token.starts_with("vx-local-"));
}

#[tokio::test]
async fn test_explicit_cloud_direct_unreachable_hub_fails_with_clear_error() {
    std::env::set_var("AGENTCONTROL_HUB_URL", "http://127.0.0.1:59999");
    let res = resolve_token_and_mode(Some(ConnectMode::CloudDirect), None).await;
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(
        err.contains("Failed to connect to Control Hub in cloud-direct mode"),
        "Unexpected error message: {}",
        err
    );
}

#[tokio::test]
async fn test_auto_detect_unreachable_hub_falls_back_or_defaults_to_local() {
    std::env::set_var("AGENTCONTROL_HUB_URL", "http://127.0.0.1:59999");
    // When no mode is specified and hub is unreachable, it should gracefully fall back to local mode
    let res = resolve_token_and_mode(None, None).await;
    assert!(res.is_ok(), "Auto-detect should fall back to local mode");
    let (token, mode) = res.unwrap();
    assert_eq!(mode, ConnectMode::Local);
    assert!(token.starts_with("vx-local-"));
}
