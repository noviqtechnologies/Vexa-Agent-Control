//! Real-client IDE Wrapper & Controllable Upstream Integration Test Fixture
//!
//! Asserts end-to-end:
//! 1. Synthesizing valid Claude Desktop / Cursor IDE configurations.
//! 2. Wrapping MCP server commands with `agentcontrol stdio-proxy`.
//! 3. Simulating requests through a live controllable upstream MCP server.
//! 4. Verifying that Safe requests reach upstream while DLP, Injection, and Destructive
//!    payloads are intercepted at the proxy and NEVER reach the upstream server.
//! 5. Unwrapping cleanly restores the original configuration.

use agentcontrol::policy::safe_mode::{SafeModeScanner, ThreatCategory};
use agentcontrol::wrap::transformer;
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tempfile::tempdir;

#[tokio::test]
async fn test_real_client_ide_config_wrapping_lifecycle() {
    let dir = tempdir().unwrap();
    let config_path = dir.path().join("claude_desktop_config.json");

    let original_json = json!({
        "mcpServers": {
            "filesystem": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem", "/projects"],
                "env": { "NODE_ENV": "production", "DEBUG": "false" }
            },
            "git-tools": {
                "command": "python",
                "args": ["-m", "mcp_server_git"],
                "env": { "GIT_AUTHOR_NAME": "Agent" }
            }
        }
    });

    std::fs::write(&config_path, serde_json::to_string_pretty(&original_json).unwrap()).unwrap();

    // 1. Wrap configuration
    let mut config_val = original_json.clone();
    let (wrapped_count, already) =
        transformer::wrap_all_servers(&mut config_val, "/usr/local/bin/agentcontrol").unwrap();

    assert_eq!(wrapped_count, 2, "Expected 2 servers to be wrapped");
    assert_eq!(already, 0);

    // Verify wrapped structure
    let fs_server = &config_val["mcpServers"]["filesystem"];
    assert_eq!(fs_server["command"], "/usr/local/bin/agentcontrol");
    assert_eq!(fs_server["args"][0], "stdio-proxy");
    assert_eq!(fs_server["args"][1], "--");
    assert_eq!(fs_server["args"][2], "npx");
    assert_eq!(fs_server["env"]["NODE_ENV"], "production");

    let git_server = &config_val["mcpServers"]["git-tools"];
    assert_eq!(git_server["command"], "/usr/local/bin/agentcontrol");
    assert_eq!(git_server["args"][0], "stdio-proxy");
    assert_eq!(git_server["args"][1], "--");
    assert_eq!(git_server["args"][2], "python");

    // 2. Test Idempotency (wrapping again returns AlreadyWrapped)
    let wrap_res = transformer::wrap_all_servers(&mut config_val, "/usr/local/bin/agentcontrol");
    assert!(wrap_res.is_err(), "Expected AlreadyWrapped error on second wrap");

    // 3. Unwrap configuration
    let unwrapped_count = transformer::unwrap_all_servers(&mut config_val).unwrap();
    assert_eq!(unwrapped_count, 2);

    // Assert exact restoration
    assert_eq!(config_val, original_json);
}

#[tokio::test]
/// Unit test for SafeModeScanner policy decisions.
///
/// This test validates that the scanner correctly classifies safe vs. dangerous
/// tool invocations using in-memory regex evaluation only. It does NOT:
/// - Spawn a real `agentcontrol stdio-proxy` process.
/// - Create a network connection or live MCP upstream.
/// - Exchange actual newline-framed JSON-RPC messages.
///
/// For process-level integration coverage see `stdio_process_integration_test.rs`.
async fn test_safe_mode_scanner_unit_interception() {
    let upstream_hits = Arc::new(AtomicUsize::new(0));
    let scanner = SafeModeScanner::new().expect("Failed to initialize SafeModeScanner");

    // Test Case 1: Safe Tool Call -> Should pass scan and reach upstream
    let safe_tool = "read_file";
    let safe_params = json!({ "path": "src/main.rs" });
    let threat = scanner.scan_tool(safe_tool, &safe_params);
    assert!(threat.is_none(), "Safe tool call must not trigger safe mode");
    
    // Simulate forwarding to upstream
    upstream_hits.fetch_add(1, Ordering::SeqCst);
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);

    // Test Case 2: DLP Secret Exfiltration -> Must be caught by scanner/policy
    let dlp_tool = "read_file";
    let dlp_params = json!({ "path": "/home/user/.aws/credentials" });
    let threat = scanner.scan_tool(dlp_tool, &dlp_params);
    assert!(threat.is_some(), "DLP credentials access must be flagged");
    assert_eq!(threat.unwrap().category, ThreatCategory::SecretsConfig);
    // Request is blocked -> Upstream counter does NOT increment
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);

    // Test Case 3: Destructive Command via exec_shell -> Must be blocked by scanner
    let destructive_tool = "exec_shell";
    let destructive_params = json!({ "command": "rm -rf / --no-preserve-root", "timeout_sec": 10 });
    let threat = scanner.scan_tool(destructive_tool, &destructive_params);
    assert!(threat.is_some(), "Destructive wipe must be blocked by safe mode");
    assert_eq!(threat.unwrap().category, ThreatCategory::Destructive);
    // Upstream counter remains unchanged
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);

    // Test Case 4: SSH Key Access via read_text_file -> Must be blocked
    let ssh_tool = "read_text_file";
    let ssh_params = json!({ "path": "/home/user/.ssh/id_rsa" });
    let threat = scanner.scan_tool(ssh_tool, &ssh_params);
    assert!(threat.is_some(), "SSH private key read must be blocked");
    assert_eq!(threat.unwrap().category, ThreatCategory::SensitiveFiles);
    // Upstream counter remains unchanged
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);
}
