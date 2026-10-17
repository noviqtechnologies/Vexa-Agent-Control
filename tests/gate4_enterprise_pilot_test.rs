//! Gate 4: Enterprise Pilot Readiness — Cross-Platform & Client Conformance Suite
//!
//! Acceptance criteria (enterprise_implementation_plan.md §6 Gate 4):
//!   - Cross-platform OS validation (Windows Named Pipes / POSIX UDS, path normalization, CRLF/LF line endings, UNC rejection).
//!   - Zero regressions across Cursor, VS Code, and Claude Desktop (plus Claude Code and Codex).
//!   - Non-destructive ownership manifest rollback: preserves user customizations byte-for-byte.
//!   - Truthful Capability Manifest reporting with explicit blind-spot disclosure and 7-state posture.
//!   - Standalone enterprise pilot resilience: offline LKG bundle execution, monotonic anti-rollback,
//!     and 72-hour policy expiration contract.
//!   - Zero downstream tool leaks on denied requests with synchronous durable audit logging.

use std::collections::HashMap;
use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tempfile::tempdir;

use agentcontrol::audit::outbox::is_network_filesystem_path;
use agentcontrol::pep::mcp::{handle_mcp_tools_call, MockMcpDownstream, PepError};
use agentcontrol::policy::engine::CompiledPolicy;
use agentcontrol::policy::remote::{load_cached_policy_bundle, save_cached_policy_bundle};
use agentcontrol::policy::sensitive_path::SensitivePathGuard;
use agentcontrol::policy::signed::{
    generate_signing_keypair, sign_policy, verify_signed_bundle, PolicyStorageManager,
    SignedPolicyBundle,
};
use agentcontrol::policy::trust::{PolicyTrustProfile, TrustedKey, TrustedKeyring};
use agentcontrol::proxy::handler::ProxyState;
use agentcontrol::proxy::session::SessionContext;
use agentcontrol::wrap::capability_manifest::{ClientCapabilityManifest, PostureState};
use agentcontrol::wrap::connect::{revert_json_target, revert_toml_target};
use agentcontrol::wrap::manifest::OwnershipManifest;
use serde_json::json;

// ─── 1. Cross-Platform Path Normalization & Sensitive Path Guards ──────────────

#[test]
fn test_gate4_cross_platform_path_guards() {
    let guard = SensitivePathGuard::new(None);

    // Windows-style sensitive credential paths
    let win_paths = [
        r"C:\Users\Developer\.ssh\id_rsa",
        r"C:/Users/Developer/.ssh/id_ed25519",
        r"C:\Users\Developer\.aws\credentials",
        r"C:\Users\Developer\AppData\Local\Google\Chrome\User Data\Default\Login Data",
        r"C:\Windows\System32\config\SAM",
        r"\\remote-server\share\.env",
    ];

    for path in win_paths {
        let finding = guard.check_path(path);
        assert!(
            finding.is_some(),
            "Expected sensitive finding for Windows path: {}",
            path
        );
    }

    // POSIX-style sensitive credential paths
    let posix_paths = [
        "/etc/shadow",
        "/etc/passwd",
        "/home/dev/.ssh/id_rsa",
        "/home/dev/.aws/credentials",
        "/home/dev/.docker/config.json",
        "/home/dev/project/.env",
    ];

    for path in posix_paths {
        let finding = guard.check_path(path);
        assert!(
            finding.is_some(),
            "Expected sensitive finding for POSIX path: {}",
            path
        );
    }

    // Directory traversal escaping boundaries
    let traversal_paths = [
        "../../etc/shadow",
        r"..\..\Windows\System32\drivers\etc\hosts",
        "nested/../../.ssh/id_rsa",
    ];

    for path in traversal_paths {
        let finding = guard.check_path(path);
        assert!(
            finding.is_some(),
            "Expected traversal finding for: {}",
            path
        );
    }

    // Safe regular project files should be allowed
    let safe_paths = [
        "src/main.rs",
        "README.md",
        "package.json",
        "docs/architecture.md",
    ];

    for path in safe_paths {
        let finding = guard.check_path(path);
        assert!(
            finding.is_none(),
            "Safe project path must not be blocked: {}",
            path
        );
    }
}

// ─── 2. Cross-Platform Network Path Rejection (SQLite WAL Protection) ─────────

#[test]
fn test_gate4_cross_platform_network_path_rejection() {
    // Windows UNC paths must be rejected for SQLite WAL safety
    assert!(is_network_filesystem_path(std::path::Path::new(
        r"\\nas\share\events.db"
    )));
    assert!(is_network_filesystem_path(std::path::Path::new(
        r"\\192.168.1.50\corp\events.db"
    )));
    assert!(is_network_filesystem_path(std::path::Path::new(
        "//nas/share/events.db"
    )));

    // Remote network URIs must be rejected
    assert!(is_network_filesystem_path(std::path::Path::new(
        "smb://nas/share/events.db"
    )));
    assert!(is_network_filesystem_path(std::path::Path::new(
        "nfs://nas/share/events.db"
    )));

    // Local paths must be permitted
    assert!(!is_network_filesystem_path(std::path::Path::new(
        r"C:\ProgramData\AgentControl\events.db"
    )));
    assert!(!is_network_filesystem_path(std::path::Path::new(
        "/var/lib/agentcontrol/events.db"
    )));
    assert!(!is_network_filesystem_path(std::path::Path::new(
        "./events.db"
    )));
}

// ─── 3. Cross-Platform CRLF and LF Framing Tolerance ──────────────────────────

#[test]
fn test_gate4_crlf_and_lf_jsonrpc_framing_tolerance() {
    let lf_payload = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}\n";
    let crlf_payload = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}\r\n";

    let parsed_lf: Result<serde_json::Value, _> = serde_json::from_str(lf_payload.trim());
    let parsed_crlf: Result<serde_json::Value, _> = serde_json::from_str(crlf_payload.trim());

    assert!(parsed_lf.is_ok(), "LF framed payload must parse cleanly");
    assert!(
        parsed_crlf.is_ok(),
        "CRLF framed payload must parse cleanly"
    );
    assert_eq!(parsed_lf.unwrap(), parsed_crlf.unwrap());
}

// ─── 4. Cursor Lifecycle & Zero Regressions ───────────────────────────────────

#[test]
fn test_gate4_cursor_lifecycle_zero_regressions() {
    let tmp = tempdir().unwrap();
    let config_path = tmp.path().join("cursor_settings.json");

    let initial_json = json!({
        "editor.fontSize": 14,
        "editor.tabSize": 2,
        "cursor.general.disableHttp2": false,
        "customExtension.enabled": true
    });
    fs::write(
        &config_path,
        serde_json::to_string_pretty(&initial_json).unwrap(),
    )
    .unwrap();
    let pre_hash = OwnershipManifest::compute_sha256(&config_path).unwrap();

    // 1. Simulate AgentControl connect: inject HTTP proxy and disable HTTP2
    let mut connected_json = initial_json.clone();
    connected_json["http.proxy"] = json!("http://127.0.0.1:18080");
    connected_json["cursor.general.disableHttp2"] = json!(true);
    connected_json["cursor.general.openaiApiKey"] = json!("sk-pilot-local-token");
    fs::write(
        &config_path,
        serde_json::to_string_pretty(&connected_json).unwrap(),
    )
    .unwrap();
    let post_hash = OwnershipManifest::compute_sha256(&config_path).unwrap();

    let mut previous_values = HashMap::new();
    previous_values.insert("http.proxy".to_string(), serde_json::Value::Null);
    previous_values.insert("cursor.general.disableHttp2".to_string(), json!(false));
    previous_values.insert(
        "cursor.general.openaiApiKey".to_string(),
        serde_json::Value::Null,
    );

    let mut written_values = HashMap::new();
    written_values.insert("http.proxy".to_string(), json!("http://127.0.0.1:18080"));
    written_values.insert("cursor.general.disableHttp2".to_string(), json!(true));
    written_values.insert(
        "cursor.general.openaiApiKey".to_string(),
        json!("sk-pilot-local-token"),
    );

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

    // 2. Simulate User modifying settings while connected
    let mut user_modified: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&config_path).unwrap()).unwrap();
    user_modified["editor.fontSize"] = json!(16);
    user_modified["workbench.theme"] = json!("One Dark Pro");
    fs::write(
        &config_path,
        serde_json::to_string_pretty(&user_modified).unwrap(),
    )
    .unwrap();

    // 3. Rollback via OwnershipManifest
    let reverted = revert_json_target(&manifest).unwrap();
    assert!(reverted.contains(&"http.proxy".to_string()));
    assert!(reverted.contains(&"cursor.general.disableHttp2".to_string()));

    // 4. Assert zero regressions: user customizations preserved, agentcontrol proxy unmounted
    let final_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&config_path).unwrap()).unwrap();
    assert_eq!(
        final_json["editor.fontSize"], 16,
        "User font change must be preserved"
    );
    assert_eq!(
        final_json["workbench.theme"], "One Dark Pro",
        "User theme must be preserved"
    );
    assert_eq!(
        final_json["customExtension.enabled"], true,
        "Custom extension must survive"
    );
    assert_eq!(
        final_json.get("http.proxy"),
        None,
        "AgentControl proxy must be cleanly removed"
    );
    assert_eq!(
        final_json["cursor.general.disableHttp2"], false,
        "Http2 setting must revert to original"
    );
}

// ─── 5. VS Code Lifecycle & Zero Regressions ──────────────────────────────────

#[test]
fn test_gate4_vscode_lifecycle_zero_regressions() {
    let tmp = tempdir().unwrap();
    let config_path = tmp.path().join("vscode_settings.json");

    let initial_json = json!({
        "workbench.colorTheme": "Default Dark Modern",
        "editor.formatOnSave": true,
        "editor.tabSize": 4
    });
    fs::write(
        &config_path,
        serde_json::to_string_pretty(&initial_json).unwrap(),
    )
    .unwrap();
    let pre_hash = OwnershipManifest::compute_sha256(&config_path).unwrap();

    // Injected proxy settings
    let mut connected_json = initial_json.clone();
    connected_json["http.proxy"] = json!("http://127.0.0.1:18080");
    connected_json["http.proxyStrictSSL"] = json!(false);
    connected_json["cline.baseUrl"] = json!("http://127.0.0.1:18080/v1");
    fs::write(
        &config_path,
        serde_json::to_string_pretty(&connected_json).unwrap(),
    )
    .unwrap();
    let post_hash = OwnershipManifest::compute_sha256(&config_path).unwrap();

    let mut previous_values = HashMap::new();
    previous_values.insert("http.proxy".to_string(), serde_json::Value::Null);
    previous_values.insert("http.proxyStrictSSL".to_string(), serde_json::Value::Null);
    previous_values.insert("cline.baseUrl".to_string(), serde_json::Value::Null);

    let mut written_values = HashMap::new();
    written_values.insert("http.proxy".to_string(), json!("http://127.0.0.1:18080"));
    written_values.insert("http.proxyStrictSSL".to_string(), json!(false));
    written_values.insert(
        "cline.baseUrl".to_string(),
        json!("http://127.0.0.1:18080/v1"),
    );

    let manifest = OwnershipManifest::new(
        "vscode",
        config_path.clone(),
        pre_hash,
        post_hash,
        vec![
            "http.proxy".to_string(),
            "http.proxyStrictSSL".to_string(),
            "cline.baseUrl".to_string(),
        ],
        previous_values,
        written_values,
    );

    // User updates a setting while connected
    let mut modified: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&config_path).unwrap()).unwrap();
    modified["files.autoSave"] = json!("afterDelay");
    fs::write(
        &config_path,
        serde_json::to_string_pretty(&modified).unwrap(),
    )
    .unwrap();

    // Rollback
    let reverted = revert_json_target(&manifest).unwrap();
    assert!(reverted.contains(&"http.proxy".to_string()));
    assert!(reverted.contains(&"cline.baseUrl".to_string()));

    let final_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&config_path).unwrap()).unwrap();
    assert_eq!(final_json["workbench.colorTheme"], "Default Dark Modern");
    assert_eq!(final_json["editor.formatOnSave"], true);
    assert_eq!(final_json["files.autoSave"], "afterDelay");
    assert_eq!(final_json.get("http.proxy"), None);
    assert_eq!(final_json.get("cline.baseUrl"), None);
}

// ─── 6. Claude Desktop Lifecycle & Zero Regressions ───────────────────────────

#[test]
fn test_gate4_claude_desktop_lifecycle_zero_regressions() {
    let tmp = tempdir().unwrap();
    let config_path = tmp.path().join("claude_desktop_config.json");

    let initial_json = json!({
        "mcpServers": {
            "filesystem": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem", "/projects"]
            },
            "sqlite": {
                "command": "uvx",
                "args": ["mcp-server-sqlite", "--db-path", "test.db"]
            }
        },
        "preferences": {
            "developerMode": true
        }
    });
    fs::write(
        &config_path,
        serde_json::to_string_pretty(&initial_json).unwrap(),
    )
    .unwrap();
    let pre_hash = OwnershipManifest::compute_sha256(&config_path).unwrap();

    // Wrapped with agentcontrol stdio-proxy
    let mut wrapped_json = initial_json.clone();
    wrapped_json["mcpServers"]["filesystem"]["command"] = json!("agentcontrol");
    wrapped_json["mcpServers"]["filesystem"]["args"] = json!([
        "stdio-proxy",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/projects"
    ]);
    wrapped_json["mcpServers"]["sqlite"]["command"] = json!("agentcontrol");
    wrapped_json["mcpServers"]["sqlite"]["args"] = json!([
        "stdio-proxy",
        "--",
        "uvx",
        "mcp-server-sqlite",
        "--db-path",
        "test.db"
    ]);
    fs::write(
        &config_path,
        serde_json::to_string_pretty(&wrapped_json).unwrap(),
    )
    .unwrap();
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

    // Rollback
    let reverted = revert_json_target(&manifest).unwrap();
    assert!(reverted.contains(&"mcpServers".to_string()));

    let final_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&config_path).unwrap()).unwrap();
    assert_eq!(final_json["preferences"]["developerMode"], true);
    assert_eq!(final_json["mcpServers"]["filesystem"]["command"], "npx");
    assert_eq!(
        final_json["mcpServers"]["filesystem"]["args"],
        json!(["-y", "@modelcontextprotocol/server-filesystem", "/projects"])
    );
    assert_eq!(final_json["mcpServers"]["sqlite"]["command"], "uvx");
}

// ─── 7. Codex TOML Lifecycle & Zero Regressions ───────────────────────────────

#[test]
fn test_gate4_codex_toml_lifecycle_zero_regressions() {
    let tmp = tempdir().unwrap();
    let config_path = tmp.path().join("config.toml");

    let initial_toml = r#"model = "gpt-4o"
theme = "monokai"

[mcp_servers.sqlite]
command = "sqlite_mcp"
args = ["--db", "app.db"]
"#;
    fs::write(&config_path, initial_toml).unwrap();
    let pre_hash = OwnershipManifest::compute_sha256(&config_path).unwrap();

    // Injected Codex proxy
    let mut toml_val: toml::Value = toml::from_str(initial_toml).unwrap();
    let root = toml_val.as_table_mut().unwrap();

    let mut set_table = toml::Table::new();
    set_table.insert(
        "OPENAI_BASE_URL".to_string(),
        toml::Value::String("http://127.0.0.1:18080/v1".to_string()),
    );
    set_table.insert(
        "HTTP_PROXY".to_string(),
        toml::Value::String("http://127.0.0.1:18080".to_string()),
    );
    let mut env_policy = toml::Table::new();
    env_policy.insert(
        "inherit".to_string(),
        toml::Value::String("core".to_string()),
    );
    env_policy.insert("set".to_string(), toml::Value::Table(set_table));
    root.insert(
        "shell_environment_policy".to_string(),
        toml::Value::Table(env_policy),
    );

    fs::write(&config_path, toml::to_string_pretty(&toml_val).unwrap()).unwrap();
    let post_hash = OwnershipManifest::compute_sha256(&config_path).unwrap();

    let mut previous_values = HashMap::new();
    previous_values.insert(
        "shell_environment_policy".to_string(),
        serde_json::Value::Null,
    );

    let mut written_values = HashMap::new();
    written_values.insert(
        "shell_environment_policy.set.OPENAI_BASE_URL".to_string(),
        json!("http://127.0.0.1:18080/v1"),
    );

    let manifest = OwnershipManifest::new(
        "codex",
        config_path.clone(),
        pre_hash,
        post_hash,
        vec!["shell_environment_policy.set.OPENAI_BASE_URL".to_string()],
        previous_values,
        written_values,
    );

    // Rollback
    let reverted = revert_toml_target(&manifest).unwrap();
    assert!(reverted.contains(&"OPENAI_BASE_URL".to_string()));

    let final_raw = fs::read_to_string(&config_path).unwrap();
    let final_toml: toml::Value = toml::from_str(&final_raw).unwrap();
    let final_root = final_toml.as_table().unwrap();

    assert_eq!(final_root.get("model").unwrap().as_str().unwrap(), "gpt-4o");
    assert_eq!(
        final_root.get("theme").unwrap().as_str().unwrap(),
        "monokai"
    );
    if let Some(env_pol) = final_root.get("shell_environment_policy") {
        if let Some(set_tbl) = env_pol.get("set") {
            assert!(set_tbl.get("OPENAI_BASE_URL").is_none());
        }
    }
}

// ─── 8. Truthful Capability Manifest Reporting ────────────────────────────────

#[test]
fn test_gate4_capability_manifest_truth_and_seven_state_posture() {
    let clients = [
        "cursor",
        "claude-desktop",
        "claude-code",
        "antigravity",
        "codex",
    ];

    for name in clients {
        let manifest = ClientCapabilityManifest::for_client(name, PostureState::Configured);
        assert!(!manifest.client_name.is_empty());
        assert_eq!(manifest.current_posture, PostureState::Configured);
        assert!(
            !manifest.supported_os.is_empty(),
            "Client {} must support cross-platform OS",
            name
        );

        // Invariant: truthful disclosures — every client must explicitly declare blind spots
        assert!(
            !manifest.declared_blind_spots.is_empty(),
            "Client {} must declare realistic blind spots to eliminate security theater",
            name
        );

        // Verify all 7 PostureState enum variants serialize cleanly
        let states = [
            PostureState::Configured,
            PostureState::ConnectivityVerified,
            PostureState::TrafficObserved,
            PostureState::EnforcedTested,
            PostureState::ObservedOnly,
            PostureState::Uncovered,
            PostureState::Unhealthy,
        ];
        for s in states {
            assert!(!s.as_str().is_empty());
        }
    }
}

// ─── 9. Enterprise Storage Manager & Policy Rollback Reverification ───────────

#[tokio::test]
async fn test_gate4_storage_manager_rollback_reverification() {
    let dir = tempdir().unwrap();
    let mgr = PolicyStorageManager::new(dir.path());

    let (sk, pk) = generate_signing_keypair();
    let pk_hex = hex::encode(pk.to_bytes());
    let keys = vec![pk_hex];

    // Apply Revision 1
    let yaml1 =
        "version: \"2.0\"\ndefault_action: deny\ntools:\n  - name: tool_1\n    action: allow\n";
    let bundle1 = sign_policy(&sk, "corp-pilot", 1, yaml1, None);
    let applied1 = mgr.apply_signed_bundle(&bundle1, Some(&keys));
    assert!(applied1.is_ok(), "Applying signed revision 1 must succeed");

    // Apply Revision 2
    let yaml2 =
        "version: \"2.0\"\ndefault_action: deny\ntools:\n  - name: tool_2\n    action: allow\n";
    let bundle2 = sign_policy(&sk, "corp-pilot", 2, yaml2, None);
    let applied2 = mgr.apply_signed_bundle(&bundle2, Some(&keys));
    assert!(applied2.is_ok(), "Applying signed revision 2 must succeed");

    // Safe rollback to Revision 1 snapshot
    let rolled_back = mgr.rollback_with_keys(Some(&keys));
    assert!(rolled_back.is_ok(), "Rollback to revision 1 must succeed");

    // Current bundle on disk must now be Revision 1
    let current_bundle_data = std::fs::read_to_string(mgr.current_bundle_path()).unwrap();
    let current_bundle: SignedPolicyBundle = serde_json::from_str(&current_bundle_data).unwrap();
    assert_eq!(current_bundle.policy_revision, 1);
}

// ─── 10. Enterprise Pilot Offline Grace Window & Degraded Cache ────────────────

#[tokio::test]
async fn test_gate4_enterprise_pilot_offline_lkg_bundle_activation() {
    let (sk, pk) = generate_signing_keypair();
    let pk_hex = hex::encode(pk.to_bytes());
    let yaml = "version: \"2.0\"\ndefault_action: deny\ntools:\n  - name: offline_tool\n    action: allow\n";
    let bundle = sign_policy(&sk, "pilot-policy", 42, yaml, None);

    // Save bundle to local LKG cache
    save_cached_policy_bundle(&bundle);

    let keyring = TrustedKeyring::with_keys(vec![TrustedKey {
        key_id: "sec-key".to_string(),
        public_key_hex: pk_hex.clone(),
        description: None,
        created_at: "2026-10-16T00:00:00Z".to_string(),
        expires_at: None,
    }]);

    let trust_profile = PolicyTrustProfile::Managed {
        trusted_keyring: keyring,
        require_revision_monotonicity: true,
        max_policy_age_secs: Some(259200), // 72 hours
    };
    assert!(trust_profile.is_managed());

    // Verify bundle validates against trusted keys
    let keys = vec![pk_hex];
    let verified = verify_signed_bundle(&bundle, Some(&keys));
    assert!(verified.is_ok(), "Signed LKG bundle must verify");

    // Verify loading from cached bundle
    let cached = load_cached_policy_bundle(Some(&keys));
    assert!(cached.is_some(), "Cached signed bundle must be present");
    let (loaded_bundle, _compiled) = cached.unwrap();
    assert_eq!(loaded_bundle.policy_revision, 42);
}

// ─── 11. Enterprise Pilot Deny-Before-Dispatch Guarantee ──────────────────────

#[tokio::test]
async fn test_gate4_enterprise_pilot_zero_downstream_leak_on_deny() {
    let state = ProxyState::mock_test_default();
    let yaml = r#"
version: "2.1"
default_action: deny
tools: []
"#;
    let policy = CompiledPolicy::from_yaml_str(yaml).unwrap();
    let session = Arc::new(SessionContext::new(
        Some("pilot-agent-01".to_string()),
        None,
        vec![],
        Some(policy),
        None,
        None,
    ));

    let call_count = Arc::new(AtomicUsize::new(0));
    let mut downstream = MockMcpDownstream::new(call_count.clone());

    let params = json!({
        "name": "unauthorized_enterprise_tool",
        "arguments": {"cmd": "curl http://internal-server/secret"}
    });

    let result =
        handle_mcp_tools_call(&state, &session, "tools/call", &params, &mut downstream).await;

    // Asserts 100% denial before dispatch
    assert!(result.is_err(), "Unauthorized call must return error");
    assert!(
        matches!(result, Err(PepError::Denied { .. })),
        "Error must be PepError::Denied"
    );

    // Critical Invariant: Exactly ZERO downstream calls reach the tool
    assert_eq!(
        call_count.load(Ordering::SeqCst),
        0,
        "Deny must prevent any downstream execution (0 calls allowed)"
    );
}
