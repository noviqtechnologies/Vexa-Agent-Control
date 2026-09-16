//! Unit tests for CLI surface compliance, canonical commands, port standardization,
//! and structured diagnostic/status contracts (PRD §2.1, §5.1, §5.3).

use clap::{CommandFactory, Parser};
use agentcontrol::cli::{CacheCommands, Cli, Commands};
use agentcontrol::doctor::{run_diagnostics, DiagnosticCheck, DiagnosticStatus, DoctorReport};
use agentcontrol::wrap::status::{FreshnessTier, StatusEndpoints, StatusReport, TargetState, TargetStatusDetails};

#[test]
fn test_cli_canonical_commands_visible() {
    let cmd = Cli::command();
    let subcommands: Vec<_> = cmd.get_subcommands().collect();

    let canonical_names = vec![
        "login",
        "connect",
        "disconnect",
        "status",
        "start",
        "doctor",
        "repair",
        "logout",
        "service",
        "test",
        "scan",
        "verify",
    ];

    for name in canonical_names {
        let sub = subcommands
            .iter()
            .find(|s| s.get_name() == name)
            .unwrap_or_else(|| panic!("Expected canonical subcommand '{}' to exist", name));
        assert!(
            !sub.is_hide_set(),
            "Canonical subcommand '{}' should NOT be hidden in --help",
            name
        );
    }
}

#[test]
fn test_cli_legacy_commands_hidden_but_functional() {
    let cmd = Cli::command();
    let subcommands: Vec<_> = cmd.get_subcommands().collect();

    #[allow(unused_mut)]
    let mut legacy_names = vec![
        "dev",
        "wrap",
        "unwrap",
        "protect",
        "unprotect",
        "watch",
        "enroll",
        "validate",
        "lint",
        "stdio-proxy",
    ];

    #[cfg(feature = "team")]
    legacy_names.push("join");

    for name in legacy_names {
        let sub = subcommands
            .iter()
            .find(|s| s.get_name() == name)
            .unwrap_or_else(|| panic!("Expected backwards-compatible subcommand '{}' to exist", name));
        assert!(
            sub.is_hide_set(),
            "Legacy subcommand '{}' MUST be hidden in --help",
            name
        );
    }

    // Verify backward compatibility: legacy commands can still be parsed
    let parsed_wrap = Cli::try_parse_from(["agentcontrol", "wrap"]);
    assert!(parsed_wrap.is_ok(), "Hidden legacy 'wrap' must parse successfully");

    let parsed_validate = Cli::try_parse_from([
        "agentcontrol",
        "validate",
        "--policy",
        "policy.yaml",
        "--tool",
        "ping",
        "--payload",
        "payload.json",
    ]);
    assert!(parsed_validate.is_ok(), "Hidden legacy 'validate' must parse successfully");
}

#[test]
fn test_cli_status_json_flag_parsing() {
    // Default: json is false
    let parsed_default = Cli::try_parse_from(["agentcontrol", "status"]).unwrap();
    match *parsed_default.command {
        Commands::Status { json } => assert!(!json, "Expected status json flag to be false by default"),
        _ => panic!("Expected Commands::Status"),
    }

    // Explicit: --json is true
    let parsed_json = Cli::try_parse_from(["agentcontrol", "status", "--json"]).unwrap();
    match *parsed_json.command {
        Commands::Status { json } => assert!(json, "Expected status json flag to be true with --json"),
        _ => panic!("Expected Commands::Status"),
    }
}

#[test]
fn test_cli_port_18080_standardization() {
    // Start default listen address
    let parsed_start = Cli::try_parse_from(["agentcontrol", "start"]).unwrap();
    match *parsed_start.command {
        Commands::Start(args) => {
            assert_eq!(
                args.listen, "127.0.0.1:18080",
                "Start listen address must default to canonical 18080"
            );
        }
        _ => panic!("Expected Commands::Start"),
    }

    // Cache status default gateway
    let parsed_cache = Cli::try_parse_from(["agentcontrol", "cache", "status"]).unwrap();
    match *parsed_cache.command {
        Commands::Cache {
            command: CacheCommands::Status { gateway, .. },
        } => {
            assert_eq!(
                gateway, "http://127.0.0.1:18080",
                "Cache status gateway must default to canonical 18080"
            );
        }
        _ => panic!("Expected Commands::Cache with CacheCommands::Status"),
    }

    // Dev listen address default
    let parsed_dev = Cli::try_parse_from(["agentcontrol", "dev"]).unwrap();
    match *parsed_dev.command {
        Commands::Dev { listen, .. } => {
            assert_eq!(
                listen, "127.0.0.1:18080",
                "Dev listen address must default to canonical 18080"
            );
        }
        _ => panic!("Expected Commands::Dev"),
    }

    // Protect listen address default
    let parsed_protect = Cli::try_parse_from(["agentcontrol", "protect"]).unwrap();
    match *parsed_protect.command {
        Commands::Protect { listen, .. } => {
            assert_eq!(
                listen, "127.0.0.1:18080",
                "Protect listen address must default to canonical 18080"
            );
        }
        _ => panic!("Expected Commands::Protect"),
    }
}

#[test]
fn test_status_report_serialization_and_disclosures() {
    let report = StatusReport {
        version: "1.0.84".to_string(),
        timestamp: "2026-09-14T00:00:00Z".to_string(),
        targets: vec![TargetStatusDetails {
            target: "Claude Desktop".to_string(),
            config_path: "C:\\Users\\test\\claude_desktop_config.json".to_string(),
            exists: true,
            states: vec![TargetState::Detected, TargetState::McpWrapped],
            llm_routing: "DIRECT_CLOUD".to_string(),
            mcp_governance: "WRAPPED (2/2)".to_string(),
            freshness: FreshnessTier::ActiveFresh.label().to_string(),
            total_servers: 2,
            wrapped_servers: 2,
            disclosures: vec!["LLM completions route directly to Anthropic Cloud".to_string()],
        }],
        endpoints: StatusEndpoints {
            default_proxy_url: "http://127.0.0.1:18080/v1".to_string(),
            hub_url: "https://app.vexasec.io".to_string(),
            device_enrolled: true,
        },
        global_disclosures: vec![
            "Native shell execution (bash/git) is UNGOVERNED by local proxy across all targets.".to_string(),
            "Workstation developers can configure personal API keys in environment variables (Bypass Possible).".to_string(),
            "Binary 'COMPLIANT' state is retired; independent capability states reflect actual workstation posture.".to_string(),
        ],
    };

    let serialized = serde_json::to_string_pretty(&report).expect("StatusReport serialization failed");
    assert!(serialized.contains("\"Claude Desktop\""));
    assert!(serialized.contains("DIRECT_CLOUD"));
    assert!(serialized.contains("http://127.0.0.1:18080/v1"));
    assert!(serialized.contains("Native shell execution (bash/git) is UNGOVERNED"));

    let deserialized: StatusReport = serde_json::from_str(&serialized).expect("StatusReport deserialization failed");
    assert_eq!(deserialized.version, "1.0.84");
    assert_eq!(deserialized.targets.len(), 1);
    assert_eq!(deserialized.targets[0].wrapped_servers, 2);
    assert_eq!(deserialized.global_disclosures.len(), 3);
}

#[test]
fn test_doctor_report_remediation_and_exit_code_contract() {
    let mut report = DoctorReport::new();
    assert_eq!(report.overall_status, DiagnosticStatus::Pass);
    assert_eq!(report.exit_code, 0);

    // Adding Pass check retains 0
    report.add_check(DiagnosticCheck {
        category: "Binary".to_string(),
        name: "Binary Integrity".to_string(),
        status: DiagnosticStatus::Pass,
        message: "Binary matches manifest".to_string(),
        details: None,
        remediation: None,
    });
    assert_eq!(report.overall_status, DiagnosticStatus::Pass);
    assert_eq!(report.exit_code, 0);

    // Adding Warn check elevates exit_code to 2 (Warn/Degraded)
    report.add_check(DiagnosticCheck {
        category: "Auth".to_string(),
        name: "Hub Enrollment".to_string(),
        status: DiagnosticStatus::Warn,
        message: "Device not enrolled".to_string(),
        details: None,
        remediation: Some("Run: agentcontrol login".to_string()),
    });
    assert_eq!(report.overall_status, DiagnosticStatus::Warn);
    assert_eq!(report.exit_code, 2);

    // Adding Fail check elevates exit_code to 1 (Critical Failure)
    report.add_check(DiagnosticCheck {
        category: "Gateway".to_string(),
        name: "Daemon Liveness".to_string(),
        status: DiagnosticStatus::Fail,
        message: "Local gateway down".to_string(),
        details: None,
        remediation: Some("Run: agentcontrol start".to_string()),
    });
    assert_eq!(report.overall_status, DiagnosticStatus::Fail);
    assert_eq!(report.exit_code, 1);

    // JSON serialization check
    let json_str = serde_json::to_string(&report).expect("DoctorReport serialization failed");
    assert!(json_str.contains("\"remediation\":\"Run: agentcontrol login\""));
    assert!(json_str.contains("\"remediation\":\"Run: agentcontrol start\""));
    assert!(json_str.contains("\"exit_code\":1"));
}

#[tokio::test]
async fn test_doctor_run_diagnostics_executes_safely() {
    let report = run_diagnostics().await;
    assert!(!report.checks.is_empty(), "Doctor should execute multiple diagnostic checks");
    assert!(!report.version.is_empty());
    assert!(!report.os.is_empty());

    // Check that every failed or warning check includes an actionable remediation
    for check in &report.checks {
        if check.status == DiagnosticStatus::Fail || check.status == DiagnosticStatus::Warn {
            assert!(
                check.remediation.is_some(),
                "Diagnostic check '{}' in status {:?} must have an actionable remediation string",
                check.name,
                check.status
            );
        }
    }
}
