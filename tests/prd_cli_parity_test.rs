//! Integration tests for PRD §12 CLI Parity and Command Dispatches.
use agentcontrol::cli::{Cli, Commands, PolicyCommands};
use agentcontrol::wrap::ConnectTarget;
use clap::Parser;

#[test]
fn test_cli_parsing_prd_core_commands() {
    // 1. status
    let cli = Cli::try_parse_from(["agentcontrol", "status"]).unwrap();
    assert!(matches!(*cli.command, Commands::Status { json: false }));

    let cli = Cli::try_parse_from(["agentcontrol", "status", "--json"]).unwrap();
    assert!(matches!(*cli.command, Commands::Status { json: true }));

    // 2. clients
    let cli = Cli::try_parse_from(["agentcontrol", "clients"]).unwrap();
    assert!(matches!(*cli.command, Commands::Clients { json: false }));

    let cli = Cli::try_parse_from(["agentcontrol", "clients", "--json"]).unwrap();
    assert!(matches!(*cli.command, Commands::Clients { json: true }));

    // 3. connect & disconnect
    let cli = Cli::try_parse_from(["agentcontrol", "connect", "cursor"]).unwrap();
    assert!(matches!(*cli.command, Commands::Connect { target: ConnectTarget::Cursor, .. }));

    let cli = Cli::try_parse_from(["agentcontrol", "disconnect", "cursor"]).unwrap();
    assert!(matches!(*cli.command, Commands::Disconnect { target: ConnectTarget::Cursor, .. }));

    // 4. policy subcommands
    let cli = Cli::try_parse_from(["agentcontrol", "policy", "init"]).unwrap();
    assert!(matches!(*cli.command, Commands::Policy { command: PolicyCommands::Init { .. } }));

    let cli = Cli::try_parse_from(["agentcontrol", "policy", "validate"]).unwrap();
    assert!(matches!(*cli.command, Commands::Policy { command: PolicyCommands::Validate { .. } }));

    let cli = Cli::try_parse_from(["agentcontrol", "policy", "show"]).unwrap();
    assert!(matches!(*cli.command, Commands::Policy { command: PolicyCommands::Show { .. } }));

    let cli = Cli::try_parse_from(["agentcontrol", "policy", "test", "--policy", "agentcontrol-policy.yaml"]).unwrap();
    assert!(matches!(*cli.command, Commands::Policy { command: PolicyCommands::Test { ref policy, .. } } if policy.as_deref() == Some("agentcontrol-policy.yaml")));

    // 5. logs
    let cli = Cli::try_parse_from(["agentcontrol", "logs", "-n", "25", "--format", "json", "--verdict", "block"]).unwrap();
    match *cli.command {
        Commands::Logs { limit, follow, ref format, ref verdict, ref tool, .. } => {
            assert_eq!(limit, 25);
            assert!(!follow);
            assert_eq!(format, "json");
            assert_eq!(verdict.as_deref(), Some("block"));
            assert_eq!(*tool, None);
        }
        _ => panic!("Expected Commands::Logs"),
    }

    // 6. approve & deny
    let cli = Cli::try_parse_from(["agentcontrol", "approve", "req-hitl-001", "--session"]).unwrap();
    assert!(matches!(*cli.command, Commands::Approve { ref id, session: true, .. } if id == "req-hitl-001"));

    let cli = Cli::try_parse_from(["agentcontrol", "deny", "req-hitl-001"]).unwrap();
    assert!(matches!(*cli.command, Commands::Deny { ref id, .. } if id == "req-hitl-001"));

    // 7. unenroll
    let cli = Cli::try_parse_from(["agentcontrol", "unenroll", "--force"]).unwrap();
    assert!(matches!(*cli.command, Commands::Unenroll { force: true }));

    // 8. stop
    let cli = Cli::try_parse_from(["agentcontrol", "stop"]).unwrap();
    assert!(matches!(*cli.command, Commands::Stop { .. }));

    // 9. doctor & support-bundle
    let cli = Cli::try_parse_from(["agentcontrol", "doctor"]).unwrap();
    assert!(matches!(*cli.command, Commands::Doctor { .. }));

    let cli = Cli::try_parse_from(["agentcontrol", "support-bundle"]).unwrap();
    assert!(matches!(*cli.command, Commands::SupportBundle { .. }));
}
