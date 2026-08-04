//! Integration test suite for FR-502: "Vexa-Scan" CLI for Developers

use agentwall::policy::mcp_score::McpScorer;

#[test]
fn test_vexa_scan_cli_execution() {
    let report = McpScorer::evaluate_server(
        "cli_scanned_server",
        &vec!["/home/dev/project".to_string()],
        false,
        4,
    );

    assert_eq!(report.server_name, "cli_scanned_server");
    assert!(report.score >= 80);
    assert_eq!(report.risk_level, "LOW");
}
