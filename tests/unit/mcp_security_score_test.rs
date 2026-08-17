//! Unit test suite for FR-303: Verified MCP Security Scoring Engine

use agentcontrol::policy::mcp_score::McpScorer;

#[test]
fn test_mcp_security_scorer_safe_tool() {
    let score = McpScorer::evaluate_server(
        "safe_mcp_server",
        &vec!["/var/app/data".to_string()],
        false,
        2,
    );
    assert_eq!(score.score, 100);
    assert_eq!(score.risk_level, "LOW");
    assert!(score.vulnerability_flags.is_empty());
}

#[test]
fn test_mcp_security_scorer_dangerous_tool() {
    let score = McpScorer::evaluate_server(
        "dangerous_mcp_server",
        &vec!["/".to_string()],
        true,
        12,
    );
    assert!(score.score <= 50);
    assert_eq!(score.risk_level, "HIGH");
    assert!(score.vulnerability_flags.contains(&"UNRESTRICTED_ROOT_OR_TRAVERSAL_PATH".to_string()));
    assert!(score.vulnerability_flags.contains(&"EXTERNAL_NETWORK_EGRESS_ENABLED".to_string()));
}
