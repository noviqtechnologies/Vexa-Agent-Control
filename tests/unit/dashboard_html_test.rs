use agentcontrol::local_dashboard::local_dashboard_html as dashboard_html;

#[test]
fn test_dashboard_html_is_embedded() {
    let html = dashboard_html();
    assert!(!html.is_empty(), "Dashboard HTML should not be empty");
    assert!(
        html.contains("<!DOCTYPE html>"),
        "Dashboard HTML should contain doctype"
    );
    assert!(
        html.contains("panel-overview"),
        "Dashboard HTML should contain overview view"
    );
    assert!(
        html.contains("panel-presets"),
        "Dashboard HTML should contain guardrail presets view"
    );
    assert!(
        html.contains("panel-detections"),
        "Dashboard HTML should contain detections view"
    );
    assert!(
        html.contains("panel-policy-rules"),
        "Dashboard HTML should contain policy rules view"
    );
    assert!(
        html.contains("panel-virtual-keys"),
        "Dashboard HTML should contain virtual keys view"
    );
    assert!(
        html.contains("panel-llm-providers"),
        "Dashboard HTML should contain LLM providers view"
    );
    assert!(
        html.contains("panel-mcp-servers"),
        "Dashboard HTML should contain MCP servers view"
    );
    assert!(
        html.contains("panel-devices"),
        "Dashboard HTML should contain connected devices view"
    );
    assert!(
        html.contains("panel-cost-budgets"),
        "Dashboard HTML should contain cost & budgets view"
    );
    assert!(
        html.contains("panel-audit-logs"),
        "Dashboard HTML should contain audit logs view"
    );
    assert!(
        html.contains("panel-users-hub"),
        "Dashboard HTML should contain users & roles view"
    );
    assert!(
        html.contains("panel-org-hub"),
        "Dashboard HTML should contain org & license view"
    );
    assert!(
        html.contains("panel-sso-hub"),
        "Dashboard HTML should contain SSO view"
    );
}
