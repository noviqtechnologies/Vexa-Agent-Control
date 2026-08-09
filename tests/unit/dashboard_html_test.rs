use agentwall::local_dashboard::local_dashboard_html as dashboard_html;

#[test]
fn test_dashboard_html_is_embedded() {
    let html = dashboard_html();
    assert!(!html.is_empty(), "Dashboard HTML should not be empty");
    assert!(
        html.contains("<!DOCTYPE html>"),
        "Dashboard HTML should contain doctype"
    );
    assert!(
        html.contains("panel-inventory"),
        "Dashboard HTML should contain inventory view"
    );
    assert!(
        html.contains("panel-timeline"),
        "Dashboard HTML should contain timeline view"
    );
    assert!(
        html.contains("panel-params"),
        "Dashboard HTML should contain params view"
    );
    assert!(
        html.contains("panel-risks"),
        "Dashboard HTML should contain risks view"
    );
    assert!(
        html.contains("panel-semantic"),
        "Dashboard HTML should contain semantic view"
    );
    assert!(
        html.contains("panel-policy"),
        "Dashboard HTML should contain policy view"
    );
    assert!(
        html.contains("panel-gateway"),
        "Dashboard HTML should contain gateway controls view"
    );
    assert!(
        html.contains("panel-self-healing"),
        "Dashboard HTML should contain self-healing view"
    );
    assert!(
        html.contains("panel-egress"),
        "Dashboard HTML should contain egress view"
    );
    assert!(
        html.contains("panel-prometheus"),
        "Dashboard HTML should contain prometheus view"
    );
}
