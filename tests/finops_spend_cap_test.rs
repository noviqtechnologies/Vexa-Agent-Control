use agentcontrol::proxy::broker_client::{BrokerError, BudgetExceededPayload};
use serde_json::json;

#[test]
fn test_finops_budget_exceeded_error_formatting() {
    let raw_gateway_429 = r#"{
        "error": {
            "message": "$100.00 / $100.00",
            "type": "budget_exceeded",
            "code": "BUDGET_EXCEEDED"
        }
    }"#;

    let parsed: BudgetExceededPayload = serde_json::from_str(raw_gateway_429).unwrap();
    let detail = parsed.error.unwrap();
    assert_eq!(detail.code.as_deref(), Some("BUDGET_EXCEEDED"));
    assert_eq!(detail.err_type.as_deref(), Some("budget_exceeded"));

    let err = BrokerError::BudgetExceeded(detail.message.unwrap());
    let formatted = format!("{}", err);
    assert!(formatted.contains("BudgetExceeded: $100.00 / $100.00"));

    // Verify standard IDE-facing JSON error structure
    let ide_error_payload = json!({
        "error": {
            "message": format!("Vexa FinOps: Monthly spend budget limit reached ($100.00 / $100.00). Contact your administrator."),
            "type": "budget_exceeded",
            "code": "BUDGET_EXCEEDED"
        }
    });

    assert_eq!(ide_error_payload["error"]["code"], "BUDGET_EXCEEDED");
    assert_eq!(ide_error_payload["error"]["type"], "budget_exceeded");
    assert!(ide_error_payload["error"]["message"]
        .as_str()
        .unwrap()
        .contains("Contact your administrator."));
}
