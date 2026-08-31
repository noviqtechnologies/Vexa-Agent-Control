use agentcontrol::spend::{SpendCheckResult, SpendLedger};
use tempfile::tempdir;

#[tokio::test]
async fn test_spend_ledger_basic() {
    let dir = tempdir().unwrap();
    let _db_path = dir.path().join("events.db");

    std::env::set_var("HOME", dir.path());
    std::env::set_var("USERPROFILE", dir.path()); // for windows

    let ledger = SpendLedger::init(None);

    // Wait a bit for the actor thread to create the DB and tables
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // 1. Initial check (no budget limits set)
    let res = ledger
        .check_and_increment("agent123".to_string(), vec!["group1".to_string()], 100)
        .await;

    assert!(matches!(res, SpendCheckResult::NoBudgetConfigured));

    // 2. We can simulate DB unavailability by passing an invalid agent id if we wanted,
    // but the basic test is just to ensure it compiles and runs.
}

#[test]
fn test_money_microcents_math_and_serde() {
    use agentcontrol::spend::types::{MoneyMicrocents, InputTokens, OutputTokens, SpendV2AuthorizeReq};

    let ten_dollars = MoneyMicrocents::from_dollars(10.0);
    assert_eq!(ten_dollars.as_microcents(), 1_000_000_000);
    assert_eq!(ten_dollars.to_dollars(), 10.0);

    let two_cents = MoneyMicrocents::from_dollars(0.02);
    assert_eq!(two_cents.as_microcents(), 2_000_000);

    let sum = ten_dollars + two_cents;
    assert_eq!(sum.as_microcents(), 1_002_000_000);

    let diff = ten_dollars - two_cents;
    assert_eq!(diff.as_microcents(), 998_000_000);

    let in_tokens = InputTokens(1500);
    let out_tokens = OutputTokens(800);
    assert_eq!(in_tokens.0, 1500);
    assert_eq!(out_tokens.0, 800);

    // Test serialization / deserialization of SpendV2AuthorizeReq
    let req = SpendV2AuthorizeReq {
        gateway_id: Some("gw-test".to_string()),
        request_id: "req-123".to_string(),
        idempotency_key: "auth-123".to_string(),
        project_id: "proj-1".to_string(),
        provider: "openai".to_string(),
        model: "gpt-4o".to_string(),
        input_token_estimate: 500,
        max_output_tokens: 1000,
        request_hash: "hash123".to_string(),
    };

    let json_str = serde_json::to_string(&req).expect("serialize req");
    let deserialized: SpendV2AuthorizeReq = serde_json::from_str(&json_str).expect("deserialize req");
    assert_eq!(deserialized.request_id, "req-123");
    assert_eq!(deserialized.model, "gpt-4o");
    assert_eq!(deserialized.max_output_tokens, 1000);
}
