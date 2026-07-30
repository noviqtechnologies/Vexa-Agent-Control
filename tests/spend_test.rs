use agentwall::spend::{
    SpendLedger, SpendCheckResult,
};
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
    let res = ledger.check_and_increment(
        "agent123".to_string(),
        vec!["group1".to_string()],
        100
    ).await;
    
    assert!(matches!(res, SpendCheckResult::NoBudgetConfigured));
    
    // 2. We can simulate DB unavailability by passing an invalid agent id if we wanted,
    // but the basic test is just to ensure it compiles and runs.
}
