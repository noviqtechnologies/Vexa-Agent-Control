use agentcontrol::audit::logger::AuditEntry;
use agentcontrol::audit::outbox::DurableOutbox;

#[tokio::test]
async fn test_durable_outbox_enqueue() {
    let outbox = DurableOutbox::new(None, None, 100, 2);

    let entry = AuditEntry {
        ts: chrono::Utc::now().to_rfc3339(),
        session_id: "test-session-outbox".to_string(),
        event: "tool_allow".to_string(),
        tool_name: Some("read_file".to_string()),
        params_hash: None,
        params: None,
        reason: None,
        latency_ms: Some(1.5),
        identity_sub: Some("user-1".to_string()),
        identity_email: Some("user@test.local".to_string()),
        policy_hash: None,
        request_ip: Some("127.0.0.1".to_string()),
        matched_group_id: None,
        entry_index: 0,
        prev_hmac: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        hmac: Some("abcdef1234567890".to_string()),
    };

    let enqueued = outbox.enqueue(entry);
    assert!(enqueued);
    assert_eq!(outbox.enqueued_count.load(std::sync::atomic::Ordering::Relaxed), 1);
}
