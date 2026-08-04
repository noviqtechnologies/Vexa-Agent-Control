//! Unit test suite for FR-301: Passive "Shadow AI" Discovery Mode & Risk Delta Reporting

use agentwall::proxy::tunnel::HardenedEgressTunnel;

#[test]
fn test_shadow_mode_hypothetical_verdict() {
    let tunnel = HardenedEgressTunnel::new(true); // shadow_mode = true
    let mut frame = agentwall::proxy::tunnel::TunneledFrame {
        session_id: "shadow-session-1".to_string(),
        payload: "Attempting secret leak sk-live-9999999".to_string(),
        is_binary: false,
        timestamp_ms: 500,
    };

    let redacted = tunnel.process_frame(&mut frame).unwrap();
    // In shadow mode, payload is NOT altered (redacted returns false), but logged
    assert!(!redacted);
    assert!(frame.payload.contains("sk-live-9999999"));
}
