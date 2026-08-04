//! Integration test suite for FR-302 / NFR-301: Hardened Rust Egress Tunneling

use agentwall::proxy::tunnel::{HardenedEgressTunnel, TunneledFrame};

#[test]
fn test_egress_tunnel_frame_throughput_and_latency_sla() {
    let tunnel = HardenedEgressTunnel::new(false);
    let mut frame = TunneledFrame {
        session_id: "bench-session-1".to_string(),
        payload: "Normal MCP payload frame without sensitive data".to_string(),
        is_binary: false,
        timestamp_ms: 100,
    };

    let start = std::time::Instant::now();
    for _ in 0..100 {
        let _ = tunnel.process_frame(&mut frame);
    }
    let duration = start.elapsed();

    // Average latency per frame must be under 5ms SLA
    let avg_latency_ms = tunnel.metrics.average_latency_ms();
    assert!(avg_latency_ms < 5.0, "Latency SLA violated: {} ms", avg_latency_ms);
    assert!(duration.as_millis() < 500);
}
