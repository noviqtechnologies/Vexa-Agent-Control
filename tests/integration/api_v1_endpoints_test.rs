use reqwest::Client;
use std::time::Duration;
use tokio::time::sleep;

struct ChildGuard(tokio::process::Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.start_kill();
    }
}

#[tokio::test]
async fn test_api_v1_endpoints() {
    let listen_addr = "127.0.0.1:8089";

    let bin = env!("CARGO_BIN_EXE_agentcontrol");
    let mut guard = ChildGuard(
        tokio::process::Command::new(bin)
            .arg("dev")
            .arg("--listen")
            .arg(listen_addr)
            .arg("--mcp-url")
            .arg("http://127.0.0.1:3000")
            .arg("--no-browser")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("Failed to start agentcontrol dev server"),
    );

    sleep(Duration::from_secs(4)).await;

    let client = Client::new();

    // 1. Test GET /api/v1/status
    let res = client
        .get(format!("http://{}/api/v1/status", listen_addr))
        .send()
        .await
        .expect("Failed to GET /api/v1/status");

    assert_eq!(res.status(), 200);
    let json: serde_json::Value = res.json().await.unwrap();
    assert_eq!(json.get("status").and_then(|v| v.as_str()), Some("active"));
    assert!(json.get("version").is_some());

    // 2. Test POST /api/v1/hitl/respond
    let hitl_payload = serde_json::json!({
        "request_id": "req-test-999",
        "decision": "approve"
    });
    let res = client
        .post(format!("http://{}/api/v1/hitl/respond", listen_addr))
        .json(&hitl_payload)
        .send()
        .await
        .expect("Failed to POST /api/v1/hitl/respond");

    assert_eq!(res.status(), 200);
    let hitl_json: serde_json::Value = res.json().await.unwrap();
    assert_eq!(hitl_json.get("status").and_then(|v| v.as_str()), Some("processed"));
    assert_eq!(hitl_json.get("request_id").and_then(|v| v.as_str()), Some("req-test-999"));
    assert_eq!(hitl_json.get("decision").and_then(|v| v.as_str()), Some("approve"));

    let _ = guard.0.kill().await;
}
