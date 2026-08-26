use crate::wrap::ide_config::{scan_all_ides, IdeConfigStatus};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TamperEventPayload {
    pub ide_name: String,
    pub event_type: String,
    pub tamper_details: String,
    pub healed_successfully: bool,
    pub occurred_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryHeartbeatRequest {
    pub device_id: String,
    pub overall_compliance: String,
    pub ide_targets: Vec<IdeConfigStatus>,
    pub tamper_events: Vec<TamperEventPayload>,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryHeartbeatResponse {
    pub acknowledged: bool,
    pub next_heartbeat_interval_seconds: Option<u64>,
    pub policy_version: Option<String>,
}

pub struct TelemetryClient {
    hub_url: String,
    device_id: String,
    client: reqwest::Client,
}

impl TelemetryClient {
    pub fn new(hub_url: String, device_id: String) -> Self {
        Self {
            hub_url,
            device_id,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
        }
    }

    pub async fn push_heartbeat(
        &self,
        proxy_url: &str,
        tamper_events: Vec<TamperEventPayload>,
    ) -> Result<TelemetryHeartbeatResponse, String> {
        let ide_statuses = scan_all_ides(proxy_url);

        let overall = if ide_statuses.iter().any(|s| s.compliance_state == "BYPASSED") {
            "NON_COMPLIANT"
        } else {
            "COMPLIANT"
        };

        let req_body = TelemetryHeartbeatRequest {
            device_id: self.device_id.clone(),
            overall_compliance: overall.to_string(),
            ide_targets: ide_statuses,
            tamper_events,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        let endpoint = format!("{}/api/v1/devices/{}/telemetry", self.hub_url, self.device_id);
        let gateway_secret = std::env::var("GATEWAY_SECRET").ok();

        let mut req_builder = self.client.post(&endpoint);
        if let Some(ref sec) = gateway_secret {
            req_builder = req_builder.header("Authorization", format!("Bearer {}", sec));
        } else {
            req_builder = req_builder.header("Authorization", format!("Bearer {}", self.device_id));
        }

        let resp = req_builder
            .json(&req_body)
            .send()
            .await
            .map_err(|e| format!("HTTP error pushing heartbeat: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(format!("Hub returned error {}: {}", status, text));
        }

        resp.json::<TelemetryHeartbeatResponse>()
            .await
            .map_err(|e| format!("JSON decode error: {}", e))
    }
}
