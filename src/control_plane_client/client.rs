//! Asynchronous HTTP client for transmitting telemetry, events, alerts, and snapshots to the Control Plane Dashboard.

use control_plane_proto::alert::RedactedAlert;
use control_plane_proto::event::RedactedEvent;
use control_plane_proto::mcp_server::McpServerSnapshot;

/// HTTP client for exporting audit events, alerts, spend data, and server snapshots.
pub struct DashboardClient {
    http: reqwest::Client,
    base_url: String,
    secret: String,
}

impl DashboardClient {
    /// Constructs a `DashboardClient` from environment variables (`AGENTCONTROL_HUB_URL`, `DASHBOARD_API_URL`, `GATEWAY_SECRET`, or device token).
    ///
    /// Falls back to local dev defaults if environment variables are unset.
    pub fn from_env() -> Option<Self> {
        let base_url = std::env::var("AGENTCONTROL_HUB_URL")
            .or_else(|_| std::env::var("AGENTWALL_HUB_URL"))
            .or_else(|_| std::env::var("DASHBOARD_API_URL"))
            .unwrap_or_else(|_| "https://console.vexasec.io".to_string());
        if base_url.trim().is_empty() {
            return None;
        }

        let auth_token = if let Some(token) = crate::identity::device::load_device_token() {
            token
        } else if let Ok(secret) = std::env::var("GATEWAY_SECRET") {
            let s = secret.trim().to_string();
            if !s.is_empty() && s != "local-dev-shared-secret-change-me" {
                s
            } else {
                "local-dev-shared-secret-change-me".to_string()
            }
        } else {
            "local-dev-shared-secret-change-me".to_string()
        };

        let http = reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .ok()?;

        Some(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            secret: format!("Bearer {}", auth_token),
        })
    }

    /// Asynchronously transmits a redacted event to the dashboard ingestion endpoint.
    pub fn send_event(&self, event: RedactedEvent) {
        let url = format!("{}/api/v1/ingest/events", self.base_url);
        let req = self
            .http
            .post(&url)
            .header("Authorization", &self.secret)
            .json(&event);

        tokio::spawn(async move {
            if let Err(e) = req.send().await {
                crate::logging::log_event(
                    crate::logging::Level::Warn,
                    "dashboard_send_event_failed",
                    serde_json::json!({"error": e.to_string()}),
                );
            }
        });
    }

    /// Asynchronously transmits a redacted alert to the dashboard ingestion endpoint.
    pub fn send_alert(&self, alert: RedactedAlert) {
        let url = format!("{}/api/v1/ingest/alerts", self.base_url);
        let req = self
            .http
            .post(&url)
            .header("Authorization", &self.secret)
            .json(&alert);

        tokio::spawn(async move {
            if let Err(e) = req.send().await {
                crate::logging::log_event(
                    crate::logging::Level::Warn,
                    "dashboard_send_alert_failed",
                    serde_json::json!({"error": e.to_string()}),
                );
            }
        });
    }

    /// Asynchronously transmits a spend snapshot JSON payload to the dashboard.
    pub fn send_spend_snapshot(&self, snapshot: serde_json::Value) {
        let url = format!("{}/api/v1/ingest/spend-snapshots", self.base_url);
        let req = self
            .http
            .post(&url)
            .header("Authorization", &self.secret)
            .json(&snapshot);

        tokio::spawn(async move {
            if let Err(e) = req.send().await {
                crate::logging::log_event(
                    crate::logging::Level::Warn,
                    "dashboard_send_spend_snapshot_failed",
                    serde_json::json!({"error": e.to_string()}),
                );
            }
        });
    }

    /// Transmits an MCP server snapshot synchronously to ensure complete delivery before process termination.
    pub fn send_mcp_server_snapshot(&self, snapshot: McpServerSnapshot) {
        let url = format!("{}/api/v1/ingest/mcp-servers", self.base_url);
        let req = self
            .http
            .post(&url)
            .header("Authorization", &self.secret)
            .json(&snapshot);

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let _ =
                tokio::task::block_in_place(|| handle.block_on(async move { req.send().await }));
        } else if let Ok(rt) = tokio::runtime::Runtime::new() {
            let _ = rt.block_on(async move { req.send().await });
        }
    }

    /// Transmits a benchmark report payload synchronously to the dashboard ingestion endpoint.
    pub fn send_benchmark_report(&self, report_payload: serde_json::Value) {
        let url = format!("{}/api/v1/ingest/benchmark", self.base_url);
        let req = self
            .http
            .post(&url)
            .header("Authorization", &self.secret)
            .json(&report_payload);

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let _ =
                tokio::task::block_in_place(|| handle.block_on(async move { req.send().await }));
        } else if let Ok(rt) = tokio::runtime::Runtime::new() {
            let _ = rt.block_on(async move { req.send().await });
        }
    }
}
