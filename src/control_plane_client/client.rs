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
    /// Constructs a `DashboardClient` from environment variables (`DASHBOARD_API_URL`, `GATEWAY_SECRET`).
    ///
    /// Falls back to local dev defaults if environment variables are unset.
    pub fn from_env() -> Option<Self> {
        // Fallback to local development dashboard API URL if DASHBOARD_API_URL is not set
        let base_url = std::env::var("DASHBOARD_API_URL").unwrap_or_else(|_| {
            // LOCAL DEV FALLBACK: Connects to local docker-compose dashboard API by default
            "http://localhost:8400".to_string()
        });

        // Fallback to local development gateway secret if GATEWAY_SECRET is not set
        let secret = std::env::var("GATEWAY_SECRET").unwrap_or_else(|_| {
            // LOCAL DEV FALLBACK: Matches default secret in dashboard/docker-compose.yml
            "local-dev-shared-secret-change-me".to_string()
        });

        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("failed to build dashboard HTTP client");

        Some(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            secret: format!("Bearer {}", secret),
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
            // Block current thread to complete request before CLI process terminates
            let _ =
                tokio::task::block_in_place(|| handle.block_on(async move { req.send().await }));
        } else if let Ok(rt) = tokio::runtime::Runtime::new() {
            let _ = rt.block_on(async move { req.send().await });
        }
    }
}
