//! Asynchronous HTTP client for transmitting telemetry, events, alerts, and snapshots to the Control Plane Dashboard.

use control_plane_proto::alert::RedactedAlert;
use control_plane_proto::event::RedactedEvent;
use control_plane_proto::mcp_server::McpServerSnapshot;
use serde::Serialize;

/// A structured LLM request log entry sent to the control hub Request Logs tab.
#[derive(Debug, Clone, Serialize)]
pub struct LlmRequestLog {
    pub request_id: String,
    pub session_id: String,
    pub key_hash: Option<String>,
    pub model: String,
    pub provider: String,
    pub is_streaming: bool,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub total_tokens: i64,
    pub latency_ms: f64,
    pub status_code: u16,
    pub verdict: String,
    pub identity_sub: Option<String>,
    pub identity_email: Option<String>,
    pub request_ip: Option<String>,
    pub timestamp_ms: i64,
    pub is_estimated: bool,
    pub protocol: String,
}

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
        let base_url = crate::identity::device::load_hub_url()
            .unwrap_or_else(|| "https://console.vexasec.io".to_string());
        if base_url.trim().is_empty() {
            return None;
        }

        let auth_token = if let Some(token) = crate::identity::device::load_device_token() {
            token
        } else if let Ok(secret) = std::env::var("GATEWAY_SECRET") {
            let s = secret.trim().to_string();
            if !s.is_empty() {
                s
            } else {
                crate::identity::device::DeviceIdentity::load_or_create()
                    .ok()
                    .map(|id| id.device_id)
                    .unwrap_or_else(|| "gw-default".to_string())
            }
        } else if let Ok(admin_token) = std::env::var("AGENTCONTROL_ADMIN_TOKEN") {
            let s = admin_token.trim().to_string();
            if !s.is_empty() {
                s
            } else {
                crate::identity::device::DeviceIdentity::load_or_create()
                    .ok()
                    .map(|id| id.device_id)
                    .unwrap_or_else(|| "gw-default".to_string())
            }
        } else {
            crate::identity::device::DeviceIdentity::load_or_create()
                .ok()
                .map(|id| id.device_id)
                .unwrap_or_else(|| "gw-default".to_string())
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

    /// Asynchronously transmits a structured LLM request log to the control hub Request Logs ingest endpoint.
    /// This populates the "Request Logs" tab in the AgentControl Console / Vexa Console.
    pub fn send_llm_request_log(&self, log: LlmRequestLog) {
        let url = format!("{}/api/v1/ingest/request-logs", self.base_url);
        let req = self
            .http
            .post(&url)
            .header("Authorization", &self.secret)
            .json(&log);

        tokio::spawn(async move {
            match req.send().await {
                Ok(resp) if resp.status().is_success() => {
                    crate::logging::log_event(
                        crate::logging::Level::Debug,
                        "request_log_sent",
                        serde_json::json!({"request_id": log.request_id, "status": resp.status().as_u16()}),
                    );
                }
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let body = resp.text().await.unwrap_or_default();
                    crate::logging::log_event(
                        crate::logging::Level::Warn,
                        "request_log_send_rejected",
                        serde_json::json!({"status": status, "request_id": log.request_id, "body": body}),
                    );
                }
                Err(e) => {
                    crate::logging::log_event(
                        crate::logging::Level::Warn,
                        "request_log_send_failed",
                        serde_json::json!({"error": e.to_string(), "request_id": log.request_id}),
                    );
                }
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
        let count = snapshot.servers.len();
        let agent_id = snapshot.agent_id.clone();
        let req = self
            .http
            .post(&url)
            .header("Authorization", &self.secret)
            .json(&snapshot);

        let send_fut = async move {
            match req.send().await {
                Ok(res) if res.status().is_success() => {
                    crate::service::eventlog::log_info(
                        1004,
                        &format!(
                            "MCP server snapshot ({} servers) accepted by Hub for agent {}",
                            count, agent_id
                        ),
                    );
                }
                Ok(res) => {
                    let status = res.status().as_u16();
                    let level = if status == 401 || status == 403 || status == 404 {
                        crate::logging::Level::Debug
                    } else {
                        crate::logging::Level::Warn
                    };
                    crate::logging::log_event(
                        level,
                        "mcp_server_snapshot_rejected",
                        serde_json::json!({"status": status, "agent_id": &agent_id}),
                    );
                    if status != 401 && status != 403 && status != 404 {
                        crate::service::eventlog::log_warn(
                            1005,
                            &format!(
                                "MCP server snapshot rejected by Hub with HTTP status: {}",
                                status
                            ),
                        );
                    }
                }
                Err(e) => {
                    let err_str = e.to_string();
                    crate::logging::log_event(
                        crate::logging::Level::Warn,
                        "mcp_server_snapshot_failed",
                        serde_json::json!({"error": &err_str, "agent_id": &agent_id}),
                    );
                    crate::service::eventlog::log_error(
                        1006,
                        &format!(
                            "Failed to connect to Hub for MCP server snapshot: {}",
                            err_str
                        ),
                    );
                }
            }
        };

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let _ = tokio::task::block_in_place(|| handle.block_on(send_fut));
        } else if let Ok(rt) = tokio::runtime::Runtime::new() {
            let _ = rt.block_on(send_fut);
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
