//! Strict mTLS HTTP client connecting to `device.vexasec.io/api/v3/broker`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrokerLLMRequest {
    pub schema_version: String,
    pub request_id: String,
    pub provider: String,
    pub project_ref: String,
    pub model: String,
    pub protocol: String,
    pub stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_token_estimate: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub virtual_key: Option<String>,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrokerLLMResponse {
    pub usage: Option<serde_json::Value>,
    pub response: serde_json::Value,
}

pub struct BrokerClient {
    base_url: String,
    http_client: reqwest::Client,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetExceededPayload {
    pub error: Option<BudgetExceededDetail>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetExceededDetail {
    pub message: Option<String>,
    pub code: Option<String>,
    #[serde(rename = "type")]
    pub err_type: Option<String>,
}

#[derive(Debug)]
pub enum BrokerError {
    BudgetExceeded(String),
    Http { status: reqwest::StatusCode, body: String },
    Other(String),
}

impl std::fmt::Display for BrokerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BrokerError::BudgetExceeded(msg) => write!(f, "BudgetExceeded: {}", msg),
            BrokerError::Http { status, body } => write!(f, "Broker HTTP {}: {}", status, body),
            BrokerError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for BrokerError {}

impl BrokerClient {
    pub fn new(base_url: Option<String>) -> Self {
        let mut builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(120));

        let mut candidate_dirs = Vec::new();
        if let Some(home_dir) = dirs::home_dir() {
            candidate_dirs.push(home_dir.join(".agentcontrol"));
            candidate_dirs.push(home_dir.join(".agentwall"));
        }
        #[cfg(windows)]
        {
            candidate_dirs.push(std::path::PathBuf::from(r"C:\ProgramData\AgentControl"));
            candidate_dirs.push(std::path::PathBuf::from(
                r"C:\Windows\System32\config\systemprofile\.agentcontrol",
            ));
            let homes = crate::wrap::config_path::get_windows_user_homes();
            for h in homes {
                candidate_dirs.push(h.join(".agentcontrol"));
            }
        }

        for dir in candidate_dirs {
            let cert_path = dir.join("device_cert.pem");
            let key_candidates = [
                dir.join("device_key.pem"),
                dir.join("mtls_p256.key"),
                dir.join("identity_ed25519.key"),
            ];
            if cert_path.exists() {
                for key_path in &key_candidates {
                    if key_path.exists() {
                        if let (Ok(cert_bytes), Ok(key_bytes)) =
                            (std::fs::read(&cert_path), std::fs::read(key_path))
                        {
                            let pem_key = if key_bytes.starts_with(b"-----BEGIN") {
                                key_bytes.clone()
                            } else {
                                use base64::Engine;
                                let b64 =
                                    base64::engine::general_purpose::STANDARD.encode(&key_bytes);
                                format!(
                                    "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
                                    b64
                                )
                                .into_bytes()
                            };

                            let mut combined = cert_bytes.clone();
                            combined.extend_from_slice(b"\n");
                            combined.extend_from_slice(&pem_key);
                            if let Ok(identity) = reqwest::Identity::from_pem(&combined) {
                                builder = builder.identity(identity);
                                break;
                            }
                        }
                    }
                }
            }
        }

        let resolved_url = base_url
            .or_else(crate::identity::device::load_hub_url)
            .unwrap_or_else(|| "https://console.vexasec.io".to_string());

        Self {
            base_url: resolved_url,
            http_client: builder.build().unwrap_or_default(),
        }
    }

    /// Helper to resolve device assertion and bearer authorization headers.
    ///
    /// Resolution order (most-to-least preferred):
    /// 1. Persisted device token (from enrollment)
    /// 2. Ed25519 device assertion JWT (from identity key)
    /// 3. `GATEWAY_SECRET` environment variable (shared-secret for containerised gateways)
    /// 4. `AGENTCONTROL_ADMIN_TOKEN` environment variable (legacy / admin fallback)
    ///
    /// Without this fallback chain the gateway would send an empty Bearer token to the
    /// hub when no device identity is present, causing the hub's `GatewayAuth` middleware
    /// to return `403 invalid gateway token`, which in turn surfaces to clients as
    /// "stream disconnected before completion: stream closed before response.completed".
    fn auth_headers(&self) -> (Option<String>, String) {
        let assertion = crate::identity::device::DeviceIdentity::load_or_create()
            .ok()
            .and_then(|id| id.create_assertion_token(None, None).ok());

        let auth_token = crate::identity::device::load_device_token()
            // Fallback 1: shared gateway secret (set via GATEWAY_SECRET env in Docker / systemd)
            .or_else(|| std::env::var("GATEWAY_SECRET").ok().filter(|s| !s.is_empty()))
            // Fallback 2: admin token (legacy / single-binary deployments)
            .or_else(|| {
                std::env::var("AGENTCONTROL_ADMIN_TOKEN")
                    .ok()
                    .filter(|s| !s.is_empty())
            })
            // Fallback 3: unenrolled device assertion
            .or_else(|| assertion.clone())
            .unwrap_or_default();

        (assertion, auth_token)
    }

    /// Dispatches a buffered LLM request to the provider broker v3 via Ed25519 device assertion.
    pub async fn invoke_brokered_llm(
        &self,
        request: &BrokerLLMRequest,
    ) -> Result<BrokerLLMResponse, Box<dyn std::error::Error + Send + Sync>> {
        let endpoint = format!(
            "{}/api/v3/gateway-broker/llm-requests",
            self.base_url.trim_end_matches('/')
        );

        let (assertion, auth_token) = self.auth_headers();

        let mut req_builder = self
            .http_client
            .post(&endpoint)
            .header("Content-Type", "application/json")
            .header("X-Request-ID", &request.request_id)
            .header("Authorization", format!("Bearer {}", auth_token));

        if let Some(ref token) = assertion {
            req_builder = req_builder.header("X-Device-Authorization", format!("Bearer {}", token));
        }

        if let Some(ref vk) = request.virtual_key {
            req_builder = req_builder.header("X-Virtual-Key", vk);
        }

        let resp = req_builder.json(request).send().await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let err_body = resp.text().await.unwrap_or_default();
            if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                let msg = if let Ok(parsed) = serde_json::from_str::<BudgetExceededPayload>(&err_body) {
                    parsed.error.and_then(|e| e.message).or(parsed.message).unwrap_or(err_body)
                } else {
                    err_body
                };
                return Err(Box::new(BrokerError::BudgetExceeded(msg)));
            }
            return Err(Box::new(BrokerError::Http { status, body: err_body }));
        }

        let parsed = resp.json::<BrokerLLMResponse>().await?;
        Ok(parsed)
    }

    /// Dispatches a streaming SSE request to the provider broker v3 via Ed25519 device assertion.
    pub async fn invoke_brokered_stream(
        &self,
        request: &BrokerLLMRequest,
    ) -> Result<reqwest::Response, Box<dyn std::error::Error + Send + Sync>> {
        let endpoint = format!(
            "{}/api/v3/gateway-broker/llm-stream",
            self.base_url.trim_end_matches('/')
        );

        let (assertion, auth_token) = self.auth_headers();

        let mut req_builder = self
            .http_client
            .post(&endpoint)
            .header("Content-Type", "application/json")
            .header("Accept", "text/event-stream")
            .header("X-Request-ID", &request.request_id)
            .header("Authorization", format!("Bearer {}", auth_token));

        if let Some(ref token) = assertion {
            req_builder = req_builder.header("X-Device-Authorization", format!("Bearer {}", token));
        }

        if let Some(ref vk) = request.virtual_key {
            req_builder = req_builder.header("X-Virtual-Key", vk);
        }

        let resp = req_builder.json(request).send().await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let err_body = resp.text().await.unwrap_or_default();
            if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                let msg = if let Ok(parsed) = serde_json::from_str::<BudgetExceededPayload>(&err_body) {
                    parsed.error.and_then(|e| e.message).or(parsed.message).unwrap_or(err_body)
                } else {
                    err_body
                };
                return Err(Box::new(BrokerError::BudgetExceeded(msg)));
            }
            return Err(Box::new(BrokerError::Http { status, body: err_body }));
        }

        Ok(resp)
    }

    /// Dispatches a stream cancellation signal to upstream gateway within 500ms (Task 3.3).
    pub async fn cancel_brokered_stream(&self, request_id: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let endpoint = format!(
            "{}/api/v3/gateway-broker/llm-stream/{}/cancel",
            self.base_url.trim_end_matches('/'),
            request_id
        );

        let (assertion, auth_token) = self.auth_headers();

        let mut req_builder = self
            .http_client
            .post(&endpoint)
            .header("Authorization", format!("Bearer {}", auth_token))
            .timeout(std::time::Duration::from_millis(500));

        if let Some(ref token) = assertion {
            req_builder = req_builder.header("X-Device-Authorization", format!("Bearer {}", token));
        }

        let _ = req_builder.send().await;

        Ok(())
    }
}
