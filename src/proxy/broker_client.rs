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

impl BrokerClient {
    pub fn new(base_url: Option<String>) -> Self {
        let mut builder = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120));

        let mut candidate_dirs = Vec::new();
        if let Some(home_dir) = dirs::home_dir() {
            candidate_dirs.push(home_dir.join(".agentcontrol"));
            candidate_dirs.push(home_dir.join(".agentwall"));
        }
        #[cfg(windows)]
        {
            candidate_dirs.push(std::path::PathBuf::from(r"C:\ProgramData\AgentControl"));
            candidate_dirs.push(std::path::PathBuf::from(r"C:\Windows\System32\config\systemprofile\.agentcontrol"));
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
                        if let (Ok(cert_bytes), Ok(key_bytes)) = (std::fs::read(&cert_path), std::fs::read(key_path)) {
                            let pem_key = if key_bytes.starts_with(b"-----BEGIN") {
                                key_bytes.clone()
                            } else {
                                use base64::Engine;
                                let b64 = base64::engine::general_purpose::STANDARD.encode(&key_bytes);
                                format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n", b64).into_bytes()
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
            .or_else(|| std::env::var("AGENTCONTROL_HUB_URL").ok())
            .or_else(|| std::env::var("AGENTWALL_HUB_URL").ok())
            .or_else(|| std::env::var("DASHBOARD_API_URL").ok())
            .unwrap_or_else(|| "https://console.vexasec.io".to_string());

        Self {
            base_url: resolved_url,
            http_client: builder.build().unwrap_or_default(),
        }
    }

    /// Dispatches a buffered LLM request to the provider broker v3 via gateway-secret auth.
    pub async fn invoke_brokered_llm(
        &self,
        request: &BrokerLLMRequest,
    ) -> Result<BrokerLLMResponse, Box<dyn std::error::Error + Send + Sync>> {
        let endpoint = format!("{}/api/v3/gateway-broker/llm-requests", self.base_url.trim_end_matches('/'));

        let gateway_secret = std::env::var("GATEWAY_SECRET").unwrap_or_default();
        let device_token = crate::identity::device::load_device_token()
            .unwrap_or_else(|| gateway_secret.clone());

        let resp = self.http_client
            .post(&endpoint)
            .header("Content-Type", "application/json")
            .header("X-Request-ID", &request.request_id)
            .header("Authorization", format!("Bearer {}", device_token))
            .json(request)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let err_body = resp.text().await.unwrap_or_default();
            return Err(format!("Broker request failed ({}): {}", status, err_body).into());
        }

        let parsed = resp.json::<BrokerLLMResponse>().await?;
        Ok(parsed)
    }

    /// Dispatches a streaming SSE request to the provider broker v3 via gateway-secret auth.
    pub async fn invoke_brokered_stream(
        &self,
        request: &BrokerLLMRequest,
    ) -> Result<reqwest::Response, Box<dyn std::error::Error + Send + Sync>> {
        let endpoint = format!("{}/api/v3/gateway-broker/llm-stream", self.base_url.trim_end_matches('/'));

        let gateway_secret = std::env::var("GATEWAY_SECRET").unwrap_or_default();
        let device_token = crate::identity::device::load_device_token()
            .unwrap_or_else(|| gateway_secret.clone());

        let resp = self.http_client
            .post(&endpoint)
            .header("Content-Type", "application/json")
            .header("Accept", "text/event-stream")
            .header("X-Request-ID", &request.request_id)
            .header("Authorization", format!("Bearer {}", device_token))
            .json(request)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let err_body = resp.text().await.unwrap_or_default();
            return Err(format!("Broker streaming request failed ({}): {}", status, err_body).into());
        }

        Ok(resp)
    }
}
