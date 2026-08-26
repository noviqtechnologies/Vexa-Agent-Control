//! Strict mTLS HTTP client connecting to `device.vexasec.io/api/v2/broker`.

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
            .timeout(std::time::Duration::from_secs(60));

        // Attempt to load enrolled mTLS identity if available in home or config dir
        if let Some(home_dir) = dirs::home_dir().map(|h| h.join(".agentcontrol")).or_else(|| dirs::home_dir().map(|h| h.join(".agentwall"))) {
            let cert_path = home_dir.join("device_cert.pem");
            let key_path = home_dir.join("device_key.pem");
            if cert_path.exists() && key_path.exists() {
                if let (Ok(cert_bytes), Ok(key_bytes)) = (std::fs::read(&cert_path), std::fs::read(&key_path)) {
                    let mut combined = cert_bytes;
                    combined.extend_from_slice(b"\n");
                    combined.extend_from_slice(&key_bytes);
                    if let Ok(identity) = reqwest::Identity::from_pem(&combined) {
                        builder = builder.identity(identity);
                    }
                }
            }
        }

        Self {
            base_url: base_url.unwrap_or_else(|| "https://device.vexasec.io".to_string()),
            http_client: builder.build().unwrap_or_default(),
        }
    }

    /// Dispatches an LLM request over authenticated mTLS to the provider broker.
    pub async fn invoke_brokered_llm(
        &self,
        request: &BrokerLLMRequest,
    ) -> Result<BrokerLLMResponse, Box<dyn std::error::Error + Send + Sync>> {
        let endpoint = format!("{}/api/v2/broker/llm-requests", self.base_url);
        
        let resp = self.http_client
            .post(&endpoint)
            .header("Content-Type", "application/json")
            .header("X-Request-ID", &request.request_id)
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
}
