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
        Self {
            base_url: base_url.unwrap_or_else(|| "https://device.vexasec.io".to_string()),
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .unwrap_or_default(),
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
