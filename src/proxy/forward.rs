//! MCP forwarding — proxy requests to the upstream MCP server

use reqwest::Client;
use serde_json::Value;

pub const MAX_FORWARD_RESPONSE_BYTES: usize = 16 * 1024 * 1024; // 16 MiB

/// Forward a JSON-RPC request to the upstream MCP server.
/// Returns the raw response body.
pub async fn forward_request(
    client: &Client,
    upstream_url: &str,
    body: &Value,
) -> Result<Value, ForwardError> {
    let resp = client
        .post(upstream_url)
        .header("Content-Type", "application/json")
        .json(body)
        .send()
        .await
        .map_err(|e| ForwardError::Network(e.to_string()))?;

    let _status = resp.status();
    if let Some(len) = resp.content_length() {
        if len as usize > MAX_FORWARD_RESPONSE_BYTES {
            return Err(ForwardError::PayloadTooLarge(len as usize));
        }
    }

    let body_bytes = resp
        .bytes()
        .await
        .map_err(|e| ForwardError::Network(e.to_string()))?;

    if body_bytes.len() > MAX_FORWARD_RESPONSE_BYTES {
        return Err(ForwardError::PayloadTooLarge(body_bytes.len()));
    }

    let response: Value = serde_json::from_slice(&body_bytes)
        .map_err(|e| ForwardError::InvalidResponse(e.to_string()))?;

    Ok(response)
}

#[derive(Debug)]
pub enum ForwardError {
    Network(String),
    InvalidResponse(String),
    PayloadTooLarge(usize),
}

impl std::fmt::Display for ForwardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Network(e) => write!(f, "Network error: {}", e),
            Self::InvalidResponse(e) => write!(f, "Invalid MCP response: {}", e),
            Self::PayloadTooLarge(sz) => write!(
                f,
                "Upstream response exceeded maximum limit ({} bytes)",
                sz
            ),
        }
    }
}
