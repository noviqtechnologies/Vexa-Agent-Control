//! Azure OpenAI Service Provider Transformer

use bytes::Bytes;
use hyper::HeaderMap;
use serde_json::Value;
use super::{NormalizedLLMRequest, ProviderTransformer};

pub struct AzureOpenAiTransformer;

impl ProviderTransformer for AzureOpenAiTransformer {
    fn provider_name(&self) -> &'static str {
        "azure"
    }

    fn transform_request(
        &self,
        req: &NormalizedLLMRequest,
        api_key: &str,
        base_url: Option<&str>,
    ) -> Result<(String, HeaderMap, Bytes), String> {
        let raw_base = base_url.unwrap_or("https://your-resource.openai.azure.com");
        let api_version = std::env::var("AZURE_OPENAI_API_VERSION").unwrap_or_else(|_| "2024-06-01".to_string());
        
        // Azure routes via deployment name: /openai/deployments/{deployment-id}/chat/completions?api-version=...
        let deployment_id = std::env::var("AZURE_OPENAI_DEPLOYMENT").unwrap_or_else(|_| req.model.replace('.', ""));
        let endpoint = format!(
            "{}/openai/deployments/{}/chat/completions?api-version={}",
            raw_base.trim_end_matches('/'),
            deployment_id,
            api_version
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            hyper::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );
        headers.insert(
            "api-key".parse::<hyper::header::HeaderName>().unwrap(),
            api_key.parse().map_err(|e| format!("Invalid api-key header: {}", e))?,
        );

        let mut body = serde_json::json!({
            "messages": req.messages,
            "stream": req.stream,
        });

        if let Some(t) = req.temperature {
            body["temperature"] = serde_json::json!(t);
        }
        if let Some(m) = req.max_tokens {
            body["max_tokens"] = serde_json::json!(m);
        }
        if let Some(ref tools) = req.tools {
            body["tools"] = tools.clone();
        }

        for (k, v) in &req.extra_params {
            body[k] = v.clone();
        }

        let bytes = serde_json::to_vec(&body).map_err(|e| format!("Serialize error: {}", e))?;
        Ok((endpoint, headers, Bytes::from(bytes)))
    }

    fn normalize_response(
        &self,
        status: u16,
        _headers: &HeaderMap,
        body: &[u8],
    ) -> Result<Value, String> {
        let val: Value = serde_json::from_slice(body).map_err(|e| format!("Azure JSON parse error ({}): {}", status, e))?;
        Ok(val)
    }

    fn normalize_stream_chunk(&self, chunk: &[u8]) -> Result<Option<String>, String> {
        let text = std::str::from_utf8(chunk).map_err(|e| format!("UTF-8 error: {}", e))?;
        Ok(Some(text.to_string()))
    }
}
