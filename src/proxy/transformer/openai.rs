//! OpenAI Native Provider Transformer

use bytes::Bytes;
use hyper::HeaderMap;
use serde_json::Value;
use super::{NormalizedLLMRequest, ProviderTransformer};

pub struct OpenAiTransformer;

impl ProviderTransformer for OpenAiTransformer {
    fn provider_name(&self) -> &'static str {
        "openai"
    }

    fn transform_request(
        &self,
        req: &NormalizedLLMRequest,
        api_key: &str,
        base_url: Option<&str>,
    ) -> Result<(String, HeaderMap, Bytes), String> {
        let endpoint = format!(
            "{}/v1/chat/completions",
            base_url.unwrap_or("https://api.openai.com").trim_end_matches('/')
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            hyper::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );
        headers.insert(
            hyper::header::AUTHORIZATION,
            format!("Bearer {}", api_key).parse().map_err(|e| format!("Invalid auth header: {}", e))?,
        );

        let mut body = serde_json::json!({
            "model": req.model,
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
        let val: Value = serde_json::from_slice(body).map_err(|e| format!("JSON parse error ({}): {}", status, e))?;
        Ok(val)
    }

    fn normalize_stream_chunk(&self, chunk: &[u8]) -> Result<Option<String>, String> {
        let text = std::str::from_utf8(chunk).map_err(|e| format!("UTF-8 error: {}", e))?;
        Ok(Some(text.to_string()))
    }
}
