use agentcontrol::proxy::transformer::{get_transformer, CanonicalMessage, NormalizedLLMRequest};
use hyper::HeaderMap;

fn make_azure_request(model: &str) -> NormalizedLLMRequest {
    NormalizedLLMRequest {
        model: model.to_string(),
        messages: vec![CanonicalMessage {
            role: "user".to_string(),
            content: "Testing Azure Transformer".to_string(),
            tool_calls: None,
            tool_call_id: None,
            name: None,
        }],
        temperature: Some(0.3),
        max_tokens: Some(512),
        stream: false,
        tools: None,
        extra_params: serde_json::Map::new(),
    }
}

#[test]
fn test_azure_endpoint_url_rewriting() {
    let t = get_transformer("azure").expect("Azure transformer should exist");
    let req = make_azure_request("gpt-4o");
    let (url, headers, _) = t.transform_request(&req, "az-key-123", Some("https://my-res.openai.azure.com")).unwrap();
    assert!(url.contains("my-res.openai.azure.com/openai/deployments/gpt-4o/chat/completions"));
    assert!(url.contains("api-version="));
    assert_eq!(headers.get("api-key").unwrap(), "az-key-123");
}

#[test]
fn test_azure_model_dot_sanitization() {
    let t = get_transformer("azure_openai").unwrap();
    let req = make_azure_request("gpt-3.5-turbo");
    let (url, _, _) = t.transform_request(&req, "az-key", None).unwrap();
    assert!(url.contains("/deployments/gpt-35-turbo/"));
}

#[test]
fn test_azure_default_base_url() {
    let t = get_transformer("azure").unwrap();
    let req = make_azure_request("gpt-4o");
    let (url, _, _) = t.transform_request(&req, "az-key", None).unwrap();
    assert!(url.starts_with("https://your-resource.openai.azure.com"));
}

#[test]
fn test_azure_headers_present() {
    let t = get_transformer("azure").unwrap();
    let req = make_azure_request("gpt-4o");
    let (_, headers, _) = t.transform_request(&req, "secret-token", None).unwrap();
    assert_eq!(headers.get("api-key").unwrap(), "secret-token");
    assert_eq!(headers.get("content-type").unwrap(), "application/json");
}

#[test]
fn test_azure_body_messages() {
    let t = get_transformer("azure").unwrap();
    let req = make_azure_request("gpt-4o");
    let (_, _, body) = t.transform_request(&req, "az-key", None).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["messages"][0]["content"], "Testing Azure Transformer");
    assert!((v["temperature"].as_f64().unwrap() - 0.3).abs() < 1e-4);
    assert_eq!(v["max_tokens"], 512);
}

#[test]
fn test_azure_streaming_flag() {
    let t = get_transformer("azure").unwrap();
    let mut req = make_azure_request("gpt-4o");
    req.stream = true;
    let (_, _, body) = t.transform_request(&req, "az-key", None).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["stream"], true);
}

#[test]
fn test_azure_normalize_response_passthrough() {
    let t = get_transformer("azure").unwrap();
    let azure_raw = serde_json::json!({
        "id": "chatcmpl-az123",
        "object": "chat.completion",
        "choices": [{
            "message": { "role": "assistant", "content": "Azure response" },
            "finish_reason": "stop"
        }]
    });
    let bytes = serde_json::to_vec(&azure_raw).unwrap();
    let val = t.normalize_response(200, &HeaderMap::new(), &bytes).unwrap();
    assert_eq!(val["choices"][0]["message"]["content"], "Azure response");
}

#[test]
fn test_azure_normalize_response_json_error() {
    let t = get_transformer("azure").unwrap();
    let res = t.normalize_response(401, &HeaderMap::new(), b"Access denied");
    assert!(res.is_err());
}

#[test]
fn test_azure_normalize_stream_chunk() {
    let t = get_transformer("azure").unwrap();
    let chunk = b"data: {\"choices\":[{\"delta\":{\"content\":\"azure chunk\"}}]}\n\n";
    let res = t.normalize_stream_chunk(chunk).unwrap();
    assert!(res.is_some());
    assert!(res.unwrap().contains("azure chunk"));
}

#[test]
fn test_azure_provider_name() {
    let t = get_transformer("azure").unwrap();
    assert_eq!(t.provider_name(), "azure");
}
