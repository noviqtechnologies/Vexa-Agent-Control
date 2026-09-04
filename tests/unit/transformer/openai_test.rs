use agentcontrol::proxy::transformer::{get_transformer, CanonicalMessage, NormalizedLLMRequest};
use hyper::HeaderMap;

fn base_request(model: &str) -> NormalizedLLMRequest {
    NormalizedLLMRequest {
        model: model.to_string(),
        messages: vec![
            CanonicalMessage {
                role: "system".to_string(),
                content: "You are a test system.".to_string(),
                tool_calls: None,
                tool_call_id: None,
                name: None,
            },
            CanonicalMessage {
                role: "user".to_string(),
                content: "Hello OpenAI!".to_string(),
                tool_calls: None,
                tool_call_id: None,
                name: None,
            },
        ],
        temperature: Some(0.7),
        max_tokens: Some(2048),
        stream: false,
        tools: None,
        extra_params: serde_json::Map::new(),
    }
}

#[test]
fn test_openai_default_endpoint() {
    let t = get_transformer("openai").expect("OpenAI transformer should exist");
    let req = base_request("gpt-4o");
    let (url, headers, _) = t.transform_request(&req, "sk-test", None).unwrap();
    assert_eq!(url, "https://api.openai.com/v1/chat/completions");
    assert_eq!(headers.get("authorization").unwrap(), "Bearer sk-test");
    assert_eq!(headers.get("content-type").unwrap(), "application/json");
}

#[test]
fn test_openai_custom_base_url() {
    let t = get_transformer("openai").unwrap();
    let req = base_request("gpt-4o-mini");
    let (url, _, _) = t.transform_request(&req, "sk-test", Some("https://custom.proxy.internal/v1")).unwrap();
    assert_eq!(url, "https://custom.proxy.internal/v1/v1/chat/completions");
}

#[test]
fn test_openai_payload_model_and_messages() {
    let t = get_transformer("openai").unwrap();
    let req = base_request("o1");
    let (_, _, body) = t.transform_request(&req, "sk-test", None).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["model"], "o1");
    assert_eq!(v["messages"].as_array().unwrap().len(), 2);
    assert!((v["temperature"].as_f64().unwrap() - 0.7).abs() < 1e-4);
    assert_eq!(v["max_tokens"], 2048);
}

#[test]
fn test_openai_streaming_flag() {
    let t = get_transformer("openai").unwrap();
    let mut req = base_request("gpt-4o");
    req.stream = true;
    let (_, _, body) = t.transform_request(&req, "sk-test", None).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["stream"], true);
}

#[test]
fn test_openai_tools_passthrough() {
    let t = get_transformer("openai").unwrap();
    let mut req = base_request("gpt-4o");
    req.tools = Some(serde_json::json!([
        {
            "type": "function",
            "function": { "name": "get_weather", "parameters": {} }
        }
    ]));
    let (_, _, body) = t.transform_request(&req, "sk-test", None).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(v.get("tools").is_some());
    assert_eq!(v["tools"][0]["function"]["name"], "get_weather");
}

#[test]
fn test_openai_extra_params_passthrough() {
    let t = get_transformer("openai").unwrap();
    let mut req = base_request("gpt-4o");
    req.extra_params.insert("top_p".to_string(), serde_json::json!(0.9));
    req.extra_params.insert("seed".to_string(), serde_json::json!(42));
    let (_, _, body) = t.transform_request(&req, "sk-test", None).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["top_p"], 0.9);
    assert_eq!(v["seed"], 42);
}

#[test]
fn test_openai_normalize_response_success() {
    let t = get_transformer("openai").unwrap();
    let raw = serde_json::json!({
        "id": "chatcmpl-123",
        "object": "chat.completion",
        "created": 1677652288,
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "message": { "role": "assistant", "content": "Hello!" },
            "finish_reason": "stop"
        }],
        "usage": { "prompt_tokens": 9, "completion_tokens": 12, "total_tokens": 21 }
    });
    let bytes = serde_json::to_vec(&raw).unwrap();
    let res = t.normalize_response(200, &HeaderMap::new(), &bytes).unwrap();
    assert_eq!(res["choices"][0]["message"]["content"], "Hello!");
    assert_eq!(res["usage"]["total_tokens"], 21);
}

#[test]
fn test_openai_normalize_response_invalid_json() {
    let t = get_transformer("openai").unwrap();
    let bad_bytes = b"{ invalid json string";
    let res = t.normalize_response(500, &HeaderMap::new(), bad_bytes);
    assert!(res.is_err());
}

#[test]
fn test_openai_normalize_stream_chunk_valid() {
    let t = get_transformer("openai").unwrap();
    let chunk = b"data: {\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}\n\n";
    let res = t.normalize_stream_chunk(chunk).unwrap();
    assert!(res.is_some());
    assert!(res.unwrap().contains("delta"));
}

#[test]
fn test_openai_provider_name() {
    let t = get_transformer("openai").unwrap();
    assert_eq!(t.provider_name(), "openai");
}
