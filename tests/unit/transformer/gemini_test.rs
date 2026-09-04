use agentcontrol::proxy::transformer::{get_transformer, CanonicalMessage, NormalizedLLMRequest};
use hyper::HeaderMap;

fn make_gemini_request(model: &str) -> NormalizedLLMRequest {
    NormalizedLLMRequest {
        model: model.to_string(),
        messages: vec![CanonicalMessage {
            role: "user".to_string(),
            content: "Hello Gemini".to_string(),
            tool_calls: None,
            tool_call_id: None,
            name: None,
        }],
        temperature: Some(0.4),
        max_tokens: Some(1024),
        stream: false,
        tools: None,
        extra_params: serde_json::Map::new(),
    }
}

#[test]
fn test_gemini_endpoint_generation() {
    let t = get_transformer("gemini").expect("Gemini transformer should exist");
    let req = make_gemini_request("gemini-1.5-pro");
    let (url, headers, _) = t.transform_request(&req, "AIzaTestKey", None).unwrap();
    assert!(url.contains("generativelanguage.googleapis.com"));
    assert!(url.contains("/v1beta/openai/chat/completions"));
    assert_eq!(headers.get("authorization").unwrap(), "Bearer AIzaTestKey");
}

#[test]
fn test_gemini_alias_google() {
    let t = get_transformer("google").expect("Google alias should resolve Gemini transformer");
    assert_eq!(t.provider_name(), "google");
}

#[test]
fn test_gemini_custom_base_url() {
    let t = get_transformer("gemini").unwrap();
    let req = make_gemini_request("gemini-1.5-flash");
    let (url, _, _) = t.transform_request(&req, "key", Some("https://internal.gemini.gw")).unwrap();
    assert!(url.starts_with("https://internal.gemini.gw"));
}

#[test]
fn test_gemini_request_body_structure() {
    let t = get_transformer("gemini").unwrap();
    let req = make_gemini_request("gemini-2.0-flash");
    let (_, _, body) = t.transform_request(&req, "key", None).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["model"], "gemini-2.0-flash");
    assert_eq!(v["messages"][0]["content"], "Hello Gemini");
    assert!((v["temperature"].as_f64().unwrap() - 0.4).abs() < 1e-4);
    assert_eq!(v["max_tokens"], 1024);
}

#[test]
fn test_gemini_streaming_parameter() {
    let t = get_transformer("gemini").unwrap();
    let mut req = make_gemini_request("gemini-1.5-pro");
    req.stream = true;
    let (_, _, body) = t.transform_request(&req, "key", None).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["stream"], true);
}

#[test]
fn test_gemini_messages_count() {
    let t = get_transformer("gemini").unwrap();
    let req = make_gemini_request("gemini-1.5-pro");
    let (_, _, body) = t.transform_request(&req, "key", None).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["messages"].as_array().unwrap().len(), 1);
}

#[test]
fn test_gemini_normalize_response_standard() {
    let t = get_transformer("gemini").unwrap();
    let raw = serde_json::json!({
        "id": "chatcmpl-gemini1",
        "object": "chat.completion",
        "choices": [{
            "message": { "role": "assistant", "content": "I am Gemini." },
            "finish_reason": "stop"
        }],
        "usage": { "prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10 }
    });
    let bytes = serde_json::to_vec(&raw).unwrap();
    let res = t.normalize_response(200, &HeaderMap::new(), &bytes).unwrap();
    assert_eq!(res["choices"][0]["message"]["content"], "I am Gemini.");
    assert_eq!(res["usage"]["total_tokens"], 10);
}

#[test]
fn test_gemini_normalize_response_invalid_body() {
    let t = get_transformer("gemini").unwrap();
    let res = t.normalize_response(503, &HeaderMap::new(), b"upstream error");
    assert!(res.is_err());
}

#[test]
fn test_gemini_normalize_stream_chunk() {
    let t = get_transformer("gemini").unwrap();
    let chunk = b"data: {\"choices\":[{\"delta\":{\"content\":\"Gemini chunk\"}}]}\n\n";
    let res = t.normalize_stream_chunk(chunk).unwrap();
    assert!(res.is_some());
    assert!(res.unwrap().contains("Gemini chunk"));
}

#[test]
fn test_gemini_provider_name() {
    let t = get_transformer("gemini").unwrap();
    assert_eq!(t.provider_name(), "google");
}
