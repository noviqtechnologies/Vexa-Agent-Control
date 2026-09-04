use agentcontrol::proxy::transformer::{get_transformer, CanonicalMessage, NormalizedLLMRequest};
use hyper::HeaderMap;

fn make_groq_request(model: &str) -> NormalizedLLMRequest {
    NormalizedLLMRequest {
        model: model.to_string(),
        messages: vec![CanonicalMessage {
            role: "user".to_string(),
            content: "Run on LPU hardware".to_string(),
            tool_calls: None,
            tool_call_id: None,
            name: None,
        }],
        temperature: Some(0.6),
        max_tokens: Some(4096),
        stream: false,
        tools: None,
        extra_params: serde_json::Map::new(),
    }
}

#[test]
fn test_groq_endpoint_and_auth() {
    let t = get_transformer("groq").expect("Groq transformer should exist");
    let req = make_groq_request("llama-3.3-70b-versatile");
    let (url, headers, _) = t.transform_request(&req, "gsk_secret", None).unwrap();
    assert_eq!(url, "https://api.groq.com/openai/v1/chat/completions");
    assert_eq!(headers.get("authorization").unwrap(), "Bearer gsk_secret");
    assert_eq!(headers.get("content-type").unwrap(), "application/json");
}

#[test]
fn test_groq_custom_base_url() {
    let t = get_transformer("groq").unwrap();
    let req = make_groq_request("llama-3.1-8b-instant");
    let (url, _, _) = t.transform_request(&req, "gsk_key", Some("https://groq.internal.corp")).unwrap();
    assert_eq!(url, "https://groq.internal.corp/openai/v1/chat/completions");
}

#[test]
fn test_groq_model_and_tokens() {
    let t = get_transformer("groq").unwrap();
    let req = make_groq_request("mixtral-8x7b-32768");
    let (_, _, body) = t.transform_request(&req, "gsk_key", None).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["model"], "mixtral-8x7b-32768");
    assert_eq!(v["max_tokens"], 4096);
    assert!((v["temperature"].as_f64().unwrap() - 0.6).abs() < 1e-4);
}

#[test]
fn test_groq_streaming_flag() {
    let t = get_transformer("groq").unwrap();
    let mut req = make_groq_request("llama-3.3-70b-versatile");
    req.stream = true;
    let (_, _, body) = t.transform_request(&req, "gsk_key", None).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["stream"], true);
}

#[test]
fn test_groq_tools_support() {
    let t = get_transformer("groq").unwrap();
    let mut req = make_groq_request("llama-3.3-70b-versatile");
    req.tools = Some(serde_json::json!([
        { "type": "function", "function": { "name": "shell_exec" } }
    ]));
    let (_, _, body) = t.transform_request(&req, "gsk_key", None).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["tools"][0]["function"]["name"], "shell_exec");
}

#[test]
fn test_groq_extra_params() {
    let t = get_transformer("groq").unwrap();
    let mut req = make_groq_request("llama-3.3-70b-versatile");
    req.extra_params.insert("top_p".to_string(), serde_json::json!(0.95));
    let (_, _, body) = t.transform_request(&req, "gsk_key", None).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["top_p"], 0.95);
}

#[test]
fn test_groq_normalize_response_success() {
    let t = get_transformer("groq").unwrap();
    let raw = serde_json::json!({
        "id": "chatcmpl-groq1",
        "object": "chat.completion",
        "choices": [{
            "message": { "role": "assistant", "content": "Fast LPU answer" },
            "finish_reason": "stop"
        }],
        "usage": { "prompt_tokens": 10, "completion_tokens": 8, "total_tokens": 18 }
    });
    let bytes = serde_json::to_vec(&raw).unwrap();
    let res = t.normalize_response(200, &HeaderMap::new(), &bytes).unwrap();
    assert_eq!(res["choices"][0]["message"]["content"], "Fast LPU answer");
}

#[test]
fn test_groq_normalize_response_error() {
    let t = get_transformer("groq").unwrap();
    let res = t.normalize_response(429, &HeaderMap::new(), b"rate limit exceeded");
    assert!(res.is_err());
}

#[test]
fn test_groq_normalize_stream_chunk() {
    let t = get_transformer("groq").unwrap();
    let chunk = b"data: {\"choices\":[{\"delta\":{\"content\":\"LPU token\"}}]}\n\n";
    let res = t.normalize_stream_chunk(chunk).unwrap();
    assert!(res.is_some());
    assert!(res.unwrap().contains("LPU token"));
}

#[test]
fn test_groq_provider_name() {
    let t = get_transformer("groq").unwrap();
    assert_eq!(t.provider_name(), "groq");
}
