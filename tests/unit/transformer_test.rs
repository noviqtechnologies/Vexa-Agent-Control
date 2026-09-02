use agentcontrol::proxy::transformer::{get_transformer, CanonicalMessage, NormalizedLLMRequest};
use hyper::HeaderMap;

fn make_sample_request() -> NormalizedLLMRequest {
    NormalizedLLMRequest {
        model: "gpt-4o".to_string(),
        messages: vec![
            CanonicalMessage {
                role: "system".to_string(),
                content: "You are a secure assistant.".to_string(),
                tool_calls: None,
                tool_call_id: None,
                name: None,
            },
            CanonicalMessage {
                role: "user".to_string(),
                content: "Hello, what is the capital of France?".to_string(),
                tool_calls: None,
                tool_call_id: None,
                name: None,
            },
        ],
        temperature: Some(0.5),
        max_tokens: Some(1024),
        stream: false,
        tools: None,
        extra_params: serde_json::Map::new(),
    }
}

#[test]
fn test_openai_transformer() {
    let t = get_transformer("openai").expect("OpenAI transformer should exist");
    let req = make_sample_request();
    let (url, headers, body) = t.transform_request(&req, "sk-test-key", None).unwrap();

    assert_eq!(url, "https://api.openai.com/v1/chat/completions");
    assert_eq!(headers.get("authorization").unwrap(), "Bearer sk-test-key");

    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["model"], "gpt-4o");
    assert_eq!(parsed["messages"].as_array().unwrap().len(), 2);
}

#[test]
fn test_azure_openai_transformer() {
    let t = get_transformer("azure").expect("Azure transformer should exist");
    let req = make_sample_request();
    let (url, headers, body) = t.transform_request(&req, "azure-secret-key", Some("https://my-azure.openai.azure.com")).unwrap();

    assert!(url.contains("my-azure.openai.azure.com/openai/deployments/"));
    assert!(url.contains("api-version="));
    assert_eq!(headers.get("api-key").unwrap(), "azure-secret-key");

    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["messages"].as_array().unwrap().len(), 2);
}

#[test]
fn test_groq_transformer() {
    let t = get_transformer("groq").expect("Groq transformer should exist");
    let mut req = make_sample_request();
    req.model = "llama-3.3-70b-versatile".to_string();

    let (url, headers, body) = t.transform_request(&req, "gsk_testkey", None).unwrap();
    assert_eq!(url, "https://api.groq.com/openai/v1/chat/completions");
    assert_eq!(headers.get("authorization").unwrap(), "Bearer gsk_testkey");

    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["model"], "llama-3.3-70b-versatile");
}

#[test]
fn test_anthropic_transformer_system_prompt_extraction() {
    let t = get_transformer("anthropic").expect("Anthropic transformer should exist");
    let mut req = make_sample_request();
    req.model = "claude-3-5-sonnet-20241022".to_string();

    let (url, headers, body) = t.transform_request(&req, "sk-ant-test", None).unwrap();
    assert_eq!(url, "https://api.anthropic.com/v1/messages");
    assert_eq!(headers.get("x-api-key").unwrap(), "sk-ant-test");
    assert_eq!(headers.get("anthropic-version").unwrap(), "2023-06-01");

    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["model"], "claude-3-5-sonnet-20241022");
    // System message extracted to top-level system field
    assert_eq!(parsed["system"], "You are a secure assistant.");
    // Messages array only contains user message
    let msgs = parsed["messages"].as_array().unwrap();
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0]["role"], "user");
}

#[test]
fn test_gemini_transformer() {
    let t = get_transformer("gemini").expect("Gemini transformer should exist");
    let mut req = make_sample_request();
    req.model = "gemini-1.5-pro".to_string();

    let (url, headers, body) = t.transform_request(&req, "AIzaSyTestKey", None).unwrap();
    assert!(url.contains("generativelanguage.googleapis.com"));
    assert_eq!(headers.get("authorization").unwrap(), "Bearer AIzaSyTestKey");

    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["model"], "gemini-1.5-pro");
}

#[test]
fn test_bedrock_transformer() {
    let t = get_transformer("bedrock").expect("Bedrock transformer should exist");
    let mut req = make_sample_request();
    req.model = "anthropic.claude-3-5-sonnet-20241022-v2:0".to_string();

    let (url, _headers, body) = t.transform_request(&req, "", None).unwrap();
    assert!(url.contains("bedrock-runtime"));
    assert!(url.contains("/converse"));

    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(parsed.get("inferenceConfig").is_some());
}

#[test]
fn test_anthropic_response_normalization() {
    let t = get_transformer("anthropic").unwrap();
    let anthropic_raw = serde_json::json!({
        "id": "msg_01XFDUDY",
        "type": "message",
        "role": "assistant",
        "content": [{
            "type": "text",
            "text": "The capital of France is Paris."
        }],
        "model": "claude-3-5-sonnet-20241022",
        "stop_reason": "end_turn",
        "usage": {
            "input_tokens": 25,
            "output_tokens": 8
        }
    });

    let raw_bytes = serde_json::to_vec(&anthropic_raw).unwrap();
    let normalized = t.normalize_response(200, &HeaderMap::new(), &raw_bytes).unwrap();

    assert_eq!(normalized["object"], "chat.completion");
    assert_eq!(normalized["choices"][0]["message"]["content"], "The capital of France is Paris.");
    assert_eq!(normalized["usage"]["prompt_tokens"], 25);
    assert_eq!(normalized["usage"]["completion_tokens"], 8);
    assert_eq!(normalized["usage"]["total_tokens"], 33);
}
