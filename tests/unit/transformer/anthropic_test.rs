use agentcontrol::proxy::transformer::{get_transformer, CanonicalMessage, NormalizedLLMRequest};
use hyper::HeaderMap;

fn make_anthropic_req(system: Option<&str>, user: &str) -> NormalizedLLMRequest {
    let mut messages = Vec::new();
    if let Some(sys) = system {
        messages.push(CanonicalMessage {
            role: "system".to_string(),
            content: sys.to_string(),
            tool_calls: None,
            tool_call_id: None,
            name: None,
        });
    }
    messages.push(CanonicalMessage {
        role: "user".to_string(),
        content: user.to_string(),
        tool_calls: None,
        tool_call_id: None,
        name: None,
    });

    NormalizedLLMRequest {
        model: "claude-3-5-sonnet-20241022".to_string(),
        messages,
        temperature: Some(0.5),
        max_tokens: Some(1024),
        stream: false,
        tools: None,
        extra_params: serde_json::Map::new(),
    }
}

#[test]
fn test_anthropic_headers_and_endpoint() {
    let t = get_transformer("anthropic").expect("Anthropic transformer should exist");
    let req = make_anthropic_req(None, "Hello Claude");
    let (url, headers, _) = t.transform_request(&req, "sk-ant-key", None).unwrap();
    assert_eq!(url, "https://api.anthropic.com/v1/messages");
    assert_eq!(headers.get("x-api-key").unwrap(), "sk-ant-key");
    assert_eq!(headers.get("anthropic-version").unwrap(), "2023-06-01");
}

#[test]
fn test_anthropic_system_prompt_extraction() {
    let t = get_transformer("anthropic").unwrap();
    let req = make_anthropic_req(Some("You are a strict security auditor."), "Analyze this code");
    let (_, _, body) = t.transform_request(&req, "sk-ant-key", None).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["system"], "You are a strict security auditor.");
    assert_eq!(v["messages"].as_array().unwrap().len(), 1);
    assert_eq!(v["messages"][0]["role"], "user");
}

#[test]
fn test_anthropic_multiple_system_prompts_joined() {
    let t = get_transformer("anthropic").unwrap();
    let mut req = make_anthropic_req(Some("Part 1"), "User message");
    req.messages.insert(
        1,
        CanonicalMessage {
            role: "system".to_string(),
            content: "Part 2".to_string(),
            tool_calls: None,
            tool_call_id: None,
            name: None,
        },
    );
    let (_, _, body) = t.transform_request(&req, "sk-ant-key", None).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["system"], "Part 1\n\nPart 2");
}

#[test]
fn test_anthropic_multi_turn_roles() {
    let t = get_transformer("anthropic").unwrap();
    let mut req = make_anthropic_req(None, "First prompt");
    req.messages.push(CanonicalMessage {
        role: "assistant".to_string(),
        content: "First answer".to_string(),
        tool_calls: None,
        tool_call_id: None,
        name: None,
    });
    req.messages.push(CanonicalMessage {
        role: "user".to_string(),
        content: "Second prompt".to_string(),
        tool_calls: None,
        tool_call_id: None,
        name: None,
    });
    let (_, _, body) = t.transform_request(&req, "sk-ant-key", None).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let msgs = v["messages"].as_array().unwrap();
    assert_eq!(msgs.len(), 3);
    assert_eq!(msgs[0]["role"], "user");
    assert_eq!(msgs[1]["role"], "assistant");
    assert_eq!(msgs[2]["role"], "user");
}

#[test]
fn test_anthropic_default_max_tokens() {
    let t = get_transformer("anthropic").unwrap();
    let mut req = make_anthropic_req(None, "Hello");
    req.max_tokens = None;
    let (_, _, body) = t.transform_request(&req, "sk-ant-key", None).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["max_tokens"], 4096);
}

#[test]
fn test_anthropic_empty_messages_fallback() {
    let t = get_transformer("anthropic").unwrap();
    let mut req = make_anthropic_req(None, "dummy");
    req.messages.clear(); // no messages
    let (_, _, body) = t.transform_request(&req, "sk-ant-key", None).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["messages"].as_array().unwrap().len(), 1);
    assert_eq!(v["messages"][0]["role"], "user");
    assert_eq!(v["messages"][0]["content"], "Hello");
}

#[test]
fn test_anthropic_response_normalization_standard() {
    let t = get_transformer("anthropic").unwrap();
    let raw = serde_json::json!({
        "id": "msg_ant123",
        "type": "message",
        "role": "assistant",
        "content": [{ "type": "text", "text": "Paris is the capital." }],
        "model": "claude-3-5-sonnet-20241022",
        "stop_reason": "end_turn",
        "usage": { "input_tokens": 15, "output_tokens": 6 }
    });
    let bytes = serde_json::to_vec(&raw).unwrap();
    let norm = t.normalize_response(200, &HeaderMap::new(), &bytes).unwrap();
    assert_eq!(norm["object"], "chat.completion");
    assert_eq!(norm["choices"][0]["message"]["content"], "Paris is the capital.");
    assert_eq!(norm["usage"]["prompt_tokens"], 15);
    assert_eq!(norm["usage"]["completion_tokens"], 6);
    assert_eq!(norm["usage"]["total_tokens"], 21);
}

#[test]
fn test_anthropic_response_normalization_tool_use() {
    let t = get_transformer("anthropic").unwrap();
    let raw = serde_json::json!({
        "id": "msg_tool123",
        "type": "message",
        "role": "assistant",
        "content": [
            { "type": "text", "text": "Calling tool" }
        ],
        "model": "claude-3-5-sonnet-20241022",
        "stop_reason": "tool_use",
        "usage": { "input_tokens": 20, "output_tokens": 10 }
    });
    let bytes = serde_json::to_vec(&raw).unwrap();
    let norm = t.normalize_response(200, &HeaderMap::new(), &bytes).unwrap();
    assert_eq!(norm["choices"][0]["message"]["content"], "Calling tool");
    assert_eq!(norm["choices"][0]["finish_reason"], "tool_calls");
}

#[test]
fn test_anthropic_normalize_stream_chunk_content_block_delta() {
    let t = get_transformer("anthropic").unwrap();
    let chunk = b"data: {\"type\": \"content_block_delta\", \"index\": 0, \"delta\": {\"type\": \"text_delta\", \"text\": \"Hello\"}}\n\n";
    let res = t.normalize_stream_chunk(chunk).unwrap();
    assert!(res.is_some());
    let formatted = res.unwrap();
    assert!(formatted.contains("data: "));
    assert!(formatted.contains("\"content\":\"Hello\""));
}

#[test]
fn test_anthropic_provider_name() {
    let t = get_transformer("anthropic").unwrap();
    assert_eq!(t.provider_name(), "anthropic");
}
