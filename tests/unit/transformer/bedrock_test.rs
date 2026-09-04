use agentcontrol::proxy::transformer::{get_transformer, CanonicalMessage, NormalizedLLMRequest};
use hyper::HeaderMap;

fn make_bedrock_request(model: &str) -> NormalizedLLMRequest {
    NormalizedLLMRequest {
        model: model.to_string(),
        messages: vec![CanonicalMessage {
            role: "user".to_string(),
            content: "Converse API input".to_string(),
            tool_calls: None,
            tool_call_id: None,
            name: None,
        }],
        temperature: Some(0.5),
        max_tokens: Some(1024),
        stream: false,
        tools: None,
        extra_params: serde_json::Map::new(),
    }
}

#[test]
fn test_bedrock_converse_endpoint() {
    let t = get_transformer("bedrock").expect("Bedrock transformer should exist");
    let req = make_bedrock_request("anthropic.claude-3-5-sonnet-20241022-v2:0");
    let (url, _, _) = t.transform_request(&req, "", None).unwrap();
    assert!(url.contains("bedrock-runtime"));
    assert!(url.contains("/model/anthropic.claude-3-5-sonnet-20241022-v2:0/converse"));
}

#[test]
fn test_bedrock_alias_aws_bedrock() {
    let t = get_transformer("aws_bedrock").expect("aws_bedrock alias should resolve");
    assert_eq!(t.provider_name(), "bedrock");
}

#[test]
fn test_bedrock_custom_base_url() {
    let t = get_transformer("bedrock").unwrap();
    let req = make_bedrock_request("amazon.titan-text-express-v1");
    let (url, _, _) = t.transform_request(&req, "", Some("https://vpce-custom.bedrock.aws")).unwrap();
    assert!(url.starts_with("https://vpce-custom.bedrock.aws"));
}

#[test]
fn test_bedrock_inference_config() {
    let t = get_transformer("bedrock").unwrap();
    let req = make_bedrock_request("meta.llama3-70b-instruct-v1:0");
    let (_, _, body) = t.transform_request(&req, "", None).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["inferenceConfig"]["maxTokens"], 1024);
    assert_eq!(v["inferenceConfig"]["temperature"], 0.5);
}

#[test]
fn test_bedrock_messages_structure() {
    let t = get_transformer("bedrock").unwrap();
    let req = make_bedrock_request("anthropic.claude-3");
    let (_, _, body) = t.transform_request(&req, "", None).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let msgs = v["messages"].as_array().unwrap();
    assert_eq!(msgs[0]["role"], "user");
    assert_eq!(msgs[0]["content"][0]["text"], "Converse API input");
}

#[test]
fn test_bedrock_auth_header_optional() {
    let t = get_transformer("bedrock").unwrap();
    let req = make_bedrock_request("anthropic.claude-3");
    let (_, headers, _) = t.transform_request(&req, "token123", None).unwrap();
    assert_eq!(headers.get("authorization").unwrap(), "Bearer token123");
}

#[test]
fn test_bedrock_normalize_response_output_mapping() {
    let t = get_transformer("bedrock").unwrap();
    let raw = serde_json::json!({
        "output": {
            "message": {
                "role": "assistant",
                "content": [{ "text": "Bedrock answer" }]
            }
        },
        "usage": {
            "inputTokens": 12,
            "outputTokens": 8
        }
    });
    let bytes = serde_json::to_vec(&raw).unwrap();
    let norm = t.normalize_response(200, &HeaderMap::new(), &bytes).unwrap();
    assert_eq!(norm["object"], "chat.completion");
    assert_eq!(norm["choices"][0]["message"]["content"], "Bedrock answer");
    assert_eq!(norm["usage"]["prompt_tokens"], 12);
    assert_eq!(norm["usage"]["completion_tokens"], 8);
    assert_eq!(norm["usage"]["total_tokens"], 20);
}

#[test]
fn test_bedrock_normalize_response_invalid_json() {
    let t = get_transformer("bedrock").unwrap();
    let res = t.normalize_response(500, &HeaderMap::new(), b"invalid json");
    assert!(res.is_err());
}

#[test]
fn test_bedrock_normalize_stream_chunk() {
    let t = get_transformer("bedrock").unwrap();
    let chunk = b"bedrock raw chunk";
    let res = t.normalize_stream_chunk(chunk).unwrap();
    assert!(res.is_some());
    assert_eq!(res.unwrap(), "bedrock raw chunk");
}

#[test]
fn test_bedrock_provider_name() {
    let t = get_transformer("bedrock").unwrap();
    assert_eq!(t.provider_name(), "bedrock");
}
