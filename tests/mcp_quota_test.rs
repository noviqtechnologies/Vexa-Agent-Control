use agentcontrol::mcp::policy::{
    calculate_json_depth, inspect_jsonrpc_frame, JsonRpcError, MAX_FRAME_SIZE, MAX_JSON_DEPTH,
};
use serde_json::json;

#[test]
fn test_mcp_frame_size_quota_16mb() {
    // 1. Frame within 16MB is accepted
    let normal_msg = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {}
    });
    let normal_bytes = serde_json::to_vec(&normal_msg).unwrap();
    let res = inspect_jsonrpc_frame(&normal_bytes, false);
    assert!(res.is_ok());

    // 2. Oversized frame (> 16MB) is rejected with -32600
    let oversized_bytes = vec![b'a'; MAX_FRAME_SIZE + 1024];
    let err = inspect_jsonrpc_frame(&oversized_bytes, false).unwrap_err();
    assert_eq!(err.code, -32600);
    assert!(err.message.contains("16MB"));
}

#[test]
fn test_mcp_max_nesting_depth_quota_32() {
    // Construct a deeply nested JSON object > 32 levels
    let mut nested = json!("deepest_value");
    for _ in 0..35 {
        nested = json!({ "child": nested });
    }

    let payload = json!({
        "jsonrpc": "2.0",
        "id": 100,
        "method": "tools/call",
        "params": {
            "name": "eval",
            "arguments": {
                "structure": nested
            }
        }
    });

    let depth = calculate_json_depth(&payload);
    assert!(depth > MAX_JSON_DEPTH);

    let bytes = serde_json::to_vec(&payload).unwrap();
    let err = inspect_jsonrpc_frame(&bytes, false).unwrap_err();
    assert_eq!(err.code, -32600);
    assert!(err.message.contains("32 levels"));
}

#[test]
fn test_mcp_parameter_dlp_and_redaction() {
    let payload = json!({
        "jsonrpc": "2.0",
        "id": 200,
        "method": "tools/call",
        "params": {
            "name": "deploy",
            "arguments": {
                "api_key": "sk-1234567890abcdef1234567890abcdef",
                "conn": "postgres://admin:pass123@db.prod.internal:5432/main",
                "cert": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----",
                "safe_param": "regular text"
            }
        }
    });

    let bytes = serde_json::to_vec(&payload).unwrap();

    // 1. Redaction mode (block_on_sensitive = false)
    let (inspected, findings) = inspect_jsonrpc_frame(&bytes, false).unwrap();
    assert_eq!(findings.len(), 3);

    let args = inspected.get("params").unwrap().get("arguments").unwrap();
    assert_eq!(args.get("api_key").unwrap().as_str().unwrap(), "[REDACTED:API_KEY]");
    assert_eq!(args.get("conn").unwrap().as_str().unwrap(), "[REDACTED:CONNECTION_STRING]");
    assert_eq!(args.get("cert").unwrap().as_str().unwrap(), "[REDACTED:PRIVATE_KEY]");
    assert_eq!(args.get("safe_param").unwrap().as_str().unwrap(), "regular text");

    // 2. Policy violation block mode (block_on_sensitive = true)
    let err = inspect_jsonrpc_frame(&bytes, true).unwrap_err();
    assert_eq!(err.code, -32001);
    assert!(err.message.contains("Policy Violation: Sensitive Parameter Detected"));
}

#[test]
fn test_mcp_timeout_error_format() {
    let err = JsonRpcError::timeout(60);
    assert_eq!(err.code, -32000);
    assert!(err.message.contains("60 seconds"));
}
