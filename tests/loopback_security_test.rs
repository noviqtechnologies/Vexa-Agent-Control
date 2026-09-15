use hyper::header::{HeaderMap, HeaderValue, ORIGIN};
use hyper::StatusCode;
use agentcontrol::proxy::egress::is_blocked_ssrf_target;
use agentcontrol::proxy::server::validate_origin_header;

#[test]
fn test_origin_header_validation_allows_desktop_and_local() {
    let allowed_origins = [
        "null",
        "http://localhost",
        "http://localhost:3000",
        "http://127.0.0.1",
        "http://127.0.0.1:8080",
        "http://[::1]:5173",
        "vscode-webview://vscode-app",
    ];

    for origin in &allowed_origins {
        let mut headers = HeaderMap::new();
        headers.insert(ORIGIN, HeaderValue::from_str(origin).unwrap());
        let res = validate_origin_header(&headers);
        assert!(
            res.is_ok(),
            "Expected origin '{}' to be allowed, got: {:?}",
            origin,
            res
        );
    }
}

#[test]
fn test_origin_header_validation_rejects_external_web_origins() {
    let forbidden_origins = [
        "https://malicious.com",
        "http://evil.org",
        "https://attacker.io:8080",
        "https://phishing-site.xyz",
        "http://192.168.1.100:8000",
        "http://victim-subdomain.attacker.com",
    ];

    for origin in &forbidden_origins {
        let mut headers = HeaderMap::new();
        headers.insert(ORIGIN, HeaderValue::from_str(origin).unwrap());
        let res = validate_origin_header(&headers);
        assert_eq!(
            res,
            Err((StatusCode::FORBIDDEN, "cross_origin_request_forbidden")),
            "Expected external origin '{}' to be rejected with 403 Forbidden",
            origin
        );
    }
}

#[test]
fn test_ssrf_non_relay_invariants() {
    // 1. Cloud metadata endpoints must be blocked
    assert!(is_blocked_ssrf_target("169.254.169.254"));
    assert!(is_blocked_ssrf_target("169.254.169.254:80"));
    assert!(is_blocked_ssrf_target("metadata.google.internal"));
    assert!(is_blocked_ssrf_target("metadata"));
    assert!(is_blocked_ssrf_target("instance-data"));
    assert!(is_blocked_ssrf_target("fd00:ec2::254"));

    // 2. Link-local IPv4 range (169.254.0.0/16) must be blocked
    assert!(is_blocked_ssrf_target("169.254.1.1"));
    assert!(is_blocked_ssrf_target("169.254.200.50"));

    // 3. Loopback targets must be blocked to prevent open loopback relay / port scanning
    assert!(is_blocked_ssrf_target("127.0.0.1"));
    assert!(is_blocked_ssrf_target("localhost"));
    assert!(is_blocked_ssrf_target("::1"));

    // 4. Legitimate public LLM and API endpoints must NOT be blocked
    assert!(!is_blocked_ssrf_target("api.openai.com"));
    assert!(!is_blocked_ssrf_target("api.anthropic.com"));
    assert!(!is_blocked_ssrf_target("generativelanguage.googleapis.com"));
    assert!(!is_blocked_ssrf_target("huggingface.co"));
}
