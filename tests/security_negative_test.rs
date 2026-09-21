use agentcontrol::proxy::security::{
    is_strict_loopback_addr, sanitize_inbound_headers, validate_ambient_browser_origin,
    validate_persistent_token, validate_rfc3986_authority, LEGACY_SENTINEL_TOKENS,
};
use hyper::header::{HeaderMap, HeaderValue, AUTHORIZATION, FORWARDED, HOST, ORIGIN};
use hyper::StatusCode;
use std::net::SocketAddr;

#[test]
fn test_socket_level_loopback_assertion() {
    // Valid loopback addresses
    let loopback_addrs: Vec<SocketAddr> = vec![
        "127.0.0.1:18080".parse().unwrap(),
        "127.0.0.2:18080".parse().unwrap(),
        "127.255.255.254:55443".parse().unwrap(),
        "[::1]:18080".parse().unwrap(),
        "[::ffff:127.0.0.1]:18080".parse().unwrap(),
    ];

    for addr in loopback_addrs {
        assert!(
            is_strict_loopback_addr(&addr),
            "Expected address {} to be recognized as strictly loopback",
            addr
        );
    }

    // Non-loopback addresses must be rejected immediately at socket layer
    let non_loopback_addrs: Vec<SocketAddr> = vec![
        "192.168.1.50:18080".parse().unwrap(),
        "10.0.0.1:18080".parse().unwrap(),
        "172.16.0.5:18080".parse().unwrap(),
        "8.8.8.8:18080".parse().unwrap(),
        "169.254.169.254:80".parse().unwrap(),
        "[2001:db8::1]:18080".parse().unwrap(),
    ];

    for addr in non_loopback_addrs {
        assert!(
            !is_strict_loopback_addr(&addr),
            "Expected address {} to be rejected as non-loopback",
            addr
        );
    }
}

#[test]
fn test_legacy_sentinel_tokens_rejected_with_401() {
    for sentinel in LEGACY_SENTINEL_TOKENS {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", sentinel)).unwrap(),
        );

        let res = validate_persistent_token(&headers, None);
        assert!(
            res.is_err(),
            "Expected sentinel token '{}' to be rejected",
            sentinel
        );
        let err = res.unwrap_err();
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert_eq!(err.code, "SENTINEL_TOKEN_REJECTED");
    }
}

#[test]
fn test_proxy_header_stripping() {
    let mut headers = HeaderMap::new();
    headers.insert("X-Forwarded-For", HeaderValue::from_static("10.0.0.1"));
    headers.insert("x-forwarded-for", HeaderValue::from_static("192.168.1.1"));
    headers.insert("X-Real-IP", HeaderValue::from_static("172.16.0.1"));
    headers.insert("x-real-ip", HeaderValue::from_static("8.8.8.8"));
    headers.insert(
        FORWARDED,
        HeaderValue::from_static("for=10.0.0.1;by=127.0.0.1"),
    );
    headers.insert("forwarded", HeaderValue::from_static("for=10.0.0.2"));
    headers.insert(HOST, HeaderValue::from_static("127.0.0.1:18080"));

    sanitize_inbound_headers(&mut headers);

    assert!(headers.get("X-Forwarded-For").is_none());
    assert!(headers.get("x-forwarded-for").is_none());
    assert!(headers.get("X-Real-IP").is_none());
    assert!(headers.get("x-real-ip").is_none());
    assert!(headers.get(FORWARDED).is_none());
    assert!(headers.get("forwarded").is_none());
    assert!(headers.get(HOST).is_some());
}

#[test]
fn test_ambient_browser_blocking_rejects_external_origin() {
    let mut headers = HeaderMap::new();
    headers.insert(
        ORIGIN,
        HeaderValue::from_static("https://malicious-site.com"),
    );

    let res = validate_ambient_browser_origin(&headers);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(err.status, StatusCode::FORBIDDEN);
    assert_eq!(err.code, "cross_origin_request_forbidden");
}

#[test]
fn test_duplicate_host_header_rejected_with_400() {
    let mut headers = HeaderMap::new();
    headers.append(HOST, HeaderValue::from_static("127.0.0.1:18080"));
    headers.append(HOST, HeaderValue::from_static("attacker.com"));

    let res = validate_rfc3986_authority(&headers, true);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(err.status, StatusCode::BAD_REQUEST);
    assert_eq!(err.code, "duplicate_host_header");
}
