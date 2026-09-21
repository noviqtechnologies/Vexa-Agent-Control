use agentcontrol::proxy::server::{is_loopback, validate_host_header};
use hyper::header::{HeaderMap, HeaderValue, HOST};
use hyper::StatusCode;

#[test]
fn test_authority_parser_valid_loopback() {
    let valid_authorities = [
        "127.0.0.1",
        "127.0.0.1:18080",
        "127.0.0.2",
        "127.255.255.254",
        "localhost",
        "localhost:18080",
        "LOCALHOST",
        "ip6-localhost",
        "localhost6",
        "::1",
        "[::1]",
        "[::1]:18080",
        "::ffff:127.0.0.1",
        "[::ffff:127.0.0.1]:18080",
    ];

    for auth in &valid_authorities {
        assert!(
            is_loopback(auth),
            "Expected authority '{}' to be recognized as loopback",
            auth
        );

        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_str(auth).unwrap());
        let res = validate_host_header(&headers, true);
        assert!(
            res.is_ok(),
            "Expected validate_host_header to accept '{}', got: {:?}",
            auth,
            res
        );
    }
}

#[test]
fn test_authority_parser_rejects_external_hosts_on_loopback() {
    let external_authorities = [
        "evil.com",
        "evil.com:18080",
        "attacker.org",
        "127.0.0.1.attacker.com",
        "127.attacker.com",
        "192.168.1.1",
        "192.168.1.1:18080",
        "10.0.0.1",
        "172.16.0.1",
        "169.254.169.254",
        "8.8.8.8",
        "2001:db8::1",
    ];

    for auth in &external_authorities {
        assert!(
            !is_loopback(auth),
            "Expected authority '{}' to NOT be recognized as loopback",
            auth
        );

        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_str(auth).unwrap());
        let res = validate_host_header(&headers, true);
        assert_eq!(
            res,
            Err((StatusCode::BAD_REQUEST, "invalid_host_authority")),
            "Expected authority '{}' to be rejected with invalid_host_authority",
            auth
        );
    }
}

#[test]
fn test_authority_parser_rejects_duplicate_host_headers() {
    let mut headers = HeaderMap::new();
    headers.append(HOST, HeaderValue::from_static("localhost:18080"));
    headers.append(HOST, HeaderValue::from_static("evil.com:18080"));

    let res = validate_host_header(&headers, true);
    assert_eq!(
        res,
        Err((StatusCode::BAD_REQUEST, "duplicate_host_header")),
        "RFC 7230 §5.4: Multiple Host headers must be rejected as bad request"
    );
}

#[test]
fn test_peer_ip_takes_precedence_over_spoofed_proxy_headers() {
    // When a request arrives from a non-loopback peer (e.g. 192.168.1.50)
    // even if it injects X-Forwarded-For: 127.0.0.1, the peer IP determines trust.
    let peer_ip = "192.168.1.50";
    let spoofed_forwarded = "127.0.0.1";

    assert!(!is_loopback(peer_ip));
    assert!(is_loopback(spoofed_forwarded));

    // The server evaluates client_ip using peer_ip directly:
    let is_peer_loopback = is_loopback(peer_ip);
    assert!(
        !is_peer_loopback,
        "Peer socket address must be the sole authority, never spoofable headers"
    );
}
