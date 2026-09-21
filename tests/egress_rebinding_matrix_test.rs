//! Deterministic Egress Resolver & DNS Rebinding Matrix Test (Gate 1).
//!
//! Validates that:
//! 1. `create_governed_pinned_client` connects strictly to `pinned_addr` while preserving Host & TLS SNI.
//! 2. Classification checks loopback, private IP ranges, link-local, and cloud metadata before issuing requests.
//! 3. Pinned transport remains bound to the pre-approved socket even if host resolution would otherwise point elsewhere.

use agentcontrol::proxy::connector::{
    canonicalize_host, classify_and_resolve_destination, classify_ip,
    create_governed_pinned_client, is_allowed_provider_host, EgressBlockReason,
};

#[tokio::test]
async fn test_pinned_client_dials_exact_mock_socket() {
    // Bind a mock server on an ephemeral local port
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bound_addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut buf = [0u8; 1024];
        let n = socket.read(&mut buf).await.unwrap();
        let req_str = String::from_utf8_lossy(&buf[..n]);

        // Assert request contains canonical Host header
        assert!(req_str.to_lowercase().contains("host: api.openai.com"));

        let response =
            "HTTP/1.1 200 OK\r\nContent-Length: 15\r\nConnection: close\r\n\r\n{\"status\":\"ok\"}";
        socket.write_all(response.as_bytes()).await.unwrap();
        let _ = socket.shutdown().await;
    });

    // Create a pinned client mapping "api.openai.com" to the bound ephemeral socket
    let client = create_governed_pinned_client("api.openai.com", bound_addr, 5);

    let url = format!("http://api.openai.com:{}/v1/models", bound_addr.port());
    let resp = client
        .get(&url)
        .send()
        .await
        .expect("Request should succeed against pinned mock socket");
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ok");

    server_task.await.unwrap();
}

#[tokio::test]
async fn test_rebinding_classification_matrix() {
    // 1. Air-gapped profile denies external hosts
    let res =
        classify_and_resolve_destination("api.openai.com", 443, "local-firewall", false, &[]).await;
    assert!(matches!(res, Err(EgressBlockReason::BlockedAirGapped(_))));

    // 2. Local-gateway denies non-allowlisted domains
    let res = classify_and_resolve_destination(
        "malicious.rebinding.attacker.com",
        443,
        "local-gateway",
        false,
        &[],
    )
    .await;
    assert!(matches!(
        res,
        Err(EgressBlockReason::BlockedProviderNotAllowlisted(_))
    ));

    // 3. Cloud metadata and link-local addresses rejected
    let meta_ip: std::net::IpAddr = "169.254.169.254".parse().unwrap();
    assert_eq!(
        classify_ip(meta_ip, false),
        Err(EgressBlockReason::BlockedLinkLocal)
    );

    // 4. Private RFC 1918 subnets rejected
    let priv_ip1: std::net::IpAddr = "10.1.2.3".parse().unwrap();
    assert!(matches!(
        classify_ip(priv_ip1, false),
        Err(EgressBlockReason::BlockedPrivateSubnet(_))
    ));
    let priv_ip2: std::net::IpAddr = "172.20.0.1".parse().unwrap();
    assert!(matches!(
        classify_ip(priv_ip2, false),
        Err(EgressBlockReason::BlockedPrivateSubnet(_))
    ));
    let priv_ip3: std::net::IpAddr = "192.168.1.100".parse().unwrap();
    assert!(matches!(
        classify_ip(priv_ip3, false),
        Err(EgressBlockReason::BlockedPrivateSubnet(_))
    ));

    // 5. CGNAT range rejected
    let cgnat_ip: std::net::IpAddr = "100.64.1.1".parse().unwrap();
    assert_eq!(
        classify_ip(cgnat_ip, false),
        Err(EgressBlockReason::BlockedCgnat)
    );

    // 6. Loopback rejected unless explicit allow_loopback is active
    let loopback_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    assert_eq!(
        classify_ip(loopback_ip, false),
        Err(EgressBlockReason::BlockedLoopback)
    );
    assert!(classify_ip(loopback_ip, true).is_ok());
}

#[test]
fn test_canonicalize_and_provider_allowlist_matching() {
    assert_eq!(
        canonicalize_host("API.OPENAI.COM.").unwrap(),
        "api.openai.com"
    );
    assert_eq!(
        canonicalize_host("api.anthropic.com:443").unwrap(),
        "api.anthropic.com"
    );

    let custom = vec!["*.corp.ai".to_string(), "internal-llm.corp".to_string()];
    assert!(is_allowed_provider_host("api.openai.com", &custom));
    assert!(is_allowed_provider_host("api.anthropic.com", &custom));
    assert!(is_allowed_provider_host("api.groq.com", &custom));
    assert!(is_allowed_provider_host(
        "generativelanguage.googleapis.com",
        &custom
    ));
    assert!(is_allowed_provider_host("deepseek.corp.ai", &custom));
    assert!(is_allowed_provider_host("internal-llm.corp", &custom));

    // Non-allowlisted hosts
    assert!(!is_allowed_provider_host("attacker.com", &custom));
    assert!(!is_allowed_provider_host("othercorp.ai", &custom));
}
