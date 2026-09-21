//! Designated exclusive outbound networking and destination classification module.
//!
//! Enforces ADR 0.2 & ADR 0.5:
//! - Complete URL canonicalization and destination classification
//! - Controlled async DNS resolution and IP address range enforcement
//! - Pinned concrete SocketAddr dialing (immune to DNS rebinding)
//! - Provider allowlisting for local-gateway and air-gapped local-firewall enforcement
//! - Direct proxy configuration (ambient HTTP_PROXY / ALL_PROXY neutralized)

use std::fmt;
use std::net::{IpAddr, SocketAddr};

/// Reason an outbound connection or target was blocked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressBlockReason {
    BlockedMalformedTarget(String),
    BlockedAirGapped(String),
    BlockedProviderNotAllowlisted(String),
    BlockedPort(u16),
    BlockedLoopback,
    BlockedPrivateSubnet(String),
    BlockedCgnat,
    BlockedLinkLocal,
    BlockedMulticast,
    BlockedDnsResolutionFailed(String),
}

impl fmt::Display for EgressBlockReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BlockedMalformedTarget(msg) => write!(f, "Malformed target authority: {}", msg),
            Self::BlockedAirGapped(msg) => write!(f, "Air-gapped profile violation: {}", msg),
            Self::BlockedProviderNotAllowlisted(host) => {
                write!(f, "Host '{}' is not in the approved LLM provider allowlist", host)
            }
            Self::BlockedPort(port) => write!(f, "Port {} is not authorized for cloud provider egress", port),
            Self::BlockedLoopback => write!(f, "Loopback egress target blocked (localhost/127.0.0.0/8/::1)"),
            Self::BlockedPrivateSubnet(ip) => write!(f, "Private subnet target blocked (RFC 1918 / ULA: {})", ip),
            Self::BlockedCgnat => write!(f, "Shared / CGNAT target blocked (RFC 6598: 100.64.0.0/10)"),
            Self::BlockedLinkLocal => write!(f, "Link-local / cloud metadata target blocked (169.254.0.0/16 / fe80::/10)"),
            Self::BlockedMulticast => write!(f, "Multicast or reserved target blocked"),
            Self::BlockedDnsResolutionFailed(msg) => write!(f, "DNS resolution failed: {}", msg),
        }
    }
}

impl EgressBlockReason {
    pub fn as_header_str(&self) -> &'static str {
        match self {
            Self::BlockedMalformedTarget(_) => "malformed_target",
            Self::BlockedAirGapped(_) => "air_gapped_violation",
            Self::BlockedProviderNotAllowlisted(_) => "provider_not_allowlisted",
            Self::BlockedPort(_) => "unauthorized_port",
            Self::BlockedLoopback => "loopback_blocked",
            Self::BlockedPrivateSubnet(_) => "private_subnet_blocked",
            Self::BlockedCgnat => "cgnat_blocked",
            Self::BlockedLinkLocal => "link_local_metadata_blocked",
            Self::BlockedMulticast => "multicast_blocked",
            Self::BlockedDnsResolutionFailed(_) => "dns_resolution_failed",
        }
    }
}

/// Standard known cloud LLM providers supported out-of-the-box.
pub const STANDARD_ALLOWED_PROVIDERS: &[&str] = &[
    "api.openai.com",
    "api.anthropic.com",
    "api.groq.com",
    "generativelanguage.googleapis.com",
];

/// Check if a canonical hostname matches standard or custom provider patterns.
pub fn is_allowed_provider_host(host: &str, custom_providers: &[String]) -> bool {
    let h = host.trim().to_ascii_lowercase();

    for std_p in STANDARD_ALLOWED_PROVIDERS {
        if h == *std_p {
            return true;
        }
    }

    // Azure OpenAI pattern: *.openai.azure.com
    if h.ends_with(".openai.azure.com") {
        return true;
    }

    // AWS Bedrock pattern: bedrock-runtime.*.amazonaws.com
    if h.starts_with("bedrock-runtime.") && h.ends_with(".amazonaws.com") {
        return true;
    }

    // Custom user/policy providers
    for p in custom_providers {
        let pattern = p.trim().to_ascii_lowercase();
        if pattern.starts_with("*.") {
            let suffix = &pattern[1..]; // e.g. ".internal.llm"
            if h.ends_with(suffix) {
                return true;
            }
        } else if h == pattern {
            return true;
        }
    }

    false
}

/// Canonicalize target host and validate basic authority structure.
pub fn canonicalize_host(raw_host: &str) -> Result<String, EgressBlockReason> {
    let mut h = raw_host.trim().to_ascii_lowercase();
    if h.is_empty() {
        return Err(EgressBlockReason::BlockedMalformedTarget("Host is empty".into()));
    }

    // Disallow userinfo (@) in host authority
    if h.contains('@') {
        return Err(EgressBlockReason::BlockedMalformedTarget("Userinfo (@) not allowed in authority".into()));
    }

    // Strip bracket notation for IPv6
    if h.starts_with('[') {
        if let Some(idx) = h.find(']') {
            h = h[1..idx].to_string();
        } else {
            return Err(EgressBlockReason::BlockedMalformedTarget("Unclosed IPv6 bracket".into()));
        }
    } else if let Some((base, port)) = h.rsplit_once(':') {
        // If there's a port on IPv4 or hostname, strip it
        if !base.contains(':') && port.chars().all(|c| c.is_ascii_digit()) {
            h = base.to_string();
        }
    }

    // Strip trailing dot
    while h.ends_with('.') {
        h.pop();
    }

    if h.is_empty() {
        return Err(EgressBlockReason::BlockedMalformedTarget("Host is empty after stripping".into()));
    }

    // Check for illegal characters
    if h.contains('/') || h.contains('\\') || h.contains('?') || h.contains('#') || h.contains(' ') {
        return Err(EgressBlockReason::BlockedMalformedTarget("Host contains illegal URI characters".into()));
    }

    Ok(h)
}

/// Check whether an IP address falls into a denied private, loopback, or metadata category.
pub fn classify_ip(ip: IpAddr, allow_loopback: bool) -> Result<(), EgressBlockReason> {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();

            // Link-local / Cloud metadata (169.254.0.0/16)
            if octets[0] == 169 && octets[1] == 254 {
                return Err(EgressBlockReason::BlockedLinkLocal);
            }

            // Loopback (127.0.0.0/8)
            if v4.is_loopback() || octets[0] == 127 {
                if !allow_loopback {
                    return Err(EgressBlockReason::BlockedLoopback);
                }
                return Ok(());
            }

            // RFC 1918 Private subnets
            // 10.0.0.0/8
            if octets[0] == 10 {
                return Err(EgressBlockReason::BlockedPrivateSubnet(v4.to_string()));
            }
            // 172.16.0.0/12
            if octets[0] == 172 && (16..=31).contains(&octets[1]) {
                return Err(EgressBlockReason::BlockedPrivateSubnet(v4.to_string()));
            }
            // 192.168.0.0/16
            if octets[0] == 192 && octets[1] == 168 {
                return Err(EgressBlockReason::BlockedPrivateSubnet(v4.to_string()));
            }

            // RFC 6598 Shared / CGNAT (100.64.0.0/10)
            if octets[0] == 100 && (64..=127).contains(&octets[1]) {
                return Err(EgressBlockReason::BlockedCgnat);
            }

            // Multicast (224.0.0.0/4)
            if v4.is_multicast() || (224..=239).contains(&octets[0]) {
                return Err(EgressBlockReason::BlockedMulticast);
            }

            // Broadcast (255.255.255.255) / Unspecified (0.0.0.0)
            if v4.is_broadcast() || v4.is_unspecified() {
                return Err(EgressBlockReason::BlockedPrivateSubnet(v4.to_string()));
            }

            Ok(())
        }
        IpAddr::V6(v6) => {
            let segs = v6.segments();

            // Link-local / Cloud metadata (fe80::/10 or AWS fd00:ec2::254)
            if (segs[0] & 0xffc0) == 0xfe80 || (segs[0] == 0xfd00 && segs[1] == 0xec2) {
                return Err(EgressBlockReason::BlockedLinkLocal);
            }

            // Loopback (::1)
            if v6.is_loopback() {
                if !allow_loopback {
                    return Err(EgressBlockReason::BlockedLoopback);
                }
                return Ok(());
            }

            // Unique Local Address (fc00::/7)
            if (segs[0] & 0xfe00) == 0xfc00 {
                return Err(EgressBlockReason::BlockedPrivateSubnet(v6.to_string()));
            }

            // Multicast (ff00::/8)
            if v6.is_multicast() {
                return Err(EgressBlockReason::BlockedMulticast);
            }

            // Unspecified (::)
            if v6.is_unspecified() {
                return Err(EgressBlockReason::BlockedPrivateSubnet(v6.to_string()));
            }

            Ok(())
        }
    }
}

/// Fully classify destination authority, apply provider allowlist, resolve DNS asynchronously,
/// and return a pinned `SocketAddr` along with the canonical hostname.
pub async fn classify_and_resolve_destination(
    raw_host: &str,
    target_port: u16,
    profile: &str,
    allow_loopback: bool,
    custom_providers: &[String],
) -> Result<(SocketAddr, String), EgressBlockReason> {
    let canonical_host = canonicalize_host(raw_host)?;

    // Check if host is loopback / local
    let is_local_host = canonical_host == "localhost"
        || canonical_host == "127.0.0.1"
        || canonical_host == "::1"
        || canonical_host.ends_with(".localhost");

    let is_air_gapped = profile.eq_ignore_ascii_case("local-firewall");

    if is_air_gapped {
        if !is_local_host {
            return Err(EgressBlockReason::BlockedAirGapped(format!(
                "External host '{}' denied in air-gapped local-firewall profile",
                canonical_host
            )));
        }
    }

    // In local-gateway mode, external traffic MUST match the provider allowlist
    let is_local_gateway = profile.eq_ignore_ascii_case("local-gateway")
        || profile.eq_ignore_ascii_case("local-enforce")
        || profile.eq_ignore_ascii_case("local-shadow");

    if !is_local_host {
        // Enforce cloud provider allowlist
        if is_local_gateway {
            if !is_allowed_provider_host(&canonical_host, custom_providers) {
                return Err(EgressBlockReason::BlockedProviderNotAllowlisted(canonical_host));
            }
            // Enforce standard TLS port 443 for cloud LLM providers
            if target_port != 443 {
                return Err(EgressBlockReason::BlockedPort(target_port));
            }
        }
    }

    // Resolve hostname asynchronously
    let resolve_target = format!("{}:{}", canonical_host, target_port);
    let resolved_addrs = tokio::net::lookup_host(&resolve_target)
        .await
        .map_err(|e| EgressBlockReason::BlockedDnsResolutionFailed(e.to_string()))?;

    let mut approved_addr: Option<SocketAddr> = None;

    for addr in resolved_addrs {
        let ip = addr.ip();
        // Check IP address safety
        classify_ip(ip, allow_loopback || (is_local_host && is_air_gapped))?;

        if approved_addr.is_none() {
            approved_addr = Some(addr);
        }
    }

    approved_addr.map(|addr| (addr, canonical_host)).ok_or_else(|| {
        EgressBlockReason::BlockedDnsResolutionFailed("No address records returned".into())
    })
}

/// Create a governed, safe HTTP client with redirects disabled and ambient proxies neutralized.
pub fn create_governed_client(timeout_secs: u64) -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonicalize_host() {
        assert_eq!(canonicalize_host("api.openai.com.").unwrap(), "api.openai.com");
        assert_eq!(canonicalize_host("API.ANTHROPIC.COM").unwrap(), "api.anthropic.com");
        assert_eq!(canonicalize_host("[::1]").unwrap(), "::1");
        assert_eq!(canonicalize_host("127.0.0.1:8080").unwrap(), "127.0.0.1");
        assert!(canonicalize_host("user:pass@api.openai.com").is_err());
        assert!(canonicalize_host("").is_err());
    }

    #[test]
    fn test_is_allowed_provider_host() {
        let custom = vec!["custom.llm.corp".to_string(), "*.internal.ai".to_string()];
        assert!(is_allowed_provider_host("api.openai.com", &custom));
        assert!(is_allowed_provider_host("api.anthropic.com", &custom));
        assert!(is_allowed_provider_host("api.groq.com", &custom));
        assert!(is_allowed_provider_host("generativelanguage.googleapis.com", &custom));
        assert!(is_allowed_provider_host("myorg.openai.azure.com", &custom));
        assert!(is_allowed_provider_host("bedrock-runtime.us-east-1.amazonaws.com", &custom));
        assert!(is_allowed_provider_host("custom.llm.corp", &custom));
        assert!(is_allowed_provider_host("agent.internal.ai", &custom));

        // Unauthorized external hosts
        assert!(!is_allowed_provider_host("evil.attacker.com", &custom));
        assert!(!is_allowed_provider_host("app.vexasec.io", &custom)); // Hub is not an LLM provider
    }

    #[test]
    fn test_classify_ip_ranges() {
        // Link-local cloud metadata
        assert_eq!(
            classify_ip("169.254.169.254".parse().unwrap(), false),
            Err(EgressBlockReason::BlockedLinkLocal)
        );

        // RFC 1918 Private subnets
        assert!(matches!(
            classify_ip("10.0.0.1".parse().unwrap(), false),
            Err(EgressBlockReason::BlockedPrivateSubnet(_))
        ));
        assert!(matches!(
            classify_ip("172.16.5.1".parse().unwrap(), false),
            Err(EgressBlockReason::BlockedPrivateSubnet(_))
        ));
        assert!(matches!(
            classify_ip("192.168.1.1".parse().unwrap(), false),
            Err(EgressBlockReason::BlockedPrivateSubnet(_))
        ));

        // CGNAT (RFC 6598)
        assert_eq!(
            classify_ip("100.64.0.1".parse().unwrap(), false),
            Err(EgressBlockReason::BlockedCgnat)
        );

        // Loopback without allow flag
        assert_eq!(
            classify_ip("127.0.0.1".parse().unwrap(), false),
            Err(EgressBlockReason::BlockedLoopback)
        );
        // Loopback with allow flag
        assert!(classify_ip("127.0.0.1".parse().unwrap(), true).is_ok());

        // Public IP (e.g. 1.1.1.1)
        assert!(classify_ip("1.1.1.1".parse().unwrap(), false).is_ok());
    }

    #[tokio::test]
    async fn test_classify_and_resolve_destination_air_gapped() {
        let err = classify_and_resolve_destination(
            "api.openai.com",
            443,
            "local-firewall",
            false,
            &[],
        )
        .await
        .unwrap_err();
        assert!(matches!(err, EgressBlockReason::BlockedAirGapped(_)));
    }

    #[tokio::test]
    async fn test_classify_and_resolve_destination_unallowlisted() {
        let err = classify_and_resolve_destination(
            "example.com",
            443,
            "local-gateway",
            false,
            &[],
        )
        .await
        .unwrap_err();
        assert_eq!(
            err,
            EgressBlockReason::BlockedProviderNotAllowlisted("example.com".to_string())
        );
    }
}
