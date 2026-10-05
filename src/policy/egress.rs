//! Egress Control & Outbound Domain Policy Guard (PRD F3-S2)
//!
//! Enforces outbound network egress filtering across AI agent tool invocations
//! (fetch, http_get, http_post, curl, browser). Maintains default denylists for
//! pastebin-style exfiltration sites and raw IP literals, with per-agent/per-tool
//! domain allow/deny policy rules.

use std::collections::HashSet;

/// Default paste and exfiltration sites denylist
const DEFAULT_PASTE_SITES: &[&str] = &[
    "pastebin.com",
    "hastebin.com",
    "ghostbin.com",
    "paste.ee",
    "justpaste.it",
    "controlc.com",
    "rentry.co",
    "paste.org",
    "dpaste.org",
    "cl1p.net",
    "dumpz.org",
    "0bin.net",
    "binshare.net",
    "pastefs.com",
    "termbin.com",
];

/// Category of egress violation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressViolationCategory {
    PasteSite,
    RawIpLiteral,
    MetadataSSRF,
    ExplicitDenylist,
    NotOnAllowlist,
}

impl EgressViolationCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            EgressViolationCategory::PasteSite => "Paste / Exfiltration Site",
            EgressViolationCategory::RawIpLiteral => "Raw IP Literal Address",
            EgressViolationCategory::MetadataSSRF => "Cloud Instance Metadata SSRF",
            EgressViolationCategory::ExplicitDenylist => "Explicit Egress Denylist",
            EgressViolationCategory::NotOnAllowlist => "Domain Not On Egress Allowlist",
        }
    }
}

/// A matched egress violation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressViolation {
    pub category: EgressViolationCategory,
    pub rule_id: &'static str,
    pub host: String,
    pub url: String,
    pub reason: String,
}

/// Configurable egress policy settings
#[derive(Debug, Clone, Default)]
pub struct EgressPolicyConfig {
    pub allowed_domains: Vec<String>,
    pub denied_domains: Vec<String>,
    pub block_raw_ips: bool,
    pub block_paste_sites: bool,
}

/// Outbound Egress Guard
#[derive(Debug, Clone)]
pub struct EgressGuard {
    paste_sites: HashSet<&'static str>,
    config: EgressPolicyConfig,
}

impl Default for EgressGuard {
    fn default() -> Self {
        Self::new(EgressPolicyConfig {
            allowed_domains: Vec::new(),
            denied_domains: Vec::new(),
            block_raw_ips: true,
            block_paste_sites: true,
        })
    }
}

impl EgressGuard {
    pub fn new(config: EgressPolicyConfig) -> Self {
        let mut paste_sites = HashSet::new();
        for site in DEFAULT_PASTE_SITES {
            paste_sites.insert(*site);
        }
        Self {
            paste_sites,
            config,
        }
    }

    /// Evaluates a raw URL or destination string
    pub fn check_egress(&self, raw_target: &str) -> Option<EgressViolation> {
        let trimmed = raw_target.trim();
        if trimmed.is_empty() {
            return None;
        }

        // Extract host
        let host = extract_host(trimmed);
        if host.is_empty() {
            return None;
        }

        let host_lower = host.to_lowercase();

        // 1. Check for cloud metadata SSRF
        if host_lower == "169.254.169.254"
            || host_lower == "metadata.google.internal"
            || host_lower == "instance-data"
        {
            return Some(EgressViolation {
                category: EgressViolationCategory::MetadataSSRF,
                rule_id: "EGR-SSRF-001",
                host: host.to_string(),
                url: trimmed.to_string(),
                reason: "Outbound egress to cloud instance metadata service is prohibited"
                    .to_string(),
            });
        }

        // 2. Check for paste sites denylist
        if self.config.block_paste_sites {
            for paste_site in &self.paste_sites {
                if host_lower == *paste_site || host_lower.ends_with(&format!(".{}", paste_site)) {
                    return Some(EgressViolation {
                        category: EgressViolationCategory::PasteSite,
                        rule_id: "EGR-PASTE-001",
                        host: host.to_string(),
                        url: trimmed.to_string(),
                        reason: format!(
                            "Outbound egress to known paste/exfiltration domain '{}' is prohibited",
                            host
                        ),
                    });
                }
            }
        }

        // 3. Check for raw IP literals (unless loopback 127.0.0.1 or ::1)
        if self.config.block_raw_ips && is_raw_ip_literal(&host_lower) {
            // Allow loopback for local tests and proxies
            if host_lower != "127.0.0.1" && host_lower != "::1" && host_lower != "localhost" {
                return Some(EgressViolation {
                    category: EgressViolationCategory::RawIpLiteral,
                    rule_id: "EGR-RAWIP-001",
                    host: host.to_string(),
                    url: trimmed.to_string(),
                    reason: format!(
                        "Outbound egress directly to raw IP address '{}' is prohibited",
                        host
                    ),
                });
            }
        }

        // 4. Check explicit policy denylist
        for denied in &self.config.denied_domains {
            if domain_matches(&host_lower, denied) {
                return Some(EgressViolation {
                    category: EgressViolationCategory::ExplicitDenylist,
                    rule_id: "EGR-DENY-001",
                    host: host.to_string(),
                    url: trimmed.to_string(),
                    reason: format!(
                        "Domain '{}' matches explicit egress denylist rule '{}'",
                        host, denied
                    ),
                });
            }
        }

        // 5. Check policy allowlist (if configured)
        if !self.config.allowed_domains.is_empty() {
            let mut allowed = false;
            for pattern in &self.config.allowed_domains {
                if domain_matches(&host_lower, pattern) {
                    allowed = true;
                    break;
                }
            }
            if !allowed {
                return Some(EgressViolation {
                    category: EgressViolationCategory::NotOnAllowlist,
                    rule_id: "EGR-ALLOW-001",
                    host: host.to_string(),
                    url: trimmed.to_string(),
                    reason: format!(
                        "Domain '{}' is not in the configured egress allowlist",
                        host
                    ),
                });
            }
        }

        None
    }
}

/// Extract hostname from URL or host string
pub fn extract_host(target: &str) -> String {
    let clean = target.trim();
    if let Ok(parsed) = reqwest::Url::parse(clean) {
        if let Some(h) = parsed.host_str() {
            return h.to_string();
        }
    }

    // Fallback: strip scheme if present
    let without_scheme = if let Some(idx) = clean.find("://") {
        &clean[idx + 3..]
    } else {
        clean
    };

    // Take until slash, colon, or question mark
    let host_part = without_scheme
        .split('/')
        .next()
        .unwrap_or("")
        .split('?')
        .next()
        .unwrap_or("")
        .split('#')
        .next()
        .unwrap_or("");

    // Strip port if present (handling IPv6 [::1]:80)
    if host_part.starts_with('[') {
        if let Some(end) = host_part.find(']') {
            return host_part[1..end].to_string();
        }
    }

    host_part.split(':').next().unwrap_or("").to_string()
}

/// Tests if a host string is a raw IPv4 or IPv6 literal
pub fn is_raw_ip_literal(host: &str) -> bool {
    let clean = host.trim_matches('[').trim_matches(']');
    clean.parse::<std::net::IpAddr>().is_ok()
}

/// Matches domain against pattern (supporting exact match and `*.example.com` wildcards)
fn domain_matches(domain: &str, pattern: &str) -> bool {
    let d = domain.to_lowercase();
    let p = pattern.to_lowercase();

    if p.starts_with("*.") {
        let suffix = &p[1..]; // e.g. ".openai.com"
        d.ends_with(suffix) || d == p[2..]
    } else {
        d == p
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_egress_paste_sites_blocked() {
        let guard = EgressGuard::default();

        let paste_urls = [
            "https://pastebin.com/raw/12345",
            "http://hastebin.com/post",
            "https://subdomain.paste.ee/d/loot",
            "https://controlc.com/view/abc",
            "https://rentry.co/payload",
        ];

        for url in paste_urls {
            let res = guard.check_egress(url);
            assert!(
                res.is_some(),
                "Expected paste site to be blocked: '{}'",
                url
            );
            assert_eq!(res.unwrap().category, EgressViolationCategory::PasteSite);
        }
    }

    #[test]
    fn test_egress_raw_ip_literals_blocked() {
        let guard = EgressGuard::default();

        let raw_ips = [
            "http://192.0.2.1/exfil",
            "https://1.2.3.4:8080/data",
            "http://10.0.0.5:9001/loot",
            "http://[2001:db8::1]/exfil",
        ];

        for url in raw_ips {
            let res = guard.check_egress(url);
            assert!(res.is_some(), "Expected raw IP to be blocked: '{}'", url);
            assert_eq!(res.unwrap().category, EgressViolationCategory::RawIpLiteral);
        }

        // Loopback is allowed
        assert!(guard
            .check_egress("http://127.0.0.1:18080/healthz")
            .is_none());
        assert!(guard.check_egress("http://localhost:3000/api").is_none());
    }

    #[test]
    fn test_egress_allowlist_enforcement() {
        let config = EgressPolicyConfig {
            allowed_domains: vec!["*.github.com".to_string(), "api.openai.com".to_string()],
            denied_domains: vec!["evil.github.com".to_string()],
            block_raw_ips: true,
            block_paste_sites: true,
        };
        let guard = EgressGuard::new(config);

        // Allowed
        assert!(guard.check_egress("https://api.github.com/repos").is_none());
        assert!(guard
            .check_egress("https://api.openai.com/v1/chat")
            .is_none());

        // Explicitly denied
        let denied = guard.check_egress("https://evil.github.com/drop");
        assert!(denied.is_some());
        assert_eq!(
            denied.unwrap().category,
            EgressViolationCategory::ExplicitDenylist
        );

        // Not in allowlist
        let other = guard.check_egress("https://random-site.org/info");
        assert!(other.is_some());
        assert_eq!(
            other.unwrap().category,
            EgressViolationCategory::NotOnAllowlist
        );
    }
}
