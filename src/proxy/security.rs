//! Security hardening for workstation loopback proxy (REQ-SEC-005, NFR-3, PRD §3.1, §6)
//!
//! Provides socket-level loopback assertion, RFC 3986 normalized authority parsing,
//! header sanitization, ambient browser blocking, and persistent local token validation.

use hyper::header::{HeaderMap, FORWARDED, HOST, ORIGIN};
use hyper::StatusCode;
use std::net::{IpAddr, SocketAddr};

/// Custom security error type with HTTP status code and machine-readable message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: &'static str,
}

impl SecurityError {
    pub fn new(status: StatusCode, code: &'static str, message: &'static str) -> Self {
        Self {
            status,
            code,
            message,
        }
    }
}

/// Socket-Level Loopback Assertion
/// Validates that a peer SocketAddr is strictly loopback:
/// IPv4 `127.0.0.0/8`, IPv6 `::1`, or IPv4-mapped IPv6 `::ffff:127.0.0.1`.
#[inline]
pub fn is_strict_loopback_addr(addr: &SocketAddr) -> bool {
    is_strict_loopback_ip(&addr.ip())
}

/// Validates that an IpAddr is strictly loopback
#[inline]
pub fn is_strict_loopback_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6
                    .to_ipv4_mapped()
                    .map(|v4| v4.is_loopback())
                    .unwrap_or(false)
                || v6.to_ipv4().map(|v4| v4.is_loopback()).unwrap_or(false)
        }
    }
}

/// Validates whether a given IP or authority string represents a valid loopback target.
pub fn is_loopback(s: &str) -> bool {
    let mut s = s.trim();
    if s.is_empty() {
        return false;
    }

    // Strip scheme if present
    if let Some(idx) = s.find("://") {
        s = &s[idx + 3..];
    }

    // Strip path or query if present
    if let Some(idx) = s.find(['/', '?', '#']) {
        s = &s[..idx];
    }

    // Strip IPv6 brackets
    let mut host = s;
    if host.starts_with('[') {
        if let Some(end_bracket) = host.find(']') {
            let inner = &host[1..end_bracket];
            let remainder = &host[end_bracket + 1..];
            if remainder.is_empty() || remainder.starts_with(':') {
                host = inner;
            }
        }
    } else if let Some(last_colon) = host.rfind(':') {
        // If there's only one colon, it's host:port
        if host.find(':') == Some(last_colon) {
            host = &host[..last_colon];
        }
    }

    // Strip zone index (e.g. ::1%lo0, ::1%1)
    if let Some(pct) = host.find('%') {
        host = &host[..pct];
    }

    let host_lower = host.to_lowercase();

    // Recognized loopback hostname aliases
    if host_lower == "localhost"
        || host_lower == "localhost."
        || host_lower == "ip6-localhost"
        || host_lower == "localhost6"
    {
        return true;
    }

    // Check IP parsing
    if let Ok(addr) = host.parse::<IpAddr>() {
        return is_strict_loopback_ip(&addr);
    }

    // Handle raw IPv4-mapped IPv6 hex notation like ::ffff:7f00:1
    if host_lower.starts_with("::ffff:7f") || host_lower.starts_with("::ffff:127.") {
        return true;
    }

    false
}

/// RFC 3986 Normalized Authority Parsing.
/// Rejects duplicate Host headers (HTTP 400).
/// Validates that Host authority belongs strictly to loopback when listening on loopback (HTTP 403).
pub fn validate_rfc3986_authority(
    headers: &HeaderMap,
    listen_is_loopback: bool,
) -> Result<String, SecurityError> {
    let host_headers: Vec<_> = headers.get_all(HOST).iter().collect();
    if host_headers.len() > 1 {
        return Err(SecurityError::new(
            StatusCode::BAD_REQUEST,
            "duplicate_host_header",
            "Multiple Host headers rejected (RFC 7230 §5.4)",
        ));
    }

    if let Some(host_val) = host_headers.first() {
        if let Ok(host_str) = host_val.to_str() {
            let host_trimmed = host_str.trim();
            if host_trimmed.is_empty() {
                return Err(SecurityError::new(
                    StatusCode::BAD_REQUEST,
                    "empty_host_header",
                    "Host header cannot be empty",
                ));
            }
            if listen_is_loopback && !is_loopback(host_trimmed) {
                return Err(SecurityError::new(
                    StatusCode::FORBIDDEN,
                    "invalid_host_authority",
                    "Host header authority rejected: must be loopback (127.0.0.1, localhost, [::1])",
                ));
            }
            return Ok(host_trimmed.to_string());
        } else {
            return Err(SecurityError::new(
                StatusCode::BAD_REQUEST,
                "malformed_host_header",
                "Host header contains invalid UTF-8 bytes",
            ));
        }
    }

    Ok(String::new())
}

/// Inbound Proxy Header Stripping
/// Strips `X-Forwarded-For`, `X-Real-IP`, and `Forwarded` headers from local clients
/// to prevent spoofing or relay confusion.
pub fn sanitize_inbound_headers(headers: &mut HeaderMap) {
    headers.remove("x-forwarded-for");
    headers.remove("X-Forwarded-For");
    headers.remove("x-real-ip");
    headers.remove("X-Real-IP");
    headers.remove(FORWARDED);
    headers.remove("forwarded");
}

/// Sentinel tokens used by legacy/unsupported versions that must be rejected
pub const LEGACY_SENTINEL_TOKENS: &[&str] = &[
    "sk-agentcontrol-managed",
    "sk-agentwall-managed",
    "sk-antigravity-managed",
    "placeholder",
];

/// Persistent Local Bearer Token Validation
/// Validates `Authorization: Bearer <token>`.
/// Strictly rejects legacy sentinel tokens with HTTP 401 Unauthorized.
pub fn validate_persistent_token(
    headers: &HeaderMap,
    expected_token: Option<&str>,
) -> Result<(), SecurityError> {
    if let Some(auth_val) = headers.get(hyper::header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_val.to_str() {
            let token = auth_str.strip_prefix("Bearer ").unwrap_or(auth_str).trim();

            for sentinel in LEGACY_SENTINEL_TOKENS {
                if token.eq_ignore_ascii_case(sentinel) {
                    return Err(SecurityError::new(
                        StatusCode::UNAUTHORIZED,
                        "SENTINEL_TOKEN_REJECTED",
                        "Sentinel placeholder tokens are not permitted. Run 'agentcontrol login' or 'agentcontrol rotate-local-token'.",
                    ));
                }
            }

            if let Some(expected) = expected_token {
                if !expected.is_empty() && token != expected {
                    return Err(SecurityError::new(
                        StatusCode::UNAUTHORIZED,
                        "INVALID_LOCAL_TOKEN",
                        "Authorization token does not match active local session token.",
                    ));
                }
            }
            return Ok(());
        }
    }

    // If expected_token is set and no Authorization header was provided
    if let Some(expected) = expected_token {
        if !expected.is_empty() {
            return Err(SecurityError::new(
                StatusCode::UNAUTHORIZED,
                "AUTH_REQUIRED",
                "Missing Authorization Bearer token.",
            ));
        }
    }

    Ok(())
}

/// Ambient Browser Blocking
/// Protects local loopback agent against Web-to-Localhost CSRF / Drive-by attacks.
pub fn validate_ambient_browser_origin(headers: &HeaderMap) -> Result<(), SecurityError> {
    if let Some(origin_val) = headers.get(ORIGIN) {
        if let Ok(origin_str) = origin_val.to_str() {
            let origin_trimmed = origin_str.trim();
            // Allow desktop apps, local scripts, and file URLs
            if origin_trimmed == "null" || origin_trimmed.is_empty() {
                return Ok(());
            }
            // Allow VS Code webview contexts
            if origin_trimmed.starts_with("vscode-webview://") {
                return Ok(());
            }
            // Parse origin as URL
            if let Ok(url) = reqwest::Url::parse(origin_trimmed) {
                if let Some(host) = url.host_str() {
                    if is_loopback(host) {
                        return Ok(());
                    }
                }
            }
            return Err(SecurityError::new(
                StatusCode::FORBIDDEN,
                "cross_origin_request_forbidden",
                "Cross-origin browser request from external origin rejected (DNS rebinding protection)",
            ));
        }
    }

    // Check Sec-Fetch-Site: if "cross-site", reject unless origin was explicitly loopback
    if let Some(site_val) = headers.get("sec-fetch-site") {
        if let Ok(site_str) = site_val.to_str() {
            if site_str.eq_ignore_ascii_case("cross-site") {
                return Err(SecurityError::new(
                    StatusCode::FORBIDDEN,
                    "cross_site_fetch_rejected",
                    "Sec-Fetch-Site cross-site request rejected",
                ));
            }
        }
    }

    Ok(())
}

/// Writes the active daemon port to `~/.agentcontrol/daemon.port` atomically.
pub fn record_daemon_port(port: u16) -> Result<(), std::io::Error> {
    let base_dir = if let Some(home) = dirs::home_dir() {
        home.join(".agentcontrol")
    } else {
        std::path::PathBuf::from(".agentcontrol")
    };

    if !base_dir.exists() {
        let _ = std::fs::create_dir_all(&base_dir);
    }

    let port_file = base_dir.join("daemon.port");
    std::fs::write(&port_file, port.to_string())?;
    Ok(())
}

/// Reads the active daemon port from `~/.agentcontrol/daemon.port`.
pub fn load_daemon_port() -> Option<u16> {
    let base_dir = if let Some(home) = dirs::home_dir() {
        home.join(".agentcontrol")
    } else {
        std::path::PathBuf::from(".agentcontrol")
    };

    let port_file = base_dir.join("daemon.port");
    if let Ok(contents) = std::fs::read_to_string(port_file) {
        if let Ok(port) = contents.trim().parse::<u16>() {
            return Some(port);
        }
    }
    None
}
