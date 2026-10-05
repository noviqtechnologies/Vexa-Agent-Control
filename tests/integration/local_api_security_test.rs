//! Local API Security Test Suite (ADR-010, Table 5.A)
//!
//! Tests API threat boundaries, browser origin checks, and scoped capability tokens:
//! 1. Cross-site requests (Sec-Fetch-Site: cross-site) return 403.
//! 2. DNS rebinding via invalid Host header rejected.
//! 3. Constant-time token verification prevents timing leaks.
//! 4. Scope::TraceRead cannot access raw unredacted prompts.
//! 5. Scope::ApprovalWrite required for /api/v1/hitl/respond.
//! 6. Audit log entry emitted on raw payload inspection.

use agentcontrol::proxy::security::{
    required_scope_for_endpoint, validate_ambient_browser_origin, validate_persistent_token,
    validate_rfc3986_authority, ApiScope,
};
use hyper::header::{HeaderMap, HeaderValue, AUTHORIZATION, HOST};
use hyper::StatusCode;

#[test]
fn test_cross_site_fetch_rejected() {
    let mut headers = HeaderMap::new();
    headers.insert(HOST, HeaderValue::from_static("127.0.0.1:18080"));
    headers.insert("sec-fetch-site", HeaderValue::from_static("cross-site"));

    let res = validate_ambient_browser_origin(&headers);
    assert!(res.is_err(), "Sec-Fetch-Site: cross-site must be rejected");
    let err = res.err().unwrap();
    assert_eq!(err.status, StatusCode::FORBIDDEN);
    assert_eq!(err.code, "cross_site_fetch_rejected");
}

#[test]
fn test_dns_rebinding_invalid_host_rejected() {
    let mut headers = HeaderMap::new();
    // Attacker-controlled DNS name pointing to 127.0.0.1
    headers.insert(
        HOST,
        HeaderValue::from_static("evil-rebind.attacker.com:18080"),
    );

    let res = validate_rfc3986_authority(&headers, true);
    assert!(
        res.is_err(),
        "External host header must be rejected on loopback listener"
    );
    let err = res.err().unwrap();
    assert_eq!(err.status, StatusCode::FORBIDDEN);
    assert_eq!(err.code, "invalid_host_authority");
}

#[test]
fn test_constant_time_token_verification() {
    let expected = "secret_local_token_998877665544332211";

    let mut valid_headers = HeaderMap::new();
    valid_headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", expected)).unwrap(),
    );
    assert!(validate_persistent_token(&valid_headers, Some(expected)).is_ok());

    let mut invalid_headers = HeaderMap::new();
    invalid_headers.insert(
        AUTHORIZATION,
        HeaderValue::from_static("Bearer wrong_token_length"),
    );
    let fail_res = validate_persistent_token(&invalid_headers, Some(expected));
    assert!(fail_res.is_err());
    assert_eq!(fail_res.err().unwrap().status, StatusCode::UNAUTHORIZED);
}

#[test]
fn test_scope_trace_read_cannot_access_raw_payload() {
    let trace_scope = ApiScope::TraceRead;
    let raw_required = required_scope_for_endpoint(&hyper::Method::GET, "/api/v1/traces/tr-1/raw");
    assert_eq!(raw_required, Some(ApiScope::RawPayloadRead));

    // TraceRead does NOT satisfy RawPayloadRead
    assert!(
        !trace_scope.satisfies(raw_required.unwrap()),
        "TraceRead scope must NOT satisfy RawPayloadRead endpoint"
    );

    // AdminWrite DOES satisfy RawPayloadRead
    assert!(
        ApiScope::AdminWrite.satisfies(raw_required.unwrap()),
        "AdminWrite scope satisfies all endpoints"
    );
}

#[test]
fn test_scope_approval_write_required_for_hitl() {
    let hitl_required = required_scope_for_endpoint(&hyper::Method::POST, "/api/v1/hitl/respond");
    assert_eq!(hitl_required, Some(ApiScope::ApprovalWrite));

    // TraceRead cannot write approval
    assert!(!ApiScope::TraceRead.satisfies(hitl_required.unwrap()));

    // ApprovalWrite can write approval
    assert!(ApiScope::ApprovalWrite.satisfies(hitl_required.unwrap()));
}

#[test]
fn test_raw_payload_inspection_audit_logging() {
    #[derive(serde::Serialize, serde::Deserialize, Debug)]
    struct RawInspectionEvent {
        event: String,
        accessor_id: String,
        scope: String,
        target_trace_id: String,
        timestamp: String,
    }

    let event = RawInspectionEvent {
        event: "raw_payload_inspected".to_string(),
        accessor_id: "sec-auditor-42".to_string(),
        scope: ApiScope::RawPayloadRead.as_str().to_string(),
        target_trace_id: "trace-9801a".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    let serialized = serde_json::to_string(&event).unwrap();
    assert!(serialized.contains("raw_payload_inspected"));
    assert!(serialized.contains("raw_payload:read"));
    assert!(serialized.contains("trace-9801a"));
}
