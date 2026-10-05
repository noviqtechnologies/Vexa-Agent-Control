//! W3C Distributed Tracing and Cross-Developer Correlation Context
//!
//! Implements W3C Trace Context (traceparent: 00-{trace_id}-{span_id}-{flags})
//! and cross-developer/multi-agent correlation attributes for Phase 3.

use rand::RngCore;
use serde::{Deserialize, Serialize};

/// W3C compliant Trace Context representation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceContext {
    /// 32 hex character trace ID (16 bytes)
    pub trace_id: String,
    /// 16 hex character current span ID (8 bytes)
    pub span_id: String,
    /// Optional 16 hex character parent span ID (8 bytes)
    pub parent_span_id: Option<String>,
    /// 2 hex character trace flags (e.g. "01" = sampled)
    pub flags: String,
    /// Developer or user ID for workspace attribution (Phase 3 Multi-User)
    pub developer_id: Option<String>,
    /// High-level multi-step run / agent session ID
    pub run_id: Option<String>,
}

impl TraceContext {
    /// Generate a fresh, root TraceContext
    pub fn new_root(developer_id: Option<String>, run_id: Option<String>) -> Self {
        let mut rng = rand::thread_rng();
        let mut trace_bytes = [0u8; 16];
        let mut span_bytes = [0u8; 8];
        rng.fill_bytes(&mut trace_bytes);
        rng.fill_bytes(&mut span_bytes);

        Self {
            trace_id: hex::encode(trace_bytes),
            span_id: hex::encode(span_bytes),
            parent_span_id: None,
            flags: "01".to_string(),
            developer_id,
            run_id,
        }
    }

    /// Parse a W3C traceparent header or generate a new root context
    /// Format: 00-{32 hex trace_id}-{16 hex span_id}-{02 hex flags}
    pub fn from_traceparent_or_generate(
        raw_header: Option<&str>,
        developer_id: Option<String>,
        run_id: Option<String>,
    ) -> Self {
        if let Some(raw) = raw_header {
            let parts: Vec<&str> = raw.trim().split('-').collect();
            if parts.len() == 4
                && parts[0] == "00"
                && parts[1].len() == 32
                && parts[2].len() == 16
                && parts[3].len() == 2
            {
                let trace_id = parts[1].to_lowercase();
                // Reject all-zero trace_id per W3C specification
                if trace_id != "00000000000000000000000000000000" {
                    return Self {
                        trace_id,
                        span_id: parts[2].to_lowercase(),
                        parent_span_id: None,
                        flags: parts[3].to_lowercase(),
                        developer_id,
                        run_id,
                    };
                }
            }
        }

        Self::new_root(developer_id, run_id)
    }

    /// Create a child span context under this trace context (preserving trace_id)
    pub fn child_span(&self) -> Self {
        let mut rng = rand::thread_rng();
        let mut span_bytes = [0u8; 8];
        rng.fill_bytes(&mut span_bytes);

        Self {
            trace_id: self.trace_id.clone(),
            span_id: hex::encode(span_bytes),
            parent_span_id: Some(self.span_id.clone()),
            flags: self.flags.clone(),
            developer_id: self.developer_id.clone(),
            run_id: self.run_id.clone(),
        }
    }

    /// Format as standard W3C traceparent header
    pub fn to_traceparent(&self) -> String {
        format!("00-{}-{}-{}", self.trace_id, self.span_id, self.flags)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_root_generates_valid_w3c() {
        let ctx = TraceContext::new_root(Some("dev-alice".into()), Some("run-101".into()));
        assert_eq!(ctx.trace_id.len(), 32);
        assert_eq!(ctx.span_id.len(), 16);
        assert!(ctx.parent_span_id.is_none());
        assert_eq!(ctx.flags, "01");
        assert_eq!(ctx.developer_id.as_deref(), Some("dev-alice"));
        assert_eq!(ctx.run_id.as_deref(), Some("run-101"));

        let header = ctx.to_traceparent();
        assert!(header.starts_with("00-"));
        assert_eq!(header.len(), 55); // 2 + 1 + 32 + 1 + 16 + 1 + 2 = 55
    }

    #[test]
    fn test_parse_valid_traceparent() {
        let raw = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let ctx = TraceContext::from_traceparent_or_generate(Some(raw), Some("bob".into()), None);
        assert_eq!(ctx.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(ctx.span_id, "00f067aa0ba902b7");
        assert_eq!(ctx.flags, "01");
        assert_eq!(ctx.to_traceparent(), raw);
    }

    #[test]
    fn test_parse_invalid_traceparent_generates_new() {
        let invalid = "invalid-header";
        let ctx = TraceContext::from_traceparent_or_generate(Some(invalid), None, None);
        assert_eq!(ctx.trace_id.len(), 32);
        assert_ne!(ctx.trace_id, "00000000000000000000000000000000");
    }

    #[test]
    fn test_child_span_correlation() {
        let parent = TraceContext::new_root(Some("dev-1".into()), Some("run-1".into()));
        let child = parent.child_span();

        assert_eq!(child.trace_id, parent.trace_id);
        assert_ne!(child.span_id, parent.span_id);
        assert_eq!(child.parent_span_id, Some(parent.span_id));
        assert_eq!(child.developer_id, parent.developer_id);
        assert_eq!(child.run_id, parent.run_id);
    }
}
