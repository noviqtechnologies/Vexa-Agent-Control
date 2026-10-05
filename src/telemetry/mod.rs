//! Phase 3: Distributed Telemetry, W3C Trace Context, and OTLP Exporter
//!
//! Provides:
//! - W3C Traceparent generation and child span propagation (`trace_context`)
//! - OpenTelemetry (OTLP v1.0.0+) HTTP JSON exporter (`otlp`)

pub mod otlp;
pub mod trace_context;
