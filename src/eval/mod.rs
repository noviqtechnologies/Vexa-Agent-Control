//! Phase 2: Measurable Security in CI — Deterministic Replay Engine
//!
//! Provides the `agentcontrol eval` command infrastructure:
//! - Content-addressed trace dataset reader (SHA-256 indexed)
//! - Mock network & MCP tool execution provider (strictly prohibits real I/O)
//! - Deterministic policy re-evaluation against candidate policies
//! - Disaggregated detector precision & recall reporting (DLP, Injection, Command, Filesystem, Egress)
//!
//! Conforms to: Plan Review Feedback v4 §Phase-2, ADR-006 (Observability), ADR-004 (Replay sandboxing)

pub mod replay;
pub mod report;
