//! FR-3: Tenant Web Dashboard — embedded HTML module.
//!
//! The tenant dashboard HTML is embedded at compile time via `include_str!()`.
//! It is served by the proxy server at `GET /` when `agentwall dev` is running.
//! No external files or Node.js are required — the entire UI ships inside the binary.

/// Returns the embedded tenant dashboard HTML for the local proxy web UI.
pub fn local_dashboard_html() -> &'static str {
    include_str!("local_dashboard.html")
}

