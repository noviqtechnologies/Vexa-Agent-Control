//! # AgentWall Security Proxy & Policy Engine Core Library
//!
//! `agentwall` provides an enterprise-grade AI proxy, dynamic policy evaluation engine,
//! process wrapper, identity management, and audit logger for securing LLM applications and agentic workflows.

pub mod audit;
pub mod check;
pub mod cli;
pub mod init;
pub mod kill;
pub mod logging;
pub mod policy;
pub mod promote;
pub mod proxy;
pub mod report;
pub mod wrap;
pub mod validate;
pub mod lint;
pub mod local_dashboard;
pub mod control_plane_client;
pub mod generate_policy;
pub mod self_healing;
pub mod identity;

pub mod license;
pub mod spend;