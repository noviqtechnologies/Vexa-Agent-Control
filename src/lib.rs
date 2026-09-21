//! # AgentWall Security Proxy & Policy Engine Core Library
//!
//! `agentwall` provides an enterprise-grade AI proxy, dynamic policy evaluation engine,
//! process wrapper, identity management, and audit logger for securing LLM applications and agentic workflows.
#![allow(
    clippy::too_many_arguments,
    clippy::type_complexity,
    clippy::upper_case_acronyms,
    clippy::large_enum_variant,
    clippy::single_match,
    clippy::collapsible_match,
    clippy::collapsible_if,
    clippy::needless_borrows_for_generic_args,
    clippy::derivable_impls,
    clippy::unnecessary_unwrap,
    clippy::manual_strip,
    clippy::lines_filter_map_ok,
    clippy::redundant_pattern_matching,
    clippy::let_unit_value,
    clippy::needless_return,
    clippy::new_without_default,
    clippy::never_loop,
    clippy::manual_range_contains,
    clippy::manual_unwrap_or,
    clippy::manual_ok_err
)]

pub mod audit;
pub mod ca;
pub mod check;
pub mod cli;
pub mod control_plane_client;
pub mod doctor;
pub mod errors;
pub mod generate_policy;
pub mod identity;
pub mod kill;
pub mod lint;
pub mod local_dashboard;
pub mod logging;
pub mod mcp;
pub mod policy;
pub mod promote;
pub mod proxy;
pub mod report;
pub mod self_healing;
pub mod service;
pub mod support;
pub mod validate;
pub mod verify;
pub mod wrap;

pub mod compliance;
pub mod license;
pub mod sentry;
pub mod spend;

pub mod bench;
pub mod detector;

#[cfg(feature = "passport-injection")]
pub mod passport;

#[cfg(feature = "hub-sync")]
pub mod sync;

#[cfg(feature = "enterprise")]
pub mod enterprise;
