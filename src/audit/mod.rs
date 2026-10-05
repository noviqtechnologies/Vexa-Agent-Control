//! Security audit logging, SIEM integration, and cryptographic audit verifier subsystem.

pub mod legacy_v1;
pub mod logger;
pub mod maintenance;
pub mod outbox;
pub mod siem;
pub mod v2;
pub mod verifier;
pub mod zk_export;
