//! Enterprise licensing, cryptographic signature validation, and feature tier gating module.

pub mod validator;

pub use validator::{License, LicenseError, LicenseValidator};
