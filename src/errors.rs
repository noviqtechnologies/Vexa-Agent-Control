//! Standardized Machine-Readable Error Taxonomy (REQ-SUP-001, PRD §FR-8.1).
//!
//! Provides stable, unambiguous error codes for CLI diagnostics, client integrations,
//! automation scripts, and support bundles.

use serde::{Deserialize, Serialize};

/// Standardized machine-readable error codes across Agent Control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    /// Workstation is not enrolled or authenticated with Control Hub.
    AuthRequired,
    /// Refresh token has expired or been revoked.
    AuthExpired,
    /// Device has been explicitly revoked by tenant administrator.
    DeviceRevoked,
    /// OS Keyring (Credential Manager / Keychain / Secret Service) is inaccessible.
    KeyringUnavailable,
    /// Loopback proxy port (18080) or OAuth callback port is already bound.
    PortUnavailable,
    /// External modification or drift in client configuration cannot be cleanly resolved.
    ConfigConflict,
    /// Spend or token budget allocation for current period is exhausted.
    BudgetExceeded,
    /// MCP tool call denied by policy rule (DLP, cycle trap, argument block).
    McpPolicyDenied,
    /// Hosted Gateway broker did not respond within deadline.
    GatewayTimeout,
    /// Unexpected internal runtime or filesystem error.
    InternalError,
}

impl ErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AuthRequired => "AUTH_REQUIRED",
            Self::AuthExpired => "AUTH_EXPIRED",
            Self::DeviceRevoked => "DEVICE_REVOKED",
            Self::KeyringUnavailable => "KEYRING_UNAVAILABLE",
            Self::PortUnavailable => "PORT_UNAVAILABLE",
            Self::ConfigConflict => "CONFIG_CONFLICT",
            Self::BudgetExceeded => "BUDGET_EXCEEDED",
            Self::McpPolicyDenied => "MCP_POLICY_DENIED",
            Self::GatewayTimeout => "GATEWAY_TIMEOUT",
            Self::InternalError => "INTERNAL_ERROR",
        }
    }

    pub fn default_message(&self) -> &'static str {
        match self {
            Self::AuthRequired => "Authentication required. Run 'agentcontrol login' to authenticate.",
            Self::AuthExpired => "Device session expired. Re-authenticate via 'agentcontrol login'.",
            Self::DeviceRevoked => "Device credentials revoked by administrator. Contact your security team.",
            Self::KeyringUnavailable => "OS Keyring service is unavailable. Check system credentials provider.",
            Self::PortUnavailable => "Required loopback port is in use by another process.",
            Self::ConfigConflict => "Configuration conflict detected between user edits and managed settings.",
            Self::BudgetExceeded => "Monthly or daily AI spend budget has been reached.",
            Self::McpPolicyDenied => "MCP tool invocation blocked by security policy rule.",
            Self::GatewayTimeout => "Gateway broker timed out while connecting upstream.",
            Self::InternalError => "An internal system error occurred.",
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.as_str(), self.default_message())
    }
}

impl std::error::Error for ErrorCode {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_serialization() {
        let code = ErrorCode::AuthRequired;
        let json = serde_json::to_string(&code).unwrap();
        assert_eq!(json, "\"AUTH_REQUIRED\"");

        let deserialized: ErrorCode = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, ErrorCode::AuthRequired);
    }
}
