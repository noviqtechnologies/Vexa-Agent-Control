//! Decodes, verifies Ed25519 signatures, and validates feature license claims for AgentWall Enterprise.

use chrono::{DateTime, Utc};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

/// A decoded, validated AgentWall license JWT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct License {
    #[serde(rename = "sub")]
    pub org_id: String,
    pub features: Vec<String>,
    #[serde(rename = "iat", with = "chrono::serde::ts_seconds")]
    pub issued_at: DateTime<Utc>,
    #[serde(rename = "exp", with = "chrono::serde::ts_seconds")]
    pub expires_at: DateTime<Utc>,
}

/// Errors raised during enterprise license verification.
#[derive(Debug)]
pub enum LicenseError {
    /// No license key provided in config or environment.
    Missing,
    /// Ed25519 cryptographic signature check failed.
    InvalidSignature,
    /// License timestamp has expired.
    Expired { expired_at: DateTime<Utc> },
    /// Enterprise feature is missing from the license's `features` array.
    FeatureNotLicensed { feature: String },
    /// Failed to parse license JWT token.
    Malformed(String),
}

impl std::fmt::Display for LicenseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LicenseError::Missing => write!(f, "Missing license key in config."),
            LicenseError::InvalidSignature => write!(f, "Invalid license signature."),
            LicenseError::Expired { expired_at } => {
                write!(f, "License expired at {}.", expired_at)
            }
            LicenseError::FeatureNotLicensed { feature } => {
                write!(f, "Feature '{}' is not enabled in your current license.", feature)
            }
            LicenseError::Malformed(e) => write!(f, "Malformed license key: {}", e),
        }
    }
}

/// Evaluates Ed25519-signed enterprise license tokens against Noviq public keys.
pub struct LicenseValidator {
    decoding_key: DecodingKey,
}

impl LicenseValidator {
    /// Constructs a `LicenseValidator` using embedded Ed25519 public key bytes.
    pub fn new() -> Result<Self, String> {
        let public_key_bytes = include_bytes!("../../keys/noviq_license.pub");
        let decoding_key = DecodingKey::from_ed_der(public_key_bytes);
        Ok(Self { decoding_key })
    }

    /// Decodes and verifies the signature and expiry timestamp of a license JWT string.
    ///
    /// # Arguments
    /// * `license_key` - Encoded JWT license string.
    ///
    /// # Errors
    /// Returns `LicenseError::InvalidSignature`, `LicenseError::Expired`, or `LicenseError::Malformed`.
    pub fn validate(&self, license_key: &str) -> Result<License, LicenseError> {
        let mut validation = Validation::new(Algorithm::EdDSA);
        // Do not validate exp here automatically so we can return a specific error
        validation.validate_exp = false;

        let token_data = decode::<License>(
            license_key,
            &self.decoding_key,
            &validation,
        )
        .map_err(|e| match e.kind() {
            jsonwebtoken::errors::ErrorKind::InvalidSignature => LicenseError::InvalidSignature,
            _ => LicenseError::Malformed(e.to_string()),
        })?;

        let license = token_data.claims;
        let now = Utc::now();

        if license.expires_at < now {
            return Err(LicenseError::Expired {
                expired_at: license.expires_at,
            });
        }

        Ok(license)
    }

    /// Checks if the given feature string is enabled in the decoded license.
    pub fn has_feature(&self, license: &License, feature: &str) -> bool {
        license.features.contains(&feature.to_string())
    }
}

/// Helper function to check whether an active, valid enterprise license key is present.
/// Checks the provided `license_key` string or the `AGENTWALL_LICENSE_KEY` environment variable.
pub fn is_license_valid(license_key: Option<&str>) -> bool {
    let key = match license_key {
        Some(k) if !k.is_empty() => k.to_string(),
        _ => match std::env::var("AGENTWALL_LICENSE_KEY") {
            Ok(k) if !k.is_empty() => k,
            _ => return false,
        },
    };

    if let Ok(validator) = LicenseValidator::new() {
        validator.validate(&key).is_ok()
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO: Write tests with mock ed25519 keys
}
