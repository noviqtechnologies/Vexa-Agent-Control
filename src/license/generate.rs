//! CLI module to issue Ed25519-signed JWT license tokens for AgentWall Hub & Gateway.

use chrono::{Duration, Utc};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Claims included in an Ed25519-signed AgentWall license JWT.
#[derive(Debug, Serialize, Deserialize)]
pub struct LicenseClaims {
    /// Organization identifier (e.g. "acme-corp")
    pub sub: String,
    /// License tier ("community", "team", "enterprise")
    pub tier: String,
    /// Maximum allowed agent seats / devices
    pub max_seats: usize,
    /// Enabled enterprise feature flags
    pub features: Vec<String>,
    /// Issued at (Unix timestamp UTC)
    #[serde(with = "chrono::serde::ts_seconds")]
    pub iat: chrono::DateTime<Utc>,
    /// Expires at (Unix timestamp UTC)
    #[serde(with = "chrono::serde::ts_seconds")]
    pub exp: chrono::DateTime<Utc>,
}

/// Issues an Ed25519-signed license JWT token.
pub fn generate_license(
    org: &str,
    tier: &str,
    seats: usize,
    days: i64,
    signing_key_path: &Path,
    custom_features: Option<Vec<String>>,
) -> Result<String, String> {
    let key_bytes = fs::read(signing_key_path)
        .map_err(|e| format!("Failed to read signing key from {}: {}", signing_key_path.display(), e))?;

    let encoding_key = if key_bytes.len() == 32 {
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        use ed25519_dalek::SigningKey;
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&key_bytes);
        let signing_key = SigningKey::from_bytes(&seed);
        let pkcs8 = signing_key
            .to_pkcs8_der()
            .map_err(|e| format!("Failed to encode private key PKCS8: {}", e))?;
        EncodingKey::from_ed_der(pkcs8.as_bytes())
    } else {
        EncodingKey::from_ed_der(&key_bytes)
    };

    let now = Utc::now();
    let expires_at = now + Duration::days(days);

    let features = match custom_features {
        Some(f) if !f.is_empty() => f,
        _ => match tier {
            "enterprise" => vec![
                "siem_aggregation".to_string(),
                "spend_caps".to_string(),
                "airgap_oidc".to_string(),
                "compliance_reports".to_string(),
            ],
            "team" => vec![
                "siem_aggregation".to_string(),
                "spend_caps".to_string(),
            ],
            _ => vec![],
        },
    };

    let claims = LicenseClaims {
        sub: org.to_string(),
        tier: tier.to_string(),
        max_seats: seats,
        features,
        iat: now,
        exp: expires_at,
    };

    let mut header = Header::new(Algorithm::EdDSA);
    header.typ = Some("JWT".to_string());

    let token = encode(&header, &claims, &encoding_key)
        .map_err(|e| format!("Failed to encode license JWT: {}", e))?;

    Ok(token)
}
