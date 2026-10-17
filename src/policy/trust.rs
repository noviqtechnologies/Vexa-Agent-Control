//! Deployment policy trust configuration & keyring management (Gate 0.1).
//!
//! Separates operational security (EnforcementMode: credentials, watchdog)
//! from policy trust validation (PolicyTrustProfile: signed bundles, keyring, monotonicity).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeyRotationPolicy {
    /// Keys never expire unless revoked
    Manual,
    /// Keys expire after max_age_secs
    TimeBased { max_age_secs: u64 },
}

impl Default for KeyRotationPolicy {
    fn default() -> Self {
        Self::Manual
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustedKey {
    pub key_id: String,
    /// Hex-encoded 32-byte Ed25519 public key
    pub public_key_hex: String,
    pub description: Option<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct TrustedKeyring {
    pub keys: Vec<TrustedKey>,
    pub rotation_policy: KeyRotationPolicy,
}

impl TrustedKeyring {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_keys(keys: Vec<TrustedKey>) -> Self {
        Self {
            keys,
            rotation_policy: KeyRotationPolicy::Manual,
        }
    }

    pub fn public_key_hexes(&self) -> Vec<String> {
        self.keys.iter().map(|k| k.public_key_hex.clone()).collect()
    }

    pub fn is_key_trusted(&self, public_key_hex: &str) -> bool {
        let needle = public_key_hex.to_lowercase();
        self.keys
            .iter()
            .any(|k| k.public_key_hex.to_lowercase() == needle)
    }
}

/// Deployment trust profile — separate from EnforcementMode.
/// EnforcementMode controls credential stripping/watchdog behavior.
/// PolicyTrustProfile controls which policy sources are accepted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PolicyTrustProfile {
    /// Development: local YAML accepted unsigned. Ephemeral keys allowed for testing.
    Development,

    /// Managed: all policy activation requires a valid signed envelope
    /// verified against a configured trusted keyring.
    Managed {
        trusted_keyring: TrustedKeyring,
        require_revision_monotonicity: bool,
        max_policy_age_secs: Option<u64>,
    },
}

impl Default for PolicyTrustProfile {
    fn default() -> Self {
        Self::Development
    }
}

impl PolicyTrustProfile {
    pub fn is_managed(&self) -> bool {
        matches!(self, Self::Managed { .. })
    }

    pub fn trusted_keys(&self) -> Option<Vec<String>> {
        match self {
            Self::Development => None,
            Self::Managed {
                trusted_keyring, ..
            } => Some(trusted_keyring.public_key_hexes()),
        }
    }

    pub fn keyring(&self) -> Option<&TrustedKeyring> {
        match self {
            Self::Development => None,
            Self::Managed {
                trusted_keyring, ..
            } => Some(trusted_keyring),
        }
    }

    /// Construct PolicyTrustProfile from environment variables and local keyring.
    pub fn from_env() -> Self {
        let is_managed = std::env::var("AGENTCONTROL_MANAGED_MODE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
            || std::env::var("AGENTCONTROL_TRUST_PROFILE")
                .map(|v| v.eq_ignore_ascii_case("managed"))
                .unwrap_or(false);

        let mut keys = Vec::new();

        // 1. Check AGENTCONTROL_TRUSTED_KEYS (comma-separated hex public keys or JSON)
        if let Ok(keys_str) = std::env::var("AGENTCONTROL_TRUSTED_KEYS") {
            let trimmed = keys_str.trim();
            if trimmed.starts_with('[') {
                if let Ok(parsed_keys) = serde_json::from_str::<Vec<TrustedKey>>(trimmed) {
                    keys.extend(parsed_keys);
                } else if let Ok(hex_list) = serde_json::from_str::<Vec<String>>(trimmed) {
                    for (i, hex_key) in hex_list.into_iter().enumerate() {
                        keys.push(TrustedKey {
                            key_id: format!("env-key-{}", i + 1),
                            public_key_hex: hex_key,
                            description: Some(
                                "Configured via AGENTCONTROL_TRUSTED_KEYS".to_string(),
                            ),
                            created_at: chrono::Utc::now().to_rfc3339(),
                            expires_at: None,
                        });
                    }
                }
            } else {
                for (i, hex_key) in trimmed
                    .split(',')
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .enumerate()
                {
                    keys.push(TrustedKey {
                        key_id: format!("env-key-{}", i + 1),
                        public_key_hex: hex_key.to_string(),
                        description: Some("Configured via AGENTCONTROL_TRUSTED_KEYS".to_string()),
                        created_at: chrono::Utc::now().to_rfc3339(),
                        expires_at: None,
                    });
                }
            }
        }

        // 2. Check local keyring file if keys are still empty
        if keys.is_empty() {
            let keyring_path = std::env::var("AGENTCONTROL_KEYRING_PATH")
                .map(std::path::PathBuf::from)
                .ok()
                .or_else(|| dirs::home_dir().map(|h| h.join(".agentcontrol").join("keyring.json")));

            if let Some(path) = keyring_path {
                if path.exists() {
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        if let Ok(ring) = serde_json::from_str::<TrustedKeyring>(&content) {
                            keys = ring.keys;
                        }
                    }
                }
            }
        }

        if is_managed || !keys.is_empty() {
            let require_revision_monotonicity =
                std::env::var("AGENTCONTROL_REQUIRE_MONOTONIC_REVISION")
                    .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
                    .unwrap_or(true);

            let max_policy_age_secs = std::env::var("AGENTCONTROL_MAX_POLICY_AGE_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok());

            Self::Managed {
                trusted_keyring: TrustedKeyring::with_keys(keys),
                require_revision_monotonicity,
                max_policy_age_secs,
            }
        } else {
            Self::Development
        }
    }

    /// Strict variant: returns Err if managed mode is requested but the keyring is empty.
    ///
    /// PRD FR-007: Managed mode must fail closed — an empty keyring in managed mode means
    /// no bundles will ever be accepted, which is worse than refusing to start because
    /// it creates the illusion of managed enforcement with zero actual verification.
    ///
    /// Call this at daemon startup in managed/team mode. Use `from_env()` only for
    /// read-only status reporting where a degraded-but-running state is acceptable.
    pub fn from_env_strict() -> Result<Self, String> {
        let profile = Self::from_env();
        match &profile {
            Self::Managed {
                trusted_keyring, ..
            } if trusted_keyring.keys.is_empty() => {
                Err("Managed mode configured (AGENTCONTROL_MANAGED_MODE=1 or \
                     AGENTCONTROL_TRUST_PROFILE=managed) but no trusted public keys found. \
                     This means no signed policy bundles will ever be accepted — \
                     the endpoint cannot enforce centrally authorized policy. \
                     Fix: set AGENTCONTROL_TRUSTED_KEYS=<hex-pubkey> or \
                     AGENTCONTROL_KEYRING_PATH=<path-to-keyring.json>. \
                     See docs/guides/managed-mode-bootstrap.md."
                    .to_string())
            }
            _ => Ok(profile),
        }
    }

    /// Returns true if the trust root is sufficient to accept signed policy bundles.
    /// Development mode is always "valid" (accepts unsigned). Managed mode requires
    /// a non-empty keyring.
    pub fn is_trust_root_valid(&self) -> bool {
        match self {
            Self::Development => true,
            Self::Managed {
                trusted_keyring, ..
            } => !trusted_keyring.keys.is_empty(),
        }
    }
}
