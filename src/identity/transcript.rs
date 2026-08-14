//! Canonical enrollment transcript generator and Ed25519 proof signer.

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

pub struct TranscriptBuilder<'a> {
    pub transaction_id: &'a str,
    pub challenge_id: &'a str,
    pub audience: &'a str,
    pub tenant_id: &'a str,
    pub ed25519_fingerprint: &'a str,
    pub csr_sha256: &'a str,
    pub schema_version: &'a str,
}

impl<'a> TranscriptBuilder<'a> {
    pub fn new(
        transaction_id: &'a str,
        challenge_id: &'a str,
        tenant_id: &'a str,
        ed25519_fingerprint: &'a str,
        csr_sha256: &'a str,
    ) -> Self {
        Self {
            transaction_id,
            challenge_id,
            audience: "enroll.vexasec.io",
            tenant_id,
            ed25519_fingerprint,
            csr_sha256,
            schema_version: "2.0",
        }
    }

    /// Builds the canonical pipe-delimited UTF-8 transcript string
    pub fn build_canonical_string(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}|{}",
            self.transaction_id,
            self.challenge_id,
            self.audience,
            self.tenant_id,
            self.ed25519_fingerprint,
            self.csr_sha256,
            self.schema_version
        )
    }

    /// Computes the SHA-256 digest hex string
    pub fn compute_sha256_hex(&self) -> String {
        let canonical = self.build_canonical_string();
        hex::encode(Sha256::digest(canonical.as_bytes()))
    }

    /// Signs the canonical transcript using the Ed25519 private key
    pub fn sign(
        &self,
        signing_key: &SigningKey,
    ) -> (String, String) {
        let canonical = self.build_canonical_string();
        let hash_hex = self.compute_sha256_hex();
        let signature = signing_key.sign(canonical.as_bytes());
        let sig_base64url = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            signature.to_bytes(),
        );

        (sig_base64url, hash_hex)
    }
}
