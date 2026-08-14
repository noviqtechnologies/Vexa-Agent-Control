#[cfg(test)]
mod tests {
    use crate::identity::transcript::TranscriptBuilder;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn test_canonical_transcript_deterministic_format() {
        let builder = TranscriptBuilder::new(
            "tx-123",
            "ch-456",
            "tenant-789",
            "fp-ed25519-abc",
            "csr-sha256-def",
        );

        let canonical = builder.build_canonical_string();
        assert_eq!(
            canonical,
            "tx-123|ch-456|enroll.vexasec.io|tenant-789|fp-ed25519-abc|csr-sha256-def|2.0"
        );

        let hash_hex = builder.compute_sha256_hex();
        assert_eq!(hash_hex.len(), 64);
    }

    #[test]
    fn test_transcript_signature_verification() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let builder = TranscriptBuilder::new(
            "0198d5b4-7376-7d90-8bc5-6dc3d4e80c26",
            "0198d5b4-89aa-7b1f-9b1e-0c52e78b3ee0",
            "0198d5b4-6fd7-7e2e-a6e2-c8d4df112a11",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "ca978112ca1bbdcafac231b39a23dc4da7860819c1966ec12179e5b7b99a4fc5",
        );

        let (sig_base64url, _) = builder.sign(&signing_key);
        let sig_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &sig_base64url,
        )
        .expect("signature must be valid base64url");

        let canonical = builder.build_canonical_string();
        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap();
        assert!(verifying_key.verify_strict(canonical.as_bytes(), &sig).is_ok());
    }
}
