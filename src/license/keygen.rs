//! CLI module to generate Ed25519 keypairs for signing AgentWall license tokens.

use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::SigningKey;
use rand::RngCore;
use std::fs;
use std::path::Path;

/// Generate an Ed25519 keypair and save the signing key and public key to disk.
pub fn generate_keypair(output_dir: &Path) -> Result<(), String> {
    if !output_dir.exists() {
        fs::create_dir_all(output_dir)
            .map_err(|e| format!("Failed to create output directory {}: {}", output_dir.display(), e))?;
    }

    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    let key_pkcs8 = signing_key
        .to_pkcs8_der()
        .map_err(|e| format!("Failed to encode PKCS8 private key: {}", e))?;
    let pub_spki = verifying_key
        .to_public_key_der()
        .map_err(|e| format!("Failed to encode SPKI public key: {}", e))?;

    let key_path = output_dir.join("vexa_license.key");
    let pub_path = output_dir.join("vexa_license.pub");

    // Write private signing key PKCS8 DER bytes
    fs::write(&key_path, key_pkcs8.as_bytes())
        .map_err(|e| format!("Failed to write private key to {}: {}", key_path.display(), e))?;

    // Write public verification key SPKI DER bytes
    fs::write(&pub_path, pub_spki.as_bytes())
        .map_err(|e| format!("Failed to write public key to {}: {}", pub_path.display(), e))?;

    println!("✓ Successfully generated Ed25519 license keypair:");
    println!("  Private signing key: {}", key_path.display());
    println!("  Public verification key: {}", pub_path.display());

    Ok(())
}
