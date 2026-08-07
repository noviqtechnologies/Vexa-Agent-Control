//! Device PKI Identity module — manages Ed25519 key generation, OS Keychain storage,
//! payload signing, and Hub token persistence.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use keyring::Entry;
use rand::rngs::OsRng;

const SERVICE_NAME: &str = "agentwall";
const KEY_NAME: &str = "device_identity_key";

pub struct DeviceIdentity {
    pub device_id: String,
    pub public_key_hex: String,
    pub signing_key: SigningKey,
}

impl DeviceIdentity {
    /// Load existing device identity from OS Keyring or fallback file, or generate a new one.
    pub fn load_or_create() -> Result<Self, String> {
        let hostname = get_hostname();
        
        // 1. Try loading private key bytes from OS Keyring
        if let Ok(entry) = Entry::new(SERVICE_NAME, KEY_NAME) {
            if let Ok(secret_hex) = entry.get_password() {
                if let Ok(bytes) = hex::decode(&secret_hex) {
                    if bytes.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        let signing_key = SigningKey::from_bytes(&arr);
                        let verifying_key: VerifyingKey = signing_key.verifying_key();
                        let pub_hex = hex::encode(verifying_key.as_bytes());
                        let device_id = derive_device_id(&hostname, &pub_hex);

                        return Ok(Self {
                            device_id,
                            public_key_hex: pub_hex,
                            signing_key,
                        });
                    }
                }
            }
        }

        // 2. Try loading from fallback file ~/.agentwall/device_identity.key
        let key_path = get_key_filepath()?;
        if key_path.exists() {
            if let Ok(secret_hex) = fs::read_to_string(&key_path) {
                let trimmed = secret_hex.trim();
                if let Ok(bytes) = hex::decode(trimmed) {
                    if bytes.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        let signing_key = SigningKey::from_bytes(&arr);
                        let verifying_key: VerifyingKey = signing_key.verifying_key();
                        let pub_hex = hex::encode(verifying_key.as_bytes());
                        let device_id = derive_device_id(&hostname, &pub_hex);

                        // Try writing to OS keyring for future runs
                        if let Ok(entry) = Entry::new(SERVICE_NAME, KEY_NAME) {
                            let _ = entry.set_password(trimmed);
                        }

                        return Ok(Self {
                            device_id,
                            public_key_hex: pub_hex,
                            signing_key,
                        });
                    }
                }
            }
        }

        // 3. Generate fresh Ed25519 keypair
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        let secret_hex = hex::encode(signing_key.to_bytes());
        let pub_hex = hex::encode(verifying_key.as_bytes());
        let device_id = derive_device_id(&hostname, &pub_hex);

        // Store in OS Keyring
        if let Ok(entry) = Entry::new(SERVICE_NAME, KEY_NAME) {
            let _ = entry.set_password(&secret_hex);
        }

        // Store in fallback file with restricted permissions
        save_fallback_file(&key_path, &secret_hex)?;

        Ok(Self {
            device_id,
            public_key_hex: pub_hex,
            signing_key,
        })
    }

    /// Sign a payload using Ed25519 signing key, returning hex signature string.
    pub fn sign(&self, payload: &[u8]) -> String {
        let signature = self.signing_key.sign(payload);
        hex::encode(signature.to_bytes())
    }
}

/// Derive a deterministic device ID from hostname and public key hash.
fn derive_device_id(hostname: &str, pub_hex: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(hostname.as_bytes());
    h.update(pub_hex.as_bytes());
    let hash = hex::encode(h.finalize());
    let short_hash = &hash[..8];
    format!("dev-{}-{}", sanitize_hostname(hostname), short_hash)
}

fn sanitize_hostname(h: &str) -> String {
    h.chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .to_lowercase()
}

fn get_hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "localhost".to_string())
}

fn get_key_filepath() -> Result<PathBuf, String> {
    let home = dirs::home_dir().ok_or_else(|| "cannot resolve home directory".to_string())?;
    let dir = home.join(".agentwall");
    if !dir.exists() {
        fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    }
    Ok(dir.join("device_identity.key"))
}

fn save_fallback_file(path: &PathBuf, content: &str) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("cannot open key file: {}", e))?;
        file.write_all(content.as_bytes())
            .map_err(|e| format!("cannot write key file: {}", e))?;
    }

    #[cfg(not(unix))]
    {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)
            .map_err(|e| format!("cannot open key file: {}", e))?;
        file.write_all(content.as_bytes())
            .map_err(|e| format!("cannot write key file: {}", e))?;
    }

    Ok(())
}

/// Persist signed Device JWT token returned by Control Hub to ~/.agentwall/device_token
pub fn save_device_token(token: &str) -> Result<(), String> {
    let home = dirs::home_dir().ok_or_else(|| "cannot resolve home directory".to_string())?;
    let dir = home.join(".agentwall");
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let token_path = dir.join("device_token");
    fs::write(&token_path, token).map_err(|e| format!("cannot write device token: {}", e))
}

/// Load saved Device JWT token from ~/.agentwall/device_token
pub fn load_device_token() -> Option<String> {
    let home = dirs::home_dir()?;
    let token_path = home.join(".agentwall").join("device_token");
    let content = fs::read_to_string(token_path).ok()?;
    let trimmed = content.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

use colored::*;

#[derive(serde::Serialize)]
struct EnrollApiRequest<'a> {
    enrollment_token: &'a str,
    device_id: &'a str,
    hostname: &'a str,
    os_arch: String,
    os_family: &'a str,
    public_key: &'a str,
    agentwall_version: &'a str,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct EnrollApiResponse {
    device_id: String,
    device_token: String,
    expires_at_ms: i64,
}

/// Executes the `agentwall enroll` command.
pub async fn run_enroll(token: &str, hub_url: &str) -> i32 {
    if token.is_empty() {
        eprintln!("{} Enrollment token is required (--token or AGENTWALL_ENROLLMENT_TOKEN)", "✖".red());
        return 1;
    }

    println!("{} AgentWall PKI Device Enrollment", "●".green().bold());
    let masked_token = if token.len() > 8 {
        format!("{}...{}", &token[..4], &token[token.len() - 4..])
    } else {
        "***".to_string()
    };
    println!("  Connecting to Control Hub: {} (token: {})", hub_url.cyan(), masked_token.dimmed());

    let identity = match DeviceIdentity::load_or_create() {
        Ok(id) => id,
        Err(e) => {
            eprintln!("{} Failed to load or generate device identity: {}", "✖".red(), e);
            return 1;
        }
    };

    println!("  Device ID: {}", identity.device_id.bold());
    println!("  Public Key: {}...", &identity.public_key_hex[..16]);

    let hostname = get_hostname();
    let os_arch = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
    let os_family = std::env::consts::OS;
    let pkg_ver = env!("CARGO_PKG_VERSION");

    let payload = EnrollApiRequest {
        enrollment_token: token,
        device_id: &identity.device_id,
        hostname: &hostname,
        os_arch,
        os_family,
        public_key: &identity.public_key_hex,
        agentwall_version: pkg_ver,
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build();

    let client = match client {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{} Failed to build HTTP client: {}", "✖".red(), e);
            return 1;
        }
    };

    let enroll_endpoint = format!("{}/api/v1/enroll", hub_url.trim_end_matches('/'));
    let response = client.post(&enroll_endpoint).json(&payload).send().await;

    match response {
        Ok(res) if res.status().is_success() => {
            if let Ok(body) = res.json::<EnrollApiResponse>().await {
                if let Err(e) = save_device_token(&body.device_token) {
                    eprintln!("{} Failed to save device token: {}", "⚠".yellow(), e);
                }
                println!();
                println!("{} Device enrolled successfully!", "✔".green().bold());
                println!("  Device Token saved to ~/.agentwall/device_token");
                0
            } else {
                eprintln!("{} Invalid response format from Hub", "✖".red());
                1
            }
        }
        Ok(res) => {
            let status = res.status();
            let err_text = res.text().await.unwrap_or_default();
            eprintln!("{} Enrollment failed (HTTP {}): {}", "✖".red(), status, err_text);
            1
        }
        Err(e) => {
            eprintln!("{} Cannot connect to Control Hub at {}: {}", "✖".red(), enroll_endpoint, e);
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_identity_load_or_create() {
        let identity = DeviceIdentity::load_or_create().unwrap();
        assert!(!identity.device_id.is_empty());
        assert!(!identity.public_key_hex.is_empty());
        assert_eq!(identity.public_key_hex.len(), 64);
    }

    #[test]
    fn test_device_identity_signing() {
        let identity = DeviceIdentity::load_or_create().unwrap();
        let payload = b"test_payload_string";
        let sig_hex = identity.sign(payload);
        assert_eq!(sig_hex.len(), 128); // Ed25519 signature is 64 bytes -> 128 hex chars
    }
}
