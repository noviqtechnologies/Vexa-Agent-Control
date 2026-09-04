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

        // 2. Try loading from fallback file ~/.agentcontrol/device_identity.key (and other Windows profiles if Session 0)
        let mut candidate_paths = Vec::new();
        if let Ok(key_path) = get_key_filepath() {
            candidate_paths.push(key_path);
        }
        #[cfg(windows)]
        {
            for profile in crate::service::windows_profiles::enumerate_user_profiles() {
                let p = profile.join(".agentcontrol").join("device_identity.key");
                if !candidate_paths.contains(&p) {
                    candidate_paths.push(p);
                }
            }
        }

        for key_path in candidate_paths {
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
        let primary_key_path = get_key_filepath()?;
        save_fallback_file(&primary_key_path, &secret_hex)?;

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

pub fn get_hostname() -> String {
    #[cfg(windows)]
    {
        if let Ok(c) = std::env::var("COMPUTERNAME") {
            let t = c.trim();
            if !t.is_empty() && t.to_lowercase() != "localhost" {
                return t.to_string();
            }
        }
    }
    if let Ok(h) = std::env::var("HOSTNAME") {
        let t = h.trim();
        if !t.is_empty() && t.to_lowercase() != "localhost" {
            return t.to_string();
        }
    }
    if let Ok(c) = std::env::var("COMPUTERNAME") {
        let t = c.trim();
        if !t.is_empty() && t.to_lowercase() != "localhost" {
            return t.to_string();
        }
    }
    if let Ok(h) = std::env::var("HOST") {
        let t = h.trim();
        if !t.is_empty() && t.to_lowercase() != "localhost" {
            return t.to_string();
        }
    }
    if let Ok(output) = std::process::Command::new("hostname").output() {
        if let Ok(s) = String::from_utf8(output.stdout) {
            let t = s.trim();
            if !t.is_empty() && t.to_lowercase() != "localhost" {
                return t.to_string();
            }
        }
    }
    "workstation".to_string()
}

pub fn get_current_user() -> String {
    #[cfg(windows)]
    {
        if let Ok(u) = std::env::var("USERNAME") {
            let t = u.trim();
            if !t.is_empty() && t.to_lowercase() != "system" && !t.to_lowercase().ends_with('$') {
                return t.to_string();
            }
        }
        let homes = crate::wrap::config_path::get_windows_user_homes();
        if let Some(first) = homes.first() {
            if let Some(name) = first.file_name().and_then(|n| n.to_str()) {
                if !name.is_empty() {
                    return name.to_string();
                }
            }
        }
    }
    if let Ok(u) = std::env::var("USER") {
        let t = u.trim();
        if !t.is_empty() {
            return t.to_string();
        }
    }
    if let Ok(u) = std::env::var("LOGNAME") {
        let t = u.trim();
        if !t.is_empty() {
            return t.to_string();
        }
    }
    if let Some(home) = dirs::home_dir() {
        if let Some(name) = home.file_name().and_then(|n| n.to_str()) {
            if !name.is_empty() {
                return name.to_string();
            }
        }
    }
    "Developer".to_string()
}

fn get_key_filepath() -> Result<PathBuf, String> {
    let home = dirs::home_dir().ok_or_else(|| "cannot resolve home directory".to_string())?;
    let dir = home.join(".agentcontrol");
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

/// Persist signed Device JWT token returned by Control Hub to ~/.agentcontrol/device_token and ProgramData
pub fn save_device_token(token: &str) -> Result<(), String> {
    if let Some(home) = dirs::home_dir() {
        let dir = home.join(".agentcontrol");
        let _ = fs::create_dir_all(&dir);
        let _ = fs::write(dir.join("device_token"), token);
    }
    #[cfg(windows)]
    {
        let program_data = std::path::PathBuf::from(r"C:\ProgramData\AgentControl");
        let _ = fs::create_dir_all(&program_data);
        let _ = fs::write(program_data.join("device_token"), token);
    }
    Ok(())
}

/// Load saved Device JWT token from ~/.agentcontrol/device_token or ProgramData (with Windows Session 0 fallback)
pub fn load_device_token() -> Option<String> {
    #[cfg(windows)]
    {
        // 1. Check C:\ProgramData\AgentControl\device_token (machine-wide store)
        let prog_data_token = std::path::PathBuf::from(r"C:\ProgramData\AgentControl\device_token");
        if let Ok(content) = fs::read_to_string(&prog_data_token) {
            let trimmed = content.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }

    if let Some(home) = dirs::home_dir() {
        let token_path = home.join(".agentcontrol").join("device_token");
        if let Ok(content) = fs::read_to_string(&token_path) {
            let trimmed = content.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }

    #[cfg(windows)]
    {
        for profile in crate::service::windows_profiles::enumerate_user_profiles() {
            let token_path = profile.join(".agentcontrol").join("device_token");
            if let Ok(content) = fs::read_to_string(&token_path) {
                let trimmed = content.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }
    }

    None
}

/// Persist enrolled Control Hub API URL to ~/.agentcontrol/hub_url and ProgramData (Windows) or /etc (Unix)
pub fn save_hub_url(url: &str) -> Result<(), String> {
    let clean = url.trim_end_matches('/');
    if clean.is_empty() {
        return Ok(());
    }
    std::env::set_var("AGENTCONTROL_HUB_URL", clean);
    std::env::set_var("DASHBOARD_API_URL", clean);

    if let Some(home) = dirs::home_dir() {
        let dir = home.join(".agentcontrol");
        let _ = fs::create_dir_all(&dir);
        let _ = fs::write(dir.join("hub_url"), clean);
    }
    #[cfg(windows)]
    {
        let program_data = std::path::PathBuf::from(r"C:\ProgramData\AgentControl");
        let _ = fs::create_dir_all(&program_data);
        let _ = fs::write(program_data.join("hub_url"), clean);
        let _ = std::process::Command::new("setx")
            .args(&["AGENTCONTROL_HUB_URL", clean])
            .output();
        let _ = std::process::Command::new("setx")
            .args(&["DASHBOARD_API_URL", clean])
            .output();
    }
    #[cfg(not(windows))]
    {
        let etc_dir = std::path::PathBuf::from("/etc/agentcontrol");
        if etc_dir.exists() || fs::create_dir_all(&etc_dir).is_ok() {
            let _ = fs::write(etc_dir.join("hub_url"), clean);
        }
    }
    Ok(())
}

/// Load enrolled Control Hub URL from environment, ~/.agentcontrol/hub_url, or machine-wide store
pub fn load_hub_url() -> Option<String> {
    // 1. Explicit override if set and not a default placeholder
    if let Ok(v) = std::env::var("AGENTCONTROL_HUB_URL") {
        let trimmed = v.trim().trim_end_matches('/');
        if !trimmed.is_empty() 
            && trimmed != "https://console.vexasec.io" 
            && trimmed != "https://console-stage.vexasec.io" 
        {
            return Some(trimmed.to_string());
        }
    }
    if let Ok(v) = std::env::var("DASHBOARD_API_URL") {
        let trimmed = v.trim().trim_end_matches('/');
        if !trimmed.is_empty() 
            && trimmed != "https://console.vexasec.io" 
            && trimmed != "https://console-stage.vexasec.io" 
        {
            return Some(trimmed.to_string());
        }
    }

    // 2. Authoritative enrolled hub URL saved on disk
    #[cfg(windows)]
    {
        let prog_data = std::path::PathBuf::from(r"C:\ProgramData\AgentControl\hub_url");
        if let Ok(content) = fs::read_to_string(&prog_data) {
            let trimmed = content.trim().trim_end_matches('/').to_string();
            if !trimmed.is_empty() {
                return Some(trimmed);
            }
        }
    }

    if let Some(home) = dirs::home_dir() {
        let hub_path = home.join(".agentcontrol").join("hub_url");
        if let Ok(content) = fs::read_to_string(&hub_path) {
            let trimmed = content.trim().trim_end_matches('/').to_string();
            if !trimmed.is_empty() {
                return Some(trimmed);
            }
        }
    }

    #[cfg(not(windows))]
    {
        let etc_path = std::path::PathBuf::from("/etc/agentcontrol/hub_url");
        if let Ok(content) = fs::read_to_string(&etc_path) {
            let trimmed = content.trim().trim_end_matches('/').to_string();
            if !trimmed.is_empty() {
                return Some(trimmed);
            }
        }
    }

    #[cfg(windows)]
    {
        for profile in crate::service::windows_profiles::enumerate_user_profiles() {
            let hub_path = profile.join(".agentcontrol").join("hub_url");
            if let Ok(content) = fs::read_to_string(&hub_path) {
                let trimmed = content.trim().trim_end_matches('/').to_string();
                if !trimmed.is_empty() {
                    return Some(trimmed);
                }
            }
        }
    }

    // 3. Fall back to any env var if set
    std::env::var("AGENTCONTROL_HUB_URL")
        .or_else(|_| std::env::var("DASHBOARD_API_URL"))
        .ok()
        .map(|v| v.trim().trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
}

/// Check if the local machine has valid enrollment credentials (token or mTLS certs)
pub fn is_device_enrolled() -> bool {
    if load_device_token().is_some() {
        return true;
    }
    if let Some(home) = dirs::home_dir() {
        if home.join(".agentcontrol").join("device_cert.pem").exists() {
            return true;
        }
    }
    #[cfg(windows)]
    {
        if std::path::Path::new(r"C:\ProgramData\AgentControl\device_cert.pem").exists() {
            return true;
        }
    }
    false
}

use colored::*;

use crate::identity::keys::IdentityKeyManager;
use crate::identity::transcript::TranscriptBuilder;

#[derive(serde::Serialize)]
struct StartEnrollmentPayload<'a> {
    schema_version: &'a str,
    enrollment_token: &'a str,
    stable_device_id: &'a str,
    display_name: &'a str,
    owner_subject: &'a str,
    identity_public_key: IdentityPubKeyPayload<'a>,
    mtls_csr: MtlsCsrPayload<'a>,
    platform: PlatformPayload<'a>,
    release: ReleasePayload<'a>,
}

#[derive(serde::Serialize)]
struct IdentityPubKeyPayload<'a> {
    algorithm: &'a str,
    value: String,
}

#[derive(serde::Serialize)]
struct MtlsCsrPayload<'a> {
    algorithm: &'a str,
    pem: &'a str,
}

#[derive(serde::Serialize)]
struct PlatformPayload<'a> {
    os_family: &'a str,
    os_version_summary: &'a str,
    architecture: &'a str,
}

#[derive(serde::Serialize)]
struct ReleasePayload<'a> {
    version: &'a str,
    manifest_id: &'a str,
}

#[derive(serde::Deserialize)]
struct StartEnrollmentApiResp {
    transaction_id: String,
    #[serde(default)]
    tenant_id: String,
    challenge: ChallengeBlock,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct ChallengeBlock {
    id: String,
    nonce: String,
    #[serde(default)]
    context: String,
}

#[derive(serde::Serialize)]
struct CompleteEnrollmentPayload<'a> {
    schema_version: &'a str,
    transaction_id: &'a str,
    challenge_id: &'a str,
    enrollment_signature: SignaturePayload<'a>,
    signed_payload_sha256: &'a str,
}

#[derive(serde::Serialize)]
struct SignaturePayload<'a> {
    algorithm: &'a str,
    value: String,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct CompleteEnrollmentApiResp {
    device: DeviceBlock,
    mtls_certificate: CertBlock,
    #[serde(default)]
    device_api_base: String,
}

#[derive(serde::Deserialize)]
struct DeviceBlock {
    id: String,
    state: String,
}

#[derive(serde::Deserialize)]
struct CertBlock {
    serial: String,
    pem_chain: String,
}

/// Executes the `agentwall enroll` command with dual-key cryptographic challenge-response proof.
pub async fn run_enroll(token: &str, hub_url: &str) -> i32 {
    if token.is_empty() {
        eprintln!(
            "{} Enrollment token is required (--token or AGENTCONTROL_ENROLLMENT_TOKEN)",
            "✖".red()
        );
        return 1;
    }

    println!("{} Vexa Agent Control PKI Device Enrollment (v4.0 Protocol)", "●".green().bold());
    let masked_token = if token.len() > 8 {
        format!("{}...{}", &token[..4], &token[token.len() - 4..])
    } else {
        "***".to_string()
    };
    println!(
        "  Connecting to Control Hub: {} (token: {})",
        hub_url.cyan(),
        masked_token.dimmed()
    );

    let home_dir = match dirs::home_dir() {
        Some(h) => h.join(".agentcontrol"),
        None => PathBuf::from(".agentcontrol"),
    };
    let key_mgr = IdentityKeyManager::new(&home_dir);

    let device_identity = match DeviceIdentity::load_or_create() {
        Ok(id) => id,
        Err(e) => {
            eprintln!("{} Failed to load or initialize device identity: {}", "✖".red(), e);
            return 1;
        }
    };
    let stable_device_id = device_identity.device_id.clone();

    println!("  Generating dual-key cryptographic credentials...");
    let bundle = match key_mgr.generate_bundle_with_key(&stable_device_id, device_identity.signing_key) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{} Failed to generate cryptographic key bundle: {}", "✖".red(), e);
            return 1;
        }
    };

    println!("  Device Identity: {}", device_identity.device_id.bold());
    println!("  Ed25519 Fingerprint: {}...", &bundle.ed25519_fingerprint[..16]);
    println!("  ECDSA P-256 CSR Hash: {}...", &bundle.csr_sha256[..16]);

    let hostname = get_hostname();
    let user_name = get_current_user();
    let stable_device_id = device_identity.device_id.clone();
    let ed25519_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &bundle.ed25519_public_bytes,
    );
    let os_family = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    let pkg_ver = env!("CARGO_PKG_VERSION");

    let start_payload = StartEnrollmentPayload {
        schema_version: "2.0",
        enrollment_token: token,
        stable_device_id: &stable_device_id,
        display_name: &hostname,
        owner_subject: &user_name,
        identity_public_key: IdentityPubKeyPayload {
            algorithm: "Ed25519",
            value: ed25519_b64,
        },
        mtls_csr: MtlsCsrPayload {
            algorithm: "ECDSA-P256",
            pem: &bundle.csr_pem,
        },
        platform: PlatformPayload {
            os_family,
            os_version_summary: os_family,
            architecture: arch,
        },
        release: ReleasePayload {
            version: pkg_ver,
            manifest_id: "manifest-v4",
        },
    };

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{} Failed to build HTTP client: {}", "✖".red(), e);
            return 1;
        }
    };

    let clean_hub = hub_url.trim_end_matches('/');
    let start_endpoint = format!("{}/api/v2/enrollment/start", clean_hub);
    let start_req_id = uuid::Uuid::new_v4().to_string();
    println!("  Step 1/2: Submitting enrollment start challenge request...");
    
    let start_res = match client
        .post(&start_endpoint)
        .header("X-Request-ID", &start_req_id)
        .json(&start_payload)
        .send()
        .await
    {
        Ok(res) => res,
        Err(e) => {
            let mut err_msg = format!("{}", e);
            let mut source = std::error::Error::source(&e);
            while let Some(s) = source {
                err_msg.push_str(&format!(" -> {}", s));
                source = std::error::Error::source(s);
            }
            eprintln!("{} Cannot connect to Hub at {} [Request-ID: {}]: {}", "✖".red(), start_endpoint, start_req_id, err_msg);
            return 1;
        }
    };

    if !start_res.status().is_success() {
        let status = start_res.status();
        let resp_req_id = start_res
            .headers()
            .get("X-Request-ID")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or(start_req_id);
        let body = start_res.text().await.unwrap_or_default();
        eprintln!("{} Enrollment start failed (HTTP {}) [Request-ID: {}]: {}", "✖".red(), status, resp_req_id, body);
        return 1;
    }

    let start_data = match start_res.json::<StartEnrollmentApiResp>().await {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{} Invalid enrollment start response: {}", "✖".red(), e);
            return 1;
        }
    };

    println!("  Step 2/2: Signing canonical transcript proof with Ed25519 private key...");
    let tenant_id = if start_data.tenant_id.is_empty() {
        "default-tenant"
    } else {
        &start_data.tenant_id
    };

    let transcript = TranscriptBuilder::new(
        &start_data.transaction_id,
        &start_data.challenge.id,
        tenant_id,
        &bundle.ed25519_fingerprint,
        &bundle.csr_sha256,
    );

    let (sig_b64url, hash_hex) = transcript.sign(&bundle.ed25519_signing_key);

    let complete_payload = CompleteEnrollmentPayload {
        schema_version: "2.0",
        transaction_id: &start_data.transaction_id,
        challenge_id: &start_data.challenge.id,
        enrollment_signature: SignaturePayload {
            algorithm: "Ed25519",
            value: sig_b64url,
        },
        signed_payload_sha256: &hash_hex,
    };

    let complete_endpoint = format!("{}/api/v2/enrollment/complete", clean_hub);
    let complete_req_id = uuid::Uuid::new_v4().to_string();
    let complete_res = match client
        .post(&complete_endpoint)
        .header("X-Request-ID", &complete_req_id)
        .json(&complete_payload)
        .send()
        .await
    {
        Ok(res) => res,
        Err(e) => {
            let mut err_msg = format!("{}", e);
            let mut source = std::error::Error::source(&e);
            while let Some(s) = source {
                err_msg.push_str(&format!(" -> {}", s));
                source = std::error::Error::source(s);
            }
            eprintln!("{} Cannot connect to Hub at {} [Request-ID: {}]: {}", "✖".red(), complete_endpoint, complete_req_id, err_msg);
            return 1;
        }
    };

    if !complete_res.status().is_success() {
        let status = complete_res.status();
        let resp_req_id = complete_res
            .headers()
            .get("X-Request-ID")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or(complete_req_id);
        let body = complete_res.text().await.unwrap_or_default();
        eprintln!("{} Enrollment completion failed (HTTP {}) [Request-ID: {}]: {}", "✖".red(), status, resp_req_id, body);
        return 1;
    }

    let complete_data = match complete_res.json::<CompleteEnrollmentApiResp>().await {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{} Invalid enrollment complete response: {}", "✖".red(), e);
            return 1;
        }
    };

    // Save cryptographic keys & certificate
    if let Err(e) = key_mgr.persist_bundle_securely(&bundle) {
        eprintln!("{} Failed to save private keys securely: {}", "✖".red(), e);
        return 1;
    }

    let cert_path = home_dir.join("device_cert.pem");
    if let Err(e) = fs::write(&cert_path, &complete_data.mtls_certificate.pem_chain) {
        eprintln!("{} Failed to write certificate chain: {}", "✖".red(), e);
    }
    // Always write the PEM key beside the cert in the user home dir
    let home_key_path = home_dir.join("device_key.pem");
    if let Err(e) = fs::write(&home_key_path, bundle.p256_key_pem.as_bytes()) {
        eprintln!("{} Failed to write device key PEM: {}", "✖".red(), e);
    }

    #[cfg(windows)]
    {
        let prog_data = std::path::PathBuf::from(r"C:\ProgramData\AgentControl");
        let _ = fs::create_dir_all(&prog_data);
        let _ = fs::write(prog_data.join("device_cert.pem"), &complete_data.mtls_certificate.pem_chain);
        let _ = fs::write(prog_data.join("device_key.pem"), bundle.p256_key_pem.as_bytes());
    }

    let _ = save_device_token(&complete_data.device.id);
    let _ = save_hub_url(clean_hub);

    println!();
    println!("{} Device enrolled successfully!", "✔".green().bold());
    println!("  Device ID:          {}", complete_data.device.id.cyan());
    println!("  Control Hub URL:    {}", clean_hub.cyan());
    println!("  Initial State:      {}", complete_data.device.state.yellow());
    println!("  Certificate Serial: {}", complete_data.mtls_certificate.serial.bold());
    println!("  Cert Location:      {}", cert_path.display());
    println!();
    println!("Next: Start AgentWall Sentry daemon to begin active policy enforcement & heartbeats.");
    0
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

    #[test]
    fn test_hub_url_persistence_roundtrip() {
        let orig = load_hub_url();
        let test_url = "https://hub.example.corp:8400/";
        let res = save_hub_url(test_url);
        assert!(res.is_ok());

        let loaded = load_hub_url();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap(), "https://hub.example.corp:8400");

        if let Some(orig_url) = orig {
            let _ = save_hub_url(&orig_url);
        }
    }

    #[test]
    fn test_is_device_enrolled_check() {
        // Enrolled check should run safely without panic
        let _ = is_device_enrolled();
    }
}
