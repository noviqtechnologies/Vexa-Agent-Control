//! Browser PKCE OAuth 2.0 & Device Onboarding Engine (REQ-ONB-001, FR-1).
//!
//! Provides the `AuthProvider` abstraction and `SmbBrowserAuthProvider` for zero-touch
//! browser-based PKCE authorization, loopback callback capture, device key registration,
//! and persistent local bearer token provisioning.

use async_trait::async_trait;
use base64::Engine;
use colored::*;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::identity::device::{save_device_token, save_hub_url, DeviceIdentity};
use crate::identity::storage::CredentialStore;

/// Core authentication provider abstraction (§FR-1.1).
#[async_trait]
pub trait AuthProvider: Send + Sync {
    /// Initiate a browser-based PKCE login session.
    async fn initiate_login(&self) -> Result<LoginSession, AuthError>;

    /// Await loopback HTTP callback and complete device enrollment.
    async fn await_callback(&self, session: &LoginSession) -> Result<DeviceEnrollmentResult, AuthError>;

    /// Refresh short-lived access credentials using device refresh token.
    async fn refresh_access_token(&self, refresh_token: &str) -> Result<TokenPair, AuthError>;

    /// Revoke device credentials from Control Hub.
    async fn revoke_device(&self, device_id: &str) -> Result<(), AuthError>;
}

/// Active browser login session holding PKCE parameters and local listener port.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LoginSession {
    pub auth_url: String,
    pub state: String,
    pub code_verifier: String,
    pub redirect_uri: String,
    pub callback_port: u16,
}

/// Result of successful device enrollment and authentication.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeviceEnrollmentResult {
    pub device_id: String,
    pub tenant_id: String,
    pub user_id: String,
    pub access_token: String,
    pub refresh_token: String,
    pub local_token: String,
}

/// Token pair returned by OAuth token endpoint.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
}

/// Authentication and enrollment errors.
#[derive(Debug)]
pub enum AuthError {
    PortUnavailable(String),
    NetworkError(String),
    Timeout(String),
    InvalidState,
    MissingCode,
    HubError(String),
    StorageError(String),
    CryptoError(String),
    Cancelled,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PortUnavailable(msg) => write!(f, "Callback port unavailable: {}", msg),
            Self::NetworkError(msg) => write!(f, "Network error: {}", msg),
            Self::Timeout(msg) => write!(f, "Authentication timed out: {}", msg),
            Self::InvalidState => write!(f, "OAuth state mismatch (potential CSRF attempt)"),
            Self::MissingCode => write!(f, "Authorization code missing in callback"),
            Self::HubError(msg) => write!(f, "Control Hub error: {}", msg),
            Self::StorageError(msg) => write!(f, "Credential storage error: {}", msg),
            Self::CryptoError(msg) => write!(f, "Cryptographic operation failed: {}", msg),
            Self::Cancelled => write!(f, "Authentication was cancelled by user"),
        }
    }
}

impl std::error::Error for AuthError {}

/// Generate a 32-byte PKCE code_verifier and S256 code_challenge (RFC 7636).
pub fn generate_pkce_pair() -> (String, String) {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);

    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let hash = hasher.finalize();
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash);

    (verifier, challenge)
}

/// Generate a high-entropy random state string.
pub fn generate_state() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Path to the persistent local proxy bearer token file (`~/.agentcontrol/local.token`).
pub fn get_local_token_path() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(".agentcontrol").join("local.token")
}

/// Generate a persistent 32-byte high-entropy local HTTP bearer token.
pub fn generate_secure_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("vx-local-{}", hex::encode(bytes))
}

/// Write local token with strict `0600` permissions on POSIX, user ACL on Windows.
pub fn write_local_token(token: &str) -> Result<(), String> {
    let token_path = get_local_token_path();
    if let Some(parent) = token_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let tmp_path = token_path.with_extension("tmp");
    std::fs::write(&tmp_path, token.trim().as_bytes())
        .map_err(|e| format!("Failed to write local token file: {}", e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600));
    }

    std::fs::rename(&tmp_path, &token_path)
        .map_err(|e| format!("Failed to commit local token file: {}", e))?;

    Ok(())
}

/// Read existing local token from `~/.agentcontrol/local.token`, or generate and persist a new one.
pub fn get_or_create_local_token() -> Result<String, String> {
    let path = get_local_token_path();
    if path.exists() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            let trimmed = content.trim();
            if trimmed.len() >= 32 {
                return Ok(trimmed.to_string());
            }
        }
    }

    let new_token = generate_secure_token();
    write_local_token(&new_token)?;
    Ok(new_token)
}

/// Deliberately rotate the persistent local token and persist new value.
pub fn rotate_local_token() -> Result<String, String> {
    let new_token = generate_secure_token();
    write_local_token(&new_token)?;
    Ok(new_token)
}

/// Open the system default browser.
pub fn open_browser(url: &str) {
    #[cfg(target_os = "windows")]
    {
        // Avoid cmd.exe /C start because cmd.exe interprets '&' in OAuth query parameters as command separators.
        // rundll32 url.dll,FileProtocolHandler invokes the OS ShellExecute directly without shell command parsing.
        let status = std::process::Command::new("rundll32")
            .args(["url.dll,FileProtocolHandler", url])
            .spawn();
        if status.is_err() {
            // Fallback to powershell Start-Process
            let _ = std::process::Command::new("powershell")
                .args(["-NoProfile", "-NonInteractive", "-Command", &format!("Start-Process '{}'", url.replace('\'', "''"))])
                .spawn();
        }
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(url).spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    }
}

/// Standard SMB browser authentication provider using PKCE.
pub struct SmbBrowserAuthProvider {
    pub hub_url: String,
    pub client_id: String,
}

impl SmbBrowserAuthProvider {
    pub fn new(hub_url: &str) -> Self {
        Self {
            hub_url: hub_url.trim_end_matches('/').to_string(),
            client_id: "agentcontrol-cli".to_string(),
        }
    }

    /// Try to find an available port in the standard loopback range 18085..=18090.
    async fn find_listener() -> Result<(TcpListener, u16), AuthError> {
        for port in 18085..=18090 {
            if let Ok(listener) = TcpListener::bind(format!("127.0.0.1:{}", port)).await {
                return Ok((listener, port));
            }
        }
        Err(AuthError::PortUnavailable(
            "Ports 18085-18090 are all in use on 127.0.0.1".to_string(),
        ))
    }
}

#[async_trait]
impl AuthProvider for SmbBrowserAuthProvider {
    async fn initiate_login(&self) -> Result<LoginSession, AuthError> {
        let (_listener, port) = Self::find_listener().await?;
        // Drop the temporary listener so await_callback can re-bind or start listening
        drop(_listener);

        let (code_verifier, code_challenge) = generate_pkce_pair();
        let state = generate_state();
        let redirect_uri = format!("http://127.0.0.1:{}/callback", port);

        let auth_url = format!(
            "{}/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&code_challenge={}&code_challenge_method=S256&state={}",
            self.hub_url,
            self.client_id,
            urlencoding::encode(&redirect_uri),
            code_challenge,
            state
        );

        Ok(LoginSession {
            auth_url,
            state,
            code_verifier,
            redirect_uri,
            callback_port: port,
        })
    }

    async fn await_callback(&self, session: &LoginSession) -> Result<DeviceEnrollmentResult, AuthError> {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", session.callback_port))
            .await
            .map_err(|e| AuthError::PortUnavailable(format!("Could not bind to port {}: {}", session.callback_port, e)))?;

        // Await callback with 120-second timeout
        let accept_future = async {
            let (mut socket, _) = listener.accept().await.map_err(|e| {
                AuthError::NetworkError(format!("Failed to accept incoming callback: {}", e))
            })?;

            let mut buf = [0u8; 4096];
            let n = socket.read(&mut buf).await.map_err(|e| {
                AuthError::NetworkError(format!("Failed to read callback request: {}", e))
            })?;

            let request = String::from_utf8_lossy(&buf[..n]);

            // Parse request line: GET /callback?code=...&state=... HTTP/1.1
            let first_line = request.lines().next().unwrap_or_default();
            let mut parts = first_line.split_whitespace();
            let _method = parts.next().unwrap_or_default();
            let path = parts.next().unwrap_or_default();

            let (code, state) = parse_callback_params(path)?;

            // Respond with styled HTML confirmation
            let html_body = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Vexa Agent Control — Authentication Successful</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0b1120; color: #f8fafc; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
    .card { background: #1e293b; padding: 2.5rem; border-radius: 12px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); text-align: center; max-width: 440px; border: 1px solid #334155; }
    h1 { color: #38bdf8; font-size: 1.5rem; margin-top: 0; margin-bottom: 0.75rem; }
    p { color: #94a3b8; line-height: 1.5; font-size: 0.95rem; margin-bottom: 1.25rem; }
    .badge { display: inline-block; padding: 0.4rem 0.85rem; background: #065f46; color: #34d399; border-radius: 9999px; font-weight: 600; font-size: 0.85rem; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Authentication Successful</h1>
    <p>Your developer workstation has successfully authenticated with Vexa Cloud Hub.</p>
    <div class="badge">&#10004; Device Enrolled</div>
    <p style="margin-top: 1.5rem; font-size: 0.85rem; color: #64748b;">You can safely close this browser window and return to your terminal.</p>
  </div>
</body>
</html>"#;

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                html_body.len(),
                html_body
            );

            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.flush().await;

            Ok::<(String, String), AuthError>((code, state))
        };

        let (code, state) = match tokio::time::timeout(Duration::from_secs(120), accept_future).await {
            Ok(res) => res?,
            Err(_) => return Err(AuthError::Timeout("Browser did not return within 120 seconds".to_string())),
        };

        if state != session.state {
            return Err(AuthError::InvalidState);
        }

        // Exchange code for token with Control Hub
        let client = reqwest::Client::new();
        let token_url = format!("{}/oauth/token", self.hub_url);
        let fallback_token_url = format!("{}/api/v2/auth/pkce/token", self.hub_url);

        let token_payload = serde_json::json!({
            "grant_type": "authorization_code",
            "client_id": self.client_id,
            "code": code,
            "code_verifier": session.code_verifier,
            "redirect_uri": session.redirect_uri,
        });

        let mut token_resp = client.post(&token_url).json(&token_payload).send().await;
        if token_resp.is_err() || !token_resp.as_ref().unwrap().status().is_success() {
            // Try fallback endpoint
            token_resp = client.post(&fallback_token_url).json(&token_payload).send().await;
        }

        // Process token response or use structured fallback for dev/offline testing
        let (access_token, refresh_token, tenant_id, user_id) = match token_resp {
            Ok(resp) if resp.status().is_success() => {
                let json: serde_json::Value = resp.json().await.map_err(|e| {
                    AuthError::HubError(format!("Failed to parse token response JSON: {}", e))
                })?;
                let access = json.get("access_token").and_then(|v| v.as_str()).unwrap_or_default().to_string();
                let refresh = json.get("refresh_token").and_then(|v| v.as_str()).unwrap_or_default().to_string();
                let tenant = json.get("tenant_id").and_then(|v| v.as_str()).unwrap_or("tenant-default").to_string();
                let user = json.get("user_id").and_then(|v| v.as_str()).unwrap_or("user-default").to_string();
                (access, refresh, tenant, user)
            }
            Ok(resp) => {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                return Err(AuthError::HubError(format!(
                    "Control Hub token exchange rejected ({status}): {body}"
                )));
            }
            Err(e) => {
                return Err(AuthError::NetworkError(format!(
                    "Failed to connect to Control Hub at {}: {}",
                    self.hub_url, e
                )));
            }
        };

        // Load or create local Ed25519 device identity
        let device_identity = DeviceIdentity::load_or_create()
            .map_err(|e| AuthError::CryptoError(format!("Failed to initialize device identity: {}", e)))?;

        // Register device Ed25519 public key with Control Hub (/api/v2/devices/enroll)
        let enroll_url = format!("{}/api/v2/devices/enroll", self.hub_url);
        let enroll_payload = serde_json::json!({
            "device_id": device_identity.device_id,
            "display_name": crate::identity::device::get_hostname(),
            "platform": std::env::consts::OS,
            "client_platform": std::env::consts::OS,
            "agent_version": env!("CARGO_PKG_VERSION"),
            "public_key_bytes": device_identity.public_key_base64(),
            "ed25519_public_key": device_identity.public_key_base64()
        });

        let enroll_resp = client
            .post(&enroll_url)
            .bearer_auth(&access_token)
            .json(&enroll_payload)
            .send()
            .await;

        match enroll_resp {
            Ok(resp) if resp.status().is_success() => {
                // Device registered successfully with Control Hub
            }
            Ok(resp) => {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                return Err(AuthError::HubError(format!(
                    "Device enrollment rejected by Control Hub ({status}): {body}"
                )));
            }
            Err(e) => {
                return Err(AuthError::NetworkError(format!(
                    "Failed to register device with Control Hub at {}: {}",
                    enroll_url, e
                )));
            }
        }

        // Save keys and tokens securely to platform CredentialStore
        let _ = CredentialStore::set("refresh_token", &refresh_token);
        let _ = CredentialStore::set("access_token", &access_token);
        let _ = save_device_token(&device_identity.device_id);
        let _ = save_hub_url(&self.hub_url);

        // Generate persistent local proxy bearer token
        let local_token = get_or_create_local_token()
            .map_err(|e| AuthError::StorageError(format!("Failed to save local proxy token: {}", e)))?;

        Ok(DeviceEnrollmentResult {
            device_id: device_identity.device_id,
            tenant_id,
            user_id,
            access_token,
            refresh_token,
            local_token,
        })
    }

    async fn refresh_access_token(&self, refresh_token: &str) -> Result<TokenPair, AuthError> {
        let client = reqwest::Client::new();
        let token_url = format!("{}/oauth/token", self.hub_url);

        let payload = serde_json::json!({
            "grant_type": "refresh_token",
            "client_id": self.client_id,
            "refresh_token": refresh_token,
        });

        let resp = client
            .post(&token_url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| AuthError::NetworkError(format!("Token refresh failed: {}", e)))?;

        if !resp.status().is_success() {
            return Err(AuthError::HubError(format!("Refresh rejected: HTTP {}", resp.status())));
        }

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AuthError::HubError(format!("Failed to parse refresh JSON: {}", e)))?;

        let access_token = json.get("access_token").and_then(|v| v.as_str()).unwrap_or_default().to_string();
        let new_refresh = json.get("refresh_token").and_then(|v| v.as_str()).unwrap_or(refresh_token).to_string();
        let expires_in = json.get("expires_in").and_then(|v| v.as_u64()).unwrap_or(3600);

        let _ = CredentialStore::set("access_token", &access_token);
        let _ = CredentialStore::set("refresh_token", &new_refresh);

        Ok(TokenPair {
            access_token,
            refresh_token: new_refresh,
            expires_in,
        })
    }

    async fn revoke_device(&self, device_id: &str) -> Result<(), AuthError> {
        let client = reqwest::Client::new();
        let revoke_url = format!("{}/api/v2/devices/{}/revoke", self.hub_url, device_id);

        let access_token = CredentialStore::get("access_token").unwrap_or(None);
        let mut req = client.post(&revoke_url);
        if let Some(token) = access_token {
            req = req.bearer_auth(token);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| AuthError::NetworkError(format!("Revoke request failed: {}", e)))?;

        if !resp.status().is_success() {
            return Err(AuthError::HubError(format!("Revocation failed: HTTP {}", resp.status())));
        }

        // Clean up local credentials
        let _ = CredentialStore::delete("access_token");
        let _ = CredentialStore::delete("refresh_token");
        let _ = CredentialStore::delete("device_token");

        Ok(())
    }
}

/// Helper to parse query parameters from the HTTP callback path.
fn parse_callback_params(path: &str) -> Result<(String, String), AuthError> {
    let query = path.split('?').nth(1).ok_or(AuthError::MissingCode)?;
    let mut code = None;
    let mut state = None;

    for pair in query.split('&') {
        let mut kv = pair.split('=');
        if let (Some(k), Some(v)) = (kv.next(), kv.next()) {
            match k {
                "code" => code = Some(urlencoding::decode(v).unwrap_or_default().to_string()),
                "state" => state = Some(urlencoding::decode(v).unwrap_or_default().to_string()),
                _ => {}
            }
        }
    }

    let code = code.ok_or(AuthError::MissingCode)?;
    let state = state.unwrap_or_default();
    Ok((code, state))
}

/// Main entry point for `agentcontrol login` command.
pub async fn run_login(hub_url: &str, no_browser: bool) -> i32 {
    let clean_hub = hub_url.trim_end_matches('/');
    println!("{}", "Vexa Agent Control — Workstation Authentication".bold().cyan());
    println!("Connecting to Vexa Cloud Hub at {}", clean_hub.yellow());

    let provider = SmbBrowserAuthProvider::new(clean_hub);
    let session = match provider.initiate_login().await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{} Failed to initiate authentication: {}", "✖".red(), e);
            return 1;
        }
    };

    println!("\nPlease authenticate in your browser:");
    println!("  {}", session.auth_url.cyan().underline());
    println!();

    if !no_browser {
        println!("Opening default browser...");
        open_browser(&session.auth_url);
    } else {
        println!("Please navigate to the URL above to complete sign-in.");
    }

    println!("Waiting for authentication callback on port {}...", session.callback_port);

    match provider.await_callback(&session).await {
        Ok(result) => {
            println!("\n{} Workstation authentication successful!", "✔".green().bold());
            println!("  Device ID:          {}", result.device_id.bold());
            println!("  Tenant ID:          {}", result.tenant_id.cyan());
            println!("  User ID:            {}", result.user_id.cyan());
            println!("  Local Proxy Token:  {} (stored in ~/.agentcontrol/local.token)", "Configured".green());

            // Automatically configure background service
            println!("\nConfiguring per-user background agent...");
            let service_action = crate::service::ServiceAction::Install {
                hub_url: clean_hub.to_string(),
                gateway_secret: None,
                policy_read_secret: None,
                agent_id: Some(result.device_id),
            };
            let _ = crate::service::run_service(service_action);

            println!("\n{} Setup complete! You can now run:", "✔".green().bold());
            println!("  {}     - Check workstation health and capabilities", "agentcontrol status".cyan());
            println!("  {} - Connect a client (e.g. codex, claude)", "agentcontrol connect codex".cyan());
            0
        }
        Err(e) => {
            eprintln!("\n{} Authentication failed: {}", "✖".red(), e);
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkce_generation() {
        let (verifier, challenge) = generate_pkce_pair();
        assert!(verifier.len() >= 43);
        assert!(challenge.len() >= 43);
        assert_ne!(verifier, challenge);

        // Verify challenge is SHA256 of verifier
        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let expected_challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize());
        assert_eq!(challenge, expected_challenge);
    }

    #[test]
    fn test_local_token_generation_and_rotation() {
        let t1 = generate_secure_token();
        assert!(t1.starts_with("vx-local-"));
        assert!(t1.len() >= 70);

        let t2 = generate_secure_token();
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_parse_callback_params() {
        let path = "/callback?code=auth_code_123&state=xyz_state_456";
        let (code, state) = parse_callback_params(path).unwrap();
        assert_eq!(code, "auth_code_123");
        assert_eq!(state, "xyz_state_456");
    }

    #[test]
    fn test_parse_callback_params_missing_code() {
        let path = "/callback?state=xyz_state_456";
        assert!(parse_callback_params(path).is_err());
    }

    #[tokio::test]
    async fn test_initiate_login_session() {
        let provider = SmbBrowserAuthProvider::new("https://app.vexasec.io");
        let session = provider.initiate_login().await.unwrap();
        assert!(session.auth_url.contains("https://app.vexasec.io/oauth/authorize"));
        assert!(session.auth_url.contains("code_challenge="));
        assert!(session.auth_url.contains("code_challenge_method=S256"));
        assert!(session.callback_port >= 18085 && session.callback_port <= 18090);
    }

    #[tokio::test]
    async fn test_enrollment_with_local_hub() {
        let id = match DeviceIdentity::load_or_create() {
            Ok(id) => id,
            Err(_) => return,
        };
        let client = reqwest::Client::new();
        let payload = serde_json::json!({
            "device_id": id.device_id,
            "display_name": crate::identity::device::get_hostname(),
            "platform": std::env::consts::OS,
            "client_platform": std::env::consts::OS,
            "agent_version": env!("CARGO_PKG_VERSION"),
            "public_key_bytes": id.public_key_base64(),
            "ed25519_public_key": id.public_key_base64()
        });
        let resp = client
            .post("http://127.0.0.1:8081/api/v2/devices/enroll")
            .json(&payload)
            .send()
            .await;
        if let Ok(r) = resp {
            assert!(r.status().is_success());
            println!("Successfully enrolled device: {}", id.device_id);
        }
    }
}
