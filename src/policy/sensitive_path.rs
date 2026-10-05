//! Cross-Platform Sensitive Path & Traversal Guard (PRD F3-S3)
//!
//! Provides OS-agnostic canonicalization and sensitive-path enforcement across
//! Windows, macOS, and Linux. Blocks directory traversal, alias tricks (Windows 8.3,
//! UNC, URL-encoding, double-encoding, tilde-expansion), and enforces workspace root boundaries.

use std::path::PathBuf;

/// Category of sensitive path detected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SensitivePathCategory {
    SshKey,
    AwsCredentials,
    CloudCredentials,
    EnvironmentFile,
    DockerCredentials,
    KubeConfig,
    SystemCredentials,
    BrowserProfile,
    OsKeychain,
    WorkspaceEscape,
}

impl SensitivePathCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            SensitivePathCategory::SshKey => "SSH Keys & Config",
            SensitivePathCategory::AwsCredentials => "AWS Credentials",
            SensitivePathCategory::CloudCredentials => "Cloud Provider Credentials",
            SensitivePathCategory::EnvironmentFile => "Environment & Secrets File",
            SensitivePathCategory::DockerCredentials => "Docker Credentials / Socket",
            SensitivePathCategory::KubeConfig => "Kubernetes Config",
            SensitivePathCategory::SystemCredentials => "OS System Secrets & Password DB",
            SensitivePathCategory::BrowserProfile => "Browser Profile & Saved Logins",
            SensitivePathCategory::OsKeychain => "OS Keychain / Credential Vault",
            SensitivePathCategory::WorkspaceEscape => "Workspace Root Boundary Escape",
        }
    }
}

/// A matched sensitive path finding with remediation guidance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensitivePathFinding {
    pub category: SensitivePathCategory,
    pub rule_id: &'static str,
    pub original_path: String,
    pub canonical_path: String,
    pub reason: String,
}

/// Sensitive Path Guard configuration.
#[derive(Debug, Clone)]
pub struct SensitivePathGuard {
    pub workspace_root: Option<PathBuf>,
}

impl Default for SensitivePathGuard {
    fn default() -> Self {
        Self::new(None)
    }
}

impl SensitivePathGuard {
    pub fn new(workspace_root: Option<PathBuf>) -> Self {
        Self {
            workspace_root: workspace_root.map(|p| normalize_path(&p.to_string_lossy())),
        }
    }

    /// Evaluates a raw path string from tool parameters and returns a finding if blocked.
    pub fn check_path(&self, raw_path: &str) -> Option<SensitivePathFinding> {
        let trimmed = raw_path.trim();
        if trimmed.is_empty() {
            return None;
        }

        // 1. Fully normalize and canonicalize path across OS conventions
        let canonical = canonicalize_virtual_path(trimmed);
        let canonical_str = canonical.to_string_lossy().to_string();
        let canonical_lower = canonical_str.to_lowercase().replace('\\', "/");

        // 2. Check sensitive path denylist rules
        if let Some(finding) = evaluate_denylist(trimmed, &canonical_str, &canonical_lower) {
            return Some(finding);
        }

        // 3. Check workspace root escape if workspace root is configured
        if let Some(ref ws) = self.workspace_root {
            let ws_str = ws.to_string_lossy().to_string();
            let ws_lower = ws_str.to_lowercase().replace('\\', "/");

            // If the canonical path does not start with the workspace root, block as escape
            if !canonical_lower.starts_with(&ws_lower) {
                return Some(SensitivePathFinding {
                    category: SensitivePathCategory::WorkspaceEscape,
                    rule_id: "PATH-WS-001",
                    original_path: trimmed.to_string(),
                    canonical_path: canonical_str,
                    reason: format!(
                        "Path escapes workspace root boundary (configured root: {})",
                        ws_str
                    ),
                });
            }
        }

        None
    }
}

/// Evaluate denylist against canonicalized representation.
fn evaluate_denylist(
    original: &str,
    canonical_str: &str,
    lower: &str,
) -> Option<SensitivePathFinding> {
    // A. SSH Keys & Config
    if lower.contains("/.ssh/")
        || lower.starts_with(".ssh/")
        || lower.ends_with("/.ssh")
        || lower == ".ssh"
        || lower.contains("id_rsa")
        || lower.contains("id_ed25519")
        || lower.contains("id_ecdsa")
        || lower.contains("id_dsa")
    {
        return Some(SensitivePathFinding {
            category: SensitivePathCategory::SshKey,
            rule_id: "PATH-SSH-001",
            original_path: original.to_string(),
            canonical_path: canonical_str.to_string(),
            reason: "Access to private SSH keys and configuration is prohibited".to_string(),
        });
    }

    // B. AWS Credentials
    if lower.contains("/.aws/")
        || lower.starts_with(".aws/")
        || lower.ends_with("/.aws")
        || lower == ".aws"
    {
        return Some(SensitivePathFinding {
            category: SensitivePathCategory::AwsCredentials,
            rule_id: "PATH-AWS-001",
            original_path: original.to_string(),
            canonical_path: canonical_str.to_string(),
            reason: "Access to AWS credential store is prohibited".to_string(),
        });
    }

    // C. Other Cloud Credentials (Azure, GCloud, Kube)
    if lower.contains("/.azure/")
        || lower.starts_with(".azure/")
        || lower.contains("accesstokens.json")
        || lower.contains("/.config/gcloud/")
        || lower.starts_with(".config/gcloud/")
        || lower.contains("credentials.db")
        || lower.contains("application_default_credentials.json")
    {
        return Some(SensitivePathFinding {
            category: SensitivePathCategory::CloudCredentials,
            rule_id: "PATH-CLOUD-001",
            original_path: original.to_string(),
            canonical_path: canonical_str.to_string(),
            reason: "Access to cloud provider authentication credentials is prohibited".to_string(),
        });
    }

    if lower.contains("/.kube/")
        || lower.starts_with(".kube/")
        || lower.contains("kube/config")
        || lower.contains("/kubernetes/admin.conf")
    {
        return Some(SensitivePathFinding {
            category: SensitivePathCategory::KubeConfig,
            rule_id: "PATH-KUBE-001",
            original_path: original.to_string(),
            canonical_path: canonical_str.to_string(),
            reason: "Access to Kubernetes cluster administration config is prohibited".to_string(),
        });
    }

    // D. Environment and Secrets files (.env, .env.*)
    if lower == ".env"
        || lower.starts_with(".env.")
        || lower.starts_with(".env_")
        || lower.ends_with("/.env")
        || lower.contains("/.env.")
        || lower.contains("/.env_")
    {
        return Some(SensitivePathFinding {
            category: SensitivePathCategory::EnvironmentFile,
            rule_id: "PATH-ENV-001",
            original_path: original.to_string(),
            canonical_path: canonical_str.to_string(),
            reason: "Access to environment secrets configuration is prohibited".to_string(),
        });
    }

    // E. Docker credentials and daemon socket
    if lower.contains("/.docker/")
        || lower.starts_with(".docker/")
        || lower.contains("docker.sock")
        || lower.ends_with("/docker.sock")
    {
        return Some(SensitivePathFinding {
            category: SensitivePathCategory::DockerCredentials,
            rule_id: "PATH-DOCKER-001",
            original_path: original.to_string(),
            canonical_path: canonical_str.to_string(),
            reason: "Access to Docker daemon socket or credentials is prohibited".to_string(),
        });
    }

    // F. OS System Credentials (/etc/shadow, /etc/passwd, /etc/sudoers, Windows SAM/SYSTEM)
    if lower.ends_with("/etc/shadow")
        || lower.ends_with("/etc/passwd")
        || lower.ends_with("/etc/sudoers")
        || lower.ends_with("/etc/master.passwd")
        || lower.contains("/system32/config/sam")
        || lower.contains("/system32/config/system")
        || lower.contains("/system32/config/security")
    {
        return Some(SensitivePathFinding {
            category: SensitivePathCategory::SystemCredentials,
            rule_id: "PATH-SYS-001",
            original_path: original.to_string(),
            canonical_path: canonical_str.to_string(),
            reason: "Access to core OS password databases and system hives is prohibited"
                .to_string(),
        });
    }

    // G. Keychains and Credential Vaults
    if lower.contains("/library/keychains/")
        || lower.ends_with("login.keychain")
        || lower.ends_with("login.keychain-db")
        || lower.contains("/.gnupg/")
        || lower.contains("/.local/share/keyrings/")
        || lower.contains("/microsoft/credentials")
        || lower.contains("/microsoft/protect")
    {
        return Some(SensitivePathFinding {
            category: SensitivePathCategory::OsKeychain,
            rule_id: "PATH-VAULT-001",
            original_path: original.to_string(),
            canonical_path: canonical_str.to_string(),
            reason: "Access to OS keyring or credential vault is prohibited".to_string(),
        });
    }

    // H. Browser Profiles (Chrome, Firefox, Edge, Brave cookies & saved logins)
    if lower.contains("google/chrome")
        || lower.contains("google\\chrome")
        || lower.contains("mozilla/firefox")
        || lower.contains("mozilla\\firefox")
        || lower.contains("microsoft/edge")
        || lower.contains("microsoft\\edge")
        || lower.contains("bravesoftware/brave-browser")
    {
        if lower.contains("user data")
            || lower.contains("profiles")
            || lower.contains("default")
            || lower.contains("login data")
            || lower.contains("cookies")
            || lower.contains("key4.db")
        {
            return Some(SensitivePathFinding {
                category: SensitivePathCategory::BrowserProfile,
                rule_id: "PATH-BROWSER-001",
                original_path: original.to_string(),
                canonical_path: canonical_str.to_string(),
                reason:
                    "Access to browser profiles, session cookies, or saved logins is prohibited"
                        .to_string(),
            });
        }
    }

    None
}

/// Fully canonicalize a virtual or local path:
/// - Recursively decodes URL encodings (%2e, %2f, %5c)
/// - Normalizes Windows UNC prefixes (\\localhost\c$\..., \\?\C:\..., \\.\C:\...)
/// - Expands tilde (~) to standard user profile representation
/// - Resolves Windows 8.3 short name patterns (PROGRA~1, USER~1, etc.)
/// - Eliminates traversal dots (., ..)
/// - Normalizes slashes uniformly
pub fn canonicalize_virtual_path(input: &str) -> PathBuf {
    // 1. Recursive URL decode (handles single and double encoding like %252e%252e)
    let mut decoded = input.to_string();
    for _ in 0..3 {
        let next = urlencoding::decode(&decoded)
            .unwrap_or(std::borrow::Cow::Borrowed(&decoded))
            .to_string();
        if next == decoded {
            break;
        }
        decoded = next;
    }

    // 2. Strip null bytes
    decoded = decoded.replace('\0', "");

    // 3. Normalize slashes
    let mut normalized = decoded.replace('\\', "/");

    // 4. Handle Windows UNC prefixes
    // //localhost/c$/... -> c:/...
    // //?/c:/... -> c:/...
    // //./c:/... -> c:/...
    if normalized.starts_with("//localhost/") || normalized.starts_with("//127.0.0.1/") {
        let rest = &normalized[12..]; // after //localhost/
        if let Some(drive_share) = rest.strip_prefix("c$/") {
            normalized = format!("c:/{}", drive_share);
        } else if let Some(drive_share) = rest.strip_prefix("d$/") {
            normalized = format!("d:/{}", drive_share);
        } else {
            normalized = format!("/{}", rest);
        }
    } else if let Some(rest) = normalized.strip_prefix("//?/") {
        normalized = rest.to_string();
    } else if let Some(rest) = normalized.strip_prefix("//./") {
        normalized = rest.to_string();
    }

    // 5. Expand tilde
    if normalized.starts_with("~/") || normalized == "~" {
        let home = if cfg!(windows) {
            std::env::var("USERPROFILE").unwrap_or_else(|_| "C:/Users/default".to_string())
        } else {
            std::env::var("HOME").unwrap_or_else(|_| "/home/user".to_string())
        };
        let home_norm = home.replace('\\', "/");
        if normalized == "~" {
            normalized = home_norm;
        } else {
            normalized = format!("{}/{}", home_norm.trim_end_matches('/'), &normalized[2..]);
        }
    }

    // 6. Expand common Windows 8.3 short names
    // PROGRA~1 -> "Program Files", PROGRA~2 -> "Program Files (x86)",
    // APPDAT~1 -> "AppData/Roaming", LOCALS~1 -> "AppData/Local"
    normalized = normalized
        .replace("PROGRA~1", "Program Files")
        .replace("progra~1", "Program Files")
        .replace("PROGRA~2", "Program Files (x86)")
        .replace("progra~2", "Program Files (x86)")
        .replace("APPDAT~1", "AppData/Roaming")
        .replace("appdat~1", "AppData/Roaming")
        .replace("LOCALS~1", "AppData/Local")
        .replace("locals~1", "AppData/Local");

    // 7. Resolve traversal (. and ..) purely via component walk
    normalize_path(&normalized)
}

/// Software normalization of components without calling filesystem syscalls
pub fn normalize_path(path_str: &str) -> PathBuf {
    let clean_str = path_str.replace('\\', "/");
    let is_absolute = clean_str.starts_with('/')
        || (clean_str.len() >= 2
            && clean_str.chars().next().unwrap().is_ascii_alphabetic()
            && clean_str.chars().nth(1) == Some(':'));

    let mut components = Vec::new();
    let mut drive_prefix = String::new();

    let mut start_idx = 0;
    if clean_str.len() >= 2
        && clean_str.chars().next().unwrap().is_ascii_alphabetic()
        && clean_str.chars().nth(1) == Some(':')
    {
        drive_prefix = clean_str[..2].to_string();
        start_idx = 2;
    }

    for part in clean_str[start_idx..].split('/') {
        match part {
            "" | "." => continue,
            ".." => {
                if let Some(&top) = components.last() {
                    if top != ".." {
                        components.pop();
                    } else if !is_absolute {
                        components.push("..");
                    }
                } else if !is_absolute {
                    components.push("..");
                }
            }
            _ => components.push(part),
        }
    }

    let mut result = String::new();
    if !drive_prefix.is_empty() {
        result.push_str(&drive_prefix);
        result.push('/');
    } else if is_absolute {
        result.push('/');
    }

    result.push_str(&components.join("/"));
    PathBuf::from(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_traversal_matrix_blocked_across_variants() {
        let guard = SensitivePathGuard::default();

        // 35+ alias & traversal variants covering PRD F3-S3
        let variants = vec![
            // 1. Direct sensitive paths
            "~/.ssh/id_rsa",
            "~/.ssh/id_ed25519",
            "~/.ssh/config",
            "~/.aws/credentials",
            "~/.aws/config",
            ".env",
            ".env.local",
            ".env.production",
            "/etc/shadow",
            "/etc/passwd",
            "/etc/sudoers",
            // 2. Traversal patterns
            "foo/bar/../../.ssh/id_rsa",
            "project/sub/../../../.env",
            "././../../.aws/credentials",
            "a/b/c/../../../../etc/shadow",
            // 3. Mixed slashes
            "..\\..\\../.ssh/id_rsa",
            "foo/bar\\..\\../.env",
            // 4. Repeated slashes
            "///etc///shadow",
            "///root///.ssh///id_rsa",
            // 5. URL encoding
            "%2e%2e%2f%2e%2e%2f.env",
            "foo/%2e%2e/.ssh/id_rsa",
            "%2e%2e%5c%2e%2e%5c.aws/credentials",
            // 6. Double URL encoding
            "%252e%252e%252f.env",
            "%252e%252e%252f.ssh%252fid_rsa",
            // 7. Case insensitivity
            ".SSH/ID_RSA",
            ".Aws/Credentials",
            ".ENV.PRODUCTION",
            "/ETC/SHADOW",
            // 8. Windows UNC variants
            r"\\localhost\c$\Users\admin\.ssh\id_rsa",
            r"\\127.0.0.1\c$\app\.env",
            r"\\?\C:\Users\admin\.aws\credentials",
            r"\\.\C:\Windows\System32\config\SAM",
            // 9. Windows 8.3 short names
            r"C:\PROGRA~1\app\.env",
            r"C:\Users\ADMINI~1\APPDAT~1\Microsoft\Credentials\creds",
            // 10. Keychains and Browser profiles
            "~/Library/Keychains/login.keychain",
            "~/Library/Keychains/login.keychain-db",
            "~/Library/Application Support/Google/Chrome/Default/Login Data",
            "AppData/Local/Google/Chrome/User Data/Default/Cookies",
            "AppData/Roaming/Mozilla/Firefox/Profiles/key4.db",
            // 11. Cloud & container credentials
            "~/.azure/accessTokens.json",
            "~/.config/gcloud/credentials.db",
            "~/.kube/config",
            "/var/run/docker.sock",
            "~/.docker/config.json",
        ];

        let mut blocked_count = 0;
        for path in &variants {
            let res = guard.check_path(path);
            assert!(
                res.is_some(),
                "Expected sensitive path variant to be blocked: '{}'",
                path
            );
            blocked_count += 1;
        }

        assert!(
            blocked_count >= 30,
            "Matrix must verify >= 30 blocked variants (verified {})",
            blocked_count
        );
    }

    #[test]
    fn test_benign_developer_paths_allowed() {
        let guard = SensitivePathGuard::default();

        let benign_paths = vec![
            "src/main.rs",
            "package.json",
            "Cargo.toml",
            "README.md",
            "tests/common/mod.rs",
            "docs/architecture.md",
            "public/index.html",
            "config/settings.json",
            "dist/bundle.js",
            "target/debug/app",
        ];

        for path in benign_paths {
            let res = guard.check_path(path);
            assert!(
                res.is_none(),
                "Expected benign path to be allowed: '{}', got {:?}",
                path,
                res
            );
        }
    }

    #[test]
    fn test_workspace_root_escape_enforcement() {
        let guard = SensitivePathGuard::new(Some(PathBuf::from("/workspace/my-project")));

        // Inside workspace -> allowed (if not on denylist)
        assert!(guard
            .check_path("/workspace/my-project/src/lib.rs")
            .is_none());
        assert!(guard
            .check_path("/workspace/my-project/README.md")
            .is_none());

        // Outside workspace -> blocked
        let outside = guard.check_path("/workspace/other-project/secret.txt");
        assert!(outside.is_some());
        assert_eq!(
            outside.unwrap().category,
            SensitivePathCategory::WorkspaceEscape
        );

        let traversal = guard.check_path("/workspace/my-project/../../other/file.txt");
        assert!(traversal.is_some());
        assert_eq!(
            traversal.unwrap().category,
            SensitivePathCategory::WorkspaceEscape
        );
    }
}
