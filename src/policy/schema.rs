//! Policy YAML schema types — strict deserialization (FR-103)
//!
//! Implements the v1 policy schema exactly as specified in PRD §6.1.
//! Uses `#[serde(deny_unknown_fields)]` for strict parsing at all levels.
//!
//! ## FR-112: Group-Scoped Policy
//!
//! `GroupIdentityPolicy` enables binding policy rules to IdP group claims
//! instead of enumerating individual agent identities. Group membership is
//! read from the JWT token's group claim (FR-113). Resolution order (FR-114):
//! agent-level → group-level (deny beats allow) → org/default.

use serde::Deserialize;

/// The supported policy schema versions.
pub const SUPPORTED_VERSIONS: &[&str] = &["1", "2"];

/// Top-level policy document.
/// Unknown fields at any level cause a fatal startup error.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyFile {
    /// Required. Must be "1" or "2". Any other value = fatal error.
    pub version: String,

    /// Required. Must be "deny". "allow" = fatal error. Absent = fatal error.
    pub default_action: String,

    /// Identity binding configuration (v2 only).
    pub identity: Option<IdentityConfig>,

    /// OIDC authentication configuration (FR-201).
    pub auth: Option<AuthConfig>,

    /// Optional session configuration.
    pub session: Option<SessionConfig>,

    /// FR-303b: Response scanning configuration.
    pub response_scanning: Option<ResponseScanningConfig>,

    /// FR-306: Agent Firewall — cycle detection and loop prevention.
    pub firewall: Option<FirewallConfig>,

    /// FR-4: Self Healing configuration.
    pub self_healing: Option<SelfHealingConfig>,

    /// Tool allowlist. Empty = all denied.
    pub tools: Option<Vec<ToolRule>>,

    /// Agent identity configuration (FR-22).
    pub agents: Option<Vec<AgentIdentityPolicy>>,

    /// FR-112: Group-scoped policy bindings.
    /// Each entry binds a set of IdP group claim values to a policy block.
    /// Group policy is additive — does not replace per-agent bindings.
    pub groups: Option<Vec<GroupIdentityPolicy>>,

    /// FR-120: Spend caps configuration (Paid tier).
    #[serde(alias = "spend")]
    pub spend_caps: Option<SpendCapsConfig>,

    /// LLM API governance configuration (providers, models, DLP).
    pub llm: Option<LlmConfig>,
}

/// LLM API configuration block.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LlmConfig {
    pub providers: Option<Vec<LlmProviderRule>>,
    pub dlp: Option<DlpConfig>,
}

/// LLM Provider access rule.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LlmProviderRule {
    pub name: String,
    pub action: String,
    pub models: Option<Vec<String>>,
    pub max_tokens_per_request: Option<u32>,
    pub dlp_tier: Option<String>,
}

/// LLM DLP configuration block.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DlpConfig {
    pub actions: Option<Vec<DlpActionRule>>,
}

/// DLP Action ladder rule.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DlpActionRule {
    pub entity: String,
    pub action: String,
}

/// Agent identity and credential policy (FR-22).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentIdentityPolicy {
    pub id: String,
    pub sub: String,
    #[serde(default)]
    pub credential_scope: Vec<CredentialScope>,
    pub max_credential_ttl: Option<String>,
    pub rotation_policy: Option<String>,
}

/// FR-112: Group-scoped identity and tool policy.
///
/// Binds one or more IdP group claim values to a set of tool rules.
/// Group membership is extracted from the JWT token's group claim (FR-113).
/// When multiple groups match, deny beats allow on the same tool (FR-114).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupIdentityPolicy {
    /// Human-readable group policy ID. Used in audit log entries (FR-115)
    /// to identify which group triggered an enforcement decision.
    pub id: String,
    /// Group claim values that trigger this policy. Any match = policy applies.
    /// Must be non-empty — an entry with no claims is rejected at load time.
    pub claims: Vec<String>,
    /// Tool rules scoped to members of this group.
    /// Reuses the existing ToolRule struct — one policy representation, not two.
    pub tools: Option<Vec<ToolRule>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpendCapsConfig {
    #[serde(default)]
    pub enabled: bool,
    pub license_key: Option<String>,
    #[serde(default)]
    pub admin_api: bool,
    pub pricing_table_path: Option<String>,
    pub concurrency_ceiling: Option<usize>,
    pub max_tokens_per_session: Option<u64>,
    pub max_concurrent_sessions: Option<usize>,
    pub retention: Option<crate::spend::RetentionPolicy>,
}

/// Per-tool credential scope (FR-22).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialScope {
    pub tool: String,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub databases: Vec<String>,
}

/// FR-306: Action to take when a cycle is detected.
#[derive(Debug, Clone, Deserialize, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum CycleAction {
    /// Return a custom JSON-RPC error (-32010) telling the agent to try a different approach.
    #[default]
    PivotError,
    /// Return a standard policy violation error (-32001) and trigger kill mode.
    Block,
    /// Pause and ask the developer interactively (falls back to block in non-TTY).
    PauseInteractive,
}

/// FR-306: Cycle detection configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CycleDetectionConfig {
    /// Number of consecutive identical calls before triggering. Default: 3.
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,

    /// What to do when a cycle is detected. Default: pivot_error.
    #[serde(default)]
    pub action: CycleAction,
}

impl Default for CycleDetectionConfig {
    fn default() -> Self {
        Self {
            max_attempts: default_max_attempts(),
            action: CycleAction::default(),
        }
    }
}

fn default_max_attempts() -> u32 {
    3
}

/// FR-306: Top-level firewall configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallConfig {
    /// Master toggle. Default: true.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Cycle detection settings.
    #[serde(default)]
    pub cycle_detection: CycleDetectionConfig,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            cycle_detection: CycleDetectionConfig::default(),
        }
    }
}

fn default_enabled() -> bool {
    true
}

/// FR-4: Self Healing configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfHealingConfig {
    pub enabled: bool,
    pub decay_window: String,
    pub auto_suggest: bool,
    pub suggest_threshold: f64,
    pub approval_required: bool,
}

/// Identity configuration (OIDC & Vault FR-22).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    pub provider: Option<String>,
    pub vault_addr: Option<String>,
    pub oidc_issuer: Option<String>,
    pub credential_type: Option<String>,
    pub default_ttl: Option<String>,
    pub rotation_drain: Option<String>,
    // Legacy fields (v1):
    pub issuer: Option<String>,
    pub audience: Option<String>,

    /// FR-113: JWT claim key to extract group membership from.
    /// Default: "groups". Configurable for IdP compatibility (e.g. "cognito:groups",
    /// "https://myapp.com/groups"). Located under identity: to match the
    /// Kubernetes auth-layer / RBAC-layer split.
    pub group_claim_key: Option<String>,
}

/// OIDC provider authentication configuration (FR-201).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    pub provider: String,
    pub jwks_uri: String,
    pub audience: String,
    pub issuer: String,
    pub cache_ttl_minutes: Option<u64>,
}

/// Response scanning configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseScanningConfig {
    /// Tools whose output should be scanned for secrets.
    pub scannable_tools: Option<Vec<String>>,
    /// Tools whose output is guaranteed safe and should never be scanned.
    pub safe_tools: Option<Vec<String>>,
}

/// Session-level configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionConfig {
    /// Max tool calls per second. 0 = unlimited. Optional.
    pub max_calls_per_second: Option<u32>,
}

/// Tool risk level.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ToolRisk {
    Low,
    Medium,
    High,
}

/// A single tool rule in the allowlist.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolRule {
    /// Exact case-sensitive tool name or regex (v2).
    pub name: String,

    /// "allow", "deny", or "notify" (v2).
    pub action: String,

    /// Tool risk score (v2).
    pub risk: Option<ToolRisk>,

    /// Parameter constraints. Optional.
    pub parameters: Option<Vec<ParameterRule>>,

    /// FR-201: Bound to specific agent sub claim
    pub identity: Option<String>,

    /// FR-5 v2.0: Required credential scopes for this tool.
    /// Agents must present one of these scopes via X-AgentWall-Credential-Scope header.
    /// Empty or absent = no scope restriction.
    /// Full enforcement requires FR-22 (Agent Identity Platform).
    #[serde(default)]
    pub credential_scope: Vec<String>,

    /// FR-5 v2.0: Per-tool semantic anomaly threshold override (0.0–1.0).
    /// Overrides gateway-level `semantic_anomaly_threshold` for this specific tool.
    /// None = use gateway default (0.9).
    pub semantic_anomaly_threshold: Option<f32>,

    /// FR-5 v2.0 / FR-21: A2A inter-agent trust level for this tool.
    /// Values: "none" | "same-org" | "verified" | "any".
    /// Absent = A2A scanning not applied to this tool.
    pub a2a_trust_level: Option<String>,
}

/// Parameter type enumeration.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ParamType {
    String,
    Number,
    Boolean,
    Object,
    Array,
}

impl std::fmt::Display for ParamType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParamType::String => write!(f, "string"),
            ParamType::Number => write!(f, "number"),
            ParamType::Boolean => write!(f, "boolean"),
            ParamType::Object => write!(f, "object"),
            ParamType::Array => write!(f, "array"),
        }
    }
}

/// Structural value-level parameter validator rules (FR-202)
#[derive(Debug, Clone, PartialEq)]
pub enum ValidatorRule {
    /// Rejects parameters containing "../" or "..\"
    PathTraversal,
    /// Rejects file://, javascript://, and configurable schemes
    UrlSchemeAllowlist(Option<Vec<String>>),
    /// Rejects UNION SELECT, DROP TABLE, and common SQLi patterns
    SqlInjectionBasic,
    /// Rejects ;, &&, ||, $(), and backtick sequences
    ShellInjectionBasic,
    /// Runs a custom compiled regex pattern
    Regex(String),
}

impl<'de> Deserialize<'de> for ValidatorRule {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ValidatorRuleVisitor;
        impl<'de> serde::de::Visitor<'de> for ValidatorRuleVisitor {
            type Value = ValidatorRule;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a string or map representing a ValidatorRule")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match value {
                    "path_traversal" => Ok(ValidatorRule::PathTraversal),
                    "url_scheme_allowlist" => Ok(ValidatorRule::UrlSchemeAllowlist(None)),
                    "sql_injection_basic" => Ok(ValidatorRule::SqlInjectionBasic),
                    "shell_injection_basic" => Ok(ValidatorRule::ShellInjectionBasic),
                    _ => Err(E::custom(format!("unknown validator rule: {}", value))),
                }
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let key: String = map
                    .next_key()?
                    .ok_or_else(|| serde::de::Error::custom("expected a validator key"))?;
                match key.as_str() {
                    "regex" => {
                        let val: String = map.next_value()?;
                        Ok(ValidatorRule::Regex(val))
                    }
                    "url_scheme_allowlist" => {
                        let val: Vec<String> = map.next_value()?;
                        Ok(ValidatorRule::UrlSchemeAllowlist(Some(val)))
                    }
                    _ => Err(serde::de::Error::custom(format!(
                        "unknown validator key: {}",
                        key
                    ))),
                }
            }
        }
        deserializer.deserialize_any(ValidatorRuleVisitor)
    }
}

/// A single parameter constraint within a tool rule.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParameterRule {
    /// Parameter name (case-sensitive).
    pub name: String,

    /// Expected JSON type.
    #[serde(rename = "type")]
    pub param_type: ParamType,

    /// Nested JSON Schema (Draft 7 subset) (FR-201).
    pub schema: Option<serde_json::Value>,

    /// Regex pattern (string type only). Auto-anchored with ^(?:...)$ unless unanchored: true.
    pub pattern: Option<String>,

    /// If true, do not auto-anchor the pattern. Default: false.
    /// Logs a startup WARNING for each unanchored parameter.
    #[serde(default)]
    pub unanchored: bool,

    /// Max byte length (string type only). Optional.
    pub max_length: Option<usize>,

    /// If true, parameter must be present. Default: false.
    #[serde(default)]
    pub required: bool,

    /// FR-202: Structural parameter validators.
    pub validators: Option<Vec<ValidatorRule>>,
}
