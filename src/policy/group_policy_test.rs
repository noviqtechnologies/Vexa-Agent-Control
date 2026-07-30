//! Group-Scoped Policy unit tests (FR-113, FR-114, Step 1.8)
//!
//! Covers:
//!   1. Group claim extraction from JWT (single, array, missing)
//!   2. Group-level allow fires when agent is in matching group
//!   3. Deny-overrides: deny in any matching group beats allow in another
//!   4. Agent-level rule takes precedence over group-level rule
//!   5. Org-level fallback when no group match
//!   6. Not-in-policy deny when tool absent from all applicable rules
//!   7. matched_group_id propagated correctly in EvalResult

#[cfg(test)]
mod tests {
    use crate::policy::engine::{
        CompiledGroupPolicy, CompiledPolicy, CompiledTool, CompiledParam, EvalResult,
    };
    use crate::policy::loader::load_policy_from_str;
    use serde_json::json;

    // ─── Helpers ──────────────────────────────────────────────────────────────

    fn allow_tool(name: &str) -> CompiledTool {
        CompiledTool {
            name: name.to_string(),
            action: "allow".to_string(),
            identity: None,
            parameters: vec![],
            risk: None,
            credential_scope: vec![],
            semantic_anomaly_threshold: None,
            a2a_trust_level: None,
        }
    }

    fn deny_tool(name: &str) -> CompiledTool {
        CompiledTool {
            name: name.to_string(),
            action: "deny".to_string(),
            identity: None,
            parameters: vec![],
            risk: None,
            credential_scope: vec![],
            semantic_anomaly_threshold: None,
            a2a_trust_level: None,
        }
    }

    fn allow_tool_identity(name: &str, sub: &str) -> CompiledTool {
        CompiledTool {
            name: name.to_string(),
            action: "allow".to_string(),
            identity: Some(sub.to_string()),
            parameters: vec![],
            risk: None,
            credential_scope: vec![],
            semantic_anomaly_threshold: None,
            a2a_trust_level: None,
        }
    }

    fn allow_param_tool(name: &str, param: &str, allowed: Vec<&str>) -> CompiledTool {
        let pattern_str = format!("^({})$", allowed.join("|"));
        CompiledTool {
            name: name.to_string(),
            action: "allow".to_string(),
            identity: None,
            parameters: vec![CompiledParam {
                name: param.to_string(),
                param_type: crate::policy::schema::ParamType::String,
                pattern: Some(regex::Regex::new(&pattern_str).unwrap()),
                schema: None,
                max_length: None,
                required: false,
                validators: vec![],
            }],
            risk: None,
            credential_scope: vec![],
            semantic_anomaly_threshold: None,
            a2a_trust_level: None,
        }
    }

    fn make_group_policy(id: &str, claims: Vec<&str>, tools: Vec<CompiledTool>) -> CompiledGroupPolicy {
        CompiledGroupPolicy {
            id: id.to_string(),
            claims: claims.into_iter().map(|s| s.to_string()).collect(),
            tools,
        }
    }

    fn base_policy(tools: Vec<CompiledTool>, groups: Vec<CompiledGroupPolicy>) -> CompiledPolicy {
        CompiledPolicy {
            tools,
            group_policies: groups,
            max_calls_per_second: 0,
            identity_validator: None,
            scannable_tools: vec![],
            safe_tools: vec![],
            firewall: None,
        }
    }

    // ─── Test 1: Group-level allow grants access ──────────────────────────────

    #[test]
    fn test_group_allow_grants_access() {
        let policy = base_policy(
            vec![],
            vec![make_group_policy(
                "engineers",
                vec!["engineering"],
                vec![allow_tool("read_file")],
            )],
        );

        let result = policy.evaluate("read_file", &json!({}), None, &["engineering".to_string()]);
        assert!(matches!(result, EvalResult::Allow { .. }), "Expected Allow for group member");
    }

    // ─── Test 2: Non-member gets not_in_policy deny ───────────────────────────

    #[test]
    fn test_non_group_member_denied() {
        let policy = base_policy(
            vec![],
            vec![make_group_policy(
                "engineers",
                vec!["engineering"],
                vec![allow_tool("read_file")],
            )],
        );

        let result = policy.evaluate("read_file", &json!({}), None, &["finance".to_string()]);
        assert!(
            matches!(&result, EvalResult::Deny { reason_code, .. } if reason_code == "not_in_policy"),
            "Expected not_in_policy deny for non-member, got: {:?}", result,
        );
    }

    // ─── Test 3: Deny-overrides (FR-114) ─────────────────────────────────────
    // Agent is in two groups: one allows, one denies — deny must win.

    #[test]
    fn test_deny_overrides_allow_across_groups() {
        let policy = base_policy(
            vec![],
            vec![
                make_group_policy("allow-grp", vec!["engineering"], vec![allow_tool("write_file")]),
                make_group_policy("deny-grp", vec!["contractors"], vec![deny_tool("write_file")]),
            ],
        );

        let groups = vec!["engineering".to_string(), "contractors".to_string()];
        let result = policy.evaluate("write_file", &json!({}), None, &groups);
        assert!(
            matches!(&result, EvalResult::Deny { reason_code, .. } if reason_code == "default_deny"),
            "Deny-overrides failed: expected default_deny, got: {:?}", result,
        );
    }

    // ─── Test 4: matched_group_id is populated correctly ─────────────────────

    #[test]
    fn test_matched_group_id_propagated() {
        let policy = base_policy(
            vec![],
            vec![make_group_policy(
                "platform-team",
                vec!["platform"],
                vec![allow_tool("deploy")],
            )],
        );

        let result = policy.evaluate("deploy", &json!({}), None, &["platform".to_string()]);
        match result {
            EvalResult::Allow { matched_group_id } => {
                assert_eq!(matched_group_id, Some("platform-team".to_string()));
            }
            other => panic!("Expected Allow, got {:?}", other),
        }
    }

    // ─── Test 5: Agent-level rule takes precedence over group rule ────────────

    #[test]
    fn test_agent_level_beats_group_level() {
        let policy = base_policy(
            // Top-level agent-specific allow for "alice"
            vec![allow_tool_identity("sensitive_tool", "alice")],
            // Group-level deny for the same tool
            vec![make_group_policy(
                "restricted",
                vec!["group-a"],
                vec![deny_tool("sensitive_tool")],
            )],
        );

        // Alice is also in "group-a" which would deny — agent rule wins
        let result = policy.evaluate(
            "sensitive_tool",
            &json!({}),
            Some("alice"),
            &["group-a".to_string()],
        );
        assert!(
            matches!(result, EvalResult::Allow { .. }),
            "Agent-level rule should override group deny",
        );
    }

    // ─── Test 6: Org-level fallback when no group matches ────────────────────

    #[test]
    fn test_org_level_fallback() {
        let policy = base_policy(
            // Wildcard/org-level allow
            vec![allow_tool("list_tools")],
            // A group policy that doesn't match the agent's groups
            vec![make_group_policy(
                "admins",
                vec!["admin"],
                vec![deny_tool("list_tools")],
            )],
        );

        // Agent in "users" — doesn't match "admin" group, falls through to org rule
        let result = policy.evaluate("list_tools", &json!({}), None, &["users".to_string()]);
        assert!(
            matches!(result, EvalResult::Allow { .. }),
            "Org-level rule should apply when no group matches",
        );
    }

    // ─── Test 7: Group policy parameter restrictions apply ───────────────────

    #[test]
    fn test_group_policy_param_restriction() {
        let policy = base_policy(
            vec![],
            vec![make_group_policy(
                "read-only",
                vec!["readers"],
                vec![allow_param_tool("query_db", "mode", vec!["SELECT"])],
            )],
        );

        // Allowed value
        let allow_result = policy.evaluate(
            "query_db",
            &json!({"mode": "SELECT"}),
            None,
            &["readers".to_string()],
        );
        assert!(matches!(allow_result, EvalResult::Allow { .. }), "SELECT should be allowed");

        // Disallowed value
        let deny_result = policy.evaluate(
            "query_db",
            &json!({"mode": "DELETE"}),
            None,
            &["readers".to_string()],
        );
        assert!(
            matches!(&deny_result, EvalResult::Deny { reason_code, .. } if reason_code == "param_pattern_mismatch"),
            "DELETE should be denied, got: {:?}", deny_result,
        );
    }

    // ─── Test 8: load_policy_from_str with groups block ──────────────────────

    #[tokio::test]
    async fn test_yaml_groups_round_trip() {
        let yaml = r#"
version: "1"
default_action: deny
identity:
  issuer: "https://example.com"
  audience: "test"
  group_claim_key: "groups"
groups:
  - id: "sre-team"
    claims: ["sre", "oncall"]
    tools:
      - name: "restart_service"
        action: allow
tools: []
"#;
        let result = load_policy_from_str(yaml, None);
        assert!(
            matches!(result, crate::policy::loader::PolicyLoadResult::Loaded { .. }),
            "Policy with groups block should load cleanly"
        );

        if let crate::policy::loader::PolicyLoadResult::Loaded { policy, .. } = result {
            assert_eq!(policy.group_policies.len(), 1);
            assert_eq!(policy.group_policies[0].id, "sre-team");
            assert_eq!(policy.group_policies[0].claims, vec!["sre", "oncall"]);
            assert_eq!(policy.group_policies[0].tools[0].name, "restart_service");
        }
    }
}
