use agentcontrol::policy::loader::load_policy;

#[test]
fn test_llm_policy_schema_parsing() {
    let yaml_content = r#"
version: "2"
default_action: deny

llm:
  providers:
    - name: "openai"
      action: "allow"
      models: ["gpt-4o", "gpt-3.5-turbo"]
      dlp_tier: "strict"
    - name: "mock-provider"
      action: "deny"
      models: ["bad-model"]
  dlp:
    actions:
      - entity: "CREDIT_CARD"
        action: "deny"
"#;

    let dir = std::env::temp_dir();
    let file_path = dir.join("test_llm_policy.yaml");
    std::fs::write(&file_path, yaml_content).unwrap();

    let res = load_policy(&file_path, None);
    match res {
        agentcontrol::policy::loader::PolicyLoadResult::Loaded { policy, .. } => {
            assert!(policy.llm.is_some());
            let llm = policy.llm.unwrap();
            assert_eq!(llm.providers.unwrap().len(), 2);
            assert_eq!(llm.dlp.unwrap().actions.unwrap().len(), 1);
        }
        _ => panic!("Failed to load LLM policy"),
    }
}
