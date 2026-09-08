pub mod anthropic_test;
pub mod azure_openai_test;
pub mod bedrock_test;
pub mod gemini_test;
pub mod groq_test;
pub mod openai_test;

#[test]
fn test_all_supported_providers_have_transformer_matrix() {
    let providers = [
        "openai",
        "azure",
        "azure_openai",
        "groq",
        "anthropic",
        "gemini",
        "google",
        "bedrock",
        "aws_bedrock",
    ];

    for provider in &providers {
        let t = agentcontrol::proxy::transformer::get_transformer(provider);
        assert!(
            t.is_some(),
            "AR-6 Guard: Provider '{}' in factory must resolve to an active transformer",
            provider
        );
        let transformer = t.unwrap();
        assert!(
            !transformer.provider_name().is_empty(),
            "AR-6 Guard: Provider '{}' transformer has empty provider_name",
            provider
        );
    }
}
