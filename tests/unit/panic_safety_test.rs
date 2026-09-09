//! Adversarial Input & Panic Safety Unit Tests
//!
//! Verifies that untrusted, malformed, oversized, or non-canonical inputs
//! do not trigger panics in the proxy, cache, or detector subsystems.

use agentcontrol::proxy::semantic_cache::embedder::Embedder;
use agentcontrol::proxy::semantic_cache::vector_index::InMemoryVectorIndex;
use agentcontrol::proxy::semantic_cache::{CanonicalContext, SemanticCache};
use serde_json::json;

#[test]
fn test_adversarial_vector_normalization_no_panic() {
    // 1. All zeros
    let mut zeros = vec![0.0f32; 384];
    InMemoryVectorIndex::normalize_vector(&mut zeros);
    assert_eq!(zeros[0], 0.0);

    // 2. Vector with NaN
    let mut nans = vec![f32::NAN, 1.0, 2.0];
    InMemoryVectorIndex::normalize_vector(&mut nans);

    // 3. Vector with Infs
    let mut infs = vec![f32::INFINITY, -f32::INFINITY, 0.5];
    InMemoryVectorIndex::normalize_vector(&mut infs);

    // 4. Empty vector
    let mut empty = vec![];
    InMemoryVectorIndex::normalize_vector(&mut empty);

    // 5. Very small subnormal numbers
    let mut subnormals = vec![1e-35f32, 1e-30f32];
    InMemoryVectorIndex::normalize_vector(&mut subnormals);
}

#[test]
fn test_adversarial_local_vectorizer_no_panic() {
    // 1. Empty string
    let v_empty = Embedder::local_vectorize("");
    assert_eq!(v_empty.len(), 384);

    // 2. Whitespace only
    let v_spaces = Embedder::local_vectorize("     \t\r\n   ");
    assert_eq!(v_spaces.len(), 384);

    // 3. Oversized string > 100 KB
    let huge = "A".repeat(128 * 1024);
    let v_huge = Embedder::local_vectorize(&huge);
    assert_eq!(v_huge.len(), 384);

    // 4. Multibyte UTF-8 emojis and homoglyphs across character boundaries
    let weird_utf8 = "🚨 🛡️ 🦀 Привет мир \u{1F600} \u{200B} \u{FEFF} 测试汉字";
    let v_utf8 = Embedder::local_vectorize(weird_utf8);
    assert_eq!(v_utf8.len(), 384);
}

#[test]
fn test_adversarial_cacheability_checks_no_panic() {
    let dummy_ctx = CanonicalContext {
        tenant_id: "t".to_string(),
        subject_id: "s".to_string(),
        virtual_key_scope: None,
        provider: "p".to_string(),
        model: "m".to_string(),
        model_version: None,
        policy_version: "1.0.0".to_string(),
        workspace_hash: None,
        system_prompt_hash: "h".to_string(),
        developer_message_hash: None,
        temperature_fixed: "0.000".to_string(),
        top_p_fixed: None,
        top_k: None,
        seed: None,
        max_tokens: None,
        stop_sequences: vec![],
        response_format: None,
        reasoning_effort: None,
        locale: None,
        normalized_prompt: "test".to_string(),
    };

    // 1. Non-object JSON root payloads
    let array_json = json!([1, 2, 3]);
    let str_json = json!("raw string");
    let null_json = json!(null);
    assert!(SemanticCache::is_request_cacheable(&array_json, &dummy_ctx).is_ok());
    assert!(SemanticCache::is_request_cacheable(&str_json, &dummy_ctx).is_ok());
    assert!(SemanticCache::is_request_cacheable(&null_json, &dummy_ctx).is_ok());

    // 2. Broken, incomplete, and non-UTF8 response bodies
    let broken_bytes = b"\xFF\xFE\xFD\x00\x01\x02";
    assert!(!SemanticCache::is_response_cacheable(
        200,
        broken_bytes,
        true,
        false
    ));

    // 3. Truncated JSON
    let truncated_json = b"{\"choices\": [{\"message\": {\"content\": ";
    assert!(!SemanticCache::is_response_cacheable(
        200,
        truncated_json,
        true,
        false
    ));
}
