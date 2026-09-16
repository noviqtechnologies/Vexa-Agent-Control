use agentcontrol::proxy::semantic_cache::embedder::{Embedder, EmbedderEngine};
use agentcontrol::proxy::semantic_cache::vector_index::{InMemoryVectorIndex, VectorEntry};
use agentcontrol::proxy::semantic_cache::SemanticCache;
use bytes::Bytes;
use reqwest::Client;
use std::time::Duration;

#[tokio::test]
async fn test_exact_l1_cache_hit_and_miss() {
    let cache = SemanticCache::new_in_memory(
        true,
        0.88,
        100,
        Duration::from_secs(60),
        EmbedderEngine::Local,
    );
    let client = Client::new();

    let tenant = "tenant-prod-1";
    let model = "gpt-4o";
    let prompt = "Explain Kubernetes pod lifecycle in detail";
    let response_bytes = Bytes::from(
        "{\"choices\":[{\"message\":{\"content\":\"A Pod is the smallest deployable unit...\"}}]}",
    );

    // Initially miss
    assert!(cache.lookup(&client, tenant, model, prompt).await.is_none());

    // Store in cache
    cache
        .store(
            &client,
            tenant,
            model,
            prompt,
            response_bytes.clone(),
            "application/json",
            120,
            350,
        )
        .await;

    // Exact query -> Hit L1
    let hit = cache.lookup(&client, tenant, model, prompt).await;
    assert!(hit.is_some(), "Expected L1 exact cache hit");
    let h = hit.unwrap();
    assert_eq!(h.hit_type, "exact");
    assert_eq!(h.similarity, 1.0);
    assert_eq!(h.response_body, response_bytes);
    assert_eq!(h.prompt_tokens, 120);
    assert_eq!(h.completion_tokens, 350);
    assert!(h.cost_saved_usd > 0.0);

    let stats = cache.metrics.snapshot();
    assert_eq!(stats["gateway_cache"]["exact_hits"].as_u64().unwrap(), 1);
    assert_eq!(stats["gateway_cache"]["semantic_hits"].as_u64().unwrap(), 0);
    assert_eq!(stats["gateway_cache"]["misses"].as_u64().unwrap(), 1);
    assert_eq!(
        stats["gateway_cache"]["tokens_saved"]["total"]
            .as_u64()
            .unwrap(),
        470
    );
}

#[tokio::test]
async fn test_semantic_l2_cache_hit() {
    let cache = SemanticCache::new_in_memory(
        true,
        0.70, // Allow semantic match threshold
        100,
        Duration::from_secs(60),
        EmbedderEngine::Local,
    );
    let client = Client::new();

    let tenant = "dev-workspace";
    let model = "claude-3-5-sonnet";
    let original_prompt = "how to sort a list of numbers in python";
    let semantically_similar_prompt = "how to sort a list of numbers in python language";
    let response_bytes = Bytes::from("{\"content\":\"Use sorted(numbers) or numbers.sort()\"}");

    // Store original prompt
    cache
        .store(
            &client,
            tenant,
            model,
            original_prompt,
            response_bytes.clone(),
            "application/json",
            40,
            60,
        )
        .await;

    // Query with semantically similar prompt -> Hits L2 Vector Search
    let hit = cache
        .lookup(&client, tenant, model, semantically_similar_prompt)
        .await;
    assert!(hit.is_some(), "Expected semantic L2 vector cache hit");
    let h = hit.unwrap();
    assert_eq!(h.hit_type, "semantic");
    assert!(
        h.similarity >= 0.70,
        "Cosine similarity {} must be >= 0.70",
        h.similarity
    );
    assert_eq!(h.response_body, response_bytes);
    assert_eq!(h.cached_prompt, original_prompt);

    let stats = cache.metrics.snapshot();
    assert_eq!(stats["gateway_cache"]["semantic_hits"].as_u64().unwrap(), 1);
    assert_eq!(stats["gateway_cache"]["exact_hits"].as_u64().unwrap(), 0);
    assert_eq!(
        stats["gateway_cache"]["tokens_saved"]["total"]
            .as_u64()
            .unwrap(),
        100
    );
}

#[tokio::test]
async fn test_semantic_threshold_rejection() {
    let cache = SemanticCache::new_in_memory(
        true,
        0.85, // Strict threshold
        100,
        Duration::from_secs(60),
        EmbedderEngine::Local,
    );
    let client = Client::new();

    let tenant = "test-tenant";
    let model = "gpt-4o";
    let original_prompt = "write a function to calculate fibonacci sequence in rust";
    let unrelated_prompt = "what is the current temperature in San Francisco today";

    cache
        .store(
            &client,
            tenant,
            model,
            original_prompt,
            Bytes::from("fn fibonacci(n: u32) -> u64 { ... }"),
            "text/plain",
            50,
            150,
        )
        .await;

    // Unrelated query must miss
    let hit = cache.lookup(&client, tenant, model, unrelated_prompt).await;
    assert!(
        hit.is_none(),
        "Unrelated prompt must not match semantic cache"
    );

    let stats = cache.metrics.snapshot();
    assert_eq!(stats["gateway_cache"]["misses"].as_u64().unwrap(), 1);
}

#[tokio::test]
async fn test_tenant_and_model_isolation() {
    let cache = SemanticCache::new_in_memory(
        true,
        0.80,
        100,
        Duration::from_secs(60),
        EmbedderEngine::Local,
    );
    let client = Client::new();

    let prompt = "generate confidential database credentials for production";
    let secret_resp = Bytes::from("SECRET_KEY_DB_12345");

    // Stored under Tenant Alpha, model gpt-4o
    cache
        .store(
            &client,
            "tenant-alpha",
            "gpt-4o",
            prompt,
            secret_resp.clone(),
            "text/plain",
            20,
            20,
        )
        .await;

    // 1. Tenant Beta querying identical prompt -> MUST MISS (Strict Tenant Isolation)
    let cross_tenant_hit = cache.lookup(&client, "tenant-beta", "gpt-4o", prompt).await;
    assert!(
        cross_tenant_hit.is_none(),
        "Tenant Beta must not access Tenant Alpha cached prompt"
    );

    // 2. Same tenant querying different model -> MUST MISS (Model Isolation)
    let cross_model_hit = cache
        .lookup(&client, "tenant-alpha", "claude-3-5-sonnet", prompt)
        .await;
    assert!(
        cross_model_hit.is_none(),
        "Cross-model query must not hit cache of different model"
    );

    // 3. Authorized tenant and model -> HITS
    let authorized_hit = cache
        .lookup(&client, "tenant-alpha", "gpt-4o", prompt)
        .await;
    assert!(authorized_hit.is_some());
    assert_eq!(authorized_hit.unwrap().response_body, secret_resp);
}

#[tokio::test]
async fn test_differentiated_token_economics_metrics() {
    let cache = SemanticCache::new_in_memory(
        true,
        0.88,
        100,
        Duration::from_secs(60),
        EmbedderEngine::Local,
    );

    // 1. Record a Vexa Gateway Hit (100% cost avoided)
    cache.metrics.record_gateway_hit(
        "semantic",
        "gpt-4o",
        "how to reverse a string in python",
        "how to reverse string python",
        0.94,
        200,
        100,
        2.5,
    );

    // 2. Record an Upstream Provider-Side Prompt Cache Hit (partial prefix discount)
    cache.metrics.record_provider_discount("gpt-4o", 1000);

    let stats = cache.metrics.snapshot();

    // Check Gateway metrics
    assert_eq!(
        stats["gateway_cache"]["tokens_saved"]["total"]
            .as_u64()
            .unwrap(),
        300
    );
    assert!(
        stats["gateway_cache"]["cost_saved_usd"].as_f64().unwrap() > 0.0,
        "Gateway avoided cost must be positive"
    );
    assert_eq!(stats["gateway_cache"]["semantic_hits"].as_u64().unwrap(), 1);

    // Check Provider metrics
    assert_eq!(
        stats["provider_cache"]["cached_tokens"].as_u64().unwrap(),
        1000
    );
    assert!(stats["provider_cache"]["discount_usd"].as_f64().unwrap() > 0.0);

    // Check Combined Net Economic Value
    let gw_cost = stats["gateway_cache"]["cost_saved_usd"].as_f64().unwrap();
    let prov_disc = stats["provider_cache"]["discount_usd"].as_f64().unwrap();
    let total_sav = stats["comparative_summary"]["total_savings_usd"]
        .as_f64()
        .unwrap();
    assert!((total_sav - (gw_cost + prov_disc)).abs() < 0.01);

    // Check Circular Buffer
    let recent = stats["recent_matches"].as_array().unwrap();
    assert_eq!(recent.len(), 1);
    let match_record = &recent[0];
    assert_eq!(match_record["model"].as_str().unwrap(), "gpt-4o");
    assert!((match_record["similarity"].as_f64().unwrap() - 0.94).abs() < 1e-4);
    assert_eq!(match_record["tokens_saved"].as_i64().unwrap(), 300);
}

#[tokio::test]
async fn test_cache_clear() {
    let cache = SemanticCache::new_in_memory(
        true,
        0.88,
        100,
        Duration::from_secs(60),
        EmbedderEngine::Local,
    );
    let client = Client::new();

    cache
        .store(
            &client,
            "default",
            "gpt-4o",
            "hello world",
            Bytes::from("hello!"),
            "text/plain",
            10,
            10,
        )
        .await;

    // Verify it's present
    assert!(cache
        .lookup(&client, "default", "gpt-4o", "hello world")
        .await
        .is_some());

    // Clear
    cache.clear();

    // Verify it's gone
    assert!(cache
        .lookup(&client, "default", "gpt-4o", "hello world")
        .await
        .is_none());
}

#[test]
fn test_local_vectorizer_properties() {
    let v1 = Embedder::local_vectorize("how to configure redis semantic cache");
    let v2 = Embedder::local_vectorize("how to configure redis semantic cache");
    let v3 = Embedder::local_vectorize("unrelated recipe for chocolate chip cookies");

    // 1. Dimension count
    assert_eq!(v1.len(), 384);
    assert_eq!(v2.len(), 384);
    assert_eq!(v3.len(), 384);

    // 2. Determinism across calls
    assert_eq!(v1, v2, "Identical inputs must yield identical vectors");

    // 3. Self-similarity (cosine similarity with self should be ~1.0 due to L2 normalization)
    let dot_self = InMemoryVectorIndex::cosine_similarity(&v1, &v1);
    assert!(
        (dot_self - 1.0).abs() < 1e-4,
        "L2-normalized vector dot product with self must be 1.0, got {}",
        dot_self
    );

    // 4. Semantically unrelated vectors should have lower cosine similarity
    let dot_unrelated = InMemoryVectorIndex::cosine_similarity(&v1, &v3);
    assert!(
        dot_unrelated < 0.6,
        "Unrelated prompts should have low similarity, got {}",
        dot_unrelated
    );
}

#[test]
fn test_vector_index_lru_eviction() {
    let index = InMemoryVectorIndex::new(2); // Capacity = 2
    let now = std::time::Instant::now();
    let ttl = Duration::from_secs(3600);

    let v1 = vec![1.0, 0.0];
    let v2 = vec![0.0, 1.0];
    let v3 = vec![0.707, 0.707];

    index.insert(VectorEntry {
        id: "entry-1".to_string(),
        tenant_id: "t1".to_string(),
        model: "m1".to_string(),
        vector: v1.clone(),
        prompt_text: "p1".to_string(),
        response_body: Bytes::from("r1"),
        content_type: "text/plain".to_string(),
        prompt_tokens: 10,
        completion_tokens: 10,
        created_at: now,
        last_accessed: now,
        ttl,
    });

    index.insert(VectorEntry {
        id: "entry-2".to_string(),
        tenant_id: "t1".to_string(),
        model: "m1".to_string(),
        vector: v2.clone(),
        prompt_text: "p2".to_string(),
        response_body: Bytes::from("r2"),
        content_type: "text/plain".to_string(),
        prompt_tokens: 10,
        completion_tokens: 10,
        created_at: now,
        last_accessed: now,
        ttl,
    });

    assert_eq!(index.total_entries(), 2);

    // Insert 3rd entry -> Should evict entry-1
    index.insert(VectorEntry {
        id: "entry-3".to_string(),
        tenant_id: "t1".to_string(),
        model: "m1".to_string(),
        vector: v3.clone(),
        prompt_text: "p3".to_string(),
        response_body: Bytes::from("r3"),
        content_type: "text/plain".to_string(),
        prompt_tokens: 10,
        completion_tokens: 10,
        created_at: now,
        last_accessed: now,
        ttl,
    });

    assert_eq!(index.total_entries(), 2);

    // Search for entry-1 with high threshold -> Should not find entry-1
    let hit_v1 = index.search("t1", "m1", &v1, 0.99);
    assert!(hit_v1.is_none(), "Oldest entry should have been evicted");

    // Search for entry-3 -> Should be found
    let hit_v3 = index.search("t1", "m1", &v3, 0.99);
    assert!(hit_v3.is_some());
    assert_eq!(hit_v3.unwrap().0.id, "entry-3");
}

#[test]
fn test_semantic_cache_config_deserialization_dual_format() {
    use agentcontrol::policy::schema::SemanticCacheConfig;

    // 1. Test nested configuration as shown in documentation
    let nested_yaml = r#"
enabled: true
similarity_threshold: 0.91
max_entries: 20000
ttl_seconds: 43200
backend: "qdrant"
qdrant:
  url: "http://qdrant.internal:6333"
  api_key: "secret-key-123"
  collection: "custom-cache"
embedder:
  engine: "openai"
  model: "text-embedding-3-small"
  endpoint: "https://api.openai.com/v1"
  api_key: "sk-openai-key"
"#;
    let cfg_nested: SemanticCacheConfig =
        serde_yaml::from_str(nested_yaml).expect("Nested YAML should deserialize");
    assert!(cfg_nested.enabled);
    assert_eq!(cfg_nested.similarity_threshold, Some(0.91));
    assert_eq!(
        cfg_nested.resolved_qdrant_url().as_deref(),
        Some("http://qdrant.internal:6333")
    );
    assert_eq!(
        cfg_nested.resolved_qdrant_api_key().as_deref(),
        Some("secret-key-123")
    );
    assert_eq!(
        cfg_nested.resolved_qdrant_collection().as_deref(),
        Some("custom-cache")
    );
    assert_eq!(
        cfg_nested.resolved_embedding_provider().as_deref(),
        Some("openai")
    );
    assert_eq!(
        cfg_nested.resolved_embedding_model().as_deref(),
        Some("text-embedding-3-small")
    );
    assert_eq!(
        cfg_nested.resolved_embedding_endpoint().as_deref(),
        Some("https://api.openai.com/v1")
    );
    assert_eq!(
        cfg_nested.resolved_embedding_api_key().as_deref(),
        Some("sk-openai-key")
    );

    // 2. Test flat configuration (backwards-compatible)
    let flat_yaml = r#"
enabled: true
backend: "in_memory"
similarity_threshold: 0.88
qdrant_url: "http://flat.url:6333"
embedding_provider: "local"
"#;
    let cfg_flat: SemanticCacheConfig =
        serde_yaml::from_str(flat_yaml).expect("Flat YAML should deserialize");
    assert!(cfg_flat.enabled);
    assert_eq!(
        cfg_flat.resolved_qdrant_url().as_deref(),
        Some("http://flat.url:6333")
    );
    assert_eq!(
        cfg_flat.resolved_embedding_provider().as_deref(),
        Some("local")
    );
}

#[test]
fn test_canonical_context_key_isolation() {
    use agentcontrol::proxy::semantic_cache::CanonicalContext;

    let base_ctx = CanonicalContext {
        tenant_id: "tenant-a".to_string(),
        subject_id: "user-1".to_string(),
        virtual_key_scope: Some("scope-x".to_string()),
        provider: "openai".to_string(),
        model: "gpt-4o".to_string(),
        model_version: None,
        policy_version: "1.0.82".to_string(),
        workspace_hash: None,
        system_prompt_hash: "sys-v1".to_string(),
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
        normalized_prompt: "hello world".to_string(),
    };

    let base_key = base_ctx.compute_exact_key();

    // 1. Cross-tenant isolation
    let mut diff_tenant = base_ctx.clone();
    diff_tenant.tenant_id = "tenant-b".to_string();
    assert_ne!(
        base_key,
        diff_tenant.compute_exact_key(),
        "Cross-tenant key collision detected"
    );

    // 2. Cross-user isolation
    let mut diff_user = base_ctx.clone();
    diff_user.subject_id = "user-2".to_string();
    assert_ne!(
        base_key,
        diff_user.compute_exact_key(),
        "Cross-user key collision detected"
    );

    // 3. System prompt change isolation
    let mut diff_sys = base_ctx.clone();
    diff_sys.system_prompt_hash = "sys-v2".to_string();
    assert_ne!(
        base_key,
        diff_sys.compute_exact_key(),
        "System prompt key collision detected"
    );

    // 4. Policy version change isolation
    let mut diff_policy = base_ctx.clone();
    diff_policy.policy_version = "1.0.85".to_string();
    assert_ne!(
        base_key,
        diff_policy.compute_exact_key(),
        "Policy version key collision detected"
    );

    // 5. Temperature parameter change isolation
    let mut diff_temp = base_ctx.clone();
    diff_temp.temperature_fixed = "0.700".to_string();
    assert_ne!(
        base_key,
        diff_temp.compute_exact_key(),
        "Temperature parameter collision detected"
    );
}

#[test]
fn test_layered_cacheability_bypasses() {
    use agentcontrol::proxy::semantic_cache::metrics::CacheBypassReason;
    use agentcontrol::proxy::semantic_cache::{CanonicalContext, SemanticCache};
    use serde_json::json;

    let valid_ctx = CanonicalContext {
        tenant_id: "tenant-corp".to_string(),
        subject_id: "alice@corp.internal".to_string(),
        virtual_key_scope: None,
        provider: "openai".to_string(),
        model: "gpt-4o-mini".to_string(),
        model_version: None,
        policy_version: "2.1.0".to_string(),
        workspace_hash: None,
        system_prompt_hash: "sys-hash-default".to_string(),
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
        normalized_prompt: "What is an RFC in internet standards?".to_string(),
    };

    // Clean prompt without tools -> Allowed
    let clean_body = json!({
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "What is an RFC in internet standards?"}]
    });
    assert!(SemanticCache::is_request_cacheable(&clean_body, &valid_ctx).is_ok());

    // 1. Syntactic bypass: tools present
    let tools_body = json!({
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "What is an RFC in internet standards?"}],
        "tools": [{"type": "function", "function": {"name": "lookup_rfc"}}]
    });
    assert_eq!(
        SemanticCache::is_request_cacheable(&tools_body, &valid_ctx),
        Err(CacheBypassReason::SyntacticToolsOrFunctions)
    );

    // 2. Syntactic bypass: functions present
    let funcs_body = json!({
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "What is an RFC in internet standards?"}],
        "functions": [{"name": "lookup"}]
    });
    assert_eq!(
        SemanticCache::is_request_cacheable(&funcs_body, &valid_ctx),
        Err(CacheBypassReason::SyntacticToolsOrFunctions)
    );

    // 3. Semantic bypass: mutating / financial imperatives
    let mut mutating_ctx = valid_ctx.clone();
    mutating_ctx.normalized_prompt = "delete all logs from production database".to_string();
    assert_eq!(
        SemanticCache::is_request_cacheable(&clean_body, &mutating_ctx),
        Err(CacheBypassReason::SemanticNonReadOnlyIntent)
    );

    mutating_ctx.normalized_prompt = "approve payment for invoice 123".to_string();
    assert_eq!(
        SemanticCache::is_request_cacheable(&clean_body, &mutating_ctx),
        Err(CacheBypassReason::SemanticNonReadOnlyIntent)
    );

    // 4. Context bypass: non-deterministic temperature
    let mut temp_ctx = valid_ctx.clone();
    temp_ctx.temperature_fixed = "0.700".to_string();
    assert_eq!(
        SemanticCache::is_request_cacheable(&clean_body, &temp_ctx),
        Err(CacheBypassReason::ContextNonDeterministicParameters)
    );

    // 5. Context bypass: missing identity
    let mut no_id_ctx = valid_ctx.clone();
    no_id_ctx.tenant_id = "".to_string();
    assert_eq!(
        SemanticCache::is_request_cacheable(&clean_body, &no_id_ctx),
        Err(CacheBypassReason::ContextMissingIdentity)
    );
}

#[test]
fn test_response_cacheability_validation() {
    use agentcontrol::proxy::semantic_cache::SemanticCache;

    // Clean 200 OK assistant response
    let clean_json = serde_json::json!({
        "choices": [{
            "message": {
                "role": "assistant",
                "content": "An RFC is a formal document from the IETF."
            },
            "finish_reason": "stop"
        }]
    });
    let clean_bytes = serde_json::to_vec(&clean_json).unwrap();
    assert!(SemanticCache::is_response_cacheable(
        200,
        &clean_bytes,
        true,
        false
    ));

    // Rejects non-200 status
    assert!(!SemanticCache::is_response_cacheable(
        500,
        &clean_bytes,
        true,
        false
    ));

    // Rejects responses with tool calls
    let tool_call_json = serde_json::json!({
        "choices": [{
            "message": {
                "role": "assistant",
                "tool_calls": [{"id": "call_1", "type": "function"}]
            },
            "finish_reason": "tool_calls"
        }]
    });
    let tool_bytes = serde_json::to_vec(&tool_call_json).unwrap();
    assert!(
        !SemanticCache::is_response_cacheable(200, &tool_bytes, true, false),
        "Tool call responses must never be cached"
    );

    // Rejects responses with security warning
    assert!(!SemanticCache::is_response_cacheable(
        200,
        &clean_bytes,
        true,
        true
    ));

    // Rejects incomplete streams
    assert!(!SemanticCache::is_response_cacheable(
        200,
        &clean_bytes,
        false,
        false
    ));
}

#[test]
fn test_vector_index_dual_capacity_limits() {
    use agentcontrol::proxy::semantic_cache::vector_index::{InMemoryVectorIndex, VectorEntry};
    use bytes::Bytes;
    use std::time::{Duration, Instant};

    // Capacity limit of 2 entries and 500 bytes
    let index = InMemoryVectorIndex::with_limits(2, 500, 1024, 1024);

    let entry1 = VectorEntry {
        id: "id-1".to_string(),
        tenant_id: "t1".to_string(),
        model: "m1".to_string(),
        vector: vec![0.5, 0.5, 0.5, 0.5],
        prompt_text: "prompt 1".to_string(),
        response_body: Bytes::from("res 1"),
        content_type: "text/plain".to_string(),
        prompt_tokens: 10,
        completion_tokens: 20,
        created_at: Instant::now(),
        last_accessed: Instant::now(),
        ttl: Duration::from_secs(60),
    };

    let mut entry2 = entry1.clone();
    entry2.id = "id-2".to_string();

    let mut entry3 = entry1.clone();
    entry3.id = "id-3".to_string();

    assert!(index.insert(entry1));
    assert!(index.insert(entry2));
    assert_eq!(index.total_entries(), 2);

    // Third entry triggers eviction of oldest entry
    assert!(index.insert(entry3));
    assert!(
        index.total_entries() <= 2,
        "Entry count must remain bounded at or below max_entries"
    );
}

#[test]
fn test_detector_heuristic_causal_threat_analysis() {
    use agentcontrol::detector::LocalDualAgentDetector;
    use serde_json::json;

    // Normal safe trace sequence
    let safe_trace = vec![
        json!({"event_id": "e1", "event_type": "request_received"}),
        json!({"event_id": "e2", "event_type": "llm_completion_clean"}),
    ];
    assert!(LocalDualAgentDetector::evaluate_heuristic_causal_chain(&safe_trace).is_none());

    // Causal chain: prompt injection -> privileged tool execution
    let threat_trace = vec![
        json!({"event_id": "e1", "event_type": "prompt_injection_warning"}),
        json!({"event_id": "e2", "event_type": "privileged_tool_exec"}),
    ];
    let advisory = LocalDualAgentDetector::evaluate_heuristic_causal_chain(&threat_trace);
    assert!(
        advisory.is_some(),
        "Expected causal threat advisory to be triggered"
    );
    let adv = advisory.unwrap();
    assert!(adv.threat_detected);
    assert_eq!(adv.threat_type, "causal_injection_to_tool_chain");
    assert!(adv.confidence >= 0.80);
    assert_eq!(adv.supporting_event_ids, vec!["e1", "e2"]);
}
