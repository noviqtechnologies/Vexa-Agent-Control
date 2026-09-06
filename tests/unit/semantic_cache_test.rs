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
    let response_bytes = Bytes::from("{\"choices\":[{\"message\":{\"content\":\"A Pod is the smallest deployable unit...\"}}]}");

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
    assert_eq!(stats["gateway_cache"]["tokens_saved"]["total"].as_u64().unwrap(), 470);
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
    assert_eq!(stats["gateway_cache"]["tokens_saved"]["total"].as_u64().unwrap(), 100);
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
    assert!(hit.is_none(), "Unrelated prompt must not match semantic cache");

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
    let authorized_hit = cache.lookup(&client, "tenant-alpha", "gpt-4o", prompt).await;
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
    assert_eq!(stats["gateway_cache"]["tokens_saved"]["total"].as_u64().unwrap(), 300);
    assert!(
        stats["gateway_cache"]["cost_saved_usd"].as_f64().unwrap() > 0.0,
        "Gateway avoided cost must be positive"
    );
    assert_eq!(stats["gateway_cache"]["semantic_hits"].as_u64().unwrap(), 1);

    // Check Provider metrics
    assert_eq!(stats["provider_cache"]["cached_tokens"].as_u64().unwrap(), 1000);
    assert!(stats["provider_cache"]["discount_usd"].as_f64().unwrap() > 0.0);

    // Check Combined Net Economic Value
    let gw_cost = stats["gateway_cache"]["cost_saved_usd"].as_f64().unwrap();
    let prov_disc = stats["provider_cache"]["discount_usd"].as_f64().unwrap();
    let total_sav = stats["comparative_summary"]["total_savings_usd"].as_f64().unwrap();
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
