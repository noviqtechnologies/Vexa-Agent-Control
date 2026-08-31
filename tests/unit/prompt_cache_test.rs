use agentcontrol::proxy::prompt_cache::PromptCache;
use bytes::Bytes;
use std::time::Duration;

#[test]
fn test_prompt_cache_hit_and_miss() {
    let cache = PromptCache::new(100);
    let key = PromptCache::compute_key("tenant-1", "key-1", "gpt-4o", "Hello world");

    // Initially miss
    assert!(cache.get(&key).is_none());

    // Insert entry
    let body = Bytes::from("{\"choices\":[{\"message\":{\"content\":\"Hello there!\"}}]}");
    cache.insert(
        key,
        body.clone(),
        "application/json".to_string(),
        Duration::from_secs(60),
        "gpt-4o".to_string(),
    );

    // Now hit
    let hit = cache.get(&key);
    assert!(hit.is_some());
    let entry = hit.unwrap();
    assert_eq!(entry.response_body, body);
    assert_eq!(entry.model, "gpt-4o");

    let (hits, misses, evictions, count) = cache.stats();
    assert_eq!(hits, 1);
    assert_eq!(misses, 1);
    assert_eq!(evictions, 0);
    assert_eq!(count, 1);
}

#[test]
fn test_prompt_cache_tenant_isolation() {
    let cache = PromptCache::new(100);
    let prompt = "Explain quantum computing";

    let key_tenant_a = PromptCache::compute_key("tenant-A", "key-A", "gpt-4o", prompt);
    let key_tenant_b = PromptCache::compute_key("tenant-B", "key-B", "gpt-4o", prompt);

    assert_ne!(key_tenant_a, key_tenant_b);

    cache.insert(
        key_tenant_a,
        Bytes::from("Tenant A secret response"),
        "application/json".to_string(),
        Duration::from_secs(60),
        "gpt-4o".to_string(),
    );

    // Tenant B must get a cache MISS for identical prompt
    assert!(cache.get(&key_tenant_b).is_none());
    assert!(cache.get(&key_tenant_a).is_some());
}
