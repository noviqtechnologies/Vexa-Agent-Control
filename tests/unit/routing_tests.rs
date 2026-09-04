use agentcontrol::proxy::provider_router::{Deployment, ProviderRouter};
use agentcontrol::proxy::routing::{
    get_strategy, LowestLatencyStrategy, RegionAffinityStrategy,
    RoutingDecision, WeightedRandomStrategy,
};
use std::time::Duration;

fn make_deployments() -> Vec<Deployment> {
    vec![
        Deployment {
            id: "dep-primary-us".to_string(),
            provider: "openai".to_string(),
            model_name: "gpt-4o".to_string(),
            endpoint_url: "https://api.openai.com/v1".to_string(),
            credential_ref: None,
            priority: 1,
            weight: 80,
        },
        Deployment {
            id: "dep-secondary-eu".to_string(),
            provider: "openai".to_string(),
            model_name: "gpt-4o".to_string(),
            endpoint_url: "https://eu.api.openai.com/v1".to_string(),
            credential_ref: None,
            priority: 2,
            weight: 20,
        },
    ]
}

#[test]
fn test_provider_router_select_deployment_backward_compatibility() {
    let router = ProviderRouter::default();
    let deps = make_deployments();
    router.register_deployments("gpt-4o", deps);

    // Default select_deployment uses PriorityStrategy
    let selected = router.select_deployment("gpt-4o").expect("should select deployment");
    assert_eq!(selected.id, "dep-primary-us");
}

#[test]
fn test_provider_router_failover_when_unhealthy() {
    let router = ProviderRouter::default();
    let deps = make_deployments();
    router.register_deployments("gpt-4o", deps);

    // Trip default failure threshold on primary (5 failures)
    for _ in 0..5 {
        router.record_failure("https://api.openai.com/v1");
    }
    assert!(!router.is_healthy("https://api.openai.com/v1"));

    // Router should automatically failover to secondary EU deployment
    let selected = router.select_deployment("gpt-4o").expect("should failover");
    assert_eq!(selected.id, "dep-secondary-eu");
}

#[test]
fn test_provider_router_with_lowest_latency_strategy() {
    let router = ProviderRouter::default();
    let deps = make_deployments();
    router.register_deployments("gpt-4o", deps);

    // Primary has 150ms latency, secondary has 35ms latency
    router.record_success("https://api.openai.com/v1", Duration::from_millis(150));
    router.record_success("https://eu.api.openai.com/v1", Duration::from_millis(35));

    let strat = LowestLatencyStrategy;
    let selected = router
        .select_deployment_with_strategy("gpt-4o", &strat)
        .expect("should select lowest latency");
    assert_eq!(selected.id, "dep-secondary-eu");
}

#[test]
fn test_provider_router_with_weighted_strategy() {
    let router = ProviderRouter::default();
    let deps = make_deployments();
    router.register_deployments("gpt-4o", deps);

    let strat = WeightedRandomStrategy;
    // Run multiple selections: both valid IDs should be returned
    let mut selected_ids = std::collections::HashSet::new();
    for _ in 0..50 {
        let sel = router
            .select_deployment_with_strategy("gpt-4o", &strat)
            .expect("should select");
        selected_ids.insert(sel.id);
    }
    assert!(selected_ids.contains("dep-primary-us"));
}

#[test]
fn test_region_affinity_enforcement_in_router() {
    let router = ProviderRouter::default();
    let deps = make_deployments();
    router.register_deployments("gpt-4o", deps);

    // Require EU data residency
    let eu_strat = RegionAffinityStrategy::new(vec!["eu".to_string()]);
    let sel = router
        .select_deployment_with_strategy("gpt-4o", &eu_strat)
        .expect("should select EU deployment");
    assert_eq!(sel.id, "dep-secondary-eu");

    // Require non-existent region -> fail-closed
    let asia_strat = RegionAffinityStrategy::new(vec!["ap-southeast-1".to_string()]);
    let decision = router.select_deployment_decision("gpt-4o", &asia_strat);
    match decision {
        RoutingDecision::NoEligibleDeployment { reason } => {
            assert!(reason.contains("Region residency constraint violation"));
        }
        _ => panic!("expected region violation error"),
    }
}

#[test]
fn test_routing_strategy_factory() {
    let s1 = get_strategy("lowest_latency", None);
    assert_eq!(s1.name(), "lowest_latency");

    let s2 = get_strategy("latency", None);
    assert_eq!(s2.name(), "lowest_latency");

    let s3 = get_strategy("weighted_random", None);
    assert_eq!(s3.name(), "weighted_random");

    let s4 = get_strategy("region_affinity", Some(vec!["eu-west-1".to_string()]));
    assert_eq!(s4.name(), "region_affinity");

    let s5 = get_strategy("unknown_strategy", None);
    assert_eq!(s5.name(), "priority");
}
