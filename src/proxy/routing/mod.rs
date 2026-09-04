//! Pluggable Routing Strategy Engine (AR-2)
//!
//! Provides extensible deployment selection policies (Priority, Lowest Latency,
//! Weighted Random, and Region Affinity) across upstream provider endpoints.

use crate::proxy::provider_router::Deployment;
use rand::Rng;

/// Read-only statistics abstraction over provider endpoints.
pub trait StatsProvider: Send + Sync {
    fn is_healthy(&self, endpoint: &str) -> bool;
    fn avg_latency_ms(&self, endpoint: &str) -> Option<u64>;
}

/// Routing decision output from strategy evaluation.
#[derive(Clone, Debug, PartialEq)]
pub enum RoutingDecision {
    Selected(Deployment),
    NoEligibleDeployment { reason: String },
}

/// Pluggable routing strategy trait contract.
pub trait RoutingStrategy: Send + Sync {
    fn name(&self) -> &'static str;
    fn select(&self, candidates: &[Deployment], stats: &dyn StatsProvider) -> RoutingDecision;
}

// ── 1. Priority Strategy (Default / Backward-Compatible) ─────────────────────

#[derive(Clone, Copy, Debug, Default)]
pub struct PriorityStrategy;

impl RoutingStrategy for PriorityStrategy {
    fn name(&self) -> &'static str {
        "priority"
    }

    fn select(&self, candidates: &[Deployment], stats: &dyn StatsProvider) -> RoutingDecision {
        if candidates.is_empty() {
            return RoutingDecision::NoEligibleDeployment {
                reason: "no deployments registered for model".to_string(),
            };
        }

        let mut eligible: Vec<Deployment> = candidates
            .iter()
            .filter(|d| stats.is_healthy(&d.endpoint_url))
            .cloned()
            .collect();

        // Half-open fallback if all are cooling down
        if eligible.is_empty() {
            eligible = candidates.to_vec();
        }

        eligible.sort_by_key(|d| d.priority);
        match eligible.first() {
            Some(d) => RoutingDecision::Selected(d.clone()),
            None => RoutingDecision::NoEligibleDeployment {
                reason: "all candidate deployments exhausted".to_string(),
            },
        }
    }
}

// ── 2. Lowest Latency Strategy ───────────────────────────────────────────────

#[derive(Clone, Copy, Debug, Default)]
pub struct LowestLatencyStrategy;

impl RoutingStrategy for LowestLatencyStrategy {
    fn name(&self) -> &'static str {
        "lowest_latency"
    }

    fn select(&self, candidates: &[Deployment], stats: &dyn StatsProvider) -> RoutingDecision {
        if candidates.is_empty() {
            return RoutingDecision::NoEligibleDeployment {
                reason: "no deployments registered for model".to_string(),
            };
        }

        let healthy: Vec<&Deployment> = candidates
            .iter()
            .filter(|d| stats.is_healthy(&d.endpoint_url))
            .collect();

        let pool = if healthy.is_empty() {
            candidates.iter().collect::<Vec<_>>()
        } else {
            healthy
        };

        let mut best: Option<(&Deployment, u64)> = None;
        for d in &pool {
            let lat = stats.avg_latency_ms(&d.endpoint_url).unwrap_or(u64::MAX);
            match best {
                None => best = Some((d, lat)),
                Some((_, best_lat)) if lat < best_lat => best = Some((d, lat)),
                Some((best_d, best_lat)) if lat == best_lat && d.priority < best_d.priority => {
                    best = Some((d, lat));
                }
                _ => {}
            }
        }

        match best {
            Some((d, _)) => RoutingDecision::Selected((*d).clone()),
            None => RoutingDecision::NoEligibleDeployment {
                reason: "failed to evaluate endpoint latencies".to_string(),
            },
        }
    }
}

// ── 3. Weighted Random Strategy ──────────────────────────────────────────────

#[derive(Clone, Copy, Debug, Default)]
pub struct WeightedRandomStrategy;

impl RoutingStrategy for WeightedRandomStrategy {
    fn name(&self) -> &'static str {
        "weighted_random"
    }

    fn select(&self, candidates: &[Deployment], stats: &dyn StatsProvider) -> RoutingDecision {
        if candidates.is_empty() {
            return RoutingDecision::NoEligibleDeployment {
                reason: "no deployments registered for model".to_string(),
            };
        }

        let healthy: Vec<&Deployment> = candidates
            .iter()
            .filter(|d| stats.is_healthy(&d.endpoint_url))
            .collect();

        let pool = if healthy.is_empty() {
            candidates.iter().collect::<Vec<_>>()
        } else {
            healthy
        };

        let total_weight: u32 = pool.iter().map(|d| if d.weight == 0 { 1 } else { d.weight }).sum();
        if total_weight == 0 {
            return RoutingDecision::Selected((*pool[0]).clone());
        }

        let mut rng = rand::thread_rng();
        let target = rng.gen_range(0..total_weight);
        let mut accumulated = 0;

        for d in &pool {
            let w = if d.weight == 0 { 1 } else { d.weight };
            accumulated += w;
            if accumulated > target {
                return RoutingDecision::Selected((*d).clone());
            }
        }

        RoutingDecision::Selected((*pool.last().unwrap()).clone())
    }
}

// ── 4. Region Affinity Strategy (Compliance & Data Residency) ────────────────

#[derive(Clone, Debug)]
pub struct RegionAffinityStrategy {
    pub allowed_regions: Vec<String>,
}

impl RegionAffinityStrategy {
    pub fn new(allowed_regions: Vec<String>) -> Self {
        Self {
            allowed_regions: allowed_regions.into_iter().map(|r| r.to_lowercase()).collect(),
        }
    }

    fn is_region_allowed(&self, d: &Deployment) -> bool {
        if self.allowed_regions.is_empty() {
            return true;
        }

        let id_lower = d.id.to_lowercase();
        let url_lower = d.endpoint_url.to_lowercase();

        self.allowed_regions
            .iter()
            .any(|r| id_lower.contains(r) || url_lower.contains(r))
    }
}

impl RoutingStrategy for RegionAffinityStrategy {
    fn name(&self) -> &'static str {
        "region_affinity"
    }

    fn select(&self, candidates: &[Deployment], stats: &dyn StatsProvider) -> RoutingDecision {
        if candidates.is_empty() {
            return RoutingDecision::NoEligibleDeployment {
                reason: "no deployments registered for model".to_string(),
            };
        }

        // Hard filter on compliance / data-residency boundary
        let regional: Vec<Deployment> = candidates
            .iter()
            .filter(|d| self.is_region_allowed(d))
            .cloned()
            .collect();

        if regional.is_empty() {
            return RoutingDecision::NoEligibleDeployment {
                reason: format!(
                    "Region residency constraint violation: no deployment matches allowed regions {:?}",
                    self.allowed_regions
                ),
            };
        }

        // Apply health and priority within compliant region candidates
        let mut healthy: Vec<Deployment> = regional
            .iter()
            .filter(|d| stats.is_healthy(&d.endpoint_url))
            .cloned()
            .collect();

        if healthy.is_empty() {
            // Fail closed: do NOT silently spill over to non-compliant regions
            return RoutingDecision::NoEligibleDeployment {
                reason: format!(
                    "All compliant deployments in regions {:?} are currently unhealthy/cooling down",
                    self.allowed_regions
                ),
            };
        }

        healthy.sort_by_key(|d| d.priority);
        RoutingDecision::Selected(healthy[0].clone())
    }
}

/// Strategy factory resolving strategy by name.
pub fn get_strategy(name: &str, allowed_regions: Option<Vec<String>>) -> Box<dyn RoutingStrategy> {
    match name.to_lowercase().as_str() {
        "lowest_latency" | "latency" => Box::new(LowestLatencyStrategy),
        "weighted_random" | "weighted" => Box::new(WeightedRandomStrategy),
        "region_affinity" | "regional" => {
            Box::new(RegionAffinityStrategy::new(allowed_regions.unwrap_or_default()))
        }
        _ => Box::new(PriorityStrategy),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockStats {
        healthy: Vec<String>,
        latencies: Vec<(String, u64)>,
    }

    impl StatsProvider for MockStats {
        fn is_healthy(&self, endpoint: &str) -> bool {
            self.healthy.contains(&endpoint.to_string())
        }

        fn avg_latency_ms(&self, endpoint: &str) -> Option<u64> {
            self.latencies
                .iter()
                .find(|(ep, _)| ep == endpoint)
                .map(|(_, l)| *l)
        }
    }

    fn sample_deployments() -> Vec<Deployment> {
        vec![
            Deployment {
                id: "dep-us-east-1".to_string(),
                provider: "openai".to_string(),
                model_name: "gpt-4o".to_string(),
                endpoint_url: "https://us-east-1.api.openai.com".to_string(),
                credential_ref: None,
                priority: 2,
                weight: 10,
            },
            Deployment {
                id: "dep-eu-west-1".to_string(),
                provider: "openai".to_string(),
                model_name: "gpt-4o".to_string(),
                endpoint_url: "https://eu-west-1.api.openai.com".to_string(),
                credential_ref: None,
                priority: 1,
                weight: 90,
            },
        ]
    }

    #[test]
    fn test_priority_strategy() {
        let deps = sample_deployments();
        let stats = MockStats {
            healthy: vec![
                "https://us-east-1.api.openai.com".to_string(),
                "https://eu-west-1.api.openai.com".to_string(),
            ],
            latencies: vec![],
        };

        let strat = PriorityStrategy;
        let decision = strat.select(&deps, &stats);
        match decision {
            RoutingDecision::Selected(d) => assert_eq!(d.id, "dep-eu-west-1"), // priority 1 < 2
            _ => panic!("expected selection"),
        }
    }

    #[test]
    fn test_lowest_latency_strategy() {
        let deps = sample_deployments();
        let stats = MockStats {
            healthy: vec![
                "https://us-east-1.api.openai.com".to_string(),
                "https://eu-west-1.api.openai.com".to_string(),
            ],
            latencies: vec![
                ("https://us-east-1.api.openai.com".to_string(), 45),
                ("https://eu-west-1.api.openai.com".to_string(), 120),
            ],
        };

        let strat = LowestLatencyStrategy;
        let decision = strat.select(&deps, &stats);
        match decision {
            RoutingDecision::Selected(d) => assert_eq!(d.id, "dep-us-east-1"), // 45ms < 120ms
            _ => panic!("expected selection"),
        }
    }

    #[test]
    fn test_region_affinity_enforcement_fail_closed() {
        let deps = sample_deployments();
        let stats = MockStats {
            healthy: vec![
                "https://us-east-1.api.openai.com".to_string(),
                "https://eu-west-1.api.openai.com".to_string(),
            ],
            latencies: vec![],
        };

        // Allow only GCC / UAE region
        let strat = RegionAffinityStrategy::new(vec!["me-central-1".to_string()]);
        let decision = strat.select(&deps, &stats);
        match decision {
            RoutingDecision::NoEligibleDeployment { reason } => {
                assert!(reason.contains("Region residency constraint violation"));
            }
            _ => panic!("expected fail-closed block for disallowed region"),
        }
    }

    #[test]
    fn test_region_affinity_allowed_region() {
        let deps = sample_deployments();
        let stats = MockStats {
            healthy: vec![
                "https://us-east-1.api.openai.com".to_string(),
                "https://eu-west-1.api.openai.com".to_string(),
            ],
            latencies: vec![],
        };

        let strat = RegionAffinityStrategy::new(vec!["eu-west-1".to_string()]);
        let decision = strat.select(&deps, &stats);
        match decision {
            RoutingDecision::Selected(d) => assert_eq!(d.id, "dep-eu-west-1"),
            _ => panic!("expected selection"),
        }
    }
}
