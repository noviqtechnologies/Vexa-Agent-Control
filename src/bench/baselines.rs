//! Internal Policy Regression Baselines for `agentcontrol bench --compare-baselines`
//!
//! Note: Baselines represent internal security policy regression profiles on synthetic task suites,
//! not competitive product evaluations.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineScore {
    pub system_name: &'static str,
    pub score: f64,
    pub tasks_blocked: usize,
    pub total_tasks: usize,
}

pub struct BaselineComparator;

impl BaselineComparator {
    pub fn get_baselines(total_tasks: usize) -> Vec<BaselineScore> {
        let count = if total_tasks == 0 { 303 } else { total_tasks };
        vec![
            BaselineScore {
                system_name: "Strict Enforce Profile (Internal Target)",
                score: 95.0,
                tasks_blocked: (count as f64 * 0.950) as usize,
                total_tasks: count,
            },
            BaselineScore {
                system_name: "Default Safe Mode Profile (Active Rules)",
                score: 90.0,
                tasks_blocked: (count as f64 * 0.900) as usize,
                total_tasks: count,
            },
            BaselineScore {
                system_name: "Permissive / Shadow Observation Profile",
                score: 70.0,
                tasks_blocked: (count as f64 * 0.700) as usize,
                total_tasks: count,
            },
            BaselineScore {
                system_name: "Unprotected Baseline (No Gateway)",
                score: 0.0,
                tasks_blocked: 0,
                total_tasks: count,
            },
        ]
    }
}
