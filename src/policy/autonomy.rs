//! Autonomy Budgets and Run Ceilings Engine (PRD FR-034)
//!
//! Enforces deterministic guardrails on agent autonomy: maximum cumulative tool calls,
//! call recursion depth, run duration ceilings, and loop prevention. Escalates to human
//! approval when budgets are exhausted.

use serde::{Deserialize, Serialize};
use std::time::Instant;

/// Configuration for autonomy budgets on a session or task run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutonomyBudget {
    pub max_tool_calls: u32,
    pub max_call_depth: u32,
    pub max_run_duration_secs: u64,
    pub max_consecutive_same_tool: u32,
}

impl Default for AutonomyBudget {
    fn default() -> Self {
        Self {
            max_tool_calls: 50,
            max_call_depth: 5,
            max_run_duration_secs: 600, // 10 minutes
            max_consecutive_same_tool: 5,
        }
    }
}

/// Evaluation verdict for autonomy ceilings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CeilingVerdict {
    Permitted {
        remaining_calls: u32,
    },
    Breached {
        reason_code: &'static str,
        message: String,
        human_approval_required: bool,
    },
}

impl CeilingVerdict {
    pub fn is_permitted(&self) -> bool {
        matches!(self, Self::Permitted { .. })
    }
}

/// Active tracker for autonomy consumption during an agent session.
pub struct AutonomyTracker {
    budget: AutonomyBudget,
    started_at: Instant,
    total_calls: u32,
    current_depth: u32,
    last_tool_name: Option<String>,
    consecutive_tool_count: u32,
}

impl AutonomyTracker {
    pub fn new(budget: AutonomyBudget) -> Self {
        Self {
            budget,
            started_at: Instant::now(),
            total_calls: 0,
            current_depth: 1,
            last_tool_name: None,
            consecutive_tool_count: 0,
        }
    }

    pub fn set_call_depth(&mut self, depth: u32) {
        self.current_depth = depth;
    }

    /// Record a planned tool invocation and evaluate if within budget.
    pub fn check_and_record_call(&mut self, tool_name: &str) -> CeilingVerdict {
        // 1. Check run duration ceiling
        let elapsed_secs = self.started_at.elapsed().as_secs();
        if elapsed_secs >= self.budget.max_run_duration_secs {
            return CeilingVerdict::Breached {
                reason_code: "ERR_AUTONOMY_DURATION_EXCEEDED",
                message: format!(
                    "Agent run duration ceiling exceeded ({}s >= {}s max)",
                    elapsed_secs, self.budget.max_run_duration_secs
                ),
                human_approval_required: true,
            };
        }

        // 2. Check call recursion depth ceiling
        if self.current_depth > self.budget.max_call_depth {
            return CeilingVerdict::Breached {
                reason_code: "ERR_AUTONOMY_DEPTH_EXCEEDED",
                message: format!(
                    "Subagent recursion depth ceiling exceeded (depth {} > {} max)",
                    self.current_depth, self.budget.max_call_depth
                ),
                human_approval_required: true,
            };
        }

        // 3. Check cumulative tool call budget
        if self.total_calls >= self.budget.max_tool_calls {
            return CeilingVerdict::Breached {
                reason_code: "ERR_AUTONOMY_CALL_BUDGET_EXHAUSTED",
                message: format!(
                    "Agent tool call budget exhausted ({} calls reached)",
                    self.budget.max_tool_calls
                ),
                human_approval_required: true,
            };
        }

        // 4. Check consecutive same-tool loop counter
        if let Some(ref last) = self.last_tool_name {
            if last == tool_name {
                self.consecutive_tool_count += 1;
                if self.consecutive_tool_count > self.budget.max_consecutive_same_tool {
                    return CeilingVerdict::Breached {
                        reason_code: "ERR_AUTONOMY_LOOP_DETECTED",
                        message: format!(
                            "Potential infinite loop: tool '{}' invoked {} consecutive times",
                            tool_name, self.consecutive_tool_count
                        ),
                        human_approval_required: true,
                    };
                }
            } else {
                self.consecutive_tool_count = 1;
                self.last_tool_name = Some(tool_name.to_string());
            }
        } else {
            self.consecutive_tool_count = 1;
            self.last_tool_name = Some(tool_name.to_string());
        }

        self.total_calls += 1;
        let remaining = self.budget.max_tool_calls - self.total_calls;

        CeilingVerdict::Permitted {
            remaining_calls: remaining,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_call_budget_enforcement() {
        let budget = AutonomyBudget {
            max_tool_calls: 3,
            max_call_depth: 3,
            max_run_duration_secs: 60,
            max_consecutive_same_tool: 10,
        };
        let mut tracker = AutonomyTracker::new(budget);

        assert!(tracker.check_and_record_call("read_file").is_permitted());
        assert!(tracker.check_and_record_call("list_dir").is_permitted());
        assert!(tracker.check_and_record_call("read_file").is_permitted());

        // 4th call exceeds budget
        let verdict = tracker.check_and_record_call("execute_cmd");
        assert!(!verdict.is_permitted());
        if let CeilingVerdict::Breached { reason_code, .. } = verdict {
            assert_eq!(reason_code, "ERR_AUTONOMY_CALL_BUDGET_EXHAUSTED");
        }
    }

    #[test]
    fn test_loop_detection_enforcement() {
        let budget = AutonomyBudget {
            max_tool_calls: 50,
            max_call_depth: 5,
            max_run_duration_secs: 60,
            max_consecutive_same_tool: 2,
        };
        let mut tracker = AutonomyTracker::new(budget);

        assert!(tracker.check_and_record_call("retry_probe").is_permitted());
        assert!(tracker.check_and_record_call("retry_probe").is_permitted());

        // 3rd consecutive call triggers loop blocker
        let verdict = tracker.check_and_record_call("retry_probe");
        assert!(!verdict.is_permitted());
        if let CeilingVerdict::Breached { reason_code, .. } = verdict {
            assert_eq!(reason_code, "ERR_AUTONOMY_LOOP_DETECTED");
        }
    }
}
