//! FR-402: Multi-Tenant Policy Sharding
//! Resolves project-scoped (`agent_project_id`) and task-scoped (`agent_task_id`)
//! policy overrides in sub-millisecond hot-path execution.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, PartialEq)]
pub struct TaskPolicy {
    pub task_id: String,
    pub project_id: String,
    pub allowed_tools: Vec<String>,
    pub shadow_mode_override: Option<bool>,
}

#[derive(Clone, Default)]
pub struct PolicyShardResolver {
    shards: Arc<RwLock<HashMap<String, TaskPolicy>>>,
}

impl PolicyShardResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_task_policy(&self, policy: TaskPolicy) {
        let mut map = self.shards.write().unwrap();
        map.insert(policy.task_id.clone(), policy);
    }

    /// Resolves policy override by matching headers `X-AgentWall-Task-ID` or `X-AgentWall-Project-ID`.
    pub fn resolve(&self, task_id: Option<&str>, project_id: Option<&str>) -> Option<TaskPolicy> {
        let map = self.shards.read().unwrap();
        if let Some(tid) = task_id {
            if let Some(policy) = map.get(tid) {
                return Some(policy.clone());
            }
        }
        if let Some(pid) = project_id {
            for policy in map.values() {
                if policy.project_id == pid {
                    return Some(policy.clone());
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shard_resolution() {
        let resolver = PolicyShardResolver::new();
        resolver.register_task_policy(TaskPolicy {
            task_id: "task-99".to_string(),
            project_id: "proj-alpha".to_string(),
            allowed_tools: vec!["git_commit".to_string()],
            shadow_mode_override: Some(true),
        });

        let found = resolver.resolve(Some("task-99"), None);
        assert!(found.is_some());
        assert_eq!(found.unwrap().project_id, "proj-alpha");

        let not_found = resolver.resolve(Some("task-unknown"), None);
        assert!(not_found.is_none());
    }
}
