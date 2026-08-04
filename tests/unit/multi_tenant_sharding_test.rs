//! Unit test suite for FR-402 / NFR-304: Multi-Tenant Policy Sharding

use agentwall::policy::sharding::{PolicyShardResolver, TaskPolicy};

#[test]
fn test_multi_tenant_sharded_policy_resolution() {
    let resolver = PolicyShardResolver::new();
    let task_pol = TaskPolicy {
        task_id: "task-fin-808".to_string(),
        project_id: "project-finance".to_string(),
        allowed_tools: vec!["read_report".to_string()],
        shadow_mode_override: Some(false),
    };
    resolver.register_task_policy(task_pol);

    let match_task = resolver.resolve(Some("task-fin-808"), None);
    assert!(match_task.is_some());
    assert_eq!(match_task.unwrap().project_id, "project-finance");

    let match_project = resolver.resolve(None, Some("project-finance"));
    assert!(match_project.is_some());
    assert_eq!(match_project.unwrap().task_id, "task-fin-808");
}
