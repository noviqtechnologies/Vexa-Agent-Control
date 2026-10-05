mod integration {
    /// Phase 1: Approval token leakage prevention (ADR-010 §Amendment-3, Phase 1 Gate 8)
    mod approval_leakage_test;
    mod audit_integration_tests;
    mod audit_migration_test;
    mod backend_integration_suite;
    mod client_matrix_test;
    /// Cross-OS IPC, Permissions & Signal Harness (Table 5.A)
    mod cross_os_harness_test;
    mod dashboard_test;
    mod egress_proxy_tests;
    mod failure_modes_test;
    /// FR-5: Centralized Enforcement Gateway acceptance criteria tests
    mod gateway_fr5;
    mod hitl_state_machine_test;
    mod hitl_webhook_integration_test;
    mod identity_integration_test;
    mod llm_proxy_test;
    /// Local API Security & Scopes (Table 5.A)
    mod local_api_security_test;
    mod mitm_interception_integration_test;
    mod multi_tenant_tests;
    /// Phase 3: Team Collaboration & Central Control — 7-gate exit criteria
    mod phase3_collaboration_test;
    /// Phase 4: Gateway Resiliency & Commercial Operations — 6-gate exit criteria
    mod phase4_resiliency_test;
    mod phase_1_1_tests;
    mod real_client_wrapper_fixture_test;
    mod schema_dispatch_test;
    mod schema_drift_integration_test;
    mod stdio_process_integration_test;
    mod stdio_tests;
    mod trace_canonical_envelope_test;
    mod verify_probe_test;
    mod wrap_integration_test;
}
