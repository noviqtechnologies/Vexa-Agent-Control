mod integration {
    mod audit_integration_tests;
    mod backend_integration_suite;
    mod dashboard_test;
    mod egress_proxy_tests;
    /// FR-5: Centralized Enforcement Gateway acceptance criteria tests
    mod gateway_fr5;
    mod identity_integration_test;
    mod llm_proxy_test;
    mod mitm_interception_integration_test;
    mod multi_tenant_tests;
    mod phase_1_1_tests;
    mod promotion_tests;
    mod proxy_test;
    mod real_client_wrapper_fixture_test;
    mod schema_drift_integration_test;
    mod stdio_process_integration_test;
    mod stdio_tests;
    mod verify_probe_test;
    mod wrap_integration_test;
}
