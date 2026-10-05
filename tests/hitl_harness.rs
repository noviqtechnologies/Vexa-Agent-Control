// HITL CAS & Crash Recovery Harness — entry point
// Run with: cargo test --test hitl_harness
//
// This harness is separate from the integration suite so it can be run independently
// as a Phase 0b exit-gate check. See tests/harness/hitl_harness.rs for all scenarios.

mod harness {
    mod hitl_harness;
}
