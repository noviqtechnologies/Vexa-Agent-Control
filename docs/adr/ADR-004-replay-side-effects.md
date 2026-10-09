# ADR-004: Replay Engine and Side-Effect Sandboxing

**Status:** APPROVED (Phase 0a Baseline)  
**Date:** 2026-10-04  
**Author:** Architecture Team  
**Governing Standard:** Architecture & Security Hardening Standard

---

## 1. Context & Problem Statement

Phase 2 introduces offline CI policy simulation and regression testing (`agentcontrol eval`). In replay mode, historical traces are fed through candidate policies to verify that security rules trigger as expected without creating false positives.

A catastrophic failure mode of policy replay is **unintended side effects**: if a replayed trace invokes an external tool (e.g. `rm -rf`, AWS CLI call, Git push, database write) or calls an upstream LLM endpoint incurring financial cost, the test runner creates real-world damage.

---

## 2. Decision: Absolute Side-Effect Isolation Contract

We mandate an absolute structural and architectural ban on external I/O during trace replay and evaluation.

```
┌────────────────────────────────────────────────────────┐
│                   REPLAY HARNESS                       │
│  (Loads content-addressed trace dataset from disk)     │
└──────────────────────────┬─────────────────────────────┘
                           │ Feeds captured requests
                           ▼
┌────────────────────────────────────────────────────────┐
│               POLICY ENGINE UNDER EVAL                 │
│  (Evaluates candidate YAML rules against payload)      │
└────────────┬──────────────────────────────┬────────────┘
             │ Verdict: ALLOW               │ Verdict: DENY
             ▼                              ▼
┌────────────────────────────┐    ┌──────────────────────┐
│  MOCK TOOL EXEC PROVIDER   │    │ RECORD VERDICT MATCH │
│ • Disconnected from OS     │    │ • Compares against   │
│ • Returns recorded output  │    │   expected baseline  │
│ • Panic if network called  │    └──────────────────────┘
└────────────────────────────┘
```

### 2.1 The Sandboxing Rules:
1. **Network Disconnection**: The HTTP transport client is replaced by an in-memory mock client. Any attempt to open a socket to an upstream LLM provider during evaluation panics immediately and fails the test suite.
2. **Tool Execution Sandboxing**: MCP tool calls are resolved strictly against the **recorded output** stored in the trace fixture. Real child processes (`std::process::Command`), shell executions, and file writes are structurally barred by using mock trait implementations.
3. **Deterministic Timestamps & Randomness**: During replay, the system clock is mocked using timestamps from the trace envelope; entropy sources for UUIDs and nonces are deterministic pseudo-random generators seeded by trace hash.
4. **Idempotency Proof**: Replaying the same dataset 1,000 times against the same policy file must produce bit-for-bit identical JSON and JUnit test reports.

---

## 3. Consequences

- **Safety Guarantee**: Running `agentcontrol eval` in pull requests or developer workstations can never mutate host filesystems, invoke cloud resources, or incur LLM provider charges.
- **Limitation**: Dynamic multi-turn branching (where an agent would have generated a different prompt based on an altered tool response) cannot be simulated purely from static traces; this limitation is accepted and documented.
