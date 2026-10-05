# ADR-008: Policy Compatibility, Versioning, Signing, and Rollback

**Status:** APPROVED (Phase 0a Baseline)  
**Date:** 2026-10-04  
**Author:** Architecture Team  
**Governing Standard:** [Plan Review Feedback v4](file:///C:/Users/wasim/.gemini/antigravity-ide/brain/9469605e-81c2-40a5-9567-198d8ebbf4c0/plan_review_feedback_v4.md)

---

## 1. Context & Problem Statement

Policies in Agent Control govern critical security boundaries: tool allowlists, path restrictions, spend caps, and DLP rules. 
In enterprise environments, policies are authored centrally, distributed dynamically, and updated frequently. Without strict schema versioning, cryptographic signing, and rollback mechanisms:
- An invalid policy push could brick active agent workstations.
- An attacker with local access could tamper with policy files to bypass rules.
- Existing policy files (`policy.example.yaml`, `agentcontrol-policy.yaml`) could fail to parse after daemon updates.

---

## 2. Decision: Versioned Policy Lifecycle & Invariant Compatibility

```
┌────────────────────────────────────────────────────────┐
│               POLICY DISTRIBUTION LIFECYCLE            │
│                                                        │
│  Central Hub (Ed25519 Signing) ──► WebSocket / SSE     │
│                                           │            │
│                                           ▼            │
│   Workstation: 1. Verify Ed25519 Signature             │
│                2. Dry-Run Lint & Schema Validation     │
│                3. Atomic Hot-Reload (Pointer Swap)     │
│                4. Fallback Snapshot on Error           │
└────────────────────────────────────────────────────────┘
```

### 2.1 Backward Compatibility Invariant
- **Existing YAML Schema Unchanged**: Existing policy YAML files without version fields are parsed under **Policy Schema v1** default rules.
- All existing rule declarations (`tools`, `filesystem`, `egress`, `dlp`, `injection`, `spend`) retain their exact semantics.
- New configurations (e.g. `trace_sampling`, `hitl_recovery_mode`, `threat_intel_url`) are strictly optional with safe, backward-compatible defaults.

### 2.2 Schema Versioning (`policy_version`)
- Explicit header added for modern policies:
  ```yaml
  schema_version: "2.0"
  policy_id: "corp-engineering-baseline"
  policy_revision: 42
  signature: "ed25519:3a8f..."
  ```
- **Policy Hash**: Every loaded policy computes a canonical SHA-256 digest (`policy_hash`). This hash is recorded on every audit entry and trace span, enabling auditors to prove which exact policy version evaluated a tool call.

### 2.3 Atomic Hot-Reload & Rollback Contract
1. **Dynamic Reload**: Daemon listens for `SIGHUP` (POSIX) or `POST /api/v1/policy/reload` (authenticated REST).
2. **Atomic Verification**:
   - The candidate policy is parsed into memory and validated against active tool schemas.
   - If parsing or signature verification fails, the candidate is rejected, an alert is emitted, and the **active policy continues running without interruption**.
3. **Rollback Snapshot**:
   - The daemon maintains `current_policy.yaml` and `rollback_policy.yaml`. If the daemon crashes within 60 seconds of a policy reload, it automatically reverts to `rollback_policy.yaml` upon restart.

---

## 3. Consequences

- **Zero-Downtime Updates**: Developers and CI agents experience zero dropped connections during policy updates.
- **Audit Verifiability**: Policy versions are cryptographically anchored to audit trail lines.
