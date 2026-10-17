# Failure-Mode & Operational Recovery Playbook
## Vexa AgentControl — Operational Guide for Engineering & SecOps

**Document Version:** 1.0  
**PRD Reference:** `PRD/pending/Vexa_AgentControl_Enforcement_Assurance_PRD.md` Section 6, FR-010  
**Authoritative Positioning:**  
> *"Vexa helps engineering teams govern the AI-agent traffic they route through it, with centrally managed policies and verifiable, per-surface enforcement evidence."*

---

## 1. Operating Principles During Outages

Security gateways must be resilient. When an infrastructure component fails (e.g. cloud hub outage, network partition, or corrupted configuration), Vexa operates according to clear, mode-specific contracts:

- **Local Developer Mode:** Fails open to preserve developer workflow. If the local proxy crashes, developers receive terminal alerts and can continue unblocked.
- **Team Managed Mode:** Preserves last-known-good (LKG) signed policy bundles locally. If the hub is offline, workstations continue enforcement seamlessly up to `max_policy_age_secs` (default 72 hours). Rejects invalid signatures or tampered bundles.
- **Mandatory Boundary Mode:** Fails closed. If policy freshness expires or tamper is detected, outbound LLM requests are halted until verified trust is restored.

---

## 2. Fault Scenarios & Automated System Behavior

| Failure Event | System State Reported | Automatic Action | Manual Intervention / Recovery |
|---|---|---|---|
| **Central Hub Offline** | `DEGRADED (OFFLINE_CACHE)` | Daemon switches to cached signed policy; SSE reconnection retries with exponential backoff. | None needed if hub recovers within 72 hours. To extend offline window, push emergency bundle via MDM. |
| **Policy Bundle Expired** | `POLICY_EXPIRED` | In Team mode: logs warning; in Mandatory mode: halts LLM traffic. | Admin publishes updated policy revision to Central Hub. |
| **Invalid Signature on Update** | `DEGRADED (SIGNATURE_REJECTED)` | Update rejected immediately. Active policy remains at last-known-good revision. | Verify signing key in Central Hub matches public key in workstation keyring. |
| **Local Proxy Stopped** | `UNKNOWN_UNHEALTHY` | IDE tool calls receive connection refused on `127.0.0.1:18080`. | Run `agentcontrol service start` or `agentcontrol repair`. |
| **Audit Log Disk Full** | `DEGRADED (AUDIT_STORAGE_FULL)` | In-memory ring buffer queues up to 1,000 events. Oldest dropped if buffer fills. | Free workstation disk space; logs flush automatically. |
| **Direct Egress Bypass** | `BYPASS_POSSIBLE` | Disclosed in `agentcontrol status`. | Enable network egress firewall rules blocking direct access to AI provider endpoints. |

---

## 3. Incident Recovery Procedures

### Scenario A: Rollback a Malformed Policy Fleet-Wide
If a newly promoted policy revision causes unintended tool blocks across engineering teams:
1. Open the Vexa Central Console or CLI:
   ```bash
   agentcontrol policy rollback --policy-id default --target-revision <last_known_good_revision>
   ```
2. The Central Hub signs a rollback bundle using the authoritative signing key.
3. Connected workstations hot-reload the signed rollback bundle via SSE in <500ms.
4. Verify convergence:
   ```bash
   agentcontrol fleet convergence --policy-id default
   ```

### Scenario B: Emergency Break-Glass (Workstation Unresponsive)
If a developer workstation is blocked during an emergency outage and cannot reach the hub:
1. Revert IDE configurations to direct mode:
   ```bash
   agentcontrol unwrap --all
   ```
2. Terminate the local service:
   ```bash
   agentcontrol service stop
   ```
3. To restore governance once the issue is resolved:
   ```bash
   agentcontrol wrap --all
   agentcontrol service start
   agentcontrol verify
   ```
