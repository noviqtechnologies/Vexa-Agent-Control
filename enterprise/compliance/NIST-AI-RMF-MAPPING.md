# NIST AI Risk Management Framework (AI RMF 1.0 / NIST SP 1270)
## Vexa Agent Control Enterprise Evidence & Control Mapping

This document provides Chief Information Security Officers (CISOs), Lead AI Security Engineers, and GRC auditors with a technical crosswalk mapping **Vexa Agent Control** enforcement mechanisms directly to the **NIST AI RMF 1.0 Core Functions**: GOVERN, MAP, MEASURE, and MANAGE.

---

### 1. GOVERN (GV) Function

| Subcategory | NIST AI RMF Requirement | Vexa Agent Control Technical Implementation | Evidence Artifact |
|---|---|---|---|
| **GV-1.1** | Legal and regulatory requirements involving AI are identified and tracked. | Enforces central policy rulesets on Model Context Protocol (MCP) tool execution, blocking unauthorized data transmission. | `agentcontrol-policy.yaml`, Central Policy Engine |
| **GV-1.2** | Trustworthiness characteristics are integrated into policies, processes, and procedures. | Safe Mode v1 default-deny rules, deterministic schema validation, and multi-turn session taint tracking. | `src/policy/safe_mode.rs`, `src/policy/taint.rs` |
| **GV-2.1** | Roles and responsibilities for AI governance are assigned and documented. | Role-Based Access Control (RBAC) in Control Hub separating CISO Policy Admins, Security Auditors, and Devs. | `control-plane/api/internal/middleware/rbac.go` |
| **GV-4.2** | Robust mechanisms for accountability and auditability of AI systems exist. | Cryptographic HMAC-SHA256 audit chaining with fail-closed fsync writes, generating tamper-evident event trails. | `audit.jsonl`, `src/audit/logger.rs` |

---

### 2. MAP (MP) Function

| Subcategory | NIST AI RMF Requirement | Vexa Agent Control Technical Implementation | Evidence Artifact |
|---|---|---|---|
| **MP-2.3** | Scientific understanding and risk profiles of model tasks are established. | Per-assistant profiling (`agentcontrol status`, `agentcontrol doctor`) identifying uncovered egress surfaces. | `docs/security/enforcement-boundary.md` |
| **MP-4.1** | AI system components and external data inputs/outputs are inventoried. | Real-time discovery and cataloging of all connected MCP tool servers, endpoints, and LLM providers. | `control-plane/api/internal/store/` |
| **MP-5.1** | Likelihood and impact of identified AI risks are evaluated. | Advisory causal threat analyzer identifying compound prompt injection → tool execution chains. | `src/detector/mod.rs` |

---

### 3. MEASURE (MS) Function

| Subcategory | NIST AI RMF Requirement | Vexa Agent Control Technical Implementation | Evidence Artifact |
|---|---|---|---|
| **MS-2.3** | AI system performance, safety, and trustworthiness are tracked over time. | Real-time spend tracking, token usage quotas, and anomaly detection per user/workstation/team. | `src/spend/`, `pricing.toml` |
| **MS-2.5** | AI system vulnerabilities and failure modes are routinely evaluated. | Automated Gate 0–4 verification test suites (fuzzing, prompt injection corpora, bypass tests). | `tests/integration/` |
| **MS-2.8** | Risk measurement data is documented and shared with decision makers. | Automated export of audit dossiers and SIEM event streams (Splunk HEC, Datadog Logs API). | `audit.jsonl`, SIEM forwarder |

---

### 4. MANAGE (MN) Function

| Subcategory | NIST AI RMF Requirement | Vexa Agent Control Technical Implementation | Evidence Artifact |
|---|---|---|---|
| **MN-1.1** | Identified AI risks are prioritized and treated based on organizational tolerance. | 3-stage phased rollout: OBSERVE (Shadow) → GUARD (Soft Warning) → ENFORCE (Hard Block). | Policy `enforcement_mode: shadow\|guard\|enforce` |
| **MN-1.3** | Mechanisms to prevent, detect, and mitigate prompt injection attacks exist. | 6-pass normalized regex and heuristic prompt injection scanning on incoming context and tool returns. | `src/policy/injection.rs` |
| **MN-2.2** | Access control mechanisms are applied to AI components and sensitive data. | Broker-Held Credential Custody: developers never hold raw API keys; virtual keys route through PEP. | `control-plane/api/internal/broker/` |
| **MN-4.1** | Plans for incident response and rollback of AI deployments are in place. | Emergency Kill Switch (`agentcontrol kill`) and instant policy revocation via SSE delta push. | `src/policy/revocation.rs` |

---

### Audit Verification Command

To verify compliance posture and export an attested NIST AI RMF evidence package:
```bash
agentcontrol verify --standard nist-ai-rmf
```
