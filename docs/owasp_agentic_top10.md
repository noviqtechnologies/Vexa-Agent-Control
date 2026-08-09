# OWASP Top 10 for Agentic Applications (ASI 2026) — Security Architecture & Compliance Mapping

> **Document Version:** 1.0  
> **Last Reviewed:** 2026-08-09  
> **Standard:** [OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)  
> **Audience:** Security Architects, GRC Officers, SecOps, DevSecOps Evaluators

---

## Executive Summary

Autonomous AI agents introduce distinct security vulnerabilities that cannot be mitigated by traditional network firewalls or probabilistic prompt-level instructions. The **OWASP Agentic Security Initiative (ASI 2026)** defines the 10 primary threat vectors facing autonomous agent ecosystems.

**Vexa AgentWall** implements deterministic, out-of-process runtime security at the network and transport boundary (MCP stdio, HTTP, HTTPS, WebSockets). This document provides an honest, evidence-backed mapping of AgentWall's controls against all 10 OWASP Agentic risks.

---

## Coverage Matrix

| Risk ID | Vulnerability Title | AgentWall Status | Primary Enforcement Component | Evidence in Codebase |
|---|---|:---:|---|---|
| **ASI01** | **Agent Goal Hijack** | ✅ **Full** | 6-Pass Normalizer & 9 Prompt Injection Scanners | [`src/policy/injection.rs`](../src/policy/injection.rs), [`src/policy/safe_mode.rs`](../src/policy/safe_mode.rs) |
| **ASI02** | **Tool Misuse and Exploitation** | ✅ **Full** | Default-Deny Policy Engine & JSON Parameter Schema Validator | [`src/policy/engine.rs`](../src/policy/engine.rs), [`src/policy/schema.rs`](../src/policy/schema.rs) |
| **ASI03** | **Identity and Privilege Abuse** | ✅ **Full** | OIDC JWT Validation, Group Claim Binding, & Credential Scopes | [`src/policy/identity.rs`](../src/policy/identity.rs), [`src/policy/credential_scope.rs`](../src/policy/credential_scope.rs) |
| **ASI04** | **Agentic Supply Chain Vulnerabilities** | ✅ **Full** | MCP Security Scoring Engine & Cross-Session Schema-Drift Detection | [`src/policy/mcp_score.rs`](../src/policy/mcp_score.rs), [`src/policy/schema_drift.rs`](../src/policy/schema_drift.rs) |
| **ASI05** | **Unexpected Code Execution (RCE)** | ✅ **Full** | Safe Mode Command Blocking & Parameter Traversal Validators | [`src/policy/safe_mode.rs`](../src/policy/safe_mode.rs), [`src/policy/engine.rs`](../src/policy/engine.rs) |
| **ASI06** | **Memory and Context Poisoning** | ⚠️ **Partial** | Response Poisoning Interceptors & HMAC-Chained Audit Trails | [`src/policy/injection.rs`](../src/policy/injection.rs), [`src/audit/logger.rs`](../src/audit/logger.rs) |
| **ASI07** | **Insecure Inter-Agent Communication** | ❌ **Gap (Scoped)** | Org-Local OIDC Identity Boundary (Upstream Federation Required) | [`src/policy/identity.rs`](../src/policy/identity.rs), [`docs/LIMITATIONS.md`](../PRD/LIMITATIONS.md) |
| **ASI08** | **Cascading Agent Failures** | ✅ **Full** | Cycle & Loop Prevention (`PivotError`), Rate Limits, & Spend Caps | [`src/proxy/handler.rs`](../src/proxy/handler.rs), [`src/spend/ledger.rs`](../src/spend/ledger.rs) |
| **ASI09** | **Human-Agent Trust Exploitation** | ✅ **Full** | Real-Time Browser Approval Modals & HMAC-Signed Webhook Escalation | [`src/policy/hitl.rs`](../src/policy/hitl.rs), [`src/proxy/server.rs`](../src/proxy/server.rs) |
| **ASI10** | **Rogue Agents & Unauthorized Egress** | ✅ **Full** | OS Sentry Daemon, PKI Device Enrollment, & Egress Tunneling | [`src/service/`](../src/service), [`src/identity/`](../src/identity), [`src/proxy/egress.rs`](../src/proxy/egress.rs) |

**Official Scorecard:** **8/10 Full Coverage, 1/10 Partial, 1/10 Scoped Gap.**

---

## Detailed Control Mappings & Code Evidence

```
                          ┌──────────────────────────────────────────────┐
                          │   Operating Surface (IDE, Agent, CLI)       │
                          └──────────────────────┬───────────────────────┘
                                                 │
                                                 ▼
┌───────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Vexa AgentWall — Out-of-Process Enforcement Boundary                                              │
│                                                                                                   │
│  ┌───────────────────────┐   ┌───────────────────────┐   ┌───────────────────────┐                │
│  │ 1. Identity (ASI03)   │──►│ 2. Schema (ASI02/04)  │──►│ 3. Injection (ASI01)  │                │
│  │ OIDC JWT & Claims     │   │ Default-Deny & Drift  │   │ 9 Threat Scanners     │                │
│  └───────────────────────┘   └───────────────────────┘   └───────────────────────┘                │
│             │                                                        │                            │
│             ▼                                                        ▼                            │
│  ┌───────────────────────┐   ┌───────────────────────┐   ┌───────────────────────┐                │
│  │ 4. DLP & Secrets      │──►│ 5. Loops (ASI08)      │──►│ 6. HITL (ASI09/10)    │                │
│  │ 2-Pass Regex & Redact │   │ PivotError & Spend    │   │ HMAC Webhook Escalate │                │
│  └───────────────────────┘   └───────────────────────┘   └───────────────────────┘                │
│                                                                      │                            │
└──────────────────────────────────────────────────────────────────────┼────────────────────────────┘
                                                                       │
                                                                       ▼
                                                      ┌─────────────────────────────────┐
                                                      │ Upstream MCP Server / LLM API   │
                                                      └─────────────────────────────────┘
```

---

### ASI01: Agent Goal Hijack
- **Threat:** Adversarial inputs or indirect prompt injections override the agent's core system prompts or alter execution trajectory.
- **AgentWall Mitigation:** Multi-pass normalizer (handling NFKC normalization, Base64 decoding, and leetspeak de-obfuscation) coupled with 9 prompt injection detectors and response poisoning checks.
- **Enforcement Point:** Out-of-process stream inspection prior to tool argument delivery and post-execution response sanitization.
- **Code Evidence:** [`src/policy/injection.rs`](../src/policy/injection.rs), [`src/policy/safe_mode.rs`](../src/policy/safe_mode.rs).
- **Status:** ✅ **Full**

---

### ASI02: Tool Misuse and Exploitation
- **Threat:** Agents invoke dangerous tools or supply malicious parameter payloads (e.g., path traversal, command injection, unconstrained SQL queries).
- **AgentWall Mitigation:** Strict default-deny YAML policy engine, compiled JSON schema parameter bounds, path traversal validators (`..` rejection), and shell character blocking.
- **Enforcement Point:** Intercepts every JSON-RPC `tools/call` on the wire; unknown or non-allowlisted tools are immediately rejected.
- **Code Evidence:** [`src/policy/engine.rs`](../src/policy/engine.rs), [`src/policy/schema.rs`](../src/policy/schema.rs), [`src/policy/loader.rs`](../src/policy/loader.rs).
- **Status:** ✅ **Full**

---

### ASI03: Identity and Privilege Abuse
- **Threat:** Unauthenticated agents or privilege-escalated sessions execute tools outside authorized tenant boundaries.
- **AgentWall Mitigation:** Validates corporate OIDC JWT tokens (Okta, Keycloak, Entra ID), maps JWT group claims dynamically to tool permissions, and enforces per-tool `X-AgentWall-Credential-Scope` constraints.
- **Enforcement Point:** Session token validation on ingress and proxy boundary credential injection (stripping raw keys from agents).
- **Code Evidence:** [`src/policy/identity.rs`](../src/policy/identity.rs), [`src/policy/credential_scope.rs`](../src/policy/credential_scope.rs).
- **Status:** ✅ **Full**

---

### ASI04: Agentic Supply Chain Vulnerabilities
- **Threat:** Compromised third-party MCP servers, plugin updates, or altered tool definitions introduce malicious capabilities post-approval ("rug pulls").
- **AgentWall Mitigation:** 
  1. Static and dynamic manifest scoring via **MCP Security Scoring Engine** (0–100 Vexa Security Score).
  2. Runtime **Cross-Session Schema-Drift Detection** (ADR-011) that hashes tool catalogs and detects schema tampering across sessions.
- **Known Gap:** AgentWall does not generate software bills of materials (SBOMs) for host binary dependencies.
- **Code Evidence:** [`src/policy/mcp_score.rs`](../src/policy/mcp_score.rs), [`src/policy/schema_drift.rs`](../src/policy/schema_drift.rs).
- **Status:** ✅ **Full**

---

### ASI05: Unexpected Code Execution (RCE)
- **Threat:** Agent execution leads to arbitrary shell command invocation, script execution, or binary tampering on the host machine.
- **AgentWall Mitigation:** Safe Mode automatically blocks dangerous commands (`rm -rf`, `curl | bash`, reverse shells, `chmod`), prevents execution in sensitive paths, and protects configuration files with self-healing file locks.
- **Code Evidence:** [`src/policy/safe_mode.rs`](../src/policy/safe_mode.rs), [`src/self_healing.rs`](../src/self_healing.rs).
- **Status:** ✅ **Full**

---

### ASI06: Memory and Context Poisoning
- **Threat:** Malicious data persisted into vector databases, scratchpads, or long-term agent memory corrupts future reasoning cycles.
- **AgentWall Mitigation:** Cryptographically chained HMAC-SHA256 audit logs provide tamper-evident history of all session decisions and responses. Response scanners redact sensitive tokens before context ingestion.
- **Known Gap:** AgentWall does not provide direct application-layer sandboxing for third-party vector databases or agent memory snapshot verification.
- **Code Evidence:** [`src/audit/logger.rs`](../src/audit/logger.rs), [`src/policy/response_scanner.rs`](../src/policy/response_scanner.rs).
- **Status:** ⚠️ **Partial**

---

### ASI07: Insecure Inter-Agent Communication
- **Threat:** Inter-agent messages lack cryptographic provenance, mutual authentication, or capability delegation boundaries across independent organizations.
- **AgentWall Assessment:** AgentWall scopes identity to enterprise OIDC providers within an organization's trust domain. It does not implement decentralized DIDs or cross-organization agent federation protocols.
- **Recommended Mitigation:** Deploy corporate IdP cross-tenant federation (e.g., Entra ID B2B or Okta Org2Org) upstream of AgentWall gateways.
- **Code Evidence:** [`src/policy/identity.rs`](../src/policy/identity.rs), [`docs/LIMITATIONS.md`](../PRD/LIMITATIONS.md).
- **Status:** ❌ **Scoped Gap**

---

### ASI08: Cascading Agent Failures
- **Threat:** Stuck agents trapped in repetitive failure cycles cause runaway LLM token spend, quota exhaustion, or cascading downstream outages.
- **AgentWall Mitigation:** 
  1. Built-in sliding-window cycle detector that returns `PivotError` (-32010) to force the model to attempt alternative strategies.
  2. Local SQLite token budget ledger enforcing session spend caps and concurrency ceilings.
- **Code Evidence:** [`src/proxy/handler.rs`](../src/proxy/handler.rs), [`src/spend/ledger.rs`](../src/spend/ledger.rs).
- **Status:** ✅ **Full**

---

### ASI09: Human-Agent Trust Exploitation
- **Threat:** Autonomous agents trigger irreversible, high-impact operations without explicit human authorization.
- **AgentWall Mitigation:** Human-in-the-Loop (HITL) policy escalation ladder. High-risk operations prompt developers in the local web dashboard (`127.0.0.1:8080`) or dispatch asynchronous Slack/Teams webhooks verified via HMAC signatures.
- **Code Evidence:** [`src/policy/hitl.rs`](../src/policy/hitl.rs), [`src/proxy/server.rs`](../src/proxy/server.rs).
- **Status:** ✅ **Full**

---

### ASI10: Rogue Agents & Unauthorized Egress
- **Threat:** Uncontrolled agent processes bypass governance, modify proxy configurations, or open unmonitored egress channels.
- **AgentWall Mitigation:** 
  1. Background OS Sentry daemon (`systemd`, `launchd`, Windows SCM) with <300ms self-healing config protection.
  2. Ed25519 hardware-bound PKI device enrollment with instant web console device revocation (`/admin/devices`).
  3. Hardened Rust egress WebSocket tunneling with TLS 1.3 termination.
- **Code Evidence:** [`src/service/`](../src/service), [`src/identity/`](../src/identity), [`src/proxy/egress.rs`](../src/proxy/egress.rs).
- **Status:** ✅ **Full**

---

## Automated Compliance Verification

Generate automated compliance evidence reports directly from production audit logs:

```bash
# Verify cryptographic integrity of the audit log
agentwall verify-log --path /var/log/agentwall/audit.jsonl

# Generate OWASP ASI compliance summary report
agentwall report --compliance --format markdown

# Export structured JSON evidence for enterprise security auditors
agentwall report --compliance --format json --output owasp_asi_evidence.json
```
