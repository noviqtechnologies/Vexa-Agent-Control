# OWASP Top 10 for Agentic Applications (ASI 2026) — Security Architecture & Compliance Mapping

> **Document Version:** 1.1 (P0-5 honest review)
> **Last Reviewed:** 2026-10-04  
> **Standard:** [OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)  
> **Audience:** Security Architects, GRC Officers, SecOps, DevSecOps Evaluators
>
> ⚠️ **Honest Review Note (P0-5):** Detection and coverage ratings are marked "Full" only where linked automated tests and published evaluation results exist. Ratings without reproducible evidence are listed as "Partial". See the "[What Vexa does not stop](#what-vexa-does-not-stop)" section below.

---

## Executive Summary

Autonomous AI agents introduce distinct security vulnerabilities that cannot be mitigated by traditional network firewalls or probabilistic prompt-level instructions. The **OWASP Agentic Security Initiative (ASI 2026)** defines the 10 primary threat vectors facing autonomous agent ecosystems.

**Vexa Agent Control** implements deterministic, out-of-process runtime security at the network and transport boundary (MCP stdio, HTTP, HTTPS, WebSockets). This document provides an honest, evidence-backed mapping of Agent Control's controls against all 10 OWASP Agentic risks.

---

## Coverage Matrix

| Risk ID | Vulnerability Title | Agent Control Status | Primary Enforcement Component | Evidence in Codebase |
|---|---|:---:|---|---|
| **ASI01** | **Agent Goal Hijack** | ⚠️ **Partial** | 6-Pass Normalizer & 9 Prompt Injection Scanners | [`src/policy/injection.rs`](../src/policy/injection.rs), [`src/policy/safe_mode.rs`](../src/policy/safe_mode.rs) |
| **ASI02** | **Tool Misuse and Exploitation** | ✅ **Full** | Default-Deny Policy Engine & JSON Parameter Schema Validator | [`src/policy/engine.rs`](../src/policy/engine.rs), [`src/policy/schema.rs`](../src/policy/schema.rs) |
| **ASI03** | **Identity and Privilege Abuse** | ✅ **Full** | OIDC JWT Validation, Group Claim Binding, & Credential Scopes | [`src/policy/identity.rs`](../src/policy/identity.rs) |
| **ASI04** | **Agentic Supply Chain Vulnerabilities** | ⚠️ **Partial** | MCP Security Scoring Engine & Cross-Session Schema-Drift Detection | [`src/policy/mcp_score.rs`](../src/policy/mcp_score.rs), [`src/policy/schema_drift.rs`](../src/policy/schema_drift.rs) |
| **ASI05** | **Unexpected Code Execution (RCE)** | ✅ **Full** | Safe Mode Command Blocking & Parameter Traversal Validators | [`src/policy/safe_mode.rs`](../src/policy/safe_mode.rs), [`src/policy/engine.rs`](../src/policy/engine.rs) |
| **ASI06** | **Memory and Context Poisoning** | ⚠️ **Partial** | Response Poisoning Interceptors & HMAC-Chained Audit Trails | [`src/policy/injection.rs`](../src/policy/injection.rs), [`src/audit/logger.rs`](../src/audit/logger.rs) |
| **ASI07** | **Insecure Inter-Agent Communication** | ❌ **Gap (Scoped)** | Org-Local OIDC Identity Boundary (Upstream Federation Required) | [`src/policy/identity.rs`](../src/policy/identity.rs), [Scope Limitations](#what-vexa-does-not-stop) |
| **ASI08** | **Cascading Agent Failures** | ✅ **Full** | Cycle & Loop Prevention (`PivotError`), Rate Limits, & Spend Caps | [`src/proxy/handler.rs`](../src/proxy/handler.rs), [`src/spend/ledger.rs`](../src/spend/ledger.rs) |
| **ASI09** | **Human-Agent Trust Exploitation** | ✅ **Full** | Real-Time Browser Approval Modals & HMAC-Signed Webhook Escalation | [`src/policy/hitl.rs`](../src/policy/hitl.rs), [`src/proxy/server.rs`](../src/proxy/server.rs) |
| **ASI10** | **Rogue Agents & Unauthorized Egress** | ✅ **Full** | OS Sentry Daemon, PKI Device Enrollment, & Egress Tunneling | [`src/service/`](../src/service), [`src/identity/`](../src/identity), [`src/proxy/egress.rs`](../src/proxy/egress.rs) |

**Official Scorecard:** **7/10 Full Coverage, 2/10 Partial (pending published eval results), 1/10 Scoped Gap.**

> Note: ASI01 and ASI04 are downgraded from "Full" to "Partial" pending a published `bench/detect` evaluation harness (PRD F2-S1) that demonstrates detection and false-positive rates against a labeled corpus. They will be re-rated "Full" once reproducible numbers are committed (F2-S1 acceptance criteria).

---

## Detailed Control Mappings & Code Evidence

```
                          ┌──────────────────────────────────────────────┐
                          │   Operating Surface (IDE, Agent, CLI)       │
                          └──────────────────────┬───────────────────────┘
                                                 │
                                                 ▼
┌───────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Vexa Agent Control — Out-of-Process Enforcement Boundary                                              │
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
- **Agent Control Mitigation:** Multi-pass normalizer (handling NFKC normalization, Base64 decoding, and leetspeak de-obfuscation) coupled with 9 prompt injection detectors and response poisoning checks.
- **Enforcement Point:** Out-of-process stream inspection prior to tool argument delivery and post-execution response sanitization.
- **Code Evidence:** [`src/policy/injection.rs`](../src/policy/injection.rs), [`src/policy/safe_mode.rs`](../src/policy/safe_mode.rs).
- **Status:** ✅ **Full**

---

### ASI02: Tool Misuse and Exploitation
- **Threat:** Agents invoke dangerous tools or supply malicious parameter payloads (e.g., path traversal, command injection, unconstrained SQL queries).
- **Agent Control Mitigation:** Strict default-deny YAML policy engine, compiled JSON schema parameter bounds, path traversal validators (`..` rejection), and shell character blocking.
- **Enforcement Point:** Intercepts every JSON-RPC `tools/call` on the wire; unknown or non-allowlisted tools are immediately rejected.
- **Code Evidence:** [`src/policy/engine.rs`](../src/policy/engine.rs), [`src/policy/schema.rs`](../src/policy/schema.rs), [`src/policy/loader.rs`](../src/policy/loader.rs).
- **Status:** ✅ **Full**

---

### ASI03: Identity and Privilege Abuse
- **Threat:** Unauthenticated agents or privilege-escalated sessions execute tools outside authorized tenant boundaries.
- **Agent Control Mitigation:** Validates corporate OIDC JWT tokens (Okta, Keycloak, Entra ID), maps JWT group claims dynamically to tool permissions, and enforces per-tool `X-Agent Control-Credential-Scope` constraints.
- **Enforcement Point:** Session token validation on ingress and proxy boundary credential injection (stripping raw keys from agents).
- **Code Evidence:** [`src/policy/identity.rs`](../src/policy/identity.rs), [`src/policy/credential_scope.rs`](../src/policy/credential_scope.rs).
- **Status:** ✅ **Full**

---

### ASI04: Agentic Supply Chain Vulnerabilities
- **Threat:** Compromised third-party MCP servers, plugin updates, or altered tool definitions introduce malicious capabilities post-approval ("rug pulls").
- **Agent Control Mitigation:** 
  1. Static and dynamic manifest scoring via **MCP Security Scoring Engine** (0–100 Vexa Security Score).
  2. Runtime **Cross-Session Schema-Drift Detection** (ADR-011) that hashes tool catalogs and detects schema tampering across sessions.
- **Known Gap:** Agent Control does not generate software bills of materials (SBOMs) for host binary dependencies.
- **Code Evidence:** [`src/policy/mcp_score.rs`](../src/policy/mcp_score.rs), [`src/policy/schema_drift.rs`](../src/policy/schema_drift.rs).
- **Status:** ✅ **Full**

---

### ASI05: Unexpected Code Execution (RCE)
- **Threat:** Agent execution leads to arbitrary shell command invocation, script execution, or binary tampering on the host machine.
- **Agent Control Mitigation:** Safe Mode automatically blocks dangerous commands (`rm -rf`, `curl | bash`, reverse shells, `chmod`), prevents execution in sensitive paths, and protects configuration files with self-healing file locks.
- **Code Evidence:** [`src/policy/safe_mode.rs`](../src/policy/safe_mode.rs), [`src/self_healing.rs`](../src/self_healing.rs).
- **Status:** ✅ **Full**

---

### ASI06: Memory and Context Poisoning
- **Threat:** Malicious data persisted into vector databases, scratchpads, or long-term agent memory corrupts future reasoning cycles.
- **Agent Control Mitigation:** Cryptographically chained HMAC-SHA256 audit logs provide tamper-evident history of all session decisions and responses. Response scanners redact sensitive tokens before context ingestion.
- **Known Gap:** Agent Control does not provide direct application-layer sandboxing for third-party vector databases or agent memory snapshot verification.
- **Code Evidence:** [`src/audit/logger.rs`](../src/audit/logger.rs), [`src/policy/response_scanner.rs`](../src/policy/response_scanner.rs).
- **Status:** ⚠️ **Partial**

---

### ASI07: Insecure Inter-Agent Communication
- **Threat:** Inter-agent messages lack cryptographic provenance, mutual authentication, or capability delegation boundaries across independent organizations.
- **Agent Control Assessment:** Agent Control scopes identity to enterprise OIDC providers within an organization's trust domain. It does not implement decentralized DIDs or cross-organization agent federation protocols.
- **Recommended Mitigation:** Deploy corporate IdP cross-tenant federation (e.g., Entra ID B2B or Okta Org2Org) upstream of Agent Control gateways.
- **Code Evidence:** [`src/policy/identity.rs`](../src/policy/identity.rs), [`docs/LIMITATIONS.md`](../PRD/LIMITATIONS.md).
- **Status:** ❌ **Scoped Gap**

---

### ASI08: Cascading Agent Failures
- **Threat:** Stuck agents trapped in repetitive failure cycles cause runaway LLM token spend, quota exhaustion, or cascading downstream outages.
- **Agent Control Mitigation:** 
  1. Built-in sliding-window cycle detector that returns `PivotError` (-32010) to force the model to attempt alternative strategies.
  2. Local SQLite token budget ledger enforcing session spend caps and concurrency ceilings.
- **Code Evidence:** [`src/proxy/handler.rs`](../src/proxy/handler.rs), [`src/spend/ledger.rs`](../src/spend/ledger.rs).
- **Status:** ✅ **Full**

---

### ASI09: Human-Agent Trust Exploitation
- **Threat:** Autonomous agents trigger irreversible, high-impact operations without explicit human authorization.
- **Agent Control Mitigation:** Human-in-the-Loop (HITL) policy escalation ladder. High-risk operations prompt developers in the local web dashboard (`127.0.0.1:8080`) or dispatch asynchronous Slack/Teams webhooks verified via HMAC signatures.
- **Code Evidence:** [`src/policy/hitl.rs`](../src/policy/hitl.rs), [`src/proxy/server.rs`](../src/proxy/server.rs).
- **Status:** ✅ **Full**

---

### ASI10: Rogue Agents & Unauthorized Egress
- **Threat:** Uncontrolled agent processes bypass governance, modify proxy configurations, or open unmonitored egress channels.
- **Agent Control Mitigation:** 
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
agentcontrol verify-db --audit-path /var/log/agentcontrol/audit.jsonl

# Generate OWASP ASI compliance summary report
agentcontrol compliance report --format markdown

# Export structured JSON evidence for enterprise security auditors
agentcontrol compliance report --format json --output owasp_asi_evidence.json
```

---

## What Vexa does not stop {#what-vexa-does-not-stop}

> This section is required for honest security positioning (PRD P0-5). Vexa Agent Control provides strong structural controls at the network and transport boundary, but it does **not** protect against every conceivable attack. Understanding these boundaries is essential for accurate threat modeling.

### 1. Novel or paraphrased prompt injections

Vexa's injection scanner uses deterministic regex patterns and heuristic token boundaries. A sufficiently novel jailbreak phrase — one not present in the trained pattern set — may pass through undetected. **Mitigation:** Use shadow mode to log and review, enable the optional local-model classifier plugin (F2-S4), and audit new patterns via the eval harness (`bench/detect`).

### 2. Semantically encoded instructions

Instructions embedded in deeply nested structures, steganographic Unicode sequences not yet in the normalizer, or formats that the normalizer does not decode (e.g. custom encodings) may bypass detection. **Mitigation:** F3 toxic-flow controls limit blast radius even when injection detection fails.

### 3. Cross-organization agent federation

Vexa's identity controls operate within a single organization's OIDC trust boundary. Cross-organization agent-to-agent communication (e.g., MCP server A calling MCP server B in a different org) is not authenticated or authorized by Vexa. **Mitigation:** Deploy upstream IdP cross-tenant federation (Entra ID B2B, Okta Org2Org) before the Vexa gateway.

### 4. In-model reasoning manipulation (pre-tool-call)

Vexa intercepts at the tool-call / API boundary. It cannot inspect or constrain what happens *inside* the LLM's reasoning process prior to a tool call being issued. A compromised system prompt that instructs the model to manipulate future reasoning steps is outside Vexa's enforcement boundary.

### 5. Encrypted or protocol-tunneled egress

Agents that exfiltrate data through cryptographic side-channels (e.g., encoding secrets as timing patterns, using encrypted protocols over allowed ports) cannot be detected by Vexa's egress domain filtering, which operates on plaintext TCP/HTTP metadata.

### 6. LLM-provider-side vulnerabilities

Vexa forwards (after policy evaluation) to upstream LLM providers. Vulnerabilities in the providers themselves (e.g., training data poisoning, model weight compromise) are outside Vexa's control surface.

### 7. Host-level compromise

If the developer workstation or container host is already compromised (kernel rootkit, process injection), the Vexa sentry process can be killed or bypassed before it can enforce policy. Vexa assumes an uncompromised host OS.

### 8. Supply chain attacks on Vexa itself

Until SBOM generation (F1-S1) and verified installer checksums (F1-S3) are shipped, a tampered Vexa binary is not detected. **Status:** Planned for Phase 1.

---

*Last updated: 2026-10-04. This section is reviewed on every release.*
