# Vexa Agent Control — Host Security Boundary & Threat Model

**Status:** APPROVED (Phase 0a Baseline)  
**Date:** 2026-10-04  
**Governing Standard:** [Plan Review Feedback v4](file:///C:/Users/wasim/.gemini/antigravity-ide/brain/9469605e-81c2-40a5-9567-198d8ebbf4c0/plan_review_feedback_v4.md) & [ADR-010](file:///c:/AgentWall/agentwall/docs/adr/ADR-010-hitl-and-local-api-security.md)

---

## 1. Executive Security Boundary Declaration

> **Zero-Trust Engineering Principle:**  
> A security tool that obscures its operational limitations creates a false sense of security. Vexa Agent Control explicitly discloses its threat assumptions, security guarantees, and boundaries upfront.

```
┌────────────────────────────────────────────────────────────────────────┐
│                          IN-SCOPE THREATS                              │
│                                                                        │
│  [ Compromised / Rogue Agents ] ──► Tool call violations, path         │
│                                     traversal, infinite loop spend     │
│  [ Malicious Remote Origins ]   ──► Web pages attempting CSRF,         │
│                                     DNS rebinding to `127.0.0.1`       │
│  [ Prompt Injection Payloads ] ──► Malicious indirect instructions in  │
│                                     tool output or web browsing        │
│  [ Credential Exfiltration ]    ──► API keys / secrets leaking to      │
│                                     third-party LLM providers          │
│  [ Side-Effect Replay ]         ──► Duplicate external execution on   │
│                                     crash recovery                     │
└────────────────────────────────────────────────────────────────────────┘

────────────────────────────── THREAT BOUNDARY ──────────────────────────

┌────────────────────────────────────────────────────────────────────────┐
│                        EXPLICIT OUT-OF-SCOPE LIMITATION                 │
│                                                                        │
│  [ Malicious Process Running as the Same OS User Account ]             │
│  An adversary executing code as the same local OS user (e.g. via local │
│  malware or unconstrained shell) shares the OS security context.       │
│  Unless constrained by host-level OS sandboxes (Windows AppContainer,  │
│  macOS Sandbox, Linux cgroups/SELinux), any process running as $USER   │
│  can inspect user memory, terminate user processes, or read user files.│
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Protected Attack Surfaces

### 2.1 Rogue Agent & MCP Tool Containment
- **Threat**: An LLM agent hallucinates, enters an infinite recursive loop, or attempts destructive tool commands (e.g. `rm -rf /`, writing outside project workspace, port scanning internal RFC 1918 subnets).
- **Control**: Deterministic policy engine evaluates every tool call against strict JSON parameter schemas, path traversal normalizers, and loop iteration ceilings. Default-deny blocks actions before execution.

### 2.2 Remote Web Origins & Browser Egress (CSRF & DNS Rebinding)
- **Threat**: A developer visits a malicious website while Vexa is running on `127.0.0.1:18080`. The website issues cross-origin fetch requests to approve pending tool calls or modify proxy policies.
- **Controls**:
  - `Sec-Fetch-Site`: Any request bearing `Sec-Fetch-Site: cross-site` is immediately rejected with HTTP 403 Forbidden.
  - `Origin` & `Host` Header Validation: Only requests originating from `127.0.0.1`, `localhost`, or explicit loopback IPs are processed. DNS rebinding domains are rejected.
  - Bearer Capability Tokens: Mutation endpoints require a cryptographically generated capability token.

### 2.3 Approval Secret Theft & Notification Snoopers
- **Threat**: An attacker or local non-privileged background process monitors terminal output (`stderr`) or desktop notification history (`/org/freedesktop/Notifications`) to steal signed approval tokens and replay them.
- **Controls**:
  - Notifications and terminal output contain **only unprivileged opaque references** (`appr-8f3a91`), never cryptographic tokens or URLs.
  - Approval consumption requires an authenticated capability session (`POST /api/v1/hitl/respond`).
  - Server-side atomic Compare-And-Set (CAS) prevents double-spend.

### 2.4 Data Loss Prevention (Credential Exfiltration)
- **Threat**: An agent reads `.env`, `id_rsa`, or cloud credentials and sends them to a third-party LLM in a prompt or tool argument.
- **Controls**:
  - 20+ inline DLP detectors scan text across regex patterns, Shannon entropy, and cryptographic checksums (Luhn, BIP-39).
  - Wire-layer redaction replaces matches with `[REDACTED:<pattern>]` *before* payloads leave the workstation.

---

## 3. Local API Capability & Authorization Model

To prevent privilege escalation between trace inspection and state mutation, the local REST/SSE API enforces granular capabilities:

```
┌────────────────────────┐
│  Client Session Token  │
└───────────┬────────────┘
            │
            ├── Possesses `Scope::TraceRead`       ──► Allowed: Read traces (masked)
            ├── Possesses `Scope::RawPayloadRead`  ──► Allowed: View unmasked secrets (Audit logged)
            ├── Possesses `Scope::ApprovalWrite`   ──► Allowed: Approve/Reject HITL actions
            └── Possesses `Scope::AdminWrite`      ──► Allowed: Hot-reload policy, rotate keys
```

### Authorization Rules:
1. **Separation of Read and Write**: Reading traces or viewing metrics never grants the authority to approve blocked actions or change security rules.
2. **Audit Logging of Sensitive Reads**: Any access to `/api/v1/traces/{id}/raw` emits an immutable audit log entry (`event = "sensitive_payload_revealed"`, recording timestamp, requesting IP, and target span).
3. **Constant-Time Verification**: All token and secret comparisons use constant-time equality checks (`subtle::constant_time_eq`) to eliminate side-channel timing attacks.

---

## 4. Multi-User & Shared Host Isolation Policy

1. **Per-User Architecture**:
   - Vexa Agent Control is designed as a **per-user workstation sentry**.
   - Multiple OS users sharing a single machine must run independent daemon instances on unique ports or Unix domain sockets.
   - Daemon configuration and credentials are saved in user-restricted directories (`%APPDATA%\AgentWall\` with NTFS user-only DACL; `~/.config/agentwall/` with mode `0600`).
2. **Shared Machine Restriction**:
   - Sharing a single daemon instance across multiple OS users is explicitly unsupported in Phase 1.
   - Multi-tenant enterprise fleet governance is provided in Phase 3 via centralized Docker/Kubernetes deployment with cryptographic OIDC identity binding.
