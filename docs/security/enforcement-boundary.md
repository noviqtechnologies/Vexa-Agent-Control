# Enforcement Boundary & Security Model
## Vexa AgentControl — Decision Correctness, Path Coverage & Tamper Resistance

**Document Version:** 1.0  
**PRD Reference:** `PRD/pending/Vexa_AgentControl_Enforcement_Assurance_PRD.md` Sections 1–4  
**Authoritative Positioning:**  
> *"Vexa helps engineering teams govern the AI-agent traffic they route through it, with centrally managed policies and verifiable, per-surface enforcement evidence."*

---

## 1. The Core Architectural Distinctions

Enterprise security buyers frequently conflate three distinct dimensions of security assurance. Vexa AgentControl explicitly separates them:

```
┌────────────────────────────────────────────────────────────────────────┐
│                      THE THREE ASSURANCE DIMENSIONS                    │
├─────────────────────┬──────────────────────────────────────────────────┤
│ Dimension           │ Definition & Scope of Guarantee                  │
├─────────────────────┼──────────────────────────────────────────────────┤
│ 1. Decision         │ Given a request that reaches Vexa, does policy   │
│    Correctness      │ evaluate accurately and block before the action  │
│                     │ reaches its downstream destination?              │
├─────────────────────┼──────────────────────────────────────────────────┤
│ 2. Path Coverage    │ Does all relevant AI agent and tool traffic      │
│                     │ actually flow through Vexa, or are there routes  │
│                     │ that bypass it entirely?                         │
├─────────────────────┼──────────────────────────────────────────────────┤
│ 3. Tamper           │ Can a user, unmanaged script, or local malware   │
│    Resistance       │ reconfigure, kill, or alter the local proxy?     │
└─────────────────────┴──────────────────────────────────────────────────┘
```

### What Vexa Solves Completely (Decision Correctness)
When an HTTP completion request or MCP stdio JSON-RPC tool call is routed through Vexa:
- In-line DLP redaction executes before payload transmission.
- Prompt injection heuristics evaluate before dispatch.
- Path traversal and tool-parameter schemas validate deterministically.
- A deny decision provably returns `NOT_FORWARDED` with zero downstream fixture hits.
- All decisions are recorded in a hash-chained, tamper-evident audit log with stable Request IDs.

### What a Local Proxy Cannot Prove Alone (Path Coverage & Tamper Resistance)
A user-space proxy running on a developer's workstation cannot, on its own:
1. Prevent a developer from exporting raw API keys (`OPENAI_API_KEY`) in shell sessions.
2. Prevent an IDE or CLI tool from directly calling cloud APIs if reconfigured.
3. Prevent a local attacker with administrative privileges from terminating the proxy process or modifying hosts files.
4. Govern arbitrary native shell execution (`bash`, `git`, `curl`) run outside wrapped MCP servers.

> [!CAUTION]
> **Prominent Limitation:**  
> Vexa does not by itself prevent a workstation owner or unmanaged process from bypassing a local proxy. Use managed endpoint and network controls when mandatory, non-bypassable enforcement is required.

---

## 2. Why Binary "Protected" Badges Are Forbidden

In legacy tools, setting a proxy configuration URL often paints a global green checkmark labeled `PROTECTED` or `COMPLIANT`. 

Vexa prohibits this presentation because it creates a false sense of security:
- **Claude Desktop Case:** Wrapping Claude Desktop's MCP servers governs local tools, but Claude Desktop's LLM completions route out-of-band directly to Anthropic Cloud over HTTPS. Reporting Claude Desktop as "protected" conceals the fact that LLM completions are completely uninspected.
- **Stopped Daemon Case:** Pointing an IDE configuration to `127.0.0.1:18080` when the daemon is not running can cause the client to fail open or hang. Reporting "configured" as "enforced" is a critical defect.
- **Shadow Mode Case:** An agent running in shadow mode evaluates policy without blocking actions. This is `OBSERVED`, never `ENFORCED`.

---

## 3. The Path to Mandatory Boundary Mode

To achieve true, non-bypassable enforcement across an engineering organization, Vexa operates in **Mandatory Boundary Mode** by integrating with existing enterprise security controls:

1. **MDM Configuration Locking:** Use Jamf, Microsoft Intune, or Fleet to enforce read-only workstation configurations for IDEs and environment variables.
2. **Network Egress Filtering:** Configure enterprise firewalls (Palo Alto, Zscaler, Cloudflare One) to block direct outbound traffic to `api.openai.com`, `api.anthropic.com`, etc., allowing access only via the Vexa Enterprise Gateway.
3. **Broker-Held Credentials:** Provision API keys in the Central Vexa Broker or HashiCorp Vault. Developers never possess raw cloud provider credentials on local workstations.
4. **EDR Process Monitoring:** Verify AgentControl process integrity and detect unwrapped tool execution via CrowdStrike or SentinelOne telemetry.

When all four pillars are active and verified, Vexa reports `MANDATORY_BOUNDARY`.
