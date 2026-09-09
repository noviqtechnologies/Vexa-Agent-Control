# Boundary Model: Localhost Wrapper vs. Network Enforcement

**Document Version:** 1.0.0  
**Status:** Security Architecture Standard  
**Applies to:** Vexa Agent Control `v1.0.82+`

---

## 1. Scope & Purpose

A critical concern in local developer security tools is **proxy bypass**: can an agent, developer, or IDE process circumvent the security proxy and communicate directly with model providers?

This document defines the boundary models supported by Vexa Agent Control, tests for boundary integrity, and security hardening guidelines.

---

## 2. Boundary Models Supported

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          Boundary Enforcement Models                        │
├──────────────────────────────┬──────────────────────────────────────────────┤
│ 1. Cooperative Wrapper       │ Environment variables (OPENAI_BASE_URL) &    │
│    (Default Developer Mode)  │ wrapped process launch (`agentcontrol run`).  │
├──────────────────────────────┼──────────────────────────────────────────────┤
│ 2. Stdio Subprocess Sandbox  │ JSON-RPC MCP proxy where child process has    │
│    (MCP Tool Guard)          │ stdout/stdin strictly wired through gateway. │
├──────────────────────────────┼──────────────────────────────────────────────┤
│ 3. Operating System /        │ iptables (Linux) or Windows Packet Filter    │
│    Network-Enforced Boundary │ redirecting 443 outbound to local proxy.     │
└──────────────────────────────┴──────────────────────────────────────────────┘
```

### Model 1: Cooperative Developer Wrapper
In standard CLI mode (`agentcontrol run -- <cmd>` or `agentcontrol dev`):
- Sets `OPENAI_BASE_URL`, `ANTHROPIC_BASE_URL`, `AZURE_OPENAI_ENDPOINT` in child process environment.
- Injects localhost loopback address (`http://127.0.0.1:8080`).
- **Limitation**: A malicious process with unrestricted network permissions can ignore environment variables and make direct socket connections to `api.openai.com`.

### Model 2: Stdio MCP Process Interception
In MCP stdio mode (`agentcontrol stdio -- <mcp-server>`):
- The agent process does not communicate over the network directly.
- All tool execution requests and responses flow through standard I/O pipes intercepted by AgentControl's Rust engine.
- Replay attacks, parameter poisoning, and unauthorized tool calls are intercepted inline.

### Model 3: Strict Network Boundary (Enterprise Egress Control)
For hardened production workstations and CI/CD runners:
- Outbound egress to external LLM provider IPs is blocked at the firewall / security group.
- Only the `agentcontrol` daemon has egress authorization (or egress traffic is transparently redirected via eBPF / iptables).
- Direct provider calls without AgentControl fail with connection refused.

---

## 3. Boundary Verification Test Cases

| Test ID | Scenario | Expected Behavior |
|---|---|---|
| **BND-01** | Wrapped process inherits environment | Child process makes requests through proxy (`X-AgentControl-Origin: upstream_provider`). |
| **BND-02** | Child process attempts to unset `OPENAI_BASE_URL` in cooperative mode | Direct call succeeds if OS firewall allows outbound; flagged in CI audit if network egress monitoring is active. |
| **BND-03** | Stdio proxy with malicious tool injection | Tool call inspected, DLP/injection rule evaluates, offending payload blocked before reaching agent. |
| **BND-04** | IPv4 vs IPv6 loopback binding | Gateway binds both `127.0.0.1` and `::1` to prevent IPv6 bypass. |
| **BND-05** | Gateway process termination | If proxy shuts down, wrapped child processes fail closed (connection refused) rather than silently leaking credentials. |
