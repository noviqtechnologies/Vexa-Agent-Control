# Getting Started with Vexa Agent Control

**Vexa Agent Control** is a developer-first, zero-elevation security sentry and governance gateway for AI agents and coding assistants.

It enables engineering teams to leverage frontier LLMs and MCP (Model Context Protocol) tools with centralized spend controls, data loss prevention (DLP), and zero plaintext secrets on the endpoint.

---

## Core Invariants

- **Zero Elevation:** Standard developer commands (`login`, `connect`, `disconnect`, `status`, `doctor`, `support-bundle`, `repair`) require **no** administrative privileges or UAC elevation.
- **Zero Provider Keys on Workstations:** Master API keys (OpenAI, Anthropic, Gemini, Groq, Bedrock) are stored strictly in the central Cloud Vault. Workstations only receive short-lived session credentials.
- **Zero OS Trust Store Mutation:** Agent Control never installs Root CA certificates or modifies operating system trust stores.
- **Non-Destructive Reversal:** Configuration mutations are tracked in cryptographic `OwnershipManifest` files (`~/.agentcontrol/manifests/`), preserving developer comments and custom settings.

---

## 5-Minute Developer Quickstart

### Step 1: Log in via Browser PKCE

Authenticate your workstation with your organization's Control Hub using OAuth 2.0 PKCE:

```bash
agentcontrol login
```

1. Agent Control opens your default web browser to the secure OAuth login page.
2. Complete authentication via your identity provider (Google, GitHub, Okta, or SAML SSO).
3. The local callback listener on `127.0.0.1:18085` exchanges the authorization code for a device token.
4. An Ed25519 device keypair is generated and stored securely in your OS Keyring (Windows Credential Manager, macOS Keychain, or Freedesktop Secret Service).
5. A per-user background agent (`VexaAgentControl`) is registered to start automatically upon user login.

*To log in on a headless server or without a browser:*
```bash
agentcontrol login --no-browser
```

---

### Step 2: Connect Your Coding Assistants

Connect your installed AI coding assistants with a single command:

#### OpenAI Codex CLI:
```bash
agentcontrol connect codex
```
- Injects local proxy routing (`http://127.0.0.1:18080/v1`) into `~/.codex/config.toml`.
- Wraps any configured MCP servers with `agentcontrol stdio-proxy --`.
- Records an ownership manifest for guaranteed clean reversal.

#### Anthropic Claude Desktop:
```bash
agentcontrol connect claude
```
- Wraps all MCP server entries in `claude_desktop_config.json` with the stdio security proxy.
- Direct model requests continue to route to Anthropic directly; all tool executions are monitored and governed.

#### Cursor IDE:
```bash
agentcontrol connect cursor
```
- Automatically configures Cursor's `User/settings.json` to proxy LLM traffic through `http://127.0.0.1:18080`.
- Wraps any configured MCP servers in `~/.cursor/mcp.json` with the stdio security proxy.
- Records an ownership manifest for guaranteed clean reversal.

#### Antigravity IDE:
```bash
agentcontrol connect antigravity
```
- Wraps all MCP server entries in `~/.gemini/antigravity/mcp_config.json` with the stdio security proxy.
- Records an ownership manifest for guaranteed clean reversal.

---

### Step 3: Check Sentry & Assistant Status

Verify the background daemon health and capability status of all supported coding assistants:

```bash
# Check daemon service health
agentcontrol service status
```

Example Output:
```text
● Vexa Agent Control Daemon Health Inspection
  OS Platform:        windows (x86_64)
  Supervisor Type:    Windows User Startup (HKCU\Run) (ACTIVE / SUPERVISED)
  Daemon Process:     PID 25936 (v1.0.89) | Up 23s
  Listener Binding:   127.0.0.1:18080 (20 ms RTT)
  Hub Connection:     ENROLLED (http://127.0.0.1:8081) | Policy: ACTIVE (local-safe-mode)
```

```bash
# Check assistant wrapping & routing status
agentcontrol status
```

Example output:
```text
=== Vexa Agent Control Workstation Status ===
Daemon:    RUNNING (127.0.0.1:18080)
Identity:  local (local.token, ~/.agentcontrol/local.token)

Target           Status               Freshness       Notes
----------------------------------------------------------------------------------
codex            CONFIGURED           ACTIVE_FRESH    OpenAI endpoint routed (127.0.0.1:18080)
claude           MCP_WRAPPED          ACTIVE_FRESH    2 MCP servers wrapped with stdio-proxy
cursor           CONFIGURED           ACTIVE_FRESH    Local proxy completions enabled
antigravity      MCP_WRAPPED          ACTIVE_FRESH    MCP servers wrapped with stdio-proxy
```

---

### Step 4: Run Health Diagnostics

Run a comprehensive pre-flight and health check:

```bash
agentcontrol doctor
```

Exit codes follow standard UNIX semantics:
- `0` = All checks passed (healthy)
- `1` = Critical error (e.g. background agent unreachable, invalid credentials)
- `2` = Degraded or warning (e.g. unverified target drift, stale credentials)

For programmatic or CI/CD pipelines, use JSON output:
```bash
agentcontrol doctor --json
```

---

### Step 5: Disconnecting & Rolling Back

To cleanly disconnect an assistant and revert configurations without affecting your personal settings:

```bash
agentcontrol disconnect codex
agentcontrol disconnect claude
agentcontrol disconnect cursor
agentcontrol disconnect antigravity
```

Agent Control consults the target's `OwnershipManifest`, restores original values, unwraps MCP server commands, and preserves all user-added properties, custom themes, and keybindings.

---

## Loopback Hardening & Multi-OS Architecture

### 1. Loopback Port & Dynamic Fallback
The Agent Control background daemon binds to `127.0.0.1:18080`. If port 18080 is already bound by another process on your workstation, the daemon dynamically falls back to the next available port in range `18080..=18090` and writes the active port to `~/.agentcontrol/daemon.port`.

### 2. Socket-Level Loopback Assertion
The daemon strictly asserts peer IP addresses at the TCP socket layer (accepting only `127.0.0.0/8`, `::1`, or `::ffff:127.0.0.1`). Any inbound connection from an external or non-loopback network interface is dropped immediately before HTTP parsing.

### 3. Ambient Browser Blocking (Web-to-Localhost CSRF Defense)
Any web request carrying an external `Origin` or `Sec-Fetch-Site: cross-site` header is rejected with HTTP 403 Forbidden to prevent cross-site port scanning and DNS rebinding attacks.

### 4. FinOps Spend Caps & Premature Stream Cancellation
- When monthly spend caps are reached, the proxy returns HTTP 429 (`BUDGET_EXCEEDED`) immediately without retry loops.
- If a client terminates or disconnects an SSE completion prematurely, AgentControl dispatches a cancellation signal to the cloud gateway within 500ms and settles only actual tokens consumed.

### 5. Multi-OS MCP Stdio Process Sandboxing
MCP server child processes are wrapped with `agentcontrol stdio-proxy`:
- **Memory Ceiling:** Enforces hard < 64MB RSS limits (Windows Job Objects, Linux `RLIMIT_AS`, macOS `RLIMIT_DATA`).
- **Parameter DLP:** Automatically redacts API keys and database connection strings before tool execution.
- **Crash Isolation:** A crashing or hung MCP server never terminates the main daemon or affects other tools.

