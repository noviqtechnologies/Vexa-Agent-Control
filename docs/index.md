# Agent Control Documentation

Welcome to the Agent Control technical documentation. 

Agent Control is an egress proxy and security gateway for AI agents operating over the Model Context Protocol (MCP), HTTP, HTTPS, and WebSocket connections. It intercepts, audits, and blocks unauthorized agent tool calls based on YAML-defined policies, auto-generates a baseline policy on first run, and includes a built-in **AI Detection & Response (ADR)** benchmark to measure security posture against 17 real-world AI attack categories.

## What is Agent Control?

MCP (Model Context Protocol) is an open standard that allows AI models to securely connect to local and remote data sources and tools. As AI agents increasingly autonomously invoke tools, a robust security boundary is necessary. Agent Control acts as a firewall specifically designed for these MCP tool calls.

Agent Control intercepts outbound traffic from your agent, surfacing patterns in a local dashboard, and generates a YAML security policy draft based on observed behavior.

## Core Capabilities

- **Observation & Routing:** Intercepts MCP, HTTP CONNECT, WebSocket, and plain HTTP traffic.
- **Enforcement:** Strict tool allowlisting with schema validation and bounds checking.
- **Data Loss Prevention (DLP):** 21 regex patterns detecting API keys, secrets, and PII.
- **Injection Defense:** 6-pass normalizer and 16-pattern injection scanner that blocks inbound tool responses and external payloads.
- **Safe Mode (FR-303a):** 15 tool-aware rules that block dangerous file access, shell exfiltration, and cloud metadata SSRF — enabled by default, no policy file required.
- **Stateful Sequence Rules:** Sliding-window session tracker and deterministic sequence engine enforce multi-step attack detection across tool call chains (e.g., block `exec` always following `read`).
- **Agent Identity & Credential Governance:** Per-agent short-lived credential provisioning, rotation, and per-tool-call scoping to eliminate long-lived secret sprawl.
- **SaaS Dashboard (FR-23):** Optional self-hosted web dashboard for fleet-wide visibility into agent activity, identity governance, policy insights, and Per-Client MCP Server Visibility (Admin-Only).
- **Central Device Governance:** OTET enrollment tokens, 60s background sentry heartbeats (`COMPLIANT`, `UNREACHABLE`, `NON_COMPLIANT`), and instant device revocation.
- **Compliance & Auditing:** HMAC-chained audit logs with direct export to SIEMs like Splunk and Datadog.
- **ADR Security Benchmark (`agentcontrol bench`):** Built-in 303-task benchmark suite measuring security posture across 17 AI attack categories (prompt injection, exfiltration, SSRF, privilege escalation, etc.) with an A/B/C grade and an HTML report.

## Architecture

Agent Control is deployed in distinct modes depending on your operational needs:

1. **Workstation Security Gateway (`agentcontrol start` + `agentcontrol connect <target>`)**
   The recommended entry point for developers. Start the local daemon on `127.0.0.1:18080` (with embedded local dashboard and `~/.agentcontrol/audit.jsonl` log), then connect your AI IDEs (Cursor, Claude Desktop, Antigravity, Codex, etc.) with automated zero-touch configuration.

2. **Observation-Only Shadow Proxy (`agentcontrol start --shadow`)**
   Runs the local proxy in observation-only mode to log agent traffic and display live telemetry without active blocking.

3. **Centralized Enforcement Gateway (`agentcontrol start --centralized`)**
   A hardened gateway deployment that actively enforces security policies in a production or staging environment. It supports TLS, stateful sequence rules, and Zero-Downtime policy hot-reloading.

4. **Agent Identity Platform (`agentcontrol identity`)**
   A tool for provisioning short-lived, scoped credentials for agents to eliminate long-lived secret sprawl.

5. **ADR Security Benchmark (`agentcontrol bench`)**
   An offline benchmark runner that stress-tests the local gateway against 303 curated tasks across 17 attack categories, producing an HTML report with grades and per-category breakdowns.

## Support Matrix

| Category | Platform / Tool | Support Level | Transport / Interface | Notes |
|---|---|---|---|---|
| **OS** | Windows 10 / 11 (x86_64) | **Tier 1 (GA)** | Stdio, HTTP Loopback, WinService | Native PowerShell & CMD support |
| **OS** | macOS (Apple Silicon / ARM64) | **Tier 1 (GA)** | Stdio, HTTP Loopback, Launchd | Universal binary, Homebrew-compatible |
| **OS** | macOS (Intel / x86_64) | **Tier 1 (GA)** | Stdio, HTTP Loopback, Launchd | Full parity |
| **OS** | Linux (Ubuntu / Debian / RHEL / Arch) | **Tier 1 (GA)** | Stdio, HTTP Loopback, Systemd | AMD64 & AArch64 |
| **OS** | Windows Subsystem for Linux (WSL2) | **Tier 1 (GA)** | Stdio, HTTP Bridge | Automatic host browser launching |
| **IDE / Client** | Cursor | **Tier 1 (GA)** | MCP over Stdio / SSE | Zero-touch `agentcontrol connect cursor` |
| **IDE / Client** | Claude Desktop | **Tier 1 (GA)** | MCP over Stdio | Zero-touch `agentcontrol connect claude` |
| **IDE / Client** | Antigravity | **Tier 1 (GA)** | MCP over Stdio / SSE | Zero-touch `agentcontrol connect antigravity` |
| **IDE / Client** | Codex CLI | **Tier 1 (GA)** | MCP over Stdio | Zero-touch `agentcontrol connect codex` |
| **IDE / Client** | VS Code Continue | **Tier 1 (GA)** | MCP over Stdio | Automatic config injection |
| **Transport** | MCP JSON-RPC 2.0 (Stdio) | **Tier 1 (GA)** | Subprocess IPC | Full duplex filtering & Safe Mode |
| **Transport** | HTTP / HTTPS Reverse Proxy | **Tier 1 (GA)** | HTTP/1.1 & HTTP/2 | DLP inspection, TLS interception |
| **Transport** | Server-Sent Events (SSE) | **Tier 1 (GA)** | Streaming HTTP | Live event streaming & policy check |
| **Transport** | WebSocket Bridge | **Tier 2 (Beta)** | RFC 6455 | Stateful session proxy |

## Documentation Index

- **Documentation Hub:** [README.md](README.md)
- **10-Minute Developer Quickstart:** [quickstart.md](quickstart.md)
- **Platform Install Guides:** [macOS](install/macos.md) · [Linux](install/linux.md) · [WSL2](install/wsl.md) · [Windows PowerShell](install/windows-powershell.md) · [Windows CMD](install/windows-cmd.md)
- **Workflow Guides:** [Workstation Guide](guides/workstation.md) · [Custom Agent HTTP](guides/custom-agent-http.md) · [Small Team Hub](guides/small-team-hub.md)
- **Integrations:** [Integrations Matrix](integrations/README.md) · [Claude Desktop](integrations/claude-desktop.md) · [Cursor](integrations/cursor.md) · [Codex](integrations/codex.md) · [Antigravity](integrations/antigravity.md)
- **Reference:** [CLI Commands](reference/cli.md) · [Configuration & Env Vars](reference/configuration.md) · [Paths & State](reference/paths-and-state.md) · [Troubleshooting](reference/troubleshooting.md) · [Removal & Recovery](reference/removal-and-recovery.md) · [Legacy Migration](reference/legacy-migration.md) · [Release Notes Template](reference/release-notes-template.md)
- **Advanced & Enterprise:** [Team Operations](advanced/team-operations.md) · [OIDC](advanced/oidc.md) · [Kubernetes](advanced/kubernetes.md) · [SIEM](advanced/siem.md) · [Enterprise](advanced/enterprise.md)
- **Security Standards:** [OWASP Agentic Top 10 Specification](owasp_agentic_top10.md) · [ADR Security Benchmark](adr_benchmark.md)

