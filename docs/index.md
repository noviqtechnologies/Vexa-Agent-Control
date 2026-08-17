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

1. **One-Command Full Protection (`agentcontrol protect`)**
   The recommended entry point for developers. A single command auto-generates a baseline `agentcontrol-policy.yaml` (with P0 DLP secret rules), discovers and atomically wraps all installed AI IDEs (Cursor, Claude Desktop, VS Code, JetBrains, Zed, Cline, OpenCode, Antigravity, Codex), starts the local gateway proxy on `127.0.0.1:8080` (audit log: `~/.agentcontrol/audit.jsonl`), and opens the local dashboard. `agentcontrol init` is deprecated in favour of this command.

2. **Observation-Only Shadow Proxy (`agentcontrol protect --shadow`)**
   Runs the local proxy in observation-only mode to log agent traffic and display live telemetry without active blocking. Note: `agentcontrol dev` is deprecated in favor of `agentcontrol protect` and `agentcontrol protect --shadow`.

3. **Centralized Enforcement Gateway (`agentcontrol start`)**
   A hardened gateway deployment that actively enforces security policies in a production or staging environment. It supports TLS, stateful sequence rules, and Zero-Downtime policy hot-reloading.

4. **Agent Identity Platform (`agentcontrol identity`)**
   A tool for provisioning short-lived, scoped credentials for agents to eliminate long-lived secret sprawl.

5. **ADR Security Benchmark (`agentcontrol bench`)**
   An offline benchmark runner that stress-tests the local gateway against 303 curated tasks across 17 attack categories, producing an HTML report with grades and per-category breakdowns.

## Documentation Index

- [Master User Guide](user_guide.md)
- [Workstation Sidecar User Guide](workstation_guide.md)
- [Team & Staging Control Hub Guide](team_hub_guide.md)
- [Enterprise Fleet Production Guide](enterprise_guide.md)
- [Common Reference Guide](common_guide.md)
- [OIDC Identity Binding & Auth Provider Guide](oidc_identity_binding.md)
- [Deployment & Installation](deployment.md)
- [Quickstart Guide](quickstart.md)
- [Comprehensive Functional Scenarios Guide](comprehensive_guide.md)
- [Configuration & Policies](configuration.md)
- [Ecosystem Integrations](integrations.md)
- [ADR Security Benchmark Guide](adr_benchmark.md)
- [OWASP Agentic Top 10 Specification](owasp_agentic_top10.md)
