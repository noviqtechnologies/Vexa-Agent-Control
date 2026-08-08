# AgentWall Documentation

Welcome to the AgentWall technical documentation. 

AgentWall is an egress proxy and security gateway for AI agents operating over the Model Context Protocol (MCP), HTTP, HTTPS, and WebSocket connections. It intercepts, audits, and blocks unauthorized agent tool calls based on YAML-defined policies, and includes a built-in **AI Detection & Response (ADR)** benchmark to measure security posture against 17 real-world AI attack categories.

## What is AgentWall?

MCP (Model Context Protocol) is an open standard that allows AI models to securely connect to local and remote data sources and tools. As AI agents increasingly autonomously invoke tools, a robust security boundary is necessary. AgentWall acts as a firewall specifically designed for these MCP tool calls.

AgentWall intercepts outbound traffic from your agent, surfacing patterns in a local dashboard, and generates a YAML security policy draft based on observed behavior.

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
- **ADR Security Benchmark (`agentwall bench`):** Built-in 303-task benchmark suite measuring security posture across 17 AI attack categories (prompt injection, exfiltration, SSRF, privilege escalation, etc.) with an A/B/C grade and an HTML report.

## Architecture

AgentWall is deployed in distinct modes depending on your operational needs:

1. **Local Developer Proxy (`agentwall dev`)**
   A shadow proxy that runs locally on a developer's machine. It observes traffic, displays a local SQLite-backed dashboard at `http://127.0.0.1:8080` (with ADR Security Score Ring, Causal Trace Graph, Sequence Rule Alerts, and 1-Click Policy Synthesizer), and generates initial policy drafts automatically.

2. **Centralized Enforcement Gateway (`agentwall start`)**
   A hardened gateway deployment that actively enforces security policies in a production or staging environment. It supports TLS, stateful sequence rules, and Zero-Downtime policy hot-reloading.

3. **Agent Identity Platform (`agentwall identity`)**
   A tool for provisioning short-lived, scoped credentials for agents to eliminate long-lived secret sprawl.

4. **ADR Security Benchmark (`agentwall bench`)**
   An offline benchmark runner that stress-tests the local gateway against 303 curated tasks across 17 attack categories, producing an HTML report with grades and per-category breakdowns.

## Documentation Index

- [Detailed User Guide](user_guide.md)
- [Team & Staging Control Hub Guide](team_hub_guide.md)
- [AWS EKS Deployment & Uninstallation Guide](team_hub_guide/aws_eks_deployment.md)
- [OIDC Identity Binding & Auth Provider Guide](oidc_identity_binding.md)
- [Deployment & Installation](deployment.md)
- [Quickstart Guide](quickstart.md)
- [Comprehensive Functional Scenarios Guide](comprehensive_guide.md)
- [Configuration & Policies](configuration.md)
- [Ecosystem Integrations](integrations.md)
- [ADR Security Benchmark Guide](adr_benchmark.md)
