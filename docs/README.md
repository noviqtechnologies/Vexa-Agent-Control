# Vexa Agent Control Documentation

**This directory contains the primary technical documentation, architecture specifications, deployment guides, and integration references for Vexa Agent Control.**

New here? Start with the [Quickstart Guide](quickstart.md), then choose your deployment profile guide below.

## Profile-Specific User Guides

These are the primary entry points for operators at each deployment tier. Each guide is self-contained for its profile and links to the [Common Reference Guide](common_guide.md) for shared topics.

| Guide | Target Audience | What it covers |
|---|---|---|
| [user_guide.md](user_guide.md) | All users — start here | Navigation hub: profile selector, capabilities matrix, and links to all guides |
| [workstation_guide.md](workstation_guide.md) | Individual developers | Local binary install, shadow mode, safe-mode rules, prompt injection, DLP, IDE wrapping, ADR benchmark, MCP scan |
| [team_hub_guide.md](team_hub_guide.md) | DevOps & Engineering leads | Docker Compose control hub, centralized policy push (SSE), OIDC binding, vault custody, HITL queue, spend caps, SIEM export |
| [enterprise_guide.md](enterprise_guide.md) | Platform & Security engineers | Kubernetes Helm deployment, HAR sidecar runtime, WebSocket tunneling, threat intel feed, zero-knowledge CMK encryption, pure-Rust TLS |
| [common_guide.md](common_guide.md) | All users — reference | YAML policy v2 schema, all 21 DLP detectors, OIDC setup, audit log verification, sequence rules, ADR benchmark, env vars, troubleshooting |

## Technical Reference & Specialist Guides

| Guide / Specification | What it covers |
|---|---|
| [quickstart.md](quickstart.md) | Step-by-step tutorial for securing local MCP servers, Claude Desktop, and Cursor IDE |
| [owasp_agentic_top10.md](owasp_agentic_top10.md) | **OWASP Top 10 for Agentic Applications (ASI 2026)** architectural security mapping, evidence, and mitigations |
| [compliance_mapping.md](compliance_mapping.md) | Multi-framework compliance mapping (OWASP ASI 2026, SOC 2, ISO 27001, NIST AI RMF) |
| [oidc_identity_binding.md](oidc_identity_binding.md) | OIDC identity provider integration guide (Okta, Keycloak, Entra ID, Auth0, AWS Cognito, PingIdentity) |
| [adr_benchmark.md](adr_benchmark.md) | ADR (AI Detection & Response) security benchmark suite reference (303 tasks across 17 attack classes) |
| [agentwall_architecture.md](agentwall_architecture.md) | Detailed system architecture specification, 6-pass security pipeline, and component interaction flows |
| [configuration.md](configuration.md) | Deep-dive configuration reference for Schema v2 policy files, DLP regex, spend caps, and environment variables |
| [deployment.md](deployment.md) | Step-by-step installation & operation for macOS, Linux, Windows, Docker Compose, Kubernetes Helm, and HAR containers |
| [integrations.md](integrations.md) | Ecosystem integrations guide for IDE wrappers, stdio proxies, Vault adapters, and SIEM exporters |
| [comprehensive_guide.md](comprehensive_guide.md) | Command-line walkthroughs and scenario tutorials across all core security capabilities |
| [index.md](index.md) | Centralized Documentation Hub index |

## The Rule for Updating Documentation

A code change that alters documented behavior, policy schemas, or runtime APIs MUST update the corresponding documentation in `docs/` **in the same pull request**.

When adding capabilities to a specific deployment profile, update both the relevant profile guide (`workstation_guide.md`, `team_hub_guide.md`, or `enterprise_guide.md`) **and** the capabilities matrix in `user_guide.md`.

