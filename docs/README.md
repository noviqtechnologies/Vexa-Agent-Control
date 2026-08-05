# Vexa AgentWall Documentation

**This directory contains the primary technical documentation, architecture specifications, deployment guides, and integration references for Vexa AgentWall.**

New here? Start with the [Quickstart Guide](quickstart.md), then explore the [User Guide](user_guide.md) and [System Architecture](agentwall_architecture.md).

## Documentation Index

| Guide / Specification | What it covers |
|---|---|
| [quickstart.md](quickstart.md) | Step-by-step tutorial for securing local MCP servers, Claude Desktop, and Cursor IDE. |
| [user_guide.md](user_guide.md) | Comprehensive operational user guide covering configuration, policy engine, DLP tuning, and identity binding. |
| [deployment.md](deployment.md) | Step-by-step installation & operation for macOS, Linux, Windows, Docker Compose, Kubernetes, and HAR containers. |
| [configuration.md](configuration.md) | Deep-dive configuration reference for Schema v2 policy files, DLP regex, spend caps, and environment variables. |
| [oidc_identity_binding.md](oidc_identity_binding.md) | OIDC identity provider integration guide (Okta, Keycloak, Entra ID, Auth0, AWS Cognito, PingIdentity). |
| [agentwall_architecture.md](agentwall_architecture.md) | Detailed system architecture specification, 6-pass security pipeline, and component interaction flows. |
| [comprehensive_guide.md](comprehensive_guide.md) | Command-line walkthroughs and scenario tutorials across all core security capabilities. |
| [adr_benchmark.md](adr_benchmark.md) | ADR (AI Detection & Response) security benchmark suite reference (303 tasks across 17 attack classes). |
| [integrations.md](integrations.md) | Ecosystem integrations guide for IDE wrappers, stdio proxies, Vault adapters, and SIEM exporters. |
| [index.md](index.md) | Centralized Documentation Hub index. |

## The Rule for Updating Documentation

A code change that alters documented behavior, policy schemas, or runtime APIs MUST update the corresponding documentation in `docs/` **in the same pull request**.
