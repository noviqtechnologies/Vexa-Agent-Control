# Vexa Agent Control Licensing

**Last updated:** 4 October 2026  
**Primary License:** [Apache License 2.0](LICENSE)

---

## 1. Core Open-Source Engine (Apache-2.0)

The core Vexa Agent Control enforcement gateway, local workstation daemon, and developer CLI are licensed under the permissive **Apache License, Version 2.0**.

### What is 100% Free and Open Source Forever:
- **Local Workstation Protection:** Full runtime protection for developers using Cursor, Claude Desktop, Claude Code, OpenAI Codex, Windsurf, VS Code, and custom agent runtimes.
- **Deterministic Out-of-Process Gateway:** Local proxy on `127.0.0.1:18080` intercepting MCP stdio, HTTP, HTTPS, and streaming tool executions.
- **Security & DLP Scanners:** Safe Mode v1 rules, 6-pass prompt injection normalizer, response secret redaction, and cycle/loop prevention (`PivotError`).
- **Cryptographic Audit Log:** Cryptographically chained HMAC-SHA256 audit ledger (`audit.jsonl` and local `events.db`).
- **Developer CLI:** `agentcontrol start`, `stop`, `status`, `doctor`, `connect`, `disconnect`, `test`, and `verify`.
- **Zero Telemetry:** Local-first operation with zero phone-home calls or external cloud dependencies.

You may inspect, modify, run locally, and redistribute the core engine without payment, account creation, or proprietary licensing restrictions.

---

## 2. Team Hub & Fleet Governance

Team Hub provides centralized governance, policy distribution, fleet telemetry aggregation, and multi-device identity binding.

### Community / Small-Team Mode (Free)
- **Device Capacity:** Free for up to 50 enrolled developer devices during early access.
- **Identity:** Up to 2 concurrent OIDC Identity Providers (e.g. Google Workspace and GitHub SSO).
- **Central Management:** Web Console UI, dynamic policy push, shared spend budgets, and centralized audit search.

### Enterprise Fleet Governance (Commercial)
- Unlimited devices and agents across large enterprise organizations.
- Unlimited federated SSO / IdPs (Okta, Microsoft Entra ID, Ping, Keycloak).
- Automated compliance audit packages (SOC 2 Type II, ISO 27001, NIST AI RMF).
- High-availability deployment configurations and enterprise SLAs.

---

## 3. Summary Matrix

| Capability | Local Workstation (Core) | Small Team (Community) | Enterprise Fleet |
| :--- | :---: | :---: | :---: |
| **License** | Apache-2.0 | Free Community | Commercial |
| **Max Devices** | Unlimited (Local) | Up to 50 Devices | Unlimited |
| **Local Proxy Interception** | ✅ Included | ✅ Included | ✅ Included |
| **Deterministic Parameter DLP** | ✅ Included | ✅ Included | ✅ Included |
| **HMAC Chained Audit Trail** | ✅ Included | ✅ Included | ✅ Included |
| **CLI & Diagnostics (`doctor`)** | ✅ Included | ✅ Included | ✅ Included |
| **Central Fleet Policy Push** | N/A | ✅ Included | ✅ Included |
| **OIDC SSO Providers** | N/A | Up to 2 IdPs | Unlimited |
| **Compliance Export Packages** | Basic JSON/Markdown | Included | Automated & Attested |

For licensing inquiries, enterprise deployment support, or commercial partnerships, visit [vexasec.io](https://vexasec.io) or open an issue on GitHub.
