# Vexa Agent Control

> **The Sovereign Security & Governance Control Plane for AI Coding Agents.**  
> Govern Cursor, Claude Code, Windsurf, Codex, and MCP tool workflows with sub-millisecond latency, broker-held credential custody, and cryptographically verifiable audit trails.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Release](https://img.shields.io/badge/release-v1.0.95-green.svg)](https://github.com/noviqtechnologies/Vexa-Agent-Control/releases)
[![Build Status](https://img.shields.io/badge/CI-Gates%200--4%20PASS-brightgreen.svg)](.github/workflows/ci.yml)
[![Security Policy](https://img.shields.io/badge/security-NIST%20AI%20RMF%20%7C%20ISO%2042001-blueviolet.svg)](enterprise/compliance/NIST-AI-RMF-MAPPING.md)

---

## Why Enterprise CISOs, AI Companies & SMBs Deploy Vexa

Autonomous coding assistants and tool-calling agents possess file system access, terminal execution authority, and outbound data egress. Security, GRC, and platform teams require answers to critical governance questions:

- **Data Leak Prevention (DLP):** How do we stop agents from reading `.env`, `~/.aws/credentials`, or proprietary source code and exfiltrating them to model providers?
- **Prompt Injection Defense (OWASP LLM01):** How do we prevent untrusted web content or pull requests from hijacking autonomous agent workflows?
- **Non-Bypassable Enforcement:** How do we guarantee developers cannot simply disable or route around the local proxy?
- **Compliance & Forensics:** How do we prove to external auditors (SOC 2, ISO 42001, EU AI Act) what data was sent to LLMs and what actions were blocked?

Vexa Agent Control is an ultra-fast, zero-trust policy engine and sovereign control plane designed specifically to solve these challenges without disrupting developer productivity.

---

## Core Capabilities

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   VEXA ARCHITECTURAL HIGHLIGHTS                                 │
├──────────────────────────┬──────────────────────────────────────────────────────────────────────┤
│ ⚡ Sub-Millisecond Core   │ Native Rust proxy evaluating regex DLP, parameter schemas, and       │
│                          │ prompt injection heuristics in <1ms p99 latency overhead.            │
├──────────────────────────┼──────────────────────────────────────────────────────────────────────┤
│ 🔑 Credential Custody    │ Upstream API keys (Anthropic, OpenAI, Azure) never touch developer   │
│                          │ workstations. Bypassing the gateway results in 401 Unauthorized.     │
├──────────────────────────┼──────────────────────────────────────────────────────────────────────┤
│ 📜 Cryptographic Audit   │ HMAC-SHA256 chained ledger with fail-closed fsync writes, creating a │
│                          │ tamper-evident, append-only forensic record of every action.         │
├──────────────────────────┼──────────────────────────────────────────────────────────────────────┤
│ 🛡️ Multi-OS Deployment   │ Turnkey enterprise packaging for Microsoft Intune (Windows), Jamf     │
│                          │ Pro (macOS), systemd (Linux), and Kubernetes Helm.                   │
├──────────────────────────┼──────────────────────────────────────────────────────────────────────┤
│ 🔒 100% Sovereign & Pure │ Zero external telemetry. No phone-home pings. All prompts, code, and │
│                          │ policies remain strictly within your organizational perimeter.       │
└──────────────────────────┴──────────────────────────────────────────────────────────────────────┘
```

---

## 2-Minute Quickstart (Evaluation Mode)

Evaluate Vexa Agent Control locally on your workstation in under two minutes:

### 1. Download & Verify

**Linux / macOS:**
```bash
# Download and install release binary (v1.0.95)
curl -fL --proto '=https' --tlsv1.2 \
  https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/v1.0.95/install/install.sh \
  -o install.sh && bash install.sh --version v1.0.95

export PATH="$HOME/.local/bin:$PATH"
agentcontrol --version
```

**Windows (PowerShell 5.1+):**
```powershell
$installer = Join-Path $env:TEMP 'vexa-install.ps1'
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/v1.0.95/install/install.ps1' -OutFile $installer
& $installer -Version 'v1.0.95'
agentcontrol.exe --version
```

### 2. Start Standalone Gateway
```bash
# Start the local gateway in standalone mode
agentcontrol start --standalone

# Connect your preferred coding assistant
agentcontrol connect cursor
```

### 3. Verify Enforcement
Inspect real-time policy decisions, DLP redactions, and audit records in the local dashboard at:  
👉 **`http://127.0.0.1:18080`**

---

## Architecture & Zero-Trust Boundary Model

Vexa operates on **Zero Trust Architecture principles (NIST SP 800-207)**: the developer workstation is treated as an untrusted edge node, and the control plane / gateway functions as the Policy Enforcement Point (PEP).

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   VEXA ENTERPRISE TOPOLOGY                                       │
├──────────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                                  │
│  Developer Workstation (Windows / macOS / Linux)                                                 │
│  ┌─────────────────────────┐          stdio / HTTP                                               │
│  │ Coding Assistants       │ ──────────────────────────────┐                                     │
│  │ (Cursor / Claude / MCP) │                               │                                     │
│  └─────────────────────────┘                               ▼                                     │
│                                           ┌──────────────────────────────────┐                   │
│                                           │ Vexa Agent Control Local Sentry  │                   │
│                                           │ • Inline Parameter DLP Scanner   │                   │
│                                           │ • Prompt Injection Guard (Pass 6)│                   │
│                                           │ • HMAC-SHA256 Audit Ledger       │                   │
│                                           └──────────────────────────────────┘                   │
│                                                            │                                     │
│                                                            │ mTLS / Signed Sync                  │
│                                                            ▼                                     │
│  Customer Perimeter / Cloud Enclave       ┌──────────────────────────────────┐                   │
│                                           │ Vexa Control Hub & Key Broker    │                   │
│                                           │ • Central Policy Distribution    │                   │
│                                           │ • Vault / KMS Credential Custody │                   │
│                                           │ • Splunk / Datadog SIEM Streams  │                   │
│                                           └──────────────────────────────────┘                   │
│                                                            │                                     │
│                                                            │ Upstream Provider Call              │
│                                                            ▼                                     │
│                                           ┌──────────────────────────────────┐                   │
│                                           │ AI Foundation Model Providers    │                   │
│                                           │ (Anthropic, OpenAI, Azure, Bedrock)                  │
│                                           └──────────────────────────────────┘                   │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### Why Credential Custody Eliminates Proxy Bypasses
In traditional proxy solutions, developers can bypass controls by pointing their tools directly at external endpoints. Vexa eliminates this bypass vector cryptographically:
1. Master API keys (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`) reside exclusively in the **Vexa Control Hub** or corporate KMS/Vault.
2. Developer workstations are only provisioned with short-lived, locally bound virtual credentials.
3. If an unmanaged script or developer attempts to bypass the gateway and contact `api.anthropic.com` directly, the call is rejected by the provider (`401 Unauthorized`).

---

## Enterprise MDM & Fleet Deployment

Turnkey packages for centralized, automated rollouts across your fleet:

- 🪟 **Windows (Microsoft Intune / MECM):** [Intune-Install.ps1](enterprise/deploy/windows/Intune-Install.ps1) — installs as a resilient Windows System Service, configures proxy registry keys, and enables fail-safe recovery.
- 🍏 **macOS (Jamf Pro / Kandji / Fleet):** [jamf-install.sh](enterprise/deploy/macos/jamf-install.sh) & [io.vexasec.agentcontrol.plist](enterprise/deploy/macos/io.vexasec.agentcontrol.plist) — registers a managed system LaunchDaemon with Keychain secret custody.
- 🐧 **Linux (systemd):** [install-systemd.sh](enterprise/deploy/linux/install-systemd.sh) & [agentcontrol.service](enterprise/deploy/linux/agentcontrol.service) — installs a hardened systemd unit with `DynamicUser` and read-only system sandboxing.
- ☸️ **Kubernetes & Cloud Ingress:** [Docker Compose](docker-compose.team.secure.yml) & [Helm Chart](chart/) — deploy high-throughput sidecars or reverse proxies for AI SaaS swarms.

---

## Capability Maturity Matrix

To uphold total transparency, every engine capability is categorized by maturity level and verified by automated CI test suites:

| Capability | Module Path | Maturity Level | Verification Test Suite |
|---|---|---|---|
| **In-Line Parameter DLP Redaction** | `src/policy/dlp.rs` | **Stable (Production)** | Gates 0–4 Automated Tests (20+ pattern classes) |
| **Tamper-Evident HMAC Audit Chain** | `src/audit/logger.rs` | **Stable (Production)** | Gate 1 Cryptographic Fsync & Continuity Tests |
| **Exact-Action HITL Approval Machine** | `src/policy/hitl.rs` | **Stable (Production)** | Concurrency Double-Spend Prevention Tests |
| **Tool Parameter Traversal Guard** | `src/policy/command_policy.rs`| **Stable (Production)** | UNC / Symlink / Traversal Test Suites |
| **Multi-Turn Session Taint Engine** | `src/policy/taint.rs` | **Beta** | Multi-Turn Toxic Flow E2E Regression Suite |
| **Virtual Key Credential Broker** | `control-plane/api/internal/broker/` | **Beta** | Cross-Platform Handshake & Spend Ledger Tests |
| **Causal Threat Reasoning Analyzer** | `src/detector/mod.rs` | **Labs (Experimental)** | Out-of-band audit trace heuristic evaluator |

---

## Compliance & GRC Evidence Mappings

Export structured, audit-ready compliance evidence binders directly from the CLI:

- 🏛️ **[NIST AI RMF 1.0 Mapping](enterprise/compliance/NIST-AI-RMF-MAPPING.md):** Full coverage across GOVERN, MAP, MEASURE, and MANAGE functions.
- 📜 **[ISO/IEC 42001:2023 Mapping](enterprise/compliance/ISO-42001-MAPPING.md):** Annex A controls for AI Risk Management Systems (AIMS).
- 🇪🇺 **[EU AI Act Mapping](enterprise/compliance/EU-AI-ACT-MAPPING.md):** Compliance crosswalk for Articles 12, 13, 14, 15, and 50.
- 🛡️ **SOC 2 Type II:** Logical access controls (CC6.1, CC6.6, CC6.7) and change management tracking.

---

## Licensing & Tiers

| Capability | Local Workstation (Core) | Community / SMB Team | Enterprise Fleet |
|---|:---:|:---:|:---:|
| **License** | **Apache 2.0 (Open Source)** | **Free Community** | **Commercial** |
| **Device Capacity** | Unlimited (Local) | Up to 50 Devices | Unlimited |
| **Deterministic Gateway Core** | ✅ Included | ✅ Included | ✅ Included |
| **In-Line DLP & Secret Redaction**| ✅ Included | ✅ Included | ✅ Included |
| **HMAC Chained Audit Ledger** | ✅ Local JSONL | ✅ Aggregated | ✅ Central Splunk/Datadog Sync |
| **Spend Caps & Budget Quotas** | Local Ledger | ✅ Central Management | ✅ Multi-Org Hierarchical Budgets |
| **Identity & SSO** | Local OS Token | 2 OIDC IdPs | Unlimited SAML 2.0 / OIDC (Okta/Entra) |
| **Credential Custody** | DPAPI / Keychain | Central SQLite Vault | HashiCorp Vault / AWS KMS / Azure CMK |
| **Compliance Export Packages** | Basic Markdown | Included | Attested PDF / Registrars Dossiers |
| **Deployment Support** | Community GitHub | Discord / Community | Dedicated Architect & 24/7 SLA |

Review [LICENSE](LICENSE) and [LICENSING.md](LICENSING.md) for full terms.

---

## Community & Security Reporting

- 🐞 **Issue Tracker:** [GitHub Issues](https://github.com/noviqtechnologies/Vexa-Agent-Control/issues)
- 🔒 **Security Disclosures:** Follow [SECURITY.md](SECURITY.md) to report vulnerabilities privately via GitHub Security Advisories or [`contact@vexasec.io`](mailto:contact@vexasec.io).
- 🏢 **Commercial Inquiries:** Visit [vexasec.io](https://vexasec.io) or email [`contact@vexasec.io`](mailto:contact@vexasec.io).