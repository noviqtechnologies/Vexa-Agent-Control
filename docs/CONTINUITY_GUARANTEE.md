# Continuity & Sovereign Independence Guarantee

For fast-growing AI startups, small engineering firms, and SMB engineering teams, adopting security infrastructure creates an understandable question:

> *"If we embed Vexa Agent Control into our developer workflows and AI pipelines, what happens to our operational capability if your company pivots, is acquired, or ceases operations?"*

This document provides our explicit, binding commitment to operational continuity, sovereign ownership, and zero vendor lock-in.

---

## 1. Perpetual & Irrevocable Open Source Core (Apache 2.0)

The foundation of Vexa Agent Control — including the Rust gateway engine, transparent MCP proxy firewall, inline DLP scanner, prompt injection defense, and local audit logging — is released under the **[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)**.

- **Irrevocable License:** Under Section 2 of the Apache 2.0 license, the grant of copyright and patent rights is perpetual, worldwide, non-exclusive, and irrevocable. No future corporate action can revoke or restrict your right to use, modify, distribute, or run any released version.
- **Permanent Availability:** Every released version, tag, and container image remains permanently accessible through open package registries and Git repositories.

---

## 2. Zero Phone-Home & Complete Offline Sovereignty

Unlike many modern security platforms that rely on continuous cloud licensing checks, **Vexa Agent Control requires zero remote connectivity to operate**:

- **No Remote Kill-Switches:** There are no phone-home pings, heartbeat verification endpoints, or remote license activation servers required for gateway operation.
- **Air-Gap Capable:** The gateway compiles to a single, self-contained binary (`agentcontrol`) that runs completely offline on developer laptops, local staging machines, or air-gapped VPCs.
- **Local State & Keys:** All policies, local audit trails, and virtual key hashes are evaluated and stored directly on your hardware.
- **Operational Durability:** If Vexa's cloud servers or domains become unavailable, **your deployed gateways, IDE sentries, and LLM proxies continue functioning without interruption or performance penalty**.

---

## 3. Self-Hosting & Portability Guarantee

Your AI workflows must never become hostage to proprietary cloud dependencies:

- **Standard Open Infrastructure:** The team control plane and database run entirely on standard open-source components (PostgreSQL, Valkey/Redis, Docker Compose, and Kubernetes Helm charts).
- **Zero Proprietary Lock-In:** You can spin up, back up, migrate, and maintain the entire platform within your own AWS, GCP, Azure, or on-premise infrastructure at any time.
- **Portable Event Formats:** Audit logs conform to the standard [Canonical Event Envelope v1](canonical-event-envelope-v1.md) in JSON Lines (`audit.jsonl`), ensuring immediate portability to any SIEM (Splunk, Datadog, OpenSearch) or data lake without specialized extractors.

---

## 4. Source-Available Transparency for Team Extensions

For team and centralized components:
- **Full Source Access:** Code for team orchestration, sync protocols, and policy distribution is openly viewable in this repository.
- **Freedom to Fork & Maintain:** In the event that Noviq Technologies / Vexa ever discontinues active development or support, your engineering organization possesses the full source tree necessary to build, patch, and maintain custom builds internally.

---

## 5. Summary Matrix: Risk vs. Mitigant

| Buyer Concern | Typical Vendor Reality | The Vexa Guarantee |
|---|---|---|
| **Vendor Insolvency / Pivot** | Cloud service shuts down; gateways brick or stop routing. | **100% Autonomous.** Core binaries require zero external pings and function indefinitely. |
| **License Price Hikes / Hostage** | Vendor changes pricing; features locked behind paywalls. | **Apache-2.0 Foundation.** Existing versions remain free, open, and forkable forever. |
| **Data & Telemetry Privacy** | Vendor ingests internal prompts and tool calls for "analytics." | **Zero Telemetry.** Prompts and keys remain exclusively inside your VPC / machine. |
| **Audit Log Longevity** | Proprietary log formats tied to vendor dashboard. | **Open Standard JSONL.** HMAC hash-chained logs are locally verifiable offline via `agentcontrol verify-log`. |

---

*For questions or custom enterprise compliance inquiries, please contact [`contact@vexasec.io`](mailto:contact@vexasec.io).*
