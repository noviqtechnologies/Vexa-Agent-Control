# Changelog

All notable changes to **Vexa Agent Control** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased] (Target: v1.1.0)

---

## [1.0.84] - 2026-09-16

### Added
- **Standalone Workstation Quickstart & Zero-Cloud Journey:** Refactored developer onboarding across all documentation (`README.md`, `user_guide.md`, `quickstart.md`, and platform installation guides) to provide zero-cloud, zero-Docker local evaluation with autonomous `local.token` generation (`~/.agentcontrol/local.token`) and embedded local developer dashboard (`http://127.0.0.1:18080`).
- **Windows Background Sentry Hardening:** Enhanced `install_windows_service` in `src/service/windows.rs` with hidden-window execution (`-WindowStyle Hidden`), reliable multi-instance scheduled task settings, and robust daemon process verification.
- **Virtual Key Scoping & Wildcard Model Matching:** Enhanced `LocalKeyCache` in `src/proxy/local_key_cache.rs` with case-insensitive model scoping, wildcard prefix validation (`m*`), and improved fallback token handling.
- **Broker Client & Remote Key Auth Resilience:** Added robust fallback token resolution in `src/proxy/broker_client.rs` and `src/policy/remote_keys.rs` prioritizing assertion headers, `GATEWAY_SECRET`, and `AGENTCONTROL_ADMIN_TOKEN`.
- **Multi-OS User Guides & Docker Quickstart:** Updated cross-platform install guides (Windows PowerShell, Windows CMD, macOS, Linux, WSL2) and Docker Quickstart with explicit copy-paste commands and `.env` initialization.

---

## [1.0.83] - 2026-09-15

### Added
- **Multi-Tenant Hub Hardening & Device Auth Middleware:** Enhanced fleet security with OAuth PKCE authorization flows and device authentication middleware.
- **Diagnostics & Troubleshooting Suite:** Added deep system diagnostics and doctor command suite for workstations and control plane.
- **Enterprise Spend Cap & FinOps Testing Suite:** Integrated comprehensive FinOps quota, budget cap, and fallback verification tests.
- **MCP Proxy Isolation & Manifest Reversals:** Hardened MCP bidirectional interception, authority parser, and loopback security boundaries.

---

## [1.0.82] - 2026-09-09

### Added
- **Threat Intelligence DLP Telemetry Forwarding:** Mapped runtime DLP findings (`req_dlp_findings`) and prompt injection findings to control-plane protobuf telemetry payloads (`RawEventForRedaction`), enabling real-time violation tracking, timeline charting, and top-signature ranking in the Team Hub Threat Intelligence console.
- **Observability & Logs Security Tab:** Integrated the comprehensive Security & DLP Audit Log view (`AuditLogs.tsx`) directly into the Observability & Logs dashboard (`/observability/logs`), surfacing tool execution records, verdicts (`allowed`/`denied`/`warned`), DLP findings count, and raw event telemetry inspector.
- **Semantic Caching Engine Enhancements:** In-memory and persistent semantic vector cache enhancements, cosine similarity threshold verification, cache invalidation, and metrics telemetry.
- **Direct Proxy Bypass Security Model:** Added formal threat model and verification tests for proxy bypass prevention and credential boundary protection.

---

## [1.0.81] - 2026-09-09

### Added
- **Repository Trust Signals:** Added formal `SECURITY.md` vulnerability disclosure policy with committed response SLAs (contact@vexasec.io).
- **Architecture Domain Code Ownership:** Added `.github/CODEOWNERS` defining domain ownership across core engine, control plane, security classifiers, and infra.
- **Contributor Standards:** Added `CONTRIBUTING.md` defining contributor workflow, DCO sign-off, and SemVer PR labeling.
- **Continuity & Sovereign Guarantee:** Added `docs/CONTINUITY_GUARANTEE.md` articulating perpetual Apache-2.0 open-source independence and zero-phone-home sovereignty for SMBs and AI engineering teams.
- **Audit Log Threat Model:** Added `docs/security/audit-threat-model.md` explicitly detailing cryptographic boundaries between Local Mode (accidental/casual tamper detection) and Central Mode (tamper resistance against workstation compromise).
- **Release Governance:** Added `docs/reference/versioning-and-releases.md` formalizing SemVer 2.0.0 rules (patches = fixes & docs only, minor = additive features).

---

## [1.0.80] - 2026-09-08

### Added
- **Spend Event Writer Backpressure & Retry:** Bounded asynchronous channel and exponential backoff retry mechanics for high-throughput spend events.
- **Deployment Region Affinity:** Regional routing hints for multi-region LLM proxies.
- **Shared Scanner Initialization:** Shared in-memory DFA compilation for DLP pattern matchers to reduce memory overhead across gateway worker threads.

### Security
- **Scheduler Introspection Hardening:** Restricted internal scheduler diagnostic endpoints to localhost loopback interfaces.

---

## [1.0.79] - 2026-09-08

### Added
- **Codex Desktop Integration:** Automatic discovery, wrapper injection, and boundary enforcement for ChatGPT Codex Desktop clients.
- **5-Point Desired-State Verification Probe:** Automated health diagnostic verifying transparent proxy interception, MCP firewall binding, DLP filtering, budget checks, and HMAC audit chaining.
- **Assignment Attributions:** Bound virtual key usage metrics directly to team member OIDC claims.

### Security
- **Responses API Reasoning Sanitizer:** Inline redaction filter targeting reasoning and thought tokens to prevent credential leaks in deep reasoning model streams.

---

## [1.0.78] - 2026-09-07

### Added
- **Virtual Keys Management Engine:** Generation, rotation, and revocation of deterministic virtual API keys mapping upstream credentials to internal cost centers.
- **Provider Routing Matrix:** Weighted and fallback routing across OpenAI, Anthropic, Gemini, Groq, and custom OpenAI-compatible endpoints.
- Client integration guides for Cursor, Claude Desktop, and custom Python HTTP agents.

---

## [1.0.77] - 2026-09-07

### Added
- Interactive web UI responsive layout refinements and mobile breakpoint support.
- Platform installer improvements for PowerShell on Windows 11 and headless Linux environments.

### Changed
- Login UX optimization: Simplified first-run local dashboard authentication flow.

---

## [1.0.76] - 2026-09-07

### Added
- **Enterprise Semantic Vector Caching Engine:** Dual-tier cache combining exact SHA-256 matching and cosine similarity vector retrieval with partitioned in-memory cosine-similarity caching and optional external Qdrant backends.
- **Team Hub Sync Architecture:** Real-time policy push and event aggregation via Server-Sent Events (SSE).
- Updated pricing tables for frontier LLM models (GPT-4o, Claude 3.5 Sonnet, Gemini 1.5 Pro).
- Interactive Policy UI enhancements: Live rule simulator and active rule toggle switches.

---

[Unreleased]: https://github.com/noviqtechnologies/Vexa-Agent-Control/compare/v1.0.84...HEAD
[1.0.84]: https://github.com/noviqtechnologies/Vexa-Agent-Control/compare/v1.0.83...v1.0.84
[1.0.83]: https://github.com/noviqtechnologies/Vexa-Agent-Control/compare/v1.0.82...v1.0.83
[1.0.82]: https://github.com/noviqtechnologies/Vexa-Agent-Control/compare/v1.0.81...v1.0.82
[1.0.81]: https://github.com/noviqtechnologies/Vexa-Agent-Control/compare/v1.0.80...v1.0.81
[1.0.80]: https://github.com/noviqtechnologies/Vexa-Agent-Control/compare/v1.0.79...v1.0.80
[1.0.79]: https://github.com/noviqtechnologies/Vexa-Agent-Control/compare/v1.0.78...v1.0.79
[1.0.78]: https://github.com/noviqtechnologies/Vexa-Agent-Control/compare/v1.0.77...v1.0.78
[1.0.77]: https://github.com/noviqtechnologies/Vexa-Agent-Control/compare/v1.0.76...v1.0.77
[1.0.76]: https://github.com/noviqtechnologies/Vexa-Agent-Control/releases/tag/v1.0.76
