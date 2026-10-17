# Vexa Agent Control Runtime Enforcement Pilot — Results & Evidence Report

**Document Reference:** `result/windows/20261017_125024/pilot-results-windows-20261017_125024.md`  
**Target Plan:** `PRD/pending/vexa-runtime-enforcement-pilot-plan.md`  
**Target OS Platform:** Windows 10/11 & Server (x86_64 / arm64)  
**Host Environment:** Windows (POSIX layer: MINGW64_NT-10.0-26300)  
**Execution Timestamp:** 2026-10-17T08:50:24Z  
**Execution Duration:** 2s  
**Test Suite:** `tests/runtime_enforcement_pilot_test.rs`  
**Overall Status:** **PASSED (11/11 TESTS PASSED — 100% VERIFIED)**

---

## Executive Summary

The Vexa Agent Control Runtime Enforcement Pilot was successfully executed on Windows in an isolated, synthetic sandbox environment. Prohibited actions were stopped before reaching downstream endpoints (asserting 0 side-effect calls), permitted actions executed cleanly with low latency, identity groups and revocations propagated deterministically, signed Ed25519 policies were acknowledged, and outbox spooling survived SIEM interruptions without audit loss.

Platform Primitives Validated: Windows Named Pipes (`\\.\pipe\agentcontrol`), Windows Security Identifiers (SIDs), Case-Insensitive NTFS/ReFS  
Canary Path Fixtures: `C:\Users\Developer\.ssh\id_rsa and \\corp-share\confidential.txt`

---

## Master Results Tracker (§8)

| Test ID | UTC Timestamp | Identity | Agent / Client | Tool / Target | Policy Version | Expected Result | Vexa Result | Destination Result | SIEM Result | Status |
|---|---|---|---|---|---|---|---|---|---|---|
| **T0** | 2026-10-17T08:50:24Z | `pilot-allowed` | `pilot-agent-01` | `fixture_read_file` & `/canary/read` | Rev 1 | Both calls succeed; 3-way correlation confirmed | **ALLOW** | 1 read executed | Ingested cleanly | **PASS** |
| **T1** | 2026-10-17T08:50:24Z | `pilot-allowed` | `pilot-agent-01` | `fixture_admin_status` | Rev 1 | Blocked before dispatch; tool server sees 0 calls | **DENY** (`default_deny`) | **0 calls** (not executed) | Ingested `tool_deny` | **PASS** |
| **T2** | 2026-10-17T08:50:24Z | `pilot-allowed` | `pilot-agent-01` | `C:\Users\Developer\.ssh\id_rsa & \\corp-share\confidential.txt` | Rev 1 | Traversal blocked; marker withheld from response | **WITHHELD** (`ResponseWithheld`) | 0 marker disclosure | Secret withheld | **PASS** |
| **T3** | 2026-10-17T08:50:24Z | `pilot-allowed` | `pilot-agent-01` | `canary_write` (`target=system_config`) | Rev 1 | Denied on invalid target; 0 ledger writes | **DENY** (`param_pattern_mismatch`) | **0 writes** (ledger empty) | Ingested `tool_deny` | **PASS** |
| **T4** | 2026-10-17T08:50:24Z | `sub-pilot-01` vs `sub-02` | `pilot-agent-01` | `fixture_read_file` | Rev 1 | `corp-engineers` allowed; `contractors` denied | `sub-01`: **ALLOW**<br>`sub-02`: **DENY** | 1 call vs 0 calls | Both claims logged | **PASS** |
| **T5** | 2026-10-17T08:50:24Z | `pilot-allowed` | `pilot-agent-01` | `fixture_read_file` | Rev 1 | Allowed pre-revocation; denied immediately post-revocation | Pre: **ALLOW**<br>Post: **DENY** (`revoked_agent`) | Post-rev: **0 new calls** | Revocation logged | **PASS** |
| **T6** | 2026-10-17T08:50:24Z | `pilot-allowed` | `pilot-agent-01` | `fixture_canary_action` | Rev 1 -> Rev 2 (Ed25519) | Allowed under Rev 1; Denied under Rev 2 after signed update | Rev 1: **ALLOW**<br>Rev 2: **DENY** | Rev 1: 1 call<br>Rev 2: 0 calls | Policy Rev 2 logged | **PASS** |
| **T7** | 2026-10-17T08:50:24Z | `pilot-allowed` | Direct test process | `/api/v1/canary/read` | Rev 1 | Routed call governed; direct call exposes boundary gap | Routed: **Governed**<br>Direct: **Unrouted** | Direct call executed | Unrouted bypass noted | **PASS** (Boundary Verified) |
| **T8** | 2026-10-17T08:50:24Z | `pilot-allowed` | `pilot-agent-01` | `canary_write` | Interrupted (No Policy) | Deterministic fail-closed; zero unverified replays | **DENY** (fail-closed) | **0 writes** (ledger untouched) | Outage alert logged | **PASS** |
| **T9** | 2026-10-17T08:50:24Z | `pilot-allowed` | `pilot-agent-01` | Multi-action batch | Rev 1 | SQLite WAL spooling during SIEM outage; 100% replay | **SPOOLED** (SQLite WAL) | Harmless ops proceed | **100% replayed** | **PASS** |
| **T10** | 2026-10-17T08:50:24Z | Auditor (`read-only`) | Forensic Tool | Audit log file | Rev 1 | HMAC chain valid; single-byte tamper flagged; read-only access | Clean: **VALID**<br>Corrupt: **INVALID** (idx 1) | N/A (audit check) | HMAC verified | **PASS** |

---

## Boundary Limit & Compensating Network Controls (T7)

- **Application Layer Scope:** Vexa functions as an application-level proxy for MCP and IDE traffic.
- **Identified Direct Bypass:** Direct TCP/HTTP traffic from arbitrary host processes that do not configure proxy environment variables bypasses Vexa.
- **Mandatory Compensating Control on Windows:** Pair workstation Vexa deployments with Windows Filtering Platform (WFP) rules or Windows Defender Firewall packet redirection to enforce all loopback egress through Vexa.

---

## Audit Disposition (§9)

**Final Verdict:** **CONDITIONAL GO FOR CONTROLLED WORKSTATION PILOT**
