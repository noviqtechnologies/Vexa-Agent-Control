# Agent Control — Compliance Evidence Collection & Technical Controls Guide

This document maps Agent Control security capabilities to major enterprise security & governance frameworks: **OWASP Agentic Top 10 (ASI 2026)**, **SOC 2 Type II**, **ISO/IEC 27001:2022**, and **NIST AI Risk Management Framework (AI RMF 1.0)**.

> [!IMPORTANT]
> **Evidence Collection vs. Compliance Certification**  
> Agent Control provides the cryptographic audit logging, policy enforcement, and DLP telemetry required to satisfy regulatory and auditor inquiries. Deploying Agent Control **supports evidence collection**, but does **not by itself constitute certified compliance**. Achieving certification requires adhering to the Shared Responsibility Model below.

---

## 1. Shared Responsibility Model for AI Governance

| Domain | Vexa Agent Control Responsibility | Customer Organization Responsibility |
|---|---|---|
| **Audit Trails & Integrity** | Generates tamper-evident HMAC-SHA256 chained audit logs and structured compliance summaries. | Configures centralized SIEM archiving, immutable storage, and auditor access reviews. |
| **Data Leakage & Secrets** | Inline 21-pattern `RegexSet` secret masking and prompt normalization. | Defines organization-specific PII/secret policies and enforces employee data handling guidelines. |
| **Authentication & RBAC** | Enforces OIDC JWT validation and identity-bound tool access. | Configures corporate Identity Provider (IdP), MFA, user group memberships, and role assignments. |
| **Endpoint Security** | Runs sandboxed proxy on loopback; provides fail-closed process termination. | Manages host OS patching, EDR agent deployment, and workstation physical security. |
| **Key Custody & KMS** | In-memory key usage; envelope encryption for stored vault secrets. | Manages root KMS customer keys, rotation schedules, and cloud provider access policies. |

---

## 2. SOC 2 Type II Control Mapping (Evidence Collection)

| Trust Services Criteria | Control Title | Agent Control Evidence Generation |
|---|---|---|
| **CC6.1** | Logical Access Controls & Least Privilege | OIDC JWT validation, identity-bound session isolation, role-based MCP tool permission policies. Evidence generated via HMAC-signed audit logs. |
| **CC6.6** | Boundary & Perimeter Defense | 6-pass prompt injection normalizer (NFKC, B64, Leetspeak), Safe Mode rule engine blocking risky filesystem & network executions. |
| **CC6.7** | Data In Transit Encryption | Enforces TLS 1.3 / HTTP CONNECT proxying for all external agent tool invocations and LLM API traffic. |
| **CC7.1** | Threat Detection & Anomaly Monitoring | Real-time sliding window cycle detector, semantic anomaly scanner, background threat intelligence analyzer. |
| **CC7.2** | Event Logging & Audit Storage | Cryptographic HMAC-SHA256 audit chaining. Centralized SIEM stream export (Splunk HEC, Datadog Logs, OpenSearch). |

---

## 3. ISO/IEC 27001:2022 Annex A Mapping

| Control ID | Control Name | Agent Control Security Evidence |
|---|---|---|
| **A.5.15** | Access Control | Role-scoped short-lived credential issuance and automatic rotation. |
| **A.8.7** | Protection Against Malware | Pre-execution MCP tool argument sanitization and unsafe command execution blocking. |
| **A.8.12** | Data Leakage Prevention (DLP) | Inline 21-pattern `RegexSet` secret detector masking API keys, SSH keys, PII, and high-entropy tokens before transmission. |
| **A.8.15** | Logging & Monitoring | Immutable append-only audit log with ZK/HMAC cryptographic verification. |

---

## 4. NIST AI RMF 1.0 Mapping

| NIST AI RMF Subcategory | AI Safety Requirement | Agent Control Implementation |
|---|---|---|
| **MAP 1.5** | AI System Boundary Definition | Hard network & stdio proxy boundary isolating LLM agents from direct host/network access. |
| **MEASURE 2.2** | Input & Output Content Verification | Outbound request inspection and response scanning for indirect prompt injection, data exfiltration, and secrets. |
| **MANAGE 2.4** | Automated Safety Fallbacks | Automatic agent process termination and fail-closed circuit breaking on policy violation. |

---

## 5. Generating Automated Compliance Evidence

You can generate structured compliance evidence reports directly from your production audit logs using the Agent Control CLI:

```bash
# Output Markdown summary to stdout
agentcontrol compliance report --log-path /var/log/agentcontrol/audit.log

# Export JSON evidence report for auditors
agentcontrol compliance report --log-path /var/log/agentcontrol/audit.log --format json --output soc2_evidence.json
```

For data retention timelines, key hierarchy details, and incident response SLAs, see the [Data Governance Standard](./security/data_governance.md).
