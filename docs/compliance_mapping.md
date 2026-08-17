# Agent Control Compliance Control Mapping Guide

This document maps Agent Control security capabilities to major enterprise security & governance frameworks: **OWASP Agentic Top 10 (ASI 2026)**, **SOC 2 Type II**, **ISO/IEC 27001:2022**, and **NIST AI Risk Management Framework (AI RMF 1.0)**.

> 📖 **Dedicated OWASP ASI Document**: For in-depth vulnerability coverage, code evidence links, and threat mitigations, see the [OWASP Agentic Top 10 Architecture Guide](./owasp_agentic_top10.md).

---

## 1. SOC 2 Type II Control Mapping

| Trust Services Criteria | Control Title | Agent Control Enforcement & Evidence |
|---|---|---|
| **CC6.1** | Logical Access Controls & Least Privilege | OIDC JWT validation, identity-bound session isolation, role-based MCP tool permission policies. Evidence generated via HMAC-signed audit logs. |
| **CC6.6** | Boundary & Perimeter Defense | 6-pass prompt injection normalizer (NFKC, B64, Leetspeak), Safe Mode rule engine blocking risky filesystem & network executions. |
| **CC6.7** | Data In Transit Encryption | Enforces TLS 1.3 / HTTP CONNECT proxying for all external agent tool invocations and LLM API traffic. |
| **CC7.1** | Threat Detection & Anomaly Monitoring | Real-time sliding window cycle detector, semantic anomaly scanner, background threat intelligence analyzer. |
| **CC7.2** | Event Logging & Audit Storage | Cryptographic HMAC-SHA256 audit chaining. Centralized SIEM stream export (Splunk HEC, Datadog Logs, OpenSearch). |

---

## 2. ISO/IEC 27001:2022 Annex A Mapping

| Control ID | Control Name | Agent Control Security Feature |
|---|---|---|
| **A.5.15** | Access Control | Role-scoped short-lived credential issuance and automatic rotation. |
| **A.8.7** | Protection Against Malware | Pre-execution MCP tool argument sanitization and unsafe command execution blocking. |
| **A.8.12** | Data Leakage Prevention (DLP) | Inline 21-pattern `RegexSet` secret detector masking API keys, SSH keys, PII, and high-entropy tokens before transmission. |
| **A.8.15** | Logging & Monitoring | Immutable append-only audit log with ZK/HMAC cryptographic verification. |

---

## 3. NIST AI RMF 1.0 Mapping

| NIST AI RMF Subcategory | AI Safety Requirement | Agent Control Implementation |
|---|---|---|
| **MAP 1.5** | AI System Boundary Definition | Hard network & stdio proxy boundary isolating LLM agents from direct host/network access. |
| **MEASURE 2.2** | Input & Output Content Verification | Outbound request inspection and response scanning for indirect prompt injection, data exfiltration, and secrets. |
| **MANAGE 2.4** | Automated Safety Fallbacks | Automatic agent process termination (`KillMode`) and circuit breaking on policy violation. |

---

## 4. Generating Automated Compliance Evidence

You can generate structured compliance evidence reports directly from your production audit logs using the Agent Control CLI:

```bash
# Output Markdown summary to stdout
agentcontrol compliance report --log-path /var/log/agentcontrol/audit.log

# Export JSON evidence report for auditors
agentcontrol compliance report --log-path /var/log/agentcontrol/audit.log --format json --output soc2_evidence.json
```
