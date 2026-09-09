# Audit Log Threat Model: Local vs. Central Mode

This document transparently specifies the cryptographic guarantees, assumptions, and threat boundaries of the audit logging system in Vexa Agent Control.

---

## Executive Summary

> **Local Mode** provides **accidental-tamper and casual-tamper detection** via an HMAC hash chain.
>
> **Central Mode** provides **cryptographic tamper detection resistant to local workstation compromise**, because the verification authority and permanent storage never reside on the workstation.

Disclosing this distinction upfront is intentional: in zero-trust security engineering, an undisclosed cryptographic limitation destroys credibility when discovered by an enterprise security assessor. Disclosing the boundary explicitly demonstrates architectural rigor.

---

## 1. Local Mode (Workstation Gateway)

In Local Mode (`agentcontrol start` or local background service), the gateway signs each sequential audit entry to disk using an HMAC-SHA256 hash chain:

$$\text{HMAC}_n = \text{HMAC-SHA256}(K_{\text{local}}, \text{Payload}_n \parallel \text{HMAC}_{n-1})$$

### Guarantees Provided
- **Accidental Tamper Detection:** Catches accidental log truncation, line deletion, disk write corruption, or partial manual edits.
- **Casual & Non-Privileged Tampering:** Detects tampering by unprivileged local processes or casual user modification of `audit.jsonl`.
- **Offline Forensic Verification:** Allows instant validation via `agentcontrol verify-log audit.jsonl` without requiring an active internet connection.

### Threat Model Limitation (Honest Disclosure)
Because the gateway runs as a local process on the developer's workstation, the signing key $K_{\text{local}}$ resides within the workstation environment (in process memory, configuration file, or local OS keychain).

**Consequently:**
If a malicious actor or malware achieves local administrator/root privilege or compromises the developer's workstation, they possess the ability to read $K_{\text{local}}$ and mathematically recompute a forged HMAC chain over modified history.

**Verdict:** Local Mode is intended for developer forensics, local accountability, and accidental tamper detection. **It does not defend against full workstation compromise.**

---

## 2. Central Mode (Control Hub & Enterprise SIEM Streaming)

In Central Mode, the workstation gateway does not act as the authoritative historical record. Instead, it streams audit events in real time over TLS directly to an isolated central destination (the Vexa Control Hub or enterprise SIEM platforms like Splunk, Datadog, or OpenSearch).

### Guarantees Provided
- **Workstation Compromise Resistance:** Even if an attacker gains full root/administrator control over the developer's laptop, **they cannot alter, delete, or rewrite historical audit records**. The central SIEM or Control Hub has already ingested and cryptographically sealed the events.
- **Asymmetric Authority:** Workstation gateways use write-only, short-lived ingestion tokens. They have no read, update, or delete permissions against the centralized audit datastore.
- **Key Isolation:** The master cryptographic verification keys and audit chain roots reside exclusively on the isolated central server or cloud SIEM, never touching developer endpoints.
- **Non-Repudiation for Compliance:** Meets enterprise compliance criteria for SOC 2 Type II (CC7.2), ISO 27001 (A.8.15), and NIST SP 800-207 Zero Trust Architecture.

---

## 3. Comparison Matrix

| Dimension | Local Mode (`audit.jsonl`) | Central Mode (SIEM / Hub) |
|---|---|---|
| **Primary Protection Goal** | Accidental corruption & casual edits | Malicious tampering & workstation compromise |
| **Signing Key Location** | Local workstation memory / config | Isolated central server / SIEM |
| **Attacker with Local Root** | **Can** recompute forged chain | **Cannot** modify historical logs |
| **Network Requirement** | Zero (completely offline) | Outbound TLS connection to collector |
| **Verification Tool** | `agentcontrol verify-log` | SIEM query / Central Audit Console |
| **Recommended Use Case** | Individual developer workflow & testing | Production fleets, enterprise teams, compliance audits |

---

## 4. Migration Recommendation for Growing Teams

1. **For Individual Developers & Prototype Testing:** Local Mode is enabled by default with zero configuration overhead. Run `agentcontrol verify-log audit.jsonl` to ensure log integrity.
2. **For Production AI Agents & Multi-Engineer Teams:** Configure real-time SIEM streaming or deploy the Vexa Control Hub:
   ```bash
   # Stream to Splunk HEC
   export AGENTCONTROL_SIEM_BACKEND="splunk"
   export AGENTCONTROL_SIEM_ENDPOINT="https://splunk.internal.corp:8088/services/collector"
   export AGENTCONTROL_SIEM_TOKEN="${SPLUNK_HEC_TOKEN}"

   # Stream to Datadog
   export AGENTCONTROL_SIEM_BACKEND="datadog"
   export AGENTCONTROL_SIEM_ENDPOINT="https://http-intake.logs.datadoghq.com/api/v2/logs"
   export AGENTCONTROL_SIEM_TOKEN="${DATADOG_API_KEY}"
   ```

For configuration details, see the [SIEM Integration Guide](../advanced/siem.md) and [Common Operations Guide](../common_guide.md).
