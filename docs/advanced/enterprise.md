# Enterprise Architecture & Security Controls

Reference for platform engineers, CISOs, and security architects evaluating Vexa Agent Control in regulated enterprise environments.

---

## Zero-Knowledge Customer-Managed Keys (CMK)

Vexa Agent Control supports envelope encryption for all at-rest SQLite databases and in-transit SSE event streams using AES-256-GCM with customer-managed keys (AWS KMS, Azure Key Vault, HashiCorp Vault).

---

## Hardware PKI & Device Identity

- **Ed25519 Hardware Keys:** Workstation enrollment generates an isolated Ed25519 keypair stored in the OS secure credential store or local protected filesystem (`~/.agentcontrol/keys/`).
- **Mutual TLS (mTLS):** Gateway-to-Hub communications can be pinned to enterprise root certificates using pure-Rust `rustls` (bypassing platform OpenSSL dependencies).

---

## Compliance Audit Evidence & Standard Mappings

Vexa Agent Control generates auditor-ready evidence logs mapped to key framework controls:

- **OWASP Top 10 for Agentic Applications (ASI 2026)**
- **SOC 2 Type II (Trust Services Criteria - Common Criteria 6.1, 6.6, 6.8)**
- **ISO/IEC 27001:2022 Annex A (A.8.12 Data Leakage, A.8.16 Monitoring)**
- **NIST AI Risk Management Framework (AI RMF 1.0 - Govern & Measure)**

### Generate Compliance Evidence Reports
```bash
agentcontrol compliance report --format markdown --output audit-evidence.md
agentcontrol compliance report --format json --output audit-evidence.json
```
