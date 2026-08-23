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

## Compliance & Standard Mappings

Vexa Agent Control provides built-in compliance report generators for:

- **OWASP Top 10 for Agentic Applications (ASI 2026)**
- **SOC 2 Type II (Trust Services Criteria - Security & Confidentiality)**
- **ISO/IEC 27001:2022 Annex A**
- **NIST AI Risk Management Framework (AI RMF 1.0)**

### Generate Compliance Artifacts
```bash
agentcontrol compliance soc2 --output soc2-report.json
agentcontrol compliance nist --output nist-ai-rmf.json
```
