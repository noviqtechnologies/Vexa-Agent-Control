# Security Policy

At Vexa, security and trust are foundational to everything we build. We take security vulnerabilities seriously and appreciate the contributions of the security research community, developers, and users in keeping Vexa Agent Control secure.

---

## Reporting a Vulnerability

If you believe you have discovered a security vulnerability in Vexa Agent Control, please report it through one of the following coordinated channels:

### 1. GitHub Private Vulnerability Reporting (Recommended)
You can report security vulnerabilities privately and securely directly through GitHub:
- Navigate to the [Vexa Security Advisories page](https://github.com/noviqtechnologies/Vexa-Agent-Control/security/advisories/new).
- Click **"Report a vulnerability"** to open an encrypted, confidential advisory draft with project maintainers.

### 2. Direct Security Contact
If you prefer email, send details of the vulnerability to:
- **Email:** [`contact@vexasec.io`](mailto:contact@vexasec.io)
- **Subject line:** `[SECURITY] Potential vulnerability in Vexa Agent Control`

Please include the following information where possible:
- Component(s) affected (Gateway Core, Control Hub, MCP proxy, CLI, Web UI).
- Version of Vexa Agent Control tested (`agentcontrol --version`).
- Detailed description of the issue and potential impact.
- Step-by-step reproduction steps or a minimal proof-of-concept (PoC).
- Any proposed remediation or patch.

> [!IMPORTANT]
> **Please do not report security vulnerabilities through public GitHub issues or public Discord channels.**

---

## Response Commitments & SLAs

We are committed to timely communication and swift remediation:

| Milestone | Commitment |
|---|---|
| **Initial Acknowledgment** | Within **48 hours** of report receipt. |
| **Triage & Severity Assessment** | Within **5 business days**, including CVSS rating and reproduction confirmation. |
| **Remediation & Patch Target** | **14–30 business days** for high/critical severity; **30–60 business days** for medium/low severity. |
| **Coordinated Public Disclosure** | Following release of the patch or within 90 days of initial disclosure, coordinated with the reporter. |

---

## Supported Versions

Security patches are prioritized for active releases:

| Version Branch | Supported | Notes |
|---|---|---|
| **1.0.x (Current Stable)** | :white_check_mark: | Supported for all critical and high-severity security fixes. |
| **< 1.0.70** | :x: | Deprecated; please upgrade to the latest stable release. |

---

## Vulnerability Disclosure & Attribution

We value the time and effort invested by researchers:
- Reporters who follow coordinated disclosure guidelines will be credited in our public release notes and GitHub Security Advisory acknowledgments (unless anonymity is requested).
- We maintain zero retaliation against researchers acting in good faith without intent to harm users or disrupt production services.
- Organizations seeking structured, third-party managed VDP triage can track our public program integrations via GitHub Security Advisories and community disclosure registries.

---

## Security Best Practices for Deployments

- **Local Workstation Mode**: Review the [Audit Log Threat Model](docs/security/audit-threat-model.md) regarding local cryptographic key boundaries.
- **Production & Cloud Deployments**: Ensure the gateway is deployed with strict network egress controls, mTLS where applicable, and telemetry streaming to a centralized SIEM or Control Hub.
