# ISO/IEC 42001:2023 (AI Management System - AIMS)
## Vexa Agent Control Enterprise Control & Evidence Mapping

This mapping specifies how **Vexa Agent Control** delivers technical controls and cryptographic evidence to satisfy **ISO/IEC 42001:2023 Annex A Controls** for organizations developing, deploying, or utilizing AI systems.

---

### Annex A Controls Matrix

| ISO/IEC 42001 Control | Requirement Summary | Vexa Agent Control Implementation | Verification & Audit Evidence |
|---|---|---|---|
| **A.6.2.2** (AI System Lifecycle) | Establish and maintain operational controls for AI system components. | Central policy distribution with version pinning and cryptographic Ed25519 signatures. | `policy.signed.json`, `src/policy/signed.rs` |
| **A.6.2.4** (Data for AI Systems) | Govern data acquisition, input validation, and egress transmission. | In-line parameter DLP redaction (20+ pattern classes, Shannon entropy, Luhn checksums). | `src/policy/dlp.rs`, `audit.jsonl` |
| **A.7.2** (Human Oversight) | Enable appropriate human intervention in autonomous AI decision-making. | Human-in-the-Loop (HITL) atomic compare-and-swap approval engine for sensitive tool calls. | `src/policy/hitl.rs`, `hitl_wal.jsonl` |
| **A.8.2** (AI Security & Robustness) | Protect AI systems against adversarial attacks (prompt injection, jailbreaks). | Fast multi-pass prompt injection normalizer detecting zero-width spaces, CJK overrides, and toxic flows. | `src/policy/injection.rs`, `src/policy/taint.rs` |
| **A.8.4** (Third-Party AI Transparency) | Monitor and verify interactions with external AI foundation model providers. | Centralized virtual key broker holding raw upstream provider credentials; transparent request metering. | `control-plane/api/internal/broker/` |
| **A.9.2** (Logging and Traceability) | Record operational events to facilitate post-incident forensics. | Append-only HMAC-SHA256 audit ledger linking each tool invocation to policy version and response digest. | `audit.jsonl`, `src/audit/logger.rs` |
| **A.9.3** (AI System Incident Response) | Detect anomalies and execute emergency containment procedures. | Instant Kill Switch: revokes active session tokens, severs MCP connections, and freezes agent autonomy. | `agentcontrol kill --agent <id>` |

---

### Auditor Guidance

To produce an ISO/IEC 42001 Annex A verification report from the command line:
```bash
agentcontrol verify --standard iso-42001
```
All cryptographic evidence files can be archived directly for external registrar review.
