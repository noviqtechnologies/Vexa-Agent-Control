# European Union Artificial Intelligence Act (EU AI Act)
## Technical Compliance & Governance Mapping for High-Risk AI Systems

This crosswalk specifies how **Vexa Agent Control** enables organizations deploying or utilizing AI coding agents, autonomous agents, and foundation models to satisfy the mandatory technical requirements of the **EU AI Act (Regulation (EU) 2024/1689)**.

---

### Mandatory Articles Compliance Matrix

| EU AI Act Article | Legal Requirement Summary | Vexa Agent Control Technical Enforcement | Implementation Architecture |
|---|---|---|---|
| **Article 12**<br>*(Record-Keeping)* | High-risk AI systems must technically enable automatic logging of events ('logs') over the system lifecycle. | Cryptographically chained HMAC-SHA256 audit ledger capturing every prompt input, tool invocation, decision, and egress event. | `src/audit/logger.rs`<br>`audit.jsonl` |
| **Article 13**<br>*(Transparency)* | AI operations must be transparent, interpretable, and reproducible for deployers and overseers. | Every decision record links to stable `request_id`, exact `policy_version`, and rule rationale (`NOT_FORWARDED`, `BLOCKED_DLP`). | `src/policy/verdict.rs` |
| **Article 14**<br>*(Human Oversight)* | Systems must be designed to enable natural persons to oversee operation, prevent risks, or stop execution. | **Atomic HITL Engine**: Exact-action Human-in-the-Loop approvals for destructive tool actions; **Emergency Kill Switch**. | `src/policy/hitl.rs`<br>`src/policy/revocation.rs` |
| **Article 15**<br>*(Accuracy, Robustness & Cybersecurity)* | Systems must be resilient against attempts by unauthorized third parties to alter their use or performance (e.g., poisoning, prompt injection). | **Zero-Trust Input Defense**: 6-pass prompt injection scanner, parameter path-traversal guard, and session taint engine (`ToxicFlow`). | `src/policy/injection.rs`<br>`src/policy/taint.rs` |
| **Article 50**<br>*(Transparency for Generative AI)* | Deployers must detect and prevent the generation or transmission of illegal or unauthorized confidential content. | **In-line DLP Inspection**: High-speed entropy and pattern-based redaction of secrets, private keys, and restricted intellectual property. | `src/policy/dlp.rs` |

---

### Compliance Declaration

Vexa Agent Control acts as an independent, deterministic Policy Enforcement Point (PEP) ensuring autonomous AI agents operate strictly within the human-directed operational boundary required by EU Regulation 2024/1689.
