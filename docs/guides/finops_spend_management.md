# FinOps Spend Governance & Budget Reservation Guide

**Vexa Agent Control** enforces deterministic, concurrency-safe spend limits across AI agents, developer workstations, and enterprise teams.

---

## 1. Core Architecture & Philosophy

In multi-agent environments, asynchronous agent loops and long-running reasoning sessions can exhaust monthly API allocations within minutes. Post-hoc billing reconciliation leaves platform teams with unexpected budget overruns.

AgentControl addresses this with **Fail-Closed Preflight Token Reservations**:

```text
┌─────────────────────────┐          ┌───────────────────────────┐          ┌──────────────────────┐
│  Developer Workstation  │          │   Vexa Gateway Broker     │          │ Upstream LLM Model   │
│   (Codex / Claude)      │          │     (Central Control)     │          │  (OpenAI / Anthropic)│
└───────────┬─────────────┘          └─────────────┬─────────────┘          └──────────┬───────────┘
            │                                      │                                   │
            │ 1. POST /v1/chat/completions         │                                   │
            │ ────────────────────────────────────►│                                   │
            │                                      │ 2. Atomic Preflight Reservation   │
            │                                      │    (Check workspace cap)          │
            │                                      │───┐                               │
            │                                      │   │ In-Memory Ledger              │
            │                                      │◄──┘                               │
            │                                      │                                   │
            │                                      │ 3. Dispatch to Upstream Provider  │
            │                                      │ ─────────────────────────────────►│
            │                                      │                                   │
            │                                      │ 4. SSE Stream Chunks              │
            │ 5. Sanitized Chunks Streamed         │◄──────────────────────────────────│
            │◄─────────────────────────────────────│                                   │
            │                                      │                                   │
            │ (If client disconnects prematurely)  │                                   │
            │    [TCP Close / Cancel]              │                                   │
            │ 6. Cancellation Notice               │ 7. Abort Provider Stream (<500ms) │
            │ ────────────────────────────────────►│ ─────────────────────────────────►│
            │                                      │                                   │
            │                                      │ 8. Reconcile Exact Tokens Used    │
```

---

## 2. Spend Limit Enforcement & HTTP 429 Formatting

When a user, workspace, or tenant exceeds their monthly spend cap, the gateway immediately rejects the request with standard HTTP **429 (Too Many Requests)**.

### Standardized Error Payload
The error response conforms to both OpenAI and Anthropic API specifications, allowing IDEs (Cursor, VS Code Continue, Codex, Claude Desktop) to render clean human-readable notifications:

```json
{
  "error": {
    "message": "Vexa FinOps: Monthly spend budget limit reached ($100.00 / $100.00). Contact your administrator.",
    "type": "budget_exceeded",
    "code": "BUDGET_EXCEEDED"
  }
}
```

### Key Operational Rules:
1. **Immediate Failure:** No internal retries are attempted.
2. **Zero Double-Spend:** Token deduction is atomic and concurrency-safe under high load.
3. **Multi-Tier Attribution:** Spend is tracked by tenant, workspace, user, and device.

---

## 3. Streaming Disconnect Settlement & 500ms Cancellation

Long-context reasoning models (o1, o3, Claude Sonnet thinking) stream responses over tens of seconds. If a developer stops generation or closes their terminal, standard proxies leave the upstream provider connection running, continuing to bill for wasted tokens.

AgentControl implements **Streaming Disconnect Settlement**:
- **Continuous Chunk Accounting:** Downstream byte streams maintain an exact token counter.
- **Premature Disconnect Detection:** If the client disconnects (TCP RST, client abort, terminal kill), the proxy catches the broken pipe immediately.
- **500ms Upstream Abort:** The proxy dispatches a cancellation signal to the Vexa Cloud Gateway within **500ms** to terminate the provider stream.
- **Partial Cost Settlement:** Actual tokens streamed up to the moment of cancellation are committed to the local audit ledger (`~/.agentcontrol/data/events.db`), releasing the remaining reserved budget.
