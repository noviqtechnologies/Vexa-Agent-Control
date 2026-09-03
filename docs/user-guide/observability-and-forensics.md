# Observability, Multi-Turn Forensics & Boundary Health

Vexa Agent Control combines LiteLLM-grade API observability with zero-trust workstation boundary enforcement. This guide explains how to track multi-turn agent sessions, explore forensic dossiers, visualize prompt cache economics, and audit fleet boundary health.

---

## 1. Run Explorer & Forensic Dossiers

The **Run Explorer** provides an authoritative, immutable record of every LLM completion evaluated and routed by Vexa Agent Control.

### Features
- **Live Tail Streaming (SSE):** Enable real-time request logging at `/api/v1/observability/request-logs/stream` to view completions as they happen with zero manual browser refreshing.
- **5-Tab Forensic Dossier:**
  - **Economics:** Preflight microcent reservation (`HOLD`), settled billable amount, token breakdown (Prompt, Completion, Cached), Cache Hit Ratio (%), and Time To First Token (TTFT).
  - **Identity:** Device ID, observed hardware posture, enrolled workstation hostname, and Virtual Key context.
  - **Policy Snapshot:** Exact active limit rules, budget caps, and price-book versions in effect at execution time.
  - **Events:** Chronological state transitions (`AUTHORIZED` ➔ `SETTLED` / `RELEASED` / `DENIED`).
  - **Dispatch:** Upstream provider, resolved model target, HTTP status code, and latency.
- **Provenance Footer:** Every dossier reports cryptographic data freshness, confidence tier (`observed` vs `inferred`), and underlying storage engine.

---

## 2. Multi-Turn Session Tracing

Agent workflows are rarely single-turn requests. Developers and coding assistants (such as Cursor, Windsurf, or Claude Desktop) alternate between reasoning completions and local MCP tool calls (`read_file`, `exec`, `web_search`).

### Unified Chronological Trajectory
Navigate to any run or click the **Session Trace** button to view:
- **Unified Timeline:** Interleaved LLM generations (`🤖`) and MCP tool invocations (`🛡️`) in exact chronological sequence.
- **Intervention Markers:** Instant visual indicators whenever DLP regex redaction, prompt-injection defense, or rate-limiting blocked or sanitized an agent action.
- **Session-Wide Rollups:** Total token consumption, cached token percentage, total billed spend, wall-clock agent duration, and count of policy interventions.

---

## 3. Token Economics & Prompt Cache Analytics

Modern LLM providers (Anthropic Prompt Caching, OpenAI Cached Tokens) offer deep discounts for shared prompt prefixes. Vexa automatically tracks and credits prompt cache hits.

- **Cache Hit Ratio Gauge:** Visualizes `(cached_tokens / (cached_tokens + prompt_tokens)) * 100` across hourly buckets.
- **Cost Avoidance Calculation:** Computes financial savings realized through cached prefixes.
- **Dimensional Attribution:** Group spend and token volume by:
  - **Provider:** OpenAI, Anthropic, Groq, Bedrock, Azure.
  - **Model:** `gpt-4o`, `claude-3-7-sonnet`, `llama-3.3-70b`.
  - **Workstation / Device:** Developer machine or CI runner.
  - **User:** Specific internal user ID or end-user identity.
  - **Team:** Virtual Key alias and department budget.

---

## 4. Workstation Coverage & Control Health

While central gateways only observe traffic that developers configure them to route, **Vexa Agent Control establishes a closed perimeter on the developer's workstation**.

### Boundary Matrix
Located at `/coverage-health`:
- **Fleet Protection Score (%):** Overall percentage of enrolled developer machines that are actively enclosed by transparent proxy and MCP filters.
- **Protected vs Exposed:** Identifies machines with active 60s heartbeats versus machines where tools are bypassing the proxy.
- **IDE Target Status:** Real-time matrix displaying whether Cursor, Claude Desktop, VS Code, JetBrains, Windsurf, Zed, or Cline are actively wrapped:
  - 🛡️ `ENFORCED`: The configuration is wrapped and routing through local Agent Control.
  - ⚠️ `EXPOSED`: Installed IDE detected with direct, unmanaged upstream connectivity.
  - ○ `NOT_DETECTED`: IDE is not installed on this machine.
- **Tamper Alerting:** Flags local developer config reversions, proxy bypass attempts, or unauthorized manual overrides within the past 24 hours.

### Remediation
Administrators can copy instant remediation commands for exposed workstations:
```bash
agentcontrol wrap cursor
agentcontrol wrap claude
agentcontrol status
```
