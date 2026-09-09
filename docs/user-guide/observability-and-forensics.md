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

## 3. Dual-Tier Token Economics & Enterprise Semantic Vector Caching

Modern enterprises cannot rely solely on upstream provider prompt caching. While providers like Anthropic and OpenAI offer discounts for exact prefix matches, **they still charge for output tokens, incur 400ms–1,500ms WAN latency, and egress sensitive prompt data over the internet**.

Vexa Agent Control introduces **Dual-Tier Token Economics**, explicitly differentiating between **Vexa Gateway Vector Caching (100% Cost Avoidance & Zero-Egress)** and **Provider-Side Prompt Caching (Partial Upstream Prefix Discounts)**:

### Architectural Comparison

| Dimension | ⚡ Vexa Gateway Semantic Cache | 🌐 Upstream Provider Prompt Cache |
|---|---|---|
| **Matching Engine** | L1 exact SHA-256 + L2 Vector Cosine Similarity | Strict exact prefix text hash only |
| **Token Cost Avoidance** | **100% Input + 100% Output tokens avoided** ($0.00 billed) | ~50–90% Input discount only (100% output tokens billed) |
| **Network Egress** | **0 Bytes (Eliminated)** — resolved in local memory / private cluster | Full prompt payload egressed across Internet WAN |
| **Execution Latency** | **~2.4 ms** (Sub-millisecond retrieval) | ~450 ms – 1,500 ms (WAN network roundtrip) |
| **Portability** | **Cross-Model & Cross-Provider** (unified gateway layer) | Vendor-locked (isolated per provider account) |
| **Storage Tiering** | Partitioned in-memory vector store + Optional enterprise Qdrant clusters | Ephemeral in-memory provider cache (5 min to 1 hr TTL) |

### Vector Backends & Embedder Options

Configure semantic vector caching in your policy YAML (`agentcontrol.yaml`):

```yaml
llm:
  semantic_cache:
    enabled: true
    similarity_threshold: 0.88        # Cosine similarity cutoff (0.0 to 1.0)
    max_entries: 25000                # In-memory LRU capacity limit
    ttl_seconds: 86400                # 24-hour knowledge retention window
    backend: "in_memory"              # "in_memory" | "qdrant" | "hybrid"
    qdrant:
      url: "http://qdrant.internal.net:6333"
      api_key: "env:QDRANT_API_KEY"
      collection: "vexa-semantic-cache"
    embedder:
      engine: "local"                 # "local" (zero-dependency 384-dim) | "openai" | "ollama"
      model: "text-embedding-3-small"
      endpoint: "https://api.openai.com/v1"
```

### Similarity Threshold Tuning Guidelines

- **0.95 – 0.98 (Strict / Critical):** Financial compliance, legal analysis, medical diagnosis where slight variations could change meaning.
- **0.88 – 0.92 (Recommended Default):** General enterprise support, customer service, internal technical documentation, and repetitive developer queries.
- **0.80 – 0.85 (High Recall):** Code generation, summarization, exploratory brainstorming, and high-volume conversational bots.

### CLI Management & Status Inspection

Inspect real-time cache performance, hit rates, and dollar savings directly from the terminal:

```bash
# Check cache status, hit rate, and economic attribution
agentcontrol cache status

# Purge cache entries across in-memory and Qdrant clusters
agentcontrol cache clear
```

### Dashboard Visualization & Semantic Cluster Inspector

The local developer dashboard (`http://127.0.0.1:8080/dashboard`) provides a dedicated **Token Economics & Cache** tab:
1. **3 Hero Impact Cards:** Visualizes Vexa Gateway 100% Avoided Costs ($), Provider-Side Prefix Discounts ($), and Total Combined Net Value.
2. **Proportional Contribution Bar:** Displays the exact percentage split between Gateway Zero-Egress savings vs. Upstream provider discounts.
3. **Live Semantic Cluster Inspector:** Inspects incoming prompt queries alongside matched cluster centroids, displaying exact cosine similarity (%), latency speedup, and per-query net dollars saved.
4. **Interactive Cache Purge:** One-click instant purge modal invoking `POST /api/v1/cache/clear`.

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
