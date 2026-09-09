# Semantic Cache Methodology, Economics & Safety Exclusions

**Document Version:** 1.0.0  
**Status:** Production Standard  
**Applies to:** Vexa Agent Control `v1.0.82+`

---

## 1. Executive Summary

Vexa Agent Control provides a multi-tiered, process-local caching architecture designed to eliminate redundant LLM token spend, avoid WAN egress latency, and preserve data privacy. 

This document defines the formal methodology, cache-hit criteria, statistical measurement formulas, economic attribution models, and non-negotiable safety exclusions that govern the semantic caching engine.

---

## 2. Architecture: Local Cosine Index vs. Optional Qdrant

| Component | Implementation | Indexing Mechanism | Persistence | Deployment Role |
|---|---|---|---|---|
| **L1 Exact Cache** | Pure-Rust `DashMap<[u8; 32], ExactCacheEntry>` | O(1) SHA-256 Hash of Canonical Context | In-Memory, Ephemeral | Sub-0.1ms exact prompt-replay avoidance |
| **L2 Semantic Cache (Local)** | Pure-Rust `InMemoryVectorIndex` | Partitioned Linear Cosine-Similarity Scan | In-Memory, Ephemeral | Sub-3ms offline lexical/semantic vector matching |
| **L2 Semantic Cache (Qdrant)** | External Qdrant Cluster | Distributed Approximate Nearest Neighbor (ANN) | Persistent / Clustered | Optional enterprise scale across multi-node fleets |

> [!IMPORTANT]
> **Honest Naming Guarantee:** The local vector index uses a pure-Rust, partitioned vector store with SIMD-friendly dot product cosine similarity scanning. It is **not** an HNSW graph. Qdrant provides optional persistent vector storage and approximate nearest-neighbor indexing when configured.

### Fail-Open Availability Semantics
If an external Qdrant cluster is unreachable or times out:
1. Semantic cache lookup immediately degrades to local memory or bypasses.
2. The live request proceeds upstream without interruption.
3. **Qdrant availability never impacts deterministic policy enforcement or gateway uptime.**

### Data Privacy Boundary
Qdrant stores **only** L2-normalized vector embeddings and UUID identifiers under strict tenant namespaces. **Zero raw prompt text, completion text, or credentials are ever transmitted to or stored within Qdrant.**

---

## 3. The 4-Layer Cacheability Evaluation Engine

Before any prompt is checked or stored, it must pass four conservative evaluation gates. **Any classification uncertainty defaults to Cache Bypass.**

```
                     Incoming Client Request
                                │
                                ▼
        ┌───────────────────────────────────────────────┐
        │  Gate 1: Syntactic Safety Filter              │
        │  • Rejects tools, functions, tool_choice      │──► [BYPASS]
        │  • Rejects agent execution metadata           │
        └───────────────────────┬───────────────────────┘
                                │ Clean (No Tools)
                                ▼
        ┌───────────────────────────────────────────────┐
        │  Gate 2: Context & Identity Validation        │
        │  • Rejects missing tenant / subject identity  │──► [BYPASS]
        │  • Rejects unversioned policy                 │
        │  • Rejects temperature != 0.0 (non-det)       │
        └───────────────────────┬───────────────────────┘
                                │ Clean (Deterministic Context)
                                ▼
        ┌───────────────────────────────────────────────┐
        │  Gate 3: Conservative Semantic Allowlisting   │
        │  • Rejects mutating imperatives (delete/pay)  │──► [BYPASS]
        │  • Rejects dynamic state (current time/date)  │
        └───────────────────────┬───────────────────────┘
                                │ Clean (Pure Read-Only)
                                ▼
        ┌───────────────────────────────────────────────┐
        │  Gate 4: Operational Boundaries               │
        │  • Rejects oversized payloads (> 64 KB)       │──► [BYPASS]
        │  • Rejects scanner timeouts / parser errors   │
        └───────────────────────┬───────────────────────┘
                                │ Approved
                                ▼
                   Proceed to Cache Lookup
```

### Core Invariant
> *"Cached entries will never replay stale tool calls, mutate external state, or suppress agent execution."*

---

## 4. Workload Definitions & Cacheability Matrix

| Workload Category | Example Prompts | Default TTL | Cache Allowed? | Rationale |
|---|---|:---:|:---:|---|
| **Deterministic Code FAQ** | *"How to reverse a linked list in Rust"* | 15 min | ✅ Yes | Pure read-only, deterministic logic |
| **Documentation Retrieval** | *"Explain RFC 9110 HTTP status 429"* | 4 hours | ✅ Yes | Stable knowledge base, no side effects |
| **Agentic Tool Loops** | *"Search repo and modify file"* | 0 (Bypass) | ❌ **No** | Tool calling must execute live |
| **Mutating / Financial** | *"Transfer $500 to account X"* | 0 (Bypass) | ❌ **No** | Strict exclusion of side-effects |
| **Operational Telemetry** | *"What is current cluster CPU?"* | 0 (Bypass) | ❌ **No** | Time-dependent dynamic state |

---

## 5. Statistical Telemetry & Attribution Formulas

### 1. Gateway Cache Hit Rate ($H_G$)
$$H_G = \frac{\text{Exact Hits} + \text{Semantic Hits}}{\text{Total Lookups}} \times 100\%$$

### 2. Avoided Egress Cost ($C_{\text{avoided}}$)
For a gateway cache hit, 100% of input and completion tokens are avoided:
$$C_{\text{avoided}} = (P_{\text{tokens}} \times R_{\text{prompt}}) + (C_{\text{tokens}} \times R_{\text{completion}})$$
Where $R_{\text{prompt}}$ and $R_{\text{completion}}$ are published per-token provider rates.

### 3. Provider Prefix Discount ($D_{\text{provider}}$)
When a request misses the gateway cache but hits upstream provider prompt caching:
$$D_{\text{provider}} = P_{\text{cached\_tokens}} \times (R_{\text{prompt}} \times 0.50)$$

### 4. WAN Egress Avoidance ($E_{\text{bytes}}$)
$$E_{\text{bytes}} = (P_{\text{tokens}} + C_{\text{tokens}}) \times 4 \text{ bytes/token}$$

---

## 6. Embedder Characteristics: Local Vectorizer vs Upstream Models

| Dimension | Local Deterministic Vectorizer | Upstream Embedding Model (OpenAI / Ollama) |
|---|---|---|
| **Algorithm** | 384-dimensional lexical n-gram sign-hashing | Deep Transformer (e.g. `text-embedding-3-small`, `nomic-embed-text`) |
| **Semantic Depth** | Lexical similarity, character n-grams, typo tolerance | Deep contextual paraphrase understanding |
| **Latency** | $< 0.2\text{ ms}$ (Local SIMD) | $15 - 50\text{ ms}$ (Network call) |
| **Deployment** | 100% air-gapped, zero external dependencies | Requires API endpoint or local Ollama daemon |
| **Recommended Use** | Local development, unit testing, air-gapped nodes | Enterprise production semantic caching |
