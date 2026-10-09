# Vexa Agent Control — Feature Lifecycle & Maturity Matrix

**Document Version:** 1.0.0  
**Status:** Canonical Reference  
**Applies to:** Vexa Agent Control `v1.0.95+`  

---

## 1. Lifecycle Definitions

To ensure operational stability and predictability in enterprise production environments, Vexa Agent Control features follow four explicit maturity tiers:

| Tier | Status | Stability & SLA | Breaking Changes | Recommended Environment |
|---|---|---|---|---|
| **[GA]** | General Availability | Fully tested, production-grade, covered by commercial support SLA. | Strict SemVer; no breaking changes within a major version. | Production workstations & enterprise CI/CD runners. |
| **[Preview]** | Feature Preview | Feature-complete and functionally validated; API may receive minor ergonomic updates. | Breaking changes announced $\ge 30$ days in advance. | Staging environments & pilot developer teams. |
| **[Experimental]** | Experimental | Proof-of-concept or cutting-edge research capability; active development. | May change or be replaced without advance notice. | Isolated test environments & research evaluation. |
| **[Deprecated]** | Deprecated | Superseded by newer architecture; targeted for removal in the next major release. | Maintained for security fixes only until formal sunset date. | Plan migration to recommended replacement. |

---

## 2. Feature Maturity Matrix

### 2.1 Core Gateway & Proxy Engine

| Feature | Maturity Tier | Since Release | Description / Migration Notes |
|---|---|---|---|
| **MCP Stdio Proxy** | `[GA]` | `v1.0.0` | JSON-RPC stdio process interception for local tools. |
| **HTTP CONNECT / LLM Proxy** | `[GA]` | `v1.0.0` | Local loopback TLS interception and upstream routing. |
| **Dynamic Port Fallback** | `[GA]` | `v1.0.80` | Automatic fallback to bounded ports (18081–18090) if 18080 is occupied. |
| **Dual-Stack Loopback Binding** | `[GA]` | `v1.0.95` | Simultaneous IPv4 (`127.0.0.1`) and IPv6 (`[::1]`) listener enforcement. |
| **Fail-Closed Watchdog** | `[GA]` | `v1.0.95` | Kernel-level process tree termination if the gateway crashes. |
| **Semantic Response Cache** | `[Preview]` | `v1.0.75` | Local embedding cache for identical prompt queries. |
| **Transparent eBPF Egress Redirect** | `[Experimental]` | `v1.0.90` | Kernel-level packet redirection on Linux workstations. |

### 2.2 Policy & Security Controls

| Feature | Maturity Tier | Since Release | Description / Migration Notes |
|---|---|---|---|
| **RegexSet DLP Secret Redaction** | `[GA]` | `v1.0.0` | 21-pattern inline masking of API keys and private keys. |
| **Safe Mode File & Command Filter** | `[GA]` | `v1.0.20` | Pre-execution AST check blocking destructive shell/file commands. |
| **6-Pass Prompt Injection Normalizer** | `[GA]` | `v1.0.60` | NFKC unicode, base64, leetspeak, and markdown defense. |
| **Human-in-the-Loop (HITL) Webhook** | `[Preview]` | `v1.0.70` | Interactive operator approval workflow for high-risk tools. |
| **Heuristic DNS Tunneling Filter** | `[Preview]` | `v1.0.95` | RFC 1035 label and entropy inspection for DNS exfiltration defense. |
| **Process-Level Kill (`--kill-mode process`)** | `[Deprecated]` | `v1.0.0` | **Removed in v6.1**. Use `--kill-mode connection` (enforcement boundary is connection termination). |

### 2.3 Identity, Teams & Central Hub

| Feature | Maturity Tier | Since Release | Description / Migration Notes |
|---|---|---|---|
| **HMAC-SHA256 Audit Chaining** | `[GA]` | `v1.0.0` | Append-only cryptographically verifiable audit log. |
| **OIDC JWT Identity Binding** | `[Preview]` | `v1.0.85` | Workstation session binding to Okta, Entra ID, or Google Workspace. |
| **Central Spend Caps & FinOps** | `[Preview]` | `v1.0.88` | Real-time token spend tracking and budget circuit breakers. |
| **Team Hub Synchronization** | `[Preview]` | `v1.0.90` | Syncing workstation audit trails with central PostgreSQL hub. |
| **SIEM Stream Export** | `[Preview]` | `v1.0.92` | Exporting audit records to Splunk HEC and Datadog Logs. |
