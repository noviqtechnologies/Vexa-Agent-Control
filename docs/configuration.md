# Configuration & Policies

Agent Control's core enforcement logic is driven by Schema v2 YAML policy files.

## Zero-Configuration Default Policy & Audit Logging

When running `agentcontrol protect` in a directory without an existing policy, Agent Control automatically generates a baseline `agentcontrol-policy.yaml` with out-of-the-box secret DLP rules:
- **Sensitive File Protection:** Automatic sequence blocking when tool calls read `.env`, `.ssh/id_rsa`, or `~/.aws/credentials` followed by outbound execution.
- **Path Traversal Shield:** Enforces canonical path verification on `read_file` and filesystem parameters.
- **Default Audit Log Location:** Audit logs are saved to `~/.agentcontrol/audit.jsonl` by default (overridable via `--log-path` or `AGENTWALL_LOG_PATH`).

## Policy Structure

A policy file strictly defines the allowed actions, tools, and identity providers. The `default_action: deny` directive is required to ensure a fail-safe posture.

Here is an example `agentcontrol-policy.yaml`:

```yaml
version: "2"
default_action: deny

# Controls local shadow proxy behavior
self_healing:
  enabled: true
  decay_window: 30d
  auto_suggest: true
  suggest_threshold: 0.9
  approval_required: true

# External authentication provider (for control-plane/users)
auth:
  provider: okta
  jwks_uri: https://your-org.okta.com/oauth2/default/v1/keys
  jwks_file: /etc/agentcontrol/jwks.json # Air-gapped deployment path (overrides jwks_uri)
  audience: agentcontrol
  issuer: https://your-org.okta.com

# Identity provider for binding Agents to specific rules
identity:
  provider: oidc
  issuer: https://your-org.okta.com
  agents:
    - id: my-agent
      description: "Data analysis agent"
      allowed_tools: ["read_file", "execute_query"]

# Rate limiting
session:
  max_calls_per_second: 10

# Stateful multi-step sequence rules (ADR Framework)
sequence_rules:
  - id: "no-read-then-exec"
    description: "Block shell execution that follows a sensitive file read (exfiltration pattern)"
    window: 5
    pattern:
      - tool: read_file
      - tool: execute_command
    action: deny
    message: "Exfiltration chain detected: read_file → execute_command"

  - id: "no-repeated-http-post"
    description: "Block repeated outbound HTTP POSTs within a sliding window"
    window: 10
    pattern:
      - tool: http_post
      - tool: http_post
      - tool: http_post
    action: deny
    message: "Repeated POST pattern blocked (possible data exfiltration loop)"

# Explicit Tool Allowlisting
tools:
  - name: read_file
    action: allow
    parameters:
      - name: path
        type: string
        required: true
        max_length: 512
        validators:
          - path_traversal
          - regex: "^/allowed/.*"
```

## Zero-Downtime Policy Reloading

Agent Control supports hot-reloading its configuration without dropping active connections. This is critical for centralized enforcement gateways.

- **Via API:** `curl -X POST http://localhost:8080/reload`
- **Via Signal (Linux):** `kill -SIGHUP $(pidof agentcontrol)`

## Data Loss Prevention (DLP)

Agent Control includes a DLP engine that scans outbound requests and inbound responses for sensitive data. 
It supports 21 built-in regex patterns, detecting:
- AWS, Azure, and GCP Keys
- GitHub and Slack Tokens
- Stripe and SendGrid Keys
- Credit Card Numbers, US SSNs
- `.env` variable references

## Stateful Sequence Rules (ADR Framework)

The `sequence_rules` stanza enables the **ADR Sequence Engine** to detect multi-step attack patterns across a sliding-window session. Each rule specifies:

| Field | Description |
|-------|-------------|
| `id` | Unique rule identifier (referenced in audit logs) |
| `description` | Plain-English explanation of the attack pattern |
| `window` | How many recent tool calls to examine |
| `pattern` | Ordered list of tool names that together constitute the attack |
| `action` | `deny` (block) or `log` (observe only) |
| `message` | Human-readable block reason surfaced to the dashboard |

Sequence rule violations are written to the audit log with the matched rule ID and appear as **Sequence Rule Violation Badges** in the local dashboard at `http://127.0.0.1:8080`.

## Safe Mode (FR-303a)

Safe Mode is an always-on enforcement layer that blocks dangerous tool calls without any policy configuration. It applies 15 tool-aware rules covering sensitive file access (SSH keys, `.env`, AWS credentials, kubeconfig, `/etc/shadow`, Docker config/socket), shell exfiltration (pipe-to-shell, netcat listeners, `rm -rf /`), and cloud metadata SSRF.

Safe Mode runs before the policy engine and is not configurable — it cannot be disabled. It protects agents even in shadow mode (`agentcontrol dev`) where no policy file is loaded. For the full rule set, see `src/policy/safe_mode.rs`.

## Agent Identity & Credential Governance

Agent Control introduces per-agent credential governance. Instead of hardcoding long-lived secrets into your AI Agents, you can provision short-lived, scoped credentials at runtime.

```bash
# Provision a scoped credential for an agent (1-hour TTL)
agentcontrol identity create --agent my-agent --scope read-only --ttl 1h

# Rotate credentials
agentcontrol identity rotate --agent my-agent

# Set per-tool-call credential scoping
agentcontrol identity scope --agent my-agent --tool execute_shell --deny
```

## ADR Security Benchmark

The `agentcontrol bench` command stress-tests your gateway configuration against 303 curated tasks across 17 AI attack categories. It measures your detection and blocking rates and assigns an overall **A/B/C security grade**.

```bash
# Run the full benchmark suite
agentcontrol bench --full

# Output: target/benchmark-report.html
```

For a complete description of all 17 attack categories, scoring methodology, and policy recommendations, see the [ADR Security Benchmark Guide](adr_benchmark.md).

## MCP Schema-Drift Detection (FR-601, ADR-011)

The `schema_drift` stanza enables cross-session detection of tool catalog tampering ("rug pulls"). When an MCP server alters tool definitions, parameter schemas, or descriptions post-approval, Agent Control detects the hash mismatch and applies the configured action.

```yaml
schema_drift:
  enabled: true
  action: warn          # Options: warn, block, downgrade_score
  baseline_path: "./schema_baselines.json" # Optional persistent storage
```

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | boolean | `false` | Enables cross-session schema drift evaluation on `tools/list` responses. |
| `action` | string | `"warn"` | Action to take upon drift: `warn` (audit log only), `block` (reject session with error `-32002`), or `downgrade_score` (reduce Vexa Security Score by 25 points). |
| `baseline_path` | string | `null` | Optional filesystem path to persist tool catalog baseline hashes across gateway restarts. |

## Authoritative LLM Spend Governance & Policy Limits

In Team and Enterprise deployments, spend management is authoritatively governed by PostgreSQL with preflight bounded reservations and integer microcents math.

### Policy Configuration Schema

Spend policies can be published via the Management Console (`/spend/limits`) or via the Control Hub API (`POST /api/v2/spend/policies`):

```json
{
  "scope_type": "organization",
  "scope_id": "00000000-0000-0000-0000-000000000001",
  "period_type": "monthly",
  "limit_usd": 500.00,
  "action": "hard_deny"
}
```

| Parameter | Type | Valid Values | Description |
|---|---|---|---|
| `scope_type` | string | `organization`, `project` | Hierarchical governance scope |
| `scope_id` | string | UUID or project slug | Tenant ID or Project identifier |
| `period_type` | string | `daily`, `monthly` | Budget reset interval (UTC calendar boundary) |
| `limit_usd` / `limit_microcents` | number / integer | `> 0` | Cap amount ($1 = 100,000,000 microcents) |
| `action` | string | `hard_deny`, `warn` | `hard_deny` returns HTTP 429 before upstream dispatch; `warn` allows with audit log |

### Preflight Reservation & Settlement Invariants
1. **Pre-dispatch Lock**: Before sending requests to providers (OpenAI, Anthropic, etc.), Agent Control locks the active `budget_windows` row `FOR UPDATE` and reserves the bounded maximum cost.
2. **Hard Limit Verification**: Invariant enforced: `reserved_microcents + settled_microcents + reserve_microcents <= limit_microcents`.
3. **Settlement**: Upon receiving provider token counts (`prompt_tokens`, `completion_tokens`, `cached_tokens`), the reservation is converted to settled spend, and unused reserve balances are released immediately.
4. **Auto-Sweeper**: A background sweeper automatically releases un-settled reservations older than 5 minutes.

---

## 8. Sentry Daemon & IDE Auto-Enforcement Configuration

The Sentry Daemon (`agentcontrol watch` / OS background service) runs locally on developer workstations to continuously watch and lock IDE proxy settings.

### Target Path Resolution Reference
| IDE Target | Windows Resolution | macOS Resolution | Linux Resolution | Injected Config Key |
|---|---|---|---|---|
| **Cursor** | `%APPDATA%\Cursor\User\settings.json` | `~/Library/Application Support/Cursor/User/settings.json` | `~/.config/Cursor/User/settings.json` | `cursor.models.openaiBaseUrl: "http://127.0.0.1:8080/v1"` |
| **VS Code** | `%APPDATA%\Code\User\settings.json` | `~/Library/Application Support/Code/User/settings.json` | `~/.config/Code/User/settings.json` | `cline.baseUrl: "http://127.0.0.1:8080/v1"` |
| **Claude Desktop** | `%APPDATA%\Claude\claude_desktop_config.json` | `~/Library/Application Support/Claude/claude_desktop_config.json` | `~/.config/Claude/claude_desktop_config.json` | MCP stdio tool proxies |
| **Zed Editor** | `%LOCALAPPDATA%\Zed\settings.json` | `~/.config/zed/settings.json` | `~/.config/zed/settings.json` | `language_models.openai.api_url: "http://127.0.0.1:8080/v1"` |
| **Windsurf** | `%APPDATA%\Windsurf\User\settings.json` | `~/Library/Application Support/Windsurf/User/settings.json` | `~/.config/Windsurf/User/settings.json` | `openai.baseUrl: "http://127.0.0.1:8080/v1"` |

### Sentry Daemon CLI Options
```bash
# Watch all supported IDE configurations with event-driven self-healing
agentcontrol watch --all

# Inspect current IDE config paths, existence, and proxy lock states
agentcontrol status
```

---

## 9. Model Groups & Pluggable Routing Configuration

Under the `llm:` block, `model_groups:` defines upstream model clusters, failover pools, and data residency boundaries.

### Schema:
```yaml
llm:
  model_groups:
    - name: "production-chat"
      routing_strategy: "lowest_latency" # priority | lowest_latency | weighted_random | region_affinity
      allowed_regions: ["us-east-1", "eu-central-1"] # Enforced by region_affinity
      deployments:
        - id: "openai-us-east"
          provider: "openai"
          model_name: "gpt-4o"
          endpoint_url: "https://api.openai.com/v1"
          priority: 1
          weight: 80
          region: "us-east-1"
        - id: "azure-eu-central"
          provider: "azure"
          model_name: "gpt-4o"
          endpoint_url: "https://my-eu.openai.azure.com"
          priority: 2
          weight: 20
          region: "eu-central-1"
```

### Strategy Behaviors:
1. **`priority` (Default):** Dispatches to the deployment with the lowest priority integer. If the primary deployment fails or health checks degrade, traffic fails over seamlessly to the secondary deployment.
2. **`lowest_latency`:** Queries rolling exponential moving average (EMA) response latencies across deployments and automatically routes requests to the fastest available provider.
3. **`weighted_random`:** Distributes requests proportionally according to the relative weights configured on each deployment (useful for canary deployments or load distribution).
4. **`region_affinity`:** Strict sovereign data residency enforcement. If a deployment's region is not in `allowed_regions`, Agent Control rejects the request with HTTP 503 `routing_policy_violation` rather than allowing cross-border data transfer.

---

## 10. Advanced Governance, Autonomy & Delegation (Schema v2)

### 10.1 Autonomy Budgets & Ceilings (FR-034)
Guards against runaway autonomous agents, recursion loops, and budget exhaustion:
```yaml
autonomy_budgets:
  max_call_recursion_depth: 8       # Max nested tool or sub-agent call depth
  max_run_duration_secs: 300        # Max wall-clock execution time per run
  max_run_tokens: 150000            # Combined prompt and completion token limit
  consecutive_failure_limit: 3      # Halt if 3 consecutive failures occur
  repetitive_loop_threshold: 4      # Halt if identical tool call repeats 4 times
  human_approval_on_breach: true    # Escalate to HITL CAS queue on ceiling breach
```

### 10.2 MCP Tool Schema-Drift Detection (FR-007)
Detects upstream or malicious modifications to MCP tool schemas using canonical SHA-256 digests:
```yaml
schema_drift:
  action: "block"                   # block | warn | review
  pinned_catalog_hash: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  strict_canonicalization: true
```

### 10.3 Hierarchical Capability Delegation (FR-035)
Enforces monotonic capability reduction when a parent agent delegates tasks to sub-agents ($C_{\text{child}} \subseteq C_{\text{parent}}$):
```yaml
delegation:
  require_monotonic_attenuation: true
  max_delegation_depth: 3
  block_cross_workspace_delegation: true
```

### 10.4 Data Provenance & Flow Tracking (FR-036)
Labels data sources and prevents poisoned or untrusted tool data from reaching sensitive sinks:
```yaml
provenance:
  track_source_labels: true
  flow_rules:
    - source_label: "UntrustedExternalWeb"
      forbidden_sinks: ["DatabaseWrite", "FilesystemWrite", "ShellExecution"]
      action: "block"
```

### 10.5 Upstream Circuit Breaking & Failover (FR-030, FR-031)
Automated provider failover with idempotent retries:
```yaml
failover:
  circuit_breaker:
    failure_threshold: 3            # Consecutive errors before tripping Open
    recovery_time_secs: 30          # Half-Open canary probe interval
  retries:
    max_attempts: 2
    retry_classes: ["502", "503", "504", "429"]
    require_idempotency_key_for_mutations: true
```

---

## 11. Enterprise Policy Trust Profiles & Hard Safety Invariants

### 11.1 Policy Trust Profiles (`PolicyTrustProfile`)
Controls which policy ingestion sources are accepted by the gateway daemon:

```yaml
trust_profile:
  mode: "managed"                 # "development" | "managed"
  require_monotonic_revision: true
  max_policy_age_secs: 86400      # 24 hours max freshness before fail-closed
  trusted_keyring:
    keys:
      - key_id: "corp-security-lead-2026"
        public_key_hex: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        description: "Primary Corporate Security Authority"
        created_at: "2026-01-01T00:00:00Z"
    rotation_policy: "manual"     # manual | time_based
```

- **Managed Mode Requirements:**
  - Unsigned local policy YAML is **strictly rejected**.
  - Ephemeral signing keys in `promote` are **forbidden**.
  - Offline cache HMAC fallback is **disabled** (requires explicit device token or secret).
  - Ingestion via `/api/v1/policy/signed-push` requires verification against the configured keyring.

### 11.2 Hard Safety Invariants vs. Advisory Detections
- **Hard Invariants:** Severe safety threats (e.g. access to `/etc/shadow`, OS hives, root filesystem destruction) produce unconditional `Deny` decisions. They **cannot be overridden** by user policy `action: allow`.
- **Advisory Detections:** Heuristic findings that can be mapped by policy to `warn`, `require_approval`, or `deny`. Silent `allow` of active detections is prohibited.

### 11.3 Break-Glass Emergency Overrides
For authorized operational necessity, an operator can provide an out-of-band break-glass token:
```yaml
break_glass:
  enabled: true
  require_operator_signature: true
  max_ttl_secs: 3600             # 1 hour maximum validity
```
Each break-glass override is cryptographically pinned to the action's parameter hash and consumed exactly once.

### 11.4 Environment Variables for Policy Trust
The gateway trust profile can be configured directly via environment variables:

| Environment Variable | Description | Default |
|----------------------|-------------|---------|
| `POLICY_SIGNING_PRIVATE_KEY` | 64-hex Ed25519 private key used by Central Hub to sign policy bundles. Independently managed — **never** derived from gateway or read secrets. | Required for Team Hub Managed Mode |
| `AGENTCONTROL_MANAGED_MODE` | Set to `1` or `true` to enforce Managed mode trust profile (fails closed at startup if keyring is empty) | `0` (Development) |
| `AGENTCONTROL_TRUST_PROFILE` | Set to `managed` or `development` | `development` |
| `AGENTCONTROL_TRUSTED_KEYS` | Comma-separated hex list or JSON array of trusted Ed25519 public keys | Empty |
| `AGENTCONTROL_KEYRING_PATH` | Path to `keyring.json` containing trusted public keys | `~/.agentcontrol/keyring.json` |
| `AGENTCONTROL_REQUIRE_MONOTONIC_REVISION` | Enforce anti-rollback revision monotonicity (`0` to disable) | `1` (true in Managed mode) |
| `AGENTCONTROL_MAX_POLICY_AGE_SECS` | Maximum acceptable age of policy bundle before fail-closed / degraded | None |
| `POLICY_READ_SECRET` | Secret used to authenticate policy bundle fetches from Hub (read secret only, cannot sign policies) | Device token |
