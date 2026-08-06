# Configuration & Policies

AgentWall's core enforcement logic is driven by Schema v2 YAML policy files. 

## Policy Structure

A policy file strictly defines the allowed actions, tools, and identity providers. The `default_action: deny` directive is required to ensure a fail-safe posture.

Here is an example `agentwall-policy.yaml`:

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
  jwks_file: /etc/agentwall/jwks.json # Air-gapped deployment path (overrides jwks_uri)
  audience: agentwall
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

AgentWall supports hot-reloading its configuration without dropping active connections. This is critical for centralized enforcement gateways.

- **Via API:** `curl -X POST http://localhost:8080/reload`
- **Via Signal (Linux):** `kill -SIGHUP $(pidof agentwall)`

## Data Loss Prevention (DLP)

AgentWall includes a DLP engine that scans outbound requests and inbound responses for sensitive data. 
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

Safe Mode runs before the policy engine and is not configurable — it cannot be disabled. It protects agents even in shadow mode (`agentwall dev`) where no policy file is loaded. For the full rule set, see `src/policy/safe_mode.rs`.

## Agent Identity & Credential Governance

AgentWall introduces per-agent credential governance. Instead of hardcoding long-lived secrets into your AI Agents, you can provision short-lived, scoped credentials at runtime.

```bash
# Provision a scoped credential for an agent (1-hour TTL)
agentwall identity create --agent my-agent --scope read-only --ttl 1h

# Rotate credentials
agentwall identity rotate --agent my-agent

# Set per-tool-call credential scoping
agentwall identity scope --agent my-agent --tool execute_shell --deny
```

## ADR Security Benchmark

The `agentwall bench` command stress-tests your gateway configuration against 303 curated tasks across 17 AI attack categories. It measures your detection and blocking rates and assigns an overall **A/B/C security grade**.

```bash
# Run the full benchmark suite
agentwall bench --full

# Output: target/benchmark-report.html
```

For a complete description of all 17 attack categories, scoring methodology, and policy recommendations, see the [ADR Security Benchmark Guide](adr_benchmark.md).
