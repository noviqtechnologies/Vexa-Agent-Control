# Vexa AgentWall

Vexa AgentWall is an enterprise-grade default-deny security gateway and LLM agent egress proxy operating over MCP (Model Context Protocol), HTTP, HTTPS, and WebSocket connections. It intercepts, sandboxes, audits, and actively enforces strict security policies on AI agent tool calls and outbound LLM API traffic across developer workstations, team staging environments, and production fleets — featuring inline DLP scanning, OIDC identity binding, centralized API key custody, and HMAC-chained tamper-evident audit logging.

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License"></a>
  <a href="Cargo.toml"><img src="https://img.shields.io/badge/version-1.0.16-green.svg" alt="Version"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-1.89%2B-orange.svg" alt="Rust"></a>
  <a href="https://go.dev/"><img src="https://img.shields.io/badge/go-1.22%2B-00ADD8.svg" alt="Go"></a>
  <a href="https://react.dev/"><img src="https://img.shields.io/badge/frontend-React%20%7C%20TypeScript-blue.svg" alt="React"></a>
</p>

<p align="center">
  <a href="https://vexasec.io/">Website</a> · <a href="docs/user_guide.md">User Guide</a> · <a href="docs/index.md">Documentation Hub</a> · <a href="docs/oidc_identity_binding.md">OIDC Guide</a> · <a href="https://github.com/noviqtechnologies/agentwall/issues">Issues</a> · <a href="mailto:security@vexasec.io">Security</a>
</p>

---

## Installation

AgentWall provides flexible installation methods tailored to your deployment tier across macOS, Linux, and Windows:

### 1. Developer / Binary Install (Standalone CLI)
Installs the statically-linked `agentwall` binary:

* **macOS / Linux / WSL:**
  ```bash
  curl -fsSL https://vexasec.io/install.sh | bash
  agentwall --version
  ```
  > **Permanent PATH Setup (Set Once):**
  > - **Bash (Linux/WSL):** `echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc`
  > - **Zsh (macOS / modern Linux):** `echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc && source ~/.zshrc`
  > - **Fish:** `fish_add_path ~/.local/bin`

* **Windows (PowerShell / CMD / Git Bash):**
  ```powershell
  irm https://vexasec.io/install.ps1 | iex
  agentwall.exe --version
  ```
  > **Permanent PATH Setup (Set Once):**
  > - **PowerShell (Run once):**
  >   ```powershell
  >   [Environment]::SetEnvironmentVariable("Path", [Environment]::GetEnvironmentVariable("Path", "User") + ";$env:USERPROFILE\.local\bin", "User")
  >   ```
  > - **Command Prompt (CMD):**
  >   ```cmd
  >   setx PATH "%PATH%;%USERPROFILE%\.local\bin"
  >   ```
  > - **Git Bash / MSYS2:**
  >   ```bash
  >   echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bash_profile && source ~/.bash_profile
  >   ```

Or build from source (requires Rust 1.89+):
```bash
git clone https://github.com/noviqtechnologies/agentwall.git
cd agentwall
cargo build --release
# Binary path: ./target/release/agentwall
```

### 2. Team / Staging Install (Docker Compose)
Run the self-hosted Control Hub stack (Go REST API, React UI, PostgreSQL DB) and connect gateway instances:

1. **Deploy Control Hub Stack:**
   ```bash
   cd control-plane
   docker compose up -d --build
   ```
   * **Control Hub UI:** `http://localhost:8081`
   * **Control Hub API:** `http://localhost:8400`

2. **Start Gateway in Centralized Mode:**
   ```bash
   export DASHBOARD_API_URL="http://localhost:8400"
   export POLICY_READ_SECRET="team-policy-read-secret"
   export GATEWAY_SECRET="team-gateway-secret"

   agentwall start --listen 127.0.0.1:8080 --centralized --log-path ./team-audit.log
   ```

### 3. Enterprise Production Install (Kubernetes & Helm)
Deploy the centralized enforcement fleet and Control Hub on Kubernetes:

1. **Create Namespace & TLS Secret:**
   ```bash
   kubectl create namespace agentwall-system
   kubectl create secret tls agentwall-tls --cert=/etc/certs/tls.crt --key=/etc/certs/tls.key -n agentwall-system
   ```

2. **Deploy Helm Chart:**
   ```bash
   helm install agentwall ./chart \
     --namespace agentwall-system \
     --set gateway.tls.enabled=true \
     --set gateway.tls.secretName="agentwall-tls" \
     --set dashboardApi.enabled=true \
     --set dashboardDb.enabled=true \
     --set dashboardFrontend.enabled=true
   ```

---

## Architecture

![AgentWall System Architecture](docs/system_architecture_diagram.png)

### Deployment Tiers

| Tier | Components | Deployment Target | Guide & Installation Links |
|------|-----------|------------------|---------------------------|
| **Local Sidecar** | Gateway + SQLite | Standalone Developer Workstation (`agentwall dev`) | [Binary Install](#1-developer--binary-install-standalone-cli) · [Tier 1 Guide](docs/user_guide.md#tier-1-developer--workstation) |
| **Team Hub** | Gateway + Hub API + Hub UI + PostgreSQL | Team Staging / Shared Server (Docker Compose) | [Docker Compose Install](#2-team--staging-install-docker-compose) · [Tier 2 Guide](docs/user_guide.md#tier-2-team--staging) |
| **Enterprise** | Gateway Fleet + Hub API Cluster + PostgreSQL | Enterprise Multi-Tenant (Kubernetes & Helm) | [Helm Production Install](#3-enterprise-production-install-kubernetes--helm) · [Tier 3 Guide](docs/user_guide.md#tier-3-enterprise-cloud--production) |

---

## Quick Start

### 1. Local Shadow Proxy & Embedded Dashboard (`agentwall dev`)

**Prerequisites:**
- **AgentWall CLI Installed**: `agentwall` binary installed locally.
- **Available Socket Address**: Local port `127.0.0.1:8080` (or custom address via `--listen`).

Launch the shadow proxy in observation mode. This automatically starts the local Web UI at `http://127.0.0.1:8080` and opens your browser:

```bash
agentwall dev
```
* Use `--no-browser` to prevent automatic browser launching.
* Use `--enforce` to test active DLP and policy blocking locally.
* Wrap stdio-based MCP servers directly (ensure target directory exists):
  ```bash
  # Linux / macOS / WSL:
  mkdir -p ~/workspace
  agentwall dev --stdio -- npx -y @modelcontextprotocol/server-filesystem ~/workspace

  # If npx is not found (e.g. nvm / brew / fnm users), pass the full path:
  agentwall dev --stdio -- $(which npx) -y @modelcontextprotocol/server-filesystem ~/workspace

  # Windows (PowerShell):
  New-Item -ItemType Directory -Force -Path $HOME\workspace
  agentwall dev --stdio -- npx -y @modelcontextprotocol/server-filesystem $HOME\workspace
  ```

### 2. Route Local Agent Traffic
Set standard proxy environment variables in your shell:

* **macOS / Linux (Bash/Zsh):**
  ```bash
  export HTTP_PROXY=http://127.0.0.1:8080
  export HTTPS_PROXY=http://127.0.0.1:8080
  export AGENTWALL_PROXY_URL=http://127.0.0.1:8080
  python my_agent.py
  ```
* **Windows (PowerShell):**
  ```powershell
  $env:HTTP_PROXY="http://127.0.0.1:8080"
  $env:HTTPS_PROXY="http://127.0.0.1:8080"
  $env:AGENTWALL_PROXY_URL="http://127.0.0.1:8080"
  python my_agent.py
  ```

### 3. Wrap Local IDEs (`agentwall wrap`)
Automatically patch IDE configuration files (Claude Desktop, Cursor) to route MCP server tool calls through AgentWall:

```bash
# Wrap Claude Desktop
agentwall wrap claude

# Inspect IDE status across all supported editors
agentwall status
```

### 4. Auto-Generate & Enforce Policy
Draft a YAML security policy from observed shadow-mode traffic, lint it, and switch to enforcement mode:

```bash
# Generate policy draft from observed events
agentwall generate-policy --decay-window 30
agentwall lint agentwall-policy.yaml

# Start gateway in active enforcement mode
agentwall start --policy agentwall-policy.yaml --listen 127.0.0.1:8080
```

---

## Configuration

### Policy YAML Example (v2 Schema)

AgentWall policies operate on a **default-deny** principle (`agentwall-policy.yaml`):

```yaml
version: 2
default_action: deny

identity:
  provider: "oidc"
  issuer: "https://auth.corp.com/oauth2/default"
  audience: "agentwall-gateway-prod"
  group_claim_key: "groups"

policy_bindings:
  - group: "secops-team"
    policy: "admin-unrestricted"
  - group: "dev-team"
    policy: "developer-standard"

tools:
  - name: "read_file"
    action: allow
    credential_scope: ["file:read"]
    parameters:
      - name: "path"
        type: string
        required: true
        max_length: 512
        validators:
          - path_traversal
          - no_sensitive_paths
        regex: "^/home/[a-z]+/projects/.*"
        deny_patterns: ["\\.ssh", "\\.env", "\\.aws"]

dlp:
  scannable_tools: ["read_file", "execute_command"]
  safe_tools: ["list_directory"]
  patterns:
    - name: "aws_access_key"
      regex: "AKIA[0-9A-Z]{16}"
      action: block
    - name: "credit_card"
      regex: "\\b\\d{4}[- ]?\\d{4}[- ]?\\d{4}[- ]?\\d{4}\\b"
      action: redact

spend:
  max_tokens_per_session: 100000
  max_concurrent_sessions: 10

loop_detection:
  threshold: 3
  action: PivotError

audit:
  log_file: "/var/log/agentwall/audit.jsonl"
  siem_export:
    type: "splunk_hec"
    endpoint: "https://splunk.corp.com:8088/services/collector/event"
    token: "${SPLUNK_HEC_TOKEN}"
```

### Environment Variables

| Variable | CLI Command | Description | Default |
|---|---|---|---|
| `HTTP_PROXY` / `HTTPS_PROXY` | `dev`, client | Standard HTTP proxy routing URLs | - |
| `AGENTWALL_LISTEN` | `start`, `dev` | Gateway listen socket address | `127.0.0.1:8080` |
| `AGENTWALL_POLICY_PATH` | `start` | Path to YAML policy file | - |
| `DASHBOARD_API_URL` | `start`, proxy | Control Hub API endpoint URL | - |
| `POLICY_READ_SECRET` | `start` | Shared secret for policy hot-reload SSE | - |
| `GATEWAY_SECRET` | `start` | Shared secret for telemetry publishing | - |
| `AGENTWALL_LOG_PATH` | `start` | Path to durable audit log file | `audit.log` |
| `AGENTWALL_OIDC_ISSUER` | `start` | OIDC issuer URL for identity binding | - |
| `AGENTWALL_SIEM_BACKEND` | `start` | SIEM backend (`splunk`, `datadog`, `opensearch`, `local`) | `local` |
| `AGENTWALL_SIEM_ENDPOINT` | `start` | SIEM ingestion URL | - |
| `AGENTWALL_SIEM_TOKEN` | `start` | SIEM authentication token | - |
| `AGENTWALL_SHADOW_MODE` | `start` | Observation mode (log without blocking) | `false` |
| `AGENTWALL_DRY_RUN` | `start` | Log policy violations without denying calls | `false` |
| `AGENTWALL_STRICT_CREDENTIAL_SCOPE` | `start` | Reject credential scope mismatches with 403 | `false` |
| `AGENTWALL_TLS_CERT` | `start` | Path to TLS certificate PEM file (`rustls`) | - |
| `AGENTWALL_TLS_KEY` | `start` | Path to TLS private key PEM file (`rustls`) | - |

---

## User Guide & Documentation Links

Consult our comprehensive documentation suite for detailed guides, architecture specifications, and provider configurations:

- 📖 **[Vexa AgentWall Detailed User Guide](docs/user_guide.md)** — Comprehensive guide covering deployment tiers, v2 policy creation, DLP tuning, OIDC identity binding, Control Hub setup, audit verification, and troubleshooting.
- 🔐 **[OIDC Identity Binding & Auth Provider Guide](docs/oidc_identity_binding.md)** — Step-by-step setup guides, claims mappings, and policy examples for Okta, Keycloak, Entra ID, Auth0, AWS Cognito, Google Workspace, and PingIdentity.
- 🚀 **[Quickstart Guide](docs/quickstart.md)** — Real-world tutorial for securing Claude Desktop and MCP tools.
- 📦 **[Deployment & Installation Guide](docs/deployment.md)** — Step-by-step installation for macOS, Linux, Windows, Docker, and Kubernetes.
- ⚙️ **[Configuration & Policy Reference](docs/configuration.md)** — In-depth reference for Schema v2 policies, Safe Mode rules, and DLP regex patterns.
- 📚 **[Documentation Hub](docs/index.md)** — Centralized documentation index.
- 🛠️ **[Comprehensive Functional Walkthrough](docs/comprehensive_guide.md)** — Command-line scenario walkthroughs for developers across all 9 core capabilities.

---

## License

Copyright © [NoviqTech](https://vexasec.io). Licensed under the [Apache License 2.0](LICENSE).