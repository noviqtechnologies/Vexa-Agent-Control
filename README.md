# Vexa Agent Control

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.0.70-green.svg?style=flat-square)](Cargo.toml)
[![Rust](https://img.shields.io/badge/Rust-1.80%2B-orange.svg?style=flat-square)](https://www.rust-lang.org/)
[![OWASP ASI 2026](https://img.shields.io/badge/OWASP-Agentic%20Top%2010%20(ASI%202026)-success.svg?style=flat-square)](docs/owasp_agentic_top10.md)
[![Documentation Hub](https://img.shields.io/badge/Docs-Documentation%20Hub-1f6feb.svg?style=flat-square)](docs/README.md)

> **Protect local AI-agent tool calls with a small, inspectable gateway.**
>
> Vexa Agent Control routes supported MCP and HTTP traffic through local policy checks, records security decisions, and helps developers catch secrets, prompt-injection patterns, and risky tool behavior before they leave the workstation.
>
> Start in observation mode if you are evaluating the tool. Move to enforcement only after you have verified the integration that you use.

---

## Navigation

- [What Vexa Does Today](#what-vexa-does-today)
- [Who Should Use It](#who-should-use-it)
- [Supported Platforms](#supported-platforms)
- [Verified Integrations](#verified-integrations)
- [10-Minute Quickstart](#10-minute-quickstart)
- [What Changes on Your Machine](#what-changes-on-your-machine)
- [Modes Explained](#modes-explained)
- [Small Team Path](#small-team-path)
- [Troubleshooting & Removal](#troubleshooting--removal)
- [Advanced & Enterprise](#advanced--enterprise)
- [Documentation Index](#documentation-index)

---

## What Vexa Does Today

Vexa Agent Control acts as a local security sidecar and transparent proxy for AI agent tool calls:

- **Centralized LLM Key Custody & Brokered Egress:** Stores provider API keys encrypted in the Hub using AES-256-GCM and decrypts in-memory inside the broker, ensuring developer endpoints never hold raw master credentials.
- **Fail-Closed Spend Governance:** Enforces integer microcent preflight reservations with row-level database locking and accurate SSE streaming token settlement.
- **Enrolled-Device Sentry & Attestation:** Provides continuous filesystem posture monitoring, auto-healing, and authentic Ed25519 cryptographic policy verification.
- **Identity Provider Integration (Local, Google, Azure Entra ID):** Authenticates operators via Local Admin or SSO, validates agent JWTs via dynamic JWKS discovery, and attributes spend and audit events to verified identities.
- **DLP & Secret Leak Prevention:** Detects AWS keys, OpenAI keys, SSH private keys, GitHub tokens, and high-entropy credentials before they leave your workstation.
- **Prompt Injection & Loop Guards:** Evaluates tool arguments against deterministic rules and structural recursion limits.
- **Tamper-Evident Audit Logging:** Emits durable, JSONL event records to `~/.agentcontrol/audit.jsonl` with HMAC signing.

> [!IMPORTANT]
> **Protection Boundary:** Vexa Agent Control inspects traffic routed through wrapped MCP configurations, explicit HTTP proxy environment variables (`AGENTCONTROL_PROXY_URL` / `HTTP_PROXY`), and strict mTLS brokered routes. In Team Enforce Mode, spend governance and broker eligibility fail closed.

---

## Who Should Use It

| Profile | Typical Use Case | Recommended Starting Point |
|---|---|---|
| **Individual Developer** | Evaluating MCP tools, inspecting tool traffic, blocking accidental secret leakage. | [10-Minute Quickstart](#10-minute-quickstart) |
| **Small AI Team / SMB** | Shared security policies across engineers, unified audit logging, spend caps. | [Small Team Hub Guide](docs/guides/small-team-hub.md) |
| **Platform & Enterprise** | Kubernetes Helm sidecars, OIDC identity binding, SIEM forwarding, zero-knowledge CMK. | [Enterprise Reference](docs/advanced/enterprise.md) |

---

## Supported Platforms

| Platform | Architecture | Status | Shell / Runtime Requirements | Notes |
|---|---|---|---|---|
| **macOS (Apple Silicon)** | `aarch64` (M1/M2/M3/M4) | **Supported** | Zsh / Bash | Mandatory SHA-256 verified |
| **macOS (Intel)** | `x86_64` | **Supported** | Zsh / Bash | Mandatory SHA-256 verified |
| **Linux** | `x86_64` / `aarch64` | **Supported** | Bash / Zsh (`curl`, `unzip`, `sha256sum`) | Ubuntu, Debian, Fedora, Arch, Alpine |
| **WSL2** | `x86_64` | **Supported** | Bash / Zsh inside WSL | Protects Linux-side tools and agents |
| **Windows 10/11** | `x86_64` (AMD64) | **Supported** | PowerShell 5.1+ / CMD | Auto-adds `%USERPROFILE%\.local\bin` to PATH |
| **Windows on ARM** | `aarch64` | *Experimental* | PowerShell | Requires specific ARM64 release asset |

---

## Verified Integrations

Trust has levels. Vexa classifies integrations based on end-to-end automated test validation:

| Level | Client / IDE | Configuration Path Checked | Automatic Wrap Support |
|---|---|---|---|
| **Verified** | **Claude Desktop** | `%APPDATA%\Claude\claude_desktop_config.json` / `~/Library/Application Support/Claude/` | Tested & fully supported |
| **Verified** | **Cursor** | `~/.cursor/mcp.json` & `User/settings.json` | Tested & fully supported ([Cursor Guide](docs/guides/cursor_governance_guide.md)) |
| **Verified** | **Codex** | `~/.codex/config.toml` | Tested & fully supported |
| **Verified** | **Antigravity** | `~/.gemini/antigravity/mcp_config.json` | Tested & fully supported |
| **Experimental** | VS Code, JetBrains, Zed, Cline, OpenCode | User-managed / hypothetical path | Requires `agentcontrol status` & manual check |
| **Custom Agent** | LangChain, LlamaIndex, CrewAI, AutoGen, Raw HTTP | `AGENTCONTROL_PROXY_URL=http://127.0.0.1:8080` | Manual proxy routing |

---

## 10-Minute Quickstart

Follow this step-by-step developer journey to install, safely discover, protect one client, verify enforcement, and roll back.

### Step 0: Preflight Check

Confirm your local architecture and ensure port `8080` is available:

```bash
# macOS / Linux / WSL
uname -m && netstat -an | grep 8080 || echo "Port 8080 is available"
```

```powershell
# Windows (PowerShell)
$env:PROCESSOR_ARCHITECTURE; Get-NetTCPConnection -LocalPort 8080 -ErrorAction SilentlyContinue
```

### Step 1: Install Vexa Agent Control

Download and install the statically-linked binary to `~/.local/bin`:

**macOS / Linux / WSL:**
```bash
curl -fsSL https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/install/install.sh | bash
export PATH="$HOME/.local/bin:$PATH"
agentcontrol --version
```

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/install/install.ps1 | iex
agentcontrol.exe --version
```

- **Expected Result:** Prints `agentcontrol 1.0.70`.
- **If it fails:** Verify curl / PowerShell connectivity; check [Platform Install Guides](docs/install/).

### Step 2: Inspect Discovered Clients (Safe Dry-Run)

Inspect which IDE configurations exist on your machine without modifying any files:

```bash
agentcontrol status
agentcontrol protect --dry-run
```

- **Expected Result:** Prints the status table identifying **[verified]** vs **[unverified]** config files.

### Step 3: Protect and Launch Local Gateway

Run one-command protection to wrap discovered configs and launch the local security gateway:

```bash
# Start in observation (shadow) mode:
agentcontrol protect --shadow

# OR start in active enforcement mode (blocks secrets & prompt injections):
agentcontrol protect
```

- **Expected Result:** Discovered MCP configs are backed up and wrapped; local gateway starts on `http://127.0.0.1:8080` and opens the local dashboard.
- **What Changes:** Configs are updated; backups saved to `<config_path>.bak.<timestamp>`.

### Step 4: Verify Live Enforcement

In a separate terminal, execute the 3-point live verification probe:

```bash
agentcontrol verify
```

- **Expected Result:**
  ```text
  ✔ [1/3] Safe Tool Execution (read_file)      ➔ ALLOWED
  ✔ [2/3] DLP Exfiltration Guard (AWS Secret) ➔ BLOCKED [DLP-01-HIGH-ENTROPY]
  ✔ [3/3] Prompt Injection (System Override)  ➔ BLOCKED [INJ-04-OVERRIDE]
  ```

### Step 5: Clean Reversion & Unprotect

To restore all original IDE configurations from backups at any time:

```bash
agentcontrol unprotect
```

- **Expected Result:** Backups are restored; configurations return to their pre-Vexa state.

---

## What Changes on Your Machine

Before writing any configuration, here is the complete footprint of Vexa Agent Control:

| Component | Path (macOS / Linux) | Path (Windows) |
|---|---|---|
| **Binary Executable** | `~/.local/bin/agentcontrol` | `%USERPROFILE%\.local\bin\agentcontrol.exe` |
| **State & Audit Logs** | `~/.agentcontrol/audit.jsonl` | `%USERPROFILE%\.agentcontrol\audit.jsonl` |
| **Local Database** | `~/.agentcontrol/events.db` | `%USERPROFILE%\.agentcontrol\events.db` |
| **Local Policy** | `./agentcontrol-policy.yaml` | `.\agentcontrol-policy.yaml` |
| **Backups Created** | `<config_dir>/<file>.bak.<timestamp>` | `<config_dir>\<file>.bak.<timestamp>` |
| **Local TCP Port** | `127.0.0.1:8080` (customizable with `--listen`) | `127.0.0.1:8080` (customizable with `--listen`) |

---

## Modes Explained

### Security Enforcement Modes
- **Observation / Shadow Mode (`--shadow`):** Logs all tool calls and evaluated policy decisions without blocking any execution. Ideal for testing and policy baseline generation (`agentcontrol generate-policy`).
- **Enforcement Mode (`--enforce` / default in `protect`):** Actively denies tool executions that violate DLP, schema validation, or prompt injection rules.
- **Custom Agent Proxy Mode:** Routes custom Python/Node.js agents via HTTP proxy variables:
  ```bash
  export AGENTCONTROL_PROXY_URL=http://127.0.0.1:8080
  export HTTP_PROXY=http://127.0.0.1:8080
  ```

### LLM Key & Spend Governance Modes (`llm_mode`)
- **`local_compat` (Default):** Standalone local developer compatibility. Dispatches upstream LLM traffic directly using workstation environment variables (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GROQ_API_KEY`, `TOGETHER_API_KEY`, `MISTRAL_API_KEY`) or client request headers.
- **`central_shadow`:** Enterprise observation mode. Upstream requests are routed through the Control Plane with centralized key custody. Evaluates price books and logs would-deny events without blocking execution.
- **`central_enforce`:** Authoritative enterprise governance. Zero provider keys on workstations. Enforces preflight row-locked budget reservations, pinned active price books, and fail-closed budget caps before dispatch.

---

## Small Team Path

Deploy a production-ready shared Control Hub for small teams using Docker Compose:

```bash
git clone https://github.com/noviqtechnologies/Vexa-Agent-Control.git
cd Vexa-Agent-Control

# 1. Create your production environment file from the secure template
cp .env.team.example .env

# 2. Fill in random secrets and your domain (e.g., using: openssl rand -hex 32)
# 3. Start the secure Team Hub stack
docker compose -f docker-compose.team.secure.yml up -d
```

- **Features:** Centralized policy management (SSE sync), shared audit logs, spend caps, provider key custody, and OTET device onboarding.
- Read the full [Small Team Hub Guide](docs/guides/small-team-hub.md).

---

## Troubleshooting & Removal

### Top 3 First-Run Checks

1. **Port 8080 in use:** Launch on an alternative port:
   ```bash
   agentcontrol protect --listen 127.0.0.1:9090
   ```
2. **IDE tool calls not intercepted:** Restart your IDE after running `agentcontrol protect` so it reloads its configuration.
3. **Backup restoration warning:** Run `agentcontrol unprotect --force` to inspect or force rollback.

### Automated Clean Uninstall

To remove the binary, service daemons, and purge state files:

**macOS / Linux:**
```bash
curl -fsSL https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/uninstall.sh | bash
```

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/uninstall.ps1 | iex
```

Read the full [Removal & Recovery Guide](docs/reference/removal-and-recovery.md).

---

## Advanced & Enterprise

For production deployments, security teams, and platform engineering:

- [Enterprise Architecture & HAR Container](docs/advanced/enterprise.md)
- [Kubernetes Helm Deployment](docs/advanced/kubernetes.md)
- [OIDC Identity Binding (Okta, Entra ID, Auth0)](docs/advanced/oidc.md)
- [SIEM Log Forwarding (Splunk, Datadog, OpenSearch)](docs/advanced/siem.md)
- [OWASP Agentic Top 10 (ASI 2026) Mapping](docs/owasp_agentic_top10.md)

---

## Documentation Index

Explore the complete [Documentation Hub](docs/README.md):

- **Install:** [macOS](docs/install/macos.md) · [Linux](docs/install/linux.md) · [WSL2](docs/install/wsl.md) · [Windows PowerShell](docs/install/windows-powershell.md) · [Windows CMD](docs/install/windows-cmd.md)
- **Guides:** [Workstation Workflow](docs/guides/workstation.md) · [Custom Agent HTTP](docs/guides/custom-agent-http.md) · [Small Team Hub](docs/guides/small-team-hub.md)
- **Integrations:** [Matrix](docs/integrations/README.md) · [Claude Desktop](docs/integrations/claude-desktop.md) · [Cursor](docs/integrations/cursor.md) · [Codex](docs/integrations/codex.md) · [Antigravity](docs/integrations/antigravity.md)
- **Reference:** [CLI Commands](docs/reference/cli.md) · [Configuration & Env Vars](docs/reference/configuration.md) · [Paths & State](docs/reference/paths-and-state.md) · [Troubleshooting](docs/reference/troubleshooting.md) · [Removal & Recovery](docs/reference/removal-and-recovery.md) · [Legacy Alias Migration](docs/reference/legacy-migration.md) · [Release Notes Template](docs/reference/release-notes-template.md)

---

## License

Vexa Agent Control is licensed under the [Apache 2.0 License](LICENSE).
