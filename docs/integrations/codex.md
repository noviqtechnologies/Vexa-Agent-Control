# ChatGPT Codex & Codex Desktop Integration Guide

This guide details configuring Vexa Agent Control to intercept, secure, and govern tool calls and LLM spend from OpenAI ChatGPT Codex agents, the Codex Desktop application, and the Codex CLI across macOS, Linux, and Windows.

---

## Configuration File Locations

Codex stores user and agent runtime configurations in a TOML configuration file:

| Operating System | Configuration File Path |
|---|---|
| **Windows** | `%USERPROFILE%\.codex\config.toml` (e.g. `C:\Users\<username>\.codex\config.toml`) |
| **macOS** | `~/.codex/config.toml` |
| **Linux** | `~/.codex/config.toml` |

---

## 1. LLM Proxy & Virtual Key Configuration

Agent Control allows you to route all Codex completions through the local edge gateway (`http://127.0.0.1:18080/v1`) to enforce authoritative token spend caps, rate limits (RPM/TPM), model governance, and DLP without exposing raw upstream OpenAI secrets.

### Recommended Configuration (`config.toml`)

In `%USERPROFILE%\.codex\config.toml` (Windows) or `~/.codex/config.toml` (macOS/Linux), configure the top-level `openai_base_url` and the child tool environment:

```toml
# ── Top-Level Core Routing (Directs Codex Desktop & CLI Chat Engine) ────────
openai_base_url = "http://127.0.0.1:18080/v1"
model = "gpt-4o"

# ── Subprocess / MCP Shell Policy (Directs Child Tools & Agents) ────────────
[shell_environment_policy]
inherit = "core"

[shell_environment_policy.set]
# Route tool LLM completions through AgentControl Gateway
OPENAI_BASE_URL = "http://127.0.0.1:18080/v1"

# Virtual Key issued from AgentControl Web Console (/virtual-keys) or Hub profile
OPENAI_API_KEY = "sk-vex-YOUR_VIRTUAL_KEY_HERE"

# Preferred model for spawned subprocess tools
OPENAI_MODEL = "gpt-4o"

# Proxy child network requests through AgentControl Gateway
HTTP_PROXY = "http://127.0.0.1:18080"
HTTPS_PROXY = "http://127.0.0.1:18080"
```

> [!IMPORTANT]
> **Top-Level `openai_base_url` vs `[shell_environment_policy.set]`**:
> - **Top-Level `openai_base_url`**: Directs the **Codex Desktop App** and **Codex CLI** chat engines to route their completions (e.g. `/v1/responses` and `/v1/chat/completions`) through the AgentControl gateway. If omitted, Codex defaults to `https://api.openai.com` directly, causing virtual keys (`sk-vex-...`) to be rejected upstream with `401 Unauthorized`.
> - **`[shell_environment_policy.set]`**: Injects environment variables into **child tools and subprocesses** spawned by Codex (such as Python scripts, Node REPL, and CLI commands).
> - **Caution on Keys**: Only use recognized top-level configuration keys (`openai_base_url`, `model`). Do not place arbitrary custom keys directly under sections like `[features]`.

### Alternative: Configuring via Operating System Environment Variables

If using the **Codex CLI** directly in your terminal, you can set standard environment variables:

#### Windows (PowerShell)
```powershell
$env:OPENAI_BASE_URL = "http://127.0.0.1:18080/v1"
$env:OPENAI_API_KEY  = "sk-vex-YOUR_VIRTUAL_KEY_HERE"
$env:OPENAI_MODEL    = "o3-mini"
```

To persist across all sessions on Windows:
```powershell
[System.Environment]::SetEnvironmentVariable('OPENAI_BASE_URL', 'http://127.0.0.1:18080/v1', 'User')
[System.Environment]::SetEnvironmentVariable('OPENAI_API_KEY', 'sk-vex-YOUR_VIRTUAL_KEY_HERE', 'User')
[System.Environment]::SetEnvironmentVariable('OPENAI_MODEL', 'o3-mini', 'User')
```

#### macOS & Linux (Bash / Zsh)
Add to `~/.bashrc` or `~/.zshrc`:
```bash
export OPENAI_BASE_URL="http://127.0.0.1:18080/v1"
export OPENAI_API_KEY="sk-vex-YOUR_VIRTUAL_KEY_HERE"
export OPENAI_MODEL="o3-mini"
```

---

## 2. Model Compatibility & Automatic Aliasing

OpenAI's Codex runtime and Computer-Use agents (`@oai/sky`) require reasoning or tool-optimized models. Standard `gpt-4o` may be rejected by the Codex desktop client runtime.

### Recommended Models for Codex
- **`o3-mini`**: High-speed, high-reasoning model optimized for coding and tool calling.
- **`gpt-4o-mini`**: Cost-efficient model for lightweight completions.
- **`o1`**: Deep reasoning model for complex architectural refactoring.

### Transparent Model Rewriting via AgentControl
If your Codex agent submits requests for one model but your organization policy enforces another (or if you want to map `o3-mini` calls to `gpt-4o` upstream), configure a `model_groups` block in `agentcontrol-policy.yaml`:

```yaml
llm:
  model_groups:
    - name: "o3-mini"
      routing_strategy: "priority"
      deployments:
        - id: "upstream-gpt4o"
          provider: "openai"
          model_name: "gpt-4o"
          endpoint_url: "https://api.openai.com/v1/chat/completions"
          priority: 1
```

---

## 3. MCP Tool Sentry Wrapping

To secure Model Context Protocol (MCP) servers configured inside Codex:

1. **Verify Configuration Detection:**
   ```bash
   agentcontrol status
   ```

2. **Connect Codex:**
   ```bash
   agentcontrol connect codex
   ```
   This automatically injects `agentcontrol stdio-proxy --` before every configured MCP command in `config.toml` and creates a timestamped backup (`config.toml.bak.<timestamp>`).

3. **Start Security Gateway:**
   ```bash
   agentcontrol start --listen 127.0.0.1:18080 --policy agentcontrol-policy.yaml
   ```

4. **Verify Live Traffic:**
   Inspect live tool calls and LLM spend in the Local Developer Dashboard at `http://127.0.0.1:18080`.

---

## 4. Disconnecting Codex

To restore the original Codex configuration from the ownership manifest:
```bash
agentcontrol disconnect codex
```
Or disconnect all managed targets at once:
```bash
agentcontrol disconnect --all
```
