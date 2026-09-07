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

Agent Control allows you to route all Codex completions through the local edge gateway (`http://127.0.0.1:8080/v1`) to enforce authoritative token spend caps, rate limits (RPM/TPM), model governance, and DLP without exposing raw upstream OpenAI secrets.

### Recommended: Configuring via `[shell_environment_policy.set]`

In your `config.toml`, configure the shell environment policy to inject the Agent Control proxy URL, your **Virtual Key** (`sk-vex-...`), and preferred model into child processes and tool executions:

```toml
[shell_environment_policy]
inherit = "core"

[shell_environment_policy.set]
# Route LLM completion traffic through AgentControl Local Gateway
OPENAI_BASE_URL = "http://127.0.0.1:8080/v1"

# Virtual Key issued from the AgentControl Web Console (/virtual-keys)
OPENAI_API_KEY = "sk-vex-YOUR_VIRTUAL_KEY_HERE"

# Preferred reasoning / coding model
OPENAI_MODEL = "o3-mini"

# Route child network connections through AgentControl Proxy
HTTP_PROXY = "http://127.0.0.1:8080"
HTTPS_PROXY = "http://127.0.0.1:8080"
```

> [!CAUTION]
> **Avoid the `config_load` Schema Violation Error**:
> Do **NOT** place `model`, `openai_api_key`, or `base_url` directly at the top level or beneath sections like `[features]` in `config.toml`. 
>
> The official ChatGPT Desktop application strictly validates its TOML schema on startup. Adding unrecognized string fields under `[features]` will cause the application to crash on boot with:
> `Windows setup didn't finish • config_load`
>
> Always place environment variables under `[shell_environment_policy.set]` where string values are officially supported.

### Alternative: Configuring via Operating System Environment Variables

If using the **Codex CLI** directly in your terminal, you can set standard environment variables:

#### Windows (PowerShell)
```powershell
$env:OPENAI_BASE_URL = "http://127.0.0.1:8080/v1"
$env:OPENAI_API_KEY  = "sk-vex-YOUR_VIRTUAL_KEY_HERE"
$env:OPENAI_MODEL    = "o3-mini"
```

To persist across all sessions on Windows:
```powershell
[System.Environment]::SetEnvironmentVariable('OPENAI_BASE_URL', 'http://127.0.0.1:8080/v1', 'User')
[System.Environment]::SetEnvironmentVariable('OPENAI_API_KEY', 'sk-vex-YOUR_VIRTUAL_KEY_HERE', 'User')
[System.Environment]::SetEnvironmentVariable('OPENAI_MODEL', 'o3-mini', 'User')
```

#### macOS & Linux (Bash / Zsh)
Add to `~/.bashrc` or `~/.zshrc`:
```bash
export OPENAI_BASE_URL="http://127.0.0.1:8080/v1"
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

2. **Wrap Codex MCP Servers:**
   ```bash
   agentcontrol wrap codex
   ```
   This automatically injects `agentcontrol stdio-proxy --` before every configured MCP command in `config.toml` and creates a timestamped backup (`config.toml.bak.<timestamp>`).

3. **Start Security Gateway:**
   ```bash
   agentcontrol start --listen 127.0.0.1:8080 --policy agentcontrol-policy.yaml
   ```

4. **Verify Live Traffic:**
   Inspect live tool calls and LLM spend in the Web Console at `http://localhost:3000` or `https://console.vexasec.io`.

---

## 4. Unwrapping Codex

To restore the original Codex configuration from its timestamped backup:
```bash
agentcontrol unwrap codex
```
Or unwrap all managed tools at once:
```bash
agentcontrol unprotect
```
