# Antigravity IDE Integration Guide

This guide covers connecting MCP servers in Google DeepMind Antigravity IDE to Vexa Agent Control across macOS, Linux, and Windows.

---

## Configuration File Location

Antigravity IDE reads global MCP configurations from:

| Operating System | Configuration File Path |
|---|---|
| **macOS / Linux** | `~/.gemini/antigravity/mcp_config.json` |
| **Windows** | `%USERPROFILE%\.gemini\antigravity\mcp_config.json` |

---

## Step-by-Step Setup

### 1. Install the Binary

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

### 2. Start the Local Security Gateway

```bash
agentcontrol start
```

This starts the local proxy on `127.0.0.1:18080` and auto-generates a local bearer token at `~/.agentcontrol/local.token`.

### 3. Connect Antigravity

```bash
agentcontrol connect antigravity
```

**What this does automatically:**
- Creates a timestamped baseline backup of `mcp_config.json`.
- Wraps each configured MCP server with `agentcontrol stdio-proxy --`.
- Records all mutations in `~/.agentcontrol/manifests/antigravity.manifest.json`.
- Sends a synthetic 1-token loopback probe to assert routing.

### 4. Verify Live Monitoring

In Antigravity IDE, trigger an MCP tool call (e.g., search resources or invoke an MCP tool).
Open the Local Developer Dashboard at `http://127.0.0.1:18080` to verify live event interception.

```bash
# Check connection status:
agentcontrol status
```

---

## Restoring Original Configuration

To cleanly restore the original Antigravity MCP configuration from the ownership manifest:

```bash
agentcontrol disconnect antigravity
```

To disconnect all managed targets at once:
```bash
agentcontrol disconnect --all
```
