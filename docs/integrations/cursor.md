# Cursor IDE Integration Guide

This guide details configuring Vexa Agent Control to intercept, secure, and govern tool calls and LLM spend inside Cursor IDE across macOS, Linux, and Windows.

---

## Configuration File Locations

Cursor uses two configuration files for settings and MCP tools:

| Configuration Item | Operating System | File Path |
|---|---|---|
| **MCP Servers (`mcp.json`)** | **Windows** | `%USERPROFILE%\.cursor\mcp.json` |
| | **macOS** | `~/.cursor/mcp.json` |
| | **Linux** | `~/.cursor/mcp.json` |
| **User Settings (`settings.json`)** | **Windows** | `%APPDATA%\Cursor\User\settings.json` |
| | **macOS** | `~/Library/Application Support/Cursor/User/settings.json` |
| | **Linux** | `~/.config/Cursor/User/settings.json` |

---

## 1. LLM Proxy & Virtual Key Configuration (BYOK Mode)

Cursor allows developers to provide custom OpenAI API endpoints for Chat, Composer, and Edit. You can direct Cursor to Agent Control's local gateway to enforce token budgets and spend caps using your **Virtual Key** (`sk-vex-...`).

In Cursor's `User/settings.json` (or via **Cursor Settings → Models → OpenAI API Key**):

```json
{
  "cursor.openAI.baseUrl": "http://127.0.0.1:8080/v1",
  "cursor.openAI.apiKey": "sk-vex-YOUR_VIRTUAL_KEY_HERE",
  "cursor.openAI.model": "gpt-4o"
}
```

> [!NOTE]
> When Cursor submits completions to `http://127.0.0.1:8080/v1`, Agent Control validates the Virtual Key, pre-authorizes the estimated token spend against your budget, checks prompt DLP rules, and swaps the virtual token with your authoritative upstream key.

---

## 2. Full Cursor Traffic Interception (Free / Pro & Enterprise Tiers)

When using Cursor's native subscription tier (`api2.cursor.sh`), Agent Control intercepts and meters traffic through local transparent proxying and Root CA trust:

```bash
# Register local CA into Current User trust store
agentcontrol ca install
```

When you execute `agentcontrol protect`, Agent Control automatically:
1. Adds `"http.proxy": "http://127.0.0.1:8080"` and `"cursor.general.disableHttp2": true` to Cursor's `settings.json`.
2. Sets `NODE_EXTRA_CA_CERTS` for Cursor's internal Node runtime.
3. Decrypts loopback CONNECT streams, metering prompt and completion tokens across Tab Autocomplete, Composer, and Chat.

---

## 3. MCP Tool Sentry Wrapping

To intercept Model Context Protocol tool calls (filesystem, terminal, databases) invoked by Cursor:

1. **Check Status:**
   ```bash
   agentcontrol status
   ```
   Confirm `Cursor` shows `[verified]` and `EXISTS: ✔`.

2. **Wrap Cursor MCP Configuration:**
   ```bash
   agentcontrol wrap cursor
   ```
   - Automatically wraps each MCP command in `~/.cursor/mcp.json` with `agentcontrol stdio-proxy --`.
   - Creates a timestamped backup: `mcp.json.bak.<timestamp>`.

3. **Restart Cursor IDE:**
   Restart Cursor to reload the wrapped stdio-proxy configuration.

4. **Verify Live Monitoring:**
   Ask Cursor's Composer or Chat to invoke a tool. Open the Agent Control Web Console at `http://localhost:3000` or `http://127.0.0.1:8080` to inspect live event telemetry.

---

## 4. Unwrapping Cursor

To restore original settings and MCP configurations:
```bash
agentcontrol unwrap cursor
```
To remove the local certificate from the OS trust store:
```bash
agentcontrol ca uninstall
```
Or reset all IDE configurations simultaneously:
```bash
agentcontrol unprotect
```
