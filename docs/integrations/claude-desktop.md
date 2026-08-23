# Claude Desktop Integration Guide

This guide details how Vexa Agent Control intercepts, sandboxes, and audits Model Context Protocol (MCP) server invocations inside Anthropic's Claude Desktop application.

---

## How It Works

Claude Desktop defines MCP servers in `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/alice/projects"]
    }
  }
}
```

When you run `agentcontrol wrap claude` or `agentcontrol protect`, Vexa transforms the configuration into:
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "agentcontrol",
      "args": [
        "stdio-proxy",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/Users/alice/projects"
      ]
    }
  }
}
```

All tool calls from Claude Desktop now pass through Vexa's local stdio proxy where they are evaluated against DLP patterns, rate limits, and prompt injection rules before execution.

---

## Step-by-Step Setup

1. **Verify Claude Desktop Config Exists:**
   ```bash
   agentcontrol status
   ```
   Confirm `Claude Desktop` shows `[verified]` and `EXISTS: ✔`.

2. **Wrap Claude Desktop:**
   ```bash
   agentcontrol wrap claude
   ```
   - Timestamped backup created: `claude_desktop_config.json.bak.<timestamp>`.

3. **Start Local Security Gateway:**
   ```bash
   agentcontrol protect
   ```

4. **Restart Claude Desktop:**
   Quit Claude Desktop completely (`Cmd+Q` on macOS, or close from taskbar on Windows) and relaunch it.

5. **Verify Live Traffic:**
   Invoke any tool in Claude Desktop. Inspect live events in the Local Dashboard at `http://127.0.0.1:8080`.

---

## Reversion

To restore the original Claude Desktop configuration:
```bash
agentcontrol unwrap claude
```
Or restore all targets:
```bash
agentcontrol unprotect
```
