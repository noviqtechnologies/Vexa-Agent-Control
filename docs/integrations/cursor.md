# Cursor IDE Integration Guide

This guide covers wrapping and monitoring Model Context Protocol (MCP) servers within Cursor IDE.

---

## Configuration Location

Cursor reads MCP configurations from:
- **macOS / Linux:** `~/.cursor/mcp.json`
- **Windows:** `%USERPROFILE%\.cursor\mcp.json`

---

## Step-by-Step Setup

1. **Check Status:**
   ```bash
   agentcontrol status
   ```

2. **Wrap Cursor Configuration:**
   ```bash
   agentcontrol wrap cursor
   ```
   Or wrap all verified targets with `agentcontrol protect`.

3. **Restart Cursor IDE:**
   Restart Cursor to load the wrapped `agentcontrol stdio-proxy` commands.

4. **Verify Live Monitoring:**
   Ask Cursor's Composer or Chat to invoke a tool (e.g. database query, filesystem operation).
   Open `http://127.0.0.1:8080` to view intercepted tool call logs.

---

## Unwrapping Cursor

To restore the pre-wrapping configuration:
```bash
agentcontrol unwrap cursor
```
