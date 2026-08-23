# Antigravity IDE Integration Guide

This guide covers wrapping MCP servers in Google DeepMind Antigravity IDE.

---

## Configuration Location

Antigravity IDE reads global MCP configurations from:
- **macOS / Linux:** `~/.gemini/antigravity/mcp_config.json`
- **Windows:** `%USERPROFILE%\.gemini\antigravity\mcp_config.json`

---

## Step-by-Step Setup

1. **Check Status:**
   ```bash
   agentcontrol status
   ```
   Confirm `Antigravity` shows `[verified]` and points to the correct user configuration path.

2. **Wrap Antigravity MCP Servers:**
   ```bash
   agentcontrol wrap antigravity
   ```

3. **Start Protection Gateway:**
   ```bash
   agentcontrol protect
   ```

4. **Verify Live Monitoring:**
   In Antigravity IDE, trigger an MCP tool call (e.g. searching resources or calling an MCP tool).
   Open `http://127.0.0.1:8080` to verify live event interception.

---

## Restoring Original Configuration

```bash
agentcontrol unwrap antigravity
```
Or restore all targets:
```bash
agentcontrol unprotect
```
