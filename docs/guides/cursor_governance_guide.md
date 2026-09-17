# Cursor Desktop Governance & LLM Spend Guide

This guide explains how **Vexa Agent Control** intercepts, tracks, and governs AI traffic in **Cursor Desktop** across Windows, macOS, and Linux using LiteLLM-style virtual key injection and zero-trust proxying.

---

## Architecture Overview

Cursor Desktop communicates across two distinct pathways:

```
┌─────────────────────────────────────────────────────────────────┐
│ Cursor Desktop Workstation                                      │
│                                                                 │
│  ┌───────────────────────┐     ┌─────────────────────────────┐  │
│  │ Local MCP Tool Calls  │     │ Built-in LLM Interactions   │  │
│  │ (e.g. read_file, bash)│     │ (Chat, Composer, Tab Auto)  │  │
│  └───────────┬───────────┘     └──────────────┬──────────────┘  │
│              │                                │                 │
│         stdio/JSON-RPC                   HTTPS / SSE            │
│              │                                │                 │
└──────────────┼────────────────────────────────┼─────────────────┘
               │                                │
               ▼                                ▼
       ┌───────────────┐               ┌──────────────────┐
       │  stdio-proxy  │               │ 127.0.0.1:18080  │
       │  (MCP Wrap)   │               │ (Proxy & Egress) │
       └───────┬───────┘               └────────┬─────────┘
               │                                │
               ▼                                ▼
       ┌──────────────────────────────────────────────────┐
       │        Vexa Agent Control Security Gateway       │
       │   • Preflight Budget Cap Check (Spend Ledger)    │
       │   • Real-Time Content-Aware DLP & Injection Scan │
       │   • Zero-Copy Streaming Token Accumulation       │
       │   • Central Control Hub Policy Synchronization   │
       └──────────────────────────────────────────────────┘
```

---

## Connecting Cursor (`agentcontrol connect cursor`)

To connect Cursor Desktop and configure the local security gateway:

```bash
# Auto-detect mode:
agentcontrol connect cursor

# Explicit virtual key:
agentcontrol connect cursor --key sk-vex-cursor-key-12345

# Force local mode:
agentcontrol connect cursor --mode local
```

### What `agentcontrol connect cursor` does automatically:
1. **Safety Backup**: Creates an atomic baseline backup of Cursor's configuration.
2. **Cursor Settings Configuration**: Atomically updates Cursor's `User/settings.json` (e.g. `%APPDATA%\Cursor\User\settings.json` on Windows, `~/Library/Application Support/Cursor/User/settings.json` on macOS):
   ```json
   {
     "http.proxy": "http://127.0.0.1:18080",
     "cursor.general.disableHttp2": true,
     "cursor.general.openaiApiKey": "sk-vex-cursor-key-12345"
   }
   ```
3. **MCP Tool Wrapping**: Wraps MCP servers in `.cursor/mcp.json` (or within settings) with `agentcontrol stdio-proxy`.
4. **Ownership Manifest**: Records all mutations in `~/.agentcontrol/manifests/cursor.manifest.json`.

---

## Standard Output Summary

```text
✔ Successfully connected Cursor IDE!
  ✔ Configuration:     C:\Users\wasim\AppData\Roaming\Cursor\User\settings.json
  ✔ LLM Endpoint:      http://127.0.0.1:18080
  ✔ Auth Token:        sk-vex...2345 (Virtual Key from Control Hub)
  ✔ MCP Servers:       0 wrapped with stdio-proxy
  ✔ Mode:              cloud-direct

  ℹ Restart Cursor IDE to apply changes.
```

---

## Clean Reversion (`agentcontrol disconnect cursor`)

To restore Cursor's original configuration and remove proxy settings without erasing personal customizations:

```bash
agentcontrol disconnect cursor
```

- Reverts `http.proxy`, `cursor.general.disableHttp2`, and `cursor.general.openaiApiKey`.
- Restores original MCP server configs.
- Preserves all custom themes, keybindings, and editor settings.

---

## Verification & Monitoring

```bash
agentcontrol doctor
agentcontrol status
agentcontrol spend status
```
