# Cursor Desktop Governance & LLM Spend Guide

This guide explains how **Vexa Agent Control** intercepts, tracks, and governs AI traffic in **Cursor Desktop** across Windows, macOS, and Linux—including **Cursor Free Tier** and **Bring-Your-Own-Key (BYOK)** setups.

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
       │  stdio-proxy  │               │ 127.0.0.1:8080   │
       │  (MCP Wrap)   │               │ (MITM & Egress)  │
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
agentcontrol connect cursor
```

### What `agentcontrol connect cursor` does automatically:
1. **Safety Backup**: Creates an atomic baseline backup of Cursor's configuration.
2. **Cursor Settings Configuration**: Atomically updates Cursor's `User/settings.json` (or `%APPDATA%\Cursor\User\settings.json` on Windows):
   ```json
   {
     "http.proxy": "http://127.0.0.1:18080",
     "cursor.general.disableHttp2": true
   }
   ```
3. **MCP Tool Wrapping**: Wraps MCP servers in `.cursor/mcp.json` with `agentcontrol stdio-proxy`.
4. **Ownership Manifest**: Records all mutations in `~/.agentcontrol/manifests/cursor.manifest.json`.

---

## Verification & Monitoring

### 1. Check Status & Doctor
```bash
agentcontrol doctor
agentcontrol status
```

### 2. Verify Live Traffic & Telemetry in Local Dashboard
Open the Local Developer Dashboard at `http://127.0.0.1:18080` or monitor terminal status:
```
✔ Intercepted Cursor IDE -> Model: gpt-4o | Prompt: 1,420 tokens | Completion: 210 tokens | Cost: $0.0048
```

### 3. Check Spend Ledger Balance
```bash
agentcontrol spend status
```

---

## Clean Reversion (`agentcontrol disconnect cursor`)

To restore Cursor's original configuration and remove proxy settings without erasing personal customizations:

```bash
agentcontrol disconnect cursor
```

This restores `settings.json` and `.cursor/mcp.json` from the ownership manifest.

---

## Troubleshooting

| Issue | Cause | Resolution |
|---|---|---|
| Cursor shows `self-signed certificate in certificate chain` | Trust store not updated or Node cert env missing | Run `agentcontrol ca install` and restart Cursor. |
| Streaming responses appear delayed or buffered | HTTP/2 frame buffering | Verify `"cursor.general.disableHttp2": true` is set in Cursor `settings.json`. |
| LLM requests blocked with `403 Forbidden` | Spend budget cap exceeded or DLP secret detected | Check `agentcontrol spend status` or inspect DLP findings in `~/.agentcontrol/audit/`. |
