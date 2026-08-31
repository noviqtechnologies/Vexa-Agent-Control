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

## 1-Command Protection (`agentcontrol protect`)

To automatically configure Cursor Desktop and start the security gateway:

```bash
agentcontrol protect
```

### What `agentcontrol protect` does automatically:
1. **Local Root CA Generation**: Generates an isolated ECDSA P-256 Root CA in `~/.agentcontrol/ca/`.
2. **OS Trust Store Registration**: Installs the CA in the **Current User** trust store (`certutil -user "Root"` on Windows / `login.keychain-db` on macOS) without requiring Administrator/sudo elevation.
3. **Cursor Settings Configuration**: Atomically updates Cursor's `User/settings.json`:
   ```json
   {
     "http.proxy": "http://127.0.0.1:8080",
     "cursor.general.disableHttp2": true
   }
   ```
4. **Node Runtime Trust**: Sets `NODE_EXTRA_CA_CERTS` so Cursor's internal Node.js extension processes trust the gateway.
5. **Gateway Daemon**: Starts the local policy enforcement gateway on `127.0.0.1:8080`.

---

## Verification & Monitoring

### 1. Check Local CA & Proxy Status
```bash
agentcontrol ca status
```
*Expected Output:*
```
Local CA Status:
  Storage Directory: C:\Users\<user>\.agentcontrol\ca
  CA Files Exist:    YES
  OS Trust Store:    INSTALLED & TRUSTED
```

### 2. Verify Live Traffic & Token Counts
Open Cursor, initiate a Chat prompt or inline completion, and monitor terminal logs:
```
✔ Intercepted Cursor IDE (api2.cursor.sh) -> Model: gpt-4o | Prompt: 1,420 tokens | Completion: 210 tokens | Cost: $0.0048
```

### 3. Check Spend Ledger Balance
```bash
agentcontrol spend status
```

---

## Clean Reversion (`agentcontrol unprotect`)

To restore Cursor's original configuration and remove the proxy settings:

```bash
agentcontrol unprotect
```

This restores `settings.json` from the atomic backup and removes the Root CA from the OS trust store.

---

## Troubleshooting

| Issue | Cause | Resolution |
|---|---|---|
| Cursor shows `self-signed certificate in certificate chain` | Trust store not updated or Node cert env missing | Run `agentcontrol ca install` and restart Cursor. |
| Streaming responses appear delayed or buffered | HTTP/2 frame buffering | Verify `"cursor.general.disableHttp2": true` is set in Cursor `settings.json`. |
| LLM requests blocked with `403 Forbidden` | Spend budget cap exceeded or DLP secret detected | Check `agentcontrol spend status` or inspect DLP findings in `~/.agentcontrol/audit/`. |
