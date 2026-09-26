# Troubleshooting Guide

Common issues, diagnostic checks, and resolutions when installing or operating Vexa Agent Control.

---

## 1. Port 18080 Already in Use

**Symptom:**
```text
Error: Failed to bind listener on 127.0.0.1:18080: Address already in use
```

**Resolution:**
The daemon automatically falls back to the next available port in range `18080..=18090` and writes the active port to `~/.agentcontrol/daemon.port`. If you need to specify a port explicitly:
```bash
agentcontrol start --listen 127.0.0.1:9090
```

---

## 2. Tool Calls Not Appearing in Dashboard

**Symptom:**
You run `agentcontrol start` and connect your assistants, but tool calls made by Claude Desktop or Cursor do not appear in the dashboard (`http://127.0.0.1:18080`) or `events.db`.

**Resolution:**
1. Check `agentcontrol status` to ensure the config shows `[verified]` and all servers are wrapped.
2. **Restart your IDE:** AI IDEs (Claude Desktop, Cursor) read their configuration once at startup. If the IDE was already open when you ran `agentcontrol connect <target>`, you must restart it.

---

## 3. macOS "Developer Cannot Be Verified"

**Symptom:**
macOS Gatekeeper blocks execution of `agentcontrol`.

**Resolution:**
Remove the quarantine attribute:
```bash
xattr -d com.apple.quarantine ~/.local/bin/agentcontrol
```

---

## 4. Windows ARM64 Asset Missing

**Symptom:**
Installation fails on Windows on ARM with asset missing.

**Resolution:**
For release v1.0.42 and earlier, native ARM64 Windows assets were not published. Ensure you are targeting `v1.0.65+` or build from source using `cargo build --release`.

---

## 5. Disconnect / Backup Restoration Warning

**Symptom:**
`agentcontrol disconnect` warns that a backup file was modified or missing.

**Resolution:**
Force restoration from the latest available backup:
```bash
agentcontrol disconnect --all --force
```

---

## 6. Streaming Disconnection / Premature Stream Close

**Symptom:**
Codex Desktop, Cursor, or Cline displays:
```text
stream disconnected before completion: stream closed before response.completed
```

**Root Causes & Resolution:**
1. **View Client Diagnostic Logs Locally:**
   - **Windows:** `Get-Content -Tail 50 "$env:LOCALAPPDATA\AgentControl\logs\agentcontrol.jsonl"`
   - **macOS:** `tail -n 50 ~/Library/Logs/AgentControl/agentcontrol.jsonl`
   - **Linux:** `tail -n 50 ~/.local/state/agentcontrol/logs/agentcontrol.jsonl`
2. **View Centrally in Observability Dashboard:**
   - Open your **AgentControl Console** at `http://localhost:5173` (or cloud dashboard).
   - Navigate to **Observability > Client & Gateway Logs**.
   - Filter by your Device ID or set `Level: Error` to inspect the exact upstream HTTP status or socket timeout reason.
3. **Verify Provider Credentials:**
   - Ensure provider API keys (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`) are valid and not expired.
   - Check if the Virtual Key monthly budget or model permissions were exceeded.

