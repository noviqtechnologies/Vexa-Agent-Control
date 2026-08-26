# Troubleshooting Guide

Common issues, diagnostic checks, and resolutions when installing or operating Vexa Agent Control.

---

## 1. Port 8080 Already in Use

**Symptom:**
```text
Error: Failed to bind listener on 127.0.0.1:8080: Address already in use
```

**Resolution:**
Specify a custom listen port:
```bash
agentcontrol protect --listen 127.0.0.1:9090
```

---

## 2. Tool Calls Not Appearing in Dashboard

**Symptom:**
You run `agentcontrol protect`, but tool calls made by Claude Desktop or Cursor do not appear in the dashboard or `audit.jsonl`.

**Resolution:**
1. Check `agentcontrol status` to ensure the config shows `[verified]` and all servers are wrapped.
2. **Restart your IDE:** AI IDEs (Claude Desktop, Cursor) read their configuration once at startup. If the IDE was already open when you ran `protect`, you must restart it.

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

## 5. Unprotect / Backup Restoration Warning

**Symptom:**
`agentcontrol unprotect` warns that a backup file was modified or missing.

**Resolution:**
Force restoration from the latest available backup:
```bash
agentcontrol unprotect --force
```
