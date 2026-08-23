# Paths, Filesystem Layout, and State Reference

Detailed inventory of every filesystem path, directory, state file, and socket created or accessed by Vexa Agent Control.

---

## Filesystem Layout by Operating System

| Component | macOS | Linux / WSL | Windows 10/11 |
|---|---|---|---|
| **Binary Executable** | `~/.local/bin/agentcontrol` | `~/.local/bin/agentcontrol` | `%USERPROFILE%\.local\bin\agentcontrol.exe` |
| **State Directory** | `~/.agentcontrol/` | `~/.agentcontrol/` | `%USERPROFILE%\.agentcontrol\` |
| **Durable Audit Log** | `~/.agentcontrol/audit.jsonl` | `~/.agentcontrol/audit.jsonl` | `%USERPROFILE%\.agentcontrol\audit.jsonl` |
| **Event Database** | `~/.agentcontrol/events.db` | `~/.agentcontrol/events.db` | `%USERPROFILE%\.agentcontrol\events.db` |
| **PKI Hardware Keys** | `~/.agentcontrol/keys/` | `~/.agentcontrol/keys/` | `%USERPROFILE%\.agentcontrol\keys\` |
| **Policy File (Local)**| `./agentcontrol-policy.yaml` | `./agentcontrol-policy.yaml` | `.\agentcontrol-policy.yaml` |
| **Configuration Backups** | `<config_dir>/<file>.bak.<timestamp>` | `<config_dir>/<file>.bak.<timestamp>` | `<config_dir>\<file>.bak.<timestamp>` |

---

## State Files Explained

### `audit.jsonl`
Append-only JSON Lines file containing structured event records for every intercepted tool call:
- Timestamp (UTC ISO-8601)
- Agent / IDE identity
- Tool name and parameter hash
- Security evaluation verdict (`ALLOW`, `DENY`, `REDACT`, `ESCALATE`)
- Matched policy rule IDs
- HMAC integrity signature

### `events.db`
Local SQLite database storing event metadata, latency metrics, and historical tool call schemas for `agentcontrol generate-policy` synthesis.

### `<file>.bak.<timestamp>`
Created before any IDE configuration file is modified. Contains the exact, byte-for-byte original JSON/TOML configuration.
