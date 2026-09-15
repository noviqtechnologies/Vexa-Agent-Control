# Troubleshooting & Health Diagnostics Guide

This guide covers diagnosing issues, verifying workstation security hygiene, generating sanitized support bundles, and repairing workstation state using **Vexa Agent Control**.

---

## 1. `agentcontrol doctor`

`agentcontrol doctor` is a read-only diagnostic command that runs pre-flight tests across 7 operational layers:

```bash
agentcontrol doctor
```

### Checks Performed:
1. **Binary Integrity & Version:** Verifies binary integrity, signature, and release version.
2. **Authentication State:** Confirms user authentication status and device registration with Control Hub.
3. **Local Token Health:** Verifies `~/.agentcontrol/local.token` existence and strict POSIX permissions (`0600`).
4. **Daemon Reachability:** Asserts that the background proxy is listening on `127.0.0.1:18080` and responding to `/gateway/status`.
5. **Gateway Connectivity:** Probes outbound HTTPS connectivity and latency to the central Control Hub.
6. **Target Drift & Manifest Verification:** Scans connected client configs (`codex`, `claude`, `vscode-continue`) against `~/.agentcontrol/manifests/` to detect external config drift or tampering.
7. **Security Hygiene:** Verifies that no plaintext provider keys (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`) reside in workstation shell environment variables or user profiles.

### Standardized Exit Codes:

| Exit Code | Classification | Meaning | Action Required |
|:---:|---|---|---|
| `0` | **Healthy** | All checks passed cleanly. | No action required. System is fully operational. |
| `1` | **Critical** | Major failure (e.g. daemon offline, auth expired, corrupt token). | Run `agentcontrol repair` or `agentcontrol login`. |
| `2` | **Degraded / Warn** | Non-critical warning (e.g. config drift, stale credentials, high latency). | Review warnings; run `agentcontrol connect <target> --force` if desired. |

### CI/CD and Scripting:
Use `--json` for machine-readable JSON output:
```bash
agentcontrol doctor --json
```

---

## 2. `agentcontrol support-bundle`

When opening a support request or reporting an issue, generate a cryptographically sanitized diagnostic archive:

```bash
agentcontrol support-bundle
```

### Security & Privacy Protections:
- **Strict Size Ceiling:** Archives are capped at **< 10MB**.
- **Structural Allowlisting:** Only 5 metadata-only files are permitted:
  - `system_info.json` (OS, architecture, Agent Control version)
  - `doctor_report.json` (Output of diagnostic checks)
  - `service_state.json` (Background service task status)
  - `event_tail.json` (Last 50 events: timestamps, tool names, verdict codes — **zero** prompt text or payload bodies)
  - `manifest_summary.json` (Managed key names and SHA-256 hashes — no raw file contents)
- **Secondary Regex Secret Scanner:** All files are scanned prior to archiving; any regex pattern matching API keys, tokens, or email addresses is replaced with `[REDACTED_SECRET]`.

---

## 3. Recovery & Repair Commands

### Repair Background Service:
If the background daemon becomes stopped or unauthenticated:
```bash
agentcontrol repair
```
Re-validates all client configs, ensures loopback listeners are active, and re-registers the per-user scheduled task.

### Rotate Local Token:
To atomically rotate the local proxy bearer token:
```bash
agentcontrol rotate-local-token
```
Generates a new cryptographically secure token, writes it to `~/.agentcontrol/local.token` (`0600`), and automatically updates all connected client configurations (`codex`, `continue`).

### Log Out:
To flush local credentials and revoke the device session:
```bash
agentcontrol logout
```

### Reset Local State:
To purge local event databases and cache while preserving baseline backups:
```bash
agentcontrol reset-local-state
```
Add `--force` to bypass the interactive confirmation prompt.
