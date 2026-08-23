# Removal & Recovery Guide

This guide details both automated and manual procedures for cleanly removing Vexa Agent Control and restoring all modified configurations to their original states.

---

## Method 1: Automated Script Uninstallation (Recommended)

### macOS / Linux / WSL
```bash
curl -fsSL https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/uninstall.sh | bash
```

### Windows (PowerShell)
```powershell
irm https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/uninstall.ps1 | iex
```

### What the Uninstaller Does:
1. Calls `agentcontrol unprotect --force` to restore all original IDE configurations from backups.
2. Stops and unregisters OS background daemon services (systemd / Launchd / Windows SCM).
3. Deletes binary executables from `~/.local/bin/` (`%USERPROFILE%\.local\bin`).
4. Purges local state directories (`~/.agentcontrol`, `~/.agent-control`, `~/.agentwall`).

---

## Method 2: Manual Recovery Procedure

If you prefer to perform recovery steps manually:

### Step 1: Restore IDE Configurations
```bash
agentcontrol unprotect --force
```

### Step 2: Verify Configurations with Status
```bash
agentcontrol status
```
Ensure all targets show unwrapped status.

### Step 3: Remove Binary
- **macOS / Linux:** `rm -f ~/.local/bin/agentcontrol ~/.local/bin/agentwall`
- **Windows:** `Remove-Item "$env:USERPROFILE\.local\bin\agentcontrol.exe"`

### Step 4: Remove State and Logs
- **macOS / Linux:** `rm -rf ~/.agentcontrol ~/.agent-control ~/.agentwall`
- **Windows:** `Remove-Item -Recurse -Force "$env:USERPROFILE\.agentcontrol"`
