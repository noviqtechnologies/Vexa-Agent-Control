# Windows PowerShell Installation Guide

This is the primary and recommended installation path for Windows 10 and Windows 11 systems.

---

## Prerequisites

- Windows 10 / Windows 11 (64-bit)
- PowerShell 5.1+ or PowerShell 7+ (Core)
- Active internet connection

---

## Architecture Compatibility

| Windows Architecture | Release Asset | Status | Notes |
|---|---|---|---|
| **Windows x86_64 (AMD64 / Intel)** | `agentcontrol-v1.0.83-windows-x86_64.zip` | **Supported (Verified)** | Standard 64-bit Windows PCs |
| **Windows on ARM (ARM64)** | `agentcontrol-v1.0.83-windows-aarch64.zip` | *Experimental* | Requires specific ARM64 release asset |

---

## Installation via PowerShell (Recommended)

1. Open PowerShell (no Administrator rights required for standard user installation).
2. Execute the one-line installer:
   ```powershell
   irm https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/install/install.ps1 | iex
   ```
3. The installer performs:
   - Platform & architecture detection
   - Download with automatic retry
   - **Fail-closed SHA-256 cryptographic checksum verification**
   - Extraction to `%USERPROFILE%\.local\bin\agentcontrol.exe`
   - User `PATH` environment variable registration

4. Restart your PowerShell window or refresh your PATH:
   ```powershell
   $env:Path = [System.Environment]::GetEnvironmentVariable("Path","User") + ";" + [System.Environment]::GetEnvironmentVariable("Path","Machine")
   ```

5. Confirm installation:
   ```powershell
   agentcontrol.exe --version
   ```

---

## Alternative: Docker Deployment on Windows

If you have **Docker Desktop for Windows** installed and want to run Vexa Agent Control in containers:

### Standalone Gateway Container
```powershell
docker run -d `
  --name agentcontrol `
  -p 8080:8080 `
  -v agentcontrol-data:/app/data `
  -v agentcontrol-logs:/var/log/agentcontrol `
  -e AGENTCONTROL_ADMIN_TOKEN="admin123456" `
  ghcr.io/noviqtechnologies/agentcontrol:latest `
  start --listen 0.0.0.0:8080
```

### Full-Stack Control Hub (Compose)
```powershell
git clone https://github.com/noviqtechnologies/Vexa-Agent-Control.git
cd Vexa-Agent-Control
Copy-Item .env.team.example .env
docker compose -f docker-compose.team.yml up -d
```
Access the Web Management Console at `http://localhost:3000`. See the complete [Docker Deployment Guide](../guides/docker-deployment.md).

---

## Starting Protection

Launch the local security gateway and dashboard on `127.0.0.1:18080`:

```powershell
agentcontrol.exe start
```

*(To install as an always-on background scheduled task without UAC elevation, run `agentcontrol.exe service install`).*

---

## Connecting Coding Assistants

In a separate PowerShell window, connect your AI assistants:

```powershell
agentcontrol.exe connect codex
agentcontrol.exe connect claude
agentcontrol.exe connect vscode-continue
agentcontrol.exe connect cursor
```

---

## Verification & Status

Check health diagnostics and active traffic status:

```powershell
agentcontrol.exe doctor
agentcontrol.exe status
```

Open the Local Developer Dashboard in your browser:
```text
http://127.0.0.1:18080
```

---

## Clean Disconnect & Uninstallation

To cleanly disconnect an assistant and restore its original settings from the ownership manifest:
```powershell
agentcontrol.exe disconnect codex
agentcontrol.exe disconnect claude
```

To completely uninstall Vexa Agent Control and clean up all state files:
```powershell
irm https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/uninstall.ps1 | iex
```
