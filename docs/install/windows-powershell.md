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
| **Windows x86_64 (AMD64 / Intel)** | `agentcontrol-v1.0.65-windows-x86_64.zip` | **Supported (Verified)** | Standard 64-bit Windows PCs |
| **Windows on ARM (ARM64)** | `agentcontrol-v1.0.65-windows-aarch64.zip` | *Experimental* | Requires specific ARM64 release asset |

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

## Starting Protection

To discover IDEs, wrap configurations with timestamped backups, and start the local security gateway:

```powershell
agentcontrol.exe protect
```

To run in observation/shadow mode (auditing only without blocking):
```powershell
agentcontrol.exe protect --shadow
```

---

## Verification

In a second PowerShell window, run:

```powershell
agentcontrol.exe verify
```

Expected output:
```text
✔ [1/3] Safe Tool Execution (read_file)      ➔ ALLOWED
✔ [2/3] DLP Exfiltration Guard (AWS Key)     ➔ BLOCKED [DLP-01-HIGH-ENTROPY]
✔ [3/3] Prompt Injection (System Override)  ➔ BLOCKED [INJ-04-OVERRIDE]
```

---

## Reversion & Uninstallation

To restore all IDE configurations from backups without deleting the binary:
```powershell
agentcontrol.exe unprotect
```

To completely uninstall Vexa Agent Control, stop any running service, and remove state files:
```powershell
irm https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/uninstall.ps1 | iex
```
