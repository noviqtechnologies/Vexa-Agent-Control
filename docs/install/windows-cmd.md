# Windows Command Prompt (CMD) Guide

This guide covers installing and running Vexa Agent Control using the traditional Windows Command Prompt (`cmd.exe`).

---

## Installation via CMD

Because Windows Command Prompt does not have native cryptographic hash and JSON parsing primitives, the CMD installer uses PowerShell under the hood in a single command:

1. Open `cmd.exe`.
2. Run the bootstrap command:
   ```cmd
   curl.exe -fsSL https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/install/install.ps1 -o "%TEMP%\install.ps1" && powershell.exe -ExecutionPolicy Bypass -File "%TEMP%\install.ps1" && del "%TEMP%\install.ps1"
   ```
3. Add the binary directory to your current CMD session:
   ```cmd
   set PATH=%USERPROFILE%\.local\bin;%PATH%
   ```
4. Verify:
   ```cmd
   agentcontrol.exe --version
   ```

---

## Alternative: Docker Deployment via CMD

If Docker Desktop is installed, run Vexa Agent Control containers directly from CMD:

```cmd
:: Standalone Gateway Container:
docker run -d ^
  --name agentcontrol ^
  -p 8080:8080 ^
  -v agentcontrol-data:/app/data ^
  -v agentcontrol-logs:/var/log/agentcontrol ^
  -e AGENTCONTROL_ADMIN_TOKEN="admin123456" ^
  ghcr.io/noviqtechnologies/agentcontrol:latest ^
  start --listen 0.0.0.0:8080

:: Full-Stack Control Hub (Compose):
git clone https://github.com/noviqtechnologies/Vexa-Agent-Control.git
cd Vexa-Agent-Control
docker compose -f docker-compose.team.yml up -d
```
Access the Web Console at `http://localhost:3000`. Read the full [Docker Deployment Guide](../guides/docker-deployment.md).

---

## Starting Protection in CMD

```cmd
:: Start in active protection mode:
agentcontrol.exe protect

:: Or start in shadow/observation mode:
agentcontrol.exe protect --shadow
```

---

## Running Verification

In a second CMD prompt window:

```cmd
agentcontrol.exe verify
```

---

## Clean Uninstallation from CMD

```cmd
powershell.exe -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/uninstall.ps1 | iex"
```
