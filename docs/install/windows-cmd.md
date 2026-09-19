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
copy .env.team.example .env
docker compose -f docker-compose.team.yml up -d
```
Access the Web Console at `http://localhost:3000`. Read the full [Docker Deployment Guide](../guides/docker-deployment.md).

---

## Starting Protection in CMD

Launch the local security gateway on `127.0.0.1:18080`:

```cmd
agentcontrol.exe start
```

---

## Connecting Coding Assistants via CMD

In a second CMD prompt window:

```cmd
agentcontrol.exe connect codex
agentcontrol.exe connect claude
agentcontrol.exe connect vscode-continue
agentcontrol.exe connect cursor
```

---

## Running Verification & Status

```cmd
agentcontrol.exe doctor
agentcontrol.exe status
```

Open the Local Developer Dashboard in your browser:
```text
http://127.0.0.1:18080
```

---

## Disconnecting & Uninstallation from CMD

To disconnect an assistant:
```cmd
agentcontrol.exe disconnect codex
agentcontrol.exe disconnect claude
```

To cleanly uninstall:
```cmd
powershell.exe -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/uninstall/uninstall.ps1 | iex"
```
