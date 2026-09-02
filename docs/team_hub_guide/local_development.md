# Team Control Hub — Local Development Guide

> **Target Audience:** Developers, Security Testing Engineers, and DevOps Engineers evaluating, testing, or developing the Agent Control Team Control Hub locally using Docker and native binaries.

---

## Overview

The **Local Development** guide covers setting up, running, and testing the **Agent Control Team Control Hub** on a local developer machine using code downloaded/cloned from GitHub. It provides OS-specific instructions for **Linux**, **macOS**, and **Windows** (PowerShell & Command Prompt).

For Workstation Sidecar setup, see → [Workstation Sidecar Guide](../workstation_guide.md).  
For Production Kubernetes deployment, see → [Kubernetes Deployment Guide](kubernetes_deployment.md).

---

## 1. Prerequisites

Before starting, ensure your local development environment meets the following requirements according to your Operating System:

### Tooling Requirements Across All Operating Systems

- **Git v2.38+** — required to clone the Agent Control repository from GitHub.
- **Docker Engine / Docker Desktop v24.0+** — installed and actively running.
- **Docker Compose v2.20+** — required to orchestrate multi-container services.
- **Rust Toolchain (Optional, for building native binary from source):** Rust 1.75+ (`cargo`).

### OS-Specific Tooling & Terminal Notes

#### Linux (Ubuntu / Debian / RHEL / Arch)
- Ensure Docker daemon is running: `sudo systemctl status docker`.
- Ensure your user belongs to the `docker` group (`sudo usermod -aG docker $USER`) to run Docker without `sudo`.

#### macOS (Intel / Apple Silicon)
- **Docker Desktop for Mac** must be running (look for the Docker whale icon in the menu bar).
- If compiling native Rust binaries on Apple Silicon (M1/M2/M3), ensure Xcode Command Line Tools are installed (`xcode-select --install`).

#### Windows 10/11
- **Docker Desktop for Windows** with **WSL2 Backend** enabled and running.
- **PowerShell 5.1+ / PowerShell 7+** or **Command Prompt (CMD)**.
- In PowerShell, run `curl.exe` explicitly to avoid built-in PowerShell aliases (`curl` -> `Invoke-WebRequest`).

### Required Network Ports
Ensure the following ports are free on your host machine:
- `8081`: Control Hub UI (React Management Console)
- `8400`: Control Hub API (Go REST API)
- `5433`: PostgreSQL 16 Database
- `8080`: Agent Control Enforcement Gateway

---

## 2. Environment Setup & Launch

Follow the steps below to clone the repository from GitHub and spin up the Control Hub stack locally.

### Step 1: Clone Repository & Navigate to Control Plane Directory

#### Linux / macOS (Bash / Zsh):
```bash
git clone https://github.com/noviqtechnologies/Vexa-Agent-Control.git
cd Vexa-Agent-Control/control-plane
```

#### Windows (PowerShell):
```powershell
git clone https://github.com/noviqtechnologies/Vexa-Agent-Control.git
cd Vexa-Agent-Control\control-plane
```

#### Windows (Command Prompt - CMD):
```cmd
git clone https://github.com/noviqtechnologies/Vexa-Agent-Control.git
cd Vexa-Agent-Control\control-plane
```

> [!TIP]
> **One-Command Root Launch:** You can also launch the full development stack directly from the repository root:
> ```bash
> docker compose -f docker-compose.team.yml up -d
> ```
> For complete single-container and full-stack options across macOS, Linux, and Windows, see the [Docker Deployment Guide](../guides/docker-deployment.md).

---

### Step 2: Launch the Control Hub Container Stack

> [!IMPORTANT]
> When running `docker compose up -d`, ensure `HTTP_PROXY` and `HTTPS_PROXY` environment variables are **not** blocking Docker daemon communication.

#### Linux / macOS (Bash / Zsh):
```bash
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy
docker compose up -d --build
```

#### Windows (PowerShell):
```powershell
$env:HTTP_PROXY=""
$env:HTTPS_PROXY=""
docker compose up -d --build
```

#### Windows (Command Prompt - CMD):
```cmd
set HTTP_PROXY=
set HTTPS_PROXY=
docker compose up -d --build
```

#### Stack Endpoints Provisioned:
- **Control Hub UI:** `http://localhost:8081`
- **Control Hub API:** `http://localhost:8400` (REST API at `/api/v1`)
- **PostgreSQL 16 Database:** `localhost:5433`
- **Enforcement Gateway (Containerized):** `http://localhost:8080`

---

### Step 3: (Optional) Build Native Rust Binary from Source

If you want to run the native Agent Control gateway binary directly on your host machine alongside Docker Compose:

#### Linux / macOS (Bash / Zsh):
```bash
# Navigate to repository root
cd ..
cargo build --bin agentcontrol
```
*(Binary output: `./target/debug/agentcontrol`)*

#### Windows (PowerShell / CMD):
```powershell
# Navigate to repository root
cd ..
cargo build --bin agentcontrol
```
*(Binary output: `.\target\debug\agentcontrol.exe`)*

---

### Step 4: Connect Gateway Instance to Control Hub

> [!NOTE]
> **Multi-Terminal Workflow**:
> - **Terminal 1**: `agentcontrol start` runs a persistent foreground gateway process. Keep Terminal 1 active to maintain active SSE connections.
> - **Terminal 2**: Use a second terminal to trigger requests, view logs, or run verification commands.
>
> **Port Notice**: Docker Compose maps a `gateway` container to port `8080`. If starting a native gateway binary on port `8080`, stop the container first (`docker compose stop gateway`) or use another port (e.g. `--listen 127.0.0.1:8082`).

#### Linux / macOS (Bash / Zsh):
```bash
export DASHBOARD_API_URL="http://localhost:8400"
export POLICY_READ_SECRET="local-dev-policy-read-secret"
export GATEWAY_SECRET="local-dev-shared-secret-change-me"

# Option A: Running globally installed binary
agentcontrol start \
  --listen 127.0.0.1:8080 \
  --centralized \
  --log-path ./team-audit.log

# Option B: Running compiled binary from repo root
./target/debug/agentcontrol start \
  --listen 127.0.0.1:8080 \
  --centralized \
  --log-path ./team-audit.log
```

#### Windows (PowerShell):
```powershell
$env:DASHBOARD_API_URL="http://localhost:8400"
$env:POLICY_READ_SECRET="local-dev-policy-read-secret"
$env:GATEWAY_SECRET="local-dev-shared-secret-change-me"

# Option A: Running globally installed binary
agentcontrol.exe start `
  --listen 127.0.0.1:8080 `
  --centralized `
  --log-path .\team-audit.log

# Option B: Running compiled binary from repo root
.\target\debug\agentcontrol.exe start `
  --listen 127.0.0.1:8080 `
  --centralized `
  --log-path .\team-audit.log
```

#### Windows (Command Prompt - CMD):
```cmd
set DASHBOARD_API_URL=http://localhost:8400
set POLICY_READ_SECRET=local-dev-policy-read-secret
set GATEWAY_SECRET=local-dev-shared-secret-change-me

:: Option A: Running globally installed binary
agentcontrol.exe start --listen 127.0.0.1:8080 --centralized --log-path .\team-audit.log

:: Option B: Running compiled binary from repo root
.\target\debug\agentcontrol.exe start --listen 127.0.0.1:8080 --centralized --log-path .\team-audit.log
```

---

## 3. Verification & Testing Workflow

### Step 1 — Verify API & DB Health

#### Linux / macOS (Bash / Zsh):
```bash
curl -i http://localhost:8400/healthz
```

#### Windows (PowerShell):
```powershell
curl.exe -i http://localhost:8400/healthz
```

#### Windows (Command Prompt - CMD):
```cmd
curl.exe -i http://localhost:8400/healthz
```

**Expected Output:** `HTTP/1.1 200 OK` with payload `{"status":"ok"}`.

---

### Step 2 — Login to Team Management Console

Open `http://localhost:8081` in your browser.

**Local Development Credentials (`DEV_MODE`):**
- **Email:** `admin`
- **Password:** `admin` (or any string in local dev mode)

> [!NOTE]
> The login API expects an `email` field (not `username`). Using any other field name returns 401 even with the correct value.

---

### Step 3 — Send MCP Tool Request & Verify Audit Log Cryptographic Integrity

In **Terminal 2**, send an MCP `tools/call` JSON-RPC request to trigger gateway evaluation and audit log output:

#### Linux / macOS (Bash / Zsh):
```bash
curl -X POST http://127.0.0.1:8080 \
     -H "Authorization: Bearer test-agent-session-1" \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/test.txt"}}}'
```

#### Windows (PowerShell):
```powershell
curl.exe -X POST http://127.0.0.1:8080 `
         -H "Authorization: Bearer test-agent-session-1" `
         -H "Content-Type: application/json" `
         -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"path\":\"/tmp/test.txt\"}}}'
```

#### Windows (Command Prompt - CMD):
```cmd
curl.exe -X POST http://127.0.0.1:8080 -H "Authorization: Bearer test-agent-session-1" -H "Content-Type: application/json" -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"path\":\"/tmp/test.txt\"}}}"
```

> [!NOTE]
> **Expected Behavior:** If no upstream MCP server is running, the gateway will evaluate policy, write the audit log entry, and return an upstream network error. The exact URL in the error differs by deployment mode:
> - **Native gateway** (running on the host): `Upstream error: Network error: error sending request for url (http://127.0.0.1:3000/)`
> - **Containerised gateway** (Docker Compose `gateway` service): the upstream URL uses the Docker DNS name configured by `AGENTWALL_LISTEN`, e.g. `http://0.0.0.0:8080/`
>
> Either way, the upstream error is **expected** for synthetic testing and confirms the gateway intercepted, evaluated, and logged the request.
>
> **Heartbeat 404 note:** A native gateway connecting to the Compose stack's `/api/v1/ingest/heartbeat` may return **404** if the gateway's `GATEWAY_SECRET` does not match the stack's secret. This is expected when running without a valid OTET-enrolled device token — the audit log entry is still recorded.

#### Verify Audit Log Integrity:

#### Linux / macOS (Bash / Zsh):
```bash
# Option A: System installed binary (in PATH)
agentcontrol verify-log ./team-audit.log

# Option B: Compiled binary (if inside control-plane directory)
../target/debug/agentcontrol verify-log ./team-audit.log

# Option C: Compiled binary (if inside repository root directory)
./target/debug/agentcontrol verify-log ./team-audit.log
```

#### Windows (PowerShell / CMD):
```powershell
# Option A: System installed binary (in PATH)
agentcontrol.exe verify-log .\team-audit.log

# Option B: Compiled binary (if inside control-plane directory)
..\target\debug\agentcontrol.exe verify-log .\team-audit.log

# Option C: Compiled binary (if inside repository root directory)
.\target\debug\agentcontrol.exe verify-log .\team-audit.log
```

**Expected Output:**
```text
ℹ Verifying log chain integrity for team-audit.log... VALID
  ✓ N entries found, cryptographic chain intact.
```
*(Where `N` is the number of MCP tool-call audit entries recorded during the session.)*

---

## 4. Next Steps & References

- For production high-availability deployments on Kubernetes using Helm, see → [Kubernetes Deployment Guide](kubernetes_deployment.md).
- For OIDC identity provider integration (Okta, Keycloak, Entra ID, Auth0, etc.), see → [OIDC Identity Binding Guide](../oidc_identity_binding.md).
- For shared YAML policy schemas, DLP rules, and troubleshooting, see → [Common Reference Guide](../common_guide.md).
