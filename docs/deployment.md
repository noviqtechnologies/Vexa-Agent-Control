# Deployment & Installation

Welcome to the AgentWall installation guide! Whether you are on Windows, macOS, or Linux, this guide will walk you through setting up AgentWall step-by-step so you can start securing your AI agents immediately.

## 🍎 macOS Installation

### Step 1: Open your Terminal
You can find the Terminal app by pressing `Cmd + Space` (Spotlight Search), typing `Terminal`, and pressing `Return`.

### Step 2: Download and Install AgentWall
Copy the following command, paste it into your Terminal window, and press `Return`:

```bash
# Standard local developer mode
curl -fsSL https://vexasec.io/install.sh | bash

# Automated enterprise enrollment & persistent system daemon installation
curl -fsSL https://vexasec.io/install.sh | AGENTWALL_TOKEN="TOK-YOUR-TOKEN" bash
```
*This script safely downloads the AgentWall application, places it in `~/.local/bin`, and optionally registers the persistent system daemon (`systemd` / `launchd`).*

### Step 3: Make AgentWall accessible
To ensure you can run the `agentwall` command from anywhere, you need to add it to your system path. Paste this into your Terminal and press `Return`:

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

### Step 4: Verify Installation
Type the following and press `Return`. If you see the AgentWall help menu, you are good to go!
```bash
agentwall --help
```

---

## 🐧 Linux Installation

### Step 1: Open your Terminal
Open your preferred terminal emulator (e.g., GNOME Terminal, Konsole, xterm).

### Step 2: Download and Install AgentWall
Paste the following command to download and install the binary:

```bash
curl -fsSL https://vexasec.io/install.sh | bash
```

### Step 3: Make AgentWall accessible
Add the installation directory to your bash profile:

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

### Step 4: Verify Installation
```bash
agentwall --help
```

---

## 🪟 Windows Installation

### Step 1: Open PowerShell
Press the `Windows` key on your keyboard, type `PowerShell`, and click **Windows PowerShell**.

### Step 2: Download and Install AgentWall
Copy and paste the following 1-line command into PowerShell and press `Enter`:

```powershell
irm https://vexasec.io/install.ps1 | iex
```

*(Alternatively, download the ZIP archive manually):*
```powershell
Invoke-WebRequest -Uri "https://github.com/noviqtechnologies/agentwall/releases/latest/download/agentwall-windows-x86_64.zip" -OutFile "agentwall.zip"
Expand-Archive -Path "agentwall.zip" -DestinationPath "$env:USERPROFILE\.local" -Force
$env:PATH += ";$env:USERPROFILE\.local\bin"
```

### Step 3: Verify Installation
Type the following and press `Enter`:
```powershell
agentwall.exe --version
agentwall.exe --help
```

*(Optional: To run the demonstration test script `quickstart_agent.py`, Python 3.8+ is required):*
```powershell
python "$env:USERPROFILE\.local\bin\quickstart_agent.py"
```

---

## 🐳 Docker Deployment (For Dev, Testing & PoC)

For local development, testing, and proof-of-concept (PoC) scenarios, you can run AgentWall and the Team Control Hub stack using Docker or Docker Compose.

```bash
# Option A: Standalone Gateway Container
docker run -d \
  --name agentwall \
  -p 8080:8080 \
  -v ./policy.yaml:/etc/agentwall/policy.yaml:ro \
  -v ./audit.log:/var/log/agentwall/audit.log \
  ghcr.io/noviqtechnologies/agentwall:latest \
  start --policy /etc/agentwall/policy.yaml --listen 0.0.0.0:8080

# Option B: Complete Control Hub Stack (Compose)
cd control-plane
docker compose up -d --build
```

For full details, see → [Team Control Hub Guide — Docker Deployment](team_hub_guide.md#21-docker-deployment-local-dev-testing--poc).

---

## ☸️ Kubernetes Deployment (For Production)

For high-availability production deployments, AgentWall includes a complete Helm chart (`./chart`) with a Kubernetes operator, CRDs, multi-replica gateway gateway deployment, Control Hub API, PostgreSQL database, and optional NetworkPolicy enforcement.

```bash
helm install agentwall ./chart \
  --namespace agentwall-system \
  --create-namespace \
  --set gateway.tls.enabled=true \
  --set gateway.tls.secretName=my-gateway-tls \
  --set dashboardApi.enabled=true \
  --set dashboardDb.enabled=true \
  --set dashboardFrontend.enabled=true \
  --set dashboardApi.oidc.issuer=https://your-idp.example.com \
  --set dashboardApi.oidc.clientId=agentwall-dashboard
```

For full details, see → [Team Control Hub Guide — Kubernetes Deployment](team_hub_guide.md#22-kubernetes-deployment-production) and `chart/values.yaml` for the full reference of configurable values.

