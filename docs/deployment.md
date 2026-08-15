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

### Step 1: Open PowerShell or Command Prompt
Press the `Windows` key on your keyboard, type `PowerShell` or `cmd`, and launch your preferred terminal.

### Step 2: Download and Install AgentWall

* **Option A: PowerShell (Recommended)**
  ```powershell
  # Standard local developer mode
  irm https://vexasec.io/install.ps1 | iex

  # Or automated enterprise enrollment with remote Control Hub:
  $env:AGENTWALL_TOKEN = "TOK-ENTERPRISE-TOKEN"
  $env:AGENTWALL_HUB_URL = "https://hub.yourdomain.com:8081"
  irm https://vexasec.io/install.ps1 | iex
  ```

* **Option B: Command Prompt (CMD)**
  ```cmd
  curl.exe -fsSL https://vexasec.io/install.ps1 -o install.ps1 && powershell -ExecutionPolicy Bypass -File install.ps1
  ```

> **Important — Installer Elevation & Administrator Permissions:**
> - **Enterprise Automated Deployments (Intune / SCCM / GPO / MSI):** Installer packages and GPO deployment tasks run under **`NT AUTHORITY\SYSTEM`** with full administrative privileges. **`agentwall service install` runs automatically without user interaction.**
> - **Manual Script Execution (`install.ps1`):** Executing `install.ps1` in a standard user PowerShell or CMD session installs the binary to `%USERPROFILE%\.local\bin`. **Installing the SCM Service (`agentwall service install`) requires opening PowerShell with "Run as Administrator".**
> - **Non-Admin Fallback:** Users without administrative privileges can run the sentry daemon interactively using **`agentwall watch`** in a standard user terminal.

*(Alternatively, download the ZIP archive manually):*
* **PowerShell:**
  ```powershell
  Invoke-WebRequest -Uri "https://github.com/noviqtechnologies/agentwall/releases/latest/download/agentwall-windows-x86_64.zip" -OutFile "agentwall.zip"
  Expand-Archive -Path "agentwall.zip" -DestinationPath "$env:USERPROFILE\.local" -Force
  $env:PATH += ";$env:USERPROFILE\.local\bin"
  ```
* **Command Prompt (CMD):**
  ```cmd
  curl.exe -fsSL https://github.com/noviqtechnologies/agentwall/releases/latest/download/agentwall-windows-x86_64.zip -o agentwall.zip
  tar -xf agentwall.zip -C "%USERPROFILE%\.local\bin"
  set PATH=%PATH%;%USERPROFILE%\.local\bin
  ```

### Step 3: Verify Installation

* **PowerShell:**
  ```powershell
  agentwall.exe --version
  agentwall.exe --help
  ```

* **Command Prompt (CMD):**
  ```cmd
  agentwall.exe --version
  agentwall.exe --help
  ```

*(Optional: To run the demonstration test script `quickstart_agent.py`, Python 3.8+ is required):*
* **PowerShell:**
  ```powershell
  python "$env:USERPROFILE\.local\bin\quickstart_agent.py"
  ```
* **Command Prompt (CMD):**
  ```cmd
  python "%USERPROFILE%\.local\bin\quickstart_agent.py"
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

## 🛠️ Building from Source

If you prefer building AgentWall directly from source, you will need the Rust toolchain (Rust 1.89+):

### Prerequisites
- **Rust Toolchain:** Install via [rustup.rs](https://rustup.rs) (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- **C Compiler:** `build-essential` (Linux), Xcode CLI tools (macOS), or MSVC C++ Build Tools (Windows)

### Build Steps

```bash
# 1. Clone repository
git clone https://github.com/noviqtechnologies/agentwall.git
cd agentwall

# 2. Compile release binary
cargo build --release

# 3. Locate compiled binary
# Target output: ./target/release/agentwall (or ./target/release/agentwall.exe on Windows)
./target/release/agentwall --version
```

---

## ☸️ Kubernetes Deployment (For Production)

For high-availability production environments, AgentWall includes a complete Helm chart (`./chart`) supporting multi-replica gateways, Control Hub API, PostgreSQL database, and automated TLS certificate management.

### Step 1: Create Namespace & TLS Secrets

```bash
kubectl create namespace agentwall-system

kubectl create secret tls agentwall-tls \
  --cert=/etc/certs/tls.crt \
  --key=/etc/certs/tls.key \
  -n agentwall-system
```

### Step 2: Deploy via Helm

```bash
helm install agentwall ./chart \
  --namespace agentwall-system \
  --set gateway.tls.enabled=true \
  --set gateway.tls.secretName=agentwall-tls \
  --set dashboardApi.enabled=true \
  --set dashboardDb.enabled=true \
  --set dashboardFrontend.enabled=true
```

For custom configuration parameters and full values reference, see `chart/values.yaml`.

---

## 🛡️ Hardened Agent Container Runtime (HAR)

AgentWall provides a pre-built, light-footprint (<100MB) Distroless OCI sidecar image designed for Kubernetes pods and production containerized agent runtimes.

```bash
# Build the HAR sidecar container
docker build -f Dockerfile.har -t agentwall-har:2.0 .

# Run container with mounted policy
docker run -d \
  --name agentwall-har \
  -p 8080:8080 \
  -v ./agentwall-policy.yaml:/etc/agentwall/policy.yaml:ro \
  -e AGENTWALL_POLICY_PATH=/etc/agentwall/policy.yaml \
  agentwall-har:2.0
```

---

## 🧹 Uninstallation & Clean Removal

### Standalone Workstation Uninstallation

To restore all IDE configurations and remove AgentWall binaries:

* **macOS / Linux:**
  ```bash
  # 1. Revert all IDE configuration wraps
  agentwall unprotect

  # 2. Stop and uninstall Sentry service if installed
  agentwall service uninstall

  # 3. Run uninstaller script to remove binary and local files
  curl -fsSL https://raw.githubusercontent.com/noviqtechnologies/agentwall/main/uninstall.sh | bash
  ```

* **Windows (PowerShell):**
  ```powershell
  # 1. Revert all IDE configuration wraps
  agentwall.exe unprotect

  # 2. Stop and remove Windows SCM service if installed
  agentwall.exe service uninstall

  # 3. Run uninstaller script
  irm https://raw.githubusercontent.com/noviqtechnologies/agentwall/main/uninstall.ps1 | iex
  ```

### Kubernetes Helm Uninstallation

```bash
helm uninstall agentwall -n agentwall-system
kubectl delete namespace agentwall-system
```

