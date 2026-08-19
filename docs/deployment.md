# Deployment & Installation

Welcome to the Agent Control installation guide! Whether you are on Windows, macOS, or Linux, this guide will walk you through setting up Agent Control step-by-step so you can start securing your AI agents immediately.

## 🍎 macOS Installation

### Step 1: Open your Terminal
You can find the Terminal app by pressing `Cmd + Space` (Spotlight Search), typing `Terminal`, and pressing `Return`.

### Step 2: Download and Install Agent Control
Copy the following command, paste it into your Terminal window, and press `Return`:

```bash
# Standard local developer mode
curl -fsSL https://vexasec.io/install.sh | bash

# Automated enterprise enrollment & persistent system daemon installation
curl -fsSL https://vexasec.io/install.sh | AGENTWALL_TOKEN="TOK-YOUR-TOKEN" bash
```
*This script safely downloads the Agent Control application, places it in `~/.local/bin`, and optionally registers the persistent system daemon (`systemd` / `launchd`).*

### Step 3: Make Agent Control accessible
To ensure you can run the `agentcontrol` command from anywhere, you need to add it to your system path. Paste this into your Terminal and press `Return`:

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

### Step 4: Verify Installation
Type the following and press `Return`. If you see the Agent Control help menu, you are good to go!
```bash
agentcontrol --help
```

---

## 🐧 Linux Installation

### Step 1: Open your Terminal
Open your preferred terminal emulator (e.g., GNOME Terminal, Konsole, xterm).

### Step 2: Download and Install Agent Control
Paste the following command to download and install the binary:

```bash
curl -fsSL https://vexasec.io/install.sh | bash
```

### Step 3: Make Agent Control accessible
Add the installation directory to your bash profile:

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

### Step 4: Verify Installation
```bash
agentcontrol --help
```

---

## 🪟 Windows Installation

### Step 1: Open PowerShell or Command Prompt
Press the `Windows` key on your keyboard, type `PowerShell` or `cmd`, and launch your preferred terminal.

### Step 2: Download and Install Agent Control

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
> - **Enterprise Automated Deployments (Intune / SCCM / GPO / MSI):** Installer packages and GPO deployment tasks run under **`NT AUTHORITY\SYSTEM`** with full administrative privileges. **`agentcontrol service install` runs automatically without user interaction.**
> - **Manual Script Execution (`install.ps1`):** Executing `install.ps1` in a standard user PowerShell or CMD session installs the binary to `%USERPROFILE%\.local\bin`. **Installing the SCM Service (`agentcontrol service install`) requires opening PowerShell with "Run as Administrator".**
> - **Non-Admin Fallback:** Users without administrative privileges can run the sentry daemon interactively using **`agentcontrol watch`** in a standard user terminal.

*(Alternatively, download the ZIP archive manually):*
* **PowerShell:**
  ```powershell
  Invoke-WebRequest -Uri "https://github.com/noviqtechnologies/Vexa-Agent-Control/releases/latest/download/agentcontrol-windows-x86_64.zip" -OutFile "agentcontrol.zip"
  Expand-Archive -Path "agentcontrol.zip" -DestinationPath "$env:USERPROFILE\.local" -Force
  $env:PATH += ";$env:USERPROFILE\.local\bin"
  ```
* **Command Prompt (CMD):**
  ```cmd
  curl.exe -fsSL https://github.com/noviqtechnologies/Vexa-Agent-Control/releases/latest/download/agentcontrol-windows-x86_64.zip -o agentcontrol.zip
  tar -xf agentcontrol.zip -C "%USERPROFILE%\.local\bin"
  set PATH=%PATH%;%USERPROFILE%\.local\bin
  ```

### Step 3: Verify Installation

* **PowerShell:**
  ```powershell
  agentcontrol.exe --version
  agentcontrol.exe --help
  ```

* **Command Prompt (CMD):**
  ```cmd
  agentcontrol.exe --version
  agentcontrol.exe --help
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

For local development, testing, and proof-of-concept (PoC) scenarios, you can run Agent Control and the Team Control Hub stack using Docker or Docker Compose.

```bash
# Option A: Standalone Gateway Container
docker run -d \
  --name agentcontrol \
  -p 8080:8080 \
  -v ./policy.yaml:/etc/agentcontrol/policy.yaml:ro \
  -v ./audit.log:/var/log/agentcontrol/audit.log \
  ghcr.io/noviqtechnologies/agentcontrol:latest \
  start --policy /etc/agentcontrol/policy.yaml --listen 0.0.0.0:8080

# Option B: Complete Control Hub Stack (Compose)
cd control-plane
docker compose up -d --build
```

For full details, see → [Team Control Hub Guide — Docker Deployment](team_hub_guide.md#21-docker-deployment-local-dev-testing--poc).

---

## 🛠️ Building from Source

If you prefer building Agent Control directly from source, you will need the Rust toolchain (Rust 1.80+ Stable):

### Prerequisites
- **Rust Toolchain:** Install via [rustup.rs](https://rustup.rs) (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- **C Compiler:** `build-essential` (Linux), Xcode CLI tools (macOS), or MSVC C++ Build Tools (Windows)

### Build Steps

```bash
# 1. Clone repository
git clone https://github.com/noviqtechnologies/Vexa-Agent-Control.git
cd Vexa-Agent-Control

# 2. Compile release binary
cargo build --release

# 3. Locate compiled binary
# Target output: ./target/release/agentcontrol (or ./target/release/agentcontrol.exe on Windows)
./target/release/agentcontrol --version
```

---

## ☸️ Kubernetes Deployment (For Production)

For high-availability production environments, Agent Control includes a complete Helm chart (`./chart`) supporting multi-replica gateways, Control Hub API, PostgreSQL database, and automated TLS certificate management.

### Step 1: Create Namespace & TLS Secrets

```bash
kubectl create namespace agentcontrol-system

kubectl create secret tls agentcontrol-tls \
  --cert=/etc/certs/tls.crt \
  --key=/etc/certs/tls.key \
  -n agentcontrol-system
```

### Step 2: Deploy via Helm

```bash
helm install agentcontrol ./chart \
  --namespace agentcontrol-system \
  --set gateway.tls.enabled=true \
  --set gateway.tls.secretName=agentcontrol-tls \
  --set dashboardApi.enabled=true \
  --set dashboardDb.enabled=true \
  --set dashboardFrontend.enabled=true
```

For custom configuration parameters and full values reference, see `chart/values.yaml`.

---

## 🛡️ Hardened Agent Container Runtime (HAR)

Agent Control provides a pre-built, light-footprint (<100MB) Distroless OCI sidecar image designed for Kubernetes pods and production containerized agent runtimes.

```bash
# Build the HAR sidecar container
docker build -f Dockerfile.har -t agentcontrol-har:2.0 .

# Run container with mounted policy
docker run -d \
  --name agentcontrol-har \
  -p 8080:8080 \
  -v ./agentcontrol-policy.yaml:/etc/agentcontrol/policy.yaml:ro \
  -e AGENTWALL_POLICY_PATH=/etc/agentcontrol/policy.yaml \
  agentcontrol-har:2.0
```

---

## 🧹 Uninstallation & Clean Removal

### Standalone Workstation Uninstallation

To restore all IDE configurations and remove Agent Control binaries:

* **macOS / Linux:**
  ```bash
  # 1. Revert all IDE configuration wraps
  agentcontrol unprotect

  # 2. Stop and uninstall Sentry service if installed
  agentcontrol service uninstall

  # 3. Run uninstaller script to remove binary and local files
  curl -fsSL https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/uninstall.sh | bash
  ```

* **Windows (PowerShell):**
  ```powershell
  # 1. Revert all IDE configuration wraps
  agentcontrol.exe unprotect

  # 2. Stop and remove Windows SCM service if installed
  agentcontrol.exe service uninstall

  # 3. Run uninstaller script
  irm https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/uninstall.ps1 | iex
  ```

### Kubernetes Helm Uninstallation

```bash
helm uninstall agentcontrol -n agentcontrol-system
kubectl delete namespace agentcontrol-system
```

