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

## ☁️ Multi-Cloud Serverless Deployment (Terraform)

Deploy production-ready, cost-effective (~$0–$25/month) serverless AgentWall infrastructure on **AWS**, **Azure**, or **GCP** using our official Terraform modules.

### Prerequisites

1. **Install Terraform (`>= 1.6.0`):**
   - **Windows:** `winget install HashiCorp.Terraform`
   - **macOS:** `brew tap hashicorp/tap && brew install hashicorp/tap/terraform`
   - **Linux:** `sudo apt-get install terraform`
2. **Cloud CLI & Authentication:**
   - **AWS:** `aws configure` (AWS CLI v2)
   - **Azure:** `az login && az account set --subscription <id>` (Azure CLI)
   - **GCP:** `gcloud auth login && gcloud auth application-default login` (Google Cloud SDK)

---

### 🅰️ Amazon Web Services — AWS ECS Fargate

Provisions a VPC, Application Load Balancer (ALB), ECS Fargate task (Gateway, Control Plane UI, Go API, PostgreSQL), and CloudWatch Log Group.

* **Target Directory:** `infra/aws/ecs/`
* **Monthly Cost:** ~$15–$25 / month

```bash
cd infra/aws/ecs

# Initialize Terraform providers
terraform init

# Review execution plan
terraform plan

# Apply and deploy infrastructure
terraform apply
```

**Post-Deployment Validation:**

* **Windows (PowerShell):**
  ```powershell
  # 1. Health Check
  Invoke-RestMethod -Uri "http://<ALB-DNS-NAME>:8080/healthz"

  # 2. Test Policy Guardrail Interception
  $body = '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_command","arguments":{"command":"rm -rf /"}}}'
  Invoke-RestMethod -Uri "http://<ALB-DNS-NAME>:8080" -Method Post -Headers @{ "Content-Type" = "application/json"; "Authorization" = "Bearer test-token" } -Body $body

  # 3. Stream CloudWatch Logs
  aws logs tail /ecs/agentwall --follow --format short
  ```

* **Linux / macOS (Bash / Zsh):**
  ```bash
  # 1. Health Check
  curl -i http://<ALB-DNS-NAME>:8080/healthz

  # 2. Test Policy Guardrail Interception
  curl -X POST http://<ALB-DNS-NAME>:8080 \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer test-token" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_command","arguments":{"command":"rm -rf /"}}}'

  # 3. Stream CloudWatch Logs
  aws logs tail /ecs/agentwall --follow --format short
  ```

* **Control Plane UI:** Navigate to `http://<ALB-DNS-NAME>:8081` in your browser.

→ **[Full AWS Guide](../infra/aws/README.md)**

---

### 🅱️ Microsoft Azure — Azure Container Apps (ACA)

Provisions Azure Container Apps with built-in Envoy ingress (automatic free HTTPS/TLS certificates), Log Analytics workspace, and dev scale-to-zero compute.

* **Target Directory:** `infra/azure/`
* **Monthly Cost:** ~$0–$20 / month (Free Auto-TLS & Scale-to-Zero)

**On Windows (PowerShell):**
```powershell
cd infra/azure
Copy-Item terraform.tfvars.example terraform.tfvars
terraform init
terraform plan
terraform apply
```

**On Linux / macOS:**
```bash
cd infra/azure
cp terraform.tfvars.example terraform.tfvars
terraform init
terraform plan
terraform apply
```

**Post-Deployment Validation:**

* **Windows (PowerShell):**
  ```powershell
  # 1. Health Check
  Invoke-RestMethod -Uri "https://<gateway-fqdn>/healthz"

  # 2. Test Policy Guardrail Interception
  $body = '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_command","arguments":{"command":"rm -rf /"}}}'
  Invoke-RestMethod -Uri "https://<gateway-fqdn>" -Method Post -Headers @{ "Content-Type" = "application/json"; "Authorization" = "Bearer test-token" } -Body $body

  # 3. Stream Azure Logs
  az containerapp logs show --name agentwall-gateway --resource-group rg-agentwall-dev-westeurope --follow
  ```

* **Linux / macOS (Bash / Zsh):**
  ```bash
  # 1. Health Check
  curl -i https://<gateway-fqdn>/healthz

  # 2. Test Policy Guardrail Interception
  curl -X POST https://<gateway-fqdn> \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer test-token" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_command","arguments":{"command":"rm -rf /"}}}'

  # 3. Stream Azure Logs
  az containerapp logs show --name agentwall-gateway --resource-group rg-agentwall-dev-westeurope --follow
  ```

* **Control Plane UI:** Navigate to `https://<ui-fqdn>` in your browser.

→ **[Full Azure Guide](../infra/azure/README.md)**

---

### 🅲 Google Cloud Platform — Cloud Run (v2)

Provisions Cloud Run services with multi-container revisions (API + Postgres sidecar), auto-managed HTTPS certificates, and scale-to-zero.

* **Target Directory:** `infra/gcp/`
* **Monthly Cost:** ~$0–$15 / month (Free Auto-TLS & Scale-to-Zero)

**On Windows (PowerShell):**
```powershell
cd infra/gcp
Copy-Item terraform.tfvars.example terraform.tfvars
# Update gcp_project_id in terraform.tfvars
terraform init
terraform plan
terraform apply
```

**On Linux / macOS:**
```bash
cd infra/gcp
cp terraform.tfvars.example terraform.tfvars
# Update gcp_project_id in terraform.tfvars
terraform init
terraform plan
terraform apply
```

**Post-Deployment Validation:**

* **Windows (PowerShell):**
  ```powershell
  # 1. Health Check
  Invoke-RestMethod -Uri "https://<gateway-url>/healthz"

  # 2. Test Policy Guardrail Interception
  $body = '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_command","arguments":{"command":"rm -rf /"}}}'
  Invoke-RestMethod -Uri "https://<gateway-url>" -Method Post -Headers @{ "Content-Type" = "application/json"; "Authorization" = "Bearer test-token" } -Body $body

  # 3. Stream Google Cloud Logs
  gcloud run services logs tail agentwall-dev-gateway --region us-central1
  ```

* **Linux / macOS (Bash / Zsh):**
  ```bash
  # 1. Health Check
  curl -i https://<gateway-url>/healthz

  # 2. Test Policy Guardrail Interception
  curl -X POST https://<gateway-url> \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer test-token" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_command","arguments":{"command":"rm -rf /"}}}'

  # 3. Stream Google Cloud Logs
  gcloud run services logs tail agentwall-dev-gateway --region us-central1
  ```

* **Control Plane UI:** Navigate to `https://<ui-url>` in your browser.

→ **[Full GCP Guide](../infra/gcp/README.md)**

---

## ☸️ Kubernetes Deployment (For Production)

For high-availability production deployments, AgentWall includes a complete Helm chart (`./chart`) with a Kubernetes operator, CRDs, multi-replica gateway deployment, Control Hub API, PostgreSQL database, and optional NetworkPolicy enforcement.

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

---

## 🧹 Cloud Infrastructure Teardown

To destroy any provisioned cloud resources and stop billing:

```bash
# Run from within the respective infra directory (infra/aws/ecs, infra/azure, or infra/gcp)
terraform destroy
```

