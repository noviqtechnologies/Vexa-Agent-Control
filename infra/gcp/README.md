# 🛡️ AgentWall on Google Cloud Run (v2)

Production-grade, ultra cost-effective (~$0–$15/month) serverless deployment of **AgentWall** and its Enterprise Control Plane on **Google Cloud Platform (GCP)** using **Google Cloud Run (v2)** with multi-container PostgreSQL sidecars.

---

## 📐 Architecture Overview

```mermaid
flowchart TD
    subgraph Internet ["🌐 Public Internet (Clients & SOC Teams)"]
        User["AI Client / MCP Agent"]
        Admin["Security Admin / SOC Team"]
    end

    subgraph GCP ["☁️ Google Cloud Platform (Serverless $0 Control Plane)"]
        subgraph CloudRun ["⚡ Google Cloud Run v2 (Free Auto-Managed HTTPS / TLS)"]
            subgraph GatewaySvc ["🛡️ Service: agentwall-dev-gateway"]
                GW["agentwall-gateway (Rust Proxy)\nPort: 8080 | 1 vCPU, 512 MiB"]
            end

            subgraph UISvc ["📊 Service: agentwall-dev-ui"]
                UI["control-plane-ui (Frontend Portal)\nPort: 80 | 1 vCPU, 512 MiB"]
            end

            subgraph APISvc ["⚙️ Service: agentwall-dev-api (Multi-Container Revision)"]
                API["dashboard-api (Backend REST API)\nPort: 8400 | Ingress Container"]
                DB["postgres (agentwall-db Engine)\nPort: 5432 (Localhost 127.0.0.1 Sidecar)"]
            end
        end

        subgraph Observability ["📊 Google Cloud Logging & Monitoring"]
            Logs["Cloud Logging & Metrics\n(First 50 GiB/month Free)"]
        end
    end

    User -->|MCP Tool Calls (HTTPS:443)| GatewaySvc --> GW
    Admin -->|Dashboard Access (HTTPS:443)| UISvc --> UI
    UI -->|REST API Calls (HTTPS:443)| APISvc --> API
    GW -->|Fetch Active Policies (HTTPS:443)| APISvc --> API
    API -->|Localhost TCP:5432| DB

    GW -.->|Stream Audit Logs| Logs
    UI -.->|Access Logs| Logs
    API -.->|Telemetry & Traces| Logs
```

---

## 💰 Cost Comparison: Google Cloud Run vs Azure vs AWS vs GKE

| Feature / Cost Factor | Google Cloud Run (This Module) | Azure Container Apps | AWS ECS Fargate | Google GKE (Kubernetes) |
| :--- | :--- | :--- | :--- | :--- |
| **Control Plane Fee** | **$0.00 / month** | **$0.00 / month** | $0.00 / month | $73.00 / month (Standard) |
| **Load Balancer / Ingress** | **$0.00 / month** (Built-in Ingress) | **$0.00 / month** (Built-in Envoy) | ~$16 - $20 / month (ALB) | ~$18 - $30 / month |
| **TLS / SSL Certificates** | **$0.00** (Free Auto-Issued) | **$0.00** (Free Auto-Issued) | $0.00 (ACM) | $0.00 (Cert-Manager) |
| **Compute Architecture** | Multi-Container Revision (Sidecar) | Microservice Containers | Fargate Multi-Container Task | Worker Node VMs |
| **Idle Scale-to-Zero** | **Supported (`min_instances = 0`)** | **Supported (`min_replicas = 0`)** | Not natively supported | Requires node scaling |
| **Monthly Free Allowance** | **2M requests, 360k GB-s, 180k vCPU-s** | 180k vCPU-s & 360k GiB-s | None for Fargate | None |
| **ESTIMATED MONTHLY COST** | **~$0 – $15 / month** | **~$15 – $20 / month** | **~$15 – $25 / month** | **~$100 – $150 / month** |

---

## 💻 Cross-Platform Prerequisites

This Terraform deployment runs seamlessly across **Windows**, **Linux**, and **macOS** with zero OS-specific dependencies.

### 1. Install Terraform (>= 1.6.0)
- **Windows (winget / choco)**:
  ```powershell
  winget install HashiCorp.Terraform
  # or: choco install terraform
  ```
- **macOS (Homebrew)**:
  ```bash
  brew tap hashicorp/tap
  brew install hashicorp/tap/terraform
  ```
- **Linux (Debian / Ubuntu / RHEL)**:
  ```bash
  sudo apt-get update && sudo apt-get install -y gnupg software-properties-common curl
  curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
  echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
  sudo apt-get update && sudo apt-get install terraform
  ```

### 2. Install Google Cloud SDK (`gcloud`) & Authenticate
- **Windows (PowerShell / winget):**
  ```powershell
  winget install Google.CloudSDK
  ```
- **macOS (Homebrew):**
  ```bash
  brew install --cask google-cloud-sdk
  ```
- **Linux (Debian / Ubuntu):**
  ```bash
  sudo apt-get install -y apt-transport-https ca-certificates gnupg curl
  curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg
  echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | sudo tee -a /etc/apt/sources.list.d/google-cloud-sdk.list
  sudo apt-get update && sudo apt-get install -y google-cloud-cli
  ```

- **Login & Set Target Project:**
  ```bash
  # Login with your Google user account
  gcloud auth login

  # Set application default credentials for Terraform
  gcloud auth application-default login

  # Configure target project
  gcloud config set project <your-gcp-project-id>
  ```

---

## 🚀 Quick Start Deployment

### On Windows (PowerShell):
```powershell
cd infra/gcp

# Copy the example variables file
Copy-Item terraform.tfvars.example terraform.tfvars

# Edit terraform.tfvars with your GCP project ID
# (e.g., notepad terraform.tfvars)

# Initialize Terraform providers
terraform init

# Plan and preview resources
terraform plan

# Deploy infrastructure
terraform apply
```

### On Linux or macOS (Bash / Zsh):
```bash
cd infra/gcp

# Copy the example variables file
cp terraform.tfvars.example terraform.tfvars

# Edit terraform.tfvars with your GCP project ID
# (e.g., nano terraform.tfvars)

# Initialize Terraform providers
terraform init

# Plan and preview resources
terraform plan

# Deploy infrastructure
terraform apply
```

---

## 🔍 Post-Deployment Validation Suite (Across All OS Types)

Once `terraform apply` finishes, the outputs will display public HTTPS URLs:

```text
Apply complete! Resources: 10 added, 0 changed, 0 destroyed.

Outputs:
control_plane_ui_url = "https://agentwall-dev-ui-xxxxxx-uc.a.run.app"
gateway_url          = "https://agentwall-dev-gateway-xxxxxx-uc.a.run.app"
dashboard_api_url    = "https://agentwall-dev-api-xxxxxx-uc.a.run.app"
health_check_url     = "https://agentwall-dev-gateway-xxxxxx-uc.a.run.app/healthz"
quick_verify_command = "curl -i https://agentwall-dev-gateway-xxxxxx-uc.a.run.app/healthz"
```

### Step 1: Verify Gateway Health Check

- **Windows (PowerShell):**
  ```powershell
  Invoke-RestMethod -Uri "https://<gateway-url>/healthz"
  ```
- **Linux / macOS (Bash / Zsh) & Windows CMD:**
  ```bash
  curl -i https://<gateway-url>/healthz
  ```
*Expected response: `HTTP 200 OK`*

### Step 2: Validate Policy Interception & Security Guardrails

Send test JSON-RPC MCP tool calls to the Cloud Run gateway endpoint:

- **Windows (PowerShell):**
  ```powershell
  # 1. Test blocked dangerous tool call (Default-Deny / Safe Mode)
  $blockedBody = '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_command","arguments":{"command":"rm -rf /"}}}'
  Invoke-RestMethod -Uri "https://<gateway-url>" -Method Post -Headers @{ "Content-Type" = "application/json"; "Authorization" = "Bearer test-token" } -Body $blockedBody

  # 2. Test safe authorized tool call
  $safeBody = '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_directory","arguments":{"path":"/workspace"}}}'
  Invoke-RestMethod -Uri "https://<gateway-url>" -Method Post -Headers @{ "Content-Type" = "application/json"; "Authorization" = "Bearer test-token" } -Body $safeBody
  ```

- **Linux / macOS (Bash / Zsh):**
  ```bash
  # 1. Test blocked dangerous tool call
  curl -X POST https://<gateway-url> \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer test-token" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_command","arguments":{"command":"rm -rf /"}}}'

  # 2. Test safe authorized tool call
  curl -X POST https://<gateway-url> \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer test-token" \
    -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_directory","arguments":{"path":"/workspace"}}}'
  ```

### Step 3: Access the Enterprise Control Plane UI
Open your browser and navigate to:
```text
https://<control-plane-ui-url>
```

### Step 4: Stream Live Container Logs (Google Cloud SDK)
```bash
# Windows PowerShell, macOS, or Linux
gcloud run services logs tail agentwall-dev-gateway \
  --project <your-gcp-project-id> \
  --region us-central1
```

---

## ⚙️ Advanced Customization

### 1. Dev Mode: Scale-to-Zero ($0 Idle Compute)
In `terraform.tfvars`, set `min_instances = 0`:
```hcl
min_instances = 0
```
When idle, Cloud Run scales down to 0 container instances, consuming zero compute resources and fitting entirely within Google Cloud's monthly free tier allowance.

### 2. Enterprise VPC Network & Connector
To deploy Cloud Run services with private VPC integration:
```hcl
enable_vpc     = true
vpc_cidr       = "10.10.0.0/16"
connector_cidr = "10.10.8.0/28"
```

### 3. Private Google Artifact Registry (GAR)
To provision a dedicated private Google Artifact Registry Docker repository:
```hcl
gar_enabled = true
```

---

## 🧹 Teardown & Clean Up

To delete all provisioned Google Cloud resources cleanly:
```bash
terraform destroy
```
