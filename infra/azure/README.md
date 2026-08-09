# 🛡️ AgentWall on Azure Container Apps (ACA)

Production-grade, highly cost-effective (~$15–$20/month) serverless deployment of **AgentWall** and its Enterprise Control Plane on **Microsoft Azure** using **Azure Container Apps (ACA)**.

---

## 📐 Architecture Overview

```mermaid
flowchart TD
    subgraph Internet ["🌐 Public Internet (Clients & SOC Teams)"]
        User["AI Client / MCP Agent"]
        Admin["Security Admin / SOC Team"]
    end

    subgraph ACA_Env ["☁️ Azure Container Apps Environment (Serverless $0 Control Plane)"]
        subgraph Ingress ["Built-in Envoy Ingress (Free Automatic HTTPS / TLS)"]
            GW_Ingress["https://agentwall-gateway...azurecontainerapps.io"]
            UI_Ingress["https://agentwall-ui...azurecontainerapps.io"]
            API_Ingress["https://agentwall-api...azurecontainerapps.io"]
        end

        subgraph Apps ["Serverless Container Apps"]
            Gateway["🛡️ agentwall-gateway (Rust Proxy)\nPort: 8080 | 0.25 vCPU, 0.5 GiB"]
            UI["📊 agentwall-ui (Control Plane Frontend)\nPort: 80 | 0.25 vCPU, 0.5 GiB"]
            API["⚙️ agentwall-api (Dashboard Backend)\nPort: 8400 | 0.25 vCPU, 0.5 GiB"]
            DB["🗄️ agentwall-db (PostgreSQL + Migrations)\nPort: 5432 (Internal Only) | 0.25 vCPU, 0.5 GiB"]
        end
    end

    subgraph Observability ["📊 Azure Monitor & Logging"]
        LogAnalytics["Azure Log Analytics Workspace\n(First 5 GB/mo Free)"]
    end

    User -->|MCP Tool Calls (HTTPS:443)| GW_Ingress --> Gateway
    Admin -->|Dashboard Access (HTTPS:443)| UI_Ingress --> UI
    UI -->|REST API Calls| API_Ingress --> API
    Gateway -->|Poll Active Policy (Internal DNS)| API
    API -->|Read/Write Schema & Audit| DB

    Gateway -.->|Stream Logs & Audit Trail| LogAnalytics
    API -.->|Telemetry| LogAnalytics
    DB -.->|Engine Logs| LogAnalytics
```

---

## 💰 Cost Comparison: Azure Container Apps vs AWS vs AKS

| Feature / Cost Factor | Azure Container Apps (This Module) | AWS ECS Fargate | AWS EKS Fargate | Azure AKS |
| :--- | :--- | :--- | :--- | :--- |
| **Control Plane Fee** | **$0.00 / month** | $0.00 / month | $73.00 / month | $0 - $73.00 / month |
| **Load Balancer / Ingress** | **$0.00 / month** (Built-in Ingress) | ~$18 - $25 / month (ALB) | ~$18 - $25 / month (ALB) | ~$18 - $30 / month |
| **TLS / SSL Certificates** | **$0.00** (Free Auto-Managed) | $0.00 (ACM) | $0.00 (ACM) | $0.00 (Cert-Manager) |
| **Compute Sizing** | 4 × 0.25 vCPU / 0.5 GiB | 1 × 1.0 vCPU / 2.0 GiB | 2-4 Fargate Pods | Minimum 2 VM Nodes |
| **Idle Scale-to-Zero** | **Supported (`min_replicas=0`)** | Not natively supported | Not supported | Requires KEDA setup |
| **Monthly Free Allowance** | **180k vCPU-s & 360k GiB-s free** | None for Fargate | None | None |
| **ESTIMATED MONTHLY COST** | **~$15 – $20 / month** | **~$18 – $25 / month** | **~$120 / month** | **~$100 – $140 / month** |

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

### 2. Install Azure CLI (`az`) & Authenticate
```bash
az login
az account set --subscription "<your-subscription-id-or-name>"
```

---

## 🚀 Quick Start Deployment

### On Windows (PowerShell):
```powershell
cd infra/azure

# Copy the example variables file
Copy-Item terraform.tfvars.example terraform.tfvars

# Initialize Terraform
terraform init

# Plan and preview resources
terraform plan

# Deploy infrastructure
terraform apply
```

### On Linux or macOS (Bash / Zsh):
```bash
cd infra/azure

# Copy the example variables file
cp terraform.tfvars.example terraform.tfvars

# Initialize Terraform
terraform init

# Plan and preview resources
terraform plan

# Deploy infrastructure
terraform apply
```

---

## 🔍 Verification & Health Checks

Once `terraform apply` finishes, the outputs will display the public HTTPS URLs:

```text
Apply complete! Resources: 7 added, 0 changed, 0 destroyed.

Outputs:
control_plane_ui_url = "https://agentwall-ui.<environment-id>.<region>.azurecontainerapps.io"
gateway_url          = "https://agentwall-gateway.<environment-id>.<region>.azurecontainerapps.io"
health_check_url     = "https://agentwall-gateway.<environment-id>.<region>.azurecontainerapps.io/healthz"
quick_verify_command = "curl -i https://agentwall-gateway.<environment-id>.<region>.azurecontainerapps.io/healthz"
```

### 1. Verify Gateway Health
```bash
curl -i https://<gateway-fqdn>/healthz
```
*Expected response: HTTP 200 OK*

### 2. Access the Enterprise Control Plane UI
Open your browser and navigate to:
```text
https://<control-plane-ui-fqdn>
```

### 3. Stream Live Container Logs (Azure CLI)
```bash
az containerapp logs show \
  --name agentwall-gateway \
  --resource-group rg-agentwall-dev-westeurope \
  --follow
```

---

## ⚙️ Advanced Customization

### 1. Dev Mode: Scale-to-Zero ($0 Idle Compute)
In `terraform.tfvars`, set `min_replicas = 0`:
```hcl
min_replicas = 0
```
When idle, instances spin down to 0 replicas, consuming zero CPU/memory and fitting completely within Azure's monthly free tier.

### 2. Enterprise VNet Isolation
To isolate Container Apps inside a custom Azure Virtual Network and Subnet, enable VNet integration:
```hcl
enable_vnet_integration = true
vnet_cidr               = "10.10.0.0/16"
aca_subnet_cidr         = "10.10.0.0/23"
```

### 3. Private Azure Container Registry (ACR)
To provision a dedicated Azure Container Registry:
```hcl
acr_enabled = true
```

---

## 🧹 Teardown & Clean Up

To delete all provisioned Azure resources cleanly:
```bash
terraform destroy
```
