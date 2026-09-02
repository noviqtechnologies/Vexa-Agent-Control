# 🛡️ AgentWall on Azure Container Apps (ACA) — Stage & Serverless Deployment

Ultra cost-effective (**~$0–$5/month** for Staging / **~$15–$20/month** for Production) serverless deployment of **AgentWall** and its Enterprise Control Plane on **Microsoft Azure** using **Azure Container Apps (ACA)** with scale-to-zero microservices and PostgreSQL engine.

---

## 📐 Architecture Overview

```mermaid
flowchart TD
    subgraph Internet ["🌐 Public Internet (Clients & SOC Teams)"]
        User["AI Client / MCP Agent"]
        Admin["Security Admin / SOC Team"]
    end

    subgraph Azure ["☁️ Microsoft Azure (Serverless ACA Environment)"]
        subgraph ACAEnv ["⚡ Azure Container Apps Managed Environment ($0 Control Plane)"]
            subgraph GatewayApp ["🛡️ App: agentwall-gateway (Public Ingress)"]
                GW["agentwall-gateway (Rust Proxy)\nPort: 8080 | 0.25 vCPU, 0.5 GiB | min=0"]
            end

            subgraph UIApp ["📊 App: agentwall-ui (Public Ingress)"]
                UI["control-plane-ui (Frontend Portal)\nPort: 80 | 0.25 vCPU, 0.5 GiB | min=0"]
            end

            subgraph APIApp ["⚙️ App: agentwall-api (Public Ingress)"]
                API["dashboard-api (Backend REST API)\nPort: 8400 | 0.25 vCPU, 0.5 GiB | min=0"]
            end

            subgraph DBApp ["🗄️ App: agentwall-db (Internal TCP)"]
                DB["postgres (agentwall-db Engine)\nPort: 5432 (Internal Only) | min=0"]
            end

            subgraph ValkeyApp ["⚡ App: agentwall-valkey (Internal TCP)"]
                Cache["valkey (Caching Engine)\nPort: 6379 (Internal Only) | min=0"]
            end
        end

        subgraph Observability ["📊 Azure Log Analytics Workspace"]
            Logs["Log Analytics (PerGB2018)\n(30-day retention)"]
        end
    end

    User -->|MCP Tool Calls (HTTPS:443)| GatewayApp --> GW
    Admin -->|Dashboard Access (HTTPS:443)| UIApp --> UI
    UI -->|REST API Calls (HTTPS:443)| APIApp --> API
    GW -->|Fetch Active Policies (HTTP:8400)| APIApp --> API
    API -->|Internal TCP:5432| DBApp --> DB
    API -->|Internal TCP:6379| ValkeyApp --> Cache

    GW -.->|Stream Audit Logs| Logs
    UI -.->|Access Logs| Logs
    API -.->|Telemetry & Traces| Logs
```

---

## 💰 Cost Optimization Matrix (Stage vs Prod)

| Feature / Resource | Stage Environment Configuration | Production Configuration | Monthly Staging Cost |
| :--- | :--- | :--- | :--- |
| **Compute Scaling** | **Scale-to-Zero (`min_replicas = 0`)** | Always-On (`min_replicas = 1`) | **$0.00** (Free Tier: 180k vCPU-s, 360k GiB-s) |
| **Max Replicas** | `max_replicas = 3` (Budget safety) | `max_replicas = 5-10` | Included |
| **Container Sizing** | 0.25 vCPU, 0.5 GiB RAM per app | 0.5 – 1.0 vCPU, 1.0 GiB | Included |
| **Database Tier** | Serverless Container App PostgreSQL | Dedicated Managed Postgres | **$0.00** (No VM fee) |
| **Ingress / TLS** | ACA Built-in Envoy Ingress (Free TLS) | ACA Built-in Ingress | **$0.00** (No ALB fee) |
| **Networking (VNet)** | Serverless Direct (`enable_vnet_integration = false`) | Dedicated VNet + Subnet | **$0.00** (No VNet/NAT fee) |
| **Log Analytics** | 30-day retention | 30-90 day retention | **$0.00** (Within free tier) |
| **MONTHLY COST** | **~$0.00 – $5.00 / month** | **~$15 – $20 / month** | **~$0 – $5 / mo** |

---

## 🚀 Quick Start: Deploy Stage Environment

### Step 1: Authenticate to Azure CLI
```bash
az login
az account set --subscription "<your-subscription-id>"
```

### Step 2: Initialize & Validate Terraform
```powershell
cd infra/azure

# Initialize Terraform providers
terraform init

# Validate configuration syntax
terraform validate
```

### Step 3: Plan & Deploy Stage Environment
```powershell
# Review staging execution plan
terraform plan -var-file="terraform.stage.tfvars"

# Apply staging infrastructure
terraform apply -var-file="terraform.stage.tfvars"
```

---

## 🔍 Post-Deployment Verification Suite

Once `terraform apply` finishes, the outputs display public HTTPS endpoints:

```text
Apply complete! Resources: 8 added, 0 changed, 0 destroyed.

Outputs:
control_plane_ui_url = "https://agentwall-ui.xxxxxx.westeurope.azurecontainerapps.io"
gateway_url          = "https://agentwall-gateway.xxxxxx.westeurope.azurecontainerapps.io"
dashboard_api_url    = "https://agentwall-api.xxxxxx.westeurope.azurecontainerapps.io"
health_check_url     = "https://agentwall-gateway.xxxxxx.westeurope.azurecontainerapps.io/healthz"
quick_verify_command = "curl -i https://agentwall-gateway.xxxxxx.westeurope.azurecontainerapps.io/healthz"
```

### 1. Verify Gateway Health Check
```bash
curl -i https://<gateway-url>/healthz
```

### 2. Stream Live Staging Logs
```bash
az containerapp logs show --name agentwall-gateway --resource-group rg-agentwall-stage-westeurope --follow
```

### 3. Teardown Stage Environment
```bash
terraform destroy -var-file="terraform.stage.tfvars"
```
