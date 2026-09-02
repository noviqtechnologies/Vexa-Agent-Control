# 🌐 AgentWall Multi-Cloud Infrastructure (Terraform)

Welcome to the **AgentWall** Multi-Cloud Infrastructure suite. This directory contains production-ready, highly cost-effective (~$0–$25/month), and cross-platform **Terraform modules** for deploying AgentWall and its full Enterprise Control Plane stack across the leading public cloud providers:

- **[Amazon Web Services (AWS)](aws/README.md)** — AWS ECS Fargate & Application Load Balancer
- **[Microsoft Azure](azure/README.md)** — Azure Container Apps (ACA) with Built-in Envoy Ingress & Scale-to-Zero
- **[Google Cloud Platform (GCP)](gcp/README.md)** — Google Cloud Run (v2) with Multi-Container Sidecars & Scale-to-Zero

---

## 📊 Cloud Architecture Comparison Matrix

All three deployments provision the complete, self-contained AgentWall system:
1. **🛡️ Gateway Proxy** (`port 8080`) — Rust proxy enforcing default-deny, safe-mode guardrails, and DLP.
2. **📊 Control Plane UI** (`port 80 / 8081`) — React/TypeScript administrative management portal.
3. **⚙️ Dashboard REST API** (`port 8400`) — Centralized Go backend managing policies and telemetry.
4. **🗄️ PostgreSQL Database** (`port 5432`) — Relational store with automatic bootstrap schema migrations.

| Feature / Architecture Aspect | [AWS ECS Fargate](aws/README.md) | [Azure Container Apps](azure/README.md) | [Google Cloud Run (v2)](gcp/README.md) |
| :--- | :--- | :--- | :--- |
| **Compute Technology** | AWS ECS Fargate Task (1.0 vCPU, 2 GiB) | Serverless Microservice Apps (4 × 0.25 vCPU) | Multi-Container Revision + Sidecar |
| **Control Plane Fee** | **$0.00 / month** | **$0.00 / month** | **$0.00 / month** |
| **Ingress & Routing** | AWS Application Load Balancer (ALB) | Built-in Envoy Ingress (Free) | Built-in Google Cloud Ingress (Free) |
| **TLS / SSL Certificate** | Free via ACM (or HTTP over ALB) | **Automatic Free Managed TLS** | **Automatic Free Managed TLS** |
| **Scale-to-Zero ($0 Idle)** | Fixed 1 Task for Stage | **Supported natively (`min_replicas = 0`)** | **Supported natively (`min_instances = 0`)** |
| **Monthly Free Tier** | None for Fargate | **180k vCPU-s & 360k GiB-s free** | **2M reqs, 360k GB-s, 180k vCPU-s free** |
| **Logging & Telemetry** | AWS CloudWatch Logs (3-day stage) | Azure Log Analytics (30-day free) | Google Cloud Logging (50 GiB/mo free) |
| **Secret Management** | Automated Secret Generation & Inject | Built-in ACA Secrets Store | Google Secret Manager |
| **ESTIMATED STAGE COST** | **~$15 – $25 / month** | **~$0 – $5 / month** | **~$0 – $2 / month** |
| **Stage Deployment** | `terraform apply -var-file="terraform.stage.tfvars"` | `terraform apply -var-file="terraform.stage.tfvars"` | `terraform apply -var-file="terraform.stage.tfvars"` |
| **Target Directory** | [`infra/aws/ecs/`](aws/README.md) | [`infra/azure/`](azure/README.md) | [`infra/gcp/`](gcp/README.md) |

---

## 💻 Cross-Platform Prerequisites & Cloud CLI Setup

Before deploying to any cloud provider, ensure you have **Terraform** and the respective **Cloud CLI** installed and authenticated on your machine.

### 1. Install Terraform (`>= 1.6.0`)

* **Windows (PowerShell / winget / choco):**
  ```powershell
  winget install HashiCorp.Terraform
  # or: choco install terraform
  ```
* **macOS (Homebrew):**
  ```bash
  brew tap hashicorp/tap
  brew install hashicorp/tap/terraform
  ```
* **Linux (Debian / Ubuntu / RHEL):**
  ```bash
  sudo apt-get update && sudo apt-get install -y gnupg software-properties-common curl
  curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
  echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
  sudo apt-get update && sudo apt-get install terraform
  ```

---

### 2. Cloud Provider CLI & Authentication

#### 🅰️ Amazon Web Services (AWS)
1. **Install AWS CLI v2:**
   - **Windows:** `winget install Amazon.AWSCLI`
   - **macOS:** `brew install awscli`
   - **Linux:** `curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" && unzip awscliv2.zip && sudo ./aws/install`
2. **Authenticate & Configure Region:**
   ```bash
   aws configure
   # Enter AWS Access Key ID, Secret Access Key, and default region (e.g., eu-west-1 or us-east-1)
   ```
3. **Required Permissions:** IAM privileges to create VPCs, Subnets, Internet Gateways, Security Groups, ALBs, ECS Clusters/Services/Tasks, CloudWatch Log Groups, and IAM Roles.

#### 🅱️ Microsoft Azure
1. **Install Azure CLI (`az`):**
   - **Windows:** `winget install Microsoft.AzureCLI`
   - **macOS:** `brew install azure-cli`
   - **Linux:** `curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash`
2. **Authenticate & Set Subscription:**
   ```bash
   az login
   az account set --subscription "<your-subscription-id-or-name>"
   ```
3. **Register Required Resource Providers (One-Time):**
   ```bash
   az provider register --namespace Microsoft.App
   az provider register --namespace Microsoft.OperationalInsights
   az provider register --namespace Microsoft.ContainerRegistry
   ```

#### 🅲 Google Cloud Platform (GCP)
1. **Install Google Cloud SDK (`gcloud`):**
   - **Windows:** `winget install Google.CloudSDK`
   - **macOS:** `brew install --cask google-cloud-sdk`
   - **Linux:** `sudo apt-get install google-cloud-sdk`
2. **Authenticate & Configure Default Project:**
   ```bash
   gcloud auth login
   gcloud auth application-default login
   gcloud config set project <your-gcp-project-id>
   ```
3. **Required Permissions & APIs:** Project Editor/Owner role, or permissions to enable and manage Cloud Run, Compute Engine, Artifact Registry, and Cloud Logging.

---

## 🚀 Quick Deployment Cheat Sheet

### Deploy to AWS ECS Fargate
```bash
cd infra/aws/ecs
terraform init
terraform plan
terraform apply
```
* **Documentation & Details:** → [AWS ECS Deployment Guide](aws/README.md)

---

### Deploy to Azure Container Apps
```bash
# Windows PowerShell
cd infra/azure
Copy-Item terraform.tfvars.example terraform.tfvars
terraform init
terraform plan
terraform apply

# Linux / macOS
cd infra/azure
cp terraform.tfvars.example terraform.tfvars
terraform init
terraform plan
terraform apply
```
* **Documentation & Details:** → [Azure Container Apps Guide](azure/README.md)

---

### Deploy to Google Cloud Run (v2)
```bash
# Windows PowerShell
cd infra/gcp
Copy-Item terraform.tfvars.example terraform.tfvars
# Update gcp_project_id in terraform.tfvars
terraform init
terraform plan
terraform apply

# Linux / macOS
cd infra/gcp
cp terraform.tfvars.example terraform.tfvars
# Update gcp_project_id in terraform.tfvars
terraform init
terraform plan
terraform apply
```
* **Documentation & Details:** → [Google Cloud Run Guide](gcp/README.md)

---

---

## 🔍 Post-Deployment Validation Suite (Across All OS Types)

Follow these multi-step validation checks to verify gateway health, active policy enforcement, dashboard UI access, and log streaming on **Windows (PowerShell / CMD)**, **Linux (Bash)**, and **macOS (Zsh)**.

### Step 1: Gateway Health Check

* **Windows (PowerShell):**
  ```powershell
  # AWS ECS
  Invoke-RestMethod -Uri "http://<ALB-DNS-NAME>:8080/healthz"
  # Azure ACA
  Invoke-RestMethod -Uri "https://<gateway-fqdn>/healthz"
  # GCP Cloud Run
  Invoke-RestMethod -Uri "https://<gateway-url>/healthz"
  ```

* **Linux / macOS (Bash / Zsh) & Windows CMD:**
  ```bash
  # AWS ECS
  curl -i http://<ALB-DNS-NAME>:8080/healthz
  # Azure ACA
  curl -i https://<gateway-fqdn>/healthz
  # GCP Cloud Run
  curl -i https://<gateway-url>/healthz
  ```
* **Expected Response:** `HTTP 200 OK` with status payload.

---

### Step 2: Policy Interception & Default-Deny Validation

Send a test MCP tool call directly to the cloud gateway to verify that the security firewall intercepts and evaluates execution policies:

* **Windows (PowerShell):**
  ```powershell
  # 1. Test Safe Mode Interception (Blocked dangerous command)
  $body = '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_command","arguments":{"command":"rm -rf /"}}}'
  Invoke-RestMethod -Uri "http://<GATEWAY-ENDPOINT>:8080" -Method Post -Headers @{ "Content-Type" = "application/json"; "Authorization" = "Bearer test-session-token" } -Body $body

  # 2. Test Safe Authorized Call
  $safeBody = '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_directory","arguments":{"path":"/workspace"}}}'
  Invoke-RestMethod -Uri "http://<GATEWAY-ENDPOINT>:8080" -Method Post -Headers @{ "Content-Type" = "application/json"; "Authorization" = "Bearer test-session-token" } -Body $safeBody
  ```

* **Linux / macOS (Bash / Zsh):**
  ```bash
  # 1. Test Safe Mode Interception (Blocked dangerous command)
  curl -X POST http://<GATEWAY-ENDPOINT>:8080 \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer test-session-token" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_command","arguments":{"command":"rm -rf /"}}}'

  # 2. Test Safe Authorized Call
  curl -X POST http://<GATEWAY-ENDPOINT>:8080 \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer test-session-token" \
    -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_directory","arguments":{"path":"/workspace"}}}'
  ```

---

### Step 3: Access Enterprise Control Plane UI

Open your web browser and navigate to the web console URL from your Terraform outputs:
- **AWS ECS:** `http://<ALB-DNS-NAME>:8081`
- **Azure ACA:** `https://<ui-fqdn>`
- **GCP Cloud Run:** `https://<ui-url>`

Confirm that the dashboard renders the active gateway connection, event telemetry feed, and policy rules.

---

### Step 4: Stream Live Cloud Container Logs

Validate that audit logs and system telemetry are actively ingesting into your cloud provider's log stream:

* **AWS CloudWatch Logs (Windows / macOS / Linux):**
  ```bash
  aws logs tail /ecs/agentwall --follow --format short
  ```

* **Azure Container Apps (Windows / macOS / Linux):**
  ```bash
  az containerapp logs show --name agentwall-gateway --resource-group <resource-group-name> --follow
  ```

* **Google Cloud Run (Windows / macOS / Linux):**
  ```bash
  gcloud run services logs tail agentwall-dev-gateway --region <region>
  ```

---

## 🧹 Teardown & Clean Up

To destroy all provisioned cloud resources and avoid any recurring charges:

```bash
# From within the respective infra directory (infra/aws/ecs, infra/azure, or infra/gcp)
terraform destroy
```
