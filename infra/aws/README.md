# 🛡️ AgentWall on AWS (ECS Fargate) — Stage & Serverless Deployment

Cost-effective (**~$15–$25/month**) containerized deployment of **AgentWall** and its Enterprise Control Plane on **Amazon Web Services (AWS)** using **AWS ECS Fargate** and an Application Load Balancer (ALB).

---

## 📐 Architecture Overview

```mermaid
flowchart TD
    subgraph Internet ["🌐 Public Internet (Clients & SOC Teams)"]
        User["AI Client / MCP Agent"]
        Admin["Security Admin / SOC Team"]
    end

    subgraph AWS ["☁️ AWS Cloud (eu-west-1 / configurable)"]
        subgraph ALB ["Application Load Balancer (ALB)"]
            Listener8080["HTTP Listener :8080 (Gateway Ingress)"]
            Listener8081["HTTP Listener :8081 (Control Plane UI)"]
        end

        subgraph ECS_Cluster ["⚡ ECS Cluster ($0 Control Plane Fee)"]
            subgraph Task ["Fargate Task (1.0 vCPU / 2048 MiB)"]
                GW["🛡️ gateway\nPort: 8080 (Rust Proxy)"]
                UI["📊 control-plane-ui\nPort: 8081 (Frontend Dashboard)"]
                API["⚙️ dashboard-api\nPort: 8400 (Backend API)"]
                DB["🗄️ postgres\nPort: 5432 (PostgreSQL Engine)"]
                Cache["⚡ valkey\nPort: 6379 (Caching Engine)"]
            end
        end

        subgraph Observability ["📊 AWS CloudWatch"]
            CW["Log Group: /ecs/agentwall-stage\n(3-Day Retention for Staging)"]
        end
    end

    User -->|MCP Tool Calls| Listener8080 --> GW
    Admin -->|Dashboard Access| Listener8081 --> UI
    UI -->|REST API Calls (127.0.0.1:8400)| API
    GW -->|Fetch Active Policies (127.0.0.1:8400)| API
    API -->|Read/Write (127.0.0.1:5432)| DB
    API -->|Cache (127.0.0.1:6379)| Cache

    GW -.->|Logs| CW
    UI -.->|Logs| CW
    API -.->|Logs| CW
    DB -.->|Logs| CW
    Cache -.->|Logs| CW
```

---

## 🚀 Quick Start: Deploy Stage Environment

### Step 1: Authenticate to AWS CLI
```bash
aws configure
# Set AWS Access Key ID, Secret Access Key, and region (eu-west-1)
```

### Step 2: Initialize & Validate Terraform
```powershell
cd infra/aws/ecs

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

Once `terraform apply` finishes, the outputs display the ALB endpoints:

```text
Apply complete! Resources: 18 added, 0 changed, 0 destroyed.

Outputs:
control_plane_ui_url = "http://agentwall-stage-alb-xxxxxx.eu-west-1.elb.amazonaws.com:8081"
gateway_url          = "http://agentwall-stage-alb-xxxxxx.eu-west-1.elb.amazonaws.com:8080"
health_check_url     = "http://agentwall-stage-alb-xxxxxx.eu-west-1.elb.amazonaws.com:8080/healthz"
quick_verify_command = "curl -i http://agentwall-stage-alb-xxxxxx.eu-west-1.elb.amazonaws.com:8080/healthz"
```

### 1. Verify Gateway Health Check
```bash
curl -i http://<alb-dns-name>:8080/healthz
```

### 2. Stream Live Gateway Logs (AWS CLI)
```bash
aws logs tail /ecs/agentwall-stage --follow --filter-pattern "gateway"
```

### 3. Teardown Stage Environment
```bash
terraform destroy -var-file="terraform.stage.tfvars"
```
