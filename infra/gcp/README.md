# 🛡️ AgentControl on Google Cloud Run (v2) — Stage & Serverless Deployment

Ultra cost-effective (**~$0–$2/month** for Staging / **~$0–$15/month** for Production) serverless deployment of **AgentControl** and its Enterprise Control Plane on **Google Cloud Platform (GCP)** using **Google Cloud Run (v2)** with multi-container PostgreSQL sidecars and Google Secret Manager integration.

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
            subgraph GatewaySvc ["🛡️ Service: agentcontrol-stage-gateway"]
                GW["agentcontrol-gateway (Rust Proxy)\nPort: 8080 | 1 vCPU, 256 MiB | min=0"]
            end

            subgraph UISvc ["📊 Service: agentcontrol-stage-ui"]
                UI["control-plane-ui (Frontend Portal)\nPort: 80 | 1 vCPU, 256 MiB | min=0"]
            end

            subgraph APISvc ["⚙️ Service: agentcontrol-stage-api (Multi-Container Revision)"]
                API["dashboard-api (Backend REST API)\nPort: 8400 | Ingress Container"]
                DB["postgres (agentcontrol-db Engine)\nPort: 5432 (Localhost 127.0.0.1 Sidecar)"]
                Cache["valkey (Localhost 127.0.0.1 Sidecar)\nPort: 6379"]
            end
        end

        subgraph SecuritySecrets ["🔐 Google Secret Manager & IAM"]
            SM["Secret Manager\n(DB URL, Gateway Key, Session Secret, Master KMS Key)"]
            SA["Dedicated Cloud Run Service Account\n(Least-privilege roles)"]
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
    API -->|Localhost TCP:6379| Cache

    SM -.->|value_source.secret_key_ref| APISvc
    SM -.->|value_source.secret_key_ref| GatewaySvc
    GW -.->|Stream Audit Logs| Logs
    UI -.->|Access Logs| Logs
    API -.->|Telemetry & Traces| Logs
```

---

## 💰 Cost Optimization Matrix (Stage vs Prod)

| Feature / Resource | Stage Environment Configuration | Production Configuration | Monthly Staging Cost |
| :--- | :--- | :--- | :--- |
| **Compute Scaling** | **Scale-to-Zero (`min_instances = 0`)** | Always-On (`min_instances = 1`) | **$0.00** (Free Tier) |
| **Max Scale Cap** | `max_instances = 3` (Budget safety) | `max_instances = 10` | Included |
| **Container Sizing** | 1 vCPU, 256 MiB per container | 1 vCPU, 512 MiB - 1 GiB | Included |
| **Database Tier** | Multi-container PostgreSQL sidecar | Cloud SQL or sidecar | **$0.00** (No VM fee) |
| **Ingress / TLS** | Cloud Run Free Auto-Managed Ingress | Cloud Run or ALB | **$0.00** (No ALB fee) |
| **Networking (VPC)** | Serverless Direct Network (`enable_vpc = false`) | VPC + Serverless Connector | **$0.00** (No NAT fee) |
| **Artifact Registry** | Auto-prune (Keep 2 tags, delete untagged > 1d) | Retain 10 tags | **<$0.10** |
| **Secret Manager** | Auto-generated tokens, version-managed | Secret Manager | **<$0.20** |
| **MONTHLY COST** | **~$0.00 – $2.00 / month** | **~$15 – $35 / month** | **~$0 – $2 / mo** |

---

## 🚀 Quick Start: High-Speed Stage Deployment

### Fast-Path 1: Automated Parallel Build & Deploy Pipeline (Recommended: ~1.5–2 min)
Run the parallel build and deployment script:

```powershell
# Windows PowerShell (Concurrent Cloud Builds on E2_HIGHCPU_4 workers + Terraform)
.\scripts\deploy-stage.ps1

# Unix / macOS / Linux
./scripts/deploy-stage.sh
```

### Fast-Path 2: Pure IaC Apply (~25–35 seconds)
If images are already built and you only modified Terraform / IAM / Secrets / Scaling configs:

```powershell
# Windows PowerShell
.\scripts\deploy-stage.ps1 -SkipBuild

# Direct Terraform Apply with High Parallelism
cd infra/gcp
terraform apply -var-file="terraform.stage.tfvars" -parallelism=20
```

---

## 🔍 Post-Deployment Verification Suite

Once `terraform apply` finishes, the outputs display the deployed Cloud Run endpoints:

```text
Apply complete! Resources: 14 added, 0 changed, 0 destroyed.

Outputs:
control_plane_ui_url = "https://agentcontrol-stage-ui-xxxxxx-ew.a.run.app"
gateway_url          = "https://agentcontrol-stage-gateway-xxxxxx-ew.a.run.app"
dashboard_api_url    = "https://agentcontrol-stage-api-xxxxxx-ew.a.run.app"
health_check_url     = "https://agentcontrol-stage-gateway-xxxxxx-ew.a.run.app/healthz"
quick_verify_command = "curl -i https://agentcontrol-stage-gateway-xxxxxx-ew.a.run.app/healthz"
```

### 1. Verify Gateway Health
```bash
curl -i https://<gateway-url>/healthz
```
*Expected output: `HTTP/2 200`*

### 2. Stream Live Staging Logs
```bash
gcloud run services logs tail agentcontrol-stage-gateway --project vexa-prod --region europe-west1
```

### 3. Teardown Stage Environment
```bash
terraform destroy -var-file="terraform.stage.tfvars"
```
