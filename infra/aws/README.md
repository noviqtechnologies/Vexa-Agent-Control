# AgentWall AWS Deployment Options & Cost Comparison

This folder contains Terraform deployment modules for AgentWall tailored for different cost and architecture requirements on AWS:

---

## 💰 Cost Comparison Table

| Option | Architecture | Estimated Monthly Cost | Best Used For | Folder |
| :--- | :--- | :--- | :--- | :--- |
| **Option 1** | **EKS Fargate + 1 NAT GW** | **~$120 / month** | Full K8s CRD Policy reconciliation & HA | [`infra/aws/`](./) |
| **Option 2** | **AWS ECS Fargate** | **~$15 - $25 / month** | Serverless containers, $0 control plane fee, no NAT GW | [`infra/aws/ecs/`](./ecs/) |
| **Option 3** | **EC2 Graviton (`t4g.small`)** | **~$8 / month** | Lowest cost standalone Docker evaluation | [`infra/aws/ec2/`](./ec2/) |

---

## 🚀 Option 3: Single EC2 Graviton Instance (~$8 / Month)

Deploys a single ARM64 Graviton (`t4g.small`) EC2 instance with Docker and Docker Compose pre-configured.

### Quick Start:
```bash
cd infra/aws/ec2
terraform init
terraform plan
terraform apply
```

Outputs will display the Elastic IP and direct health check URL (`http://<IP>:8080/healthz`).

---

## ⚡ Option 2: AWS ECS Fargate (~$15–$25 / Month)

Deploys AgentWall containers to AWS ECS Fargate using public subnets (assign public IP) with $0 control plane fees and zero NAT Gateway charges.

### Quick Start:
```bash
cd infra/aws/ecs
terraform init
terraform plan
terraform apply
```

---

## ☸️ Option 1: EKS Fargate (~$120 / Month)

Full Kubernetes deployment with `AgentWallPolicy` CRDs and network policy isolation on EKS Fargate.

### Quick Start:
```bash
cd infra/aws
cp terraform.tfvars.example terraform.tfvars
terraform init
terraform plan
terraform apply
```
