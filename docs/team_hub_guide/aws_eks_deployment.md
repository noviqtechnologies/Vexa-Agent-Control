# Team Control Hub — AWS EKS Deployment & Uninstallation Guide

> **Target Audience:** Cloud Engineers, DevOps Engineers, Platform Security Teams, and Infrastructure Leads deploying or evaluating the **Agent Control Team Control Hub** on **Amazon Web Services (AWS) Elastic Kubernetes Service (EKS)** across **Linux**, **macOS**, and **Windows**.

---

## Overview

This guide provides an end-to-end operational walkthrough for deploying, validating, and uninstalling the **Agent Control Team Control Hub** on **AWS EKS**. It covers:

1. AWS Infrastructure Prerequisites & Tools (Linux, macOS, Windows).
2. EKS Cluster & Storage Driver Provisioning (`eksctl` / AWS CLI).
3. AWS Load Balancer & TLS Certificate Configuration (AWS ACM / Ingress).
4. Production Helm Deployment & Custom Resource (`Agent ControlPolicy`) Reconciliation.
5. Post-Deployment Multi-OS Validation & Health Verification.
6. Complete Uninstallation & Infrastructure Teardown.

For generic Kubernetes deployments, see → [Kubernetes Deployment Guide](kubernetes_deployment.md).  
For Local Docker development, see → [Local Development Guide](local_development.md).  
For OIDC Identity Provider setup, see → [OIDC Identity Binding Guide](../oidc_identity_binding.md).

---

## 1. Prerequisites & Environment Setup

Before starting, ensure your local workstation and AWS account meet the following specifications.

### AWS Account & IAM Requirements
- **AWS Account** with administrative permissions to create EKS clusters, IAM roles, EC2 instances, EBS volumes, and VPC resources.
- **Sufficient EC2 Quota:** At least 3 `t3.medium` or `m5.large` instances in your target AWS Region.

### Workstation Tooling Requirements (All Operating Systems)
- **AWS CLI v2.10+** — configured with active AWS credentials (`aws configure` or SSO).
- **eksctl v0.140+** — CLI tool for creating and managing EKS clusters.
- **Kubectl v1.24+** — Kubernetes command-line tool.
- **Helm v3.10+** — Package manager for Kubernetes.
- **Git v2.38+** — To clone the Agent Control repository.

---

### OS-Specific Installation Commands

#### Linux (Ubuntu / Debian / RHEL / Arch)
```bash
# AWS CLI v2
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip && sudo ./aws/install

# eksctl
curl --silent --location "https://github.com/weaveworks/eksctl/releases/latest/download/eksctl_$(uname -s)_amd64.tar.gz" | tar xz -C /tmp
sudo mv /tmp/eksctl /usr/local/bin

# kubectl & helm
sudo snap install kubectl --classic
sudo snap install helm --classic
```

#### macOS (Intel / Apple Silicon)
```zsh
# Install all required tools via Homebrew
brew install awscli eksctl kubernetes-cli helm git
```

#### Windows (PowerShell 5.1+ / PowerShell 7+)
```powershell
# Install tools using Winget or Chocolatey
winget install Amazon.AWSCLI
winget install Weaveworks.eksctl
winget install Kubernetes.kubectl
winget install Helm.Helm
winget install Git.Git
```
*Note for Windows:* Ensure `curl.exe` is called explicitly in PowerShell to prevent conflicts with built-in PowerShell aliases (`curl` -> `Invoke-WebRequest`).

---

### AWS Credential Configuration & Pre-Flight Verification

Once tooling is installed, ensure your workstation has active AWS credentials configured to authenticate with AWS CloudFormation, EKS, and STS:

#### Method A: Standard IAM Access Keys (`aws configure`)
```bash
aws configure
# AWS Access Key ID: AKIA...
# AWS Secret Access Key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
# Default region name: us-east-1
# Default output format: json
```

#### Method B: AWS IAM Identity Center / SSO (Recommended for Enterprise)
```bash
aws configure sso
aws sso login --profile my-eks-profile
export AWS_PROFILE=my-eks-profile # Linux/macOS
# $env:AWS_PROFILE="my-eks-profile" # Windows PowerShell
```

#### Method C: Environment Variables (Session Keys / CI/CD)
```bash
# Linux / macOS
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_DEFAULT_REGION="us-east-1"
# export AWS_SESSION_TOKEN="..." # If using temporary STS credentials
```
```powershell
# Windows PowerShell
$env:AWS_ACCESS_KEY_ID="AKIA..."
$env:AWS_SECRET_ACCESS_KEY="..."
$env:AWS_DEFAULT_REGION="us-east-1"
# $env:AWS_SESSION_TOKEN="..." # If using temporary STS credentials
```

#### Pre-Flight Verification
Verify that your active session is authenticated before creating resources:
```bash
aws sts get-caller-identity
```
**Expected Output:**
```json
{
    "UserId": "AROAXXXXXXXXXXXXXXXXX:session-name",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/devops-admin"
}
```

---

## 2. AWS EKS Cluster Provisioning

### Step 1: Create the EKS Cluster with NetworkPolicy Support

Agent Control requires a Kubernetes cluster with multi-replica node capacity and NetworkPolicy support (for agent egress isolation).

Create an EKS cluster configuration file `eks-cluster.yaml`:

```yaml
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig

metadata:
  name: agentcontrol-eks-cluster
  region: us-east-1
  version: "1.28"

vpc:
  clusterEndpoints:
    publicAccess: true
    privateAccess: true

managedNodeGroups:
  - name: agentcontrol-workers
    instanceType: t3.medium
    desiredCapacity: 3
    minSize: 2
    maxSize: 5
    volumeSize: 30
    iam:
      withAddonPolicies:
        ebs: true
        albIngress: true

addons:
  - name: vpc-cni
  - name: coredns
  - name: kube-proxy
  - name: aws-ebs-csi-driver
```

Execute `eksctl` to create the cluster (takes ~10–15 minutes):

#### Linux / macOS (Bash / Zsh) / Windows (PowerShell):
```bash
eksctl create cluster -f eks-cluster.yaml
```

Update your local `kubeconfig`:
```bash
aws eks update-kubeconfig --region us-east-1 --name agentcontrol-eks-cluster
```

Verify cluster nodes:
```bash
kubectl get nodes
```

---

## 3. Storage & Ingress Configuration

### Step 1: Verify AWS EBS CSI Storage Class
The SaaS Dashboard PostgreSQL database (`dashboardDb.enabled=true`) requires a Persistent Volume. EKS provides the `gp3` or `gp2` StorageClass via the EBS CSI Driver addon.

Check available storage classes:
```bash
kubectl get storageclass
```
*(You should see `gp2` or `gp3` listed with `(default)`).*

---

### Step 2: Configure TLS Certificates & Ingress

#### Option A: Self-Signed TLS Certificate (Evaluation / Testing)
You can instruct Helm to generate self-signed secrets automatically during installation by setting `--set gateway.tls.createSelfSigned=true`.

#### Option B: AWS Certificate Manager (ACM) + AWS Load Balancer Controller (Production)
If using AWS ACM and AWS Load Balancer Controller:
1. Create a TLS secret manually in the namespace:

#### Linux / macOS (Bash / Zsh):
```bash
kubectl create namespace agentcontrol-system
kubectl create secret tls agentcontrol-gateway-tls \
  --cert=path/to/tls.crt \
  --key=path/to/tls.key \
  -n agentcontrol-system
```

#### Windows (PowerShell):
```powershell
kubectl create namespace agentcontrol-system
kubectl create secret tls agentcontrol-gateway-tls `
  --cert=path/to/tls.crt `
  --key=path/to/tls.key `
  -n agentcontrol-system
```

---

## 4. Deploy Agent Control via Helm

### Step 1: Clone Repository & Navigate to Chart Directory

#### Linux / macOS / Windows (All Shells):
```bash
git clone https://github.com/noviqtechnologies/Vexa-Agent-Control.git
cd Vexa-Agent-Control
```

---

### Step 2: Install Helm Release

Execute the Helm installation command configured for AWS EKS:

#### Linux / macOS (Bash / Zsh):
```bash
helm install agentcontrol ./chart \
  --namespace agentcontrol-system \
  --create-namespace \
  --set gateway.tls.enabled=true \
  --set gateway.tls.createSelfSigned=true \
  --set gateway.replicas=3 \
  --set dashboardApi.enabled=true \
  --set dashboardDb.enabled=true \
  --set dashboardDb.storageClass=gp3 \
  --set dashboardFrontend.enabled=true
```

#### Windows (PowerShell):
```powershell
helm install agentcontrol .\chart `
  --namespace agentcontrol-system `
  --create-namespace `
  --set gateway.tls.enabled=true `
  --set gateway.tls.createSelfSigned=true `
  --set gateway.replicas=3 `
  --set dashboardApi.enabled=true `
  --set dashboardDb.enabled=true `
  --set dashboardDb.storageClass=gp3 `
  --set dashboardFrontend.enabled=true
```

#### Windows (Command Prompt - CMD):
```cmd
helm install agentcontrol .\chart --namespace agentcontrol-system --create-namespace --set gateway.tls.enabled=true --set gateway.tls.createSelfSigned=true --set gateway.replicas=3 --set dashboardApi.enabled=true --set dashboardDb.enabled=true --set dashboardDb.storageClass=gp3 --set dashboardFrontend.enabled=true
```

---

### Step 3: Apply `Agent ControlPolicy` CRDs & Operator Reconciliation

Create custom policy file `policy.yaml`:

```yaml
apiVersion: agentcontrol.io/v1alpha1
kind: Agent ControlPolicy
metadata:
  name: aws-production-policy
  namespace: agentcontrol-system
spec:
  policy: |
    version: "2.0"
    default_action: deny
    tools:
      - name: "read_file"
        action: allow
      - name: "exec_shell"
        action: block
    firewall:
      enabled: true
      cycle_detection:
        max_attempts: 3
        action: pivot_error
  networkPolicy:
    enforced: true
    mcpPort: 8080
    agentPodSelector:
      agentcontrol.io/agent: "true"
    gatewayPodSelector:
      agentcontrol.io/gateway: "true"
```

Apply manifest:
```bash
kubectl apply -f policy.yaml
```

---

## 5. Post-Deployment Validation & Health Verification

Perform the following steps across your OS terminal to verify the AWS EKS deployment.

### Step 1: Verify Pod & Deployment Status

Check that all pods in `agentcontrol-system` are in the `Running` state and persistent storage is bound:

#### Linux / macOS / Windows (All Shells):
```bash
kubectl get pods,pvc -n agentcontrol-system
```

**Expected Output:**
```
NAME                                          READY   STATUS    RESTARTS   AGE
pod/agentcontrol-dashboard-api-7b89799-x2k9s     1/1     Running   0          3m
pod/agentcontrol-dashboard-db-0                  1/1     Running   0          3m
pod/agentcontrol-dashboard-frontend-5b4d45-98k21 1/1     Running   0          3m
pod/agentcontrol-gateway-69d58d9766-4k1lm        1/1     Running   0          3m
pod/agentcontrol-gateway-69d58d9766-m29pq        1/1     Running   0          3m
pod/agentcontrol-gateway-69d58d9766-z88np        1/1     Running   0          3m
pod/agentcontrol-operator-8687d46c4f-l8s7b       1/1     Running   0          3m

NAME                                           STATUS   VOLUME                                     CAPACITY   ACCESS MODES   STORAGECLASS   AGE
persistentvolumeclaim/data-agentcontrol-db-0      Bound    pvc-a1b2c3d4-5678-90ab-cdef-1234567890ab   10Gi       RWO            gp3            3m
```

---

### Step 2: Validate Gateway Health Endpoint

Forward service port `8080` locally to execute end-to-end health checks:

#### Linux / macOS (Bash / Zsh):
```bash
# Terminal 1:
kubectl port-forward svc/agentcontrol-gateway 8080:8080 -n agentcontrol-system

# Terminal 2:
curl -i http://127.0.0.1:8080/healthz
```

#### Windows (PowerShell):
```powershell
# Terminal 1:
kubectl port-forward svc/agentcontrol-gateway 8080:8080 -n agentcontrol-system

# Terminal 2:
curl.exe -i http://127.0.0.1:8080/healthz
```

#### Windows (Command Prompt - CMD):
```cmd
:: Terminal 1:
kubectl port-forward svc/agentcontrol-gateway 8080:8080 -n agentcontrol-system

:: Terminal 2:
curl.exe -i http://127.0.0.1:8080/healthz
```

**Expected Output:** `HTTP/1.1 200 OK` with payload `{"status":"ok"}`.

---

### Step 3: Inspect AWS EKS Enforcement Logs

Check logs from the multi-replica gateway cluster and operator:

```bash
# Gateway cluster logs
kubectl logs -n agentcontrol-system deploy/agentcontrol-gateway --tail=50 -f

# Operator reconciliation logs
kubectl logs -n agentcontrol-system deploy/agentcontrol-operator --tail=50 -f
```

---

## 6. Complete Uninstallation & Infrastructure Teardown

To avoid incurring residual AWS charges for EC2 instances, EBS volumes, and Load Balancers when testing is finished, follow these teardown steps in sequence.

### Step 1: Remove Custom Resources & Helm Release

Uninstall the Helm release and delete custom policy resources:

#### Linux / macOS / Windows (All Shells):
```bash
# 1. Delete Agent Control Policy CRDs
kubectl delete agentcontrolpolicy aws-production-policy -n agentcontrol-system --ignore-not-found

# 2. Uninstall Helm release
helm uninstall agentcontrol -n agentcontrol-system

# 3. Delete registered CRD schema
kubectl delete crd agentcontrolpolicies.agentcontrol.io --ignore-not-found

# 4. Delete Persistent Volume Claims (EBS Volumes)
kubectl delete pvc --all -n agentcontrol-system

# 5. Delete namespace
kubectl delete namespace agentcontrol-system
```

---

### Step 2: Delete EKS Cluster & AWS Infrastructure

Use `eksctl` to automatically delete all AWS resources associated with the cluster (CloudFormation stacks, EC2 instances, IAM roles, Security Groups, and VPC resources):

#### Linux / macOS / Windows (All Shells):
```bash
eksctl delete cluster --name agentcontrol-eks-cluster --region us-east-1
```

---

### Step 3: Verify Resource Cleanup in AWS CLI

Verify that no orphaned EBS volumes or EKS resources remain:

#### Linux / macOS (Bash / Zsh):
```bash
aws ec2 describe-volumes --filters "Name=tag:kubernetes.io/cluster/agentcontrol-eks-cluster,Values=owned" --region us-east-1
```

#### Windows (PowerShell):
```powershell
aws ec2 describe-volumes --filters "Name=tag:kubernetes.io/cluster/agentcontrol-eks-cluster,Values=owned" --region us-east-1
```

**Expected Output:** `Volumes: []` (Empty array).

---

## Summary Checklist

| Task | Command / Reference | Status |
| :--- | :--- | :--- |
| **Tooling Setup** | Install AWS CLI, `eksctl`, `kubectl`, `helm` | ✅ |
| **Cluster Launch** | `eksctl create cluster -f eks-cluster.yaml` | ✅ |
| **Helm Install** | `helm install agentcontrol ./chart -n agentcontrol-system` | ✅ |
| **CRD Policy Apply** | `kubectl apply -f policy.yaml` | ✅ |
| **Health Validation** | `curl.exe http://127.0.0.1:8080/healthz` | ✅ |
| **Helm Teardown** | `helm uninstall agentcontrol -n agentcontrol-system` | ✅ |
| **Cluster Teardown** | `eksctl delete cluster --name agentcontrol-eks-cluster` | ✅ |
