# Team Control Hub — Kubernetes Deployment Guide

> **Target Audience:** DevOps Engineers, Platform Security Teams, and Infrastructure Leads deploying AgentWall Team Control Hub in production Kubernetes clusters across **Linux**, **macOS**, and **Windows**.

---

## Overview

The **Kubernetes Deployment** guide covers high-availability, multi-replica production deployments of the **AgentWall Team Control Hub** using Helm (`./chart`), Custom Resource Definitions (`AgentWallPolicy`), and the Kubernetes Operator (`agentwall-operator`).

For Local Development and Docker testing, see → [Local Development Guide](local_development.md).  
For Enterprise Fleet security options (pure-Rust TLS, CMK SIEM encryption, HAR runtime), see → [Enterprise Fleet User Guide](../enterprise_guide.md).

---

## 1. Prerequisites & Cluster Requirements

Before starting, ensure your cluster and deployment client environment meet the following specifications:

### Cluster Requirements
- **Kubernetes 1.24+** cluster with multi-replica node capacity.
- **Cluster CNI with NetworkPolicy support** (e.g., Calico, Cilium, Antrea) if enabling egress policy enforcement.
- **Ingress Controller** or **LoadBalancer Service Provisioner** for external TLS routing.
- **Dynamic Storage Provisioner** (Persistent Volume provider) if enabling PostgreSQL for the SaaS Dashboard (`dashboardDb.enabled=true`).

### Tooling Requirements Across All Operating Systems
- **Git v2.38+** — required to clone the AgentWall repository from GitHub.
- **Kubectl v1.24+** — configured with cluster-admin access to your target Kubernetes context.
- **Helm v3.10+** — installed on your client machine.

### OS-Specific Tooling & Terminal Notes

#### Linux (Ubuntu / Debian / RHEL / Arch)
- Terminal: **Bash** or **Zsh**.
- Install tools via native package manager (e.g. `sudo apt install git`, `snap install kubectl --classic`, `snap install helm --classic`).

#### macOS (Intel / Apple Silicon)
- Terminal: **Zsh** or **Bash**.
- Install tools via Homebrew: `brew install git kubernetes-cli helm`.

#### Windows 10/11
- Terminal: **PowerShell 5.1+ / PowerShell 7+** or **Command Prompt (CMD)**.
- Install tools via Winget or Chocolatey:
  ```powershell
  winget install Git.Git Kubernetes.kubectl Helm.Helm
  ```
- In PowerShell, run `curl.exe` explicitly to avoid built-in PowerShell aliases (`curl` -> `Invoke-WebRequest`).

---

## 2. Production Deployment Steps

### Step 1: Clone Repository & Create System Namespace

Clone the AgentWall repository to obtain the Helm chart directory (`./chart`) and navigate to the project root:

#### Linux / macOS (Bash / Zsh):
```bash
git clone https://github.com/noviqtechnologies/Vexa-Agent-Control.git
cd Vexa-Agent-Control
kubectl create namespace agentwall-system
```

#### Windows (PowerShell):
```powershell
git clone https://github.com/noviqtechnologies/Vexa-Agent-Control.git
cd Vexa-Agent-Control
kubectl create namespace agentwall-system
```

#### Windows (Command Prompt - CMD):
```cmd
git clone https://github.com/noviqtechnologies/Vexa-Agent-Control.git
cd Vexa-Agent-Control
kubectl create namespace agentwall-system
```

---

### Step 2: Configure Ingress TLS Secrets

Create a Kubernetes TLS secret in the `agentwall-system` namespace containing your domain's TLS certificate and private key:

#### Linux / macOS (Bash / Zsh):
```bash
kubectl create secret tls agentwall-gateway-tls \
  --cert=path/to/tls.crt \
  --key=path/to/tls.key \
  -n agentwall-system
```

#### Windows (PowerShell):
```powershell
kubectl create secret tls agentwall-gateway-tls `
  --cert=path/to/tls.crt `
  --key=path/to/tls.key `
  -n agentwall-system
```

#### Windows (Command Prompt - CMD):
```cmd
kubectl create secret tls agentwall-gateway-tls --cert=path/to/tls.crt --key=path/to/tls.key -n agentwall-system
```

> [!TIP]
> **Staging / Evaluation Clusters:** If you do not have a custom TLS certificate ready, you can instruct Helm to automatically generate a self-signed secret by setting `--set gateway.tls.createSelfSigned=true` during installation.

---

### Step 3: Deploy Full Stack via Helm

Deploy the HA AgentWall gateway cluster, operator, Control Hub API, PostgreSQL database, and Web Console using Helm:

#### Linux / macOS (Bash / Zsh):
```bash
helm install agentwall ./chart \
  --namespace agentwall-system \
  --create-namespace \
  --set gateway.tls.enabled=true \
  --set gateway.tls.secretName=agentwall-gateway-tls \
  --set gateway.replicas=3 \
  --set gateway.mcpUrl="http://your-mcp-service:3000" \
  --set dashboardApi.enabled=true \
  --set dashboardDb.enabled=true \
  --set dashboardFrontend.enabled=true \
  --set dashboardApi.oidc.issuer=https://your-idp.example.com \
  --set dashboardApi.oidc.clientId=agentwall-dashboard
```

#### Windows (PowerShell):
```powershell
helm install agentwall .\chart `
  --namespace agentwall-system `
  --create-namespace `
  --set gateway.tls.enabled=true `
  --set gateway.tls.secretName=agentwall-gateway-tls `
  --set gateway.replicas=3 `
  --set gateway.mcpUrl="http://your-mcp-service:3000" `
  --set dashboardApi.enabled=true `
  --set dashboardDb.enabled=true `
  --set dashboardFrontend.enabled=true `
  --set dashboardApi.oidc.issuer=https://your-idp.example.com `
  --set dashboardApi.oidc.clientId=agentwall-dashboard
```

#### Windows (Command Prompt - CMD):
```cmd
helm install agentwall .\chart --namespace agentwall-system --create-namespace --set gateway.tls.enabled=true --set gateway.tls.secretName=agentwall-gateway-tls --set gateway.replicas=3 --set gateway.mcpUrl="http://your-mcp-service:3000" --set dashboardApi.enabled=true --set dashboardDb.enabled=true --set dashboardFrontend.enabled=true --set dashboardApi.oidc.issuer=https://your-idp.example.com --set dashboardApi.oidc.clientId=agentwall-dashboard
```

---

### Step 4: Apply `AgentWallPolicy` CRDs & Operator Reconciliation

The Helm chart registers the `AgentWallPolicy` Custom Resource Definition (CRD) and deploys `agentwall-operator`.

Create a custom policy CR manifest (`policy.yaml`):

```yaml
apiVersion: agentwall.io/v1alpha1
kind: AgentWallPolicy
metadata:
  name: team-production-policy
  namespace: agentwall-system
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
      agentwall.io/agent: "true"
    gatewayPodSelector:
      agentwall.io/gateway: "true"
```

Apply the policy manifest to the cluster:

#### Linux / macOS (Bash / Zsh):
```bash
kubectl apply -f policy.yaml
```

#### Windows (PowerShell / CMD):
```powershell
kubectl apply -f policy.yaml
```

> [!NOTE]
> **Operator Egress NetworkPolicy Enforcement:** When `spec.networkPolicy.enforced: true` is configured, label your AI agent application pods with `agentwall.io/agent=true`. The `agentwall-operator` will automatically generate a Kubernetes `NetworkPolicy` restricting agent pod egress strictly to the gateway on port `8080` (+DNS).

---

## 3. Verification & Cluster Testing Workflow

After completing the deployment, perform the following verification steps to ensure cluster components are running healthily.

### Step 1: Verify Pod & Deployment Status

Check that all pods in `agentwall-system` are in the `Running` state:

#### Linux / macOS / Windows (All Shells):
```bash
kubectl get pods -n agentwall-system
```

**Expected Output:**
```
NAME                                          READY   STATUS    RESTARTS   AGE
agentwall-dashboard-api-7b89799-x2k9s         1/1     Running   0          2m
agentwall-dashboard-db-0                      1/1     Running   0          2m
agentwall-dashboard-frontend-5b4d45-98k21     1/1     Running   0          2m
agentwall-gateway-69d58d9766-4k1lm            1/1     Running   0          2m
agentwall-gateway-69d58d9766-m29pq            1/1     Running   0          2m
agentwall-gateway-69d58d9766-z88np            1/1     Running   0          2m
agentwall-operator-8687d46c4f-l8s7b           1/1     Running   0          2m
```

---

### Step 2: Test Gateway Health Endpoint

Forward the gateway service port locally to test the `/healthz` endpoint:

#### Linux / macOS (Bash / Zsh):
```bash
# In Terminal 1:
kubectl port-forward svc/agentwall-gateway 8080:8080 -n agentwall-system

# In Terminal 2:
curl -i http://127.0.0.1:8080/healthz
```

#### Windows (PowerShell):
```powershell
# In Terminal 1:
kubectl port-forward svc/agentwall-gateway 8080:8080 -n agentwall-system

# In Terminal 2:
curl.exe -i http://127.0.0.1:8080/healthz
```

#### Windows (Command Prompt - CMD):
```cmd
:: In Terminal 1:
kubectl port-forward svc/agentwall-gateway 8080:8080 -n agentwall-system

:: In Terminal 2:
curl.exe -i http://127.0.0.1:8080/healthz
```

**Expected Output:** `HTTP/1.1 200 OK` with response `{"status":"ok"}`.

---

### Step 3: Inspect Logs

Inspect the enforcement logs from the gateway cluster or operator:

#### Linux / macOS / Windows (All Shells):
```bash
# Gateway deployment logs
kubectl logs -n agentwall-system deploy/agentwall-gateway --tail=50 -f

# Operator logs
kubectl logs -n agentwall-system deploy/agentwall-operator --tail=50 -f
```

---

## 4. Maintenance & Day-2 Operations

### Zero-Downtime Rolling Upgrades

To update Helm release configurations or upgrade component image tags:

#### Linux / macOS (Bash / Zsh):
```bash
helm upgrade agentwall ./chart -n agentwall-system
```

#### Windows (PowerShell / CMD):
```powershell
helm upgrade agentwall .\chart -n agentwall-system
```

*When `gateway.replicas >= 2`, Kubernetes performs rolling updates with a 5-second `preStop` request drain to preserve traffic continuity.*

---

### Triggering Instant Policy Hot-Reloads

If you update custom policies directly on disk or in ConfigMaps outside the SSE push stream, force immediate policy reloads without pod restarts using either method below:

#### Method A: HTTP Gateway Reload Endpoint

#### Linux / macOS (Bash / Zsh):
```bash
kubectl exec -n agentwall-system deploy/agentwall-gateway -- \
  wget -qO- --post-data '' http://localhost:8080/reload
```

#### Windows (PowerShell):
```powershell
kubectl exec -n agentwall-system deploy/agentwall-gateway -- `
  wget -qO- --post-data '' http://localhost:8080/reload
```

#### Windows (Command Prompt - CMD):
```cmd
kubectl exec -n agentwall-system deploy/agentwall-gateway -- wget -qO- --post-data '' http://localhost:8080/reload
```

#### Method B: Process SIGHUP Signal

#### Linux / macOS (Bash / Zsh):
```bash
POD=$(kubectl get pod -n agentwall-system -l app.kubernetes.io/component=gateway -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n agentwall-system $POD -- kill -HUP 1
```

#### Windows (PowerShell):
```powershell
$POD = (kubectl get pod -n agentwall-system -l app.kubernetes.io/component=gateway -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n agentwall-system $POD -- kill -HUP 1
```

#### Windows (Command Prompt - CMD):
```cmd
kubectl exec -n agentwall-system deploy/agentwall-gateway -- kill -HUP 1
```

---

### Uninstalling the Deployment

To cleanly remove all AgentWall resources and Helm releases:

#### Linux / macOS / Windows (All Shells):
```bash
helm uninstall agentwall -n agentwall-system
```

*Note: CRDs are retained intentionally on Helm uninstall (`helm.sh/resource-policy: keep`) to protect active policy data. To delete CRDs explicitly:*

```bash
kubectl delete crd agentwallpolicies.agentwall.io
```

---

## 5. Production Security & References

- **OIDC Identity Binding:** Bind corporate IdPs (Okta, Keycloak, Entra ID, Ping) for centralized team identity. See → [OIDC Identity Binding Guide](../oidc_identity_binding.md).
- **Audit Log Verification & SIEM Export:** Stream real-time JSON-RPC audit logs to Splunk, Datadog, or OpenSearch. See → [Common Reference Guide — SIEM Export](../common_guide.md#session-reports--siem-export).
- **Enterprise Features:** For HSM token storage, pure-Rust TLS termination, and HAR isolation, see → [Enterprise Fleet User Guide](../enterprise_guide.md).
