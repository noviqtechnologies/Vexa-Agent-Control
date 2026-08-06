# Team Control Hub — Kubernetes Deployment Guide

> **Target Audience:** DevOps Engineers, Platform Security Teams, and Infrastructure Leads deploying AgentWall Team Control Hub in production Kubernetes clusters.

---

## Overview

The **Kubernetes Deployment** guide covers high-availability, multi-replica production deployments of the **AgentWall Team Control Hub** using Helm (`./chart`), Custom Resource Definitions (`AgentWallPolicy`), and the Kubernetes Operator (`agentwall-operator`).

For Local Development and Docker testing, see → [Local Development Guide](local_development.md).  
For Enterprise Fleet security options (pure-Rust TLS, CMK SIEM encryption, HAR runtime), see → [Enterprise Fleet User Guide](../enterprise_guide.md).

---

## 1. Prerequisites & Cluster Requirements

Ensure your target production Kubernetes cluster meets the following specifications:

- **Kubernetes 1.24+** cluster with multi-replica node capacity.
- **Helm 3.10+** installed on your client machine.
- **Cluster CNI with NetworkPolicy support** (e.g., Calico, Cilium, Antrea) if enabling egress policy enforcement.
- **Ingress Controller** or **LoadBalancer Service Provisioner** for external TLS routing.
- **Dynamic Storage Provisioner** (Persistent Volume provider) for PostgreSQL database persistent volume claims.

---

## 2. Production Deployment Steps

### Step 1: Create System Namespace

Create a dedicated namespace for AgentWall system components:

```bash
kubectl create namespace agentwall-system
```

---

### Step 2: Configure Ingress TLS Secrets

Create a Kubernetes TLS secret containing your domain's TLS certificate and private key:

```bash
kubectl create secret tls agentwall-gateway-tls \
  --cert=path/to/tls.crt \
  --key=path/to/tls.key \
  -n agentwall-system
```

> [!TIP]
> For staging or evaluation clusters without custom TLS certificates, set `--set gateway.tls.createSelfSigned=true` during Helm installation.

---

### Step 3: Deploy Full Stack via Helm

Deploy the HA AgentWall gateway cluster, operator, Control Hub API, PostgreSQL database, and Web Console:

```bash
helm install agentwall ./chart \
  --namespace agentwall-system \
  --create-namespace \
  --set gateway.tls.enabled=true \
  --set gateway.tls.secretName=agentwall-gateway-tls \
  --set gateway.replicas=3 \
  --set dashboardApi.enabled=true \
  --set dashboardDb.enabled=true \
  --set dashboardFrontend.enabled=true \
  --set dashboardApi.oidc.issuer=https://your-idp.example.com \
  --set dashboardApi.oidc.clientId=agentwall-dashboard
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
  networkPolicyEnforced: true
  policyYaml: |
    version: "2.0"
    mode: "enforce"
    rules:
      - name: "block-env-exfiltration"
        match:
          tools: ["read_file", "execute_shell"]
        action: "block"
```

Apply the policy to the cluster:

```bash
kubectl apply -f policy.yaml
```

The operator will automatically reconcile the custom resource and sync active policies to gateway pods.

---

## 3. Maintenance & Day-2 Operations

### Zero-Downtime Rolling Upgrades

To update Helm release configurations or upgrade image tags:

```bash
helm upgrade agentwall ./chart -n agentwall-system
```

*When `gateway.replicas >= 2`, Kubernetes performs rolling updates to preserve request traffic continuity.*

---

### Triggering Instant Policy Hot-Reloads

If you bypass the SSE push stream or update custom policies directly on disk/configmaps, force immediate policy reloads without pod restarts using either of the following methods:

**Method A: Native Gateway Reload Endpoint**
```bash
kubectl exec -n agentwall-system deploy/agentwall-gateway -- \
  wget -qO- --post-data '' http://localhost:8080/reload
```

**Method B: Process SIGHUP Signal**
```bash
POD=$(kubectl get pod -n agentwall-system -l app.kubernetes.io/component=gateway -o name | head -1)
kubectl exec -n agentwall-system $POD -- kill -HUP 1
```

---

### Uninstalling the Deployment

To cleanly remove all AgentWall resources and Helm releases:

```bash
helm uninstall agentwall -n agentwall-system
```

---

## 4. Production Security & References

- **OIDC Configuration:** Bind corporate IdPs (Okta, Keycloak, Entra ID, Ping) for centralized team identity. See → [OIDC Identity Binding Guide](../oidc_identity_binding.md).
- **Audit Log Verification & SIEM Export:** Stream real-time JSON-RPC audit logs to Splunk, Datadog, or OpenSearch. See → [Common Reference Guide — SIEM Export](../common_guide.md#session-reports--siem-export).
- **Enterprise Features:** For HSM token storage, pure-Rust TLS termination, and HAR isolation, see → [Enterprise Fleet User Guide](../enterprise_guide.md).
