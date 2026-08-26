# Kubernetes & Hardened Agent Container Runtime (HAR)

This guide details deploying Vexa Agent Control in Kubernetes using Helm or as a Hardened Agent Container Runtime (HAR) sidecar.

---

## Helm Chart Deployment

Deploy the central gateway or Hub in your Kubernetes cluster:

```bash
# Add Vexa Helm repository
helm repo add vexa https://charts.vexasec.io
helm repo update

# Install Gateway with custom values
helm install agentcontrol vexa/agentcontrol \
  --namespace security \
  --create-namespace \
  --set replicaCount=3 \
  --set policy.defaultVerdict=deny
```

---

## Hardened Agent Container Runtime (HAR) Sidecar Pattern

In autonomous agent deployments, inject the `agentcontrol` sidecar alongside the agent pod:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: autonomous-researcher
  namespace: agents
spec:
  replicas: 2
  template:
    spec:
      containers:
        # Agent Container
        - name: agent
          image: mycompany/research-agent:latest
          env:
            - name: HTTP_PROXY
              value: "http://127.0.0.1:8080"
            - name: AGENTCONTROL_PROXY_URL
              value: "http://127.0.0.1:8080"

        # Vexa Agent Control Security Sidecar
        - name: security-sidecar
          image: noviqtechnologies/agentcontrol:1.0.65
          args: ["start", "--policy", "/etc/agentcontrol/policy.yaml"]
          volumeMounts:
            - name: policy-vol
              mountPath: /etc/agentcontrol
      volumes:
        - name: policy-vol
          configMap:
            name: cluster-agent-policy
```
