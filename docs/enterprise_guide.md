# Enterprise Fleet — User Guide

> **Target Audience:** Platform engineers and Security architects deploying Agent Control as a high-availability, cloud-native gateway fleet on Kubernetes for enterprise production workloads.
> Requires Kubernetes v1.26+, Helm v3+, and a domain TLS certificate.

---

## What This Profile Provides

The **Enterprise Fleet** profile delivers the full Agent Control security stack on Kubernetes with production-grade reliability, cryptographic privacy, and zero-trust enforcement across multi-tenant agent fleets.

> [!NOTE]
> All Workstation Sidecar and Team Control Hub capabilities are **fully included** in this profile. This guide covers the additional enterprise-exclusive capabilities.
>
> - Workstation Sidecar setup → [Workstation Sidecar Guide](workstation_guide.md)
> - Team Control Hub setup → [Team Control Hub Guide](team_hub_guide.md)

| Capability | What You Get |
|---|---|
| **Hardened Agent Container Runtime (HAR)** | Pre-built <100 MB Distroless/Alpine OCI sidecar image for Kubernetes pod deployments |
| **MCP Cross-Session Schema-Drift Defense** | Automatic detection and blocking of tool catalog modifications / rug pulls across sessions |
| **OWASP Agentic Top 10 (ASI 2026) Coverage** | Full architectural alignment with 8/10 full coverage, 1/10 partial, and automated audit evidence CLI |
| **Provider Key AES-256-GCM Encryption** | AES-256-GCM encrypted database custody for LLM provider API keys using 32-byte master key |
| **Offline Ed25519 Licensing & Seat Gating** | Ed25519-signed JWT licensing with zero telemetry and automatic seat enforcement (429 HTTP rejection) |
| **Air-Gapped OIDC & JWKS Support** | Offline disk-based JWKS key loading (`auth.jwks_file`) and `agentcontrol identity export-jwks` CLI tool |
| **Compliance Control Mapping & Evidence CLI** | Automated report generator (`agentcontrol compliance report`) mapped to OWASP ASI 2026, SOC 2, ISO 27001, and NIST AI RMF |
| **Centralized Hub SIEM Aggregation** | Multi-gateway log fan-in and batch export to Splunk HEC, Datadog Logs, or OpenSearch |
| **Hardened WebSocket Egress Tunneling** | Secure WebSocket proxy connecting remote cloud agents to local on-premise MCP servers (<5ms latency) |
| **Real-Time Threat Intelligence Feed** | Dynamically ingests Vexa AI Malware signature feeds via SSE — updates DLP patterns in-flight without downtime |
| **Zero-Knowledge CMK Encryption** | Client-side AES-256-GCM encryption of audit streams using Customer-Managed Keys before SIEM egress |
| **Pure-Rust TLS Termination** | Memory-safe HTTPS listener powered by `rustls` — eliminates C-library vulnerabilities and OpenSSL dependencies |
| **Fleet-Wide Telemetry & Monitoring** | Monitor gateway fleet health, pod status, policy sync state, and socket performance natively in Kubernetes |
| **Enterprise SIEM Integration** | Direct audit streaming to Splunk HEC, Datadog, or OpenSearch with zero-knowledge encryption |
| **Enterprise OIDC SSO** | Full OIDC SSO with Okta, Keycloak, Microsoft Entra ID, PingIdentity for fleet-wide identity binding |

---

## Table of Contents

1. [Production Prerequisites](#1-production-prerequisites)
2. [Installation: Kubernetes Helm Deployment](#2-installation-kubernetes-helm-deployment)
3. [Post-Deployment Verification](#3-post-deployment-verification)
4. [Hardened Agent Container Runtime (HAR)](#4-hardened-agent-container-runtime-har)
5. [Hardened WebSocket Egress Tunneling](#5-hardened-websocket-egress-tunneling)
6. [Real-Time Threat Intelligence Feed](#6-real-time-threat-intelligence-feed)
7. [Zero-Knowledge Customer-Managed Key Encryption](#7-zero-knowledge-customer-managed-key-encryption)
8. [Pure-Rust TLS Termination](#8-pure-rust-tls-termination)
9. [Fleet Telemetry & Monitoring](#9-fleet-telemetry--monitoring)
10. [Shared Reference Sections](#10-shared-reference-sections)

---

## 1. Production Prerequisites

### 1. Target Kubernetes Cluster

- Kubernetes cluster **v1.26+** (AWS EKS, GCP GKE, Azure AKS, or on-premises K8s).
- Ingress controller / Load Balancer configured for external TLS traffic termination.
- StorageClass available for persistent database storage (if deploying embedded PostgreSQL via Helm).

### 2. Admin Workstation / CI/CD Deployment Host

- `helm` CLI **v3+** installed.
- `kubectl` CLI installed and configured with `cluster-admin` context permissions for the target cluster.

### 3. Security & Cryptography Assets

- Domain **TLS Certificate** (`tls.crt`) and matching private key (`tls.key`) in PEM format.
- Alternatively, configure cert-manager for automated Let's Encrypt certificate provisioning.

### 4. Enterprise Identity & Audit Services

| Service | Requirement |
|---|---|
| **OIDC Provider** | Okta, Keycloak, Microsoft Entra ID, Auth0, or PingIdentity with OIDC Discovery URL (`.well-known/openid-configuration`) |
| **SIEM Collector (Optional)** | Splunk HEC, Datadog HTTP Intake, or OpenSearch endpoint with authentication token |
| **Customer-Managed Key (Optional)** | AES-256 key material for zero-knowledge audit log encryption before SIEM export |

---

## 2. Installation: Kubernetes Helm Deployment

### Step 1 — Create Namespace & TLS Secret

```bash
kubectl create namespace agentcontrol-system

kubectl create secret tls agentcontrol-tls \
  --cert=/etc/certs/tls.crt \
  --key=/etc/certs/tls.key \
  -n agentcontrol-system
```

### Step 2 — Deploy Agent Control Stack via Helm

```bash
helm install agentcontrol ./chart \
  --namespace agentcontrol-system \
  --set gateway.tls.enabled=true \
  --set gateway.tls.secretName="agentcontrol-tls" \
  --set gateway.oidcIssuer="https://auth.corp.com/oauth2/default" \
  --set gateway.siem.backend="splunk" \
  --set gateway.siem.endpoint="https://splunk.corp.com:8088/services/collector/event" \
  --set gateway.siem.token="${SPLUNK_HEC_TOKEN}" \
  --set dashboardApi.enabled=true \
  --set dashboardDb.enabled=true \
  --set dashboardFrontend.enabled=true
```

**Key Helm values reference:**

| Helm Key | Description | Example |
|---|---|---|
| `gateway.tls.enabled` | Enable `rustls` TLS termination | `true` |
| `gateway.tls.secretName` | K8s TLS secret name | `agentcontrol-tls` |
| `gateway.oidcIssuer` | OIDC provider discovery URL | `https://auth.corp.com/oauth2/default` |
| `gateway.siem.backend` | SIEM target (`splunk`, `datadog`, `opensearch`) | `splunk` |
| `gateway.siem.endpoint` | SIEM ingestion endpoint URL | `https://splunk.corp.com:8088/...` |
| `gateway.siem.token` | SIEM authentication token (use K8s secret reference) | `${SPLUNK_HEC_TOKEN}` |
| `dashboardApi.enabled` | Deploy Control Hub REST API pod | `true` |
| `dashboardDb.enabled` | Deploy embedded PostgreSQL pod | `true` |
| `dashboardFrontend.enabled` | Deploy React Management Console pod | `true` |

---

## 3. Post-Deployment Verification

### Step 1 — Verify Kubernetes Workload Health

```bash
kubectl get pods -n agentcontrol-system -o wide
```

**Expected output:** All pods showing status `Running` and readiness `1/1`.

This confirms gateway pods, Control Hub API, PostgreSQL, and frontend deployments are healthy.

---

### Step 2 — Inspect Gateway Container Logs

```bash
kubectl logs -n agentcontrol-system -l app.kubernetes.io/component=gateway --tail=100
```

**Expected log entries:**
```
[INFO] TLS listener bound on 0.0.0.0:443 (rustls)
[INFO] OIDC discovery completed: https://auth.corp.com/.well-known/openid-configuration
[INFO] SIEM HTTP intake connected: https://splunk.corp.com:8088/services/collector/event
[INFO] Policy loaded successfully from Control Hub
[INFO] SSE event subscription connected
```

This validates TLS binding, OIDC provider discovery, and SIEM telemetry streaming.

---

### Step 3 — Execute Automated Policy Smoke Test

```bash
agentcontrol test --policy agentcontrol-policy.yaml --gateway https://agentcontrol.corp.com fixtures/smoke_test.json
```

**Expected output:** A terminal test report summarizing passed assertions and policy enforcement checks.

This provides end-to-end empirical verification of governance policy enforcement across the live gateway fleet.

---

### Step 4 — Verify Enterprise SIEM & OIDC Audit Telemetry

Check your enterprise SIEM dashboard (e.g., Splunk, Datadog):
- **Splunk:** Confirm events appearing in the configured index (e.g., `security_events`).
- **Datadog:** Confirm events visible under the `agentcontrol` log source in the Logs Explorer.
- **OIDC Provider:** Verify audit logs show valid `sub`, `iss`, and `aud` claim bindings for each gateway session.

---

## 4. Hardened Agent Container Runtime (HAR)

The HAR is a pre-built, distroless/Alpine OCI sidecar image designed as an entrypoint proxy for Kubernetes pods. It embeds the full Agent Control gateway in a **<100 MB** container.

### Build the HAR Image

```bash
docker build -f Dockerfile.har -t agentcontrol-har:2.0 .
```

### Run Standalone (Testing)

```bash
docker run \
  -e AGENTWALL_POLICY_PATH=/etc/agentcontrol/policy.yaml \
  agentcontrol-har:2.0
```

### Deploy as Kubernetes Sidecar

Add the HAR container as an `initContainer` or sidecar container alongside your agent workload pod:

```yaml
spec:
  containers:
    - name: ai-agent
      image: your-agent-image:latest
      env:
        - name: HTTP_PROXY
          value: "http://localhost:8080"
        - name: HTTPS_PROXY
          value: "http://localhost:8080"
    - name: agentcontrol-sidecar
      image: agentcontrol-har:2.0
      env:
        - name: AGENTWALL_POLICY_PATH
          value: /etc/agentcontrol/policy.yaml
        - name: AGENTWALL_LISTEN
          value: "0.0.0.0:8080"
      volumeMounts:
        - name: policy-config
          mountPath: /etc/agentcontrol
  volumes:

---

## 5. Enterprise MDM Fleet Deployment Templates

Enterprise security administrators can deploy Agent Control across developer fleets using MDM platforms (Jamf Pro, Kandji, Microsoft Intune, Ansible).

### 1. macOS MDM Deployment (Jamf Pro / Kandji)

**Script Payload (Jamf Script Editor / Kandji Custom Script):**
```bash
#!/bin/bash
# Jamf Pro / Kandji Managed Deployment Script for Agent Control
export AGENTWALL_TOKEN="TOK-ENTERPRISE-TOKEN-892A"
export AGENTWALL_HUB_URL="https://agentcontrol.corp.com"

# Install binary and run automated enrollment & daemon registration
curl -fsSL https://agentcontrol.corp.com/install.sh | bash

# Ensure system LaunchDaemon is active
launchctl load -w /Library/LaunchDaemons/io.vexasec.agentcontrol.plist || true
```

### 2. Windows MDM Deployment (Microsoft Intune Win32App)

**PowerShell Script (Intune Management Extension):**
```powershell
<#
.SYNOPSIS
    Microsoft Intune Win32App Deployment Script for Agent Control Sentry Service
#>
$env:AGENTWALL_TOKEN = "TOK-ENTERPRISE-TOKEN-892A"
$env:AGENTWALL_HUB_URL = "https://agentcontrol.corp.com"

irm https://agentcontrol.corp.com/install.ps1 | iex

# Start Agent Control SCM Service
Start-Service -Name "Agent ControlSentry" -ErrorAction SilentlyContinue
```

### 3. Linux Fleet Ansible Playbook

```yaml
---
- name: Deploy Agent Control Persistent Security Sentry Daemon
  hosts: developer_workstations
  become: yes
  vars:
    enrollment_token: "TOK-ENTERPRISE-TOKEN-892A"
    hub_url: "https://agentcontrol.corp.com"

  tasks:
    - name: Download & install Agent Control binary
      shell: "curl -fsSL https://agentcontrol.corp.com/install.sh | AGENTWALL_TOKEN='{{ enrollment_token }}' AGENTWALL_HUB_URL='{{ hub_url }}' bash"
      args:
        creates: /usr/local/bin/agentcontrol

    - name: Ensure agentcontrol.service is enabled and running
      systemd:
        name: agentcontrol
        state: started
        enabled: yes
```
    - name: policy-config
      configMap:
        name: agentcontrol-policy
```

**What You Achieve:**
- Every AI agent container in your K8s fleet gets full Agent Control governance — DLP scanning, prompt injection protection, audit logging, OIDC binding, and spend control — without modifying agent application code.

---

## 5. Hardened WebSocket Egress Tunneling

Bridge cloud-hosted agents to local on-premise MCP servers securely via the Agent Control WebSocket proxy:

```
Cloud Agent Pod ──► Agent Control Gateway (K8s) ──WSS──► Agent Control Tunnel (On-Prem) ──► MCP Server
```

- **Latency:** <5ms frame latency.
- **Security:** Inline DLP scanning on all WebSocket frames.
- **TLS:** End-to-end TLS powered by `rustls`.

Enable in Helm:
```bash
helm upgrade agentcontrol ./chart \
  --namespace agentcontrol-system \
  --set gateway.websocketTunnel.enabled=true \
  --set gateway.websocketTunnel.upstreamUrl="wss://tunnel.on-prem.corp.com:8443"
```

Or via CLI (on-prem tunnel endpoint):
```bash
agentcontrol start \
  --centralized \
  --listen 0.0.0.0:8080 \
  --ws-tunnel wss://tunnel.on-prem.corp.com:8443
```

---

## 6. Real-Time Threat Intelligence Feed

Agent Control subscribes to live Vexa AI Malware signature feeds via SSE, updating DLP regex patterns in-flight without dropping active connections or restarting gateway pods.

```
Vexa Threat Intel SSE Stream ──► Agent Control Gateway ──► In-memory DLP pattern update
```

Enable in Helm:
```bash
helm upgrade agentcontrol ./chart \
  --namespace agentcontrol-system \
  --set gateway.threatIntel.enabled=true \
  --set gateway.threatIntel.feedUrl="https://feeds.vexasec.io/v1/patterns"
```

Or via environment variable:
```bash
export AGENTWALL_THREAT_INTEL_URL="https://feeds.vexasec.io/v1/patterns"
agentcontrol start --centralized --listen 0.0.0.0:8080
```

**What You Achieve:**
New AI malware signatures are deployed to your entire gateway fleet within seconds of Vexa publishing them — with zero downtime.

---

## 7. Zero-Knowledge Customer-Managed Key Encryption

Encrypt audit log streams with your own Customer-Managed Key (AES-256-GCM) client-side **before** they are transmitted to your SIEM — ensuring Vexa and your SIEM provider have zero access to plaintext audit data.

```bash
agentcontrol start \
  --centralized \
  --listen 0.0.0.0:8080 \
  --siem-backend splunk \
  --siem-endpoint https://splunk.corp.com:8088/services/collector/event \
  --siem-token "${SPLUNK_HEC_TOKEN}" \
  --cmk-key-file /etc/agentcontrol/customer.key
```

**Key Management Integration:**

For hardware key management (HSM / Cloud KMS):

| KMS Provider | Environment Variable |
|---|---|
| AWS KMS | `AGENTWALL_CMK_KMS_ARN=arn:aws:kms:...` |
| GCP Cloud KMS | `AGENTWALL_CMK_KMS_RESOURCE=projects/.../cryptoKeyVersions/1` |
| Azure Key Vault | `AGENTWALL_CMK_VAULT_URL=https://vault.vault.azure.net/keys/...` |
| HashiCorp Vault | `AGENTWALL_CMK_VAULT_ADDR=https://vault.corp.com` |

**What You Achieve:**
Your SIEM receives AES-256-GCM encrypted payloads. Only systems holding your Customer-Managed Key can decrypt audit records — full compliance with data residency and sovereignty requirements.

---

## 8. Pure-Rust TLS Termination

Agent Control's HTTPS listener is powered by `rustls` — a memory-safe TLS implementation written entirely in Rust. This eliminates:
- OpenSSL/LibreSSL C-library memory corruption vulnerabilities.
- Buffer overflow attack surfaces.
- Dependency on system-level TLS libraries (fully statically linked).

**TLS is configured via Helm** (see [Step 2](#step-2--deploy-agentcontrol-stack-via-helm)) or via CLI:

```bash
agentcontrol start \
  --listen 0.0.0.0:443 \
  --tls-cert /etc/certs/tls.crt \
  --tls-key /etc/certs/tls.key \
  --policy policy.yaml
```

> [!IMPORTANT]
> Both `--tls-cert` and `--tls-key` must be specified together. Providing only one will result in startup error: `Both --tls-cert and --tls-key must be specified together`.

---

## 9. Fleet Telemetry & Monitoring

Monitor the health and performance of your gateway fleet natively in Kubernetes:

**Pod-level health:**
```bash
kubectl get pods -n agentcontrol-system -o wide
kubectl top pods -n agentcontrol-system
```

**Real-time log streaming:**
```bash
kubectl logs -n agentcontrol-system -l app.kubernetes.io/component=gateway -f
```

**Policy sync state verification:**
```bash
kubectl logs -n agentcontrol-system -l app.kubernetes.io/component=gateway | grep "Policy"
```

**Enterprise Management Console:**
Access the fleet-wide management console via your configured Kubernetes Ingress TLS endpoint (e.g., `https://agentcontrol-console.corp.com`). The console provides:
- HAR container pod telemetry
- Threat intelligence feed subscription status
- Zero-knowledge CMK SIEM encryption status
- Fleet-wide security compliance overview

---

## 10. Shared Reference Sections

The following technical reference sections are maintained in the shared [Common Reference Guide](common_guide.md):

| Reference Topic | Link |
|---|---|
| Writing YAML Policies (v2 Schema) | [common_guide.md → YAML Policies](common_guide.md#writing-yaml-policies-v2-schema) |
| Configuring Data Loss Prevention (DLP) | [common_guide.md → DLP](common_guide.md#configuring-data-loss-prevention-dlp) |
| Setting Up OIDC Identity Binding | [common_guide.md → OIDC](common_guide.md#setting-up-oidc-identity-binding) |
| Verifying Audit Logs | [common_guide.md → Audit Logs](common_guide.md#verifying-audit-logs) |
| SIEM Export (Splunk, Datadog, OpenSearch) | [common_guide.md → SIEM Export](common_guide.md#session-reports--siem-export) |
| Stateful Sequence Rules (ADR Framework) | [common_guide.md → Sequence Rules](common_guide.md#stateful-sequence-rules-adr-framework) |
| ADR Security Benchmark Reference | [common_guide.md → ADR Benchmark](common_guide.md#adr-security-benchmark) |
| Environment Variables Reference | [common_guide.md → Environment Variables](common_guide.md#environment-variables) |
| Troubleshooting Common Issues | [common_guide.md → Troubleshooting](common_guide.md#troubleshooting-common-issues) |
