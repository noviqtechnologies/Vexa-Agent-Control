# SOC Web Console User & Administration Guide

The VEXA Agent Control Web Console is an enterprise Security Operations Center (SOC) interface for managing developer agent fleets, enforcing zero-master-key custody, monitoring multi-state posture, and auditing AI tool execution.

---

## 1. Navigating the Console

The sidebar organizes functionality into six core operational domains:
- **Device & Fleet Governance**: Workstation fleet inventory, multi-state capability tracking, coverage matrix, and IDE drift logs.
- **Policies & Security**: Dynamic policy authoring, DLP rules, 6-pass prompt injection defense, group policy assignment, and safe mode controls.
- **Integrations & Keys**: Universal AI Gateway virtual key custody, model provider credentials, and MCP server registry.
- **Observability & Runs**: Forensics run explorer, multi-turn session tracing, and streaming audit logs.
- **Spend & Budgets**: Authoritative spend limits, preflight reservations, and self-service increase requests.
- **Team & Organization**: Single Sign-On (SSO) providers, user roles, license management, and administrative tokens.

---

## 2. Fleet Overview & Composite Posture Index

The Fleet Overview dashboard provides immediate executive visibility into organizational AI safety via the **Composite Posture Index (0-100%)**:

### The 4 Posture Score Factors
1. **Workstation Capability & Freshness (35% Weight)**: Proportion of registered endpoints with active `ACTIVE_FRESH` telemetry and verified proxy/MCP routing.
2. **Active Guardrails & DLP Rules (35% Weight)**: Enforcement status of the 21 enterprise DLP detection patterns, prompt injection shields, and Safe Mode defaults.
3. **Universal Gateway & Key Custody (15% Weight)**: Active Virtual Key deployment with zero raw API keys exposed on developer endpoints.
4. **Spend Governance & Preflight Caps (15% Weight)**: Real-time reservation settlement and automated fail-closed budget adherence.

Clicking **"Score Factors"** expands an interactive breakdown showing the exact mathematical points attributed to each domain.

---

## 3. Device Governance & Multi-State Observability

Modern developer environments are heterogeneous and dynamic. Rather than reducing device health to a simplistic binary "compliant" flag, Agent Control implements **Multi-State Capability Observability**:

### 3.1 Capability Vectors
Each workstation reports which operational boundaries are verified:
- `CONFIGURED`: Workstation configuration locked to local proxy (`127.0.0.1:8080`).
- `MCP_WRAPPED`: Stdio tool wrappers active for CLI and IDE agents.
- `PROBE_VERIFIED`: Active verification probe executed and signed by endpoint.
- `TRAFFIC_VERIFIED`: Attested LLM or MCP transactions successfully routed through gateway.
- `MCP_TRAFFIC_VERIFIED`: MCP tool calls inspected and approved by policy engine.
- `BYPASS_POSSIBLE`: Direct internet egress detected outside the managed boundary.

### 3.2 Freshness Tiers
Tracks communication recency without false alarms:
- `🟢 ACTIVE_FRESH`: Telemetry or heartbeat received within the last **15 minutes**.
- `🟡 ACTIVE_RECENT`: Active communication within the last **24 hours**.
- `🔴 STALE`: No authenticated telemetry in over **24 hours** (machine asleep, offboarded, or network isolated).

---

## 4. Onboarding Workstations

Workstations can be enrolled through two seamless paths:

### Method A: Zero-Touch Developer Login (Recommended)
Developers run a single command in their terminal:
```bash
agentcontrol login
```
This opens the browser, executes an OAuth 2.0 PKCE challenge against the Control Hub, generates local Ed25519 identity keys inside the OS secure storage (DPAPI / Keychain), and automatically registers the public key at `/api/v2/devices/enroll`.

### Method B: Headless Enrollment Token (CI/CD or MDM)
1. Navigate to **Device Governance** in the Web Console.
2. Click **"+ Generate Enrollment Token"**.
3. Select expiration (e.g. 24 hours) and provide a reason or device label.
4. Execute the generated command on the target system:
```bash
agentcontrol enroll --hub-url https://console.vexasec.io --token <token_value>
```

---

## 5. Workstation Inspection & Revocation

### Inspecting Endpoint Health
Click the **magnifying glass (🔍)** or **"Inspect"** button on any workstation row to view:
- Hardware architecture, OS version, and agent release.
- Ed25519 identity key fingerprint and active status.
- Detected IDE installations (Cursor, VS Code, Windsurf, Zed, Cline) and proxy configuration state.
- Recent anti-tamper drift logs and policy realignment history.

### Immediate Device Revocation
If an endpoint is compromised, lost, or decommissioned:
1. Click **"Revoke"** on the target workstation.
2. Select a revocation reason preset (e.g. *Security Incident*, *Offboarded*, or *Custom Reason*).
3. Confirm revocation. The Control Hub immediately sets `status = REVOKED` and marks the device's public keys as revoked. All subsequent broker requests, telemetry ingestion, and token refreshes are rejected at the edge gateway.

---

## 6. Spend Limits & Increase Requests

Administrators configure financial boundaries under **Spend & Budgets**:
- **Hard Budget Caps**: Set maximum allowable spend per day or billing period.
- **Preflight Reservations**: Gateway estimates token costs before dispatching requests to LLM providers; calls exceeding limits receive HTTP 429 (`BudgetExceeded`).
- **Increase Requests**: When a developer requires additional budget for complex tasks, they can submit an increase request from their CLI. Administrators can review, approve, or decline requests directly in the console at `/spend/requests`.
