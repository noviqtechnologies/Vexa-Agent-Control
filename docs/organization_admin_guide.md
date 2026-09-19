# Organization & License Administration Guide

## 1. Overview
**Vexa Agent Control** is an organization-first, single-tenant security gateway and control plane designed to govern AI agent tool execution, prevent credential leakage, enforce spend budgets, and ensure compliance at the workstation boundary.

Under the **Single-Tenant Open-Core** model:
- **No Shared SaaS Multi-Tenancy:** Each deployment belongs entirely to your organization (`organization_id`). Sensitive API keys, source code, and telemetry never traverse third-party shared infrastructure.
- **Unified Single Docker Image:** All capabilities ship in a single unified image (`ghcr.io/noviqtechnologies/vexa-agentcontrol:latest`).
- **Cryptographic Offline Licensing (Ed25519):** Advanced tiers unlock at runtime via self-contained Ed25519 JWT tokens without calling home.

---

## 2. Edition & Licensing Model

Vexa operates on an **Open-Core** distribution model:

| Edition | Capacity | Capabilities Included | Licensing & Availability |
|---|---|---|---|
| **Community Core (Open Source)** | Unlimited | Core Rust Gateway, local proxy, MCP inspection, JSONL audit logs, safe-mode execution, prompt injection firewall, regex DLP | **Free & Open Source** (Apache 2.0 forever) |
| **Team Control Hub** | Up to 5 devices (Early Access) / 50 devices (GA) | Centralized SSE policy push, OIDC identity binding, vault credential custody, live spend ledger, device compliance governance | **Free for 30 Days during Early Access** (Self-hosted via Docker Compose / Helm) |
| **Enterprise / Sovereign** | Custom / Unlimited | Dedicated enterprise SLA, custom deployment support, sovereign air-gapped deployment assistance, SIEM streaming, custom DLP classifiers | **Commercial License / Design Partner Pilot** (Ed25519 Token) |

---

## 3. Managing Your Organization Profile

### Web Console Management
1. Log in to the Control Plane Web Console (`http://localhost:8081` or your private domain).
2. Navigate to **Team & Organization ➔ Organization & License** (`/settings/license`).
3. View your active organization details:
   - **Organization Name & Slug**
   - **Active License Tier** (`DEVELOPER`, `TEAM`, `ENTERPRISE`)
   - **Device Quota & Capacity:** Real-time count of enrolled devices against your tier limit (e.g. `1/5`, `5/5`, or `Unlimited`).
   - **Expiration Countdown:** Days remaining on your active license key or 30-day Early Access evaluation window.

### Activating a License Key
To upgrade or apply a commercial enterprise or design partner license (required after 30 days of Early Access or to connect > 5 devices):
1. Obtain your cryptographically signed Ed25519 license JWT from your Vexa representative or design partner onboarding.
2. In **Organization & License**, paste the JWT into the **Activate Design Partner / Enterprise License** input.
3. Click **Activate License**. The control plane verifies the signature offline and immediately unlocks your new device capacity and capabilities.

Alternatively, set the environment variable on your Control Plane container:
```bash
export VEXA_LICENSE_KEY="eyJhbGciOiJFZERTQSI..."
```

---

## 4. Device Enrollment Governance & Caps

When an agent workstation initiates enrollment via `agentcontrol login --hub <URL>` (interactive PKCE) or `agentcontrol enroll --token <TOKEN> --hub-url <URL>` (headless/MDM, requires admin-issued OTET):
1. The Control Plane verifies that the 30-day Early Access evaluation window has not expired and that the active enrolled device count has not exceeded the license tier limit (`1` for Developer, `5` for Team during Early Access, `50` for Team at GA, unlimited for Enterprise).
2. If the quota is full or the 30-day window has expired, enrollment is rejected with `429 Too Many Requests` (`device_limit_reached`) or `403 Forbidden` (`license_expired`). To request additional Early Access device capacity, reach out on the community Discord or email `early-access@vexasec.io`.
3. Revoking decommissioned devices in **Device Governance** immediately excludes them from the total enrolled count, freeing up capacity for new enrollments.

> [!NOTE]
> The primary developer onboarding path is `agentcontrol login`, which handles PKCE authentication, device registration, and background service installation in a single step. The `agentcontrol enroll --token` path requires an admin-issued one-time token and is reserved for future headless/MDM/CI fleet deployment workflows (Hub-side token generation not yet available).

---

## 5. Security & Isolation Guarantee

- **Full Sovereign Ownership:** Every database table (`users`, `devices`, `policies`, `provider_keys`, `virtual_keys`, `spend_ledger`) is bounded by your private `organization_id`.
- **Air-Gap Compatibility:** License verification requires zero outbound connectivity. All public keys are embedded and verified with Ed25519 math.
- **Fail-Closed Gateways:** If a device is revoked or compromised, gateways immediately sever brokered credential access.
