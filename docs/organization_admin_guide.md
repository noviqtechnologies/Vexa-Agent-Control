# Organization & License Administration Guide

## 1. Overview
**Vexa Agent Control** is an organization-first, single-tenant security gateway and control plane designed to govern AI agent tool execution, prevent credential leakage, enforce spend budgets, and ensure compliance at the workstation boundary.

Under the **Single-Tenant Open-Core** model:
- **No Shared SaaS Multi-Tenancy:** Each deployment belongs entirely to your organization (`organization_id`). Sensitive API keys, source code, and telemetry never traverse third-party shared infrastructure.
- **Unified Single Docker Image:** All capabilities ship in a single unified image (`ghcr.io/noviqtechnologies/vexa-agentcontrol:latest`).
- **Cryptographic Offline Licensing (Ed25519):** Advanced tiers unlock at runtime via self-contained Ed25519 JWT tokens without calling home.

---

## 2. Edition & Licensing Model

| Edition | Capacity | Capabilities Included | Activation Method |
|---|---|---|---|
| **Community (Open Source)** | Unlimited | Core Rust Gateway, local proxy, MCP inspection, JSONL audit logs, prompt injection guards, regex DLP, team control plane | Free & Open Source (Apache 2.0) |
| **Commercial / Enterprise** | Custom / Enterprise SLA | Everything in Community + Dedicated enterprise SLA, custom deployment support, sovereign deployment assistance | Signed Commercial License Token or Contract |

---

## 3. Managing Your Organization Profile

### Web Console Management
1. Log in to the Control Plane Web Console (`http://localhost:8081` or your private domain).
2. Navigate to **Team & Organization ➔ Organization & License** (`/settings/license`).
3. View your active organization details:
   - **Organization Name & Slug**
   - **Active License Tier** (`DEVELOPER`, `TEAM`, `ENTERPRISE`)
   - **Device Quota & Capacity:** Real-time count of enrolled devices against your tier limit (e.g. `1/1`, `12/25`, or `Unlimited`).
   - **Expiration Countdown:** Days remaining on your active license key.

### Activating a License Key
To upgrade or renew your license tier:
1. Obtain your cryptographically signed Ed25519 license JWT from your Vexa representative.
2. In **Organization & License**, paste the JWT into the **Activate License Key** input.
3. Click **Activate License**. The control plane verifies the signature offline and immediately unlocks your new device capacity and capabilities.

Alternatively, set the environment variable on your Control Plane container:
```bash
export VEXA_LICENSE_KEY="eyJhbGciOiJFZERTQSI..."
```

---

## 4. Device Enrollment Governance & Caps

When an agent workstation initiates enrollment via `agentcontrol enroll --token <TOKEN> --hub-url <URL>`:
1. The Control Plane verifies that the active enrolled device count has not exceeded the license tier limit (`1` for Developer, `25` for Team, unlimited for Enterprise).
2. If the quota is full, enrollment is rejected with `429 Too Many Requests` (`device_limit_reached`).
3. Revoking decommissioned devices in **Device Governance** immediately frees up capacity for new enrollments.

---

## 5. Security & Isolation Guarantee

- **Full Sovereign Ownership:** Every database table (`users`, `devices`, `policies`, `provider_keys`, `virtual_keys`, `spend_ledger`) is bounded by your private `organization_id`.
- **Air-Gap Compatibility:** License verification requires zero outbound connectivity. All public keys are embedded and verified with Ed25519 math.
- **Fail-Closed Gateways:** If a device is revoked or compromised, gateways immediately sever brokered credential access.
