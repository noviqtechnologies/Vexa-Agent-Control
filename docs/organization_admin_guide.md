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

---

## 6. OIDC Federation & Enterprise Identity Management

Organization Admins can configure OIDC Identity Providers (Google Workspace, Microsoft Entra ID, Okta, Auth0, Keycloak, Clerk) under **Auth Providers & SSO** (`/settings/auth-providers`).

### Core Guarantees:
1. **Durable Subject Binding:** Users are bound to their immutable `provider_subject` (`sub` claim) rather than mutable email strings.
2. **Ambiguity Guard:** If an SSO user logs in and multiple local accounts share that email address, automatic linking halts with an explicit error to prevent account takeover.
3. **Safe Account Linking:** Local password `MEMBER` users require a password confirmation challenge before binding external SSO identities. Privileged `ADMIN` and `OWNER` accounts cannot be linked self-service.
4. **Endpoint Diagnostics:** Admins can test IdP discovery and JWKS connectivity at any time using `POST /api/v1/auth/providers/{id}/test`.

### Host-Bound Emergency Break-Glass Recovery
If an IdP configuration error, expired certificate, or network outage locks administrators out of the Hub, generate a single-use 15-minute emergency recovery token directly on the host:

```bash
agentcontrol-admin break-glass --email admin@agentcontrol.local
```

Redeem the token at `http://<hub-host>:8081/break-glass` to immediately restore Owner access and invalidate compromised sessions.

---

## 7. Scoped Virtual Keys Administration & Governance

Vexa Agent Control allows organization administrators to issue and govern **Scoped Virtual Keys** for human developers, client tools, and automation.

### Admin-Only Provisioning Workflow
Under the Zero Trust security model, virtual keys are **not automatically issued** during onboarding. An Organization Administrator explicitly provisions keys tailored to specific developer workloads:

1. In the Web Console, navigate to **Scoped Virtual Keys** (`/virtual-keys`).
2. Click **Issue Virtual Key** (`#btn-issue-virtual-key`).
3. Configure the governance policy:
   - **Key Ownership Persona**: Restricted to `🧑 User / Developer` (Service Accounts and Autonomous Agents are reserved for future releases).
   - **Key Name**: Descriptive identifier (e.g. `alice-cursor-ide`, `evals-harness`).
   - **Team / Developer ID**: Attribution identifier (e.g. `alice@acme.com`, `core-backend`).
   - **Monthly Spend Budget ($ USD)**: Financial limit enforced atomically (e.g. `$50.00`).
   - **Rate Limits**: Maximum requests per minute (`RPM`), tokens per minute (`TPM`), and concurrent in-flight requests.
   - **Model Allowlists**: Model wildcard filters (e.g. `claude-3-5-sonnet*`, `gpt-4o-mini`).
   - **CIDR IP Allowlists**: Restrict execution to approved corporate egress IPs or developer VPN blocks.
4. Click **Issue**. The raw secret (`sk-vex-...`) is displayed **once**. Deliver the secret securely to the developer.

### Developer Client Integration

#### Cursor IDE / VS Code
In Cursor Settings ➔ Models ➔ OpenAI API Key / Base URL override:
- **Base URL**: `https://<agentcontrol-host>/v1`
- **API Key**: `sk-vex-<secret>`

#### Claude Code CLI
```bash
export ANTHROPIC_BASE_URL="https://<agentcontrol-host>"
export ANTHROPIC_API_KEY="sk-vex-<secret>"
claude
```

#### OpenAI Python SDK
```python
from openai import OpenAI

client = OpenAI(
    base_url="https://<agentcontrol-host>/v1",
    api_key="sk-vex-<secret>"
)

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Hello Agent Control"}]
)
print(response.choices[0].message.content)
```

### Zero-Downtime Rotation & Revocation
- **Zero-Downtime Rotation**: Admins can rotate active keys with a configurable grace period (default: 3600 seconds). Both old and new secrets authenticate cleanly until the grace period elapses.
- **Immediate Revocation**: Clicking Revoke invalidates the key hash and evicts all connected edge proxy caches via real-time SSE invalidation events.

---

## 6. Centralized Provider Key Custody (Zero-Leakage Model)

To eliminate the security liability of distributing raw company API keys (OpenAI, Anthropic, Gemini, AWS Bedrock) to developer laptops:

1. **Central KMS Envelope Encryption:** Navigate to **Settings ➔ Provider Keys** in the Web Console. Enter your company's master provider API keys.
2. **Encrypted at Rest:** Keys are encrypted using AES-256-GCM envelope encryption backed by Docker Secrets (`/run/secrets/master_key` with `0400` permissions) or cloud KMS.
3. **Transient In-Memory Decryption:** Provider secrets are decrypted strictly in memory at the Control Hub gateway during upstream request dispatch and zeroized immediately after execution.
4. **Zero Secrets on Workstations:** Developers authenticate with their corporate SSO accounts (`agentcontrol login`). The local proxy forwards requests to the Hub without requiring or storing any raw provider API keys on developer disks.

---

## 7. First-Class Team Governance & Immediate Offboarding

1. **Team Model Allowlists & Budgets:** Assign developers to teams (`team_memberships`) with model allowlists (e.g. `claude-3-5-sonnet`, `gpt-4o`) and monthly spend limits ($50/developer).
2. **Immediate Offboarding Guarantee:** When an employee leaves the company, disabling their account in Google Workspace or Microsoft Entra ID immediately invalidates OIDC token refreshes. Model access and proxy routing terminate instantly without manual credential rotation.
3. **Immutable Attribution Ledger:** Every admitted request is recorded in `broker_admissions` with verified `organization_id`, `team_id`, `user_id`, `device_id`, and `policy_version` before upstream dispatch.


