# Vexa Agent Control v4.0 Operator Runbook

**Target Audience:** Owner-Admins, Security Leads, and SaaS Operators  
**Domain:** `console.vexasec.io` (GCP SaaS Hub)  

---

## 1. Issuing Enrollment Tokens (OTET)

One-Time Enrollment Tokens (OTET) are single-use bootstrap secrets with a default 24-hour expiration.

### Via Admin Console API
```bash
curl -X POST https://console.vexasec.io/api/v2/admin/enrollment-tokens \
  -H "Authorization: Bearer <ADMIN_OIDC_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "schema_version": "2.0",
    "expires_in_minutes": 480,
    "device_label": "Taylor-Laptop",
    "reason": "New engineer onboarding"
  }'
```

> [!WARNING]
> **Delivery Rule:** The token is returned in the API response **exactly once**. Never share raw tokens via public chat or unencrypted email.

---

## 2. Emergency Device Revocation

When a laptop is lost, stolen, or compromised, containment is executed with a single administrative call.

### Immediate Revocation
```bash
curl -X POST https://console.vexasec.io/api/v2/admin/devices/0198d5b4-7376-7d90-8bc5-6dc3d4e80c26/revoke \
  -H "Authorization: Bearer <ADMIN_OIDC_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "reason": "Device reported lost in transit",
    "incident_reference": "INC-2026-0042"
  }'
```

### Guarantees:
1. **Immediate Backend Denial**: Cloud SQL records `REVOKED` state; next mTLS call to `device.vexasec.io` receives `403 Forbidden` (`device_revoked`).
2. **Terminal Invariant**: Revoked devices cannot be reactivated by resetting flags or re-submitting old tokens.

---

## 3. Controlled Recovery Workflow

If a revoked device is recovered or wiped:
1. **Issue Recovery Grant**:
   ```bash
   POST /api/v2/admin/devices/{id}/recovery-approvals
   ```
2. **Generate Fresh Token**: A fresh one-use recovery token is minted.
3. **Fresh Lineage**: The endpoint re-enrolls with a brand new Ed25519 key and new ECDSA client certificate. Historical revoked certificates remain permanently revoked.

---

## 4. Provider Broker & Capability Management

Agent Control manages provider master keys directly in **GCP Secret Manager**.
* **Zero Keys on Endpoints**: Endpoints never receive raw OpenAI or Anthropic API keys.
* **Per-Device Capabilities**: Scopes can be limited to specific model families (e.g. `gpt-4.1-mini` or `claude-3-5-sonnet`) and project references via `PUT /api/v2/admin/devices/{id}/provider-capabilities`.

---

## 5. Authoritative Spend Governance & Increase Approvals

Operators govern organization and project LLM budgets through the Management Console (`/spend/*`) or direct REST API calls.

### 1. Publishing / Adjusting Spend Policies
```bash
curl -X POST https://console.vexasec.io/api/v2/spend/policies \
  -H "Authorization: Bearer <ADMIN_OIDC_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "scope_type": "project",
    "scope_id": "customer-support",
    "period_type": "monthly",
    "limit_usd": 250.00,
    "action": "hard_deny"
  }'
```

### 2. Reviewing & Deciding Increase Requests
List pending increase requests submitted by developers:
```bash
curl -X GET https://console.vexasec.io/api/v2/spend/increase-requests \
  -H "Authorization: Bearer <ADMIN_OIDC_TOKEN>"
```

Approve or reject a specific request:
```bash
curl -X POST https://console.vexasec.io/api/v2/spend/increase-requests/0198d5c4-1234-7d90-8bc5-6dc3d4e80c26/decide \
  -H "Authorization: Bearer <ADMIN_OIDC_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "decision": "APPROVED",
    "reason": "Approved for Q3 customer support automation initiative"
  }'
```
Approving automatically updates or creates an authoritative policy version and adjusts the project's active budget window without service interruption.

### 3. Auditing Spend Transitions
Query immutable financial transaction logs:
```bash
curl -X GET "https://console.vexasec.io/api/v2/spend/events?limit=50" \
  -H "Authorization: Bearer <ADMIN_OIDC_TOKEN>"
```

---

## 6. Fleet Device Governance & Sentry Auto-Enforcement

### 1. Monitoring Developer Workstations
View the real-time compliance status of all developer machines:
```bash
curl -X GET https://console.vexasec.io/api/v1/devices \
  -H "Cookie: agentcontrol_session=<SESSION_COOKIE>"
```

### 2. Investigating Configuration Tampering Incidents
Inspect the forensic tamper and self-healing log:
```bash
curl -X GET https://console.vexasec.io/api/v1/devices/tamper-log \
  -H "Cookie: agentcontrol_session=<SESSION_COOKIE>"
```
Any developer attempt to clear `cursor.models.openaiBaseUrl` or point IDEs directly to public AI endpoints is automatically healed in $<500\text{ ms}$ and permanently recorded with event type `AUTO_HEALED` or `CONFIG_TAMPERED`.

---

## 7. Multi-Tenant Onboarding & Automated License Minting

The SaaS Operator interface (`/operator/tenants`) automates tenant onboarding, free trials, and license key generation using Ed25519 signing keys from GCP Secret Manager.

### 1. Secret Manager Key Setup (One-Time Infra Task)
```bash
# Store Ed25519 private signing seed in GCP Secret Manager
gcloud secrets create vexa-prod-license-signing-key \
  --project="vexa-prod" \
  --replication-policy="automatic"

echo -n "<64-hex-char-private-seed>" | gcloud secrets versions add vexa-prod-license-signing-key \
  --project="vexa-prod" \
  --data-file=-
```

### 2. Provisioning Tenant Orgs via Operator API
```bash
# Provision 15-day Free Trial
curl -X POST https://console.vexasec.io/api/v1/operator/organizations \
  -H "Cookie: agentcontrol_session=<OPERATOR_COOKIE>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Acme Health",
    "slug": "acme-health",
    "contact_email": "admin@acmehealth.com",
    "license_tier": "enterprise",
    "max_seats": 50,
    "is_trial": true,
    "trial_days": 15
  }'
```

### 3. Extending Trials or Renewing Annual Contracts
```bash
# Renew for 365 days
curl -X POST https://console.vexasec.io/api/v1/operator/organizations/<ORG_ID>/renew-license \
  -H "Cookie: agentcontrol_session=<OPERATOR_COOKIE>" \
  -H "Content-Type: application/json" \
  -d '{
    "additional_days": 365,
    "is_trial": false
  }'
```
