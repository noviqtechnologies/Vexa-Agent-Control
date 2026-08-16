# SaaS Operator & Platform Administration Guide

## 1. Overview
The **Vexa Agent Control SaaS Platform** is a multi-tenant security operations center for governing AI agent tool calls, data leakage, and compute spend. 

This guide details operational workflows for **Platform Operators / Super-Admins** responsible for tenant provisioning, trial management, automated licensing, and platform health.

---

## 2. Platform Architecture & Multi-Tenancy

```
                              Edge Load Balancer (ALB)
                                 console.vexasec.io
                                        │
           ┌────────────────────────────┼────────────────────────────┐
           ▼                            ▼                            ▼
    [ SaaS Operator ]          [ Tenant Org: Acme ]        [ Tenant Org: Globex ]
     /operator/tenants          Unified Auth Token          Unified Auth Token
           │                            │                            │
           └────────────────────────────┼────────────────────────────┘
                                        ▼
                           [ Pooled Cloud Run Services ]
                                        │
                                        ▼
                       [ Multi-Tenant Cloud SQL Database ]
                       (Every row scoped by tenant_id UUID)
```

### Key Principles:
- **No Resource Sprawl:** All tenants share the same high-availability Cloud Run microservices and PostgreSQL database.
- **Data Isolation:** Every database table uses `tenant_id` foreign keys and composite indexes (`tenant_id, ...`).
- **Zero-Trust BYOK:** SaaS Operators do **not** configure or store customer LLM keys. Customers own their keys and enter them inside their private tenant console.

---

## 3. Onboarding a New Organization

### Step 1: Access Operator Console
1. Navigate to `https://console.vexasec.io` (or local development: `http://localhost:8081`).
2. Log in with your platform super-admin account (`SAAS_OPERATOR_EMAIL`).
3. In the sidebar, select **Platform Operations ➔ Tenant Onboarding**.

### Step 2: Provision Organization
Click **Onboard Organization** and configure:
1. **Organization Name:** e.g., `Acme Healthcare`.
2. **Tenant Slug:** e.g., `acme-health` (unique tenant identifier).
3. **Admin Email:** Primary IT / Security contact (e.g., `sec-admin@acmehealth.com`).
4. **License Plan:**
   - **15-Day Free Trial:** Zero setup trial with full enterprise governance.
   - **30-Day Free Trial:** Extended evaluation for enterprise POCs.
   - **Paid Contract:** Custom agreed duration (e.g., 365 days / 1 year).
5. **License Tier:** `Enterprise` (DLP + Spend + Device Control), `Team`, or `Community`.
6. **Max Seat Allocation:** Number of workstation agents allowed.

Click **Provision Organization**.

### Step 3: Secure Handoff Credentials
Upon creation, the system auto-mints an Ed25519-signed license JWT and displays:
- **Customer Console URL:** `https://console.vexasec.io`
- **Single-Use Bootstrap Token:** One-time password for the customer administrator.
- **Gateway Secret:** For centralized proxy telemetry.
- **Policy Read Secret:** For gateway dynamic rule subscriptions.

> [!IMPORTANT]
> Copy the **Bootstrap Token** and send it via secure channel to the customer admin. The token is stored as a SHA-256 hash and cannot be recovered after leaving the screen.

---

## 4. Managing Trials & License Renewals

### Extending a Trial or Renewing a Contract
1. In the **Tenant Organizations Directory**, find the organization.
2. Click **Extend / Renew**.
3. Select the extension duration (e.g., `+15 days` or `+365 days`).
4. Click **Mint & Apply Extension**. The platform automatically updates the database and signs a fresh JWT in memory.

### Suspending a Compromised Tenant
Click **Suspend** on the tenant row. All subsequent gateway queries, logins, and policy pushes for that `tenant_id` will be immediately rejected with `403 Forbidden`.

### Regenerating Bootstrap Access
If a customer admin lost their setup token before initial login:
1. Click **New Token** on the tenant row.
2. A fresh single-use token will be generated, resetting `bootstrap_consumed_at`.

---

## 5. API Reference for Operators

```bash
# 1. List all tenants
curl -X GET https://console.vexasec.io/api/v1/operator/organizations \
  -H "Cookie: agentwall_session=<OPERATOR_COOKIE>"

# 2. Onboard tenant via API
curl -X POST https://console.vexasec.io/api/v1/operator/organizations \
  -H "Cookie: agentwall_session=<OPERATOR_COOKIE>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Globex Corp",
    "slug": "globex",
    "contact_email": "admin@globex.com",
    "license_tier": "enterprise",
    "max_seats": 50,
    "is_trial": true,
    "trial_days": 30
  }'

# 3. Platform Health & Aggregate KPIs
curl -X GET https://console.vexasec.io/api/v1/operator/stats \
  -H "Cookie: agentwall_session=<OPERATOR_COOKIE>"
```
