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
gcloud secrets create vexa-license-signing-key \
  --project="<YOUR_GCP_PROJECT_ID>" \
  --replication-policy="automatic"

echo -n "<64-hex-char-private-seed>" | gcloud secrets versions add vexa-license-signing-key \
  --project="<YOUR_GCP_PROJECT_ID>" \
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

---

## 8. Host-Bound Emergency Break-Glass Recovery

When IdP misconfigurations, certificate expirations, or third-party outages lock administrators out of the Control Hub, operators can generate a single-use break-glass token directly on the server or container host.

### 1. Generating the Break-Glass Token
Execute on the Control Hub server or within the Docker container:
```bash
agentcontrol-admin break-glass --org-id 00000000-0000-0000-0000-000000000001 --email admin@agentcontrol.local
```

**Output:**
```text
✔ Emergency Break-Glass Token Generated
────────────────────────────────────────────────────────────────────────
  Organization ID: 00000000-0000-0000-0000-000000000001
  Target Admin:    admin@agentcontrol.local
  Recovery Token:  bg_dGVzdF9icmVha19nbGFzc190b2tlbg
  Redemption URL:  http://127.0.0.1:8081/break-glass
  Validity:        15 minutes (Single-Use Only)
────────────────────────────────────────────────────────────────────────
⚠ WARNING: Redeeming this token will grant emergency owner access.
```

### 2. Redeeming the Token
1. Open `http://<hub-url>/break-glass` in your browser.
2. Enter the recovery token (`bg_...`) and submit.
3. Upon redemption, all previous tenant sessions are invalidated and an emergency Owner session is issued.

---

## 9. OIDC Provider Diagnostic Probing

Verify provider connectivity, discovery metadata, and JWKS key retrieval in real time:

```bash
curl -X POST https://console.vexasec.io/api/v1/auth/providers/<PROVIDER_ID>/test \
  -H "Authorization: Bearer <ADMIN_SESSION_TOKEN>"
```

---

## 10. Route Profile Lifecycle (Draft, Simulate, Activate, Rollback)

Vexa Agent Control enforces an immutable configuration lifecycle for centrally brokered LLM traffic.

### 1. Creating a Candidate Route Profile
```bash
curl -X POST https://console.vexasec.io/api/v1/routes \
  -H "Authorization: Bearer <ADMIN_OIDC_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production Frontier Route",
    "api_family": "chat_completions",
    "match_model": "gpt-*",
    "primary_provider": "openai",
    "primary_model": "gpt-4o",
    "fallback_provider": "anthropic",
    "fallback_model": "claude-3-5-sonnet",
    "max_attempts": 2,
    "deadline_ms": 30000,
    "retry_classes": ["502", "503", "504", "429", "connect_timeout", "dns_error"],
    "allowed_regions": ["*"]
  }'
```

### 2. Simulating Against Synthetic Fixtures (Dry Run)
Validate match behavior, region enforcement, and fallback eligibility before activation:
```bash
curl -X POST https://console.vexasec.io/api/v1/routes/simulate \
  -H "Authorization: Bearer <ADMIN_OIDC_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "profile": {
      "name": "Production Frontier Route",
      "api_family": "chat_completions",
      "match_model": "gpt-*",
      "primary_provider": "openai",
      "primary_model": "gpt-4o",
      "fallback_provider": "anthropic",
      "fallback_model": "claude-3-5-sonnet",
      "max_attempts": 2,
      "deadline_ms": 30000
    }
  }'
```

### 3. Activating a Route Profile
Atomic activation deactivates competing profiles and broadcasts an SSE notification to all connected gateways within **30 seconds**:
```bash
curl -X POST https://console.vexasec.io/api/v1/routes/<ROUTE_PROFILE_ID>/activate \
  -H "Authorization: Bearer <ADMIN_OIDC_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"reason": "Promoting candidate v2 to production"}'
```

### 4. Zero-Downtime Rollback
Restore a previous known-good route version without restarting containers:
```bash
curl -X POST https://console.vexasec.io/api/v1/routes/<PREVIOUS_PROFILE_ID>/rollback \
  -H "Authorization: Bearer <ADMIN_OIDC_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"reason": "Emergency rollback due to upstream provider rate limits"}'
```

---

## 11. Request Dossier Inspection & Forensic Tracing

Investigate why a request failed or retried, inspect ordered attempt timelines, spend reservation lifecycle, and W3C trace correlation:

```bash
curl -X GET https://console.vexasec.io/api/v1/observability/request-logs/req-1727954000/dossier \
  -H "Authorization: Bearer <ADMIN_OIDC_TOKEN>"
```

**Sample Output:**
```json
{
  "request": {
    "request_id": "req-1727954000",
    "status": "succeeded",
    "requested_provider": "openai",
    "requested_model": "gpt-4o",
    "settled_microcents": 37000
  },
  "route_decision": {
    "selected_primary": "openai/gpt-4o",
    "selected_fallback": "anthropic/claude-3-5-sonnet",
    "candidate_reasons": {
      "openai/gpt-4o": "candidate_selected",
      "anthropic/claude-3-5-sonnet": "fallback_candidate_eligible"
    }
  },
  "attempts": [
    {
      "attempt_number": 1,
      "target_type": "primary",
      "provider": "openai",
      "model": "gpt-4o",
      "http_status": 503,
      "error_class": "server_5xx",
      "latency_ms": 320
    },
    {
      "attempt_number": 2,
      "target_type": "fallback",
      "provider": "anthropic",
      "model": "claude-3-5-sonnet",
      "http_status": 200,
      "input_tokens": 25,
      "output_tokens": 12,
      "latency_ms": 610
    }
  ],
  "total_latency_ms": 930
}
```

---

## 12. Multi-Factor Readiness Diagnostics (`/readyz`)

The `/readyz` probe validates all core components required to serve centrally brokered traffic:

```bash
curl -i https://console.vexasec.io/readyz
```

**Expected Response (HTTP 200):**
```json
{
  "status": "ready",
  "checks": {
    "database": "ok",
    "spend_engine": "ok",
    "route_engine": "ok",
    "audit_spool": "ok"
  },
  "timestamp": "2026-10-03T13:20:00Z"
}
```

### Degraded Component Matrix & Remediation:
* **`database: unreachable`**: Check PostgreSQL connection pool and firewall rules.
* **`spend_engine: uninitialized`**: Verify spend database migration status.
* **`audit_spool: full`**: Check disk capacity and SIEM exporter connectivity (Splunk / Datadog).

---

## 13. Signed Cryptographic Policy Distribution

Vexa Agent Control v4.0 supports central distribution of Ed25519 cryptographically signed policy bundles from the Team Hub to all deployed gateway daemons.

### 13.1 Key Generation & Storage
Operators generate 32-byte Ed25519 signing keys stored in secure HSM / KMS:
```bash
agentwall generate-keypair --out-priv secops_signing.key --out-pub secops_signing.pub
```
Fleet gateways configure `trusted_public_keys` in `agentwall.toml`:
```toml
[policy.distribution]
trusted_public_keys = [
  "e4d909c290d0fb1ca068ffaddf22cbd0a...32byte_hex..."
]
auto_rollback_on_health_failure = true
```

### 13.2 Minting & Distributing Signed Bundles
```bash
agentwall sign-policy \
  --key secops_signing.key \
  --policy /etc/agentcontrol/policies/corp-sec-v2.yaml \
  --policy-id "corp-sec-global" \
  --revision 4 \
  --expires-in-hours 168 \
  --out /var/dist/corp-sec-bundle-rev4.json
```

### 13.3 Gateway Invariants & Automatic Rollback
Upon receiving a bundle via WebSocket, SSE, or local API (`POST /api/v1/policy/apply-signed`):
1. **Signature Verification**: Validates Ed25519 signature against `canonical_sign_bytes(policy_id, revision, policy_yaml)`.
2. **Key Pinning**: Rejects any signer key not explicitly present in `trusted_public_keys`.
3. **Dry-Run Compilation**: Compiles the candidate YAML. If compilation fails (e.g. malformed regex, invalid schema, missing `default_action`), rejects immediately with 0 downtime.
4. **Atomic Swap & Snapshot**: Snapshots current policy to `policy.yaml.rollback` before atomic file replacement.
5. **Instant Rollback**: If post-switchover health checks fail or an operator triggers `agentwall rollback-policy`, the gateway reverts to `policy.yaml.rollback` in <10ms.

---

## 14. Real-Time Capability Revocation List (CRL) Broadcast

When an agent token, model key, or tool credential is leak-compromised, CRL broadcast propagates revocation to all active gateways in under 30 seconds.

### 14.1 Emergency Capability Revocation API
```bash
curl -X POST https://console.vexasec.io/api/v2/admin/revocations \
  -H "Authorization: Bearer <ADMIN_OIDC_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "finance-analyst-agent-07",
    "tool_id": "transfer_funds",
    "token_id": "tok-98a2f1b0",
    "reason": "Suspicious exfiltration activity detected by SIEM",
    "ttl_seconds": 86400
  }'
```

### 14.2 Inspecting Local Gateway Revocation Table
```bash
curl -H "Authorization: Bearer $(cat /run/agentcontrol/token)" \
  http://127.0.0.1:18080/api/v1/revocations
```
**Response (HTTP 200):**
```json
{
  "active_revocations": [
    {
      "revocation_id": "rev-0198d5e1",
      "agent_id": "finance-analyst-agent-07",
      "tool_id": "transfer_funds",
      "revoked_at": "2026-10-05T08:00:00Z",
      "expires_at": "2026-10-06T08:00:00Z",
      "reason": "Suspicious exfiltration activity detected by SIEM"
    }
  ]
}
```

---

## 15. Distributed Tracing & OpenTelemetry (OTLP) Export

Agent Control captures end-to-end execution traces conforming to W3C TraceContext specifications (`traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01`).

### 15.1 Real-Time Streaming to OTLP Collectors
Configure direct OTLP gRPC / HTTP push in `agentcontrol.toml`:
```toml
[telemetry.otlp]
enabled = true
collector_endpoint = "http://otel-collector.corp.internal:4318/v1/traces"
export_batch_size = 50
export_timeout_secs = 5
protocol = "http_json"
```

### 15.2 Forensic Trace Export via CLI
Export historical traces locally for audits, forensics, or CI replay evaluation:
```bash
# JSONL format (streaming-friendly for jq and grep)
agentwall export-traces --format jsonl --limit 5000 --output ./traces-20261005.jsonl

# OTLP format to upstream collector
agentwall export-traces --format otlp --collector "http://localhost:4318/v1/traces" --limit 500
```

---

## 16. Disaster Recovery & Automated Backup / Restore Verification

To protect against filesystem corruption, accidental deletion, or catastrophic node loss, Agent Control features a cryptographic disaster recovery subsystem.

### 16.1 Generating an Encrypted Snapshot Archive
```bash
agentwall backup \
  --target-dir /var/agentcontrol \
  --output /var/backups/agentcontrol-backup-$(date +%Y%m%d).json \
  --include policy.yaml,audit.jsonl,config.toml
```
The backup creates an archive binding SHA-256 digests of every file and an aggregate manifest hash.

### 16.2 Restoring from Backup Archive
```bash
agentwall restore \
  --archive /var/backups/agentcontrol-backup-20261005.json \
  --destination /var/agentcontrol \
  --verify-audit-chain
```

### 16.3 Pre-Activation Verification Checks
During restoration, the recovery engine guarantees:
1. **Manifest Integrity**: Recomputed SHA-256 for all restored files must exactly equal the archive manifest digest.
2. **HMAC Chain Continuity**: Automatically verifies restored audit logs (`verify_chain`). If any entry has tampered bytes, broken parent linkages, or skipped sequences, the restore aborts with `AuditVerificationFailed` before overwriting live disk state.

---

## 17. Multi-Provider Failover & Circuit Breaker Tuning

Agent Control safeguards mission-critical agent workflows against upstream cloud outages via active circuit breaking and multi-region/multi-provider failover.

### 17.1 Circuit Breaker Topology
Each registered provider deployment tracks consecutive 5xx errors and connection drop events:
* **Failure Threshold**: Configured via `failure_threshold` (default: 5 consecutive failures).
* **Cooldown Period**: Configured via `cooldown_period_secs` (default: 30 seconds).
* **Half-Open Probing**: Once the cooldown expires, a single probe request is permitted through. A successful response immediately clears the error count and restores the deployment to active rotation.

### 17.2 Deployment Configuration (`agentcontrol.toml`)
```toml
[routing]
strategy = "priority" # "priority" | "lowest_latency" | "weighted" | "region_affinity"

[[routing.deployments]]
id = "openai-us-east"
provider = "openai"
model_name = "gpt-4o"
endpoint_url = "https://api.openai.com/v1/chat/completions"
priority = 1
weight = 100
region = "us-east-1"

[[routing.deployments]]
id = "anthropic-us-east"
provider = "anthropic"
model_name = "claude-3-5-sonnet"
endpoint_url = "https://api.anthropic.com/v1/messages"
priority = 2
weight = 100
region = "us-east-1"
```

---

## 18. Idempotency-Aware Retries & Uncertainty Containment

To prevent double execution of financial transactions, destructive file modifications, or external side effects, retry logic enforces strict idempotency boundaries.

### 18.1 Classification Matrix
| Tool Type | Error Class | Retry Action | Rationale |
|---|---|---|---|
| **Idempotent** (`read_file`, `get_*`) | 502, 503, 504, Timeout | Automatic Retry (exp. backoff) | Side-effect free; safe to retry. |
| **Non-Idempotent** (`delete_*`, `transfer_*`) | 502, 503, 504, Drop | Flag `OUTCOME_UNKNOWN` | Ambiguous connection loss; mutation may have occurred. |
| **Any Tool** | Partial SSE stream chunk committed | Strict Abort | Partial bytes delivered to agent; retry causes protocol corruption. |
| **Any Tool** | 400, 401, 403, 404 | Strict Abort | Permanent client/credential error; retry will not succeed. |

### 18.2 Resolving `OUTCOME_UNKNOWN` Tool Events
When a network drop occurs during non-idempotent tool execution, the HITL engine halts the agent turn and requires manual resolution:
```bash
# Query pending uncertain actions
curl -H "Authorization: Bearer <TOKEN>" http://127.0.0.1:18080/api/v1/hitl/uncertain

# Mark resolved after forensic check
curl -X POST http://127.0.0.1:18080/api/v1/hitl/resolve-uncertain \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "request_id": "req-1727954000",
    "action": "ABORT_RETRY",
    "reason": "Verified funds were already debited upstream"
  }'
```

---

## 19. Scoped Semantic Cache Partitioning & Multi-Tenant Isolation

The enterprise semantic caching engine provides sub-3ms responses while enforcing strict cryptographic and contextual boundaries.

### 19.1 Isolation Invariants
Cache keys are cryptographically generated using SHA-256 over a `CanonicalContext` that binds:
```
SHA-256(tenant_id : subject_id : virtual_key_scope : prompt_sha256 : policy_version : temperature_fixed : model)
```
* **Tenant Isolation**: Identical queries executed under different tenants produce distinct hashes. Zero cross-tenant cache leakage is guaranteed.
* **Policy Isolation**: Modifying or redeploying security policies immediately partitions cache lookups; cached responses never bypass newly introduced policy restrictions.

### 19.2 Cache Bypass Safeguards
A request strictly bypasses semantic caching if:
1. It contains `tools`, `functions`, or parallel tool choice specifications.
2. It represents a multi-turn conversation with prior tool execution history.
3. The prompt contains imperative mutating verbs (`delete`, `drop`, `insert`, `transfer`, `pay`, `write`).
4. `temperature` is non-zero (non-deterministic responses).

---

## 20. Cost Ledgers, Rate Cards & Microcent Spend Auditing

Agent Control tracks exact token usage and financial spend with integer microcent precision ($0.00000001 USD), eliminating floating-point rounding errors.

### 20.1 Querying Real-Time Spend Ledgers
```bash
# Get aggregate spend for an agent
curl -H "Authorization: Bearer <TOKEN>" \
  http://127.0.0.1:18080/api/v1/spend/agents/finance-agent-01

# Export detailed usage attribution ledger (CSV / JSON)
agentwall export-spend \
  --client "fintech-corp-client" \
  --project "fraud-detection-model" \
  --format json \
  --output ./spend-attribution-oct2026.json
```

### 20.2 Rate Card Overrides
Deploy custom contractual rates by placing `pricing.toml` in `/etc/agentcontrol/`:
```toml
version = "2026-10-custom"

[models."gpt-4o"]
input_per_1m_cents = 250
output_per_1m_cents = 1000

[models."claude-3-5-sonnet"]
input_per_1m_cents = 300
output_per_1m_cents = 1500

[fallback]
input_per_1m_cents = 500
output_per_1m_cents = 2000
```




