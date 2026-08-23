# Spend & Budgets — End-to-End Testing Guide (Windows Local)

> **Prerequisites**: Laptop registered, Windows Sentry service running, Control Hub at `https://console.vexasec.io/`

---

## Architecture Overview

```
┌──────────────────────┐      ┌───────────────────────┐      ┌──────────────────────────┐
│   IDE  (Any IDE)     │      │  AgentControl Gateway  │      │  Control Hub (Cloud)      │
│  Claude / Cursor /   │─────►│  127.0.0.1:8080        │─────►│  console.vexasec.io       │
│  VS Code / AGY       │      │  Local Proxy + Ledger  │      │  PostgreSQL V2 Ledger     │
└──────────────────────┘      └───────────────────────┘      └──────────────────────────┘
                                      │                               │
                              Local SQLite                   Budget Windows
                              ~/.agentcontrol/events.db      Reservations
                              (Legacy observational)         Settlement Events
                                                             Spend Policies
                                                             Increase Requests
```

There are **two spend layers** in AgentControl:

| Layer | Database | Purpose | Authority |
|---|---|---|---|
| **Local Ledger (Legacy)** | SQLite at `~/.agentcontrol/events.db` | Observational telemetry, per-agent daily caps | Read-only local mirror |
| **Central V2 Ledger** | PostgreSQL via Control Plane API | Preflight reservations, settlements, policy enforcement | **Authoritative** |

---

## Phase 1: Verify Prerequisites

### 1.1 Confirm Windows Sentry Is Running

```powershell
# Check the Sentry service status
Get-Service -Name "VexaAgentControl*" -ErrorAction SilentlyContinue
# Or check for the process
Get-Process -Name "agentcontrol*" -ErrorAction SilentlyContinue
```

You should see the Sentry daemon active. If it's not running, start it manually:

```powershell
# Start from the project directory
cd C:\AgentWall\agentwall
.\target\debug\agentcontrol.exe sentry start
```

### 1.2 Confirm Control Plane Is Accessible

```powershell
# Health check
Invoke-RestMethod -Uri "https://console.vexasec.io/health" -Method Get

# Verify V2 spend endpoints are alive
Invoke-RestMethod -Uri "https://console.vexasec.io/api/v2/spend/effective" -Method Get
Invoke-RestMethod -Uri "https://console.vexasec.io/api/v2/spend/policies" -Method Get
```

> [!NOTE]
> The Control Hub is cloud-hosted at `https://console.vexasec.io/`. No local Docker setup needed for the Control Plane.
> Ensure your gateway is configured to sync with this URL.

### 1.3 Confirm the Gateway Is Running

```powershell
# Check if the gateway proxy is listening
Test-NetConnection -ComputerName "127.0.0.1" -Port 8080
```

If not running, start it:

```powershell
cd C:\AgentWall\agentwall
$env:OPENAI_API_KEY = "sk-proj-YOUR-KEY-HERE"   # or Anthropic key
.\target\debug\agentcontrol.exe start --listen 127.0.0.1:8080 --policy test-llm-policy.yaml
```

### 1.4 Verify Local SQLite Database Exists

```powershell
Test-Path "$env:USERPROFILE\.agentcontrol\events.db"
```

This database is auto-created the first time the gateway starts and initializes the spend ledger.

---

## Phase 2: Create a Spend Policy (Budget)

This step creates an **authoritative budget** via the Control Plane's PostgreSQL V2 API.

### 2.1 Create an Organization-Level Daily Budget ($5.00/day)

```powershell
$body = @{
    scope_type  = "organization"
    scope_id    = "global"
    period_type = "daily"
    limit_usd   = 5.00
    action      = "hard_deny"
} | ConvertTo-Json

Invoke-RestMethod `
    -Uri "https://console.vexasec.io/api/v2/spend/policies" `
    -Method Post `
    -Body $body `
    -ContentType "application/json"
```

**Expected Response**:
```json
{
  "status": "created_and_published",
  "policy": {
    "policy_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "scope_type": "organization",
    "scope_id": "global",
    "currency": "USD",
    "period_type": "daily",
    "limit_microcents": 500000000,
    "action": "hard_deny",
    "status": "PUBLISHED"
  },
  "policy_version": { ... }
}
```

> [!IMPORTANT]
> **$5.00 USD = 500,000,000 microcents**. The system uses integer microcents ($1.00 = 100,000,000 µ¢) to prevent floating-point rounding errors.

### 2.2 Create a Project-Level Budget ($2.00/day)

```powershell
$body = @{
    scope_type  = "project"
    scope_id    = "proj_alpha"
    period_type = "daily"
    limit_usd   = 2.00
    action      = "hard_deny"
} | ConvertTo-Json

Invoke-RestMethod `
    -Uri "https://console.vexasec.io/api/v2/spend/policies" `
    -Method Post `
    -Body $body `
    -ContentType "application/json"
```

### 2.3 Verify Policies Were Created

```powershell
Invoke-RestMethod -Uri "https://console.vexasec.io/api/v2/spend/policies" -Method Get
```

You should see both policies listed with `status: "PUBLISHED"`.

---

## Phase 3: Test Preflight Authorization (Spend Check Before LLM Call)

This simulates what the gateway does before forwarding an LLM prompt to a provider.

### 3.1 Authorize a Request (Within Budget)

```powershell
$authBody = @{
    gateway_id          = "win-dev-gateway"
    request_id          = "test-req-001"
    idempotency_key     = "idem-001"
    project_id          = "proj_alpha"
    provider            = "openai"
    model               = "gpt-4o"
    input_token_estimate = 500
    max_output_tokens    = 1000
    request_hash         = "hash001"
} | ConvertTo-Json

$authResp = Invoke-RestMethod `
    -Uri "https://console.vexasec.io/api/v2/spend/authorize" `
    -Method Post `
    -Body $authBody `
    -ContentType "application/json"

$authResp | ConvertTo-Json -Depth 5
```

**Expected**: `decision: "allow"`, `reservation_id` present, `reserved_microcents` shows the pre-calculated cost.

### 3.2 Verify the Budget Window Updated

```powershell
$windows = Invoke-RestMethod -Uri "https://console.vexasec.io/api/v2/spend/effective" -Method Get
$windows.windows | Format-Table scope_type, scope_id, limit_microcents, reserved_microcents, settled_microcents, available_microcents
```

You should see `reserved_microcents` increased by the reservation amount.

---

## Phase 4: Settle After LLM Response (Record Actual Usage)

After the LLM provider returns tokens, the gateway settles the reservation with actual usage.

### 4.1 Settle the Reservation

```powershell
$reservationId = $authResp.reservation_id   # from Phase 3

$settleBody = @{
    request_id          = "test-req-001"
    idempotency_key     = "settle-001"
    provider_request_id = "chatcmpl-abc123"
    input_tokens        = 480
    output_tokens       = 750
    cached_input_tokens = 0
    is_estimated        = $false
    status              = 200
    request_hash        = "hash001"
} | ConvertTo-Json

Invoke-RestMethod `
    -Uri "https://console.vexasec.io/api/v2/spend/reservations/$reservationId/settle" `
    -Method Post `
    -Body $settleBody `
    -ContentType "application/json"
```

**Expected**: `status: "settled"`, `settled_microcents` shows actual cost, `released_microcents` shows any excess reservation returned.

### 4.2 Check the Budget Window Again

```powershell
$windows = Invoke-RestMethod -Uri "https://console.vexasec.io/api/v2/spend/effective" -Method Get
$windows.windows | Format-Table scope_type, scope_id, reserved_microcents, settled_microcents, available_microcents
```

`reserved_microcents` should decrease, `settled_microcents` should increase.

---

## Phase 5: Test Budget Exhaustion (Hard Deny)

### 5.1 Create a Tiny Budget ($0.01/day)

```powershell
$body = @{
    scope_type  = "project"
    scope_id    = "proj_tiny"
    period_type = "daily"
    limit_usd   = 0.01
    action      = "hard_deny"
} | ConvertTo-Json

Invoke-RestMethod `
    -Uri "https://console.vexasec.io/api/v2/spend/policies" `
    -Method Post `
    -Body $body `
    -ContentType "application/json"
```

### 5.2 Try to Authorize a Large Request (Expect Denial)

```powershell
$bigReqBody = @{
    gateway_id          = "win-dev-gateway"
    request_id          = "test-req-big"
    idempotency_key     = "idem-big"
    project_id          = "proj_tiny"
    provider            = "openai"
    model               = "gpt-4o"
    input_token_estimate = 10000
    max_output_tokens    = 4000
    request_hash         = "hashbig"
} | ConvertTo-Json

try {
    Invoke-RestMethod `
        -Uri "https://console.vexasec.io/api/v2/spend/authorize" `
        -Method Post `
        -Body $bigReqBody `
        -ContentType "application/json"
} catch {
    Write-Host "✅ BUDGET EXHAUSTED: Request denied with HTTP 429" -ForegroundColor Green
    $_.Exception.Response.StatusCode
}
```

**Expected**: HTTP 429 response with `decision: "deny"`, `reason_code: "spend_budget_exhausted"`.

---

## Phase 6: Test Release (Cancel Unused Reservation)

If a request fails or is aborted before the LLM response arrives, the reservation should be released.

### 6.1 Create a New Reservation

```powershell
$authBody2 = @{
    gateway_id          = "win-dev-gateway"
    request_id          = "test-req-cancel"
    idempotency_key     = "idem-cancel"
    project_id          = "proj_alpha"
    provider            = "anthropic"
    model               = "claude-3-5-sonnet-20240620"
    input_token_estimate = 1000
    max_output_tokens    = 2000
    request_hash         = "hashcancel"
} | ConvertTo-Json

$authResp2 = Invoke-RestMethod `
    -Uri "https://console.vexasec.io/api/v2/spend/authorize" `
    -Method Post `
    -Body $authBody2 `
    -ContentType "application/json"

Write-Host "Reservation ID: $($authResp2.reservation_id)"
```

### 6.2 Release the Reservation

```powershell
$releaseBody = @{
    request_id      = "test-req-cancel"
    idempotency_key = "release-cancel"
    reason          = "upstream_timeout"
    request_hash    = "hashcancel"
} | ConvertTo-Json

$reservationId2 = $authResp2.reservation_id

Invoke-RestMethod `
    -Uri "https://console.vexasec.io/api/v2/spend/reservations/$reservationId2/release" `
    -Method Post `
    -Body $releaseBody `
    -ContentType "application/json"
```

**Expected**: `status: "released"`, `released_microcents` restores the funds to the budget window.

---

## Phase 7: Test Budget Increase Request (End User → Admin Workflow)

### 7.1 Submit an Increase Request (as End User)

```powershell
$increaseBody = @{
    project_id           = "proj_alpha"
    requested_limit_usd  = 50.00
    current_limit_microcents = 0
    reason               = "Sprint deadline requires higher LLM throughput for code generation workloads"
} | ConvertTo-Json

$increaseResp = Invoke-RestMethod `
    -Uri "https://console.vexasec.io/api/v2/spend/increase-requests" `
    -Method Post `
    -Body $increaseBody `
    -ContentType "application/json"

Write-Host "Request ID: $($increaseResp.request_id), Status: $($increaseResp.status)"
```

**Expected**: `status: "PENDING"`, `request_id` returned.

### 7.2 List All Increase Requests (as Admin)

```powershell
$requests = Invoke-RestMethod -Uri "https://console.vexasec.io/api/v2/spend/increase-requests" -Method Get
$requests.requests | Format-Table request_id, project_id, status, reason -AutoSize
```

### 7.3 Approve the Increase Request (as Admin)

```powershell
$requestId = $increaseResp.request_id

$decideBody = @{
    decision = "APPROVED"
    reason   = "Sprint deadline approved by engineering manager"
} | ConvertTo-Json

Invoke-RestMethod `
    -Uri "http://localhost:8400/api/v2/spend/increase-requests/$requestId/decide" `
    -Method Post `
    -Body $decideBody `
    -ContentType "application/json"
```

### 7.4 Verify the Request Was Resolved

```powershell
$requests = Invoke-RestMethod -Uri "http://localhost:8400/api/v2/spend/increase-requests" -Method Get
$requests.requests | Where-Object { $_.request_id -eq $requestId } | Format-List
```

**Expected**: `status: "APPROVED"`, `decided_by` populated.

### 7.5 Test Rejection Too

```powershell
$increaseBody2 = @{
    project_id           = "proj_rogue"
    requested_limit_usd  = 10000.00
    current_limit_microcents = 0
    reason               = "Need unlimited budget for personal experiments"
} | ConvertTo-Json

$increaseResp2 = Invoke-RestMethod `
    -Uri "http://localhost:8400/api/v2/spend/increase-requests" `
    -Method Post `
    -Body $increaseBody2 `
    -ContentType "application/json"

$decideBody2 = @{
    decision = "REJECTED"
    reason   = "Request exceeds organizational spending policy. Contact finance for exception."
} | ConvertTo-Json

Invoke-RestMethod `
    -Uri "http://localhost:8400/api/v2/spend/increase-requests/$($increaseResp2.request_id)/decide" `
    -Method Post `
    -Body $decideBody2 `
    -ContentType "application/json"
```

---

## Phase 8: View Spend Event Audit Log

### 8.1 List All Immutable Spend Events

```powershell
$events = Invoke-RestMethod -Uri "http://localhost:8400/api/v2/spend/events?limit=50" -Method Get
$events.events | Format-Table event_type, amount_microcents, actor, reason_code, occurred_at -AutoSize
```

Each event is an **immutable append-only ledger entry**. Event types you'll see:

| Event Type | Meaning |
|---|---|
| `AUTHORIZED` | Preflight reservation created |
| `SETTLED` | Actual usage recorded after LLM response |
| `RELEASED` | Unused reservation returned |
| `REVERSED` | Admin reversal / correction |

---

## Phase 9: Test with a Real IDE (Claude Desktop / Cursor / VS Code)

Now that you've validated the API layer directly, test end-to-end with an actual IDE.

### 9.1 Enable Spend Caps in Your Policy

Add a `spend_caps` block to your active policy file. For example, edit [test-llm-policy.yaml](file:///c:/AgentWall/agentwall/test-llm-policy.yaml):

```yaml
version: "2"
default_action: deny

spend_caps:
  enabled: true
  admin_api: true
  concurrency_ceiling: 50
  max_tokens_per_session: 100000

session:
  max_calls_per_second: 10

llm:
  providers:
    - name: "anthropic"
      action: "allow"
      models:
        - "claude*"
    - name: "openai"
      action: "allow"
      models:
        - "gpt*"
        - "o1*"
        - "o3*"
        - "*"
  dlp:
    actions:
      - entity: "CREDIT_CARD"
        action: "deny"
      - entity: "SSN"
        action: "deny"

tools:
  - name: "read_file"
    action: allow
    parameters:
      - name: "path"
        type: string
        required: true
```

### 9.2 Restart the Gateway with the Updated Policy

```powershell
cd C:\AgentWall\agentwall

# Stop existing gateway
Stop-Process -Name "agentcontrol" -Force -ErrorAction SilentlyContinue

# Restart with spend-enabled policy
.\target\debug\agentcontrol.exe start --listen 127.0.0.1:8080 --policy test-llm-policy.yaml
```

### 9.3 Make LLM Calls From Your IDE

1. Open **Claude Desktop**, **Cursor**, **VS Code Copilot**, or **Antigravity IDE**
2. Ensure the IDE is configured to route through the AgentControl proxy at `127.0.0.1:8080`
3. Send a normal coding prompt (e.g., "Explain how async works in Rust")
4. The gateway will:
   - **Pre-authorize** the estimated token cost against your budget
   - **Forward** the request to the LLM provider
   - **Settle** the actual token usage after the response arrives
   - **Sync** the local SQLite telemetry to the Control Plane every 60 seconds

### 9.4 Monitor in Real-Time

While the IDE is generating responses, watch the spend counters:

```powershell
# Watch budget windows update in real-time
while ($true) {
    Clear-Host
    $w = Invoke-RestMethod -Uri "http://localhost:8400/api/v2/spend/effective" -Method Get
    Write-Host "=== Budget Windows ===" -ForegroundColor Cyan
    $w.windows | Format-Table scope_type, scope_id, @{N="Limit ($)"; E={($_.limit_microcents / 100000000).ToString("F4")}}, @{N="Reserved ($)"; E={($_.reserved_microcents / 100000000).ToString("F4")}}, @{N="Settled ($)"; E={($_.settled_microcents / 100000000).ToString("F4")}}, @{N="Available ($)"; E={($_.available_microcents / 100000000).ToString("F4")}}
    Start-Sleep -Seconds 5
}
```

---

## Phase 10: Web Console Dashboard Verification

### 10.1 Access the Control Plane Dashboard

Open in your browser: **https://console.vexasec.io/**

### 10.2 Navigate to Spend Views

| View | URL Path | What to Check |
|---|---|---|
| **Spend Status** | `/spend/status` | Active budget windows, progress bars, settled vs reserved amounts |
| **Spend Visualization** | `/spend/visualization` | Top spenders chart, fleet-wide totals, historical authorizations |
| **Increase Requests** | `/spend/requests` | Pending/approved/rejected requests with approve/reject buttons |

### 10.3 Submit an Increase Request via Dashboard

1. Go to **Spend Status** → **Submit Increase Request** panel
2. Enter Project/Scope ID: `proj_alpha`
3. Enter Requested New Cap: `25.00`
4. Enter Business Justification: "Need higher cap for sprint demo"
5. Click **Submit Request**
6. Navigate to **Increase Requests** to approve/reject it

---

## Phase 11: Inspect Local SQLite Telemetry

The legacy local ledger provides observational spend data synced to the Control Plane.

```powershell
# Open SQLite database
sqlite3 "$env:USERPROFILE\.agentcontrol\events.db"

-- View budget configurations
SELECT * FROM spend_budgets;

-- View spend counters per agent per period
SELECT * FROM spend_counters;

-- View threshold alerts that fired
SELECT * FROM spend_thresholds_fired;

-- View increase requests
SELECT * FROM spend_increase_requests;

-- Exit
.exit
```

> [!TIP]
> If you don't have `sqlite3` installed, you can install it via:
> ```powershell
> winget install SQLite.SQLite
> ```
> Or use [DB Browser for SQLite](https://sqlitebrowser.org/) for a GUI.

---

## Phase 12: Pricing Table Verification

AgentControl uses a built-in pricing table for token cost estimation. View current pricing:

| Model | Input (per 1M tokens) | Output (per 1M tokens) |
|---|---|---|
| `claude-3-5-sonnet-20240620` | $3.00 (300¢) | $15.00 (1500¢) |
| `claude-3-opus-20240229` | $15.00 (1500¢) | $75.00 (7500¢) |
| `claude-3-haiku-20240307` | $0.25 (25¢) | $1.25 (125¢) |
| `gpt-4o` | $5.00 (500¢) | $15.00 (1500¢) |
| `gpt-4o-mini` | $0.15 (15¢) | $0.60 (60¢) |
| `o1` / `o3` | $15.00 (1500¢) | $60.00 (6000¢) |
| `gemini-1.5-pro` | $3.50 (350¢) | $10.50 (1050¢) |
| `gemini-1.5-flash` | $0.35 (35¢) | $1.05 (105¢) |
| **Fallback (unknown model)** | $3.00 (300¢) | $15.00 (1500¢) |

You can override this by placing a custom `pricing_override.toml` and referencing it in the policy:

```yaml
spend_caps:
  enabled: true
  pricing_table_path: "./my_custom_pricing.toml"
```

---

## Quick-Reference: Complete Test Checklist

| # | Test Case | Expected Result | ✅ |
|---|---|---|---|
| 1 | Create org-level daily budget | Policy created with `PUBLISHED` status | ☐ |
| 2 | Create project-level daily budget | Policy created with unique scope_id | ☐ |
| 3 | Authorize request (within budget) | `decision: "allow"`, reservation_id returned | ☐ |
| 4 | Verify budget window has reservation | `reserved_microcents > 0` | ☐ |
| 5 | Settle reservation with actual usage | `settled_microcents` reflects real cost | ☐ |
| 6 | Verify excess reservation released | `released_microcents` returned | ☐ |
| 7 | Authorize against exhausted budget | HTTP 429, `spend_budget_exhausted` | ☐ |
| 8 | Release unused reservation | `released_microcents` restores available | ☐ |
| 9 | Submit increase request (user) | `status: "PENDING"` | ☐ |
| 10 | List increase requests (admin) | Requests visible with metadata | ☐ |
| 11 | Approve increase request | `status: "APPROVED"` | ☐ |
| 12 | Reject increase request | `status: "REJECTED"` | ☐ |
| 13 | View immutable spend events | `AUTHORIZED`, `SETTLED`, `RELEASED` events logged | ☐ |
| 14 | Enable `spend_caps` in policy YAML | Gateway starts with spend enforcement active | ☐ |
| 15 | Send LLM request from IDE | Budget window reflects new spend | ☐ |
| 16 | Verify Web Console dashboard | Budget bars, events table, increase forms work | ☐ |
| 17 | Check local SQLite telemetry | `spend_budgets` and `spend_counters` tables populated | ☐ |

---

## Troubleshooting

| Issue | Cause | Fix |
|---|---|---|
| `No active budget windows` in dashboard | No policies published yet | Run Phase 2 to create and publish policies |
| Authorization always returns `"allow"` with no reservation | `spend_caps.enabled` is `false` or missing | Add `spend_caps: enabled: true` to policy YAML |
| HTTP 500 on `/api/v2/spend/authorize` | PostgreSQL not available or schema not initialized | Check Control Hub status at `https://console.vexasec.io/health` |
| Local SQLite `events.db` not created | Gateway never started | Start the gateway via `agentcontrol start` |
| Settle returns "reservation not found" | Reservation expired (default TTL) | Settle within the reservation window or re-authorize |
| Budget window shows stale data | 60-second sync interval | Wait 60s or query the V2 API directly for real-time data |
