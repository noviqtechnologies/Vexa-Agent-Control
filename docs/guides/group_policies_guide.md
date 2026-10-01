# Role-Based Group Policies & Identity Claims Governance Guide

## 1. Overview

**Group Policies** in Vexa Agent Control provide fine-grained, identity-bound Role-Based Access Control (RBAC) on top of the organization's base policy. They allow administrators to bind specific tool permissions, LLM model access, and security guardrails to user groups defined in enterprise Identity Providers (such as **Microsoft Entra ID** or **Google Workspace**).

---

## 2. Policy Editor vs. Group Policy Editor

The Control Plane enforces security through a **layered 5-tier policy hierarchy**:

| Policy Layer | Configuration Location | Scope | Primary Purpose |
|---|---|---|---|
| **Level 1: Base Organization Policy** | **Policy Editor** (`/policies`) | Entire Organization | Defines global baseline rules: Prompt Injection Firewall, secret DLP regexes, rate limits (`max_calls_per_second`), and default fallback actions (`default_action: deny`). |
| **Level 2: Group Policy Overrides** | **Group Policies** (`/group-policies`) | Scoped to IdP Claims | Grants or denies specific tools (`read_file`, `write_file`, `bash`) and LLM models (`gpt-4o` vs `gpt-4o-mini`) based on verified JWT group assertions. |
| **Level 3: Spend Caps** | Spend Budgets (`/spend`) | Team / Org / User | Hard financial budgets and microcent thresholds. |
| **Level 4: Virtual Key** | Scoped Virtual Keys (`/virtual-keys`) | Developer / Tool | Specific key-level model allowlists, CIDR restrictions, and RPM/TPM limits. |
| **Level 5: Device Compliance** | Device Governance (`/devices`) | Workstation | Sentry hardware attestation and enrollment status. |

### Why Both Are Essential
1. **Separation of Concerns:** SecOps manages the global baseline security (DLP, firewall, rate limits) in the **Policy Editor**, while project and engineering leads configure team-level tool entitlements in **Group Policies**.
2. **Deny-Overrides & Safe Fallbacks:** If a user belongs to multiple groups where one allows a tool and another explicitly denies it, the `deny` action takes precedence for fail-closed security.
3. **No Monolithic Policy Bloat:** Instead of maintaining a complex, multi-thousand-line single policy YAML, group policies are authored independently and dynamically merged into the active policy served to edge gateways.

---

## 3. Web Console Group Policy Editor Walkthrough

Navigate to **Policies & Security ➔ Group Policies** (`/group-policies`):

### Form Fields & Validation Rules

| UI Field | Description | Rules & Requirements |
|---|---|---|
| **TARGET GROUP ID** | Unique internal identifier for the group rule. | **Required.** Must not be empty (the *Publish Version* button remains disabled if this is empty). Example: `engineering` or `contractor-restricted`. |
| **REQUIRED CLAIMS (JSON)** | JSON object matching JWT claims from the authenticated OIDC token. | Must be valid JSON. String values (such as GUIDs) must be wrapped in double quotes. |
| **TOOL OVERRIDES (JSON)** | Array of tool permission rules. | Array of objects: `[{"name": "<tool_or_model>", "action": "allow"|"deny"}]`. |
| **Publish Version** | Commits and activates this policy version. | Dynamically compiles into the organization's policy and pushes updates via SSE to all active workstation gateways. |

---

## 4. Identity Provider Configurations

### A. Microsoft Entra ID (Azure AD)

#### 1. Enable Groups Claim in Entra ID
1. In the **Microsoft Entra admin center** (or Azure Portal), go to **Microsoft Entra ID ➔ App registrations**.
2. Select your AgentControl application.
3. Navigate to **Token configuration** ➔ **+ Add groups claim**.
4. Check **Security groups** (and ensure **ID** and **Access** tokens are checked).
5. Click **Add**.

#### 2. Obtain Group Object IDs
Go to **Microsoft Entra ID ➔ Groups ➔ All groups** and copy the **Object ID (GUID)** for your target groups.

#### 3. Group Policy Examples

**Engineering Team (Full Tool & Model Access):**
- **TARGET GROUP ID:** `entra-engineering`
- **REQUIRED CLAIMS (JSON):**
  ```json
  {
    "groups": ["a1b2c3d4-e5f6-7890-abcd-ef1234567890"]
  }
  ```
- **TOOL OVERRIDES (JSON):**
  ```json
  [
    { "name": "read_file", "action": "allow" },
    { "name": "write_file", "action": "allow" },
    { "name": "bash", "action": "allow" },
    { "name": "execute_query", "action": "allow" }
  ]
  ```

**Contractors / Offshore (Restricted Access):**
- **TARGET GROUP ID:** `entra-contractors`
- **REQUIRED CLAIMS (JSON):**
  ```json
  {
    "groups": ["f0e9d8c7-b6a5-4321-fedc-ba9876543210"]
  }
  ```
- **TOOL OVERRIDES (JSON):**
  ```json
  [
    { "name": "read_file", "action": "allow" },
    { "name": "write_file", "action": "deny" },
    { "name": "bash", "action": "deny" },
    { "name": "execute_query", "action": "deny" }
  ]
  ```

---

### B. Google Workspace / Google Cloud Identity

#### 1. Group / Hosted Domain Mapping
Google Workspace OIDC tokens include identity assertions such as `email`, `sub`, and `hd` (hosted domain). If using Google Cloud Identity groups or SAML group assertion mappings, groups appear in the `groups` claim.

#### 2. Group Policy Examples

**Data Science Group:**
- **TARGET GROUP ID:** `gsuite-data-science`
- **REQUIRED CLAIMS (JSON):**
  ```json
  {
    "groups": ["data-science@yourcompany.com"]
  }
  ```
- **TOOL OVERRIDES (JSON):**
  ```json
  [
    { "name": "read_file", "action": "allow" },
    { "name": "execute_query", "action": "allow" },
    { "name": "bash", "action": "deny" }
  ]
  ```

**Domain-Wide Base Employee Rule:**
- **TARGET GROUP ID:** `gsuite-corp-users`
- **REQUIRED CLAIMS (JSON):**
  ```json
  {
    "hd": "yourcompany.com"
  }
  ```
- **TOOL OVERRIDES (JSON):**
  ```json
  [
    { "name": "read_file", "action": "allow" }
  ]
  ```

---

## 5. LLM Access Governance Under Group Policies

LLM routing (OpenAI GPT, Anthropic Claude, Azure OpenAI) is fully governed by the Zero-Leakage Credential Broker:

1. **Zero Raw Keys on Client Machines:** Developers never possess master OpenAI API keys. Keys reside in the Hub's KMS-backed vault (**Settings ➔ Provider Keys**).
2. **Model Tier Scoping:**
   - Standard Engineers can be granted `gpt-4o`, `o1-preview`, and `claude-3-5-sonnet`.
   - Contractors can be restricted to `gpt-4o-mini` with lower spend caps ($15/mo).
3. **Agentic Tool Execution Interception:** Even if an LLM generates a tool call to modify files or execute shell commands, the workstation gateway evaluates the user's active group policy before allowing the tool to execute.

---

## 6. Testing & Verifying on Windows Workstations

### Interactive Developer Login (End-to-End)
```powershell
agentcontrol login --hub http://<control-hub-host>:8081
```
1. Authenticate with your Microsoft Entra ID or Google Workspace SSO account.
2. The workstation receives the OIDC JWT and synchronizes the active group policy.
3. Start or wrap an agent session:
   ```powershell
   agentcontrol wrap -- mcp-server-filesystem C:\projects
   ```
4. Verify that allowed tools succeed and denied tools are blocked according to the user's IdP group membership.

### Offline Policy Dry-Run (`agentcontrol test`)
```powershell
agentcontrol test --policy policy.yaml --fixture fixture.json --oidc-token "<JWT_BEARER_TOKEN>"
```
