# OIDC Identity Binding & Auth Provider Configuration Guide

This guide provides detailed instructions for configuring **OIDC Identity Binding** and **Authentication Providers** in Vexa AgentWall. 

AgentWall enforces Zero-Trust identity governance by binding agent sessions and tool calls to cryptographically verified OpenID Connect (OIDC) identities, extracting group memberships, and applying group-based policy rules.

---

## 1. Prerequisites

Before configuring OIDC Identity Binding in AgentWall, ensure the following requirements are met:

* **AgentWall Installation:** AgentWall CLI and Gateway binary (v6.1 or later) installed and operational.
* **OIDC-Compliant Identity Provider (IdP):** An active Identity Provider (e.g. Okta, Keycloak, Microsoft Entra ID, Auth0, AWS Cognito, Google Workspace, or PingIdentity) accessible over HTTPS.
* **OIDC Discovery & JWKS Endpoint:** The IdP must expose a standard OpenID Connect discovery document at `{issuer}/.well-known/openid-configuration` and a valid JSON Web Key Set (`jwks_uri`) endpoint.
* **Registered API Audience / Client ID:** An OAuth 2.0 API Application or Audience configured in your IdP specifically for AgentWall Gateway.
* **JWT Token Support in Agents:** AI Agents or SDK clients must be configured to acquire an OIDC JWT access/ID token from the IdP and pass it in the `Authorization: Bearer <JWT>` HTTP header on tool call requests.
* **Network Connectivity:** AgentWall Gateway must have HTTPS outbound network access to the IdP issuer endpoint to fetch and periodically rotate JWKS public keys.

---

## 2. How OIDC Identity Binding Works

AgentWall intercepts agent tool calls and validates incoming OIDC JSON Web Tokens (JWTs):

```
┌───────────────┐     1. Bearer <JWT>      ┌─────────────────────────┐     3. Fetch JWKS      ┌──────────────────────┐
│  AI Agent /   │ ───────────────────────► │   AgentWall Gateway     │ ────────────────────►  │ Identity Provider    │
│  Developer    │                          │                         │ ◄────────────────────  │ (Okta/Entra/Keycloak)│
└───────────────┘                          └─────────────────────────┘   4. Verify Signature  └──────────────────────┘
                                                        │
                                                        ▼
                                            2. Validate Claims (iss, aud, exp, alg)
                                            3. Extract `group_claim_key`
                                            4. Match `groups` / `agents` policy rules
```

1. **Bearer Token Extraction:** Agents pass an OIDC JWT in the `Authorization: Bearer <token>` HTTP header.
2. **Automatic OIDC Discovery & JWKS Caching:** The gateway automatically fetches `{issuer}/.well-known/openid-configuration`, discovers the `jwks_uri`, and caches public RSA (RS256) and EC (ES256) signing keys in RAM (with configurable TTL rotation).
3. **Token Verification:** Validates algorithm (`RS256` or `ES256`), signature (`kid`), expiration (`exp`), issuer (`iss`), and audience (`aud`).
4. **Group Claim Extraction:** Dynamically extracts user/agent group memberships using the configured `group_claim_key` (e.g., `groups`, `cognito:groups`, `roles`).
5. **Policy Matching:** Matches extracted group claims (`groups[].claims`) or agent subject (`agents[].sub`) to rulesets defined in `agentwall-policy.yaml`. Deny rules beat allow rules across matching groups.

---

## 3. Policy Schema Reference (v2 / v2.1)

To enable OIDC Identity Binding, define the `identity` block along with `groups` or `agents` in your `agentwall-policy.yaml`:

```yaml
version: "2"
default_action: deny

# 1. Identity & OIDC Configuration
identity:
  provider: "oidc"
  issuer: "https://auth.yourcorp.com/oauth2/default"
  audience: "agentwall-gateway-prod"
  group_claim_key: "groups"    # IdP-specific claim key (default: "groups")

# 2. Group Identity Policies (Group-Scoped Tool Access)
groups:
  - id: "secops-policy"
    claims: ["secops-team", "security-admins"]
    tools:
      - name: "read_file"
        action: allow
      - name: "exec_command"
        action: allow

  - id: "developer-policy"
    claims: ["dev-team", "engineering"]
    tools:
      - name: "read_file"
        action: allow
      - name: "write_file"
        action: allow

# 3. Agent Subject Identity Policies (Individual Agent Scoping)
agents:
  - id: "ci-agent"
    sub: "ci-agent@yourcorp.com"
    credential_scope:
      - tool: "read_file"
        paths: ["/tmp/build/*"]
    max_credential_ttl: "1h"

# 4. Global Tool Allowlist / Rules
tools:
  - name: "read_file"
    action: allow
```

> [!IMPORTANT]
> AgentWall uses strict schema validation (`deny_unknown_fields`). Top-level keys like `groups` and `agents` must match the schema structure exactly. Placing unknown keys or putting `cache_ttl_minutes` inside `identity:` will trigger a startup parsing error.

---

## 4. Supported Authentication Providers

### 4.1. Okta

Okta uses a custom authorization server (or default server) to issue JWT tokens with group claims.

* **Documentation:** [Okta Authorization Server Claims Guide](https://developer.okta.com/docs/guides/customize-tokens-returned-from-okta/)

#### Okta Settings:
* **Issuer URL (`issuer`):** `https://{yourOktaDomain}/oauth2/default` (or custom auth server `https://{yourOktaDomain}/oauth2/{authServerId}`)
* **Audience (`audience`):** `api://agentwall` (or your configured Audience string in Okta)
* **Group Claim Key (`group_claim_key`):** `groups`

#### Okta IdP Setup Instructions:
1. In the **Okta Admin Console**, navigate to **Security -> API -> Authorization Servers**.
2. Select your Authorization Server (e.g., `default`).
3. Under **Claims**, click **Add Claim**:
   * **Name:** `groups`
   * **Include in token:** `Access Token` -> `Always`
   * **Value type:** `Group filter` -> `Matches regex` -> `.*` (or filter by prefix `agentwall-.*`).
4. Save the claim and copy the Issuer URI and Audience.

#### AgentWall Policy Configuration (`agentwall-policy.yaml`):
```yaml
version: "2"
default_action: deny

identity:
  provider: "oidc"
  issuer: "https://dev-12345678.okta.com/oauth2/default"
  audience: "api://agentwall"
  group_claim_key: "groups"

groups:
  - id: "engineering-group-policy"
    claims: ["Engineering"]
    tools:
      - name: "read_file"
        action: allow
      - name: "write_file"
        action: allow

  - id: "secops-group-policy"
    claims: ["Security-Admins"]
    tools:
      - name: "exec_command"
        action: allow
```

---

### 4.2. Keycloak

Keycloak manages realms and clients, issuing signed JWT tokens with roles or group claims.

* **Documentation:** [Keycloak Protocol Mappers Guide](https://www.keycloak.org/docs/latest/server_admin/#_protocol-mappers)

#### Keycloak Settings:
* **Issuer URL (`issuer`):** `https://{keycloak-host}/realms/{realm-name}`
* **Audience (`audience`):** `{client-id}` (e.g., `agentwall-gateway`)
* **Group Claim Key (`group_claim_key`):** `groups` (or `roles`)

#### Keycloak IdP Setup Instructions:
1. Log in to the **Keycloak Admin Console** and select your Realm.
2. Under **Client Scopes**, select `roles` or create a new Client Scope named `groups`.
3. Add a **Group Membership Mapper**:
   * **Mapper Type:** `Group Membership`
   * **Token Claim Name:** `groups`
   * **Full Group Path:** `false` (removes leading slashes).
   * **Add to ID token:** `On`, **Add to access token:** `On`.
4. Assign the Client Scope to your Agent client application.

#### AgentWall Policy Configuration (`agentwall-policy.yaml`):
```yaml
version: "2"
default_action: deny

identity:
  provider: "oidc"
  issuer: "https://keycloak.corp.internal/realms/production"
  audience: "agentwall-gateway"
  group_claim_key: "groups"

groups:
  - id: "devops-group-policy"
    claims: ["DevOps"]
    tools:
      - name: "restart_service"
        action: allow
      - name: "read_file"
        action: allow
```

---

### 4.3. Microsoft Entra ID (Azure AD)

Microsoft Entra ID issues tokens containing Azure AD user object IDs, security group GUIDs, or directory role claim keys.

* **Documentation:** [Microsoft Entra ID Optional Group Claims Guide](https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims)

#### Entra ID Settings:
* **Issuer URL (`issuer`):** `https://login.microsoftonline.com/{tenant-id}/v2.0`
* **Audience (`audience`):** `api://{client-id}` or `{client-id}`
* **Group Claim Key (`group_claim_key`):** `groups` (or `wids` for directory roles)

#### Entra ID Setup Instructions:
1. In the **Azure Portal**, go to **Microsoft Entra ID -> App Registrations** and open your App Registration.
2. Go to **Token Configuration -> Add groups claim**.
3. Select **Security groups** (or **Directory roles**).
4. For ID / Access Token attributes, choose **Group ID** (or `sAMAccountName` if using Azure AD Connect).
5. Ensure your Application Manifest sets `"acceptMappedClaims": true`.

#### AgentWall Policy Configuration (`agentwall-policy.yaml`):
```yaml
version: "2"
default_action: deny

identity:
  provider: "oidc"
  issuer: "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/v2.0"
  audience: "api://agentwall-client-app-id"
  group_claim_key: "groups"

groups:
  # Entra ID emits group Object IDs (GUIDs) in the groups claim array
  - id: "entra-secops-policy"
    claims: ["9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"]
    tools:
      - name: "exec_command"
        action: allow
```

---

### 4.4. Auth0

Auth0 supports custom claims in access tokens via Auth0 Actions / Rules.

* **Documentation:** [Auth0 Actions Token Customization Guide](https://auth0.com/docs/customize/actions/flows-and-triggers/post-login-flow/customize-tokens)

#### Auth0 Settings:
* **Issuer URL (`issuer`):** `https://{yourTenant}.us.auth0.com/` (must include trailing slash)
* **Audience (`audience`):** `https://api.agentwall.corp.com`
* **Group Claim Key (`group_claim_key`):** `https://agentwall.corp.com/groups` (custom namespaced claim)

#### Auth0 Setup Instructions:
1. In the **Auth0 Dashboard**, go to **Actions -> Triggers -> Post-Login**.
2. Create a new Action to attach user roles/groups to the token:
   ```javascript
   exports.onExecutePostLogin = async (event, api) => {
     const namespace = 'https://agentwall.corp.com';
     if (event.authorization && event.authorization.roles) {
       api.accessToken.setCustomClaim(`${namespace}/groups`, event.authorization.roles);
     }
   };
   ```
3. Deploy the Action and bind it to the Post-Login Flow.

#### AgentWall Policy Configuration (`agentwall-policy.yaml`):
```yaml
version: "2"
default_action: deny

identity:
  provider: "oidc"
  issuer: "https://mycorp.us.auth0.com/"
  audience: "https://api.agentwall.corp.com"
  group_claim_key: "https://agentwall.corp.com/groups"

groups:
  - id: "auth0-admin-policy"
    claims: ["admin"]
    tools:
      - name: "read_file"
        action: allow
      - name: "write_file"
        action: allow
```

---

### 4.5. AWS Cognito

AWS Cognito User Pools issue access and ID tokens containing native Cognito group claims (`cognito:groups`).

* **Documentation:** [AWS Cognito User Pool Groups Guide](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-user-groups.html)

#### AWS Cognito Settings:
* **Issuer URL (`issuer`):** `https://cognito-idp.{region}.amazonaws.com/{userPoolId}`
* **Audience (`audience`):** `{appClientId}`
* **Group Claim Key (`group_claim_key`):** `cognito:groups`

#### AWS Cognito Setup Instructions:
1. Open the **AWS Cognito Console** and select your **User Pool**.
2. Under **App Integration**, select your App Client ID.
3. Assign users or agents to Cognito User Pool Groups (e.g., `agentwall-admins`, `agentwall-developers`).
4. Cognito automatically populates the `cognito:groups` array in issued tokens.

#### AgentWall Policy Configuration (`agentwall-policy.yaml`):
```yaml
version: "2"
default_action: deny

identity:
  provider: "oidc"
  issuer: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abc123XYZ"
  audience: "1h23456789abcdef0123456789"
  group_claim_key: "cognito:groups"

groups:
  - id: "cognito-admins-policy"
    claims: ["agentwall-admins"]
    tools:
      - name: "exec_command"
        action: allow
  - id: "cognito-devs-policy"
    claims: ["agentwall-developers"]
    tools:
      - name: "read_file"
        action: allow
```

---

### 4.6. Google Workspace / GCP Identity Platform

Google Workspace / GCP Identity Platform issues standard OIDC tokens for Google accounts or service accounts.

* **Documentation:** [Google OpenID Connect Documentation](https://developers.google.com/identity/openid-connect/openid-connect)

#### Google Settings:
* **Issuer URL (`issuer`):** `https://accounts.google.com`
* **Audience (`audience`):** `{google-oauth-client-id}.apps.googleusercontent.com`
* **Group Claim Key (`group_claim_key`):** `groups` (or use `agents` with `sub` matching the email address)

#### AgentWall Policy Configuration (`agentwall-policy.yaml`):
```yaml
version: "2"
default_action: deny

identity:
  provider: "oidc"
  issuer: "https://accounts.google.com"
  audience: "123456789012-abcdefghijklmnopqrstuvwxyz.apps.googleusercontent.com"
  group_claim_key: "groups"

agents:
  - id: "secops-lead-agent"
    sub: "secops-lead@yourcompany.com"
    credential_scope:
      - tool: "read_file"
        paths: ["/var/log/*"]
```

---

### 4.7. PingIdentity / PingFederate

PingFederate issues standard OIDC assertions with LDAP/Active Directory attributes mapped to token claims.

* **Documentation:** [PingFederate OAuth & OIDC Configuration Guide](https://docs.pingidentity.com/pingfederate/latest/)

#### PingIdentity Settings:
* **Issuer URL (`issuer`):** `https://{ping-host}/as`
* **Audience (`audience`):** `agentwall-gateway-client`
* **Group Claim Key (`group_claim_key`):** `memberOf` (or `groups`)

#### AgentWall Policy Configuration (`agentwall-policy.yaml`):
```yaml
version: "2"
default_action: deny

identity:
  provider: "oidc"
  issuer: "https://ping.corp.com/as"
  audience: "agentwall-gateway-client"
  group_claim_key: "memberOf"

groups:
  - id: "ping-admins-policy"
    claims: ["CN=AgentWall-Admins,OU=Groups,DC=corp,DC=com"]
    tools:
      - name: "read_file"
        action: allow
      - name: "write_file"
        action: allow
```

---

## 5. Cross-OS Environment Setup & Launch Instructions

Configure the AgentWall Gateway with your OIDC Issuer URL across different operating systems:

### Linux / macOS (Bash or Zsh)

```bash
# 1. Set environment variables
export AGENTWALL_OIDC_ISSUER="https://dev-12345678.okta.com/oauth2/default"
export AGENTWALL_OIDC_TOKEN="eyJhbGciOiJSUzI1NiIs..."
export VEXA_GATEWAY_URL="https://agentwall.internal.corp"

# 2. Run AgentWall gateway in centralized mode with OIDC enforcement
./agentwall dev --policy agentwall-policy.yaml --oidc-issuer $AGENTWALL_OIDC_ISSUER --centralized

# 3. Alternatively, wrap an agent command
./agentwall wrap --command "npx @modelcontextprotocol/server-memory" --policy agentwall-policy.yaml
```

### Windows (PowerShell)

```powershell
# 1. Set environment variables
$env:AGENTWALL_OIDC_ISSUER = "https://dev-12345678.okta.com/oauth2/default"
$env:AGENTWALL_OIDC_TOKEN = "eyJhbGciOiJSUzI1NiIs..."
$env:VEXA_GATEWAY_URL = "https://agentwall.internal.corp"

# 2. Run AgentWall gateway in centralized mode with OIDC enforcement
.\agentwall.exe dev --policy agentwall-policy.yaml --oidc-issuer $env:AGENTWALL_OIDC_ISSUER --centralized

# 3. Alternatively, wrap an agent command
.\agentwall.exe wrap --command "npx @modelcontextprotocol/server-memory" --policy agentwall-policy.yaml
```

### Windows (Command Prompt / CMD)

```cmd
:: 1. Set environment variables
set AGENTWALL_OIDC_ISSUER=https://dev-12345678.okta.com/oauth2/default
set AGENTWALL_OIDC_TOKEN=eyJhbGciOiJSUzI1NiIs...
set VEXA_GATEWAY_URL=https://agentwall.internal.corp

:: 2. Run AgentWall gateway in centralized mode with OIDC enforcement
agentwall.exe dev --policy agentwall-policy.yaml --oidc-issuer %AGENTWALL_OIDC_ISSUER% --centralized

:: 3. Alternatively, wrap an agent command
agentwall.exe wrap --command "npx @modelcontextprotocol/server-memory" --policy agentwall-policy.yaml
```

---

## 6. End-to-End Validation & Verification Steps

To verify that OIDC Identity Binding and policy enforcement are functioning properly, follow these step-by-step validation procedures:

### Step 1: Decode & Verify OIDC JWT Token Claims

Before sending requests to AgentWall, decode your JWT (using `jwt.io` or `jq`) to ensure essential claims match:

```bash
# Decode JWT Header & Payload (Linux/macOS)
echo "YOUR_JWT_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq .
```

Verify that:
* `iss` matches `identity.issuer` in `agentwall-policy.yaml` exactly.
* `aud` matches `identity.audience` in `agentwall-policy.yaml` exactly.
* `exp` is in the future.
* `alg` in the header is either `RS256` or `ES256`.
* The claim key specified by `identity.group_claim_key` (e.g., `"groups"`) exists and contains the expected array or string of group names.

### Step 2: Validate Policy Syntax & OIDC Gateway Fixtures (`agentwall test`)

Use the built-in `agentwall test` command to validate your policy against a deployed gateway instance in CI/CD pipelines:

#### Linux / macOS:
```bash
./agentwall test \
  --policy agentwall-policy.yaml \
  --gateway https://agentwall.internal.corp \
  --oidc-token "$AGENTWALL_OIDC_TOKEN" \
  fixtures/test_tool_calls.json
```

#### Windows PowerShell:
```powershell
.\agentwall.exe test `
  --policy agentwall-policy.yaml `
  --gateway https://agentwall.internal.corp `
  --oidc-token $env:AGENTWALL_OIDC_TOKEN `
  fixtures\test_tool_calls.json
```

### Step 3: Validate Gateway Enforcement via HTTP Tool Calls

Test HTTP requests directly against the gateway endpoint to verify authorization and token validation:

#### 1. Test Valid OIDC Token (Should succeed / permit tool call):
```bash
curl -i -X POST https://agentwall.internal.corp/v1/tools/execute \
  -H "Authorization: Bearer $AGENTWALL_OIDC_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tool": "read_file", "parameters": {"path": "/tmp/test.txt"}}'
```

#### 2. Test Missing / Invalid Token (Should fail with 401 Unauthorized):
```bash
curl -i -X POST https://agentwall.internal.corp/v1/tools/execute \
  -H "Content-Type: application/json" \
  -d '{"tool": "read_file", "parameters": {"path": "/tmp/test.txt"}}'
```

---

## 7. Runtime Identity Management CLI (`agentwall identity`)

AgentWall provides a built-in CLI suite to manage short-lived agent identities, rotate credentials, and verify identity logs:

### 1. Provision Short-Lived Credential:
```bash
agentwall identity create --agent financial-agent-01 --scope "read-only" --ttl 1h
```

### 2. Rotate Agent Credentials (Zero Downtime):
```bash
agentwall identity rotate --agent financial-agent-01 --drain-secs 30
```

### 3. Configure Per-Tool Scoping Rules:
```bash
agentwall identity scope --agent financial-agent-01 --tool execute_shell --deny
```

### 4. Inspect Credential Binding Details:
```bash
agentwall identity inspect --credential "550e8400-e29b-41d4-a716-446655440000"
```

### 5. Audit Identity History & Verify Cryptographic Integrity:
```bash
agentwall identity audit --agent financial-agent-01 --verify
```

### 6. Verify Log HMAC Chain Integrity:
```bash
agentwall verify-log audit.log --key-file hmac.key
```

---

## 8. Troubleshooting OIDC Authorization Failures

### 1. Error: `IDENTITY_REQUIRED` (401 Unauthorized)
```json
{
  "error": {
    "code": "IDENTITY_REQUIRED",
    "message": "Missing or invalid OIDC JWT Bearer token"
  }
}
```
* **Cause:** The request lacked the `Authorization: Bearer <jwt>` header or the token was malformed.
* **Fix:** Verify that the client includes the Bearer token in HTTP headers.

### 2. Error: `TOKEN_EXPIRED` (401 Unauthorized)
* **Cause:** Token `exp` timestamp is in the past.
* **Fix:** Refresh the agent's JWT token from your IdP before invoking tool calls.

### 3. Error: `AUDIENCE_MISMATCH` / `ISSUER_MISMATCH`
* **Cause:** The `aud` or `iss` claim in the JWT does not match the strings specified in `identity.audience` or `identity.issuer` in `agentwall-policy.yaml`.
* **Fix:** Decode your JWT using `jwt.io` or `jq` and update `identity.issuer` and `identity.audience` to match exact string values.

### 4. Error: Unsupported Signing Algorithm
* **Cause:** Token uses an unsupported algorithm (e.g., `HS256`, `none`).
* **Fix:** AgentWall requires asymmetric signature algorithms (`RS256` or `ES256`). Reconfigure your IdP Authorization Server to sign tokens using `RS256` or `ES256`.

### 5. Group Claims Not Matching Policy Rules
* **Cause:** The `group_claim_key` in policy configuration does not match the actual JSON key emitted by your IdP (e.g. using `groups` instead of `cognito:groups` or `roles`), or claim value formats differ (e.g. GUIDs vs string names).
* **Fix:** Inspect the unencrypted JWT token payload to confirm the exact claim key name and array contents, then update `groups[].claims` in `agentwall-policy.yaml`.
