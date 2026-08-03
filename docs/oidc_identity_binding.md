# OIDC Identity Binding & Auth Provider Configuration Guide

This guide provides detailed instructions for configuring **OIDC Identity Binding** and **Authentication Providers** in Vexa AgentWall. 

AgentWall enforces Zero-Trust identity governance by binding agent sessions and tool calls to cryptographically verified OpenID Connect (OIDC) identities, extracting group memberships, and applying group-based policy rules.

---

## 1. How OIDC Identity Binding Works

AgentWall intercepts agent tool calls and validates incoming OIDC JSON Web Tokens (JWTs):

```
┌───────────────┐     1. Bearer <JWT>      ┌─────────────────────────┐     3. Fetch JWKS      ┌──────────────────────┐
│  AI Agent /   │ ───────────────────────► │   AgentWall Gateway     │ ────────────────────►  │ Identity Provider    │
│  Developer    │                          │                         │ ◄────────────────────  │ (Okta/Entra/Keycloak)│
└───────────────┘                          └─────────────────────────┘   4. Verify Signature  └──────────────────────┘
                                                        │
                                                        ▼
                                           2. Validate Claims (iss, aud, exp)
                                           3. Extract `group_claim_key`
                                           4. Match `policy_bindings`
```

1. **Bearer Token Extraction:** Agents pass an OIDC JWT in the `Authorization: Bearer <token>` HTTP header.
2. **Automatic OIDC Discovery & JWKS Caching:** The gateway automatically fetches `{issuer}/.well-known/openid-configuration`, discovers the `jwks_uri`, and caches public RSA/EC signing keys in RAM (with configurable TTL rotation).
3. **Token Verification:** Validates signature (`kid`), expiration (`exp`), issuer (`iss`), and audience (`aud`).
4. **Group Claim Extraction:** Dynamically extracts user/agent group memberships using the configured `group_claim_key` (e.g., `groups`, `cognito:groups`, `roles`).
5. **Policy Binding:** Matches the extracted subject (`sub`) or groups to policy rulesets in `policy_bindings`.

---

## 2. Policy Schema Reference (v2)

To enable OIDC Identity Binding, define the `identity` block and `policy_bindings` array in your `agentwall-policy.yaml`:

```yaml
version: 2
default_action: deny

# 1. Identity & OIDC Configuration
identity:
  provider: "oidc"
  issuer: "https://auth.yourcorp.com/oauth2/default"
  audience: "agentwall-gateway-prod"
  group_claim_key: "groups"    # IdP-specific claim key (default: "groups")
  cache_ttl_minutes: 15        # JWKS in-memory cache TTL (default: 15 min)

# 2. Policy Bindings (Group & Subject Mappings)
policy_bindings:
  - group: "secops-team"
    policy: "admin-unrestricted"
  - group: "dev-team"
    policy: "developer-standard"
  - sub: "ci-agent@yourcorp.com"
    policy: "ci-restricted"

# 3. Tool Rules & Credential Scope Controls
tools:
  - name: "read_file"
    action: allow
    credential_scope: ["file:read"]

  - name: "write_file"
    action: allow
    credential_scope: ["file:write"]
```

---

## 3. Supported Authentication Providers

### 3.1. Okta

Okta uses a custom authorization server (or default server) to issue JWT tokens with group claims.

#### Okta Settings:
* **Issuer URL (`issuer`):** `https://{yourOktaDomain}/oauth2/default` (or custom auth server URL `https://{yourOktaDomain}/oauth2/{authServerId}`)
* **Audience (`audience`):** `api://agentwall` (or your configured Audience string in Okta)
* **Group Claim Key (`group_claim_key`):** `groups`

#### Okta IdP Setup Instructions:
1. In the **Okta Admin Console**, navigate to **Security -> API -> Authorization Servers**.
2. Select your Authorization Server (e.g., `default`).
3. Under **Claims**, click **Add Claim**:
   * Name: `groups`
   * Include in token: `Access Token` -> `Always`
   * Value type: `Group filter` -> `Matches regex` -> `.*` (or filter by prefix `agentwall-.*`).
4. Save the claim and copy the Issuer URI and Audience.

#### AgentWall Policy Configuration (`agentwall-policy.yaml`):
```yaml
identity:
  provider: "oidc"
  issuer: "https://dev-12345678.okta.com/oauth2/default"
  audience: "api://agentwall"
  group_claim_key: "groups"

policy_bindings:
  - group: "Engineering"
    policy: "developer-standard"
  - group: "Security-Admins"
    policy: "admin-unrestricted"
```

---

### 3.2. Keycloak

Keycloak manages realms and clients, issuing signed JWT tokens with roles or group claims.

#### Keycloak Settings:
* **Issuer URL (`issuer`):** `https://{keycloak-host}/realms/{realm-name}`
* **Audience (`audience`):** `{client-id}` (e.g., `agentwall-gateway`)
* **Group Claim Key (`group_claim_key`):** `groups` (or `roles`)

#### Keycloak IdP Setup Instructions:
1. Log in to the **Keycloak Admin Console** and select your Realm.
2. Under **Client Scopes**, select `roles` or create a new Client Scope named `groups`.
3. Add a **Group Membership Mapper**:
   * Mapper Type: `Group Membership`
   * Token Claim Name: `groups`
   * Full Group Path: `false` (removes leading slashes).
   * Add to ID token: `On`, Add to access token: `On`.
4. Assign the Client Scope to your Agent client application.

#### AgentWall Policy Configuration (`agentwall-policy.yaml`):
```yaml
identity:
  provider: "oidc"
  issuer: "https://keycloak.corp.internal/realms/production"
  audience: "agentwall-gateway"
  group_claim_key: "groups"

policy_bindings:
  - group: "DevOps"
    policy: "developer-standard"
```

---

### 3.3. Microsoft Entra ID (Azure AD)

Microsoft Entra ID issues tokens containing Azure AD user object IDs, security group GUIDs, or directory role claim keys.

#### Entra ID Settings:
* **Issuer URL (`issuer`):** `https://login.microsoftonline.com/{tenant-id}/v2.0`
* **Audience (`audience`):** `api://{client-id}` or `{client-id}`
* **Group Claim Key (`group_claim_key`):** `groups` (or `wids` for directory roles)

#### Entra ID Setup Instructions:
1. In the **Azure Portal**, go to **Microsoft Entra ID -> App Registrations** and open your App Registration.
2. Go to **Token Configuration -> Add groups claim**.
3. Select **Security groups** (or **Directory roles**).
4. For ID / Access Token attributes, choose **Group ID** (or sAMAccountName if using Azure AD Connect).
5. Ensure your Application Manifest sets `"acceptMappedClaims": true`.

#### AgentWall Policy Configuration (`agentwall-policy.yaml`):
```yaml
identity:
  provider: "oidc"
  issuer: "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/v2.0"
  audience: "api://agentwall-client-app-id"
  group_claim_key: "groups"

policy_bindings:
  # Entra ID emits group Object IDs (GUIDs) in the groups claim array
  - group: "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"
    policy: "admin-unrestricted"
```

---

### 3.4. Auth0

Auth0 supports custom claims in access tokens via Auth0 Actions / Rules.

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
3. Deploy the Action and bind it to the Flow.

#### AgentWall Policy Configuration (`agentwall-policy.yaml`):
```yaml
identity:
  provider: "oidc"
  issuer: "https://mycorp.us.auth0.com/"
  audience: "https://api.agentwall.corp.com"
  group_claim_key: "https://agentwall.corp.com/groups"

policy_bindings:
  - group: "admin"
    policy: "admin-unrestricted"
```

---

### 3.5. AWS Cognito

AWS Cognito User Pools issue access and ID tokens containing native Cognito group claims (`cognito:groups`).

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
identity:
  provider: "oidc"
  issuer: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abc123XYZ"
  audience: "1h23456789abcdef0123456789"
  group_claim_key: "cognito:groups"

policy_bindings:
  - group: "agentwall-admins"
    policy: "admin-unrestricted"
  - group: "agentwall-developers"
    policy: "developer-standard"
```

---

### 3.6. Google Workspace / GCP Identity Platform

Google Workspace / GCP Identity Platform issues standard OIDC tokens for Google accounts or service accounts.

#### Google Settings:
* **Issuer URL (`issuer`):** `https://accounts.google.com`
* **Audience (`audience`):** `{google-oauth-client-id}.apps.googleusercontent.com`
* **Group Claim Key (`group_claim_key`):** `groups` (or custom claim via Identity-Aware Proxy / Firebase OIDC)

#### AgentWall Policy Configuration (`agentwall-policy.yaml`):
```yaml
identity:
  provider: "oidc"
  issuer: "https://accounts.google.com"
  audience: "123456789012-abcdefghijklmnopqrstuvwxyz.apps.googleusercontent.com"
  group_claim_key: "groups"

policy_bindings:
  - sub: "secops-lead@yourcompany.com"
    policy: "admin-unrestricted"
```

---

### 3.7. PingIdentity / PingFederate

PingFederate issues standard OIDC assertions with LDAP/Active Directory attributes mapped to token claims.

#### PingIdentity Settings:
* **Issuer URL (`issuer`):** `https://{ping-host}/as`
* **Audience (`audience`):** `agentwall-gateway-client`
* **Group Claim Key (`group_claim_key`):** `memberOf` (or `groups`)

#### AgentWall Policy Configuration (`agentwall-policy.yaml`):
```yaml
identity:
  provider: "oidc"
  issuer: "https://ping.corp.com/as"
  audience: "agentwall-gateway-client"
  group_claim_key: "memberOf"

policy_bindings:
  - group: "CN=AgentWall-Admins,OU=Groups,DC=corp,DC=com"
    policy: "admin-unrestricted"
```

---

## 4. Runtime Identity Management CLI (`agentwall identity`)

AgentWall provides a built-in CLI suite to manage short-lived agent identities, rotate credentials, and verify identity logs:

### 1. Provision Short-Lived Credential:
```bash
agentwall identity create --agent financial-agent-01 --scope "file:read" --ttl 1h
```

### 2. Rotate Agent Credentials Zero-Downtime:
```bash
agentwall identity rotate --agent financial-agent-01 --drain-secs 30
```

### 3. Configure Per-Tool Scoping Rules:
```bash
agentwall identity scope --agent financial-agent-01 --tool execute_shell --deny
```

### 4. Audit Identity History & Verify Cryptographic Integrity:
```bash
agentwall identity audit --agent financial-agent-01 --verify
```

---

## 5. Troubleshooting OIDC Authorization Failures

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
* **Fix:** Verify that the client includes the Bearer token in HTTP requests.

### 2. Error: `TOKEN_EXPIRED` (401 Unauthorized)
* **Cause:** Token `exp` timestamp is in the past.
* **Fix:** Refresh the agent's JWT token from your IdP before invoking tool calls.

### 3. Error: `AUDIENCE_MISMATCH` / `ISSUER_MISMATCH`
* **Cause:** The `aud` or `iss` claim in the JWT does not match the strings specified in `identity.audience` or `identity.issuer` in `agentwall-policy.yaml`.
* **Fix:** Decode your JWT using `jwt.io` or `jq` and update `identity.issuer` and `identity.audience` to match exact string values.

### 4. Group Claims Not Matching Rules:
* **Cause:** The `group_claim_key` in policy configuration does not match the actual JSON key emitted by your IdP (e.g. using `groups` instead of `cognito:groups` or `roles`).
* **Fix:** Inspect the unencrypted JWT token payload to confirm the exact claim key name.
