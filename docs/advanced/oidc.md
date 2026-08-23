# OIDC Identity Provider Binding Guide

This guide covers binding developer and agent identities to your corporate Identity Provider (IdP) via OpenID Connect (OIDC).

---

## Supported Identity Providers

- **Okta**
- **Microsoft Entra ID (Azure AD)**
- **Keycloak**
- **Auth0**
- **AWS Cognito**
- **PingIdentity**

---

## Gateway Configuration

Configure the gateway to validate JWT tokens and extract user group claims:

### Environment Variables
```bash
export AGENTCONTROL_OIDC_ISSUER="https://company.okta.com/oauth2/default"
export AGENTCONTROL_OIDC_AUDIENCE="agentcontrol-gateway"
```

### Policy Group Mapping (`agentcontrol-policy.yaml`)
```yaml
identity:
  oidc:
    issuer: "https://company.okta.com/oauth2/default"
    claims_map:
      user_id: "sub"
      groups: "groups"

groups:
  - name: "data-scientists"
    allowed_tools:
      - "read_file"
      - "execute_sql_query"

  - name: "platform-engineers"
    allowed_tools:
      - "read_file"
      - "deploy_container"
      - "execute_command"
```

---

## Running with OIDC Validation

```bash
agentcontrol start --oidc-issuer "https://company.okta.com/oauth2/default" --policy agentcontrol-policy.yaml
```
Tool calls without a valid Bearer token or from unauthorized groups are rejected with `HTTP 401 Unauthorized` / `HTTP 403 Forbidden`.
