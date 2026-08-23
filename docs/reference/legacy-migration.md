# Legacy Migration Guide (`AGENTWALL_*` &rarr; `AGENTCONTROL_*`)

In earlier versions (prior to v1.0.40), environment variables and binary names used the legacy `agentwall` branding. The product has standardized exclusively on `agentcontrol` and `AGENTCONTROL_*`.

---

## Environment Variable Mapping Table

| Legacy Name (`AGENTWALL_*`) | Canonical Name (`AGENTCONTROL_*`) | Notes |
|---|---|---|
| `AGENTWALL_LISTEN` | `AGENTCONTROL_LISTEN` | Gateway listen socket address |
| `AGENTWALL_POLICY_PATH` | `AGENTCONTROL_POLICY_PATH` | Path to YAML policy file |
| `AGENTCONTROL_PROXY_URL` / `AGENTWALL_PROXY_URL` | `AGENTCONTROL_PROXY_URL` | Upstream proxy URL |
| `AGENTWALL_LOG_PATH` | `AGENTCONTROL_LOG_PATH` | Path to JSONL audit log |
| `AGENTWALL_DB_PATH` | `AGENTCONTROL_DB_PATH` | Path to local SQLite event database |
| `AGENTWALL_SHADOW_MODE` | `AGENTCONTROL_SHADOW_MODE` | Observation mode toggle |
| `AGENTWALL_TOKEN` / `AGENTWALL_ENROLLMENT_TOKEN` | `AGENTCONTROL_ENROLLMENT_TOKEN` | OTET device enrollment token |
| `AGENTWALL_HUB_URL` | `AGENTCONTROL_HUB_URL` | Control Hub base URL |
| `AGENTWALL_OIDC_ISSUER` | `AGENTCONTROL_OIDC_ISSUER` | OIDC IdP issuer URL |
| `AGENTWALL_OIDC_TOKEN` | `AGENTCONTROL_OIDC_TOKEN` | Bearer token for OIDC |
| `AGENTWALL_SIEM_BACKEND` | `AGENTCONTROL_SIEM_BACKEND` | SIEM target export engine |
| `AGENTWALL_SIEM_ENDPOINT`| `AGENTCONTROL_SIEM_ENDPOINT` | External SIEM ingestion URL |
| `AGENTWALL_SIEM_TOKEN` | `AGENTCONTROL_SIEM_TOKEN` | SIEM authentication token |

---

## Binary Name Mapping

- `agentwall` &rarr; `agentcontrol`
- `agentwall protect` &rarr; `agentcontrol protect`
- `agentwall status` &rarr; `agentcontrol status`
- `agentwall verify` &rarr; `agentcontrol verify`
- `agentwall unwrap --all` &rarr; `agentcontrol unprotect`

---

## State Directory Consolidation

Previous versions stored credentials and logs across `~/.agentwall` and `~/.agent-control`.
All current versions store state exclusively in:
- **macOS / Linux:** `~/.agentcontrol/`
- **Windows:** `%USERPROFILE%\.agentcontrol\`

Uninstall scripts and migration hooks automatically inspect and purge all legacy directories.
