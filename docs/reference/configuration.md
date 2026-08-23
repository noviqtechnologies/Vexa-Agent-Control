# Configuration & Environment Variables Reference

Authoritative reference for `agentcontrol-policy.yaml` Schema v2, threat detectors, and all `AGENTCONTROL_*` environment variables.

---

## Canonical Environment Variables

All environment variables follow the canonical `AGENTCONTROL_*` prefix:

| Variable | Description | Default |
|---|---|---|
| `AGENTCONTROL_LISTEN` | Gateway listen address | `127.0.0.1:8080` |
| `AGENTCONTROL_POLICY_PATH` | Path to YAML policy file | `agentcontrol-policy.yaml` |
| `AGENTCONTROL_LOG_PATH` | Path to durable JSONL audit log | `~/.agentcontrol/audit.jsonl` |
| `AGENTCONTROL_DB_PATH` | Path to local SQLite event database | `~/.agentcontrol/events.db` |
| `AGENTCONTROL_PROXY_URL` | Upstream proxy URL for custom agents | `http://127.0.0.1:8080` |
| `AGENTCONTROL_SHADOW_MODE` | Observation mode (log without blocking) | `false` |
| `AGENTCONTROL_ENROLLMENT_TOKEN` | One-Time Enrollment Token (OTET) | — |
| `AGENTCONTROL_HUB_URL` | Control Hub base URL | `https://console.vexasec.io` |
| `AGENTCONTROL_OIDC_ISSUER` | OIDC IdP Issuer URL | — |
| `AGENTCONTROL_OIDC_TOKEN` | Bearer token for OIDC validation | — |
| `AGENTCONTROL_SIEM_BACKEND` | SIEM target (`splunk`, `datadog`, `opensearch`, `local`) | `local` |
| `AGENTCONTROL_SIEM_ENDPOINT`| External SIEM log ingestion endpoint | — |
| `AGENTCONTROL_SIEM_TOKEN`   | SIEM API authentication token | — |
| `AGENTCONTROL_TLS_CERT`     | Path to TLS certificate PEM | — |
| `AGENTCONTROL_TLS_KEY`      | Path to TLS private key PEM | — |

*(For legacy `AGENTWALL_*` aliases, see the [Legacy Migration Guide](legacy-migration.md)).*

---

## Policy Schema v2 (`agentcontrol-policy.yaml`)

```yaml
version: "2.0"
mode: "enforce" # "enforce" or "shadow"

default_verdict: "deny" # Default-deny security posture

# Global DLP Secret Detectors
dlp:
  enabled: true
  rules:
    - id: "DLP-01-AWS-KEYS"
      description: "Block AWS Access and Secret Keys"
      pattern: "(?i)(AKIA[0-9A-Z]{16}|aws_secret_access_key)"
      action: "deny"

    - id: "DLP-02-OPENAI-KEYS"
      description: "Block OpenAI API Keys"
      pattern: "sk-[a-zA-Z0-9]{48}"
      action: "deny"

    - id: "DLP-03-PRIVATE-KEYS"
      description: "Block RSA/DSA/EC Private Keys"
      pattern: "-----BEGIN [A-Z]+ PRIVATE KEY-----"
      action: "deny"

    - id: "DLP-04-ENV-FILES"
      description: "Block reading .env and credentials files"
      file_patterns:
        - "**/.env*"
        - "**/.aws/credentials"
        - "**/.ssh/id_*"
      action: "deny"

# Tool-Specific Allow Rules
tools:
  - name: "read_file"
    action: "allow"
    constraints:
      path:
        must_not_match:
          - "**/.env"
          - "**/.ssh/*"
          - "**/secrets.json"

  - name: "list_dir"
    action: "allow"

  - name: "execute_command"
    action: "deny" # Dangerous tools blocked by default
```
