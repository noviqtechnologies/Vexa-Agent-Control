# SIEM Integration & Audit Log Forwarding

This guide covers streaming tamper-evident AI agent audit logs to enterprise SIEM platforms (Splunk, Datadog, OpenSearch, AWS CloudWatch).

---

## Supported Backends

- **Splunk HEC (HTTP Event Collector)**
- **Datadog Logs API**
- **OpenSearch / Elasticsearch**
- **Generic Syslog / Webhook**

---

## Configuring SIEM Forwarding

### Splunk HEC Example
```bash
export AGENTCONTROL_SIEM_BACKEND="splunk"
export AGENTCONTROL_SIEM_ENDPOINT="https://splunk.internal.corp:8088/services/collector"
export AGENTCONTROL_SIEM_TOKEN="00000000-0000-0000-0000-000000000000"

agentcontrol start --policy agentcontrol-policy.yaml
```

### Datadog Example
```bash
export AGENTCONTROL_SIEM_BACKEND="datadog"
export AGENTCONTROL_SIEM_ENDPOINT="https://http-intake.logs.datadoghq.com/api/v2/logs"
export AGENTCONTROL_SIEM_TOKEN="<DATADOG_API_KEY>"

agentcontrol start --policy agentcontrol-policy.yaml
```

---

## Tamper-Evident HMAC Chaining

Every audit log entry contains an HMAC cryptographic chain:
```json
{
  "event_id": "evt_01J7...",
  "timestamp": "2026-08-23T12:00:00Z",
  "agent_id": "claude-desktop",
  "tool": "execute_command",
  "verdict": "DENY",
  "prev_hash": "a1b2c3d4...",
  "hmac_sig": "e5f6g7h8..."
}
```

To verify log integrity offline:
```bash
agentcontrol verify-log ~/.agentcontrol/audit.jsonl
```
