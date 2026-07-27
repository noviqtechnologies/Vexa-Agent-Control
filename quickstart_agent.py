import os
import json
import urllib.request
import urllib.error
import sys
import time
import uuid

# Ensure UTF-8 output on Windows terminals
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

def send_request(url, payload, headers=None):
    if headers is None:
        headers = {"Content-Type": "application/json"}
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            code = response.getcode()
            raw = response.read().decode("utf-8").strip()
            body = json.loads(raw) if raw else {"status": "ok"}
            return code, body
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8").strip() if e.fp else ""
        try:
            body = json.loads(raw) if raw else {"error": str(e)}
        except Exception:
            body = {"error": raw or str(e)}
        return e.code, body
    except Exception as e:
        return 0, {"error": str(e)}

def main():
    proxy_url = os.environ.get("AGENTWALL_PROXY_URL", "http://127.0.0.1:8443")
    dashboard_api_url = os.environ.get("DASHBOARD_API_URL", "http://127.0.0.1:8081/api/v1/ingest")
    gateway_secret = os.environ.get("GATEWAY_SECRET", "local-dev-shared-secret-change-me")
    ingest_headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {gateway_secret}"
    }

    print("============================================================")
    print(" 🚀 AgentWall Complete Functionality Demonstration Agent")
    print("============================================================")
    print(f"Proxy Endpoint    : {proxy_url}")
    print(f"Dashboard Ingest  : {dashboard_api_url}")
    print("------------------------------------------------------------\n")

    # ------------------------------------------------------------------
    # 1. MCP Proxy Tool Calls (Populates Fleet Overview & Policy Engine)
    # ------------------------------------------------------------------
    print("Step 1: Executing MCP Tool Calls through Security Proxy...")
    print("-" * 50)
    calls = [
        {"id": 1, "name": "read_file", "args": {"path": "README.md"}, "note": "Safe file read operation"},
        {"id": 2, "name": "list_directory", "args": {"directory": "."}, "note": "Directory discovery"},
        {"id": 3, "name": "exec_shell", "args": {"command": "rm -rf /"}, "note": "High-risk shell command (Anomaly)"},
        {"id": 4, "name": "write_file", "args": {"path": "test.txt", "content": "Vexa security audit"}, "note": "State mutation operation"},
        {"id": 5, "name": "configure_settings", "args": {"options": {"theme": "dark", "retries": 3}}, "note": "JSON Schema object validation"}
    ]

    for c in calls:
        print(f"[AGENT] Calling tool: {c['name']} | Purpose: {c['note']}")
        code, res = send_request(proxy_url, {
            "jsonrpc": "2.0",
            "id": c["id"],
            "method": "tools/call",
            "params": {"name": c["name"], "arguments": c["args"]}
        })
        if code == 200 and "error" not in res:
            print("        Result: ✅ ALLOWED by Gateway")
        else:
            errMsg = res.get("error", {}).get("message", res.get("error"))
            print(f"        Result: 🚫 BLOCKED/POLICY ENFORCED ({errMsg})")
        print()

    # ------------------------------------------------------------------
    # 2. Identity & Credential Governance (Populates Agent Identity Tab)
    # ------------------------------------------------------------------
    print("\nStep 2: Registering Agent Identity & Credential Governance Metadata...")
    print("-" * 50)
    now_ms = int(time.time() * 1000)

    credentials = [
        {
            "credential_id": f"cred-oidc-{uuid.uuid4().hex[:8]}",
            "agent_id": "agent-dev-01",
            "scope": ["read:workspace", "write:logs", "exec:safe_tools"],
            "ttl_seconds": 3600,
            "created_at_ms": now_ms,
            "expires_at_ms": now_ms + 3600000,
            "rotation_history": [{"rotated_at_ms": now_ms - 1800000, "reason": "scheduled_rotation"}]
        },
        {
            "credential_id": f"cred-vault-{uuid.uuid4().hex[:8]}",
            "agent_id": "agent-sec-bot",
            "scope": ["read:sensitive", "audit:write"],
            "ttl_seconds": 7200,
            "created_at_ms": now_ms,
            "expires_at_ms": now_ms + 7200000,
            "rotation_history": []
        }
    ]

    for cred in credentials:
        print(f"[IDENTITY] Registering short-lived credential for '{cred['agent_id']}'...")
        code, _ = send_request(f"{dashboard_api_url}/credentials", cred, ingest_headers)
        if code in (200, 201):
            print(f"           Result: ✅ Credential '{cred['credential_id']}' registered successfully.")
        else:
            print(f"           Result: ⚠️ Ingest response code {code}")

    # ------------------------------------------------------------------
    # 3. Threat Intelligence & Security Alerts (Populates Threat Intel & Alert Feed)
    # ------------------------------------------------------------------
    print("\nStep 3: Ingesting Threat Intelligence Findings & Security Alerts...")
    print("-" * 50)

    threat_alerts = [
        {
            "alert_id": str(uuid.uuid4()),
            "severity": "critical",
            "event": {
                "event_id": str(uuid.uuid4()),
                "timestamp_ms": now_ms - 2000,
                "session_id": "sess-threat-101",
                "agent_id": "agent-sec-bot",
                "tool_name": "exec_shell",
                "decision": "denied",
                "dlp_findings": [{"category": "CREDENTIAL", "pattern_name": "AWS_SECRET_ACCESS_KEY", "count": 1}],
                "injection_findings": [{"pattern_name": "PROMPT_INJECTION_OVERRIDE", "count": 1}],
                "semantic_findings": [{"anomaly_score": 0.98, "finding_type": "UNAUTHORIZED_COMMAND"}]
            }
        },
        {
            "alert_id": str(uuid.uuid4()),
            "severity": "warning",
            "event": {
                "event_id": str(uuid.uuid4()),
                "timestamp_ms": now_ms - 1000,
                "session_id": "sess-threat-102",
                "agent_id": "agent-dev-01",
                "tool_name": "write_file",
                "decision": "warned",
                "dlp_findings": [{"category": "PII", "pattern_name": "EMAIL_ADDRESS", "count": 3}],
                "injection_findings": [],
                "semantic_findings": []
            }
        }
    ]

    for alert in threat_alerts:
        sev = alert["severity"].upper()
        agent = alert["event"]["agent_id"]
        tool = alert["event"]["tool_name"]
        print(f"[THREAT] Emitting [{sev}] Alert for Agent '{agent}' on tool '{tool}'...")
        code, _ = send_request(f"{dashboard_api_url}/alerts", alert, ingest_headers)
        if code in (200, 201):
            print(f"         Result: ✅ Alert '{alert['alert_id'][:8]}' ingested live into Threat Intelligence.")
        else:
            print(f"         Result: ⚠️ Ingest response code {code}")

    print("\n============================================================")
    print(" 🎉 All AgentWall Demonstration Workflows Completed!")
    print("============================================================")
    print("Next step: Refresh http://localhost:8081/ to inspect:")
    print("  • Fleet Overview & Live Alert Feed")
    print("  • Agent Identity & Credentials Governance")
    print("  • Audit Logs & Threat Intelligence (DLP / Prompt Injections)")
    print("============================================================\n")

if __name__ == "__main__":
    main()
