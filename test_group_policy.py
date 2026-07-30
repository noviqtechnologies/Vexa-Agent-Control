#!/usr/bin/env python3
"""
Cross-Platform Test Script for AgentWall Group Policy & Spend Caps
-------------------------------------------------------------------
Runs across Windows, macOS, and Linux using Python standard library (no pip dependencies required).
Simulates an agent sending requests through AgentWall Gateway with Group claims.
"""

import os
import sys
import json
import base64
import urllib.request
import urllib.error

# Ensure UTF-8 output on Windows terminals
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

def create_dev_jwt(sub="agent-001", groups=None):
    """Generate a lightweight unverified JWT token for DEV_MODE authentication."""
    if groups is None:
        groups = ["engineering"]
    
    header = {"alg": "none", "typ": "JWT"}
    payload = {
        "sub": sub,
        "groups": groups,
        "iss": "mock-oidc",
        "aud": "agentwall"
    }
    
    def b64url(data):
        return base64.urlsafe_b64encode(json.dumps(data).encode("utf-8")).decode("utf-8").rstrip("=")
    
    return f"{b64url(header)}.{b64url(payload)}."

def send_tool_call(gateway_url, jwt_token, tool_name, params, request_id=1):
    """Sends a JSON-RPC tool call through the AgentWall Gateway."""
    payload = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": params
        },
        "id": request_id
    }
    
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {jwt_token}"
    }
    
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(gateway_url, data=data, headers=headers)
    
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
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
    gateway_url = os.environ.get("AGENTWALL_GATEWAY_URL", "http://127.0.0.1:8080")
    group_name = os.environ.get("AGENT_GROUP", "engineering")
    agent_id = os.environ.get("AGENT_ID", "agent-engineering-01")
    
    # Generate dev token containing the requested group claims
    token = create_dev_jwt(sub=agent_id, groups=[group_name])

    print("\n" + "=" * 60)
    print(" 🛡️ AgentWall Group Policy & Spend Caps Verification Test")
    print("=" * 60)
    print(f" OS Platform    : {sys.platform}")
    print(f" Target Gateway : {gateway_url}")
    print(f" Agent ID       : {agent_id}")
    print(f" Claim Groups   : {['engineering']}")
    print("=" * 60 + "\n")

    # ------------------------------------------------------------------
    # Test 1: Allowed Tool Call (read_file)
    # ------------------------------------------------------------------
    print("🧪 Test 1: Calling 'read_file' (Allowed globally)")
    code, body = send_tool_call(gateway_url, token, "read_file", {"path": "README.md"}, request_id=1)
    
    if code in (200, 201):
        print(f"   [PASS] Status: {code} OK — Request allowed as expected.")
    else:
        print(f"   [RESULT] Status: {code} — Response: {json.dumps(body)}")

    print("-" * 60)

    # ------------------------------------------------------------------
    # Test 2: Group Policy Restricted Tool Call (exec_shell)
    # ------------------------------------------------------------------
    print(f"🧪 Test 2: Calling 'exec_shell' (Restricted for group '{group_name}')")
    code, body = send_tool_call(gateway_url, token, "exec_shell", {"command": "whoami"}, request_id=2)
    
    if code in (402, 403):
        print(f"   [PASS] Status: {code} Forbidden — Correctly BLOCKED by Group Policy!")
    elif code in (200, 201):
        print(f"   [ALERT] Status: {code} OK — Request passed. Check if '{group_name}' Group Policy is active.")
    else:
        print(f"   [RESULT] Status: {code} — Response: {json.dumps(body)}")

    print("=" * 60)
    print(" Verification Complete! Check Audit Logs in Dashboard at http://localhost:3000\n")

if __name__ == "__main__":
    main()
