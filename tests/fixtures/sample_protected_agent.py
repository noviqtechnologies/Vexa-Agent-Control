#!/usr/bin/env python3
"""
Sample Protected Agent (Phase 0b Deliverable)
Demonstrates a multi-turn agent that executes through the local gateway (127.0.0.1:18080),
handling W3C traceparents, prompt submissions, and MCP tool call governance.
"""

import sys
import json
import urllib.request
import urllib.error

class ProtectedAgent:
    def __init__(self, gateway_url="http://127.0.0.1:18080"):
        self.gateway_url = gateway_url
        self.trace_id = "4bf92f3577b34da6a3ce929d0e0e4736"
        self.run_id = "b1b9e837-1234-4567-89ab-cdef01234567"

    def run_step(self, user_goal):
        headers = {
            "Content-Type": "application/json",
            "traceparent": f"00-{self.trace_id}-00f067aa0ba902b7-01",
            "X-Run-ID": self.run_id,
            "Authorization": "Bearer sk-vex-sample-test-key",
        }

        payload = {
            "model": "gpt-4o",
            "messages": [
                {"role": "system", "content": "You are a protected developer assistant."},
                {"role": "user", "content": user_goal}
            ]
        }

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(f"{self.gateway_url}/v1/chat/completions", data=data, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                status = response.getcode()
                body = json.loads(response.read().decode("utf-8"))
                return status, body
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8")
            return e.code, json.loads(raw) if raw.startswith("{") else {"error": raw}
        except Exception as e:
            return 0, {"error": str(e)}

if __name__ == "__main__":
    agent = ProtectedAgent()
    print("[SAMPLE AGENT] Initialized with W3C Trace Context:")
    print(f"  Trace ID: {agent.trace_id}")
    print(f"  Run ID:   {agent.run_id}")
    print(f"  Gateway:  {agent.gateway_url}")
