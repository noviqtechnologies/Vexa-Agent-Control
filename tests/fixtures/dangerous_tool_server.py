#!/usr/bin/env python3
"""
Dangerous Tool Fixture Server (Phase 0b Deliverable)
Simulates side-effecting tools with configurable failure modes, idempotency tracking,
and crash reconciliation capabilities.
"""

import sys
import json
import argparse

class DangerousToolServer:
    def __init__(self, simulate_crash_on_tool=None):
        self.simulate_crash_on_tool = simulate_crash_on_tool
        self.executed_idempotency_keys = set()

    def handle_request(self, request_json):
        method = request_json.get("method")
        params = request_json.get("params", {})
        tool_name = params.get("name")
        idempotency_key = params.get("idempotency_key")

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": request_json.get("id"),
                "result": {
                    "tools": [
                        {
                            "name": "write_restricted_file",
                            "description": "Writes to a path requiring strict HITL approval",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
                                "required": ["path", "content"]
                            }
                        },
                        {
                            "name": "execute_shell_command",
                            "description": "Executes shell commands with side effects",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"command": {"type": "string"}},
                                "required": ["command"]
                            }
                        },
                        {
                            "name": "cloud_delete_resource",
                            "description": "Deletes cloud infrastructure resources",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"resource_id": {"type": "string"}},
                                "required": ["resource_id"]
                            }
                        }
                    ]
                }
            }

        elif method == "tools/call":
            if tool_name == self.simulate_crash_on_tool:
                # Simulate unhandled process crash during side effect execution
                sys.stderr.write(f"[FAULT INJECTION] Process crashed during execution of {tool_name}\n")
                sys.exit(137)

            if idempotency_key and idempotency_key in self.executed_idempotency_keys:
                return {
                    "jsonrpc": "2.0",
                    "id": request_json.get("id"),
                    "result": {
                        "content": [{"type": "text", "text": f"Idempotent replay: {tool_name} already executed."}],
                        "idempotency_key": idempotency_key,
                        "replayed": True
                    }
                }

            if idempotency_key:
                self.executed_idempotency_keys.add(idempotency_key)

            return {
                "jsonrpc": "2.0",
                "id": request_json.get("id"),
                "result": {
                    "content": [{"type": "text", "text": f"Successfully executed {tool_name} with side effect."}],
                    "idempotency_key": idempotency_key,
                    "replayed": False
                }
            }

        return {
            "jsonrpc": "2.0",
            "id": request_json.get("id"),
            "error": {"code": -32601, "message": f"Method {method} not found"}
        }

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Dangerous Tool Mock Server")
    parser.add_argument("--crash-on", default=None, help="Tool name that triggers a simulated crash")
    args = parser.parse_args()

    server = DangerousToolServer(simulate_crash_on_tool=args.crash_on)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            res = server.handle_request(req)
            sys.stdout.write(json.dumps(res) + "\n")
            sys.stdout.flush()
        except Exception as e:
            sys.stderr.write(f"Error handling request: {e}\n")
