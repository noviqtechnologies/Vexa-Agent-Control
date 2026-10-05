"""
Mock MCP server that returns valid JSON-RPC 2.0 responses.
This is what the agentcontrol MCP gateway actually proxies to — not raw OpenAI REST.

The gateway speaks JSON-RPC 2.0 upstream (MCP protocol), so the mock must also.

Usage:
    python mock_mcp_ok.py             # listens on 127.0.0.1:9002 (default)
    python mock_mcp_ok.py 9004        # custom port

Endpoints served:
    POST /            -> JSON-RPC 2.0 dispatch
    GET  /            -> health check (200 OK)
    GET  /healthz     -> health check (200 OK)
"""

import json
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9002
REQUEST_COUNT = 0


def handle_jsonrpc(payload: dict) -> dict:
    """Route JSON-RPC method calls to stub handlers."""
    method = payload.get("method", "")
    req_id = payload.get("id")

    # MCP initialize handshake
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "mock-mcp-ok", "version": "1.0.0"},
            },
        }

    # MCP tools/list
    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": [
                    {
                        "name": "test_tool",
                        "description": "A mock test tool",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"key": {"type": "string"}},
                            "required": ["key"],
                        },
                    }
                ]
            },
        }

    # MCP tools/call
    if method == "tools/call":
        global REQUEST_COUNT
        REQUEST_COUNT += 1
        tool_name = payload.get("params", {}).get("name", "unknown")
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": f"[BACKUP-MOCK:{PORT}] Tool '{tool_name}' executed successfully (call #{REQUEST_COUNT})",
                    }
                ],
                "isError": False,
            },
        }

    # notifications/initialized (no response needed, but we send one anyway for completeness)
    if method == "notifications/initialized":
        return None  # notification — no response

    # Fallback: method not found
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    }


class MCPOKHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(content_length) if content_length else b"{}"

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = {}

        method = payload.get("method", "<no method>")
        print(f"[OK-MOCK:{PORT}] <- {method}  (call #{REQUEST_COUNT + 1})")

        response = handle_jsonrpc(payload)

        if response is None:
            # Notification: send 204 No Content
            self.send_response(204)
            self.end_headers()
            return

        body = json.dumps(response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        print(f"[OK-MOCK:{PORT}] -> 200 {method} OK (total served: {REQUEST_COUNT})")

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(f"mock-mcp-ok healthy (port {PORT}, served {REQUEST_COUNT} calls)".encode())

    def log_message(self, format, *args):
        pass  # suppress default access log noise


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", PORT), MCPOKHandler)
    print(f"[OK-MOCK] MCP JSON-RPC server on 127.0.0.1:{PORT}")
    print(f"[OK-MOCK] Methods: initialize, tools/list, tools/call")
    print(f"[OK-MOCK] Press Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n[OK-MOCK:{PORT}] Stopped. Total calls served: {REQUEST_COUNT}")
