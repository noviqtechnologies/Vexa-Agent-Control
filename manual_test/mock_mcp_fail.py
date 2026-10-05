"""
Mock MCP server that always returns a JSON-RPC 2.0 error response (simulates failure).
Used to verify the gateway handles upstream MCP errors correctly.

Usage:
    python mock_mcp_fail.py           # listens on 127.0.0.1:9001 (default)
    python mock_mcp_fail.py 9003      # custom port
"""

import json
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9001
CALL_COUNT = 0


class MCPFailHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        global CALL_COUNT
        CALL_COUNT += 1

        content_length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(content_length) if content_length else b"{}"

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = {}

        method = payload.get("method", "<no method>")
        req_id = payload.get("id")

        print(f"[FAIL-MOCK:{PORT}] <- {method} -> returning error (call #{CALL_COUNT})")

        # Return a JSON-RPC error (internal server error)
        response = {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32603,
                "message": "Internal error: upstream MCP server unavailable",
                "data": {"simulated": True, "port": PORT},
            },
        }
        body = json.dumps(response).encode("utf-8")

        # Return HTTP 503 to also trigger gateway-level error handling
        self.send_response(503)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.send_response(503)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(f"mock-mcp-fail unhealthy (port {PORT})".encode())

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", PORT), MCPFailHandler)
    print(f"[FAIL-MOCK] MCP error server on 127.0.0.1:{PORT} — all calls return 503 + JSON-RPC error")
    print(f"[FAIL-MOCK] Press Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n[FAIL-MOCK:{PORT}] Stopped. Total calls received: {CALL_COUNT}")
