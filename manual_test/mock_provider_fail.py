"""
Mock LLM provider that always returns HTTP 503 Service Unavailable.
Used to simulate a failing/degraded upstream for failover testing.

Usage:
    python mock_provider_fail.py          # listens on 127.0.0.1:9001 (default)
    python mock_provider_fail.py 9003     # custom port
"""

import json
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9001


class FailHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.dumps({"error": {"message": "Service Unavailable", "type": "server_error", "code": 503}})
        encoded = body.encode("utf-8")
        self.send_response(503)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)
        print(f"[FAIL-MOCK:{PORT}] -> 503 returned for {self.path}")

    def do_GET(self):
        # Health check endpoint
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"failing-mock-ok")

    def log_message(self, format, *args):
        pass  # suppress default access log noise


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", PORT), FailHandler)
    print(f"[FAIL-MOCK] Listening on 127.0.0.1:{PORT} — returning 503 for all POST requests")
    print(f"[FAIL-MOCK] Press Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n[FAIL-MOCK:{PORT}] Stopped.")
