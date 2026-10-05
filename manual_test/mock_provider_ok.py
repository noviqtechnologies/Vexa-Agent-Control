"""
Mock LLM provider that returns a valid OpenAI-compatible HTTP 200 response.
Used as the "healthy backup" provider during failover testing.

Usage:
    python mock_provider_ok.py            # listens on 127.0.0.1:9002 (default)
    python mock_provider_ok.py 9004       # custom port
"""

import json
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9002
REQUEST_COUNT = 0


class OKHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        global REQUEST_COUNT
        REQUEST_COUNT += 1

        # Read and ignore request body
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length:
            self.rfile.read(content_length)

        response = {
            "id": f"chatcmpl-backup-{REQUEST_COUNT:04d}",
            "object": "chat.completion",
            "created": 1700000000,
            "model": "gpt-4",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": f"Hello from BACKUP provider (request #{REQUEST_COUNT})"
                    },
                    "finish_reason": "stop"
                }
            ],
            "usage": {
                "prompt_tokens": 12,
                "completion_tokens": 10,
                "total_tokens": 22
            }
        }
        body = json.dumps(response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        print(f"[OK-MOCK:{PORT}] -> 200 returned for {self.path} (total served: {REQUEST_COUNT})")

    def do_GET(self):
        # Health check endpoint
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok-mock-healthy")

    def log_message(self, format, *args):
        pass  # suppress default access log noise


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", PORT), OKHandler)
    print(f"[OK-MOCK] Listening on 127.0.0.1:{PORT} — returning 200 for all POST requests")
    print(f"[OK-MOCK] Press Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n[OK-MOCK:{PORT}] Stopped. Total requests served: {REQUEST_COUNT}")
