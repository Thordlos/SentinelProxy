#!/usr/bin/env python3
"""Mock LLM upstream for SentinelProxy integration test."""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        print(f"[MOCK] {format % args}")

    def do_POST(self):
        if self.path == "/v1/chat/completions":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")
            print(f"[MOCK] received body length: {len(body)}, body: {body[:200]}", file=sys.stderr)
            if not body:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"empty body")
                return
            data = json.loads(body)
            messages = data.get("messages", [])
            user_msg = ""
            for m in messages:
                if m.get("role") == "user":
                    user_msg = m.get("content", "")
                    break

            print(f"[MOCK] received user message: {user_msg}", file=sys.stderr)

            stream = data.get("stream", False)
            model = data.get("model", "deepseek-chat")

            if stream:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()

                # Echo back the user message in chunks, simulating placeholder reference
                reply = f"收到你的信息：{user_msg}"
                # Split into chunks to test streaming unmasking
                chunks = [reply[i:i+4] for i in range(0, len(reply), 4)]
                for chunk in chunks:
                    event = {
                        "id": "chatcmpl-test",
                        "object": "chat.completion.chunk",
                        "created": 1700000000,
                        "model": model,
                        "choices": [
                            {
                                "index": 0,
                                "delta": {"role": "assistant", "content": chunk},
                                "finish_reason": None,
                            }
                        ],
                    }
                    self.wfile.write(f"data: {json.dumps(event, ensure_ascii=False)}\n\n".encode("utf-8"))

                # Final chunk
                final = {
                    "id": "chatcmpl-test",
                    "object": "chat.completion.chunk",
                    "created": 1700000000,
                    "model": model,
                    "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
                }
                self.wfile.write(f"data: {json.dumps(final, ensure_ascii=False)}\n\n".encode("utf-8"))
                self.wfile.write(b"data: [DONE]\n\n")
            else:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                resp = {
                    "id": "chatcmpl-test",
                    "object": "chat.completion",
                    "created": 1700000000,
                    "model": model,
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": f"收到你的信息：{user_msg}"},
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
                }
                self.wfile.write(json.dumps(resp, ensure_ascii=False).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 9999), Handler)
    print("[MOCK] Server started on http://127.0.0.1:9999", file=sys.stderr)
    server.serve_forever()
