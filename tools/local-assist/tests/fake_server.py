"""A scripted loopback stand-in for llama-server's OpenAI-compatible API."""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class FakeLlamaServer:
    """Serves /v1/models and /v1/chat/completions from a queue of scripted replies.

    Each scripted reply is either a dict (sent as the completion content, JSON
    encoded), a string (sent verbatim as content), or a dict with a "__raw__"
    key describing status/body/delay behavior.
    """

    def __init__(self, model_id: str = "fireemu-local-Q4_K_M.gguf"):
        self.model_id = model_id
        self.replies: list[object] = []
        self.requests: list[dict] = []
        self._lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def _send(self, status: int, body: bytes, headers: dict | None = None):
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                outer.requests.append({"method": "GET", "path": self.path})
                if self.path == "/v1/models":
                    body = {
                        "data": [
                            {
                                "id": outer.model_id,
                                "object": "model",
                                "meta": {
                                    "n_params": 3_000_000_000,
                                    "size": 48_000_000_000,
                                    "n_ctx_train": 262144,
                                },
                            }
                        ]
                    }
                    self._send(200, json.dumps(body).encode())
                else:
                    self._send(404, b"{}")

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length)
                try:
                    payload = json.loads(raw)
                except ValueError:
                    payload = {"__invalid__": raw.decode("utf-8", "replace")}
                outer.requests.append(
                    {"method": "POST", "path": self.path, "body": payload}
                )
                if self.path != "/v1/chat/completions":
                    self._send(404, b"{}")
                    return
                with outer._lock:
                    scripted = (
                        outer.replies.pop(0)
                        if outer.replies
                        else {"findings": [], "unknowns": []}
                    )
                if isinstance(scripted, dict) and "__raw__" in scripted:
                    raw_spec = scripted["__raw__"]
                    delay = raw_spec.get("delay", 0)
                    if delay:
                        time.sleep(delay)
                    self._send(
                        raw_spec.get("status", 200),
                        raw_spec.get("body", b"{}"),
                        raw_spec.get("headers"),
                    )
                    return
                content = (
                    scripted if isinstance(scripted, str) else json.dumps(scripted)
                )
                finish = "stop"
                if isinstance(scripted, str) and scripted.startswith("__length__"):
                    content = scripted[len("__length__") :]
                    finish = "length"
                body = {
                    "id": "chatcmpl-fake",
                    "object": "chat.completion",
                    "model": outer.model_id,
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": content},
                            "finish_reason": finish,
                        }
                    ],
                    "usage": {
                        "prompt_tokens": len(json.dumps(payload)) // 4,
                        "completion_tokens": len(content) // 4,
                    },
                    "timings": {
                        "prompt_ms": 12.5,
                        "predicted_ms": 40.0,
                        "predicted_per_second": 50.0,
                    },
                }
                self._send(200, json.dumps(body).encode())

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(
            target=lambda: self._server.serve_forever(poll_interval=0.05), daemon=True
        )

    @property
    def endpoint(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}/v1/chat/completions"

    def start(self) -> FakeLlamaServer:
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)

    def posts(self) -> list[dict]:
        return [r for r in self.requests if r["method"] == "POST"]
