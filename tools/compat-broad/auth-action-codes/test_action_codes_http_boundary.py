"""The real stdlib HTTP sender is local, bounded and never follows redirects."""
from __future__ import annotations

import contextlib
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import action_codes_collector as module


@contextlib.contextmanager
def endpoint():
    calls = []
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            calls.append(self.path)
            payload = b'{"users":[]}'
            status, length = 200, len(payload)
            if self.path == "/short": length = 2000
            if self.path == "/oversize": payload = b'{"x":"' + b'x'*65536 + b'"}'; length=len(payload)
            if self.path == "/invalid": payload=b'oops'; status=400; length=len(payload)
            if self.path == "/array": payload=b'[]'; length=len(payload)
            if self.path == "/redirect": status=307
            self.send_response(status)
            if status == 307: self.send_header("Location", "/target")
            self.send_header("Content-Length", str(length))
            self.send_header("Connection", "close"); self.end_headers()
            self.wfile.write(payload); self.close_connection=True
        def log_message(self, *_): pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try: yield f"http://127.0.0.1:{server.server_port}", calls
    finally: server.shutdown(); server.server_close(); thread.join(timeout=2); assert not thread.is_alive()


@pytest.mark.parametrize("route", ["short", "oversize", "invalid", "array", "redirect"])
def test_wire_rejects_incomplete_unbounded_or_redirected_results(route):
    with endpoint() as (origin, calls):
        with pytest.raises(module.CollectorError):
            module._http_send("POST", origin+"/"+route, {}, {})
        assert calls == ["/"+route]


def test_wire_success_remains_a_typed_object():
    with endpoint() as (origin, calls):
        assert module._http_send("POST", origin+"/target", {}, {}) == (200, {"users": []})
        assert calls == ["/target"]


def test_inherited_proxy_configuration_is_never_consulted(monkeypatch):
    def unexpected(): raise AssertionError("proxy discovery must not run")
    monkeypatch.setattr(module.urllib.request, "getproxies", unexpected)
    module.http_opener()
