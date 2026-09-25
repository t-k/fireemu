"""Loopback regressions for HTTP framing and absolute header deadlines."""

from __future__ import annotations

import contextlib
import socketserver
import threading
import time

import pytest

from test_credential_prep import prep


@contextlib.contextmanager
def raw_server(scenario: str):
    stop = threading.Event()
    state = {"scenario": scenario, "requests": 0, "sentBodyBytes": 0}

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.connection.settimeout(5)
            while True:
                line = self.rfile.readline(65537)
                if not line or line == b"\r\n":
                    break
            state["requests"] += 1
            try:
                if scenario == "trickling_headers":
                    self.wfile.write(b"HTTP/1.1 200 OK\r\nX-Slow: ")
                    self.wfile.flush()
                    for _ in range(30):
                        self.wfile.write(b"a")
                        self.wfile.flush()
                        if stop.wait(0.1):
                            return
                    self.wfile.write(
                        b"\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"
                    )
                    self.wfile.flush()
                    return

                headers = b"HTTP/1.1 200 OK\r\n"
                if scenario.startswith("dual_"):
                    headers += b"Transfer-Encoding: chunked\r\nContent-Length: 2\r\n"
                elif scenario == "chunked_success":
                    headers += b"Transfer-Encoding: chunked\r\n"
                else:
                    headers += b"Content-Length: 2\r\n"
                self.wfile.write(headers + b"Connection: close\r\n\r\n")
                if scenario == "fixed_success":
                    self.wfile.write(b"{}")
                    state["sentBodyBytes"] = 2
                else:
                    self.wfile.write(b"2\r\n{}\r\n")
                    state["sentBodyBytes"] = 2
                    if scenario == "dual_truncated":
                        return
                    if scenario == "dual_trailing":
                        self.wfile.write(b"1\r\nx\r\n0\r\n\r\n")
                        state["sentBodyBytes"] += 1
                    elif scenario == "dual_oversize":
                        payload = b"x" * 17000
                        self.wfile.write(
                            f"{len(payload):x}\r\n".encode()
                            + payload
                            + b"\r\n0\r\n\r\n"
                        )
                        state["sentBodyBytes"] += len(payload)
                    else:
                        self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, TimeoutError):
                pass

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    server = Server(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", state
    finally:
        stop.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()


@pytest.mark.parametrize(
    "scenario", ["dual_truncated", "dual_trailing", "dual_oversize"]
)
@pytest.mark.parametrize("private", [False, True], ids=["http-call", "worker-call"])
def test_conflicting_framing_is_never_accepted(scenario, private):
    module = prep()
    with raw_server(scenario) as (origin, state):
        if private:
            result = module._private_request(
                "tokeninfo", "synthetic-review-token", fixture_origin=origin, deadline=2
            )
        else:
            result = module._http_request(
                "tokeninfo",
                "synthetic-review-token",
                fixture_origin=origin,
                timeout=0.5,
            )
    assert state["requests"] == 1
    assert result["complete"] is False, result


def test_trickling_headers_report_header_timeout_before_worker_kill():
    module = prep()
    with raw_server("trickling_headers") as (origin, state):
        started = time.monotonic()
        result = module._private_request(
            "tokeninfo", "synthetic-review-token", fixture_origin=origin, deadline=2
        )
        elapsed = time.monotonic() - started
    assert state["requests"] == 1
    assert elapsed < 2
    assert result["complete"] is False
    assert result["workerReaped"] is True
    assert result.get("failure") == "headers-timeout", result
    assert result.get("phase") == "headers", result


@pytest.mark.parametrize("scenario", ["fixed_success", "chunked_success"])
def test_single_framing_controls_remain_successful(scenario):
    module = prep()
    with raw_server(scenario) as (origin, state):
        result = module._private_request(
            "tokeninfo", "synthetic-review-token", fixture_origin=origin, deadline=2
        )
    assert state["requests"] == 1
    assert result["complete"] is True, result
    assert result["body"] == {}
