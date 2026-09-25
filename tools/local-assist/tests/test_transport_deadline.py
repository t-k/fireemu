"""Real loopback-wire regression for the transport (no model needed).

Run: uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/local-assist/tests/test_transport_deadline.py
"""

from __future__ import annotations

import contextlib
import io
import json
import math
import os
import socket
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from local_assist import transport
from local_assist.packet import PacketError, parse_packet

BODY = b'{"choices":[{"message":{"content":"ok"},"finish_reason":"stop"}]}'


CHUNKED_HEADERS = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"


def response(body=BODY, extra=b"", status=b"200 OK"):
    return (
        b"HTTP/1.1 "
        + status
        + b"\r\nContent-Length: "
        + str(len(body)).encode()
        + b"\r\n"
        + extra
        + b"\r\n"
        + body
    )


class RawServer:
    """One explicit loopback listener, finite I/O, joined on every exit path."""

    def __init__(self, chunks, *, interval=0, family=socket.AF_INET, hold=False):
        self.chunks = chunks
        self.interval = interval
        self.hold = hold
        self.stop = threading.Event()
        self.done = threading.Event()
        self.request = b""
        self.error = None
        self.conn = None
        self.listener = socket.socket(family, socket.SOCK_STREAM)
        address = "::1" if family == socket.AF_INET6 else "127.0.0.1"
        self.listener.bind((address, 0))
        self.listener.listen(1)
        self.listener.settimeout(1)
        self.port = self.listener.getsockname()[1]
        host = f"[{address}]" if family == socket.AF_INET6 else address
        self.url = f"http://{host}:{self.port}/v1/chat/completions"
        self.thread = threading.Thread(
            target=self._serve, name="test-loopback-http", daemon=True
        )

    def _serve(self):
        try:
            self.conn, _ = self.listener.accept()
            with self.conn as conn:
                conn.settimeout(1)
                while b"\r\n\r\n" not in self.request:
                    chunk = conn.recv(65536)
                    if not chunk:
                        return
                    self.request += chunk
                header, body = self.request.split(b"\r\n\r\n", 1)
                lengths = [
                    line.split(b":", 1)[1].strip()
                    for line in header.split(b"\r\n")
                    if line.lower().startswith(b"content-length:")
                ]
                size = int(lengths[0]) if lengths else 0
                while len(body) < size:
                    chunk = conn.recv(65536)
                    if not chunk:
                        return
                    self.request += chunk
                    body += chunk
                for chunk in self.chunks:
                    if self.stop.is_set():
                        return
                    conn.sendall(chunk)
                    if self.interval and self.stop.wait(self.interval):
                        return
                if self.hold:
                    self.stop.wait(2)
        except (BrokenPipeError, ConnectionResetError, TimeoutError, OSError):
            pass  # client refusal or deadline is expected for negative tests
        except BaseException as error:  # noqa: BLE001 - surfaced to the test thread
            self.error = error
        finally:
            self.done.set()

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.stop.set()
        if self.conn is not None:
            with contextlib.suppress(OSError):
                self.conn.shutdown(socket.SHUT_RDWR)
        self.listener.close()
        self.thread.join(2)
        if self.thread.is_alive():
            raise AssertionError("test server failed to stop")
        if self.error:
            raise self.error


class TransportDeadlineTests(unittest.TestCase):
    def query(self, payload, *, timeout=1, **server_options):
        with RawServer([payload], **server_options) as server:
            return transport.http_json("POST", server.url, {"messages": []}, timeout)

    def rejects(self, payload, *, status="server-error", **kwargs):
        with self.assertRaises(transport.TransportError) as caught:
            self.query(payload, **kwargs)
        self.assertEqual(caught.exception.status, status)
        return caught.exception

    def test_fixed_length_success(self):
        self.assertEqual(self.query(response()), json.loads(BODY))

    def test_chunked_success_with_trailer(self):
        wire = (
            CHUNKED_HEADERS
            + hex(len(BODY))[2:].encode()
            + b"\r\n"
            + BODY
            + b"\r\n0\r\nX-Test: yes\r\n\r\n"
        )
        self.assertEqual(self.query(wire), json.loads(BODY))

    def test_close_delimited_success(self):
        self.assertEqual(
            self.query(b"HTTP/1.0 200 OK\r\n\r\n" + BODY), json.loads(BODY)
        )

    def test_multiple_chunks_success(self):
        chunks = [BODY[:15], BODY[15:30], BODY[30:]]
        body = b"".join(f"{len(c):x}\r\n".encode() + c + b"\r\n" for c in chunks)
        self.assertEqual(
            self.query(CHUNKED_HEADERS + body + b"0\r\n\r\n"), json.loads(BODY)
        )

    def test_content_length_truncation_is_not_valid_json_success(self):
        self.rejects(
            b"HTTP/1.1 200 OK\r\nContent-Length: "
            + str(len(BODY) + 64).encode()
            + b"\r\n\r\n"
            + BODY
        )

    def test_missing_chunk_terminator_is_not_success(self):
        self.rejects(CHUNKED_HEADERS + f"{len(BODY):x}\r\n".encode() + BODY + b"\r\n")

    def test_zero_chunk_without_final_crlf_is_not_success(self):
        self.rejects(
            CHUNKED_HEADERS + f"{len(BODY):x}\r\n".encode() + BODY + b"\r\n0\r\n"
        )

    def test_partial_chunk_is_refused(self):
        self.rejects(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nFFFF\r\n" + BODY
        )

    def test_invalid_chunk_size_is_refused(self):
        self.rejects(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nNOPE\r\n" + BODY
        )

    def test_conflicting_framing_is_refused(self):
        self.rejects(response(extra=b"Transfer-Encoding: chunked\r\n"))

    def test_duplicate_length_is_refused(self):
        self.rejects(response(extra=f"Content-Length: {len(BODY)}\r\n".encode()))

    def test_invalid_length_is_refused(self):
        for length in (b"-1", b"xyz", b"12, 12", b"+12", b"9" * 6000):
            with self.subTest(length=length[:10]):
                self.rejects(
                    b"HTTP/1.1 200 OK\r\nContent-Length: " + length + b"\r\n\r\n" + BODY
                )

    def test_unsupported_transfer_encoding_is_refused(self):
        self.rejects(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n" + BODY)

    def test_empty_json_body_is_refused(self):
        self.rejects(response(b""))

    def test_json_array_is_refused(self):
        self.rejects(response(b"[]"))

    def test_invalid_utf8_is_refused(self):
        self.rejects(response(b"{\xff}"))

    def test_invalid_json_is_refused(self):
        self.rejects(response(b"not-json"))

    def test_byte_cap_is_enforced(self):
        with patch.object(transport, "MAX_RESPONSE_BYTES", len(BODY) - 1):
            self.rejects(response())
            self.rejects(b"HTTP/1.0 200 OK\r\n\r\n" + BODY)

    def test_exact_byte_cap_is_accepted(self):
        with patch.object(transport, "MAX_RESPONSE_BYTES", len(BODY)):
            self.assertEqual(self.query(response()), json.loads(BODY))

    def test_status_mapping_and_secret_free_errors(self):
        for code in (301, 302, 307, 401, 403, 429, 500, 503):
            with self.subTest(code=code):
                error = self.rejects(
                    response(b"SECRET-NOT-FOR-LOGS", status=f"{code} status".encode()),
                    status="busy" if code in (429, 503) else "server-error",
                )
                self.assertNotIn("SECRET-NOT-FOR-LOGS", str(error))

    def assertDeadline(self, chunks):
        with RawServer(chunks, interval=0.025, hold=True) as server:
            start = time.monotonic()
            with self.assertRaises(transport.TransportError) as caught:
                transport.http_json("GET", server.url, None, 0.15)
            elapsed = time.monotonic() - start
            self.assertEqual(caught.exception.status, "timeout")
            self.assertLess(elapsed, 0.65, f"deadline overrun: {elapsed}")

    def test_status_line_drip_obeys_total_deadline(self):
        self.assertDeadline([b"H"] + [b"T"] * 48)

    def test_header_drip_obeys_total_deadline(self):
        self.assertDeadline(
            [b"HTTP/1.1 200 OK\r\nX-Slow: "]
            + [b"x"] * 48
            + [b"\r\nContent-Length: 2\r\n\r\n{}"]
        )

    def test_body_drip_obeys_total_deadline(self):
        self.assertDeadline(
            [b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n"] + [b" "] * 48
        )

    def test_chunk_size_drip_obeys_total_deadline(self):
        self.assertDeadline(
            [b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"] + [b"0"] * 48
        )

    def test_trailer_drip_obeys_total_deadline(self):
        self.assertDeadline(
            [CHUNKED_HEADERS + b"2\r\n{}\r\n0\r\nX-Trailer: "] + [b"x"] * 48
        )

    def test_interim_status_drip_obeys_total_deadline(self):
        self.assertDeadline([b"HTTP/1.1 100 Continue\r\n\r\n"] * 48)

    def test_regular_interim_response_is_accepted(self):
        self.assertEqual(
            self.query(b"HTTP/1.1 100 Continue\r\n\r\n" + response()),
            json.loads(BODY),
        )

    def test_no_reply_times_out(self):
        with RawServer([], hold=True) as server:
            with self.assertRaises(transport.TransportError) as caught:
                transport.http_json("GET", server.url, None, 0.1)
            self.assertEqual(caught.exception.status, "timeout")

    def test_complete_message_does_not_wait_for_eof(self):
        with RawServer([response()], hold=True) as server:
            start = time.monotonic()
            self.assertEqual(
                transport.http_json("GET", server.url, None, 0.5), json.loads(BODY)
            )
            self.assertLess(time.monotonic() - start, 0.5)

    def test_no_background_watchdog_or_reader_survives(self):
        before = {t.ident for t in threading.enumerate()}
        self.test_header_drip_obeys_total_deadline()
        self.assertEqual({t.ident for t in threading.enumerate()}, before)

    def test_descriptor_not_leaked_on_success_or_error(self):
        fd_dir = Path("/proc/self/fd")
        if not fd_dir.is_dir():
            self.skipTest("Linux fd-count check; socket-close tested elsewhere")
        before = len(list(fd_dir.iterdir()))
        for _ in range(10):
            self.query(response())
            self.rejects(response(b"invalid"))
        self.assertEqual(len(list(fd_dir.iterdir())), before)

    def test_localhost_uses_literal_loopback_without_dns(self):
        with (
            RawServer([response()]) as server,
            patch.object(
                socket, "getaddrinfo", side_effect=AssertionError("DNS forbidden")
            ),
        ):
            url = server.url.replace("127.0.0.1", "localhost")
            self.assertEqual(transport.http_json("GET", url, None, 1), json.loads(BODY))

    def test_ipv6_loopback(self):
        try:
            server = RawServer([response()], family=socket.AF_INET6)
        except OSError:
            self.skipTest("IPv6 loopback unavailable")
        with (
            server,
            patch.object(
                socket, "getaddrinfo", side_effect=AssertionError("DNS forbidden")
            ),
        ):
            self.assertEqual(
                transport.http_json("GET", server.url, None, 1), json.loads(BODY)
            )

    def test_proxies_and_ambient_credentials_are_not_used(self):
        with (
            RawServer([response()]) as server,
            patch.dict(
                os.environ,
                {
                    "HTTP_PROXY": "http://192.0.2.1:1",
                    "ALL_PROXY": "http://192.0.2.1:1",
                    "ANTHROPIC_API_KEY": "CLOUD-SECRET",
                    "GOOGLE_APPLICATION_CREDENTIALS": "/private/credential",
                },
            ),
        ):
            transport.http_json("GET", server.url, None, 1)
            self.assertNotIn(b"CLOUD-SECRET", server.request)
            self.assertNotIn(b"Authorization:", server.request)

    def test_explicit_key_and_utf8_payload_are_sent_once(self):
        with RawServer([response()]) as server:
            transport.http_json(
                "POST", server.url, {"message": "日本語"}, 1, api_key="LOCAL-ONLY"
            )
            header, raw = server.request.split(b"\r\n\r\n", 1)
            self.assertIn(b"Authorization: Bearer LOCAL-ONLY", header)
            self.assertEqual(json.loads(raw), {"message": "日本語"})
            self.assertIn(f"Content-Length: {len(raw)}".encode(), header)

    def test_nonloopback_and_redirect_inputs_rejected_before_socket(self):
        with patch.object(
            socket, "socket", side_effect=AssertionError("must not connect")
        ):
            for url in (
                "http://192.0.2.1:1/x",
                "https://127.0.0.1:1/x",
                "http://user:key@127.0.0.1/x",
                "http://127.0.0.1/x?token=bad",
            ):
                with self.subTest(url=url), self.assertRaises(PacketError):
                    transport.http_json("GET", url, None, 1)

    def test_invalid_timeout_rejected_before_socket(self):
        with patch.object(
            socket, "socket", side_effect=AssertionError("must not connect")
        ):
            for timeout in (
                float("nan"),
                float("inf"),
                -float("inf"),
                0,
                -1,
                True,
                "1",
                10**500,
            ):
                with (
                    self.subTest(timeout=repr(timeout)),
                    self.assertRaises(transport.TransportError),
                ):
                    transport.http_json("GET", "http://127.0.0.1:1/x", None, timeout)

    def test_invalid_port_method_or_key_rejected_before_socket(self):
        with patch.object(
            socket, "socket", side_effect=AssertionError("must not connect")
        ):
            for url in (
                "http://127.0.0.1:0/x",
                "http://127.0.0.1:65536/x",
                "http://127.0.0.1:x/x",
            ):
                with self.subTest(url=url), self.assertRaises(transport.TransportError):
                    transport.http_json("GET", url, None, 1)
            for key in ("x\r\nInjected: yes", "非ASCII", "", "a" * 513):
                with (
                    self.subTest(key=key[:10]),
                    self.assertRaises(transport.TransportError),
                ):
                    transport.http_json(
                        "GET", "http://127.0.0.1:1/x", None, 1, api_key=key
                    )
            with self.assertRaises(transport.TransportError):
                transport.http_json("GET\r\nInjected", "http://127.0.0.1:1/x", None, 1)

    def test_errors_do_not_print_secret(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            error = self.rejects(response(b"SECRET-INVALID-JSON"))
        self.assertEqual(output.getvalue(), "")
        self.assertNotIn("SECRET", str(error))


class PacketDeadlineTests(unittest.TestCase):
    def packet(self, value):
        return {
            "taskId": "TEST-1",
            "kind": "classify-log",
            "repoRoot": "/tmp/repo",
            "baseCommit": "a" * 40,
            "question": "Classify",
            "inputs": [{"path": "test.txt", "startLine": 1, "endLine": 2}],
            "maxFindings": 5,
            "maxOutputTokens": 100,
            "deadlineSeconds": value,
        }

    def test_nan_deadline_rejected(self):
        with self.assertRaises(PacketError):
            parse_packet(self.packet(math.nan))

    def test_infinite_negative_zero_and_boolean_deadlines_rejected(self):
        for value in (math.inf, -math.inf, -1, 0, True, 901):
            with self.subTest(value=value), self.assertRaises(PacketError):
                parse_packet(self.packet(value))

    def test_valid_deadline_boundaries(self):
        for value in (0.001, 1, 120, 900):
            self.assertEqual(
                parse_packet(self.packet(value)).deadlineSeconds, float(value)
            )


if __name__ == "__main__":
    unittest.main()
