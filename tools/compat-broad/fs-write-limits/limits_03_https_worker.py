"""Source bytes executed by the fixed FS-WRITE-LIMITS-03 HTTPS process exchange.

A copy of the request-byte lane's worker, scoped to this campaign: the only
paths it will send are the owned `oracle/{nonce}/limits-03` namespace and the
`:batchWrite` method of the fixed production database, and the only methods are
the four the compiled plan uses. It reads one private message and one body on
stdin, never argv or the environment, and frames the response back on stdout.
"""

import http.client
import json
import re
import struct
import sys
import time

_HOST = "firestore.googleapis.com"
_PATH = re.compile(
    r"/v1/projects/[a-z][a-z0-9-]{4,61}[a-z0-9]/databases/\(default\)/documents"
    r"(?::batchWrite|/oracle/[0-9a-f]{32}/limits-03/[A-Za-z0-9/-]{1,6200}"
    r"(?:\?currentDocument\.(?:exists=false|updateTime=[A-Za-z0-9%:.-]+))?)\Z"
)
_TOKEN = re.compile(r"Bearer [A-Za-z0-9._~+/-]{1,8192}=*\Z")
_PROJECT = re.compile(r"[a-z][a-z0-9-]{4,61}[a-z0-9]\Z")
_MAX_BODY = 4 * 1024 * 1024
_MAX_LINE = 16 * 1024
_MAX_RESPONSE = 2 * 1024 * 1024


def frame(kind, payload):
    sys.stdout.buffer.write(kind + struct.pack(">I", len(payload)) + payload)
    sys.stdout.buffer.flush()


def failure(code):
    frame(b"F", code.encode("ascii"))


def run():
    # A compiled path may be 6,178 bytes and a bearer token up to 8,192, so the
    # message line is allowed 16 KiB where the request-byte worker allows 12.
    line = sys.stdin.buffer.readline(_MAX_LINE + 1)
    if not line.endswith(b"\n") or len(line) > _MAX_LINE:
        failure("worker-failure")
        return
    try:
        message = json.loads(line)
        if set(message) != {
            "method",
            "path",
            "authorization",
            "project",
            "bodyBytes",
            "deadline",
        }:
            raise ValueError
        method = message["method"]
        path = message["path"]
        authorization = message["authorization"]
        project = message["project"]
        count = message["bodyBytes"]
        deadline = message["deadline"]
        if (
            method not in ("GET", "PATCH", "POST", "DELETE")
            or not isinstance(path, str)
            or not _PATH.fullmatch(path)
            or not isinstance(authorization, str)
            or not _TOKEN.fullmatch(authorization)
            or not isinstance(project, str)
            or not _PROJECT.fullmatch(project)
            or type(count) is not int
            or not 0 <= count <= _MAX_BODY
            or type(deadline) not in (int, float)
            or not 0 < deadline - time.monotonic() <= 13
        ):
            raise ValueError
        if path.split("/", 4)[3] != project:
            raise ValueError
        carries_body = method in ("POST", "PATCH")
        if (
            (method == "POST") != path.endswith(":batchWrite")
            or (method == "PATCH") != ("?currentDocument.exists=false" in path)
            or (carries_body and count == 0)
            or (not carries_body and count != 0)
        ):
            raise ValueError
        body = sys.stdin.buffer.read(count)
        if len(body) != count or sys.stdin.buffer.read(1):
            raise ValueError
    except (ValueError, TypeError, UnicodeDecodeError, KeyError):
        failure("worker-failure")
        return
    headers = {"Authorization": authorization, "x-goog-user-project": project}
    if body:
        headers["Content-Type"] = "application/json"
    connection = None
    total = 0
    try:
        if time.monotonic() >= deadline:
            failure("timeout")
            return
        connection = http.client.HTTPSConnection(
            _HOST, timeout=max(0.001, deadline - time.monotonic())
        )
        if time.monotonic() >= deadline:
            failure("timeout")
            return
        connection.request(method, path, body=body if body else None, headers=headers)
        response = connection.getresponse()
        content_type = response.getheader("Content-Type", "")[:128]
        frame(
            b"H",
            json.dumps(
                {"status": response.status, "contentType": content_type}
            ).encode(),
        )
        # Limits-03 expects typed JSON results (200, 400 or 404). Refuse
        # no-content/upgrade statuses even when empty: http.client forces their
        # length to zero, so it cannot expose illegal attached octets reliably.
        if 100 <= response.status < 200 or response.status in (204, 205, 304):
            # http.client forces these responses to length zero, hiding any
            # illegal octets that follow the header block from read1().
            failure("response-incomplete")
            return
        # Match the local limits observer's closed framing contract. Inspect
        # all fields before read1() can hide conflicting lengths or codings.
        lengths = response.headers.get_all("Content-Length", [])
        codings = response.headers.get_all("Transfer-Encoding", [])
        content_encodings = response.headers.get_all("Content-Encoding", [])
        # This worker preserves raw response bytes and has no content decoder;
        # Content-Encoding (including identity) is outside the JSON contract.
        if content_encodings:
            failure("response-incomplete")
            return
        if codings and (
            lengths
            or len(codings) != 1
            or codings[0].strip(" \t").lower() != "chunked"
        ):
            failure("response-incomplete")
            return
        if codings and not response.chunked:
            # http.client only recognizes the exact token; after validating
            # legal surrounding OWS, restore the parser state it should use.
            response.chunked = True
            response.chunk_left = None
            response.length = None
        declared = None
        if lengths:
            value = lengths[0].strip(" \t")
            if len(lengths) != 1 or not value or any(
                digit not in "0123456789" for digit in value
            ):
                failure("invalid-content-length")
                return
            try:
                declared = int(value)
            except ValueError:
                failure("invalid-content-length")
                return
            if declared > _MAX_RESPONSE:
                failure("response-oversize")
                return
        while True:
            chunk = response.read1(16_384)
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_RESPONSE:
                failure("response-oversize")
                return
            frame(b"B", chunk)
        if declared is not None and declared != total:
            failure("response-incomplete")
        else:
            frame(b"E", b"")
    except http.client.IncompleteRead as error:
        partial = error.partial
        if isinstance(partial, bytes) and partial:
            remaining = partial[: max(0, _MAX_RESPONSE - total)]
            for offset in range(0, len(remaining), 16_384):
                frame(b"B", remaining[offset : offset + 16_384])
        failure("response-incomplete")
    except TimeoutError:
        failure("timeout")
    except (OSError, http.client.HTTPException):
        failure("transport-error")
    finally:
        if connection is not None:
            connection.close()


if __name__ == "__main__":
    run()
