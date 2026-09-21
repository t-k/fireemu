"""Source bytes executed by the fixed transaction-expiry HTTPS process exchange.

One request per process. The secret arrives on stdin, never on the command
line. Only the campaign's own routes on the fixed Firestore host are reachable:
`:beginTransaction`, `:commit`, `:rollback` and a document GET below the
nonce-owned `oracle/<nonce>/txn-expiry-04` collection, optionally selected by a
transaction. The parent pins these bytes by digest before it spawns them.
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
    r"(?::(?:beginTransaction|commit|rollback)"
    r"|/oracle/[0-9a-f]{32}/txn-expiry-04/(?:control|locked-[abcd])"
    r"(?:\?transaction=[A-Za-z0-9%._~-]{1,4096})?)\Z"
)
_TOKEN = re.compile(r"Bearer [A-Za-z0-9._~+/-]{1,8192}=*\Z")
_PROJECT = re.compile(r"[a-z][a-z0-9-]{4,61}[a-z0-9]\Z")
_MAX_BODY = 8192
_MAX_RESPONSE = 65536
_MAX_SECONDS = 120


def frame(kind, payload):
    sys.stdout.buffer.write(kind + struct.pack(">I", len(payload)) + payload)
    sys.stdout.buffer.flush()


def failure(code):
    frame(b"F", code.encode("ascii"))


def run():
    line = sys.stdin.buffer.readline(12289)
    if not line.endswith(b"\n") or len(line) > 12288:
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
            method not in ("GET", "POST")
            or not isinstance(path, str)
            or not _PATH.fullmatch(path)
            or not isinstance(authorization, str)
            or not _TOKEN.fullmatch(authorization)
            or not isinstance(project, str)
            or not _PROJECT.fullmatch(project)
            or type(count) is not int
            or not 0 <= count <= _MAX_BODY
            or type(deadline) not in (int, float)
            or not 0 < deadline - time.monotonic() <= _MAX_SECONDS
        ):
            raise ValueError
        if path.split("/", 4)[3] != project:
            raise ValueError
        posting = method == "POST"
        if posting != (":" in path.rsplit("/", 1)[-1].split("?", 1)[0]):
            raise ValueError
        if (posting and count == 0) or (not posting and count != 0):
            raise ValueError
        body = sys.stdin.buffer.read(count)
        if len(body) != count or sys.stdin.buffer.read(1):
            raise ValueError
    except (ValueError, TypeError, UnicodeDecodeError, KeyError):
        failure("worker-failure")
        return
    headers = {
        "Authorization": authorization,
        "x-goog-user-project": project,
        "Accept": "application/json",
    }
    if body:
        headers["Content-Type"] = "application/json"
    connection = None
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
        declared = response.getheader("Content-Length")
        if declared is not None:
            try:
                if int(declared) > _MAX_RESPONSE:
                    failure("response-oversize")
                    return
            except ValueError:
                failure("invalid-content-length")
                return
        total = 0
        while True:
            chunk = response.read1(16_384)
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_RESPONSE:
                failure("response-oversize")
                return
            frame(b"B", chunk)
        if declared is not None and int(declared) != total:
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
