"""Source bytes executed by the fixed request-byte HTTPS process exchange."""

import http.client
import json
import re
import struct
import sys
import time
from datetime import datetime
from urllib.parse import quote

_HOST = "firestore.googleapis.com"
_PATH = re.compile(
    r"/v1/projects/[a-z][a-z0-9-]{4,61}[a-z0-9]/databases/\(default\)/documents"
    r"(?::commit|(?:/oracle/[0-9a-f]{32}/request-bytes-01/probe-[ueo]01/items/"
    r"(?:control|payload-(?:0[0-9]|1[0-5]))"
    r"|/oracle/[0-9a-f]{32}/request-bytes-02/probe-r16m1/items/"
    r"(?:control|payload-(?:0[0-9]|1[0-8]))"
    r")(?:\?currentDocument\.updateTime=[A-Za-z0-9%:.-]+)?)\Z"
)
_TOKEN = re.compile(r"Bearer [A-Za-z0-9._~+/-]{1,8192}=*\Z")
_PROJECT = re.compile(r"[a-z][a-z0-9-]{4,61}[a-z0-9]\Z")
_VERSION = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z\Z")


def _version_bound_delete(path):
    _, separator, query = path.partition("?")
    prefix = "currentDocument.updateTime="
    if not separator or not query.startswith(prefix):
        return False
    encoded_version = query[len(prefix) :]
    version = encoded_version.replace("%3A", ":")
    if _VERSION.fullmatch(version) is None or quote(version, safe="") != encoded_version:
        return False
    try:
        datetime.fromisoformat(version.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


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
        deadline_ceiling = 80 if count > 10_485_761 else 60
        if (
            method not in ("GET", "POST", "DELETE")
            or not isinstance(path, str)
            or not _PATH.fullmatch(path)
            or (method == "DELETE" and not _version_bound_delete(path))
            or not isinstance(authorization, str)
            or not _TOKEN.fullmatch(authorization)
            or not isinstance(project, str)
            or not _PROJECT.fullmatch(project)
            or type(count) is not int
            or not 0 <= count <= 16_777_217
            or type(deadline) not in (int, float)
            or not 0 < deadline - time.monotonic() <= deadline_ceiling
        ):
            raise ValueError
        if path.split("/", 4)[3] != project:
            raise ValueError
        if (
            (method == "POST") != path.endswith(":commit")
            or (method == "POST" and count == 0)
            or (method != "POST" and count != 0)
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
                if int(declared) > 2 * 1024 * 1024:
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
            if total > 2 * 1024 * 1024:
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
            remaining = partial[: max(0, 2 * 1024 * 1024 - total)]
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
