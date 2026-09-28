"""Source bytes executed by the fixed FS-CONFIG-LIFECYCLE HTTPS process exchange.

The worker accepts exactly one request whose path is one of the campaign's own
Admin API routes under the oracle project's default database, sends it to the fixed
production host, and frames the answer back. It is spawned from these bytes by the
lane's remote transport, which pins their digest; stdlib only, no repository import.
"""

import http.client
import json
import re
import struct
import sys
import time

_HOST = "firestore.googleapis.com"
_DATABASE = r"/v1/projects/fireemu-35fe6/databases"
_GROUP = r"/\(default\)/collectionGroups/fsconfig_(?:ttl|exempt)_[0-9a-f]{12}"
# Exactly the campaign's own routes: the default database projection, the
# enumeration, one field of each nonce-owned collection group (read or patched under
# one of the two update masks), the two reconciliation listings of such a group, and
# an operation under the default database. Each alternative is a whole route, so a
# concatenation of two routes never matches.
_ROUTES = (
    r"/\(default\)",
    r"\?showDeleted=(?:false|true)",
    _GROUP + r"/fields/(?:expiresAt|payload)",
    _GROUP + r"/fields/(?:expiresAt|payload)\?updateMask=(?:ttlConfig|indexConfig)",
    _GROUP
    + r"/fields\?filter=indexConfig\.usesAncestorConfig(?:%3A|:)false&pageSize=20",
    _GROUP + r"/fields\?filter=ttlConfig(?:%3A|:)(?:%2A|\*)&pageSize=20",
    r"/\(default\)/operations/[A-Za-z0-9_.-]{1,128}",
)
_PATH = re.compile(_DATABASE + "(?:" + "|".join(_ROUTES) + r")\Z")
_TOKEN = re.compile(r"Bearer [A-Za-z0-9._~+/-]{1,8192}=*\Z")
_MAX_BODY = 4096
_RESPONSE_CAP = 256 * 1024


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
        if set(message) != {"method", "path", "authorization", "bodyBytes", "deadline"}:
            raise ValueError
        method = message["method"]
        path = message["path"]
        authorization = message["authorization"]
        count = message["bodyBytes"]
        deadline = message["deadline"]
        if (
            method not in ("GET", "PATCH")
            or not isinstance(path, str)
            or not _PATH.fullmatch(path)
            or not isinstance(authorization, str)
            or not _TOKEN.fullmatch(authorization)
            or type(count) is not int
            or not 0 <= count <= _MAX_BODY
            or type(deadline) not in (int, float)
            or not 0 < deadline - time.monotonic() <= 60
            or (method == "PATCH") != ("updateMask=" in path)
            or (method == "PATCH") != (count > 0)
        ):
            raise ValueError
        body = sys.stdin.buffer.read(count)
        if len(body) != count or sys.stdin.buffer.read(1):
            raise ValueError
    except (ValueError, TypeError, UnicodeDecodeError, KeyError):
        failure("worker-failure")
        return
    headers = {"Authorization": authorization, "x-goog-user-project": "fireemu-35fe6"}
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
                if int(declared) > _RESPONSE_CAP:
                    failure("response-oversize")
                    return
            except ValueError:
                failure("invalid-content-length")
                return
        while True:
            chunk = response.read1(16_384)
            if not chunk:
                break
            total += len(chunk)
            if total > _RESPONSE_CAP:
                failure("response-oversize")
                return
            frame(b"B", chunk)
        if declared is not None and int(declared) != total:
            failure("response-incomplete")
        else:
            frame(b"E", b"")
    except http.client.IncompleteRead:
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
