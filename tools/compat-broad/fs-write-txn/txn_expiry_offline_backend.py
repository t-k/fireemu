"""Offline Firestore stand-in for the transaction expiry O8 integration proof.

This is test support, not a transport. It answers the collector's requests by
the plan slot each names, with the code the frozen case table expects for a
case and an ordinary success otherwise, and it keeps the five owned documents
so readbacks, conditional deletes and absence reads behave. Every answer is
shaped by the production transport's own normalizer from a status and a JSON
body, so what the collector and the Gate see is what the fixed wire would hand
them. Nothing here opens a socket.

`install(mode)` patches the production transport and the management transport
in the running process, which is how the subprocess proofs (no-data abort and
abandoned cleanup, which need the coordinator process to be gone) run the real
launcher against this backend.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(HERE))

import txn_expiry_cases as cases
from broad_contract import digest
from txn_expiry_remote_transport import normalize

TOKEN = "offline-fixture-token"
CLIENT_ID = "offline-client"
SUBJECT = "offline-subject"
SCOPE = "https://www.googleapis.com/auth/cloud-platform"
PROJECT_BODY = {"projectId": "fireemu-35fe6", "projectNumber": "592603257417"}
DATABASE_BODY = {
    "name": "projects/fireemu-35fe6/databases/(default)",
    "uid": "fixture-uid",
    "type": "FIRESTORE_NATIVE",
    "databaseEdition": "STANDARD",
    "locationId": "us-central1",
}
AUTH_BODY = {"name": "projects/592603257417/config", "mfa": {"state": "DISABLED"}}
VERSION = "2026-09-21T00:00:00.000001Z"
HTTP = {0: 200, 3: 400, 5: 404, 10: 409}
MODES = (
    "complete",
    "preflight-failure",
    "stop-after-first-case",
    "tokeninfo-401",
    "begin-503",
)

CASE_BY_SLOT = {
    "idle/lock-held": "idle-expiry/lock-held-before-idle",
    "idle/commit-before": "idle-expiry/commit-before-idle",
    "idle/commit-after": "idle-expiry/commit-after-idle",
    "idle/rollback-after": "idle-expiry/rollback-after-idle",
    "idle/lock-released": "idle-expiry/lock-released-after-idle",
    "finished/rollback-after-begin": "finished-token/rollback-after-begin",
    "finished/rollback-after-rollback": "finished-token/rollback-after-rollback",
    "finished/rollback-after-commit": "finished-token/rollback-after-commit",
    "retry/rolled-back-previous": "retry-token/retry-with-rolled-back-previous",
    "retry/committed-previous": "retry-token/retry-with-committed-previous",
    "retry/read-only-previous": "retry-token/retry-with-read-only-previous",
    "retry/unissued-previous": "retry-token/retry-with-unissued-previous",
    "retry/malformed-previous": "retry-token/retry-with-malformed-previous",
}


class Backend:
    """One in-memory database, one nonce, sequential tokens."""

    def __init__(self, mode="complete"):
        if mode not in MODES:
            raise ValueError(f"unknown offline backend mode {mode}")
        self.mode = mode
        self.documents = {}
        self.issued = 0
        self.calls = []
        self.management_calls = []
        self.versions = 0

    def _version(self):
        self.versions += 1
        return f"2026-09-21T00:00:{self.versions // 1000:02d}.{self.versions % 1000:03d}000Z"

    def _error(self, code, message):
        status = HTTP[code]
        return status, {
            "error": {"code": status, "status": cases.CODES[code], "message": message}
        }

    def answer(self, request):
        """(status, body) for one collector request."""
        site = request.get("site")
        rpc = request["rpc"]
        case_id = CASE_BY_SLOT.get(site)
        if case_id is not None:
            expected = cases.CASE_BY_ID[case_id]["expectedLocal"]
            if expected["code"] != 0:
                return self._error(expected["code"], expected["message"])
        if rpc == "BeginTransaction":
            if self.mode == "begin-503" and site == "idle/begin/b":
                return 503, {
                    "error": {
                        "code": 503,
                        "status": "UNAVAILABLE",
                        "message": "try later",
                    }
                }
            self.issued += 1
            token = base64.b64encode(f"token-{self.issued}".encode()).decode()
            return 200, {"transaction": token}
        if rpc == "Rollback":
            return 200, {}
        if rpc == "Commit":
            results = []
            for write in request["body"]["writes"]:
                if "delete" in write:
                    current = self.documents.get(write["delete"])
                    if current is None:
                        return self._error(5, "No document to update")
                    if (
                        write.get("currentDocument", {}).get("updateTime")
                        != current["updateTime"]
                    ):
                        return 400, {
                            "error": {
                                "code": 400,
                                "status": "FAILED_PRECONDITION",
                                "message": "stale",
                            }
                        }
                    del self.documents[write["delete"]]
                    results.append({})
                    continue
                name = write["update"]["name"]
                if (
                    write.get("currentDocument") == {"exists": False}
                    and name in self.documents
                ):
                    return 409, {
                        "error": {
                            "code": 409,
                            "status": "ALREADY_EXISTS",
                            "message": "exists",
                        }
                    }
                version = self._version()
                self.documents[name] = {
                    "fields": write["update"]["fields"],
                    "updateTime": version,
                }
                results.append({"updateTime": version})
            return 200, {"writeResults": results, "commitTime": VERSION}
        if rpc == "GetDocument":
            document = self.documents.get(request["name"])
            if document is None:
                return 404, {
                    "error": {"code": 404, "status": "NOT_FOUND", "message": "missing"}
                }
            return 200, {
                "name": request["name"],
                "fields": document["fields"],
                "createTime": VERSION,
                "updateTime": document["updateTime"],
            }
        raise AssertionError(f"unexpected rpc {rpc}")

    def _wire(self, status, raw, failure=None):
        return {
            "status": status,
            "contentType": "application/json",
            "failure": failure,
            "rawBodyBytes": len(raw),
            "rawBodySha256": hashlib.sha256(raw).hexdigest(),
            "rawBodyBase64": base64.b64encode(raw).decode("ascii"),
            "requestBytes": 0,
            "requestSha256": hashlib.sha256(b"").hexdigest(),
            "elapsedSeconds": 0.001,
        }

    def transport(self, request, token, deadline):
        """The injected data wire: `(request, token, deadline)` to a response."""
        assert token == TOKEN
        assert isinstance(deadline, float)
        self.calls.append(request)
        site = request.get("site")
        fail = (self.mode == "preflight-failure" and len(self.calls) == 1) or (
            self.mode == "stop-after-first-case" and site == "verify/idle/lock-held"
        )
        if fail:
            return {
                "complete": False,
                "code": None,
                "status": None,
                "httpStatus": None,
                "message": "transport-error",
                "body": None,
                "wire": self._wire(None, b"", "transport-error"),
            }
        status, body = self.answer(request)
        raw = json.dumps(body, separators=(",", ":")).encode()
        result = normalize(status, raw, request)
        result["wire"] = self._wire(status, raw)
        return result

    def management(self, value):
        """The injected management wire for the seven closed slots."""
        assert value["kind"] == "management"
        self.management_calls.append((value["phase"], value["slot"]))
        slot = value["slot"]
        if slot == "oauth-tokeninfo":
            if self.mode == "tokeninfo-401":
                return {
                    "status": 401,
                    "complete": True,
                    "workerReaped": True,
                    "bodyKind": "json",
                    "body": {"error": "invalid_token"},
                }
            body = {
                "issued_to": CLIENT_ID,
                "user_id": SUBJECT,
                "scope": SCOPE,
                "expires_in": 3600,
            }
        else:
            body = {
                "project": PROJECT_BODY,
                "database": DATABASE_BODY,
                "auth": AUTH_BODY,
            }[slot]
        return {
            "status": 200,
            "complete": True,
            "workerReaped": True,
            "bodyKind": "json",
            "body": body,
        }


def permission_baselines():
    from batch_contract import database_evidence

    return {
        "databaseProjectionDigest": database_evidence(DATABASE_BODY)[
            "projectionDigest"
        ],
        "authConfigDigest": digest(AUTH_BODY),
    }


def install(mode="complete"):
    """Patch the production transports in this process with one backend.

    Used by the subprocess proofs. The patched `request` accepts the fixed
    wire's keyword signature and ignores the capability: the point of those
    proofs is the Ledger, Gate and receipt behaviour around a stop, and the
    admission that precedes them is exercised unpatched.
    """
    import txn_expiry_preflight
    import txn_expiry_remote_transport as remote

    backend = Backend(mode)

    def request(value, *, deadline, **_kwargs):
        return backend.transport(value["request"], value["token"], float(deadline))

    def management_transport(slot, token, *, deadline, **_kwargs):
        # The phase is not part of the reviewed transport's signature; the
        # backend only needs the slot.
        return backend.management(
            {
                "kind": "management",
                "phase": "patched",
                "slot": slot,
                "token": token,
                "deadline": deadline,
            }
        )

    remote.request = request
    txn_expiry_preflight.preflight.management_transport = management_transport
    return backend
