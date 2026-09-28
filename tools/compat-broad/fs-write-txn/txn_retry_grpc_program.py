"""Closed P09 native gRPC retry graph; this module grants no send permission."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path

PROJECT = "fireemu-oracle-sbx"
DATABASE = "(default)"
PROGRAM = "FS-TRANSACTION-P09-GRPC-RETRY"
UNKNOWN_TOKEN = "AAAAAAAAAAA="
MAX_REQUESTS = 48
OBSERVATION_SECONDS = 120
RECOVERY_SECONDS = 180
_CAPS = {"observation": 25, "tokenCleanup": 7, "documentCleanup": 7, "management": 7, "credential": 2}
_IDENTITY = re.compile(r"[a-f0-9]{32}\Z")

# id, RPC, token input, token output, write/read state, observation case.
# Begin outputs are tracked even when a refusal was expected.
_STEPS = (
    ("setup/absence", "GetDocument", None, None, None, None),
    ("setup/create", "Commit", None, None, "created", None),
    ("committed/begin", "BeginTransaction", None, "committed", None, None),
    ("committed/read", "GetDocument", "committed", None, "created", None),
    ("committed/commit", "Commit", "committed", None, "committed", None),
    ("committed/rollback", "Rollback", "committed", None, None, "grpc/rollback-after-commit"),
    ("committed/outside", "Commit", None, None, "outside", None),
    ("committed/retry", "BeginTransaction", "committed", "committed-retry", None, "grpc/retry-with-committed-previous"),
    ("committed/snapshot", "GetDocument", "committed-retry", None, "outside", None),
    ("committed/rollback-retry", "Rollback", "committed-retry", None, None, None),
    ("rolled-back/begin", "BeginTransaction", None, "rolled-back", None, None),
    ("rolled-back/read", "GetDocument", "rolled-back", None, "outside", None),
    ("rolled-back/rollback", "Rollback", "rolled-back", None, None, None),
    ("rolled-back/rollback-again", "Rollback", "rolled-back", None, None, "grpc/rollback-after-rollback"),
    ("rolled-back/retry", "BeginTransaction", "rolled-back", "rolled-back-retry", None, "grpc/retry-with-rolled-back-previous"),
    ("rolled-back/snapshot", "GetDocument", "rolled-back-retry", None, "outside", None),
    ("rolled-back/rollback-retry", "Rollback", "rolled-back-retry", None, None, None),
    ("read-only/begin", "BeginTransaction", None, "read-only", None, None),
    ("read-only/read", "GetDocument", "read-only", None, "outside", None),
    ("read-only/outside", "Commit", None, None, "after-readonly-start", None),
    ("read-only/retry", "BeginTransaction", "read-only", "unexpected-read-only-retry", None, "grpc/retry-with-read-only-previous"),
    ("read-only/snapshot", "GetDocument", "read-only", None, "outside", None),
    ("read-only/rollback", "Rollback", "read-only", None, None, None),
    ("unknown/retry", "BeginTransaction", "unissued", "unexpected-unknown-retry", None, "grpc/retry-with-unissued-previous"),
    ("post-state/read", "GetDocument", None, None, "after-readonly-start", None),
)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def source_digest():
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def corpus_digest():
    return hashlib.sha256(_canonical(_STEPS).encode()).hexdigest()


def compile_plan(nonce, owner_id):
    if not isinstance(nonce, str) or not _IDENTITY.fullmatch(nonce):
        raise ValueError("canonical run nonce required")
    if not isinstance(owner_id, str) or not _IDENTITY.fullmatch(owner_id):
        raise ValueError("canonical run owner required")
    steps = [dict(zip(("id", "rpc", "tokenInput", "tokenOutput", "state", "caseId"), row, strict=True)) for row in _STEPS]
    database = f"projects/{PROJECT}/databases/{DATABASE}"
    return {"kind": "txn-retry-grpc-plan-v1", "program": PROGRAM, "project": PROJECT, "database": database, "nonce": nonce, "ownerId": owner_id, "document": f"{database}/documents/oracle/{nonce}/txn-p09/control", "steps": steps, "cases": [row["caseId"] for row in steps if row["caseId"]], "caps": dict(_CAPS), "maxRequests": MAX_REQUESTS, "observationSeconds": OBSERVATION_SECONDS, "recoverySeconds": RECOVERY_SECONDS, "iamConfig": "none", "retries": "none", "sourceDigest": source_digest(), "corpusDigest": corpus_digest()}


def validate_plan(value):
    if not isinstance(value, dict):
        raise ValueError("closed P09 plan required")
    expected = compile_plan(value.get("nonce"), value.get("ownerId"))
    try:
        same = _canonical(value) == _canonical(expected)
    except (ValueError, TypeError):
        same = False
    if not same:
        raise ValueError("P09 plan differs from its closed source graph")


def canonical_token(value):
    if not isinstance(value, str) or not 0 < len(value) <= 2048:
        raise ValueError("bounded canonical transaction bytes required")
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError:
        raise ValueError("bounded canonical transaction bytes required") from None
    if not decoded or len(decoded) > 1024 or base64.b64encode(decoded).decode() != value:
        raise ValueError("bounded canonical transaction bytes required")
    return value


def request_for_step(value, step, tokens):
    """Resolve only a declared slot using already issued private token bindings."""
    validate_plan(value)
    if step not in value["steps"] or not isinstance(tokens, dict):
        raise ValueError("declared P09 step and token bindings required")
    token = None
    if step["tokenInput"]:
        if step["tokenInput"] == "unissued":
            token = UNKNOWN_TOKEN
        elif step["tokenInput"] not in tokens:
            raise ValueError("P09 step has no earlier issued token")
        else:
            token = canonical_token(tokens[step["tokenInput"]])
    rpc = step["rpc"]
    if rpc == "GetDocument":
        return {"name": value["document"], **({"transaction": token} if token else {})}
    if rpc == "Rollback":
        return {"database": value["database"], "transaction": token}
    if rpc == "BeginTransaction":
        options = {"readOnly": {}} if step["id"] == "read-only/begin" else {"readWrite": {**({"retryTransaction": token} if token else {})}}
        return {"database": value["database"], "options": options}
    if rpc == "Commit":
        document = {"name": value["document"], "fields": {name: {"stringValue": entry} for name, entry in {"owner": value["ownerId"], "nonce": value["nonce"], "role": "control", "state": step["state"]}.items()}}
        return {"database": value["database"], "writes": [{"update": document, "currentDocument": {"exists": step["id"] != "setup/create"}}], **({"transaction": token} if token else {})}
    raise ValueError("P09 RPC is not admitted")


class GraphCursor:
    """Claim each observation slot once and in the declared order."""

    def __init__(self, value):
        validate_plan(value)
        self._plan = json.loads(_canonical(value))
        self._next = 0

    @property
    def complete(self):
        return self._next == len(self._plan["steps"])

    def claim(self, name):
        if self.complete or name != self._plan["steps"][self._next]["id"]:
            raise ValueError("P09 graph slot is repeated, missing or out of order")
        row = self._plan["steps"][self._next]
        self._next += 1
        return dict(row)


class RequestBudget:
    """Charge before dispatch; observation cannot borrow recovery reserves."""

    def __init__(self, value):
        validate_plan(value)
        self._caps = dict(value["caps"])
        self.used = {phase: 0 for phase in self._caps}

    @property
    def total(self):
        return sum(self.used.values())

    def charge(self, phase):
        if not isinstance(phase, str) or phase not in self._caps or self.used[phase] >= self._caps[phase] or self.total >= MAX_REQUESTS:
            raise ValueError("P09 request phase exhausted or unknown")
        self.used[phase] += 1
