"""Closed P10-A native gRPC retry graph; this module grants no send permission."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path

PROJECT = "fireemu-oracle-sbx"
DATABASE = "(default)"
PROGRAM = "FS-TRANSACTION-P10-A-GRPC-IDLE"
MAX_REQUESTS = 48
OBSERVATION_SECONDS = 900
RECOVERY_SECONDS = 180
_CAPS = {"observation": 26, "tokenCleanup": 6, "documentCleanup": 7, "management": 7, "credential": 2}
_WAITS = {"live/commit": 55, "expired/commit": 65, "rollback-first/rollback": 65, "get-first/expired-read": 65}
_IDENTITY = re.compile(r"[a-f0-9]{32}\Z")

# id, RPC, token input, token output, write/read state, observation case.
# Begin outputs are tracked even when a refusal was expected.
_STEPS = (
    ('setup/absence', 'GetDocument', None, None, None, None),
    ('setup/create', 'Commit', None, None, 'created', None),
    ('live/begin', 'BeginTransaction', None, 'live', None, None),
    ('live/read', 'GetDocument', 'live', None, 'created', None),
    ('live/commit', 'Commit', 'live', None, 'committed-before-idle', 'grpc/commit-before-idle'),
    ('live/post-state', 'GetDocument', None, None, None, None),
    ('expired/begin', 'BeginTransaction', None, 'late', None, None),
    ('expired/read', 'GetDocument', 'late', None, None, None),
    ('expired/commit', 'Commit', 'late', None, 'attempted-after-idle', 'grpc/commit-after-idle'),
    ('expired/post-state', 'GetDocument', None, None, None, None),
    ('rollback-first/begin', 'BeginTransaction', None, 'rollback-first', None, None),
    ('rollback-first/read', 'GetDocument', 'rollback-first', None, None, None),
    ('rollback-first/rollback', 'Rollback', 'rollback-first', None, None, 'grpc/rollback-first-after-idle'),
    ('rollback-first/outside', 'Commit', None, None, 'after-rollback-first', None),
    ('rollback-first/retry', 'BeginTransaction', 'rollback-first', 'rollback-retry', None, 'grpc/retry-after-rollback-first'),
    ('rollback-first/snapshot', 'GetDocument', 'rollback-retry', None, None, None),
    ('rollback-first/finish', 'Rollback', 'rollback-retry', None, None, None),
    ('get-first/begin', 'BeginTransaction', None, 'get-first', None, None),
    ('get-first/read', 'GetDocument', 'get-first', None, None, None),
    ('get-first/expired-read', 'GetDocument', 'get-first', None, None, 'grpc/get-first-after-idle'),
    ('get-first/rollback', 'Rollback', 'get-first', None, None, 'grpc/rollback-after-expiry-touch'),
    ('get-first/outside', 'Commit', None, None, 'after-get-first', None),
    ('get-first/retry', 'BeginTransaction', 'get-first', 'get-retry', None, 'grpc/retry-after-expiry-touch'),
    ('get-first/snapshot', 'GetDocument', 'get-retry', None, None, None),
    ('get-first/finish', 'Rollback', 'get-retry', None, None, None),
    ('post-state', 'GetDocument', None, None, None, None),
)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def source_digest():
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def corpus_digest():
    return hashlib.sha256(_canonical({"steps": _STEPS, "waits": _WAITS}).encode()).hexdigest()


def compile_plan(nonce, owner_id):
    if not isinstance(nonce, str) or not _IDENTITY.fullmatch(nonce):
        raise ValueError("canonical run nonce required")
    if not isinstance(owner_id, str) or not _IDENTITY.fullmatch(owner_id):
        raise ValueError("canonical run owner required")
    steps = [dict(zip(("id", "rpc", "tokenInput", "tokenOutput", "state", "caseId"), row, strict=True)) for row in _STEPS]
    database = f"projects/{PROJECT}/databases/{DATABASE}"
    return {"kind": "txn-idle-grpc-plan-v1", "program": PROGRAM, "project": PROJECT, "database": database, "nonce": nonce, "ownerId": owner_id, "document": f"{database}/documents/oracle/{nonce}/txn-p10/control", "steps": steps, "cases": [row["caseId"] for row in steps if row["caseId"]], "conditionalSkips": ["rollback-first/snapshot", "rollback-first/finish", "get-first/snapshot", "get-first/finish"], "skipBasis": "definitive-earlier-begin-refusal-only", "waits": dict(_WAITS), "idleThresholdSeconds": 60, "timing": "wall-clock", "caps": dict(_CAPS), "maxRequests": MAX_REQUESTS, "observationSeconds": OBSERVATION_SECONDS, "recoverySeconds": RECOVERY_SECONDS, "iamConfig": "none", "retries": "none", "sourceDigest": source_digest(), "corpusDigest": corpus_digest()}


def validate_plan(value):
    if not isinstance(value, dict):
        raise ValueError("closed P10-A plan required")
    expected = compile_plan(value.get("nonce"), value.get("ownerId"))
    try:
        same = _canonical(value) == _canonical(expected)
    except (ValueError, TypeError):
        same = False
    if not same:
        raise ValueError("P10-A plan differs from its closed source graph")


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
        raise ValueError("declared P10-A step and token bindings required")
    token = None
    if step["tokenInput"]:
        if step["tokenInput"] not in tokens:
            raise ValueError("P10-A step has no earlier issued token")
        else:
            token = canonical_token(tokens[step["tokenInput"]])
    rpc = step["rpc"]
    if rpc == "GetDocument":
        return {"name": value["document"], **({"transaction": token} if token else {})}
    if rpc == "Rollback":
        return {"database": value["database"], "transaction": token}
    if rpc == "BeginTransaction":
        options = {"readWrite": {**({"retryTransaction": token} if token else {})}}
        return {"database": value["database"], "options": options}
    if rpc == "Commit":
        document = {"name": value["document"], "fields": {name: {"stringValue": entry} for name, entry in {"owner": value["ownerId"], "nonce": value["nonce"], "role": "control", "state": step["state"]}.items()}}
        return {"database": value["database"], "writes": [{"update": document, "currentDocument": {"exists": step["id"] != "setup/create"}}], **({"transaction": token} if token else {})}
    raise ValueError("P10-A RPC is not admitted")


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
            raise ValueError("P10-A graph slot is repeated, missing or out of order")
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
            raise ValueError("P10-A request phase exhausted or unknown")
        self.used[phase] += 1
