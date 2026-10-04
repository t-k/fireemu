"""FS-TRANSACTION P02: a read-only transaction's snapshot, its refused writes, and the read-write control.

This table grants no send permission. Owned documents: `a` (created in setup) and `m` (never created). Per transport:

- S1: a read-only transaction begins, an outside writer changes `a`, the transaction then reads `a` (and, over REST,
  batch-reads `a` and `m`); a commit that writes on the read-only transaction must be refused;
- S2: a read-only transaction reads `a`, an outside writer changes it, the transaction reads it again, and an empty
  commit ends it;
- W: a read-write transaction commits the same kind of write and succeeds (the control).

A read-only transaction may show any state acknowledged since it began; which one it shows (the state at its begin or
the state at its first read) is exactly what the recording keeps. REST runs every chain; gRPC a representative subset
so the request cap stays inside the corpus proposal's 64."""

from pathlib import Path

REFUSED = (3, 5, 9, 10)
STATES = ("created", "held") + tuple(f"{transport}-{label}" for transport in ("rest", "grpc") for label in ("s1-w", "s2-w", "w-commit"))


def _step(step_id, transport, rpc, role, *, document=None, documents=None, token_in=None, token_out=None, mode=None, writes=(), case=None, allow=(0,), deadline=None):
    step = {"id": step_id, "transport": transport, "rpc": rpc, "document": document, "tokenInput": token_in, "tokenOutput": token_out,
            "writes": tuple({"document": name, "state": state, "exists": exists} for name, state, exists in writes),
            "caseId": case, "role": role, "allow": allow}
    if documents:
        step["documents"] = tuple(documents)
    if mode:
        step["mode"] = mode
    if deadline:
        step["deadlineMs"] = deadline
    return step


def _begin(chain, transport, mode):
    return _step(f"{transport}/{chain}/begin", transport, "BeginTransaction", "control", token_out=f"{transport}-{chain}", mode=mode if mode != "readWrite" else None)


def _writer(chain, transport):
    return _step(f"{transport}/{chain}/writer", transport, "Commit", "outside-writer", writes=(("a", f"{transport}-{chain}-w", True),), case=f"{transport}/{chain}-writer", allow=(0, 10), deadline=30000)


def _observe(chain, transport, name, rpc, *, allow=(0,), writes=(), documents=None, document=None):
    return _step(f"{transport}/{chain}/{name}", transport, rpc, "observation", document=document, documents=documents, token_in=f"{transport}-{chain}", writes=writes, case=f"{transport}/{chain}-{name}", allow=allow)


def _post(chain, transport):
    return _step(f"{transport}/{chain}/post-read-a", transport, "GetDocument", "post-state", document="a")


def _s1(transport, full):
    steps = [_begin("s1", transport, "readOnly"), _writer("s1", transport), _observe("s1", transport, "ro-read", "GetDocument", document="a")]
    if full:
        steps.append(_observe("s1", transport, "ro-batch", "BatchGetDocuments", documents=("a", "m")))
    steps.append(_observe("s1", transport, "ro-write", "Commit", writes=(("a", "held", True),), allow=REFUSED))
    if full:
        steps.append(_observe("s1", transport, "rollback", "Rollback", allow=(0,) + REFUSED))
    return steps + [_post("s1", transport)]


def _s2(transport):
    token = f"{transport}-s2"
    return [_begin("s2", transport, "readOnly"),
            _step(f"{transport}/s2/read-a", transport, "GetDocument", "control", document="a", token_in=token),
            _writer("s2", transport),
            _observe("s2", transport, "ro-read-again", "GetDocument", document="a"),
            _observe("s2", transport, "ro-empty", "Commit", allow=(0,) + REFUSED),
            _post("s2", transport)]


def _w(transport):
    token = f"{transport}-w"
    return [_begin("w", transport, "readWrite"),
            _step(f"{transport}/w/read-a", transport, "GetDocument", "control", document="a", token_in=token),
            _observe("w", transport, "commit", "Commit", writes=(("a", f"{transport}-w-commit", True),)),
            _post("w", transport)]


_SETUP = [
    _step("setup/absence-a", "grpc", "GetDocument", "control", document="a", allow=(5,)),
    _step("setup/absence-m", "grpc", "GetDocument", "control", document="m", allow=(5,)),
    _step("setup/create-a", "grpc", "Commit", "control", writes=(("a", "created", False),)),
]

STEPS = tuple(_SETUP + _s1("rest", True) + _s2("rest") + _w("rest") + _s1("grpc", False) + _s2("grpc") + _w("grpc"))

TABLE = {
    "name": "p02-readonly",
    "program": "FS-TRANSACTION-P02-READONLY",
    "envelopeId": "FS-TRANSACTION-p02-readonly-001",
    "slug": "txn-p02",
    "documents": ("a", "m"),
    "states": STATES,
    "steps": STEPS,
    # Observation is one request per step; cleanup reserves 7 per owned document.
    "caps": {"observation": len(STEPS), "tokenCleanup": 6, "documentCleanup": 14, "management": 7, "credential": 2},
    # Four outside writers may each wait their full 30 s; the other requests take a few seconds each.
    "observationSeconds": 300,
    "recoverySeconds": 180,
    "maxTokens": 6,
    "sourceFile": Path(__file__),
}
