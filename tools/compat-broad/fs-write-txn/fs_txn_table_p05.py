"""FS-TRANSACTION P05: what a read-write transaction's read lock holds back, and when it lets go.

This table grants no send permission. Owned documents: `a` (read by the transaction) and `b` (unrelated to it), both
created in setup. Per transport (REST first, then native gRPC), two chains, each a fresh read-write transaction:

- C (released by its commit): the transaction reads `a` and stays open; an outside writer writes `b` (unrelated, expected to
  succeed at once); then an outside writer writes `a` while the transaction commits a write to `a` 5 s later: the writer is sent
  first and may be held by the read lock, so the commit is sent while it is still pending (a concurrent step); an outside writer
  then writes `a` and succeeds; plain reads keep the final values.
- R (released by its rollback): the transaction reads `a` and stays open; an outside writer writes `a` and the transaction
  rolls back 5 s later, while the writer is still pending; an outside writer then writes `a` and succeeds; a plain read keeps the
  final value.

Production has shown two behaviours for an outside writer that meets a read lock: refused (409 ABORTED "Too much contention")
after about 21 s (P06 recording 1, both transports), and held past 30 s until the holder let go, then committed about 1.2 s after
the release (P06 recording 2). The holder here releases 5 s in, inside the first behaviour's window, so the writer's answer
(committed once released, or refused) and the holder's answer are recorded together, never judged: this is the closure condition's
"hold the competing writer in a separate task, release by commit or rollback, then compare outcome and order". Every answer a
step may give is fixed here; an answer outside the set stops the recording, and an unknown outcome (a timeout at the writer's
30 s, UNAVAILABLE, INTERNAL) is never resent. The document a concurrent pair both write may end in either writer's state, so a
read after it may show either until a later write settles it."""

from pathlib import Path

REFUSED = (3, 5, 9, 10)
STATES = ("created",) + tuple(f"{transport}-{label}" for transport in ("rest", "grpc") for label in ("c-conflict", "c-unrelated", "c-commit", "c-after", "r-conflict", "r-after"))


HOLD_SECONDS = 5


def _step(step_id, transport, rpc, role, *, document=None, token_in=None, token_out=None, writes=(), case=None, allow=(0,), deadline=None, wait=None, concurrent_with=None):
    step = {"id": step_id, "transport": transport, "rpc": rpc, "document": document, "tokenInput": token_in, "tokenOutput": token_out,
            "writes": tuple({"document": name, "state": state, "exists": exists} for name, state, exists in writes),
            "caseId": case, "role": role, "allow": allow}
    if deadline:
        step["deadlineMs"] = deadline
    if wait:
        step["waitSeconds"] = wait
    if concurrent_with:
        step["concurrentWith"] = concurrent_with
    return step


def _writer(transport, chain, name, document, label, *, concurrent_with=None):
    return _step(f"{transport}/{chain}/{name}", transport, "Commit", "outside-writer", writes=((document, f"{transport}-{label}", True),), case=f"{transport}/{chain}-{name}", allow=(0, 10), deadline=30000, concurrent_with=concurrent_with)


def _begin(transport, chain):
    token = f"{transport}-{chain}"
    return [_step(f"{transport}/{chain}/begin", transport, "BeginTransaction", "control", token_out=token),
            _step(f"{transport}/{chain}/read-a", transport, "GetDocument", "control", document="a", token_in=token)]


def _post(transport, chain, document):
    return _step(f"{transport}/{chain}/post-read-{document}", transport, "GetDocument", "post-state", document=document)


def _chains(transport):
    committed = _begin(transport, "c") + [
        _writer(transport, "c", "writer-b", "b", "c-unrelated"),
        _step(f"{transport}/c/commit", transport, "Commit", "observation", token_in=f"{transport}-c", writes=(("a", f"{transport}-c-commit", True),), case=f"{transport}/c-commit", allow=(0,) + REFUSED, wait=HOLD_SECONDS),
        _writer(transport, "c", "writer-a", "a", "c-conflict", concurrent_with=f"{transport}/c/commit"),
        _writer(transport, "c", "writer-after-commit", "a", "c-after"),
        _post(transport, "c", "a"),
        _post(transport, "c", "b"),
    ]
    rolled = _begin(transport, "r") + [
        _step(f"{transport}/r/rollback", transport, "Rollback", "observation", token_in=f"{transport}-r", case=f"{transport}/r-rollback", allow=(0, 10), wait=HOLD_SECONDS),
        _writer(transport, "r", "writer-a", "a", "r-conflict", concurrent_with=f"{transport}/r/rollback"),
        _writer(transport, "r", "writer-after-rollback", "a", "r-after"),
        _post(transport, "r", "a"),
    ]
    return committed + rolled


_SETUP = [
    _step("setup/absence-a", "grpc", "GetDocument", "control", document="a", allow=(5,)),
    _step("setup/absence-b", "grpc", "GetDocument", "control", document="b", allow=(5,)),
    _step("setup/create-a-and-b", "grpc", "Commit", "control", writes=(("a", "created", False), ("b", "created", False))),
]

STEPS = tuple(_SETUP + _chains("rest") + _chains("grpc"))

TABLE = {
    "name": "p05-readlock",
    "program": "FS-TRANSACTION-P05-READLOCK",
    "envelopeId": "FS-TRANSACTION-p05-readlock-001",
    "slug": "txn-p05",
    "documents": ("a", "b"),
    "states": STATES,
    "steps": STEPS,
    # Observation is one request per step; cleanup reserves 7 per owned document.
    "caps": {"observation": len(STEPS), "tokenCleanup": 4, "documentCleanup": 14, "management": 7, "credential": 2},
    # Ten outside writers may each wait their full 30 s (four of them concurrent with a holder that releases after 5 s), the four holds
    # take 5 s each, and the other requests take a few seconds each.
    "observationSeconds": 420,
    "recoverySeconds": 180,
    "maxTokens": 4,
    "sourceFile": Path(__file__),
}
