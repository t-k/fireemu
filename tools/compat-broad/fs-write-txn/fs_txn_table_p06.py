"""FS-TRANSACTION P06: a multi-document commit is all or nothing, and what a holder's lock does to it.

This table grants no send permission. Owned documents: `a` (the holder's), `b` (created in setup), and `c` and `d` (each created by one
transport's multi-write, so the two chains never contend for the same new document). Per transport (REST first, then native gRPC) one chain:

- a read-write transaction reads `a` and keeps it open;
- an outside writer commits `a` and `b` together while the holder is open: production is expected to refuse it, and
  the plain reads that follow prove neither document changed (no partial publication);
- an outside writer commits `b` and a new document (which does not touch `a`): expected to succeed;
- the holder rolls back, and the writer commits `a` and `b` together: expected to succeed;
- plain reads prove the final values.

Every answer a step may give is fixed here; an answer outside the set stops the recording, and an unknown outcome
(a timeout at the writer's 30 s, UNAVAILABLE, INTERNAL) is never resent."""

from pathlib import Path

REFUSED = (3, 5, 9, 10)
STATES = ("created",) + tuple(f"{transport}-{label}" for transport in ("rest", "grpc") for label in ("ab-held", "bc", "ab-after"))


def _step(step_id, transport, rpc, role, *, document=None, token_in=None, token_out=None, writes=(), case=None, allow=(0,), deadline=None):
    step = {"id": step_id, "transport": transport, "rpc": rpc, "document": document, "tokenInput": token_in, "tokenOutput": token_out,
            "writes": tuple({"document": name, "state": state, "exists": exists} for name, state, exists in writes),
            "caseId": case, "role": role, "allow": allow}
    if deadline:
        step["deadlineMs"] = deadline
    return step


def _writer(transport, name, writes, allow):
    return _step(f"{transport}/{name}", transport, "Commit", "outside-writer", writes=writes, case=f"{transport}/{name}", allow=allow, deadline=30000)


def _plain(transport, name, document, *, case=True):
    return _step(f"{transport}/{name}", transport, "GetDocument", "observation" if case else "post-state", document=document, case=f"{transport}/{name}" if case else None)


def _chain(transport, spare):
    token = f"{transport}-h"
    return [
        _step(f"{transport}/begin", transport, "BeginTransaction", "control", token_out=token),
        _step(f"{transport}/read-a", transport, "GetDocument", "control", document="a", token_in=token),
        _writer(transport, "multiwrite-with-holder", (("a", f"{transport}-ab-held", True), ("b", f"{transport}-ab-held", True)), (0, 10)),
        _plain(transport, "plain-a-after-refusal", "a"),
        _plain(transport, "plain-b-after-refusal", "b"),
        _writer(transport, "multiwrite-without-holder-doc", (("b", f"{transport}-bc", True), (spare, f"{transport}-bc", False)), (0, 10)),
        _step(f"{transport}/rollback", transport, "Rollback", "observation", token_in=token, case=f"{transport}/rollback"),
        _writer(transport, "multiwrite-after-rollback", (("a", f"{transport}-ab-after", True), ("b", f"{transport}-ab-after", True)), (0, 10)),
        _plain(transport, "post-read-a", "a", case=False),
        _plain(transport, "post-read-b", "b", case=False),
    ]


_SETUP = [
    _step("setup/absence-a", "grpc", "GetDocument", "control", document="a", allow=(5,)),
    _step("setup/absence-b", "grpc", "GetDocument", "control", document="b", allow=(5,)),
    _step("setup/absence-c", "grpc", "GetDocument", "control", document="c", allow=(5,)),
    _step("setup/absence-d", "grpc", "GetDocument", "control", document="d", allow=(5,)),
    _step("setup/create-a-and-b", "grpc", "Commit", "control", writes=(("a", "created", False), ("b", "created", False))),
]

STEPS = tuple(_SETUP + _chain("rest", "c") + _chain("grpc", "d"))

TABLE = {
    "name": "p06-multiwrite",
    "program": "FS-TRANSACTION-P06-MULTIWRITE",
    "envelopeId": "FS-TRANSACTION-p06-multiwrite-001",
    "slug": "txn-p06",
    "documents": ("a", "b", "c", "d"),
    "states": STATES,
    "steps": STEPS,
    # Observation is one request per step; cleanup reserves 7 per owned document.
    "caps": {"observation": len(STEPS), "tokenCleanup": 2, "documentCleanup": 28, "management": 7, "credential": 2},
    # Six outside writers may each wait their full 30 s; the other 26 requests take a few seconds each.
    "observationSeconds": 360,
    "recoverySeconds": 180,
    "maxTokens": 2,
    "sourceFile": Path(__file__),
}
