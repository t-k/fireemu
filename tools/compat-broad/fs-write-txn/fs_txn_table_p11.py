"""FS-TRANSACTION P11: a transaction's total lifetime, with its idle time kept short by reads.

This table grants no send permission. Owned documents: `a` (created in setup) and `m` (never created). One chain per
transport (REST first, then native gRPC), each a fresh read-write transaction:

- it begins and reads `a`, then reads `a` again nine times, 24 s apart (well inside the idle limit), so the transaction
  is never idle for long but grows old;
- a read after a further 12 s (a transaction close to four minutes old) is the live control;
- a read after another 50 s (at least 278 s old, past the 270 s total lifetime the documentation gives, and still
  only 50 s idle) and a commit
  that writes are the expiry observation; the commit is expected to be refused;
- an outside writer then writes `a`, which succeeds once the expired transaction's lock is gone.

The keepalive reads are observations without case ids: a refused one is recorded in the rows and the recording goes on,
so an early expiry is measured, not fatal. The age bounds of every waiting request are kept as parent-clock
intervals; the projection compares only whether each token was certainly younger than 270 s, certainly older, or
neither. Nothing here proves the exact lifetime: the observation brackets it."""

from pathlib import Path

REFUSED = (3, 5, 9, 10)
ANY_ANSWER = (0,) + REFUSED
KEEPALIVES = 9
KEEPALIVE_WAIT = 24
LIVE_WAIT = 12
EXPIRY_WAIT = 50
STATES = ("created",) + tuple(f"{transport}-{label}" for transport in ("rest", "grpc") for label in ("commit", "writer"))


def _step(step_id, transport, rpc, role, *, document=None, token_in=None, token_out=None, writes=(), case=None, allow=(0,), wait=None, deadline=None):
    step = {"id": step_id, "transport": transport, "rpc": rpc, "document": document, "tokenInput": token_in, "tokenOutput": token_out,
            "writes": tuple({"document": name, "state": state, "exists": exists} for name, state, exists in writes),
            "caseId": case, "role": role, "allow": allow}
    if wait:
        step["waitSeconds"] = wait
    if deadline:
        step["deadlineMs"] = deadline
    return step


def _chain(transport):
    token = f"{transport}-k"
    steps = [
        _step(f"{transport}/begin", transport, "BeginTransaction", "control", token_out=token),
        _step(f"{transport}/read-a", transport, "GetDocument", "control", document="a", token_in=token),
    ]
    for index in range(1, KEEPALIVES + 1):
        steps.append(_step(f"{transport}/keepalive-{index}", transport, "GetDocument", "observation", document="a", token_in=token, allow=ANY_ANSWER, wait=KEEPALIVE_WAIT))
    steps += [
        _step(f"{transport}/live-read", transport, "GetDocument", "observation", document="a", token_in=token, case=f"{transport}/live-read", allow=ANY_ANSWER, wait=LIVE_WAIT),
        _step(f"{transport}/expiry-read", transport, "GetDocument", "observation", document="a", token_in=token, case=f"{transport}/expiry-read", allow=ANY_ANSWER, wait=EXPIRY_WAIT),
        _step(f"{transport}/expiry-commit", transport, "Commit", "observation", token_in=token, writes=(("a", f"{transport}-commit", True),), case=f"{transport}/expiry-commit", allow=ANY_ANSWER),
        _step(f"{transport}/writer", transport, "Commit", "outside-writer", writes=(("a", f"{transport}-writer", True),), case=f"{transport}/writer", allow=(0, 10), deadline=30000),
        _step(f"{transport}/post-read-a", transport, "GetDocument", "post-state", document="a"),
    ]
    return steps


_SETUP = [
    _step("setup/absence-a", "grpc", "GetDocument", "control", document="a", allow=(5,)),
    _step("setup/absence-m", "grpc", "GetDocument", "control", document="m", allow=(5,)),
    _step("setup/create-a", "grpc", "Commit", "control", writes=(("a", "created", False),)),
]

STEPS = tuple(_SETUP + _chain("rest") + _chain("grpc"))

TABLE = {
    "name": "p11-lifetime",
    "program": "FS-TRANSACTION-P11-LIFETIME",
    "envelopeId": "FS-TRANSACTION-p11-lifetime-001",
    "slug": "txn-p11",
    "documents": ("a", "m"),
    "states": STATES,
    "steps": STEPS,
    "thresholds": {"totalAgeSeconds": 270},
    # Observation is one request per step; cleanup reserves 7 per owned document.
    "caps": {"observation": len(STEPS), "tokenCleanup": 2, "documentCleanup": 14, "management": 7, "credential": 2},
    # Two chains of about 300 s each (278 s of waits and a few seconds per request) with the admission re-check before every request; the last wait must still fit.
    "observationSeconds": 840,
    "recoverySeconds": 180,
    "maxTokens": 2,
    "sourceFile": Path(__file__),
}
