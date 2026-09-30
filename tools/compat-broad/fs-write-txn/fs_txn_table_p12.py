"""FS-TRANSACTION P12: what a transaction answers as its FIRST request after its total lifetime, and the requests after it.

This table grants no send permission. Owned document: `a`, created in setup. Per transport (REST, then native gRPC), two
chains, each a fresh read-write transaction that is kept alive by reads (9 reads 24 s apart, then one 62 s wait, at least
278 s old and never idle for long) and then meets an expiry, not a read, first:

- C (Commit first): the first request after the wait is a Commit that writes; then two reads; then a Rollback.
- R (Rollback first): the first request after the wait is a Rollback; then a read; then a Commit that writes.

P11 recorded only read, Commit, Rollback over REST (10, 3, 3). Two models fit that recording: "the first refused request
answers 10, everything after answers 3" and "a read answers 10, a Commit and a Rollback answer 3". C and R separate them: a
Commit first answers 10 under the first and 3 under the second, a Rollback first answers 0 or 10 under the first and 3 under
the second, and a second read answers 3 under the first and 10 under the second. Every answer of the requests after the wait is
observed, never judged (any code is allowed); the keepalive reads are observations without case ids. A Rollback that
answers 3 "Invalid transaction." finishes the token only after the token was refused as expired, so the reads sit before the
last Rollback of chain C and the chain-end release of chain R."""

from pathlib import Path

REFUSED = (3, 5, 9, 10)
ANY_ANSWER = (0,) + REFUSED
KEEPALIVES = 9
KEEPALIVE_WAIT = 24
EXPIRY_WAIT = 62
STATES = ("created",) + tuple(f"{transport}-{label}" for transport in ("rest", "grpc") for label in ("c-commit", "r-commit"))


def _step(step_id, transport, rpc, role, *, document=None, token_in=None, token_out=None, writes=(), case=None, allow=(0,), wait=None):
    step = {"id": step_id, "transport": transport, "rpc": rpc, "document": document, "tokenInput": token_in, "tokenOutput": token_out,
            "writes": tuple({"document": name, "state": state, "exists": exists} for name, state, exists in writes),
            "caseId": case, "role": role, "allow": allow}
    if wait:
        step["waitSeconds"] = wait
    return step


def _observe(transport, chain, name, rpc, *, wait=None, writes=(), document=None):
    return _step(f"{transport}/{chain}/{name}", transport, rpc, "observation", document=document, token_in=f"{transport}-{chain}", writes=writes,
                 case=f"{transport}/{chain}-{name}", allow=ANY_ANSWER, wait=wait)


def _aged(transport, chain):
    token = f"{transport}-{chain}"
    steps = [_step(f"{transport}/{chain}/begin", transport, "BeginTransaction", "control", token_out=token),
             _step(f"{transport}/{chain}/read-a", transport, "GetDocument", "control", document="a", token_in=token)]
    for index in range(1, KEEPALIVES + 1):
        steps.append(_step(f"{transport}/{chain}/keepalive-{index}", transport, "GetDocument", "observation", document="a", token_in=token, allow=ANY_ANSWER, wait=KEEPALIVE_WAIT))
    return steps


def _commit_first(transport):
    return _aged(transport, "c") + [
        _observe(transport, "c", "commit-first", "Commit", wait=EXPIRY_WAIT, writes=(("a", f"{transport}-c-commit", True),)),
        _observe(transport, "c", "read-after", "GetDocument", document="a"),
        _observe(transport, "c", "read-again", "GetDocument", document="a"),
        _observe(transport, "c", "rollback-last", "Rollback"),
        _step(f"{transport}/c/post-read-a", transport, "GetDocument", "post-state", document="a"),
    ]


def _rollback_first(transport):
    return _aged(transport, "r") + [
        _observe(transport, "r", "rollback-first", "Rollback", wait=EXPIRY_WAIT),
        _observe(transport, "r", "read-after", "GetDocument", document="a"),
        _observe(transport, "r", "commit-last", "Commit", writes=(("a", f"{transport}-r-commit", True),)),
        _step(f"{transport}/r/post-read-a", transport, "GetDocument", "post-state", document="a"),
    ]


_SETUP = [
    _step("setup/absence-a", "grpc", "GetDocument", "control", document="a", allow=(5,)),
    _step("setup/create-a", "grpc", "Commit", "control", writes=(("a", "created", False),)),
]

STEPS = tuple(_SETUP + _commit_first("rest") + _rollback_first("rest") + _commit_first("grpc") + _rollback_first("grpc"))

TABLE = {
    "name": "p12-first-request",
    "program": "FS-TRANSACTION-P12-FIRST-REQUEST",
    "envelopeId": "FS-TRANSACTION-p12-first-request-001",
    "slug": "txn-p12",
    "documents": ("a",),
    "states": STATES,
    "steps": STEPS,
    "thresholds": {"totalAgeSeconds": 270},
    # Observation is one request per step; cleanup reserves 7 per owned document.
    "caps": {"observation": len(STEPS), "tokenCleanup": 4, "documentCleanup": 7, "management": 7, "credential": 2},
    # Four chains of about 300 s each (278 s of waits and a few seconds per request) with the admission re-check before every request.
    "observationSeconds": 1500,
    "recoverySeconds": 180,
    "maxTokens": 4,
    "sourceFile": Path(__file__),
}
