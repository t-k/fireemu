"""FS-TRANSACTION P13a (REST): the inferred strict answers about a token past its total lifetime or idle limit, recorded.

This table grants no send permission. Owned document: `a`, created in setup. Four chains over REST, each a fresh read-write transaction.
Every answer after a wait is observed and never judged (any code is allowed): the run may stop for ownership or cleanup reasons only,
never because an answer refutes what strict does today.

- U-C (a Commit as the first request in 270 to 300 s): begin, read, 9 keepalive reads 24 s apart, a read after 12 s, then a Commit that
  writes after a further 32 s. The waits alone total 260 s and each request takes about 1.1 to 1.3 s, so the Commit lands at a token age of
  about 283 to 288 s (the P11 v4 timing). Strict answers 10 with the expired text, as P11 v4 recorded for a read and then a Commit.
- U-R (a Rollback as the first request in 270 to 300 s): the same, with a Rollback as the first request, then a read.
- I-1 (an idle-expired token): begin, read, an idle wait of 130 s (past the idle limit: P10-C accepted 110 s and refused 120 s), a read,
  a wait of 100 s, a read, a wait of 50 s, a Rollback at a token age of about 285 s, then a read. Strict (before the P13a recording) answered the first read 10, the second
  read 10 (an idle-expired token is remembered until about 300 s of token age), the Rollback 0 (the idle expiry, not the lifetime, finished it)
  and the last read 10.
- I-2 (an idle-expired token past 300 s): begin, read, an idle wait of 130 s, a read, a wait of 175 s, a read at a token age of about 310 s.
  Strict answers the first read 10 and the last 3 "Invalid transaction." (forgotten at 300 s).

All four rows are INFERRED in strict today (docs/compatibility/fs-transaction-next-campaign-preparation.md, "Strict answers that go
beyond the recordings"); this table records them. The release of a token that no accepted answer finishes is judged narrowly (10 with the
expired text, or the age rule below): `releaseAfterAgeSeconds` 275 releases a token on any definitive refusal of a Rollback once the token is
certainly older than 275 s (state `released-expired`), which P11 v4 grounds (an expired token holds no lock: the outside writer answered 0).
Without that rule a recording in which the forgotten token answers 3 would stop on an unconfirmed release.

Recorded (2026-10-01, two agreeing recordings): U-C and U-R answered 10 with the expired text at token ages of 280.4 to 284.5 s (and the read after the
Rollback 10); I-1 answered the reads at 132 s and 232 s 10, the Rollback at 286 to 289 s 10 (strict had answered 0: refuted, strict fixed) and the read after it
10; I-2 answered the first read 10 and the read at 309 to 312 s 3 "Invalid transaction.".

The table is REST only. gRPC lifetime answers were identical to REST in P11 v4; the gRPC forms of these four rows are not recorded."""

from pathlib import Path

REFUSED = (3, 5, 9, 10)
ANY_ANSWER = (0,) + REFUSED
KEEPALIVES = 9
KEEPALIVE_WAIT = 24
LIVE_WAIT = 12
EXPIRY_WAIT = 32
IDLE_WAIT = 130
STATES = ("created", "rest-uc-commit")


def _step(step_id, transport, rpc, role, *, document=None, token_in=None, token_out=None, writes=(), case=None, allow=(0,), wait=None):
    step = {"id": step_id, "transport": transport, "rpc": rpc, "document": document, "tokenInput": token_in, "tokenOutput": token_out,
            "writes": tuple({"document": name, "state": state, "exists": exists} for name, state, exists in writes),
            "caseId": case, "role": role, "allow": allow}
    if wait:
        step["waitSeconds"] = wait
    return step


def _observe(chain, name, rpc, *, wait=None, writes=(), document=None):
    return _step(f"rest/{chain}/{name}", "rest", rpc, "observation", document=document, token_in=f"rest-{chain}", writes=writes,
                 case=f"rest/{chain}-{name}", allow=ANY_ANSWER, wait=wait)


def _begin(chain):
    token = f"rest-{chain}"
    return [_step(f"rest/{chain}/begin", "rest", "BeginTransaction", "control", token_out=token),
            _step(f"rest/{chain}/read-a", "rest", "GetDocument", "control", document="a", token_in=token)]


def _aged(chain):
    steps = _begin(chain)
    for index in range(1, KEEPALIVES + 1):
        steps.append(_step(f"rest/{chain}/keepalive-{index}", "rest", "GetDocument", "observation", document="a", token_in=f"rest-{chain}", allow=ANY_ANSWER, wait=KEEPALIVE_WAIT))
    steps.append(_step(f"rest/{chain}/live-read", "rest", "GetDocument", "observation", document="a", token_in=f"rest-{chain}", allow=ANY_ANSWER, wait=LIVE_WAIT))
    return steps


def _u_commit():
    return _aged("uc") + [
        _observe("uc", "first-commit", "Commit", wait=EXPIRY_WAIT, writes=(("a", "rest-uc-commit", True),)),
        _step("rest/uc/post-read-a", "rest", "GetDocument", "post-state", document="a"),
    ]


def _u_rollback():
    return _aged("ur") + [
        _observe("ur", "first-rollback", "Rollback", wait=EXPIRY_WAIT),
        _observe("ur", "read-after", "GetDocument", document="a"),
    ]


def _idle_memory():
    return _begin("i1") + [
        _observe("i1", "idle-read", "GetDocument", wait=IDLE_WAIT, document="a"),
        _observe("i1", "memory-read", "GetDocument", wait=100, document="a"),
        _observe("i1", "late-rollback", "Rollback", wait=50),
        _observe("i1", "read-after", "GetDocument", document="a"),
    ]


def _idle_forgotten():
    return _begin("i2") + [
        _observe("i2", "idle-read", "GetDocument", wait=IDLE_WAIT, document="a"),
        _observe("i2", "late-read", "GetDocument", wait=175, document="a"),
    ]


_SETUP = [
    _step("setup/absence-a", "grpc", "GetDocument", "control", document="a", allow=(5,)),
    _step("setup/create-a", "grpc", "Commit", "control", writes=(("a", "created", False),)),
]

STEPS = tuple(_SETUP + _u_commit() + _u_rollback() + _idle_memory() + _idle_forgotten()
              + [_step("final/post-read-a", "rest", "GetDocument", "post-state", document="a")])

TABLE = {
    "name": "p13a-inferred-answers",
    "program": "FS-TRANSACTION-P13A-INFERRED-ANSWERS",
    "envelopeId": "FS-TRANSACTION-p13a-inferred-answers-001",
    "slug": "txn-p13a",
    "documents": ("a",),
    "states": STATES,
    "steps": STEPS,
    "thresholds": {"totalAgeSeconds": 270, "releaseAfterAgeSeconds": 275},
    # Observation is one request per step; cleanup reserves 7 per owned document.
    "caps": {"observation": len(STEPS), "tokenCleanup": 4, "documentCleanup": 7, "management": 7, "credential": 2},
    # Four chains of about 285, 285, 285 and 310 s (1,105 s of waits and about 55 requests) with the admission re-check before every request.
    "observationSeconds": 1320,
    "recoverySeconds": 180,
    "maxTokens": 4,
    "sourceFile": Path(__file__),
}
