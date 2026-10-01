"""FS-TRANSACTION P13b (REST): what a retry (`retryTransaction`) does with an expired or finished token, and when a retry attempt takes its snapshot.

This table grants no send permission. Owned document: `a`, created in setup. Four chains over REST. What is judged (a different answer stops
the run): the setup and every chain's begin and first read (controls), the retry that follows RT-1's Rollback (a control: recorded as accepted
for REST in P09 and P10), RT-1's Rollback (0 or 10), RT-1's outside writer (0 or 10) and the final read of `a` (0). Every other answer is
observed and never judged, so no answer that refutes what strict does today can stop the run: it may stop for ownership or cleanup reasons only.

- RT-1 (the retry snapshot): begin T1, read, Rollback T1, a retry of T1 (T1r), an outside writer commits `a`, the first read in T1r (it may show the
  writer, as the official emulator's read-write transactions do at first use, or not), a Commit in T1r. Strict reads a retry attempt at
  its begin today; this records which one production does.
- RT-2 (a retry naming an idle-expired token, no Rollback first): begin T2, read, an idle wait of 130 s, a retry of T2. Strict refuses it
  ("Invalid retry transaction.") because nothing finished T2 as rolled back.
- RT-3 (a retry naming an idle-expired token after its Rollback): begin T3, read, an idle wait of 130 s, a Rollback of T3, a retry of T3.
- RT-4 (a retry naming a lifetime-expired token): begin T4, read, 9 keepalive reads 24 s apart, a read after 12 s, then after 32 s a retry of T4
  (the token is then about 280 to 285 s old, past the 270 s lifetime and inside the remembered window: P13a recorded 280.4 to 284.5 s for the same waits).

The retry of RT-2 to RT-4 ends its chain, so a refusal (no token issued) strands no step; an accepted retry issues a token that the cleanup releases.
The strict answers are INFERRED today ("Strict answers that go beyond the recordings"); this table records them. The release of a token that no accepted
answer finishes is judged narrowly, with `releaseAfterAgeSeconds` 275 for a token certainly older than that (T4, T4r); an idle-expired token (T2, T3) whose
release is refused with anything but the expired text stops the run on an unconfirmed release, an ownership stop.

An accepted retry mints a fresh token (the P09 and P10 recordings: a retry of a committed, a rolled-back and a get-first token each answered 0 with a
transaction value different from the one it named), which is what the ledger requires of every issued token.

REST only: the shared gRPC wire cannot send `retryTransaction`."""

from pathlib import Path

REFUSED = (3, 5, 9, 10)
ANY_ANSWER = (0,) + REFUSED
KEEPALIVES = 9
KEEPALIVE_WAIT = 24
LIVE_WAIT = 12
EXPIRY_WAIT = 32
IDLE_WAIT = 130
STATES = ("created", "rest-rt1-writer", "rest-rt1-commit")


def _step(step_id, rpc, role, *, transport="rest", document=None, token_in=None, token_out=None, writes=(), case=None, allow=(0,), wait=None, retry_of=None, since_begin=False, deadline=None):
    step = {"id": step_id, "transport": transport, "rpc": rpc, "document": document, "tokenInput": token_in, "tokenOutput": token_out,
            "writes": tuple({"document": name, "state": state, "exists": exists} for name, state, exists in writes),
            "caseId": case, "role": role, "allow": allow}
    if wait:
        step["waitSeconds"] = wait
    if retry_of:
        step["retryOf"] = retry_of
    if since_begin:
        step["sinceBegin"] = True
    if deadline:
        step["deadlineMs"] = deadline
    return step


def _begin(chain, token):
    return [_step(f"rest/{chain}/begin", "BeginTransaction", "control", token_out=token),
            _step(f"rest/{chain}/read-a", "GetDocument", "control", document="a", token_in=token)]


def _retry_snapshot():
    return _begin("rt1", "t1") + [
        _step("rest/rt1/rollback", "Rollback", "observation", token_in="t1", case="rest/rt1-rollback", allow=(0, 10)),
        _step("rest/rt1/retry-begin", "BeginTransaction", "control", token_out="t1r", retry_of="t1"),
        _step("rest/rt1/writer", "Commit", "outside-writer", writes=(("a", "rest-rt1-writer", True),), case="rest/rt1-writer", allow=(0, 10), deadline=30000),
        _step("rest/rt1/first-read", "GetDocument", "observation", document="a", token_in="t1r", case="rest/rt1-first-read", allow=ANY_ANSWER, since_begin=True),
        _step("rest/rt1/commit", "Commit", "observation", token_in="t1r", writes=(("a", "rest-rt1-commit", True),), case="rest/rt1-commit", allow=ANY_ANSWER),
    ]


def _retry_idle():
    return _begin("rt2", "t2") + [
        _step("rest/rt2/retry-idle", "BeginTransaction", "observation", token_out="t2r", retry_of="t2", case="rest/rt2-retry-idle", allow=ANY_ANSWER, wait=IDLE_WAIT),
    ]


def _retry_after_rollback():
    return _begin("rt3", "t3") + [
        _step("rest/rt3/rollback-idle", "Rollback", "observation", token_in="t3", case="rest/rt3-rollback-idle", allow=ANY_ANSWER, wait=IDLE_WAIT),
        _step("rest/rt3/retry-after-rollback", "BeginTransaction", "observation", token_out="t3r", retry_of="t3", case="rest/rt3-retry-after-rollback", allow=ANY_ANSWER),
    ]


def _retry_lifetime():
    steps = _begin("rt4", "t4")
    for index in range(1, KEEPALIVES + 1):
        steps.append(_step(f"rest/rt4/keepalive-{index}", "GetDocument", "observation", document="a", token_in="t4", allow=ANY_ANSWER, wait=KEEPALIVE_WAIT))
    steps.append(_step("rest/rt4/live-read", "GetDocument", "observation", document="a", token_in="t4", allow=ANY_ANSWER, wait=LIVE_WAIT))
    steps.append(_step("rest/rt4/retry-lifetime", "BeginTransaction", "observation", token_out="t4r", retry_of="t4", case="rest/rt4-retry-lifetime", allow=ANY_ANSWER, wait=EXPIRY_WAIT))
    return steps


_SETUP = [
    _step("setup/absence-a", "GetDocument", "control", transport="grpc", document="a", allow=(5,)),
    _step("setup/create-a", "Commit", "control", transport="grpc", writes=(("a", "created", False),)),
]

STEPS = tuple(_SETUP + _retry_snapshot() + _retry_idle() + _retry_after_rollback() + _retry_lifetime()
              + [_step("final/post-read-a", "GetDocument", "post-state", document="a")])

TABLE = {
    "name": "p13b-retry-answers",
    "program": "FS-TRANSACTION-P13B-RETRY-ANSWERS",
    "envelopeId": "FS-TRANSACTION-p13b-retry-answers-001",
    "slug": "txn-p13b",
    "documents": ("a",),
    "states": STATES,
    "steps": STEPS,
    "thresholds": {"totalAgeSeconds": 270, "releaseAfterAgeSeconds": 275},
    # Observation is one request per step; cleanup reserves 7 per owned document and a release per token.
    "caps": {"observation": len(STEPS), "tokenCleanup": 8, "documentCleanup": 7, "management": 7, "credential": 2},
    # Four chains: about 10 s, 135 s, 270 s and 285 s of waits and requests, 520 s of waits in all, and the admission re-check before every request.
    "observationSeconds": 780,
    "recoverySeconds": 180,
    "maxTokens": 8,
    "sourceFile": Path(__file__),
}
