"""FS-TRANSACTION P12 (REST): what a transaction answers as its FIRST request after its total lifetime, and the requests after it.

This table grants no send permission. Owned document: `a`, created in setup. Two chains over REST, each a fresh read-write
transaction that is kept alive by reads (9 reads 24 s apart, then one 90 s wait) and then meets an expiry, not a read, first:

- C (Commit first): the first request after the wait is a Commit that writes; then two reads; then a Rollback.
- R (Rollback first): the first request after the wait is a Rollback; then a read; then a Commit that writes.

The first request lands at a token age past 301 s. P11 recording 1 (REST) saw a request live at a token age of 246.8 to 249.2 s
and refused at 298.7 to 301.0 s, so the lifetime lies in (246.8, 301.0]; the waits alone total 306 s, and the real age at the first
request is about 325 s (P11 pace: an RPC about 1.1 to 1.3 s, each wait about 0.6 s long). The 90 s idle before that request is
inside the idle a recorded request was accepted after (75 to 110 s, P10-C). The documented 270 s is not relied on.

P11 recorded only read, Commit, Rollback (10, 3, 3). Models that fit it: A "the first refused request answers 10, then everything
answers 3"; B "a read answers 10, a Commit and a Rollback answer 3"; C "the first request answers by its RPC (a read 10, a Commit
or Rollback 3) and the token is then forgotten, so a later read answers 3"; and D "production forgets an expired transaction at
about 300 s, and every request after that answers 3". C and R separate A, B and C by their first answers and by `read-after`;
D is not separated from A at ages of 300 s or less, and this table starts past that age. Past 300 s model D predicts the same
answers as model C, so this table cannot separate C from D; P11 v3's Commit at about 283 s (model C: 3, model D: 10) can, which is why
P11 v3 runs before this table. A result that looks like A after 301 s is named as such when it is judged.

Every answer after the wait is observed, never judged (any code is allowed); the keepalive reads are observations without case
ids. The release of the token is judged, narrowly: a Rollback finishes it on an accepted answer, on 10 with the expired text, or on
3 "Invalid transaction." after such a 10; and, because the table declares `releaseAfterAgeSeconds` 315, on any definitive refusal
of a Rollback once the token is certainly older than 315 s (state `released-expired`, shown in the projection). Without that rule
a recording under model C would stop after the first chain with the token unconfirmed. Its premise, that a token past its
lifetime holds no lock, is what P11's outside writer after expiry records (P11 v3), so the run order is P11 v3, then this table. The
age is 315, not 301: the lower bound of the real age at the first request is the waits (306 s) plus ten requests at the recorded
minimum pace (1.1 s), about 317 s, which leaves the rule 2 s of margin above the age and 14 s above the recorded refusal.

gRPC follows in its own packet (one representative chain C) after P11 has recorded the gRPC lifetime."""

from pathlib import Path

REFUSED = (3, 5, 9, 10)
ANY_ANSWER = (0,) + REFUSED
KEEPALIVES = 9
KEEPALIVE_WAIT = 24
EXPIRY_WAIT = 90
STATES = ("created",) + tuple(f"{transport}-{label}" for transport in ("rest",) for label in ("c-commit", "r-commit"))


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

STEPS = tuple(_SETUP + _commit_first("rest") + _rollback_first("rest"))

TABLE = {
    "name": "p12-first-request",
    "program": "FS-TRANSACTION-P12-FIRST-REQUEST",
    "envelopeId": "FS-TRANSACTION-p12-first-request-001",
    "slug": "txn-p12",
    "documents": ("a",),
    "states": STATES,
    "steps": STEPS,
    "thresholds": {"totalAgeSeconds": 270, "releaseAfterAgeSeconds": 315},
    # Observation is one request per step; cleanup reserves 7 per owned document.
    "caps": {"observation": len(STEPS), "tokenCleanup": 2, "documentCleanup": 7, "management": 7, "credential": 2},
    # Two chains of about 336 s each (306 s of waits and about 30 s of requests) with the admission re-check before every request.
    "observationSeconds": 900,
    "recoverySeconds": 180,
    "maxTokens": 2,
    "sourceFile": Path(__file__),
}
