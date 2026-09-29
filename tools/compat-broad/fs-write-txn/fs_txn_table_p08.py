"""FS-TRANSACTION P08: a deliberate failed commit, what the same token can still do, and how holders and writers proceed.

This table grants no send permission. Per transport (REST first, then native gRPC) it runs three chains
against the owned documents `a` (created in setup) and `m` (never created):

- A: begin, read `a`, a commit that must be refused (it also writes `m` under an exists:true precondition),
  a plain read, a same-token read, an outside writer, a corrected commit on the same token, a rollback, and a
  repeated rollback.
- B: begin, read `a`, the refused commit, an explicit rollback, an outside writer, a repeated rollback.
- C (control): begin, read `a`, a commit that succeeds, then the rollback of a committed token (production
  answers ABORTED; recorded for REST and gRPC before this program).

Every answer a step may give is fixed here. An answer outside its set stops the recording, and an unknown
outcome (a timeout, UNAVAILABLE, INTERNAL) is never resent."""

from pathlib import Path

REFUSED = (3, 5, 9, 10)
# What a same-token request may answer once its transaction may or may not still be alive.
TOKEN_AFTER_REFUSAL = (0,) + REFUSED
STATES = ("created", "held") + tuple(f"{transport}-{label}" for transport in ("rest", "grpc") for label in ("a-writer", "a-corrected", "b-writer", "c-commit"))


def _step(step_id, transport, rpc, role, *, document=None, token_in=None, token_out=None, writes=(), case=None, allow=(0,), deadline=None):
    step = {"id": step_id, "transport": transport, "rpc": rpc, "document": document, "tokenInput": token_in, "tokenOutput": token_out,
            "writes": tuple({"document": name, "state": state, "exists": exists} for name, state, exists in writes),
            "caseId": case, "role": role, "allow": allow}
    if deadline:
        step["deadlineMs"] = deadline
    return step


def _failed_commit(chain, transport):
    token = f"{transport}-{chain}"
    return _step(f"{transport}/{chain}/fail-commit", transport, "Commit", "observation", token_in=token, writes=(("a", "held", True), ("m", "held", True)), case=f"{transport}/{chain}-fail-commit", allow=REFUSED)


def _begin(chain, transport):
    token = f"{transport}-{chain}"
    return [_step(f"{transport}/{chain}/begin", transport, "BeginTransaction", "control", token_out=token),
            _step(f"{transport}/{chain}/read-a", transport, "GetDocument", "control", document="a", token_in=token)]


def _writer(chain, transport):
    return _step(f"{transport}/{chain}/writer", transport, "Commit", "outside-writer", writes=(("a", f"{transport}-{chain}-writer", True),), case=f"{transport}/{chain}-writer", allow=(0, 10), deadline=30000)


def _rollback(chain, transport, name, case):
    return _step(f"{transport}/{chain}/{name}", transport, "Rollback", "observation", token_in=f"{transport}-{chain}", case=f"{transport}/{chain}-{case}", allow=TOKEN_AFTER_REFUSAL)


def _post_read(chain, transport):
    return _step(f"{transport}/{chain}/post-read-a", transport, "GetDocument", "post-state", document="a")


def _chains(transport):
    token = f"{transport}-a"
    a = _begin("a", transport) + [
        _failed_commit("a", transport),
        _step(f"{transport}/a/plain-read-a", transport, "GetDocument", "observation", document="a", case=f"{transport}/a-plain-read"),
        _step(f"{transport}/a/same-token-read-a", transport, "GetDocument", "observation", document="a", token_in=token, case=f"{transport}/a-same-token-read", allow=TOKEN_AFTER_REFUSAL),
        _writer("a", transport),
        _step(f"{transport}/a/corrected-commit", transport, "Commit", "observation", token_in=token, writes=(("a", f"{transport}-a-corrected", True),), case=f"{transport}/a-corrected-commit", allow=TOKEN_AFTER_REFUSAL),
        _rollback("a", transport, "rollback", "rollback"),
        _rollback("a", transport, "rollback-again", "rollback-again"),
        _post_read("a", transport),
    ]
    b = _begin("b", transport) + [
        _failed_commit("b", transport),
        _rollback("b", transport, "rollback", "rollback"),
        _writer("b", transport),
        _rollback("b", transport, "rollback-again", "rollback-again"),
        _post_read("b", transport),
    ]
    c = _begin("c", transport) + [
        _step(f"{transport}/c/commit", transport, "Commit", "observation", token_in=f"{transport}-c", writes=(("a", f"{transport}-c-commit", True),), case=f"{transport}/c-commit"),
        _step(f"{transport}/c/rollback-after-commit", transport, "Rollback", "observation", token_in=f"{transport}-c", case=f"{transport}/c-rollback-after-commit", allow=(0, 10)),
    ]
    return a + b + c


_SETUP = [
    _step("setup/absence-a", "grpc", "GetDocument", "control", document="a", allow=(5,)),
    _step("setup/absence-m", "grpc", "GetDocument", "control", document="m", allow=(5,)),
    _step("setup/create-a", "grpc", "Commit", "control", writes=(("a", "created", False),)),
]

STEPS = tuple(_SETUP + _chains("rest") + _chains("grpc"))

TABLE = {
    "name": "p08-failed-commit",
    "program": "FS-TRANSACTION-P08-FAILED-COMMIT",
    "envelopeId": "FS-TRANSACTION-p08-failed-commit-001",
    "slug": "txn-p08",
    "documents": ("a", "m"),
    "states": STATES,
    "steps": STEPS,
    # Observation is one request per step; cleanup reserves 7 per owned document.
    "caps": {"observation": len(STEPS), "tokenCleanup": 6, "documentCleanup": 14, "management": 7, "credential": 2},
    "observationSeconds": 180,
    "recoverySeconds": 180,
    "maxTokens": 6,
    "sourceFile": Path(__file__),
}
