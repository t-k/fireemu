"""FS-TRANSACTION P02b: what a read-only token answers after a write commit on it was refused.

This table grants no send permission. Owned document: `a`, created in setup. Per transport (REST, then native gRPC),
two chains, each a fresh read-only transaction that reads `a`, has a write commit refused, and then meets the same
token again in one of two orders:

- X: a GetDocument, then an empty Commit;
- Y: an empty Commit, then a GetDocument.

Each chain ends with a Rollback and a plain read. The 2026-09-07 production matrix row (conformance/firestore-production-matrix.json,
program `transactions/lifecycle`, steps `read-only-commit-with-writes` then `read-only-commit-without-writes`) recorded a
refused write followed by an empty commit answering `INVALID_ARGUMENT` "no longer valid" on REST; P02 recorded that an
empty commit of a fresh read-only token answers 0. These chains record the token's other uses after the refusal, in both
orders and on both transports, so no order is assumed. Every answer a step may give is fixed here."""

from pathlib import Path

REFUSED = (3, 5, 9, 10)
STATES = ("created", "held")


def _step(step_id, transport, rpc, role, *, document=None, token_in=None, token_out=None, mode=None, writes=(), case=None, allow=(0,)):
    step = {"id": step_id, "transport": transport, "rpc": rpc, "document": document, "tokenInput": token_in, "tokenOutput": token_out,
            "writes": tuple({"document": name, "state": state, "exists": exists} for name, state, exists in writes),
            "caseId": case, "role": role, "allow": allow}
    if mode:
        step["mode"] = mode
    return step


def _observe(chain, transport, name, rpc, *, allow, writes=(), document=None):
    return _step(f"{transport}/{chain}/{name}", transport, rpc, "observation", document=document, token_in=f"{transport}-{chain}", writes=writes, case=f"{transport}/{chain}-{name}", allow=allow)


def _chain(transport, chain, order):
    token = f"{transport}-{chain}"
    later = {"get": lambda: _observe(chain, transport, "get-after", "GetDocument", document="a", allow=(0,) + REFUSED),
             "commit": lambda: _observe(chain, transport, "commit-empty", "Commit", allow=(0,) + REFUSED)}
    return [_step(f"{transport}/{chain}/begin", transport, "BeginTransaction", "control", token_out=token, mode="readOnly"),
            _step(f"{transport}/{chain}/read-a", transport, "GetDocument", "control", document="a", token_in=token),
            _observe(chain, transport, "ro-write", "Commit", writes=(("a", "held", True),), allow=REFUSED),
            *[later[name]() for name in order],
            _observe(chain, transport, "rollback", "Rollback", allow=(0,) + REFUSED),
            _step(f"{transport}/{chain}/post-read-a", transport, "GetDocument", "post-state", document="a")]


_SETUP = [
    _step("setup/absence-a", "grpc", "GetDocument", "control", document="a", allow=(5,)),
    _step("setup/create-a", "grpc", "Commit", "control", writes=(("a", "created", False),)),
]

STEPS = tuple(_SETUP + [step for transport in ("rest", "grpc") for chain, order in (("x", ("get", "commit")), ("y", ("commit", "get"))) for step in _chain(transport, chain, order)])

TABLE = {
    "name": "p02b-readonly-refused",
    "program": "FS-TRANSACTION-P02B-READONLY-REFUSED",
    "envelopeId": "FS-TRANSACTION-p02b-readonly-refused-001",
    "slug": "txn-p02b",
    "documents": ("a",),
    "states": STATES,
    "steps": STEPS,
    # Observation is one request per step; cleanup reserves 7 per owned document.
    "caps": {"observation": len(STEPS), "tokenCleanup": 4, "documentCleanup": 7, "management": 7, "credential": 2},
    "observationSeconds": 180,
    "recoverySeconds": 180,
    "maxTokens": 4,
    "sourceFile": Path(__file__),
}
