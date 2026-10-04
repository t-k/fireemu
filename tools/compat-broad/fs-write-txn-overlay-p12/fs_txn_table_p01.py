"""FS-TRANSACTION P01: the read-write transaction lifecycle, and what each way of ending it leaves usable.

This table grants no send permission. Owned documents: `a` (created in setup) and `m` (never created; a batch read
must report it missing). Every chain uses a fresh read-write transaction and ends by a commit that writes, an empty
commit, or a rollback; each end is followed by the requests a client might still try on that token, and a plain read
proves what became visible.

REST runs every chain. Native gRPC is a representative subset (setup and the same three ends, with fewer follow-ups),
so the request cap stays inside the corpus proposal's 72."""

from pathlib import Path

REFUSED = (3, 5, 9, 10)
# What a request on an ended token may answer: production says the transaction is invalid, or a read may still answer.
AFTER_END = (0,) + REFUSED
STATES = ("created",) + tuple(f"{transport}-{label}" for transport in ("rest", "grpc") for label in ("l-commit", "l-again", "e-after", "r-after"))


def _step(step_id, transport, rpc, role, *, document=None, documents=None, token_in=None, token_out=None, writes=(), case=None, allow=(0,)):
    step = {"id": step_id, "transport": transport, "rpc": rpc, "document": document, "tokenInput": token_in, "tokenOutput": token_out,
            "writes": tuple({"document": name, "state": state, "exists": exists} for name, state, exists in writes),
            "caseId": case, "role": role, "allow": allow}
    if documents:
        step["documents"] = tuple(documents)
    return step


def _begin(chain, transport):
    return _step(f"{transport}/{chain}/begin", transport, "BeginTransaction", "control", token_out=f"{transport}-{chain}")


def _read(chain, transport):
    return _step(f"{transport}/{chain}/read-a", transport, "GetDocument", "control", document="a", token_in=f"{transport}-{chain}")


def _observe(chain, transport, name, rpc, *, allow=(0,), writes=(), documents=None, document=None, token=True):
    return _step(f"{transport}/{chain}/{name}", transport, rpc, "observation", document=document, documents=documents, token_in=f"{transport}-{chain}" if token else None, writes=writes, case=f"{transport}/{chain}-{name}", allow=allow)


def _post(chain, transport):
    return _step(f"{transport}/{chain}/post-read-a", transport, "GetDocument", "post-state", document="a")


def _write(transport, label):
    return (("a", f"{transport}-{label}", True),)


def _rest():
    t = "rest"
    lifecycle = [_begin("l", t), _read("l", t),
                 _observe("l", t, "batch", "BatchGetDocuments", documents=("a", "m")),
                 _observe("l", t, "commit", "Commit", writes=_write(t, "l-commit")),
                 _observe("l", t, "commit-again", "Commit", writes=_write(t, "l-again"), allow=REFUSED),
                 _observe("l", t, "get-after-commit", "GetDocument", document="a", allow=AFTER_END),
                 _observe("l", t, "batch-after-commit", "BatchGetDocuments", documents=("a",), allow=AFTER_END),
                 _observe("l", t, "rollback-after-commit", "Rollback", allow=(0, 10)),
                 _post("l", t)]
    empty = [_begin("e", t), _read("e", t),
             _observe("e", t, "empty-commit", "Commit"),
             _observe("e", t, "commit-after-empty", "Commit", writes=_write(t, "e-after"), allow=REFUSED),
             _observe("e", t, "get-after-empty", "GetDocument", document="a", allow=AFTER_END),
             _post("e", t)]
    rolled = [_begin("r", t), _read("r", t),
              _observe("r", t, "rollback", "Rollback"),
              _observe("r", t, "commit-after-rollback", "Commit", writes=_write(t, "r-after"), allow=REFUSED),
              _observe("r", t, "get-after-rollback", "GetDocument", document="a", allow=AFTER_END),
              _observe("r", t, "batch-after-rollback", "BatchGetDocuments", documents=("a", "m"), allow=AFTER_END),
              _post("r", t)]
    return lifecycle + empty + rolled


def _grpc():
    t = "grpc"
    lifecycle = [_begin("l", t),
                 _observe("l", t, "batch", "BatchGetDocuments", documents=("a", "m")),
                 _observe("l", t, "commit", "Commit", writes=_write(t, "l-commit")),
                 _observe("l", t, "commit-again", "Commit", writes=_write(t, "l-again"), allow=REFUSED),
                 _observe("l", t, "get-after-commit", "GetDocument", document="a", allow=AFTER_END),
                 _post("l", t)]
    empty = [_begin("e", t),
             _observe("e", t, "empty-commit", "Commit"),
             _observe("e", t, "commit-after-empty", "Commit", writes=_write(t, "e-after"), allow=REFUSED),
             _post("e", t)]
    rolled = [_begin("r", t),
              _observe("r", t, "rollback", "Rollback"),
              _observe("r", t, "commit-after-rollback", "Commit", writes=_write(t, "r-after"), allow=REFUSED),
              _post("r", t)]
    return lifecycle + empty + rolled


_SETUP = [
    _step("setup/absence-a", "grpc", "GetDocument", "control", document="a", allow=(5,)),
    _step("setup/absence-m", "grpc", "GetDocument", "control", document="m", allow=(5,)),
    _step("setup/create-a", "grpc", "Commit", "control", writes=(("a", "created", False),)),
]

STEPS = tuple(_SETUP + _rest() + _grpc())

TABLE = {
    "name": "p01-lifecycle",
    "program": "FS-TRANSACTION-P01-LIFECYCLE",
    "envelopeId": "FS-TRANSACTION-p01-lifecycle-001",
    "slug": "txn-p01",
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
