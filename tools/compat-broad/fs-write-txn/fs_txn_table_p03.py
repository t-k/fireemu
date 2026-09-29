"""FS-TRANSACTION P03: reads at a time in the past, read-only transactions at a time, and an embedded new transaction.

This table grants no send permission. Owned documents: `a` (created in setup, then updated twice, so it has three
acknowledged versions) and `m` (never created). A read time is the time a version's commit was acknowledged, taken from
the write acknowledgement itself, never from a clock. Per transport:

- a plain read of the current value (the control), then a Get of `a` at version 1 (and, over REST, at version 0) and a
  batch read of `a` and `m` at version 1;
- a read-only transaction that begins at version 1, and two reads inside it that must show version 1;
- a batch read that embeds a new read-write transaction, a read inside it, a commit that writes, and a plain read.

REST runs every case. Native gRPC is a representative subset so the request cap stays well inside the corpus proposal's 72."""

from pathlib import Path

REFUSED = (3, 5, 9, 10)
STATES = ("created", "v1", "v2", "rest-emb-commit", "grpc-emb-commit")


def _step(step_id, transport, rpc, role, *, document=None, documents=None, token_in=None, token_out=None, mode=None, read_at=None, new_transaction=None, writes=(), case=None, allow=(0,)):
    step = {"id": step_id, "transport": transport, "rpc": rpc, "document": document, "tokenInput": token_in, "tokenOutput": token_out,
            "writes": tuple({"document": name, "state": state, "exists": exists} for name, state, exists in writes),
            "caseId": case, "role": role, "allow": allow}
    if documents:
        step["documents"] = tuple(documents)
    if mode:
        step["mode"] = mode
    if read_at is not None:
        step["readAt"] = {"document": "a", "version": read_at}
    if new_transaction:
        step["newTransaction"] = new_transaction
    return step


def _case(transport, name):
    return f"{transport}/{name}"


def _plain(transport, name, **kwargs):
    return _step(f"{transport}/{name}", transport, kwargs.pop("rpc", "GetDocument"), "observation", case=_case(transport, name), **kwargs)


def _chains(transport, full):
    steps = [
        _plain(transport, "current-a", document="a"),
        _plain(transport, "get-at-v1", document="a", read_at=1),
    ]
    if full:
        steps.append(_plain(transport, "get-at-v0", document="a", read_at=0))
    steps += [
        _plain(transport, "batch-at-v1", rpc="BatchGetDocuments", documents=("a", "m"), read_at=1),
        _step(f"{transport}/ro/begin", transport, "BeginTransaction", "control", token_out=f"{transport}-ro", mode="readOnly", read_at=1),
        _step(f"{transport}/ro/read-a", transport, "GetDocument", "observation", document="a", token_in=f"{transport}-ro", case=_case(transport, "ro-read-a")),
    ]
    if full:
        steps.append(_step(f"{transport}/ro/batch", transport, "BatchGetDocuments", "observation", documents=("a", "m"), token_in=f"{transport}-ro", case=_case(transport, "ro-batch")))
    steps.append(_step(f"{transport}/emb/batch-new", transport, "BatchGetDocuments", "observation", documents=("a", "m"), token_out=f"{transport}-emb", new_transaction="readWrite", case=_case(transport, "emb-batch-new")))
    if full:
        steps.append(_step(f"{transport}/emb/get-a", transport, "GetDocument", "observation", document="a", token_in=f"{transport}-emb", case=_case(transport, "emb-get-a")))
    steps += [
        _step(f"{transport}/emb/commit", transport, "Commit", "observation", token_in=f"{transport}-emb", writes=(("a", f"{transport}-emb-commit", True),), case=_case(transport, "emb-commit")),
        _step(f"{transport}/emb/post-read-a", transport, "GetDocument", "post-state", document="a"),
    ]
    return steps


_SETUP = [
    _step("setup/absence-a", "grpc", "GetDocument", "control", document="a", allow=(5,)),
    _step("setup/absence-m", "grpc", "GetDocument", "control", document="m", allow=(5,)),
    _step("setup/create-a", "grpc", "Commit", "control", writes=(("a", "created", False),)),
    _step("setup/update-a-1", "grpc", "Commit", "control", writes=(("a", "v1", True),)),
    _step("setup/update-a-2", "grpc", "Commit", "control", writes=(("a", "v2", True),)),
]

STEPS = tuple(_SETUP + _chains("rest", True) + _chains("grpc", False))

TABLE = {
    "name": "p03-readtime",
    "program": "FS-TRANSACTION-P03-READTIME",
    "envelopeId": "FS-TRANSACTION-p03-readtime-001",
    "slug": "txn-p03",
    "documents": ("a", "m"),
    "states": STATES,
    "steps": STEPS,
    # Observation is one request per step; cleanup reserves 7 per owned document.
    "caps": {"observation": len(STEPS), "tokenCleanup": 4, "documentCleanup": 14, "management": 7, "credential": 2},
    "observationSeconds": 180,
    "recoverySeconds": 180,
    "maxTokens": 4,
    "sourceFile": Path(__file__),
}
