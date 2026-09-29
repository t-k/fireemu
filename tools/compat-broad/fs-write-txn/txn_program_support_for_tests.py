"""A small two-transport table the framework's tests run against; it is never sent to production."""

from pathlib import Path

_ROW = ("id", "transport", "rpc", "document", "tokenInput", "tokenOutput", "writes", "caseId", "role", "allow")


def _chain(prefix, transport, label):
    token = f"{transport}-{prefix}"
    return [
        (f"{prefix}/begin", transport, "BeginTransaction", None, None, token, (), None, "control", (0,)),
        (f"{prefix}/read", transport, "GetDocument", "a", token, None, (), None, "control", (0,)),
        (f"{prefix}/fail-commit", transport, "Commit", None, token, None, (("a", "held", True), ("m", "held", True)), f"{label}/fail-commit", "observation", (5, 9, 10)),
        (f"{prefix}/plain-read", transport, "GetDocument", "a", None, None, (), f"{label}/plain-read", "observation", (0,)),
        (f"{prefix}/writer", transport, "Commit", None, None, None, (("a", "moved", True),), f"{label}/writer", "outside-writer", (0, 10)),
        (f"{prefix}/rollback", transport, "Rollback", None, token, None, (), f"{label}/rollback", "observation", (0, 3, 5, 9, 10)),
        (f"{prefix}/rollback-again", transport, "Rollback", None, token, None, (), f"{label}/rollback-again", "observation", (0, 3, 5, 9, 10)),
        (f"{prefix}/post-read", transport, "GetDocument", "a", None, None, (), None, "post-state", (0,)),
    ]


def _rows():
    rows = [
        ("setup/absence-a", "grpc", "GetDocument", "a", None, None, (), None, "control", (5,)),
        ("setup/absence-m", "grpc", "GetDocument", "m", None, None, (), None, "control", (5,)),
        ("setup/create-a", "grpc", "Commit", None, None, None, (("a", "created", False),), None, "control", (0,)),
    ]
    rows += _chain("r", "rest", "rest") + _chain("g", "grpc", "grpc")
    return rows


def _step(values):
    step = dict(zip(_ROW, values, strict=True))
    step["writes"] = tuple({"document": document, "state": state, "exists": exists} for document, state, exists in step["writes"])
    if step["role"] == "outside-writer":
        step["deadlineMs"] = 30000
    if step["id"].endswith("/rollback-again"):
        step["finished"] = True
    return step


STEPS = tuple(_step(row) for row in _rows())

TABLE = {
    "name": "toy-failed-commit",
    "program": "FS-TRANSACTION-TOY",
    "envelopeId": "FS-TRANSACTION-toy-failed-commit-001",
    "slug": "txn-toy",
    "documents": ("a", "m"),
    "states": ("created", "held", "moved"),
    "steps": STEPS,
    "caps": {"observation": len(STEPS), "tokenCleanup": 4, "documentCleanup": 14, "management": 7, "credential": 2},
    "observationSeconds": 240,
    "recoverySeconds": 180,
    "maxTokens": 2,
    "sourceFile": Path(__file__),
}
