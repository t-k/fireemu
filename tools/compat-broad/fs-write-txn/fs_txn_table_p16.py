"""P16: foreign database/project tokens, with no production send permission."""

from pathlib import Path

WIDE = (0, 3, 5, 9, 10)
DATABASES = {"named": "projects/fireemu-oracle-query/databases/txn-{nonce}", "foreign": "projects/fireemu-oracle-txn/databases/(default)"}


def _step(site, transport, rpc, *, alias=None, document=None, token=None, output=None, writes=(), documents=None, observe=False, allow=(0,)):
    return {"id": site, "transport": transport, "rpc": rpc, "document": document, "tokenInput": token, "tokenOutput": output,
            "writes": [{"document": role, "state": "created", "exists": exists} for role, exists in writes], "caseId": site if observe else None,
            "role": "observation" if observe else "control", "allow": WIDE if observe else allow,
            **({"onDatabase": alias} if alias else {}), **({"documents": documents} if documents else {})}


steps = [_step(f"setup/absence-{role}", "grpc", "GetDocument", alias=alias, document=role, allow=(5,)) for role, alias in (("a", None), ("b", "named"), ("m", "foreign"))]
steps += [_step(f"setup/create-{role}", "grpc", "Commit", alias=alias, writes=((role, False),)) for role, alias in (("a", None), ("b", "named"))]
for transport in ("rest", "grpc"):
    # A valid token on the named database controls all four target RPCs.
    token = f"{transport}-valid"
    steps += [
        _step(f"{transport}/valid/begin", transport, "BeginTransaction", alias="named", output=token),
        _step(f"{transport}/valid/get", transport, "GetDocument", alias="named", document="b", token=token),
        _step(f"{transport}/valid/batch", transport, "BatchGetDocuments", alias="named", documents=["b"], token=token),
        _step(f"{transport}/valid/commit", transport, "Commit", alias="named", token=token),
        _step(f"{transport}/valid/begin-rollback", transport, "BeginTransaction", alias="named", output=token + "-rollback"),
        _step(f"{transport}/valid/rollback", transport, "Rollback", alias="named", token=token + "-rollback"),
    ]
    for alias, role, rpcs in (("named", "b", ("GetDocument", "BatchGetDocuments", "Commit", "Rollback")), ("foreign", "m", ("GetDocument", "BatchGetDocuments", "Rollback"))):
        for rpc in rpcs:
            if transport == "grpc" and rpc == "BatchGetDocuments":
                continue
            token = f"{transport}-{alias}-{rpc}"
            site = f"{transport}/{alias}/{rpc}"
            # Each foreign use has a fresh primary-database token and a successful primary read.
            steps += [
                _step(site + "/begin", transport, "BeginTransaction", output=token),
                _step(site + "/control", transport, "GetDocument", document="a", token=token),
                _step(site, transport, rpc, alias=alias, token=token, document=role if rpc == "GetDocument" else None,
                      documents=[role] if rpc == "BatchGetDocuments" else None, writes=(("b", True),) if rpc == "Commit" else (), observe=True),
                _step(site + "/release", transport, "Rollback", token=token, observe=True),
            ]

TABLE = {
    "name": "p16-foreign-tokens", "program": "FS-TRANSACTION-P16-FOREIGN-TOKENS", "envelopeId": "FS-TRANSACTION-p16-foreign-tokens-001",
    "slug": "txn-p16", "project": "fireemu-oracle-query", "databases": DATABASES, "placements": {"b": "named", "m": "foreign"},
    "documents": ("a", "b", "m"), "states": ("created",), "steps": tuple(steps),
    "caps": {"observation": len(steps), "tokenCleanup": 16, "documentCleanup": 21, "management": 32, "credential": 2},
    "observationSeconds": 1200, "recoverySeconds": 300, "maxTokens": 16, "sourceFile": Path(__file__),
}
