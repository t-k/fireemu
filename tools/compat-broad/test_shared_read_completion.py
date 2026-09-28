"""Read-RPC retirement regression; real Gate journals, simulated wire only."""

import copy
import socket
from types import SimpleNamespace
from urllib.parse import quote

import pytest
import shared_gate
from shared_gate import Gate, can_create, create, unconfirmed_creates

ROOT = "projects/p/databases/(default)/documents"
PARENT = ROOT + "/campaign/" + "e" * 32
RESOURCE = PARENT + "/items/a"
VERSION = "2026-09-19T00:00:00Z"
ABSENT = {"error": {"code": 404, "status": "NOT_FOUND"}}
READS = [
    ("runQuery", {"structuredQuery": {"from": [{"collectionId": "items"}]},
                  "explainOptions": {"analyze": True}}),
    ("runAggregationQuery", {"structuredAggregationQuery": {
        "structuredQuery": {"from": [{"collectionId": "items"}]},
        "aggregations": [{"count": {}, "alias": "count"}]},
        "explainOptions": {"analyze": True}}),
    ("listCollectionIds", {"pageSize": 1, "pageToken": "fixture-token"}),
    ("partitionQuery", {"structuredQuery": {"from": [{"collectionId": "items"}]},
                         "partitionCount": 10, "pageToken": "fixture-token"}),
]


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    now = [1000.0]
    def sleep(seconds):
        assert seconds >= 0
        now[0] += seconds
    monkeypatch.setattr(shared_gate, "time", SimpleNamespace(
        monotonic=lambda: now[0], sleep=sleep))
    def forbidden(*args, **kwargs):
        raise AssertionError("network is forbidden")
    for name in ("create_connection", "getaddrinfo"):
        monkeypatch.setattr(socket, name, forbidden)
    for name in ("connect", "connect_ex"):
        monkeypatch.setattr(socket.socket, name, forbidden)


def operation(rpc, body, parent=PARENT):
    return {"service": "firestore", "method": "POST",
            "path": "/v1/" + parent + ":" + rpc, "body": copy.deepcopy(body)}


@pytest.mark.parametrize("rpc,body", READS)
@pytest.mark.parametrize("parent", [ROOT, PARENT, PARENT + "/children/one"])
def test_known_read_rpcs_are_non_creating(rpc, body, parent):
    assert can_create(operation(rpc, body, parent)) is False


@pytest.mark.parametrize("rpc,body", READS)
@pytest.mark.parametrize("mutation", [
    "wrong-service", "missing-service", "patch", "put", "delete", "collection",
    "extra-suffix", "wrong-version", "query-string", "fragment", "percent-path",
    "dot-parent", "dot-tail", "parent-traversal", "empty-component", "body-reference",
    "new-transaction", "existing-transaction", "write-field", "list-body", "missing-body",
])
def test_unknown_or_ambiguous_operations_still_retain_ownership(rpc, body, mutation):
    request = operation(rpc, body)
    if mutation == "wrong-service":
        request["service"] = "auth"
    elif mutation == "missing-service":
        del request["service"]
    elif mutation in {"patch", "put", "delete"}:
        request["method"] = mutation.upper()
    elif mutation == "collection":
        request["path"] = "/v1/" + PARENT + "/items:" + rpc
    elif mutation == "extra-suffix":
        request["path"] += "/item"
    elif mutation == "wrong-version":
        request["path"] = request["path"].replace("/v1/", "/v1beta1/", 1)
    elif mutation == "query-string":
        request["path"] += "?other=value"
    elif mutation == "fragment":
        request["path"] += "#suffix"
    elif mutation == "percent-path":
        request["path"] = request["path"].replace("/campaign/", "/campaign%2F/", 1)
    elif mutation == "dot-parent":
        request["path"] = "/v1/projects/./databases/(default)/documents:" + rpc
    elif mutation == "dot-tail":
        request["path"] = "/v1/" + ROOT + "/items/.:" + rpc
    elif mutation == "parent-traversal":
        request["path"] = "/v1/" + ROOT + "/items/..:" + rpc
    elif mutation == "empty-component":
        request["path"] = request["path"].replace("/campaign/", "/campaign//", 1)
    elif mutation == "body-reference":
        request["bodyRef"] = {"sha256": "f" * 64, "bytes": 100}
    elif mutation in {"new-transaction", "existing-transaction"}:
        request["body"]["newTransaction" if mutation == "new-transaction" else "transaction"] = {}
    elif mutation == "write-field":
        request["body"]["writes"] = []
    elif mutation == "list-body":
        request["body"] = [request["body"]]
    elif mutation == "missing-body":
        del request["body"]
        # An opaque reference remains potentially creating when the operation
        # cannot be recognized; a body-less POST was historically unclassified.
        request["bodyRef"] = {"sha256": "f" * 64, "bytes": 100}
    assert can_create(request) is True


def plan(request, *, scheduled):
    read = {"service": "firestore", "method": "GET",
            "path": "/v1/" + RESOURCE, "body": None}
    setup = {"service": "firestore", "method": "PATCH",
             "path": "/v1/" + RESOURCE + "?currentDocument.exists=false",
             "body": {"fields": {"_sharedOwner": {"referenceValue": RESOURCE}}}}
    recovery = [read, {**read, "method": "DELETE", "versionFrom": 0}, read]
    job = {"resources": [RESOURCE], "observation": [setup, request],
           "recovery": recovery}
    if scheduled:
        job["schedule"] = [
            {"phase": "observation", "index": 0, "creates": True},
            {"phase": "observation", "index": 1, "creates": False},
            *[{"phase": "recovery", "index": i, "creates": False} for i in range(3)],
        ]
    return {"contract": "shared-local-v2", "nonce": "e" * 32,
            "wallSeconds": 300, "recoverySeconds": 120,
            "observationRequests": 2, "requestCostMicrousd": 1,
            "costMicrousd": 20, "intervalSeconds": 0.25, "jobs": {"read": job}}


def start(tmp_path, frozen):
    path = tmp_path / "gate"
    create(path, frozen)
    gate = Gate(path, "read")
    gate.claim()
    return gate


def cleanup(gate, frozen):
    doc = {"name": RESOURCE, "fields": frozen["jobs"]["read"]["observation"][0]["body"]["fields"],
           "updateTime": VERSION}
    recovery = frozen["jobs"]["read"]["recovery"]
    gate.dispatch(recovery[0], True, lambda: (200, doc))
    delete = {k: v for k, v in recovery[1].items() if k != "versionFrom"}
    delete["path"] += "?currentDocument.updateTime=" + quote(VERSION, safe="")
    gate.dispatch(delete, True, lambda: (200, {}))
    gate.dispatch(recovery[2], True, lambda: (404, copy.deepcopy(ABSENT)))


@pytest.mark.parametrize("rpc,body", READS)
@pytest.mark.parametrize("scheduled", [False, True])
@pytest.mark.parametrize("result", ["success", "refusal", "timeout"])
def test_confirmed_create_then_read_can_finish_owned_cleanup(tmp_path, rpc, body, scheduled, result):
    request = operation(rpc, body)
    frozen = plan(request, scheduled=scheduled)
    gate = start(tmp_path, frozen)
    setup = frozen["jobs"]["read"]["observation"][0]
    gate.dispatch(setup, False, lambda: (200, {
        "name": RESOURCE, "fields": setup["body"]["fields"], "updateTime": VERSION}))
    if result == "timeout":
        def timeout():
            raise TimeoutError("simulated read response lost")
        with pytest.raises(TimeoutError):
            gate.dispatch(request, False, timeout)
    else:
        reply = (200, [{"readTime": VERSION}]) if result == "success" else (
            400, {"error": {"code": 400, "status": "INVALID_ARGUMENT"}})
        gate.dispatch(request, False, lambda: reply)
    assert unconfirmed_creates(gate.snapshot(), "read") == 0
    cleanup(gate, frozen)
    gate.finish()
    snapshot = gate.snapshot()
    assert snapshot["jobs"]["read"]["complete"] is True
    assert snapshot["total"] == 5
    assert "creationOutcome" not in snapshot["events"][1]
    assert snapshot["events"][0]["creationOutcome"] == "created"


@pytest.mark.parametrize("result", ["timeout", "server-error"])
def test_read_exception_does_not_release_an_uncertain_creation(tmp_path, result):
    request = operation(*READS[0])
    frozen = plan(request, scheduled=False)
    gate = start(tmp_path, frozen)
    setup = frozen["jobs"]["read"]["observation"][0]
    if result == "timeout":
        def timeout():
            raise TimeoutError("create may have landed")
        with pytest.raises(TimeoutError):
            gate.dispatch(setup, False, timeout)
    else:
        gate.dispatch(setup, False, lambda: (500, {"error": {"code": 500, "status": "INTERNAL"}}))
    for entry in frozen["jobs"]["read"]["recovery"]:
        request = {k: v for k, v in entry.items() if k != "versionFrom"}
        gate.dispatch(request, True, lambda: (404, copy.deepcopy(ABSENT)))
    assert unconfirmed_creates(gate.snapshot(), "read") == 1
    with pytest.raises(ValueError, match="ownership retained"):
        gate.finish()


@pytest.mark.parametrize("rpc,body", READS)
@pytest.mark.parametrize("scheduled", [False, True])
def test_read_recipe_can_release_real_ledger_only_after_typed_cleanup(
    tmp_path, rpc, body, scheduled
):
    # Import the real sibling Ledger without relying on other tests having
    # incidentally modified sys.path during collection.
    import importlib.util
    from pathlib import Path
    from broad_contract import digest

    module_path = Path(shared_gate.__file__).resolve().parent / "production-admission/reservations.py"
    spec = importlib.util.spec_from_file_location("read_recipe_reservations", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    ledger = module.Ledger.create(tmp_path / "ledger")
    request = operation(rpc, body)
    frozen = plan(request, scheduled=scheduled)
    claim = {
        "campaignId": "FS-DATA-WRITE-LIMITS-02",
        "gateJob": "read",
        "manifestDigest": digest("offline-read-fixture"),
        "nonceDigest": digest(frozen["nonce"]),
        "gatePath": str((tmp_path / "gate").resolve()),
        "gatePlanDigest": digest(frozen),
        "locks": [{"key": "project/p/firestore/(default)/documents/campaign", "mode": "WRITE"}],
        "budget": {"requests": 5, "accounts": 0, "resources": 1, "costMicrousd": 20},
        "durationSeconds": 300,
    }
    envelope = {
        "permissionDigest": "a" * 64,
        "issuedAt": 1000,
        "expiresAt": 10000,
        "limits": {"requests": 10, "accounts": 0, "resources": 2, "costMicrousd": 40},
        "concurrency": 1,
        "scopes": [{"key": "project/p", "mode": "EXCLUSIVE"}],
    }
    ticket = ledger.reserve(envelope, claim, frozen, now=1100)
    gate = start(tmp_path, frozen)
    setup = frozen["jobs"]["read"]["observation"][0]
    gate.dispatch(setup, False, lambda: (200, {
        "name": RESOURCE, "fields": setup["body"]["fields"], "updateTime": VERSION}))
    gate.dispatch(request, False, lambda: (200, [{"readTime": VERSION}]))
    with pytest.raises(ValueError, match="cleanup/accounting incomplete"):
        ledger.finish(ticket)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"
    cleanup(gate, frozen)
    gate.finish()
    ledger.finish(ticket)
    snapshot = ledger.snapshot()
    assert snapshot["reservations"][ticket["reservation"]]["state"] == "released"
    assert snapshot["envelopes"][digest(envelope)]["allocated"] == claim["budget"]
