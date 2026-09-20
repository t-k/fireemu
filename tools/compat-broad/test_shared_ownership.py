"""Ownership regressions at the generic Adapter/Gate callback boundary, offline."""

import copy
from urllib.parse import quote

import pytest
from batch_adapter import Adapter, observer_digest
from batch_contract import candidate
from shared_cases import manifest, op
from shared_gate import Gate, create

VERSION = "2026-09-14T00:00:00Z"
FOREIGN_VERSION = "2026-09-14T00:00:01Z"


def harness(tmp_path):
    plan = manifest("c" * 32)
    plan.update(
        coordinatorRequests=0,
        localOrigins={
            "auth": "http://127.0.0.1:12345",
            "firestore": "http://127.0.0.1:12346",
        },
        observerSha256=observer_digest(),
    )
    key = "transaction-field"
    path = tmp_path / "gate"
    create(path, plan)
    adapter = Adapter(
        candidate(),
        plan["nonce"],
        tmp_path / "adapter",
        local_origins=plan["localOrigins"],
    )
    gate = adapter.shared_gate = Gate(path, key)
    gate.claim()
    name = plan["jobs"][key]["resources"][0]
    operation = plan["jobs"][key]["observation"][1]
    document = {
        "name": name,
        "fields": copy.deepcopy(operation["body"]["fields"]),
        "updateTime": VERSION,
    }
    return plan, adapter, gate, name, document


def dispatch(adapter, operation, response, *, recovery=False):
    adapter.budget.recovery = recovery

    def send():
        if isinstance(response, BaseException):
            raise response
        return response

    return adapter.shared_gate.adapter_request(adapter, operation, send)


@pytest.mark.parametrize(
    "variant",
    [
        "conflict",
        "lost",
        "wrong-name",
        "missing-name",
        "missing-version",
        "empty-version",
        "invalid-version",
        "bool-version",
        "bool-status",
        "wrong-fields",
        "bool-fields",
    ],
)
def test_unproved_creation_never_adopts_foreign_recovery_version(tmp_path, variant):
    plan, adapter, gate, name, document = harness(tmp_path)
    observations = plan["jobs"]["transaction-field"]["observation"]
    dispatch(
        adapter, observations[0], (404, {"error": {"code": 404, "status": "NOT_FOUND"}})
    )
    response = (200, copy.deepcopy(document))
    if variant == "conflict":
        response = (409, {"error": {"code": 409}})
    elif variant == "lost":
        response = TimeoutError("response lost after another writer created")
    elif variant == "bool-status":
        response = (True, response[1])
    elif variant in {"wrong-name", "missing-name"}:
        response[1]["name"] = "foreign" if variant == "wrong-name" else None
    elif variant == "wrong-fields":
        response[1]["fields"] = {}
    elif variant == "bool-fields":
        response[1]["fields"]["a"] = {"integerValue": True}
    else:
        response[1]["updateTime"] = {
            "missing-version": None,
            "empty-version": "",
            "invalid-version": "not-a-timestamp",
            "bool-version": True,
        }[variant]
    try:
        dispatch(adapter, observations[1], response)
    except (ValueError, TimeoutError):
        pass
    foreign = {**document, "updateTime": FOREIGN_VERSION}
    dispatch(adapter, op(name), (200, foreign), recovery=True)
    before = gate.snapshot()
    called = []
    deletion = op(
        name + "?currentDocument.updateTime=" + quote(FOREIGN_VERSION, safe=""),
        "DELETE",
    )
    try:
        gate.adapter_request(
            adapter, deletion, lambda: (called.append(True) or 200, {})
        )
    except ValueError:
        pass
    assert called == [], "unproved create must not authorize a destructive callback"
    after = gate.snapshot()
    assert after["total"] == before["total"]
    assert after["costMicrousd"] == before["costMicrousd"]
    assert name not in after["jobs"]["transaction-field"]["owned"]


def test_successful_conditional_create_cleans_up_only_exact_created_version(tmp_path):
    plan, adapter, gate, name, document = harness(tmp_path)
    operations = plan["jobs"]["transaction-field"]["observation"]
    dispatch(
        adapter, operations[0], (404, {"error": {"code": 404, "status": "NOT_FOUND"}})
    )
    assert gate.snapshot()["jobs"]["transaction-field"]["owned"] == []
    dispatch(adapter, operations[1], (200, document))
    dispatch(adapter, op(name), (200, document), recovery=True)
    dispatch(
        adapter,
        op(name + "?currentDocument.updateTime=" + quote(VERSION, safe=""), "DELETE"),
        (200, {}),
        recovery=True,
    )
    dispatch(
        adapter,
        op(name),
        (404, {"error": {"code": 404, "status": "NOT_FOUND"}}),
        recovery=True,
    )
    gate.finish()
    assert gate.snapshot()["jobs"]["transaction-field"]["complete"]


def test_replacement_read_cannot_transfer_ownership_or_consume_delete_budget(tmp_path):
    plan, adapter, gate, name, document = harness(tmp_path)
    for operation, response in zip(
        plan["jobs"]["transaction-field"]["observation"][:2],
        [(404, {"error": {"code": 404, "status": "NOT_FOUND"}}), (200, document)],
        strict=True,
    ):
        dispatch(adapter, operation, response)
    dispatch(
        adapter,
        op(name),
        (200, {**document, "updateTime": FOREIGN_VERSION}),
        recovery=True,
    )
    before = gate.snapshot()
    with pytest.raises(ValueError, match="ownership|creation"):
        gate.adapter_request(
            adapter,
            op(
                name + "?currentDocument.updateTime=" + quote(FOREIGN_VERSION, safe=""),
                "DELETE",
            ),
            lambda: pytest.fail("foreign delete"),
        )
    after = gate.snapshot()
    assert (after["total"], after["costMicrousd"], after["reservedRecovery"]) == (
        before["total"],
        before["costMicrousd"],
        before["reservedRecovery"],
    )


@pytest.fixture
def document_server():
    """A private ephemeral HTTP fixture with actual conditional-write semantics."""
    import json
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import parse_qs, urlsplit

    state = {"docs": {}, "calls": [], "fault": None}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def handle_request(self):
            parsed = urlsplit(self.path)
            name = parsed.path.removeprefix("/v1/")
            query = parse_qs(parsed.query)
            payload = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            body = json.loads(payload) if payload else None
            state["calls"].append((self.command, name, query))
            docs = state["docs"]
            fault = state["fault"] if "transaction-field" in name else None
            status, response = 200, {}
            if self.command == "GET":
                status, response = (
                    (200, docs[name])
                    if name in docs
                    else (404, {"error": {"code": 404, "status": "NOT_FOUND"}})
                )
            elif self.command == "PATCH":
                if fault == "conflict":
                    docs[name] = {
                        "name": name,
                        "fields": {"foreign": {"booleanValue": True}},
                        "updateTime": FOREIGN_VERSION,
                    }
                if name in docs:
                    status = 409
                else:
                    docs[name] = {
                        "name": name,
                        "fields": body["fields"],
                        "updateTime": VERSION,
                    }
                    response = docs[name]
                    if fault == "lost":
                        self.close_connection = True
                        return
            elif self.command == "DELETE":
                if fault == "replace-before-delete":
                    docs[name] = {**docs[name], "updateTime": FOREIGN_VERSION}
                if query.get("currentDocument.updateTime") != [
                    docs[name]["updateTime"]
                ]:
                    status = 412
                else:
                    del docs[name]
            else:
                if "transaction" in body:
                    status = 400
                    response = {"error": {"code": 400, "status": "INVALID_ARGUMENT"}}
                else:
                    statuses, results = [], []
                    for write in body["writes"]:
                        update = write["update"]
                        if (
                            write.get("currentDocument") == {"exists": False}
                            and update["name"] in docs
                        ):
                            statuses.append({"code": 6})
                            results.append({})
                        else:
                            docs[update["name"]] = {**update, "updateTime": VERSION}
                            statuses.append({"code": 0})
                            results.append({"updateTime": VERSION})
                    response = {"status": statuses, "writeResults": results}
            encoded = json.dumps(response).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        do_GET = do_PATCH = do_DELETE = do_POST = handle_request

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


@pytest.mark.parametrize(
    "fault", [None, "conflict", "lost", "replace-before-read", "replace-before-delete"]
)
def test_real_scenario_retains_uncertain_document_and_recovers_unrelated_job(
    tmp_path, document_server, fault
):
    import json

    from shared_cases import run_scenario

    origin, server = document_server
    server["fault"] = fault
    plan = manifest("d" * 32)
    plan.update(
        coordinatorRequests=0, localOrigins={"auth": origin, "firestore": origin}
    )
    create(tmp_path / "gate", plan)
    results = {}
    for key in ("transaction-field", "partial"):
        adapter = Adapter(
            candidate(),
            plan["nonce"],
            tmp_path / key,
            local_origins=plan["localOrigins"],
        )
        adapter.shared_gate = Gate(tmp_path / "gate", key)
        adapter.shared_gate.claim()
        name = plan["jobs"][key]["resources"][0]

        def before_cleanup(key=key, name=name):
            if key == "transaction-field" and fault == "replace-before-read":
                server["docs"][name] = {
                    **server["docs"][name],
                    "updateTime": FOREIGN_VERSION,
                }

        run_scenario(adapter, plan, key, before_cleanup)
        results[key] = json.loads((adapter.output / "result.json").read_bytes())
        state = adapter.shared_gate.snapshot()
        assert adapter.budget.counts["total"] == len(
            [event for event in state["events"] if event["job"] == key]
        )
    assert results["partial"]["cleanupComplete"]
    assert results["partial"]["safety"]
    assert results["transaction-field"]["cleanupComplete"] is (fault is None)
    deletes = [
        call
        for call in server["calls"]
        if call[0] == "DELETE" and "transaction-field" in call[1]
    ]
    assert len(deletes) == (1 if fault in (None, "replace-before-delete") else 0)
    if deletes:
        assert deletes[0][2] == {"currentDocument.updateTime": [VERSION]}
    assert len(server["docs"]) == (0 if fault is None else 1)


@pytest.mark.parametrize(
    "variant",
    [
        "success",
        "protobuf-default",
        "bool-code",
        "null-code",
        "string-code",
        "list-code",
        "object-code",
        "missing-status",
        "array-status",
        "nonzero-code",
        "missing-results",
        "invalid-version",
        "wrong-length",
    ],
)
def test_batch_conditional_creation_requires_typed_per_write_acknowledgements(
    tmp_path, variant
):
    plan, _adapter, gate, _name, _document = harness(tmp_path)
    key = "partial"
    partial = Gate(gate.path, key)
    partial.claim()
    job = plan["jobs"][key]
    for operation in job["observation"][:3]:
        partial.dispatch(
            operation,
            False,
            lambda: (404, {"error": {"code": 404, "status": "NOT_FOUND"}}),
        )
    setup = job["observation"][3]
    partial.dispatch(
        setup,
        False,
        lambda: (
            200,
            {
                "name": job["resources"][1],
                "fields": setup["body"]["fields"],
                "updateTime": VERSION,
            },
        ),
    )
    body = {
        "status": [{"code": 0}, {"code": 6}, {"code": 0}],
        "writeResults": [{"updateTime": VERSION}, {}, {"updateTime": VERSION}],
    }
    if variant == "protobuf-default":
        body["status"][0] = body["status"][2] = {}
    elif variant == "bool-code":
        body["status"][0]["code"] = False
    elif variant in {"null-code", "string-code", "list-code", "object-code"}:
        body["status"][0]["code"] = {
            "null-code": None,
            "string-code": "0",
            "list-code": [],
            "object-code": {},
        }[variant]
    elif variant in {"missing-status", "array-status"}:
        body["status"][0] = None if variant == "missing-status" else []
    elif variant == "nonzero-code":
        body["status"][0] = body["status"][2] = {"code": 6}
    elif variant == "missing-results":
        del body["writeResults"]
    elif variant == "invalid-version":
        body["writeResults"][2]["updateTime"] = "invalid"
    elif variant == "wrong-length":
        body["status"].pop()
    if variant in {"success", "protobuf-default", "nonzero-code"}:
        partial.dispatch(job["observation"][4], False, lambda: (200, body))
    else:
        with pytest.raises(ValueError):
            partial.dispatch(job["observation"][4], False, lambda: (200, body))
    owned = partial.snapshot()["jobs"][key]["owned"]
    assert set(owned) == set(
        job["resources"]
        if variant in {"success", "protobuf-default"}
        else [job["resources"][1]]
    )


def test_current_generic_manifest_does_not_reuse_historical_collector_identity():
    import json
    from pathlib import Path

    from broad_contract import digest
    from shared_production_pair import validate_record

    current = manifest("a" * 32)
    assert current["contract"] == "shared-local-v2"
    assert current["collector"] == "existing-batch-adapter-shared-v2"
    historical = json.loads(
        (
            Path(__file__).parents[2]
            / "spec/compatibility/broad-runs/a35f85b4-shared-local-reference.json"
        ).read_bytes()
    )
    assert historical["batch"]["gate"]["plan"]["contract"] == "shared-local-v1"
    assert (
        historical["batch"]["gate"]["plan"]["collector"]
        == "existing-batch-adapter-shared-v1"
    )
    assert digest(current) != digest(historical["batch"]["gate"]["plan"])
    with pytest.raises(ValueError):
        validate_record(historical, local=True)


def test_interrupted_creation_retains_uncertainty_and_cannot_be_reclaimed(tmp_path):
    plan, adapter, gate, name, _document = harness(tmp_path)
    operations = plan["jobs"]["transaction-field"]["observation"]
    dispatch(
        adapter, operations[0], (404, {"error": {"code": 404, "status": "NOT_FOUND"}})
    )
    with pytest.raises(KeyboardInterrupt):
        dispatch(adapter, operations[1], KeyboardInterrupt())
    state = gate.snapshot()
    assert state["jobs"]["transaction-field"]["inflight"]
    assert state["jobs"]["transaction-field"]["owned"] == []
    with pytest.raises(ValueError, match="ownership retained"):
        Gate(gate.path, "transaction-field").claim()
    with pytest.raises(ValueError, match="uncertain"):
        dispatch(
            adapter,
            op(name),
            (404, {"error": {"code": 404, "status": "NOT_FOUND"}}),
            recovery=True,
        )


def test_recovery_marker_change_cannot_adopt_even_same_version(tmp_path):
    plan, adapter, gate, name, document = harness(tmp_path)
    operations = plan["jobs"]["transaction-field"]["observation"]
    dispatch(
        adapter, operations[0], (404, {"error": {"code": 404, "status": "NOT_FOUND"}})
    )
    dispatch(adapter, operations[1], (200, document))
    changed = copy.deepcopy(document)
    changed["fields"]["_sharedOwner"] = {"referenceValue": name + "-foreign"}
    dispatch(adapter, op(name), (200, changed), recovery=True)
    with pytest.raises(ValueError, match="ownership"):
        gate.adapter_request(
            adapter,
            op(
                name + "?currentDocument.updateTime=" + quote(VERSION, safe=""),
                "DELETE",
            ),
            lambda: pytest.fail("changed owner marker"),
        )


def test_old_absence_ownership_without_creation_journal_cannot_delete(tmp_path):
    from shared_gate import _save

    _plan, adapter, gate, name, document = harness(tmp_path)
    with gate.locked() as state:
        job = state["jobs"]["transaction-field"]
        job["owned"] = [name]
        del job["creationProofs"]
        _save(gate.path, state)
    dispatch(adapter, op(name), (200, document), recovery=True)
    with pytest.raises(ValueError, match="ownership"):
        gate.adapter_request(
            adapter,
            op(
                name + "?currentDocument.updateTime=" + quote(VERSION, safe=""),
                "DELETE",
            ),
            lambda: pytest.fail("legacy absence does not prove creation"),
        )
