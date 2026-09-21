"""The Gate facade admits only journaled bindings and settles only typed answers."""

import base64
import copy
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/o8-core"))
sys.path.insert(0, str(HERE))

import shared_gate
from broad_contract import digest

import txn_expiry_descriptor as campaign
import txn_expiry_gate as gate_module

NONCE = "c" * 32
TOKEN = base64.b64encode(b"token-1").decode()
VERSION = "2026-09-21T00:00:01.000000Z"


def _gate(tmp_path):
    plan = campaign.execution_plan(campaign.plan_compiler(NONCE))
    gate_plan = campaign.gate_plan(plan)
    gate_plan["permissionExpiresAt"] = 4_102_444_800
    shared_gate.create(tmp_path / "gate", gate_plan)
    gate = gate_module.TxnGate(tmp_path / "gate", gate_module.JOB)
    gate.claim()
    return gate, gate_plan, plan


def _preflight(gate):
    """Charge the four observation management slots with fixture answers."""
    for slot in ("oauth-tokeninfo", "project", "database", "auth"):
        body = None
        if slot == "oauth-tokeninfo":
            body = {
                "kind": "request-byte-token-attestation-v1",
                "principalDigest": "0" * 64,
                "requiredScopeVerified": True,
                "identityMode": "subject",
                "identityVerified": True,
                "oauthClientVerified": True,
                "expiresInSeconds": 3600,
                "remainingSecondsAtVerification": 3500.0,
                "requiredSeconds": 1200,
                "complete": True,
                "workerReaped": True,
            }
        gate.management_dispatch(
            "observation",
            slot,
            lambda _deadline, body=body: {
                "status": 200,
                "complete": True,
                "workerReaped": True,
                "bodyKind": "json",
                "body": body if body is not None else {"slot": "fixture"},
            },
        )


def _dispatch_until(gate, job, site, answers):
    """Dispatch observation slots in order up to and including `site`."""
    for index, operation in enumerate(job["observation"]):
        answer = answers(operation)
        gate.dispatch(copy.deepcopy(operation), False, lambda answer=answer: answer)
        if operation["site"] == site:
            return index
    raise AssertionError(site)


def test_a_token_the_gate_never_observed_cannot_be_bound(tmp_path):
    gate, _plan, _ = _gate(tmp_path)
    with pytest.raises(ValueError, match="validated response"):
        gate.bind("txn:a", TOKEN)
    with pytest.raises(ValueError):
        gate.bind("other:a", TOKEN)


def test_a_begin_answer_is_observed_and_installed_canonically(tmp_path):
    gate, gate_plan, _ = _gate(tmp_path)
    _preflight(gate)
    job = gate_plan["jobs"][gate_module.JOB]
    created = {}

    def answers(operation):
        kind = operation["kind"]
        if kind == "preflight-read":
            return 404, {"error": {"code": 404, "status": "NOT_FOUND"}}
        if kind == "create":
            write = operation["body"]["writes"][0]
            created[write["update"]["name"]] = write["update"]["fields"]
            return 200, {"writeResults": [{"updateTime": VERSION}]}
        if kind == "begin":
            return 200, {"transaction": TOKEN}
        raise AssertionError(kind)

    _dispatch_until(gate, job, "idle/begin/a", answers)
    assert gate.observed("txn:a") == TOKEN
    with pytest.raises(ValueError):
        gate.bind("txn:a", base64.b64encode(b"token-2").decode())
    gate.bind("txn:a", TOKEN)
    # The transactional read is normalized to its placeholder only with the
    # bound token; another token is refused before the wire.
    read = copy.deepcopy(job["observation"][11])
    assert read["site"] == "idle/read/a"
    read["query"] = {"transaction": base64.b64encode(b"token-9").decode()}
    with pytest.raises(ValueError, match="runtime binding differs"):
        gate.dispatch(read, False, lambda: (200, {}))
    read["query"] = {"transaction": TOKEN}
    name = read["resource"]
    gate.dispatch(
        read,
        False,
        lambda: (200, {"name": name, "fields": created[name], "updateTime": VERSION}),
    )
    snapshot = gate.snapshot()
    assert snapshot["events"][-1]["requestDigest"] == digest(job["observation"][11])
    # Begins settle as non-creating; the creates settle as created.
    outcomes = [event.get("creationOutcome") for event in snapshot["events"]]
    assert outcomes[5:10] == ["created"] * 5
    assert outcomes[10] == "refused"
    assert shared_gate.unconfirmed_creates(snapshot, gate_module.JOB) == 0


def test_a_lost_begin_answer_stays_unknown_and_blocks_release(tmp_path):
    gate, gate_plan, _ = _gate(tmp_path)
    _preflight(gate)
    job = gate_plan["jobs"][gate_module.JOB]

    def answers(operation):
        kind = operation["kind"]
        if kind == "preflight-read":
            return 404, {"error": {"code": 404, "status": "NOT_FOUND"}}
        if kind == "create":
            return 200, {"writeResults": [{"updateTime": VERSION}]}
        return None, None

    with pytest.raises(ValueError, match="typed HTTP status required"):
        _dispatch_until(gate, job, "idle/begin/a", answers)
    snapshot = gate.snapshot()
    assert snapshot["events"][-1]["creationOutcome"] == "unknown"
    assert shared_gate.unconfirmed_creates(snapshot, gate_module.JOB) == 1
    with pytest.raises(ValueError, match="unconfirmed write"):
        gate.skip_recovery_slot(job["recovery"][0], "transaction-not-open-at-cleanup")


def test_settlement_accepts_only_typed_answers():
    plan = campaign.execution_plan(campaign.plan_compiler(NONCE))
    gate_plan = campaign.gate_plan(plan)
    job = gate_plan["jobs"][gate_module.JOB]
    facade = gate_module.TxnGate.__new__(gate_module.TxnGate)
    facade.plan = gate_plan
    update = next(op for op in job["observation"] if op["site"] == "idle/commit-before")
    resource = update["resource"]
    state_job = {"creationProofs": {resource: {}}}
    settle = facade._settle
    assert (
        settle(
            "commit-update",
            update,
            200,
            {"writeResults": [{"updateTime": VERSION}]},
            state_job,
        )
        == "created"
    )
    assert settle("commit-update", update, 200, {"writeResults": []}, state_job) is None
    assert (
        settle(
            "commit-update",
            update,
            200,
            {"writeResults": [{"updateTime": VERSION}]},
            {"creationProofs": {}},
        )
        is None
    )
    aborted = {"error": {"code": 409, "status": "ABORTED", "message": "expired"}}
    assert settle("commit-update", update, 409, aborted, state_job) == "refused"
    assert (
        settle(
            "commit-update",
            update,
            500,
            {"error": {"code": 500, "status": "INTERNAL"}},
            state_job,
        )
        is None
    )
    assert (
        settle(
            "commit-update",
            update,
            409,
            {"error": {"code": 400, "status": "ABORTED"}},
            state_job,
        )
        is None
    )
    assert settle("begin", {}, 200, {"transaction": TOKEN}, state_job) == "refused"
    assert settle("begin", {}, 200, {"transaction": "not base64!"}, state_job) is None
    assert settle("rollback", {}, 200, {}, state_job) == "refused"
    assert settle("rollback", {}, 200, {"unexpected": 1}, state_job) is None
    assert settle("readback", {}, 200, {}, state_job) is None


def test_a_delete_needs_an_owned_read_of_this_run(tmp_path):
    gate, gate_plan, _plan = _gate(tmp_path)
    job = gate_plan["jobs"][gate_module.JOB]
    delete = next(
        op
        for op in job["recovery"]
        if op["site"] == "cleanup/conditional-delete/control"
    )
    with pytest.raises(ValueError, match="journaled creation ownership"):
        gate._admit_delete(delete)


def test_recovery_skips_are_journaled_zero_wire_and_in_order(tmp_path):
    gate, gate_plan, _ = _gate(tmp_path)
    _preflight(gate)
    job = gate_plan["jobs"][gate_module.JOB]
    gate.abandon_observation("offline-fixture-stop")
    first = job["recovery"][0]
    # The next slot is the first release; skipping a later one is a request
    # outside the frozen order and is refused as outside the closed scenario.
    with pytest.raises(ValueError, match="outside closed scenario"):
        gate.skip_recovery_slot(job["recovery"][3], "transaction-not-open-at-cleanup")
    with pytest.raises(ValueError, match="outside closed scenario"):
        gate.skip_recovery_slot({**first, "body": {"transaction": "other"}}, "note")
    gate.skip_recovery_slot(first, "transaction-not-open-at-cleanup")
    snapshot = gate.snapshot()
    assert snapshot["jobs"][gate_module.JOB]["recovery"] == 1
    assert snapshot["jobs"][gate_module.JOB]["skippedByStop"] == 50
    assert snapshot["skips"][-1] == {
        "job": gate_module.JOB,
        "index": 0,
        "reason": shared_gate.ZERO_WIRE_REASON,
        "note": "transaction-not-open-at-cleanup",
    }
    assert snapshot["total"] == 4


def test_the_facade_refuses_a_foreign_plan(tmp_path):
    plan = campaign.execution_plan(campaign.plan_compiler(NONCE))
    gate_plan = campaign.gate_plan(plan)
    foreign = copy.deepcopy(gate_plan)
    foreign["campaignId"] = "FS-LIMIT-API-REQUEST-BYTES"
    shared_gate.create(tmp_path / "gate", foreign)
    with pytest.raises(ValueError, match="closed transaction expiry Gate plan"):
        gate_module.TxnGate(tmp_path / "gate", gate_module.JOB)
    with pytest.raises(ValueError):
        gate_module.TxnGate(tmp_path / "gate", "limits")


def test_every_collector_request_lands_on_its_frozen_slot():
    """The projection is hand-written; the collector's own requests must match it."""
    import txn_expiry_collector as collector
    from test_txn_expiry_collector import Endpoint, advances

    plan = campaign.execution_plan(campaign.plan_compiler(NONCE))
    gate_plan = campaign.gate_plan(plan)
    job = gate_plan["jobs"][gate_module.JOB]
    endpoint = Endpoint()
    options = {
        **campaign.collector_options(plan, target="local", host="127.0.0.1", port=1),
        "timing": collector.CONTROL_CLOCK,
    }
    collection = collector.Collection(
        options, plan, endpoint, advance=advances([]), monotonic=lambda: 0.0
    )
    collection.run()
    sites = {
        op["site"]: op for phase in ("observation", "recovery") for op in job[phase]
    }

    def normalize(value, declared):
        if isinstance(declared, str) and declared.startswith(gate_module.PLACEHOLDER):
            return declared
        if isinstance(value, dict) and isinstance(declared, dict):
            return {
                key: normalize(item, declared.get(key)) for key, item in value.items()
            }
        if isinstance(value, list) and isinstance(declared, list):
            return [
                normalize(item, expected)
                for item, expected in zip(value, declared, strict=True)
            ]
        return value

    seen = []
    for request in endpoint.calls:
        declared = sites[request["site"]]
        operation = copy.deepcopy(declared)
        if request["rpc"] == "GetDocument":
            operation["path"] = "/v1/" + request["name"]
            if request.get("query"):
                operation["query"] = request["query"]
        else:
            operation["body"] = request["body"]
        assert digest(normalize(operation, declared)) == digest(declared), request[
            "site"
        ]
        seen.append(request["site"])
    assert seen[:50] == [op["site"] for op in job["observation"]]
    assert all(site.startswith(("release/", "cleanup/")) for site in seen[50:])
