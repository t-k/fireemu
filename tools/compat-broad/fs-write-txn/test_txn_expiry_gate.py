"""The Gate facade admits only journaled bindings and settles only typed answers."""

import base64
import copy
import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/o8-core"))
sys.path.insert(0, str(HERE))

import shared_gate
import txn_expiry_descriptor as campaign
import txn_expiry_gate as gate_module
from broad_contract import digest

NONCE = "c" * 32
TOKEN = base64.b64encode(b"token-1").decode()
VERSION = "2026-09-21T00:00:01.000000Z"


class Clock:
    """A simulated monotonic clock: the Gate's rate waits advance it, not the wall."""

    def __init__(self):
        self.now = 1000.0

    def monotonic(self):
        return self.now

    def time(self):
        return __import__("time").time()

    def sleep(self, seconds):
        self.now += seconds


@pytest.fixture(autouse=True)
def simulated_gate_clock(monkeypatch):
    clock = Clock()
    monkeypatch.setattr(shared_gate, "time", clock)
    monkeypatch.setattr(gate_module, "time", clock)
    return clock


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
    gate.abandon_observation("fixture-stop")
    # Rollback slots pass over no document and may still be skipped; the first
    # document slot may not, so the run stays held for the owner.
    for index in range(14):
        gate.skip_recovery_slot(
            job["recovery"][index], "transaction-not-open-at-cleanup"
        )
    with pytest.raises(ValueError, match="unconfirmed write"):
        gate.skip_recovery_slot(job["recovery"][14], "cleanup-not-attempted")


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
    # A begin or rollback can never create a document: any completed typed
    # answer settles it, a 5xx envelope included; only a lost answer does not.
    assert settle("begin", {}, 200, {"transaction": TOKEN}, state_job) == "refused"
    assert (
        settle("begin", {}, 200, {"transaction": "not base64!"}, state_job) == "refused"
    )
    assert (
        settle(
            "begin",
            {},
            503,
            {"error": {"code": 503, "status": "UNAVAILABLE"}},
            state_job,
        )
        == "refused"
    )
    assert settle("begin", {}, None, None, state_job) is None
    assert settle("begin", {}, 200, "not json", state_job) is None
    assert settle("rollback", {}, 200, {}, state_job) == "refused"
    assert (
        settle(
            "rollback",
            {},
            500,
            {"error": {"code": 500, "status": "INTERNAL"}},
            state_job,
        )
        == "refused"
    )
    assert settle("rollback", {}, None, None, state_job) is None
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
        gate._admit_delete(delete, delete)


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


# -- the facade's own recovery admission ---------------------------------------
#
# `_dispatch_rpc_recovery` and `_admit_delete` duplicate the shared Gate's
# recovery admission for the two request shapes it cannot host. Each test below
# names the mutation it was verified to kill on a copy of the facade.


def _materialize(operation, bindings):
    """The runtime request for one frozen slot, placeholders resolved."""

    def resolve(value):
        if isinstance(value, str) and value.startswith(gate_module.PLACEHOLDER):
            return bindings[value.removeprefix(gate_module.PLACEHOLDER)]
        if isinstance(value, dict):
            return {key: resolve(item) for key, item in value.items()}
        if isinstance(value, list):
            return [resolve(item) for item in value]
        return value

    return resolve(copy.deepcopy(operation))


def _complete_observation(gate, gate_plan, *, fault=None):
    """Drive every observation slot with typed answers and install the bindings.

    `fault` is `(site, status, body)` for one slot answered differently.
    """
    job = gate_plan["jobs"][gate_module.JOB]
    documents = {}
    issued = 0
    for operation in job["observation"]:
        try:
            request = _materialize(operation, gate.bindings)
        except KeyError:
            # The collector has no token for this slot and stops here; the
            # coordinator abandons the observation before recovery.
            gate.abandon_observation("fixture-stop:missing-binding")
            return documents
        kind = operation["kind"]
        if fault is not None and operation["site"] == fault[0]:
            status, body = fault[1], fault[2]
        elif kind == "preflight-read":
            status, body = 404, {"error": {"code": 404, "status": "NOT_FOUND"}}
        elif kind in ("create", "commit-update"):
            write = request["body"]["writes"][0]["update"]
            documents[write["name"]] = write["fields"]
            status, body = 200, {"writeResults": [{"updateTime": VERSION}]}
        elif kind == "begin":
            issued += 1
            token = base64.b64encode(f"token-{issued}".encode()).decode()
            status, body = 200, {"transaction": token}
        elif kind in ("read-in-transaction", "readback"):
            name = operation["resource"]
            status, body = (
                200,
                {"name": name, "fields": documents[name], "updateTime": VERSION},
            )
        elif kind == "rollback":
            status, body = 200, {}
        else:
            raise AssertionError(kind)
        gate.dispatch(request, False, lambda answer=(status, body): answer)
        binds = operation.get("binds")
        if binds and gate.observed(binds) is not None:
            gate.bind(binds, gate.observed(binds))
    return documents


def _recovery_ready(tmp_path, **kwargs):
    gate, gate_plan, _plan = _gate(tmp_path)
    _preflight(gate)
    documents = _complete_observation(gate, gate_plan, **kwargs)
    return gate, gate_plan, documents


def _edit_state(gate, mutate):
    """Edit the Gate journal outside its own paths (the plan stays untouched)."""
    path = gate.path / "state.json"
    state = json.loads(path.read_bytes())
    mutate(state)
    path.write_text(json.dumps(state))


def test_a_recovery_rollback_is_charged_and_journaled(tmp_path):
    """Kills: dropping `state["costMicrousd"] += cost` / `total += 1` (M3)."""
    gate, gate_plan, _ = _recovery_ready(tmp_path)
    job = gate_plan["jobs"][gate_module.JOB]
    before = gate.snapshot()
    release = job["recovery"][0]
    request = _materialize(release, gate.bindings)
    gate.dispatch(request, True, lambda: (200, {}))
    after = gate.snapshot()
    assert (
        after["costMicrousd"]
        == before["costMicrousd"] + gate_plan["requestCostMicrousd"]
    )
    assert after["total"] == before["total"] + 1
    assert (
        after["recovery"] == 1
        and after["reservedRecovery"] == before["reservedRecovery"] - 1
    )
    event = after["events"][-1]
    assert event["phase"] == "recovery" and event["index"] == 0
    assert event["requestDigest"] == digest(release)
    assert event["completed"] is True and event["status"] == 200
    assert after["jobs"][gate_module.JOB]["inflight"] is False


def test_a_recovery_rollback_out_of_order_is_refused(tmp_path):
    """Kills: dropping the schedule-cursor check (M10).

    The observation is not finished and not abandoned, so the next frozen slot
    is an observation slot; the first release slot is not yet reachable.
    """
    gate, gate_plan, _ = _gate(tmp_path)
    _preflight(gate)
    job = gate_plan["jobs"][gate_module.JOB]
    for operation in job["observation"][:5]:
        gate.dispatch(
            copy.deepcopy(operation),
            False,
            lambda: (404, {"error": {"code": 404, "status": "NOT_FOUND"}}),
        )
    # Bind a token by hand so only the cursor stands in the way.
    gate._observed_bindings["txn:a"] = TOKEN
    gate.bind("txn:a", TOKEN)
    sent = []
    with pytest.raises(ValueError, match="outside the frozen execution schedule"):
        gate.dispatch(
            _materialize(job["recovery"][0], gate.bindings),
            True,
            lambda: sent.append(1) or (200, {}),
        )
    assert sent == []
    assert gate.snapshot()["recovery"] == 0


def test_a_recovery_rollback_with_an_altered_body_is_refused(tmp_path):
    """Kills: dropping the exact-request digest check (M11)."""
    gate, gate_plan, _ = _recovery_ready(tmp_path)
    request = _materialize(
        gate_plan["jobs"][gate_module.JOB]["recovery"][0], gate.bindings
    )
    request["body"]["extra"] = True
    sent = []
    with pytest.raises(ValueError, match="outside closed scenario"):
        gate.dispatch(request, True, lambda: sent.append(1) or (200, {}))
    assert sent == [] and gate.snapshot()["recovery"] == 0


def test_a_recovery_rollback_of_an_unbound_token_is_refused(tmp_path):
    gate, gate_plan, _ = _recovery_ready(tmp_path)
    request = _materialize(
        gate_plan["jobs"][gate_module.JOB]["recovery"][0], gate.bindings
    )
    request["body"]["transaction"] = base64.b64encode(b"token-99").decode()
    with pytest.raises(ValueError, match="runtime binding differs"):
        gate.dispatch(request, True, lambda: (200, {}))


def test_a_recovery_rollback_past_the_deadline_or_budget_is_refused(tmp_path):
    """Kills: dropping the capacity check and the post-wait deadline check (M4)."""
    gate, gate_plan, _ = _recovery_ready(tmp_path)
    request = _materialize(
        gate_plan["jobs"][gate_module.JOB]["recovery"][0], gate.bindings
    )
    sent = []
    _edit_state(
        gate,
        lambda state: state.update(started=state["started"] - gate_plan["wallSeconds"]),
    )
    with pytest.raises(ValueError, match="capacity"):
        gate.dispatch(request, True, lambda: sent.append(1) or (200, {}))
    _edit_state(
        gate,
        lambda state: state.update(started=state["started"] + gate_plan["wallSeconds"]),
    )
    _edit_state(
        gate, lambda state: state.update(costMicrousd=gate_plan["costMicrousd"])
    )
    with pytest.raises(ValueError, match="capacity"):
        gate.dispatch(request, True, lambda: sent.append(1) or (200, {}))
    assert sent == [] and gate.snapshot()["recovery"] == 0


def test_a_transport_exception_leaves_a_charged_failed_event(tmp_path):
    gate, gate_plan, _ = _recovery_ready(tmp_path)
    request = _materialize(
        gate_plan["jobs"][gate_module.JOB]["recovery"][0], gate.bindings
    )
    before = gate.snapshot()["total"]

    def lost():
        raise TimeoutError("fixture: answer lost")

    with pytest.raises(TimeoutError):
        gate.dispatch(request, True, lost)
    state = gate.snapshot()
    event = state["events"][-1]
    assert state["total"] == before + 1 and state["recovery"] == 1
    assert event["failure"] == "TimeoutError" and event["completed"] is False
    assert state["jobs"][gate_module.JOB]["inflight"] is False
    assert state["jobs"][gate_module.JOB]["stopped"] is True


def _at_delete(gate, gate_plan, role):
    """Consume every recovery slot before the delete of `role` as zero-wire skips."""
    job = gate_plan["jobs"][gate_module.JOB]
    target = next(
        index
        for index, op in enumerate(job["recovery"])
        if op["site"] == f"cleanup/conditional-delete/{role}"
    )
    for index in range(target):
        gate.skip_recovery_slot(job["recovery"][index], "fixture-skip")
    return job["recovery"][target]


def test_a_delete_without_a_creation_proof_is_refused(tmp_path):
    """Kills: dropping `resource not in creationProofs` in `_admit_delete` (M5)."""
    gate, gate_plan, _ = _recovery_ready(tmp_path)
    delete = _at_delete(gate, gate_plan, "control")
    gate._observed_bindings["version:control"] = VERSION
    gate.bind("version:control", VERSION)
    _edit_state(
        gate,
        lambda state: state["jobs"][gate_module.JOB]["creationProofs"].pop(
            delete["resource"]
        ),
    )
    sent = []
    with pytest.raises(ValueError, match="journaled creation ownership"):
        gate.dispatch(
            _materialize(delete, gate.bindings),
            True,
            lambda: sent.append(1) or (200, {"writeResults": [{}]}),
        )
    assert sent == []


def test_a_delete_with_a_binding_the_gate_never_observed_is_refused(tmp_path):
    """Kills: dropping the observed-binding equality in `_admit_delete` (M6)."""
    gate, gate_plan, _ = _recovery_ready(tmp_path)
    delete = _at_delete(gate, gate_plan, "control")
    gate.bindings["version:control"] = VERSION  # installed behind `bind`
    sent = []
    with pytest.raises(ValueError, match="journaled creation ownership"):
        gate.dispatch(
            _materialize(delete, gate.bindings),
            True,
            lambda: sent.append(1) or (200, {"writeResults": [{}]}),
        )
    assert sent == []


def test_a_delete_naming_another_document_is_refused(tmp_path):
    gate, gate_plan, _ = _recovery_ready(tmp_path)
    delete = _at_delete(gate, gate_plan, "control")
    gate._observed_bindings["version:control"] = VERSION
    gate.bind("version:control", VERSION)
    request = _materialize(delete, gate.bindings)
    request["body"]["writes"][0]["delete"] = delete["resource"].replace(
        "control", "locked-a"
    )
    with pytest.raises(ValueError, match="exactly its resource"):
        gate.dispatch(request, True, lambda: (200, {"writeResults": [{}]}))
    request = _materialize(delete, gate.bindings)
    request["body"]["writes"].append(
        {"delete": delete["resource"].replace("control", "locked-b")}
    )
    with pytest.raises(ValueError, match="exactly its resource"):
        gate.dispatch(request, True, lambda: (200, {"writeResults": [{}, {}]}))


def test_an_owned_read_then_delete_then_absence_is_admitted(tmp_path):
    gate, gate_plan, documents = _recovery_ready(tmp_path)
    job = gate_plan["jobs"][gate_module.JOB]
    for index in range(14):
        gate.skip_recovery_slot(
            job["recovery"][index], "transaction-not-open-at-cleanup"
        )
    read, delete, absence = job["recovery"][14:17]
    name = read["resource"]
    gate.dispatch(
        copy.deepcopy(read),
        True,
        lambda: (200, {"name": name, "fields": documents[name], "updateTime": VERSION}),
    )
    assert gate.observed("version:control") == VERSION
    gate.bind("version:control", VERSION)
    gate.dispatch(
        _materialize(delete, gate.bindings), True, lambda: (200, {"writeResults": [{}]})
    )
    gate.dispatch(
        copy.deepcopy(absence),
        True,
        lambda: (404, {"error": {"code": 404, "status": "NOT_FOUND"}}),
    )
    state = gate.snapshot()
    assert state["jobs"][gate_module.JOB]["absent"] == [name]
    assert (
        state["jobs"][gate_module.JOB]["absenceProofs"][name]["eventIndex"]
        == len(state["events"]) - 1
    )


def test_a_typed_5xx_on_a_begin_settles_and_releases_still_skip(tmp_path):
    """Should Fix 1: an unconfirmed transaction start must not strand the cleanup."""
    fault = (
        "idle/begin/b",
        503,
        {"error": {"code": 503, "status": "UNAVAILABLE", "message": "try later"}},
    )
    gate, gate_plan, _ = _recovery_ready(tmp_path, fault=fault)
    snapshot = gate.snapshot()
    assert shared_gate.unconfirmed_creates(snapshot, gate_module.JOB) == 0
    job = gate_plan["jobs"][gate_module.JOB]
    gate.skip_recovery_slot(job["recovery"][0], "transaction-not-open-at-cleanup")
    # A lost create answer still blocks skipping a document slot.
    _edit_state(
        gate, lambda state: state["events"][5].update(creationOutcome="unknown")
    )
    gate.skip_recovery_slot(job["recovery"][1], "transaction-not-open-at-cleanup")
    for index in range(2, 14):
        gate.skip_recovery_slot(
            job["recovery"][index], "transaction-not-open-at-cleanup"
        )
    with pytest.raises(ValueError, match="unconfirmed write"):
        gate.skip_recovery_slot(job["recovery"][14], "cleanup-not-attempted")


def test_the_plan_validation_checks_recovery_request_shapes():
    plan = campaign.execution_plan(campaign.plan_compiler(NONCE))
    gate_plan = campaign.gate_plan(plan)
    gate_module.validate_plan(gate_plan)
    job = gate_plan["jobs"][gate_module.JOB]
    delete = next(op for op in job["recovery"] if op["kind"] == "conditional-delete")
    read = next(op for op in job["recovery"] if op["kind"] == "owned-read")

    def damages(job, delete, read):
        return (
            lambda: delete["body"]["writes"][0].update(delete=read["resource"] + "x"),
            lambda: delete["body"]["writes"].append({"delete": read["resource"]}),
            lambda: delete.update(resource=read["resource"] + "x"),
            lambda: read.update(path="/v1/" + read["resource"] + "x"),
            lambda: job["resources"].pop(),
        )

    for position in range(5):
        damaged = copy.deepcopy(gate_plan)
        job = damaged["jobs"][gate_module.JOB]
        delete = next(
            op for op in job["recovery"] if op["kind"] == "conditional-delete"
        )
        read = next(op for op in job["recovery"] if op["kind"] == "owned-read")
        damages(job, delete, read)[position]()
        with pytest.raises(ValueError):
            gate_module.validate_plan(damaged)
