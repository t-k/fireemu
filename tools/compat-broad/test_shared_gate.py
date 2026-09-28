"""Cross-process admission tests, with no network or credentials."""

import multiprocessing as mp
import os
from urllib.parse import quote

import pytest
from broad_contract import digest
from shared_gate import (
    Gate,
    _auth_creation_ownership,
    body_reference,
    can_create,
    canonical_body_bytes,
    create,
    unconfirmed_creates,
)


def plan():
    op = lambda key: {
        "service": "firestore",
        "path": "/v1/" + key,
        "body": None,
        "method": "GET",
        "privileged": True,
        "form": False,
    }
    return {
        "contract": "shared-local-v1",
        "wallSeconds": 120,
        "recoverySeconds": 60,
        "observationRequests": 1,
        "costMicrousd": 300,
        "requestCostMicrousd": 100,
        "intervalSeconds": 0.25,
        "jobs": {
            k: {"resources": [k], "observation": [op(k)], "recovery": [op(k)]}
            for k in ("a", "b")
        },
    }


def limits_preparation_plan():
    import time

    return {
        "contract": "shared-local-v2",
        "transport": "limits-03-baseline-preparation-v2",
        "receiptKind": "limits-03-baseline-preparation-receipt-v1",
        "campaignId": "FS-WRITE-LIMITS-03",
        "nonce": "a" * 32,
        "sourceCommit": "b" * 40,
        "collectorSourceDigest": "c" * 64,
        "sourceDigests": {"worker.py": "d" * 64},
        "permissionExpiresAt": time.time() + 600,
        "wallSeconds": 180,
        "recoverySeconds": 30,
        "observationRequests": 6,
        "costMicrousd": 600,
        "requestCostMicrousd": 100,
        "intervalSeconds": 0.25,
        "jobs": {"limits": {
            "resources": [], "observation": [], "recovery": [], "schedule": [],
        }},
        "management": {
            "dispatchKind": "closed-v1",
            "credentialIds": ["oauth-tokeninfo"],
            "credentialSlots": ["oauth-tokeninfo"],
            "observation": [
                {"id": slot, "timeout": 12}
                for slot in ("refresh", "oauth-tokeninfo", "project", "database", "auth", "key")
            ],
            "recovery": [],
        },
    }


def test_limits_preparation_allows_only_typed_empty_data_plan(tmp_path):
    value = limits_preparation_plan()
    create(tmp_path / "gate", value)
    gate = Gate(tmp_path / "gate", "limits")
    gate.claim()
    before = gate.snapshot()
    with pytest.raises(ValueError):
        gate.finish()
    assert gate.snapshot() == before
    with pytest.raises(ValueError):
        gate.dispatch(plan()["jobs"]["a"]["observation"][0], False, lambda: pytest.fail("no data"))
    assert gate.snapshot() == before


@pytest.mark.parametrize("fault", ["untyped", "campaign", "receipt", "slot", "order", "recovery", "data", "resource", "cost"])
def test_limits_preparation_rejects_mixed_contract_before_creation(tmp_path, fault):
    value = limits_preparation_plan()
    if fault == "untyped":
        value.pop("transport")
    elif fault == "campaign":
        value["campaignId"] = "FS-DATA-WRITE-LIMITS-02"
    elif fault == "receipt":
        value["receiptKind"] = "limits-03-production-receipt-v1"
    elif fault == "slot":
        value["management"]["observation"][-1]["id"] = "index-lifecycle-apply"
    elif fault == "order":
        value["management"]["observation"].reverse()
    elif fault == "recovery":
        value["management"]["recovery"] = [{"id": "restore", "timeout": 12}]
    elif fault == "data":
        value["jobs"]["limits"]["observation"] = plan()["jobs"]["a"]["observation"]
    elif fault == "resource":
        value["jobs"]["limits"]["resources"] = ["fake"]
    elif fault == "cost":
        value["costMicrousd"] = 601
    with pytest.raises(ValueError):
        create(tmp_path / "gate", value)
    assert not (tmp_path / "gate").exists()


def _custom_ownership_state(*, uid="custom-uid", resource="projects/p/auth/accounts/custom"):
    operation = {
        "id": "custom-sign-in",
        "kind": "custom-sign-in",
        "service": "auth",
        "account": "custom",
        "method": "POST",
        "path": "identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken",
        "form": False,
        "body": {"token": "$binding:customToken", "returnSecureToken": True},
        "resource": resource,
    }
    delete = {"kind": "delete", "account": "custom", "resource": resource}
    state = {
        "plan": {"jobs": {"job": {"observation": [operation]}}, "nonce": "a" * 32},
        "events": [{
            "phase": "observation",
            "index": 0,
            "completed": True,
            "creationOutcome": "created",
            "requestDigest": digest(operation),
            "authEvidence": {
                "kind": "custom-sign-in",
                "account": "custom",
                "uid": uid,
                "resource": resource,
                "creationOutcome": "created",
            },
        }],
        "jobs": {
            "job": {"authAccounts": {"custom": {"uid": uid, "resource": resource, "createEvent": 0}}}
        },
    }
    return state, state["jobs"]["job"], delete


def test_custom_signin_new_user_creation_projection_authorizes_exact_cleanup():
    state, job, delete = _custom_ownership_state()
    assert _auth_creation_ownership(state, job, delete) is True


@pytest.mark.parametrize(
    "mutation",
    [
        lambda operation: operation.update({"path": "identitytoolkit.googleapis.com/v1/accounts:signInWithPassword"}),
        lambda operation: operation["body"].update({"returnSecureToken": False}),
        lambda operation: operation.update({"account": "other"}),
    ],
)
def test_custom_signin_ownership_rejects_route_body_and_account_tampering(mutation):
    state, job, delete = _custom_ownership_state()
    mutation(state["plan"]["jobs"]["job"]["observation"][0])
    assert _auth_creation_ownership(state, job, delete) is False


def compete(path, key, ready, start, results, crash=False):
    gate = Gate(path, key)
    gate.claim()
    ready.put(key)
    start.wait(5)
    try:

        def send():
            if crash:
                os._exit(7)
            return 404, {"error": {"code": 404, "status": "NOT_FOUND"}}

        gate.dispatch(plan()["jobs"][key]["observation"][0], False, send)
        results.put("sent")
    except ValueError:
        results.put("refused")


def test_last_observation_capacity_is_atomic_and_recovery_reserved(tmp_path):
    path = tmp_path / "gate"
    create(path, plan())
    ctx = mp.get_context("spawn")
    ready, results, start = ctx.Queue(), ctx.Queue(), ctx.Event()
    children = [
        ctx.Process(target=compete, args=(path, k, ready, start, results))
        for k in ("a", "b")
    ]
    try:
        for p in children:
            p.start()
        for _ in children:
            ready.get(timeout=10)
        start.set()
        for p in children:
            p.join(10)
            assert p.exitcode == 0
        assert sorted(results.get(timeout=2) for _ in children) == ["refused", "sent"]
        state = Gate(path, "a").snapshot()
        assert state["total"] == 1
        assert state["reservedRecovery"] == 2
    finally:
        for p in children:
            if p.is_alive():
                p.terminate()
                p.join(5)


def test_ownership_cannot_be_shared(tmp_path):
    p = plan()
    p["jobs"]["b"]["resources"] = ["a"]
    with pytest.raises(ValueError):
        create(tmp_path / "gate", p)


def test_local_stop_preserves_other_job_and_global_stop_allows_recovery(tmp_path):
    p = plan()
    p.update(observationRequests=2, costMicrousd=400)
    path = tmp_path / "gate"
    create(path, p)
    a, b = Gate(path, "a"), Gate(path, "b")
    a.claim()
    b.claim()
    a.dispatch(
        p["jobs"]["a"]["observation"][0],
        False,
        lambda: (404, {"error": {"code": 404, "status": "NOT_FOUND"}}),
    )
    a.stop()
    with pytest.raises(ValueError):
        a.dispatch(p["jobs"]["a"]["observation"][0], False, lambda: (200, {}))
    b.dispatch(
        p["jobs"]["b"]["observation"][0],
        False,
        lambda: (404, {"error": {"code": 404, "status": "NOT_FOUND"}}),
    )
    b.stop(environment=True)
    for key, gate in [("a", a), ("b", b)]:
        gate.dispatch(
            p["jobs"][key]["recovery"][0],
            True,
            lambda: (404, {"error": {"code": 404, "status": "NOT_FOUND"}}),
        )
        gate.finish()
    state = a.snapshot()
    assert state["total"] == 4
    assert state["recovery"] == 2  # subset, not five total requests
    assert state["reservedRecovery"] == 0
    assert state["costMicrousd"] == 400


def test_crashed_inflight_worker_does_not_release_ownership(tmp_path):
    path = tmp_path / "gate"
    create(path, plan())
    ctx = mp.get_context("spawn")
    ready, results, start = ctx.Queue(), ctx.Queue(), ctx.Event()
    child = ctx.Process(target=compete, args=(path, "a", ready, start, results, True))
    child.start()
    ready.get(timeout=10)
    start.set()
    child.join(10)
    assert child.exitcode == 7
    gate = Gate(path, "a")
    with pytest.raises(ValueError):
        gate.claim()
    state = gate.snapshot()
    assert state["jobs"]["a"]["inflight"]
    assert state["jobs"]["a"]["resources"] == ["a"]
    b = Gate(path, "b")
    b.claim()
    with pytest.raises(ValueError):
        b.dispatch(plan()["jobs"]["b"]["observation"][0], False, lambda: (200, {}))


def test_missing_gate_never_falls_back(tmp_path):
    with pytest.raises((ValueError, FileNotFoundError)):
        Gate(tmp_path / "absent", "a").claim()


def test_deadline_cost_and_wrong_operation_refuse_before_callback(tmp_path):
    for variant in ("deadline", "cost", "query", "duplicate", "method"):
        p = plan()
        if variant == "deadline":
            p.update(wallSeconds=61, recoverySeconds=60)
        if variant == "cost":
            p["costMicrousd"] = 200
        path = tmp_path / variant
        create(path, p)
        gate = Gate(path, "a")
        gate.claim()
        operation = dict(p["jobs"]["a"]["observation"][0])
        if variant == "query":
            operation["path"] += "?mask.fieldPaths=a&mask.fieldPaths=a"
        if variant == "method":
            operation["method"] = "DELETE"
        if variant == "duplicate":
            gate.dispatch(
                operation,
                False,
                lambda: (404, {"error": {"code": 404, "status": "NOT_FOUND"}}),
            )
        called = []
        with pytest.raises(ValueError):
            gate.dispatch(operation, False, lambda called=called: called.append(True))
        assert called == []


def test_failed_callback_stops_only_local_job(tmp_path):
    p = plan()
    p.update(observationRequests=2, costMicrousd=400)
    path = tmp_path / "gate"
    create(path, p)
    a, b = Gate(path, "a"), Gate(path, "b")
    a.claim()
    b.claim()

    def timeout():
        raise TimeoutError("fixture transport ended")

    with pytest.raises(TimeoutError):
        a.dispatch(p["jobs"]["a"]["observation"][0], False, timeout)
    b.dispatch(
        p["jobs"]["b"]["observation"][0],
        False,
        lambda: (404, {"error": {"code": 404, "status": "NOT_FOUND"}}),
    )
    assert a.snapshot()["jobs"]["a"]["stopped"]
    assert not a.snapshot()["stopped"]
    with pytest.raises(ValueError):
        a.finish()


def test_adapter_rejects_remote_even_before_authentication(tmp_path):
    from batch_adapter import Adapter
    from batch_contract import candidate

    p = plan()
    path = tmp_path / "gate"
    create(path, p)
    adapter = Adapter(
        candidate(),
        "a" * 32,
        tmp_path / "adapter",
        local_origins={
            "auth": "http://127.0.0.1:12345",
            "firestore": "http://127.0.0.1:12346",
        },
    )
    adapter.shared_gate = Gate(path, "a")
    adapter.shared_gate.claim()
    adapter.local = None
    with pytest.raises(ValueError, match="local-only"):
        adapter.request(**p["jobs"]["a"]["observation"][0])
    assert adapter.budget.counts["total"] == 0


def test_readback_missing_fields_does_not_establish_state(tmp_path):
    p = plan()
    path = tmp_path / "gate"
    create(path, p)
    gate = Gate(path, "a")
    gate.claim()
    with pytest.raises(ValueError, match="readback"):
        gate.dispatch(
            p["jobs"]["a"]["observation"][0], False, lambda: (200, {"name": "a"})
        )
    with pytest.raises(ValueError):
        gate.finish()


def test_absent_or_failed_cleanup_read_never_sends_unconditional_delete(tmp_path):
    for failed in (False, True):
        p = plan()
        p.update(costMicrousd=700)
        p["jobs"]["a"]["recovery"] = [
            p["jobs"]["a"]["recovery"][0],
            {**p["jobs"]["a"]["recovery"][0], "method": "DELETE", "versionFrom": 0},
            p["jobs"]["a"]["recovery"][0],
        ]
        path = tmp_path / str(failed)
        create(path, p)
        gate = Gate(path, "a")
        gate.claim()
        gate.dispatch(
            p["jobs"]["a"]["observation"][0],
            False,
            lambda: (404, {"error": {"code": 404, "status": "NOT_FOUND"}}),
        )

        def read(failed=failed):
            if failed:
                raise TimeoutError()
            return 404, {"error": {"code": 404, "status": "NOT_FOUND"}}

        if failed:
            with pytest.raises(TimeoutError):
                gate.dispatch(p["jobs"]["a"]["recovery"][0], True, read)
        else:
            gate.dispatch(p["jobs"]["a"]["recovery"][0], True, read)
        sent = []
        operation = {
            k: v for k, v in p["jobs"]["a"]["recovery"][1].items() if k != "versionFrom"
        }
        status, result = gate.dispatch(
            operation, True, lambda sent=sent: sent.append(True)
        )
        assert status is None and result["skipped"]
        assert sent == []
        gate.dispatch(
            p["jobs"]["a"]["recovery"][2],
            True,
            lambda: (404, {"error": {"code": 404, "status": "NOT_FOUND"}}),
        )
        gate.finish()
        assert gate.snapshot()["total"] == 3


def test_base_exception_retains_uncertain_dispatch(tmp_path):
    p = plan()
    path = tmp_path / "gate"
    create(path, p)
    gate = Gate(path, "a")
    gate.claim()

    def interrupted():
        raise KeyboardInterrupt()

    with pytest.raises(KeyboardInterrupt):
        gate.dispatch(p["jobs"]["a"]["observation"][0], False, interrupted)
    assert gate.snapshot()["jobs"]["a"]["inflight"]


def recover_in_process(path, key, ready, start, results):
    gate = Gate(path, key)
    gate.claim()
    p = gate.snapshot()["plan"]
    gate.dispatch(
        p["jobs"][key]["observation"][0],
        False,
        lambda: (404, {"error": {"code": 404, "status": "NOT_FOUND"}}),
    )
    ready.put(key)
    start.wait(5)
    refused = False
    try:
        gate.dispatch(
            p["jobs"][key]["observation"][1],
            False,
            lambda: (404, {"error": {"code": 404, "status": "NOT_FOUND"}}),
        )
    except ValueError:
        refused = True
    gate.dispatch(
        p["jobs"][key]["recovery"][0],
        True,
        lambda: (404, {"error": {"code": 404, "status": "NOT_FOUND"}}),
    )
    gate.finish()
    results.put(refused)


def test_two_processes_recover_after_global_observation_exhaustion(tmp_path):
    p = plan()
    p.update(observationRequests=2, costMicrousd=400)
    for job in p["jobs"].values():
        job["observation"] *= 2
    path = tmp_path / "gate"
    create(path, p)
    ctx = mp.get_context("spawn")
    ready, results, start = ctx.Queue(), ctx.Queue(), ctx.Event()
    children = [
        ctx.Process(target=recover_in_process, args=(path, key, ready, start, results))
        for key in ("a", "b")
    ]
    try:
        for child in children:
            child.start()
        for _ in children:
            ready.get(timeout=10)
        start.set()
        for child in children:
            child.join(10)
            assert child.exitcode == 0
        assert all(results.get(timeout=2) for _ in children)
        state = Gate(path, "a").snapshot()
        assert state["total"] == 4 and state["recovery"] == 2
        assert all(job["complete"] for job in state["jobs"].values())
    finally:
        for child in children:
            if child.is_alive():
                child.terminate()
                child.join(5)


# Reuse the existing owned HTTP fixture; no external requests are possible.
from test_second_wire import wire_server  # noqa: F401


@pytest.mark.parametrize("mode", ["non-json", "partial", "denied"])
def test_existing_adapter_wire_failure_is_retained_by_gate(tmp_path, wire_server, mode):  # noqa: F811
    from batch_adapter import Adapter, observer_digest
    from batch_contract import candidate

    origin, handler = wire_server
    handler.mode = mode
    p = plan()
    p.update(
        localOrigins={"auth": origin, "firestore": origin},
        nonce="a" * 32,
        observerSha256=observer_digest(),
    )
    p["jobs"]["a"]["observation"][0]["method"] = "POST"
    path = tmp_path / "gate"
    create(path, p)
    adapter = Adapter(
        candidate(), p["nonce"], tmp_path / "adapter", local_origins=p["localOrigins"]
    )
    adapter.shared_gate = Gate(path, "a")
    adapter.shared_gate.claim()
    with pytest.raises(ValueError):
        adapter.request(**p["jobs"]["a"]["observation"][0])
    state = adapter.shared_gate.snapshot()
    assert state["total"] == 1
    assert state["jobs"]["a"]["stopped"]
    assert state["events"][0]["failure"]
    assert not state["jobs"]["a"]["complete"]
    assert adapter.budget.counts["total"] == 1


@pytest.mark.parametrize("version", [None, "", 7])
def test_invalid_recovery_version_keeps_independent_cleanup_available(
    tmp_path, version
):
    p = plan()
    read = p["jobs"]["a"]["observation"][0]
    p["jobs"]["a"]["recovery"] = [
        read,
        {**read, "method": "DELETE", "versionFrom": 0},
        read,
    ]
    p["costMicrousd"] = 600
    path = tmp_path / "gate"
    create(path, p)
    gate = Gate(path, "a")
    gate.claim()
    gate.dispatch(
        read, False, lambda: (404, {"error": {"code": 404, "status": "NOT_FOUND"}})
    )
    gate.dispatch(
        read, True, lambda: (200, {"name": "a", "fields": {}, "updateTime": version})
    )
    status, _ = gate.dispatch(
        {**read, "method": "DELETE"}, True, lambda: pytest.fail("unsafe delete")
    )
    assert status is None
    gate.dispatch(read, True, lambda: (200, {"name": "a", "fields": {}}))
    with pytest.raises(ValueError):
        gate.finish()
    assert gate.snapshot()["jobs"]["a"]["recovery"] == 3


def test_fixed_cost_cannot_spend_recovery_reservation(tmp_path):
    p = plan()
    p.update(fixedCostMicrousd=101)
    with pytest.raises(ValueError):
        create(tmp_path / "gate", p)


def test_recovery_time_is_reserved_before_any_worker_claim(tmp_path):
    p = plan()
    p.update(wallSeconds=60, recoverySeconds=20)
    with pytest.raises(ValueError):
        create(tmp_path / "gate", p)


@pytest.mark.parametrize("entry", ["dispatch", "adapter_request"])
@pytest.mark.parametrize(
    "change",
    [
        "unchanged",
        "false-int",
        "false-float",
        "principal-int",
        "missing",
        "extra",
        "target",
    ],
)
def test_typed_json_admission_before_callback_or_debit(tmp_path, entry, change):
    import copy

    from batch_adapter import Adapter, observer_digest
    from batch_contract import candidate

    p = plan()
    p.update(
        localOrigins={
            "auth": "http://127.0.0.1:12345",
            "firestore": "http://127.0.0.1:12346",
        },
        nonce="a" * 32,
        observerSha256=observer_digest(),
    )
    expected = p["jobs"]["a"]["observation"][0]
    expected.update(
        method="POST", body={"writes": [{"currentDocument": {"exists": False}}]}
    )
    path = tmp_path / "gate"
    create(path, p)
    gate = Gate(path, "a")
    gate.claim()
    adapter = Adapter(
        candidate(), p["nonce"], tmp_path / "adapter", local_origins=p["localOrigins"]
    )
    actual = copy.deepcopy(expected)
    if change in ("false-int", "false-float"):
        actual["body"]["writes"][0]["currentDocument"]["exists"] = (
            0 if change == "false-int" else 0.0
        )
    elif change == "principal-int":
        actual["privileged"] = 1
    elif change == "missing":
        del actual["body"]["writes"][0]["currentDocument"]["exists"]
    elif change == "extra":
        actual["body"]["extra"] = None
    elif change == "target":
        actual["path"] = "/v1/other-project/other-document"
    calls = []

    def send():
        calls.append(True)
        return 200, {}

    def invoke():
        return (
            gate.dispatch(actual, False, send)
            if entry == "dispatch"
            else gate.adapter_request(adapter, actual, send)
        )

    if change == "unchanged":
        assert invoke() == (200, {})
    else:
        with pytest.raises(ValueError):
            invoke()
    assert len(calls) == (1 if change == "unchanged" else 0)
    assert gate.snapshot()["total"] == len(calls)


def scheduled_plan(slots=3, probes=("p1", "p2", "p3")):
    """A campaign whose probes interleave observation and recovery in one stream."""
    op = lambda key: {
        "service": "firestore",
        "path": "/v1/" + key,
        "body": None,
        "method": "GET",
        "privileged": True,
        "form": False,
        # These scheduled probes are read-only; do not classify their
        # observation slots as conditional creates for cleanup accounting.
        "creates": False,
    }
    jobs = {
        key: {
            "resources": [key],
            "observation": [op(key), op(key)],
            "recovery": [op(key), op(key)],
            "schedule": [
                {"phase": "observation", "index": 0, "creates": False},
                {"phase": "recovery", "index": 0},
                {"phase": "observation", "index": 1, "creates": False},
                {"phase": "recovery", "index": 1},
            ],
        }
        for key in probes
    }
    return {
        "contract": "shared-local-v1",
        "wallSeconds": 600,
        "recoverySeconds": 300,
        "observationRequests": 2 * len(probes),
        "costMicrousd": 10000,
        "requestCostMicrousd": 100,
        "intervalSeconds": 0.25,
        "requestSeconds": 2,
        "jobSlots": slots,
        "jobs": jobs,
    }


def _absent():
    return 404, {"error": {"code": 404, "status": "NOT_FOUND"}}


def test_job_slots_bound_the_job_count_and_default_to_two(tmp_path):
    """A campaign declares how many jobs its schedule spans; the default is today's."""
    create(tmp_path / "two", plan())
    assert len(Gate(tmp_path / "two", "a").snapshot()["jobs"]) == 2
    three = plan()
    three["jobs"]["c"] = {
        "resources": ["c"],
        "observation": [three["jobs"]["a"]["observation"][0]],
        "recovery": [three["jobs"]["a"]["recovery"][0]],
    }
    three["jobs"]["c"]["observation"][0]["path"] = "/v1/c"
    three["jobs"]["c"]["recovery"][0]["path"] = "/v1/c"
    with pytest.raises(ValueError, match="invalid shared allocation"):
        create(tmp_path / "three-default", three)
    three["jobSlots"] = 3
    create(tmp_path / "three", three)
    assert len(Gate(tmp_path / "three", "a").snapshot()["jobs"]) == 3


@pytest.mark.parametrize("slots", [0, 1, 2.0, "3", None, 9])
def test_malformed_or_exceeded_job_slots_are_refused(tmp_path, slots):
    value = scheduled_plan(slots)
    with pytest.raises(ValueError, match="invalid shared allocation"):
        create(tmp_path / f"gate-{slots}", value)


def test_a_scheduled_job_interleaves_observation_and_recovery(tmp_path):
    """Recovery is one-way only for a campaign that did not declare a schedule."""
    path = tmp_path / "gate"
    create(path, scheduled_plan())
    gate = Gate(path, "p1")
    gate.claim()
    operations = scheduled_plan()["jobs"]["p1"]
    gate.dispatch(operations["observation"][0], False, _absent)
    gate.dispatch(operations["recovery"][0], True, _absent)
    job = gate.snapshot()["jobs"]["p1"]
    assert job["stopped"] is False
    assert job["scheduleDone"] == 2
    gate.dispatch(operations["observation"][1], False, _absent)
    gate.dispatch(operations["recovery"][1], True, _absent)
    state = gate.snapshot()
    assert state["jobs"]["p1"]["scheduleDone"] == 4
    assert [event["phase"] for event in state["events"]] == [
        "observation",
        "recovery",
        "observation",
        "recovery",
    ]
    gate.finish()
    assert gate.snapshot()["jobs"]["p1"]["complete"] is True


def test_an_unscheduled_job_keeps_recovery_one_way(tmp_path):
    """The existing campaigns must not silently gain a second observation phase."""
    path = tmp_path / "gate"
    create(path, plan())
    gate = Gate(path, "a")
    gate.claim()
    operations = plan()["jobs"]["a"]
    gate.dispatch(operations["recovery"][0], True, _absent)
    assert gate.snapshot()["jobs"]["a"]["stopped"] is True
    assert "scheduleDone" not in gate.snapshot()["jobs"]["a"]
    with pytest.raises(ValueError, match="stopped"):
        gate.dispatch(operations["observation"][0], False, _absent)


def test_a_dispatch_outside_the_declared_schedule_is_refused(tmp_path):
    path = tmp_path / "gate"
    create(path, scheduled_plan())
    gate = Gate(path, "p1")
    gate.claim()
    operations = scheduled_plan()["jobs"]["p1"]
    with pytest.raises(ValueError, match="frozen execution schedule"):
        gate.dispatch(operations["recovery"][0], True, _absent)
    state = gate.snapshot()
    assert state["events"] == []
    assert state["jobs"]["p1"]["scheduleDone"] == 0
    gate.dispatch(operations["observation"][0], False, _absent)
    with pytest.raises(ValueError, match="frozen execution schedule"):
        gate.dispatch(operations["observation"][1], False, _absent)
    assert gate.snapshot()["jobs"]["p1"]["scheduleDone"] == 1


@pytest.mark.parametrize(
    "damage",
    [
        [],
        [{"phase": "observation", "index": 0}],
        [{"phase": "observation", "index": 0}] * 4,
        [
            {"phase": "observation", "index": 0},
            {"phase": "observation", "index": 1},
            {"phase": "recovery", "index": 0},
            {"phase": "recovery", "index": 2},
        ],
        [
            {"phase": "observation", "index": 0},
            {"phase": "observation", "index": 1},
            {"phase": "recovery", "index": 0},
            {"phase": "cleanup", "index": 1},
        ],
        [{"phase": "observation"}, {"phase": "recovery", "index": 0}],
    ],
)
def test_a_schedule_must_cover_every_slot_exactly_once(tmp_path, damage):
    value = scheduled_plan()
    value["jobs"]["p1"]["schedule"] = damage
    with pytest.raises(ValueError, match="invalid shared allocation"):
        create(tmp_path / "gate", value)


def test_the_plan_supplies_its_own_per_request_reservation(tmp_path):
    """Thirteen seconds a request is the Commit lane's number, not every campaign's."""
    value = scheduled_plan()
    del value["requestSeconds"]
    value["recoverySeconds"] = 40
    with pytest.raises(ValueError, match="invalid shared allocation"):
        create(tmp_path / "default", value)
    value["requestSeconds"] = 2
    create(tmp_path / "declared", value)
    assert Gate(tmp_path / "declared", "p1").snapshot()["plan"]["requestSeconds"] == 2


@pytest.mark.parametrize("seconds", [0, -1, "2", None, float("inf")])
def test_a_malformed_per_request_reservation_is_refused(tmp_path, seconds):
    value = scheduled_plan()
    value["requestSeconds"] = seconds
    with pytest.raises(ValueError, match="invalid shared allocation"):
        create(tmp_path / "gate", value)


def split_plan(upload=60.0, small=2.0):
    """One job whose requests are two populations: big uploads and small reads.

    No single per-request reservation is honest here. Sixty seconds cannot fit
    the cleanup slots inside any admissible recovery window, and the small value
    would under-reserve the upload by more than an order of magnitude.
    """
    op = lambda key: {
        "service": "firestore",
        "path": "/v1/" + key,
        "body": None,
        "method": "GET",
        "privileged": True,
        "form": False,
    }
    schedule = [
        {"phase": "observation", "index": 0, "seconds": small},
        {"phase": "observation", "index": 1, "seconds": upload},
        {"phase": "recovery", "index": 0, "seconds": small},
        {"phase": "recovery", "index": 1, "seconds": small},
        {"phase": "recovery", "index": 2, "seconds": small},
    ]
    return {
        "contract": "shared-local-v1",
        "wallSeconds": 600,
        "recoverySeconds": 20,
        "observationRequests": 2,
        "costMicrousd": 10000,
        "requestCostMicrousd": 1,
        "intervalSeconds": 0.25,
        "requestSeconds": upload,
        "jobSlots": 1,
        "jobs": {
            "probe": {
                "resources": ["probe"],
                "observation": [op("probe"), op("probe")],
                "recovery": [op("probe")] * 3,
                "schedule": schedule,
            }
        },
    }


def test_a_slot_may_reserve_its_own_seconds(tmp_path):
    """Three cleanup reads at two seconds fit a window the upload bound cannot."""
    create(tmp_path / "split", split_plan())
    bare = split_plan()
    for entry in bare["jobs"]["probe"]["schedule"]:
        del entry["seconds"]
    with pytest.raises(ValueError, match="invalid shared allocation"):
        create(tmp_path / "plan-wide", bare)


@pytest.mark.parametrize("seconds", [0, -1, "2", None, float("inf"), True])
def test_a_malformed_slot_reservation_is_refused(tmp_path, seconds):
    value = split_plan()
    value["jobs"]["probe"]["schedule"][0]["seconds"] = seconds
    with pytest.raises(ValueError, match="invalid shared allocation"):
        create(tmp_path / "gate", value)


def test_a_dispatch_reserves_the_seconds_its_own_slot_declared(tmp_path):
    """The deadline check uses the slot's bound, not one number for the campaign.

    The window is rewound so that five seconds remain. The small slot reserves
    two and is admitted; the upload slot reserves sixty and is refused. Were the
    plan-wide sixty used for both, the small slot would have been refused too.
    """
    import time as _time

    from shared_gate import _save

    value = split_plan()
    create(tmp_path / "gate", value)
    gate = Gate(tmp_path / "gate", "probe")
    gate.claim()
    with gate.locked() as state:
        window = value["wallSeconds"] - value["recoverySeconds"]
        state["started"] = _time.monotonic() - (window - 5)
        _save(gate.path, state)
    operations = value["jobs"]["probe"]["observation"]
    gate.dispatch(operations[0], False, _absent)
    assert gate.snapshot()["jobs"]["probe"]["scheduleDone"] == 1
    with pytest.raises(ValueError, match="capacity"):
        gate.dispatch(operations[1], False, _absent)
    assert gate.snapshot()["jobs"]["probe"]["scheduleDone"] == 1


def ceiling_plan(upload=60.0, ceiling=60.0):
    """A campaign that declares the wire ceiling its body-carrying slots must reserve."""
    value = split_plan(upload=upload)
    value["transportCeilingSeconds"] = ceiling
    value["jobs"]["probe"]["observation"][1] = {
        **value["jobs"]["probe"]["observation"][1],
        "method": "POST",
        "body": {"writes": []},
    }
    return value


def test_a_body_carrying_slot_must_reserve_the_declared_transport_ceiling(tmp_path):
    """The upload reservation is checkable, not conventional."""
    create(tmp_path / "at-ceiling", ceiling_plan())
    create(tmp_path / "above", ceiling_plan(upload=61.0))
    with pytest.raises(ValueError, match="invalid shared allocation"):
        create(tmp_path / "below", ceiling_plan(upload=59.0))
    shrunk = ceiling_plan()
    shrunk["jobs"]["probe"]["schedule"][1]["seconds"] = 2.0
    with pytest.raises(ValueError, match="invalid shared allocation"):
        create(tmp_path / "shrunk", shrunk)


def test_a_slot_without_a_body_is_not_held_to_the_transport_ceiling(tmp_path):
    value = ceiling_plan()
    assert value["jobs"]["probe"]["observation"][0]["body"] is None
    assert value["jobs"]["probe"]["schedule"][0]["seconds"] == 2.0
    create(tmp_path / "gate", value)


@pytest.mark.parametrize("ceiling", [0, -1, "60", None, float("inf"), True])
def test_a_malformed_transport_ceiling_is_refused(tmp_path, ceiling):
    with pytest.raises(ValueError, match="invalid shared allocation"):
        create(tmp_path / "gate", ceiling_plan(ceiling=ceiling))


def test_scheduled_observation_must_fit_the_window_it_is_left(tmp_path):
    """The whole arithmetic is proven before the run, not at the last dispatch."""
    value = split_plan()
    value["wallSeconds"] = 80
    value["recoverySeconds"] = 20
    with pytest.raises(ValueError, match="invalid shared allocation"):
        create(tmp_path / "tight", value)
    value["wallSeconds"] = 120
    create(tmp_path / "fits", value)


@pytest.mark.parametrize("creates", ["false", 0, None, 1])
def test_a_malformed_creating_declaration_is_refused(tmp_path, creates):
    value = split_plan()
    value["jobs"]["probe"]["schedule"][0]["creates"] = creates
    with pytest.raises(ValueError, match="invalid shared allocation"):
        create(tmp_path / "gate", value)


def published_plan(wall=600, recovery=300, published_wall=900, published_recovery=300):
    """A campaign that names the allocation its own budget artifact publishes."""
    value = scheduled_plan()
    value["wallSeconds"] = wall
    value["recoverySeconds"] = recovery
    value["publishedAllocation"] = {
        "wallSeconds": published_wall,
        "recoverySeconds": published_recovery,
    }
    return value


def test_a_plan_may_not_reserve_more_than_its_artifact_publishes(tmp_path):
    """The drift the request-byte campaign hit: a 345 second reserve against 300.

    `create` proved the plan internally consistent and had no way to see the
    published allocation, so the Gate and the budget artifact could disagree
    without anything failing.
    """
    create(tmp_path / "equal", published_plan(recovery=300, published_recovery=300))
    create(tmp_path / "under", published_plan(recovery=200, published_recovery=300))
    with pytest.raises(ValueError, match="invalid shared allocation"):
        create(tmp_path / "over", published_plan(recovery=345, published_recovery=300))
    with pytest.raises(ValueError, match="invalid shared allocation"):
        create(tmp_path / "wall", published_plan(wall=1000, published_wall=900))


def test_a_plan_without_a_published_allocation_is_unchanged(tmp_path):
    """Every campaign that never named an artifact keeps today's admission."""
    value = scheduled_plan()
    assert "publishedAllocation" not in value
    create(tmp_path / "gate", value)
    assert "publishedAllocation" not in Gate(tmp_path / "gate", "p1").snapshot()["plan"]


@pytest.mark.parametrize(
    "allocation",
    [
        {},
        {"wallSeconds": 900},
        {"recoverySeconds": 300},
        {"wallSeconds": 900, "recoverySeconds": 300, "extra": 1},
        {"wallSeconds": "900", "recoverySeconds": 300},
        {"wallSeconds": 900, "recoverySeconds": 0},
        {"wallSeconds": 900, "recoverySeconds": -1},
        {"wallSeconds": float("inf"), "recoverySeconds": 300},
        {"wallSeconds": True, "recoverySeconds": 300},
        None,
        [900, 300],
    ],
)
def test_a_malformed_published_allocation_is_refused(tmp_path, allocation):
    value = published_plan()
    value["publishedAllocation"] = allocation
    with pytest.raises(ValueError, match="invalid shared allocation"):
        create(tmp_path / "gate", value)


NONCE = "n" * 32
VERSION = "2026-09-18T00:00:00.000000Z"


def test_transform_with_exists_true_is_not_a_potential_create():
    operation = {
        "kind": "commit-transform",
        "service": "firestore",
        "method": "POST",
        "path": "/v1/projects/p/databases/(default)/documents:commit",
        "body": {
            "writes": [
                {
                    "transform": {"document": "projects/p/databases/(default)/documents/owned/doc"},
                    "currentDocument": {"exists": True},
                }
            ]
        },
    }
    assert can_create(operation) is False


def test_transform_without_exists_precondition_remains_a_potential_create():
    operation = {
        "kind": "commit-transform",
        "service": "firestore",
        "method": "POST",
        "path": "/v1/projects/p/databases/(default)/documents:commit",
        "body": {
            "writes": [{"transform": {"document": "projects/p/databases/(default)/documents/owned/doc"}}]
        },
    }
    assert can_create(operation) is True


def test_action_stage_creation_cannot_be_relabelled_as_noncreating():
    signup = {
        "kind": "action-stage",
        "id": "signup-relabelled-readback",
        "service": "auth",
        "project": "fireemu-35fe6",
        "method": "POST",
        "path": "identitytoolkit.googleapis.com/v1/accounts:signUp",
        "body": {"email": "owner@example.invalid"},
    }
    assert can_create(signup) is True


def test_known_action_stage_readback_is_noncreating():
    readback = {
        "kind": "action-stage",
        "id": "account-a-readback",
        "service": "auth",
        "project": "fireemu-35fe6",
        "method": "POST",
        "path": "identitytoolkit.googleapis.com/v1/projects/fireemu-35fe6/accounts:lookup",
        "resource": "projects/fireemu-35fe6/auth/accounts/o1-oob-" + ("a" * 32) + "-a",
        "body": {"localId": "$binding:accountAUid"},
    }
    assert can_create(readback) is False


@pytest.mark.parametrize("route", ("signUp", "import", "update", "create"))
@pytest.mark.parametrize("identifier", ("account-a-readback", "reset-link-generate", "account-b-delete"))
def test_action_noncreating_id_cannot_override_creation_route(route, identifier):
    operation = {
        "kind": "action-stage",
        "id": identifier,
        "service": "auth",
        "project": "fireemu-35fe6",
        "method": "POST",
        "path": f"identitytoolkit.googleapis.com/v1/accounts:{route}",
        "body": {"localId": "$binding:accountAUid"},
    }
    assert can_create(operation) is True


def test_action_noncreating_route_cannot_derive_authority_from_foreign_resource():
    operation = {
        "kind": "action-stage",
        "id": "account-a-readback",
        "service": "auth",
        "project": "fireemu-35fe6",
        "method": "POST",
        "path": "identitytoolkit.googleapis.com/v1/projects/fireemu-35fe6/accounts:lookup",
        "resource": "projects/foreign/auth/accounts/owned",
        "body": {"localId": "$binding:accountAUid"},
    }
    assert can_create(operation) is True


def commit_plan(marker="shared", writes=2, alias=True):
    """A campaign that creates its documents with one conditional POST :commit."""
    scope = "projects/p/databases/(default)/documents/owned/" + NONCE
    resources = [f"{scope}/items/doc-{index:02d}" for index in range(writes)]

    def fields(name):
        if marker == "shared":
            return {
                "_sharedOwner": {"referenceValue": name},
                "blob": {"stringValue": "x"},
            }
        return {"_owner": {"stringValue": NONCE}, "blob": {"stringValue": "x"}}

    commit = {
        "service": "firestore",
        "method": "POST",
        "path": "/v1/projects/p/databases/(default)/documents:commit",
        "body": {
            "writes": [
                {
                    "update": {"name": name, "fields": fields(name)},
                    "currentDocument": {"exists": False},
                }
                for name in resources
            ]
        },
        "privileged": True,
        "form": False,
    }
    read = lambda name: {
        "kind": "ownership-read",
        "resource": name,
        "service": "firestore",
        "method": "GET",
        "path": "/v1/" + name,
        "body": None,
        "privileged": True,
        "form": False,
    }
    delete = lambda name: {
        "kind": "version-bound-delete",
        "resource": name,
        "service": "firestore",
        "method": "DELETE",
        "path": "/v1/" + name,
        "body": None,
        "privileged": True,
        "form": False,
        "versionFrom": "ownership-read" if alias else 0,
    }
    recovery = []
    for name in resources:
        recovery.extend([read(name), delete(name)])
    value = {
        "contract": "shared-local-v2",
        "nonce": NONCE,
        "wallSeconds": 600,
        "recoverySeconds": 300,
        "observationRequests": 1,
        "costMicrousd": 10000,
        "requestCostMicrousd": 1,
        "intervalSeconds": 0.25,
        "requestSeconds": 2,
        "jobs": {
            "probe": {
                "resources": resources,
                "observation": [commit],
                "recovery": recovery,
            }
        },
    }
    if marker != "shared":
        value["ownershipMarker"] = {"field": "_owner", "binding": "nonce"}
    return value, resources


def _commit_response(count):
    return 200, {
        "writeResults": [{"updateTime": VERSION} for _ in range(count)],
        "commitTime": VERSION,
    }


def test_a_conditional_commit_yields_one_creation_proof_per_write(tmp_path):
    """Seventeen conditional creates in one Commit are seventeen ownership proofs."""
    value, resources = commit_plan()
    create(tmp_path / "gate", value)
    gate = Gate(tmp_path / "gate", "probe")
    gate.claim()
    gate.dispatch(
        value["jobs"]["probe"]["observation"][0],
        False,
        lambda: _commit_response(len(resources)),
    )
    job = gate.snapshot()["jobs"]["probe"]
    assert sorted(job["creationProofs"]) == sorted(resources)
    assert sorted(job["owned"]) == sorted(resources)
    assert all(
        proof["updateTime"] == VERSION for proof in job["creationProofs"].values()
    )


def test_a_commit_acknowledgement_must_answer_every_write(tmp_path):
    value, resources = commit_plan()
    create(tmp_path / "gate", value)
    gate = Gate(tmp_path / "gate", "probe")
    gate.claim()
    with pytest.raises(ValueError, match="acknowledgement incomplete"):
        gate.dispatch(
            value["jobs"]["probe"]["observation"][0],
            False,
            lambda: _commit_response(len(resources) - 1),
        )
    assert gate.snapshot()["jobs"]["probe"]["creationProofs"] == {}
    assert gate.snapshot()["jobs"]["probe"]["stopped"] is True


def test_a_campaign_may_declare_how_its_documents_mark_ownership(tmp_path):
    """The v2 marker is one convention, not the only one a campaign can carry."""
    value, resources = commit_plan(marker="nonce")
    create(tmp_path / "gate", value)
    gate = Gate(tmp_path / "gate", "probe")
    gate.claim()
    gate.dispatch(
        value["jobs"]["probe"]["observation"][0],
        False,
        lambda: _commit_response(len(resources)),
    )
    assert sorted(gate.snapshot()["jobs"]["probe"]["creationProofs"]) == sorted(
        resources
    )


def test_a_document_without_its_declared_marker_is_refused(tmp_path):
    value, resources = commit_plan(marker="nonce")
    # Declared as the nonce binding, but the documents carry the v2 shape.
    for write in value["jobs"]["probe"]["observation"][0]["body"]["writes"]:
        write["update"]["fields"] = {
            "_sharedOwner": {"referenceValue": write["update"]["name"]}
        }
    create(tmp_path / "gate", value)
    gate = Gate(tmp_path / "gate", "probe")
    gate.claim()
    with pytest.raises(ValueError, match="namespace marker"):
        gate.dispatch(
            value["jobs"]["probe"]["observation"][0],
            False,
            lambda: _commit_response(len(resources)),
        )


@pytest.mark.parametrize(
    "marker",
    [
        {},
        {"field": "_owner"},
        {"binding": "nonce"},
        {"field": "_owner", "binding": "other"},
        {"field": "", "binding": "nonce"},
        {"field": "_owner", "binding": "nonce", "extra": 1},
        None,
        "_owner",
    ],
)
def test_a_malformed_ownership_marker_is_refused(tmp_path, marker):
    value, _resources = commit_plan(marker="nonce")
    value["ownershipMarker"] = marker
    with pytest.raises(ValueError, match="invalid shared allocation"):
        create(tmp_path / "gate", value)


def test_a_delete_may_name_its_ownership_read_instead_of_its_index(tmp_path):
    """Seventeen deletes per probe should not have to hard-code seventeen indices."""
    value, resources = commit_plan()
    create(tmp_path / "gate", value)
    gate = Gate(tmp_path / "gate", "probe")
    gate.claim()
    operations = value["jobs"]["probe"]
    gate.dispatch(
        operations["observation"][0], False, lambda: _commit_response(len(resources))
    )
    name = resources[0]
    body = {
        "name": name,
        "fields": operations["observation"][0]["body"]["writes"][0]["update"]["fields"],
        "updateTime": VERSION,
    }
    gate.dispatch(operations["recovery"][0], True, lambda: (200, body))
    deleted = dict(operations["recovery"][1])
    del deleted["versionFrom"]
    deleted["path"] += "?currentDocument.updateTime=" + quote(VERSION, safe="")
    result = gate.dispatch(deleted, True, lambda: (200, {}))
    assert result == (200, {})
    assert gate.snapshot()["skips"] == [] if "skips" in gate.snapshot() else True
    assert gate.snapshot()["jobs"]["probe"]["recovery"] == 2


def test_a_version_alias_must_resolve_to_exactly_one_slot(tmp_path):
    value, _resources = commit_plan()
    probe = value["jobs"]["probe"]
    probe["recovery"][1]["versionFrom"] = "no-such-kind"
    with pytest.raises(ValueError, match="exactly one"):
        create(tmp_path / "missing", value)
    value, _resources = commit_plan()
    probe = value["jobs"]["probe"]
    # Two reads of the same resource make the alias ambiguous.
    probe["recovery"].insert(1, dict(probe["recovery"][0]))
    with pytest.raises(ValueError, match="exactly one"):
        create(tmp_path / "ambiguous", value)


def test_a_numeric_version_source_stays_canonical(tmp_path):
    value, _resources = commit_plan(writes=1, alias=False)
    create(tmp_path / "gate", value)
    assert (
        Gate(tmp_path / "gate", "probe").snapshot()["plan"]["jobs"]["probe"][
            "recovery"
        ][1]["versionFrom"]
        == 0
    )


def scheduled_commit_plan():
    """One probe: a conditional Commit, a readback, then its scheduled cleanup."""
    value, resources = commit_plan(writes=1)
    probe = value["jobs"]["probe"]
    name = resources[0]
    readback = {
        "kind": "probe-readback",
        "resource": name,
        "service": "firestore",
        "method": "GET",
        "path": "/v1/" + name,
        "body": None,
        "privileged": True,
        "form": False,
    }
    verify = {**readback, "kind": "cleanup-verify-absence"}
    probe["observation"] = [probe["observation"][0], readback]
    probe["recovery"] = [probe["recovery"][0], probe["recovery"][1], verify]
    probe["schedule"] = [
        {"phase": "observation", "index": 0},
        {"phase": "observation", "index": 1, "creates": False},
        {"phase": "recovery", "index": 0, "creates": False},
        {"phase": "recovery", "index": 1, "creates": False},
        {"phase": "recovery", "index": 2, "creates": False},
    ]
    value["observationRequests"] = 2
    return value, resources


@pytest.mark.parametrize("slot", [0, 1])
def test_a_slot_that_can_create_may_not_declare_that_it_cannot(tmp_path, slot):
    """The Ledger relaxes retirement on this declaration, so the Gate checks it."""
    value, _resources = scheduled_commit_plan()
    if slot == 0:
        value["jobs"]["probe"]["schedule"][0]["creates"] = False
    else:
        value["jobs"]["probe"]["observation"][1]["body"] = {"writes": []}
        value["jobs"]["probe"]["schedule"][1]["creates"] = False
    with pytest.raises(ValueError, match="cannot declare"):
        create(tmp_path / "gate", value)


def test_a_conditional_patch_slot_may_not_declare_that_it_cannot_create(tmp_path):
    value, resources = scheduled_commit_plan()
    probe = value["jobs"]["probe"]
    probe["observation"][1] = {
        **probe["observation"][1],
        "method": "PATCH",
        "path": "/v1/" + resources[0] + "?currentDocument.exists=false",
        "body": None,
    }
    with pytest.raises(ValueError, match="cannot declare"):
        create(tmp_path / "gate", value)


def _created(gate, value, resources):
    gate.claim()
    gate.dispatch(
        value["jobs"]["probe"]["observation"][0],
        False,
        lambda: _commit_response(len(resources)),
    )


def test_an_abandoned_observation_still_reaches_its_scheduled_cleanup(tmp_path):
    """An early stop must not cost the campaign its only way to delete."""
    value, resources = scheduled_commit_plan()
    create(tmp_path / "gate", value)
    gate = Gate(tmp_path / "gate", "probe")
    _created(gate, value, resources)
    name = resources[0]
    fields = value["jobs"]["probe"]["observation"][0]["body"]["writes"][0]["update"][
        "fields"
    ]
    gate.abandon_observation("transport-deadline")
    assert gate.snapshot()["jobs"]["probe"]["stopReason"] == "transport-deadline"
    recovery = value["jobs"]["probe"]["recovery"]
    gate.dispatch(
        recovery[0],
        True,
        lambda: (200, {"name": name, "fields": fields, "updateTime": VERSION}),
    )
    deleted = dict(recovery[1])
    del deleted["versionFrom"]
    deleted["path"] += "?currentDocument.updateTime=" + quote(VERSION, safe="")
    gate.dispatch(deleted, True, lambda: (200, {}))
    gate.dispatch(recovery[2], True, _absent)
    job = gate.snapshot()["jobs"]["probe"]
    assert job["recovery"] == 3
    assert job["absent"] == [name]
    # The one observation slot the stop skipped is counted, not dispatched.
    assert job["skippedByStop"] == 1
    assert job["observation"] == 1
    assert job["scheduleDone"] == 5


def test_a_commit_whose_answer_was_lost_is_never_treated_as_uncreated(tmp_path):
    """A dispatched write with no answer may have written, so nothing is skipped."""
    value, _resources = scheduled_commit_plan()
    create(tmp_path / "gate", value)
    gate = Gate(tmp_path / "gate", "probe")
    gate.claim()

    def deadline():
        raise TimeoutError("transport deadline")

    with pytest.raises(TimeoutError):
        gate.dispatch(value["jobs"]["probe"]["observation"][0], False, deadline)
    assert unconfirmed_creates(gate.snapshot(), "probe") == 1
    gate.abandon_observation("transport-deadline")
    sent = []

    def readback():
        sent.append(1)
        return _absent()

    gate.dispatch(value["jobs"]["probe"]["recovery"][0], True, readback)
    # The cleanup read goes to the wire: only a readback can settle it.
    assert sent == [1]
    assert gate.snapshot().get("skips", []) == []


@pytest.mark.parametrize(
    ("status", "body"),
    [
        (500, {"error": {"code": 500, "status": "INTERNAL"}}),
        (504, "<html>gateway timeout</html>"),
    ],
)
def test_a_completed_server_failure_keeps_create_recovery_required(
    tmp_path, status, body
):
    """A 5xx response does not prove that a conditional Commit was not applied."""
    value, _resources = scheduled_commit_plan()
    path = tmp_path / "gate"
    create(path, value)
    gate = Gate(path, "probe")
    gate.claim()
    gate.dispatch(
        value["jobs"]["probe"]["observation"][0],
        False,
        lambda: (status, body),
    )
    state = gate.snapshot()
    assert state["events"][0]["creationOutcome"] == "unknown"
    assert unconfirmed_creates(state, "probe") == 1
    gate.abandon_observation("server-failure")

    # Reload from the durable state before entering recovery.  The ownership
    # read must still be sent, and the following delete slot cannot be consumed
    # as a zero-wire refusal while the create outcome is unknown.
    reloaded = Gate(path, "probe")
    read = value["jobs"]["probe"]["recovery"][0]
    sent = []
    reloaded.dispatch(
        read,
        True,
        lambda: (sent.append(True) or (404, {"error": {"code": 404, "status": "NOT_FOUND"}})),
    )
    assert sent == [True]
    delete = dict(value["jobs"]["probe"]["recovery"][1])
    delete.pop("versionFrom")
    with pytest.raises(ValueError, match="unconfirmed write"):
        reloaded.skip_scheduled_slot(delete, True, "unknown server outcome")


def test_an_incomplete_success_acknowledgement_keeps_create_recovery_required(
    tmp_path,
):
    """A 200 without all write results is an unknown create, not a refusal."""
    value, _resources = scheduled_commit_plan()
    path = tmp_path / "gate"
    create(path, value)
    gate = Gate(path, "probe")
    gate.claim()
    with pytest.raises(ValueError, match="acknowledgement incomplete"):
        gate.dispatch(
            value["jobs"]["probe"]["observation"][0],
            False,
            lambda: _commit_response(0),
        )
    state = gate.snapshot()
    assert state["events"][0]["creationOutcome"] == "unknown"
    assert unconfirmed_creates(state, "probe") == 1
    gate.abandon_observation("incomplete-acknowledgement")
    reloaded = Gate(path, "probe")
    read = value["jobs"]["probe"]["recovery"][0]
    reloaded.dispatch(
        read,
        True,
        lambda: (404, {"error": {"code": 404, "status": "NOT_FOUND"}}),
    )
    delete = dict(value["jobs"]["probe"]["recovery"][1])
    delete.pop("versionFrom")
    with pytest.raises(ValueError, match="unconfirmed write"):
        reloaded.skip_scheduled_slot(delete, True, "incomplete server outcome")


def test_a_refused_commit_leaves_nothing_to_clean_and_spends_no_request(tmp_path):
    """A typed refusal settles the outcome, so its slots are zero-wire skips."""
    value, _resources = scheduled_commit_plan()
    create(tmp_path / "gate", value)
    gate = Gate(tmp_path / "gate", "probe")
    gate.claim()
    gate.dispatch(
        value["jobs"]["probe"]["observation"][0],
        False,
        lambda: (400, {"error": {"code": 400, "status": "INVALID_ARGUMENT"}}),
    )
    state = gate.snapshot()
    assert state["events"][0]["creationOutcome"] == "refused"
    assert unconfirmed_creates(state, "probe") == 0
    gate.abandon_observation("over-boundary-refusal")
    before = gate.snapshot()
    result = gate.dispatch(
        value["jobs"]["probe"]["recovery"][0], True, lambda: pytest.fail("no wire call")
    )
    assert result == (None, {"skipped": "skipped-refused-create"})
    after = gate.snapshot()
    assert after["events"] == before["events"]
    assert [skip["reason"] for skip in after["skips"]] == ["skipped-refused-create"]


def test_abandoning_observation_is_refused_outside_a_scheduled_job(tmp_path):
    create(tmp_path / "gate", plan())
    gate = Gate(tmp_path / "gate", "a")
    gate.claim()
    with pytest.raises(ValueError, match="declared schedule"):
        gate.abandon_observation("transport-deadline")


@pytest.mark.parametrize("reason", ["", None, 7, "x" * 129])
def test_an_abandon_reason_must_be_a_bounded_string(tmp_path, reason):
    value, resources = scheduled_commit_plan()
    create(tmp_path / "gate", value)
    gate = Gate(tmp_path / "gate", "probe")
    _created(gate, value, resources)
    with pytest.raises(ValueError, match="stop reason"):
        gate.abandon_observation(reason)
    assert gate.snapshot()["jobs"]["probe"].get("stopReason") is None


def test_an_abandoned_job_cannot_be_abandoned_twice_or_observe_again(tmp_path):
    value, resources = scheduled_commit_plan()
    create(tmp_path / "gate", value)
    gate = Gate(tmp_path / "gate", "probe")
    _created(gate, value, resources)
    gate.abandon_observation("transport-deadline")
    with pytest.raises(ValueError, match="already abandoned"):
        gate.abandon_observation("transport-deadline")
    with pytest.raises(ValueError, match="stopped"):
        gate.dispatch(value["jobs"]["probe"]["observation"][1], False, _absent)


def test_a_slot_that_will_never_be_sent_can_be_consumed_without_a_wire_call(tmp_path):
    """A refused Commit leaves slots its collector never sends; the cursor must move."""
    value, resources = scheduled_commit_plan()
    create(tmp_path / "gate", value)
    gate = Gate(tmp_path / "gate", "probe")
    gate.claim()
    gate.dispatch(
        value["jobs"]["probe"]["observation"][0],
        False,
        lambda: (400, {"error": {"code": 400, "status": "INVALID_ARGUMENT"}}),
    )
    probe = value["jobs"]["probe"]
    gate.dispatch(probe["observation"][1], False, _absent)
    gate.dispatch(probe["recovery"][0], True, _absent)
    skipped = dict(probe["recovery"][1])
    del skipped["versionFrom"]
    result = gate.skip_scheduled_slot(skipped, True, "refused-commit-created-nothing")
    assert result == (None, {"skipped": "no-creation-proof"})
    # The slot behind it is now reachable, which was the whole problem.
    gate.dispatch(probe["recovery"][2], True, _absent)
    state = gate.snapshot()
    assert state["jobs"]["probe"]["recovery"] == 3
    assert state["jobs"]["probe"]["absent"] == [resources[0]]
    assert state["skips"][0]["note"] == "refused-commit-created-nothing"


def test_a_slot_that_could_have_written_is_never_skipped(tmp_path):
    value, resources = scheduled_commit_plan()
    create(tmp_path / "gate", value)
    gate = Gate(tmp_path / "gate", "probe")
    gate.claim()
    with pytest.raises(ValueError, match="could have written"):
        gate.skip_scheduled_slot(value["jobs"]["probe"]["observation"][0], False, "no")
    probe = value["jobs"]["probe"]
    gate.dispatch(
        probe["observation"][0], False, lambda: _commit_response(len(resources))
    )
    gate.dispatch(probe["observation"][1], False, _absent)
    gate.dispatch(probe["recovery"][0], True, _absent)
    skipped = dict(probe["recovery"][1])
    del skipped["versionFrom"]
    with pytest.raises(ValueError, match="must be cleaned"):
        gate.skip_scheduled_slot(skipped, True, "nothing here")
    assert gate.snapshot().get("skips", []) == []


def test_a_skip_is_refused_while_a_write_is_unconfirmed(tmp_path):
    value, _resources = scheduled_commit_plan()
    create(tmp_path / "gate", value)
    gate = Gate(tmp_path / "gate", "probe")
    gate.claim()

    def deadline():
        raise TimeoutError("transport deadline")

    with pytest.raises(TimeoutError):
        gate.dispatch(value["jobs"]["probe"]["observation"][0], False, deadline)
    probe = value["jobs"]["probe"]
    gate.abandon_observation("transport-deadline")
    skipped = dict(probe["recovery"][0])
    with pytest.raises(ValueError, match="unconfirmed write"):
        gate.skip_scheduled_slot(skipped, True, "nothing here")


def test_a_refused_create_lets_its_delete_be_skipped_on_the_normal_path(tmp_path):
    """The expected outcome of the over-boundary probe, not an early stop.

    The collector sends nothing for a delete whose document was never created,
    so the Gate has to consume that slot or the absence readback behind it is
    refused as out of order, and the run cannot prove absence or release.
    """
    value, resources = scheduled_commit_plan()
    create(tmp_path / "gate", value)
    gate = Gate(tmp_path / "gate", "probe")
    gate.claim()
    probe = value["jobs"]["probe"]
    gate.dispatch(
        probe["observation"][0],
        False,
        lambda: (400, {"error": {"code": 400, "status": "INVALID_ARGUMENT"}}),
    )
    gate.dispatch(probe["observation"][1], False, _absent)
    # The ownership read still runs: a readback is what proves absence.
    gate.dispatch(probe["recovery"][0], True, _absent)
    skipped = dict(probe["recovery"][1])
    del skipped["versionFrom"]
    before = gate.snapshot()
    assert gate.dispatch(skipped, True, lambda: pytest.fail("no wire call")) == (
        None,
        {"skipped": "skipped-refused-create"},
    )
    assert gate.snapshot()["events"] == before["events"]
    gate.dispatch(probe["recovery"][2], True, _absent)
    gate.finish()
    state = gate.snapshot()
    assert state["jobs"]["probe"]["complete"] is True
    assert state["jobs"]["probe"]["absent"] == [resources[0]]
    assert [skip["reason"] for skip in state["skips"]] == ["skipped-refused-create"]


def test_a_commit_whose_answer_was_lost_leaves_its_delete_unskippable(tmp_path):
    """A lost answer is not a refusal, and the difference decides the exit."""
    value, _resources = scheduled_commit_plan()
    create(tmp_path / "gate", value)
    gate = Gate(tmp_path / "gate", "probe")
    gate.claim()
    probe = value["jobs"]["probe"]

    def deadline():
        raise TimeoutError("transport deadline")

    with pytest.raises(TimeoutError):
        gate.dispatch(probe["observation"][0], False, deadline)
    gate.abandon_observation("transport-deadline")
    sent = []

    def readback():
        sent.append(1)
        return _absent()

    gate.dispatch(probe["recovery"][0], True, readback)
    assert sent == [1]
    skipped = dict(probe["recovery"][1])
    del skipped["versionFrom"]
    with pytest.raises(ValueError, match="unconfirmed write"):
        gate.skip_scheduled_slot(skipped, True, "nothing here")
    assert gate.snapshot().get("skips", []) == []


def test_a_lost_create_answer_blocks_normal_finish(tmp_path):
    """A typed absence read does not settle an uncertain create outcome."""
    value, _resources = scheduled_commit_plan()
    path = tmp_path / "gate"
    create(path, value)
    gate = Gate(path, "probe")
    gate.claim()

    with pytest.raises(TimeoutError):
        gate.dispatch(
            value["jobs"]["probe"]["observation"][0],
            False,
            lambda: (_ for _ in ()).throw(TimeoutError("transport deadline")),
        )
    with pytest.raises(ValueError, match="cleanup incomplete"):
        gate.finish()


def test_an_unscheduled_lost_create_answer_blocks_normal_finish_after_recovery(
    tmp_path,
):
    """Legacy plans must retain ownership even without a schedule declaration."""
    value, resources = commit_plan(writes=1)
    path = tmp_path / "gate"
    create(path, value)
    gate = Gate(path, "probe")
    gate.claim()
    probe = value["jobs"]["probe"]

    with pytest.raises(TimeoutError):
        gate.dispatch(
            probe["observation"][0],
            False,
            lambda: (_ for _ in ()).throw(TimeoutError("transport deadline")),
        )
    assert unconfirmed_creates(gate.snapshot(), "probe") == 1

    # Complete the full legacy recovery sequence: a typed absence read, the
    # unavailable version-bound delete skipped by the Gate, and final absence.
    gate.dispatch(probe["recovery"][0], True, _absent)
    delete = dict(probe["recovery"][1])
    delete.pop("versionFrom")
    gate.dispatch(delete, True, _absent)
    state = gate.snapshot()
    assert state["jobs"]["probe"]["absent"] == resources
    assert state["jobs"]["probe"]["recovery"] == len(probe["recovery"])
    assert unconfirmed_creates(state, "probe") == 1
    with pytest.raises(ValueError, match="cleanup incomplete"):
        gate.finish()


@pytest.mark.parametrize("shape", ["commit", "patch"])
@pytest.mark.parametrize("failure", ["timeout", 500, 504])
def test_unscheduled_unknown_create_stays_owned_after_complete_recovery(
    tmp_path, shape, failure
):
    """Legacy jobs retain uncertain Commit and PATCH writes through finish."""
    value, resources = commit_plan(writes=1)
    probe = value["jobs"]["probe"]
    if shape == "patch":
        update = probe["observation"][0]["body"]["writes"][0]["update"]
        probe["observation"][0] = {
            "service": "firestore",
            "method": "PATCH",
            "path": "/v1/" + resources[0] + "?currentDocument.exists=false",
            "body": {
                "name": resources[0],
                "fields": update["fields"],
            },
            "privileged": True,
            "form": False,
        }
    path = tmp_path / f"{shape}-{failure}"
    create(path, value)
    gate = Gate(path, "probe")
    gate.claim()

    def lost_answer():
        if failure == "timeout":
            raise TimeoutError("transport deadline")
        return failure, {"error": {"code": failure, "status": "INTERNAL"}}

    if failure == "timeout":
        with pytest.raises(TimeoutError):
            gate.dispatch(probe["observation"][0], False, lost_answer)
    else:
        gate.dispatch(probe["observation"][0], False, lost_answer)

    # Finish the legacy recovery sequence: ownership read, versionless delete
    # (the Gate must retain responsibility rather than silently skip it), then
    # the final absence proof.
    recovery = probe["recovery"]
    gate = Gate(path, "probe")
    gate.dispatch(recovery[0], True, _absent)
    delete = dict(recovery[1])
    delete.pop("versionFrom", None)
    gate.dispatch(delete, True, _absent)
    assert gate.snapshot()["jobs"]["probe"]["absent"] == resources
    assert unconfirmed_creates(gate.snapshot(), "probe") == 1
    with pytest.raises(ValueError, match="cleanup incomplete"):
        gate.finish()


def test_a_nonce_bound_marker_requires_nonce_scoped_resources(tmp_path):
    """The binding is only adequate because the path scopes it, so check the path."""
    value, _resources = commit_plan(marker="nonce")
    create(tmp_path / "scoped", value)
    outside = commit_plan(marker="nonce")[0]
    probe = outside["jobs"]["probe"]
    renamed = "projects/p/databases/(default)/documents/shared/items/doc-00"
    probe["resources"] = [renamed]
    probe["observation"][0]["body"]["writes"][0]["update"]["name"] = renamed
    probe["recovery"] = [
        {**operation, "path": "/v1/" + renamed, "resource": renamed}
        for operation in probe["recovery"]
    ]
    with pytest.raises(ValueError, match="invalid shared allocation"):
        create(tmp_path / "unscoped", outside)


# The three request sizes the campaign probes, either side of the 10 MiB limit.
PROBE_SIZES = (10_485_759, 10_485_760, 10_485_761)


def _sized_body(total):
    """A body whose canonical encoding is exactly `total` bytes."""
    body = {"b": "x" * (total - 8)}
    assert len(canonical_body_bytes(body)) == total
    return body


def referenced_plan(sizes=PROBE_SIZES):
    """A plan whose oversized request bodies are carried by reference."""
    scope = "projects/p/databases/(default)/documents/owned/" + NONCE
    resources = [f"{scope}/items/doc-{index:02d}" for index in range(len(sizes))]
    bodies = [_sized_body(size) for size in sizes]
    observation = [
        {
            "service": "firestore",
            "method": "POST",
            "path": "/v1/projects/p/databases/(default)/documents:commit",
            "body": None,
            "bodyRef": body_reference(body),
            "privileged": True,
            "form": False,
        }
        for body in bodies
    ]
    recovery = [
        {
            "service": "firestore",
            "method": "GET",
            "path": "/v1/" + name,
            "body": None,
            "privileged": True,
            "form": False,
        }
        for name in resources
    ]
    return bodies, {
        "contract": "shared-local-v1",
        "nonce": NONCE,
        "wallSeconds": 600,
        "recoverySeconds": 300,
        "observationRequests": len(sizes),
        "costMicrousd": 10000,
        "requestCostMicrousd": 1,
        "intervalSeconds": 0.25,
        "requestSeconds": 60,
        "bodyReferenceThresholdBytes": 65536,
        "jobs": {
            "probe": {
                "resources": resources,
                "observation": observation,
                "recovery": recovery,
            }
        },
    }


def test_a_ten_mebibyte_slot_dispatches_and_validates_by_digest(tmp_path):
    """The body is verified against the reference the plan digest already binds."""
    bodies, value = referenced_plan()
    create(tmp_path / "gate", value)
    gate = Gate(tmp_path / "gate", "probe")
    gate.claim()
    sent = []
    for index, body in enumerate(bodies):
        operation = {**value["jobs"]["probe"]["observation"][index], "body": body}
        del operation["bodyRef"]
        gate.dispatch(
            operation,
            False,
            lambda operation=operation: (sent.append(operation["body"]), (200, {}))[1],
        )
    # Exactly the buffers that were verified are the ones the send received.
    assert [id(body) for body in sent] == [id(body) for body in bodies]
    assert gate.snapshot()["jobs"]["probe"]["observation"] == len(bodies)


def test_a_one_byte_body_change_is_refused(tmp_path):
    bodies, value = referenced_plan()
    create(tmp_path / "gate", value)
    gate = Gate(tmp_path / "gate", "probe")
    gate.claim()
    operation = {**value["jobs"]["probe"]["observation"][0], "body": bodies[0]}
    del operation["bodyRef"]
    longer = {"b": bodies[0]["b"] + "x"}
    shorter = {"b": bodies[0]["b"][:-1]}
    changed = {"b": "y" + bodies[0]["b"][1:]}
    for body in (longer, shorter, changed):
        with pytest.raises(ValueError, match="frozen reference"):
            gate.dispatch({**operation, "body": body}, False, lambda: (200, {}))
    assert gate.snapshot()["events"] == []


def test_a_referenced_plan_keeps_the_gate_state_small(tmp_path):
    """Three ten-mebibyte bodies inline would be twice the Ledger's receipt bound."""
    bodies, value = referenced_plan()
    create(tmp_path / "gate", value)
    state = (tmp_path / "gate" / "state.json").stat().st_size
    inline = sum(len(canonical_body_bytes(body)) for body in bodies)
    assert state < 16 * 1024 * 1024 < inline


def test_every_body_bearing_slot_carries_a_reference_and_no_inline_body(tmp_path):
    """The structural walk the freeze requires, and the exact observed sizes."""
    bodies, value = referenced_plan()
    create(tmp_path / "gate", value)
    plan = Gate(tmp_path / "gate", "probe").snapshot()["plan"]
    carried = [
        operation
        for job in plan["jobs"].values()
        for phase in ("observation", "recovery")
        for operation in job[phase]
        if operation.get("bodyRef") is not None
    ]
    assert len(carried) == len(bodies)
    for operation, body, size in zip(carried, bodies, PROBE_SIZES, strict=True):
        assert set(operation["bodyRef"]) == {"sha256", "bytes"}
        assert operation["body"] is None
        assert operation["bodyRef"]["bytes"] == size
        assert operation["bodyRef"]["bytes"] == len(canonical_body_bytes(body))
    assert [operation["bodyRef"]["bytes"] for operation in carried] == list(PROBE_SIZES)


def test_an_inline_body_over_the_declared_threshold_is_refused(tmp_path):
    bodies, value = referenced_plan()
    operation = value["jobs"]["probe"]["observation"][0]
    operation["body"] = bodies[0]
    del operation["bodyRef"]
    with pytest.raises(ValueError, match="invalid shared allocation"):
        create(tmp_path / "gate", value)


def test_an_inline_body_under_the_threshold_behaves_as_before(tmp_path):
    """The Commit and stream lanes carry small bodies inline and are untouched."""
    _bodies, value = referenced_plan(sizes=(64,))
    operation = value["jobs"]["probe"]["observation"][0]
    small = _sized_body(64)
    operation["body"] = small
    del operation["bodyRef"]
    create(tmp_path / "gate", value)
    gate = Gate(tmp_path / "gate", "probe")
    gate.claim()
    with pytest.raises(ValueError, match="closed scenario"):
        gate.dispatch({**operation, "body": {"b": "z" * 56}}, False, lambda: (200, {}))
    gate.dispatch({**operation}, False, lambda: (200, {}))
    assert gate.snapshot()["jobs"]["probe"]["observation"] == 1


@pytest.mark.parametrize(
    "reference",
    [
        {"sha256": "0" * 64},
        {"bytes": 10},
        {"sha256": "0" * 64, "bytes": 0},
        {"sha256": "0" * 64, "bytes": -1},
        {"sha256": "0" * 63, "bytes": 10},
        {"sha256": "0" * 64, "bytes": 10, "extra": 1},
        {"sha256": "0" * 64, "bytes": True},
        "0" * 64,
        [],
    ],
)
def test_a_malformed_body_reference_is_refused(tmp_path, reference):
    _bodies, value = referenced_plan(sizes=(64,))
    value["jobs"]["probe"]["observation"][0]["bodyRef"] = reference
    with pytest.raises(ValueError, match="invalid shared allocation"):
        create(tmp_path / "gate", value)


def test_a_slot_may_not_carry_both_a_body_and_a_reference(tmp_path):
    bodies, value = referenced_plan(sizes=(64,))
    value["jobs"]["probe"]["observation"][0]["body"] = bodies[0]
    with pytest.raises(ValueError, match="invalid shared allocation"):
        create(tmp_path / "gate", value)


def test_observation_auth_delete_defaults_to_refused(tmp_path):
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).parent / "auth-action-codes"))
    import action_codes_gate

    value = action_codes_gate.gate_plan("fireemu-35fe6", "c" * 32)
    value.pop("observationDeletePolicy")
    with pytest.raises(ValueError, match="destructive Auth delete"):
        create(tmp_path / "gate", value)
