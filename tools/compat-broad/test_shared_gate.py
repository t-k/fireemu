"""Cross-process admission tests, with no network or credentials."""

import multiprocessing as mp
import os

import pytest
from shared_gate import Gate, create


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
