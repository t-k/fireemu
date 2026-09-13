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
        "wallSeconds": 60,
        "recoverySeconds": 20,
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
            return 404, {}

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
    a.dispatch(p["jobs"]["a"]["observation"][0], False, lambda: (404, {}))
    a.stop()
    with pytest.raises(ValueError):
        a.dispatch(p["jobs"]["a"]["observation"][0], False, lambda: (200, {}))
    b.dispatch(p["jobs"]["b"]["observation"][0], False, lambda: (404, {}))
    b.stop(environment=True)
    for key, gate in [("a", a), ("b", b)]:
        gate.dispatch(p["jobs"][key]["recovery"][0], True, lambda: (404, {}))
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
            p.update(wallSeconds=21, recoverySeconds=20)
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
            gate.dispatch(operation, False, lambda: (404, {}))
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
    b.dispatch(p["jobs"]["b"]["observation"][0], False, lambda: (404, {}))
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
        local_origins={"auth": "http://127.0.0.1:12345", "firestore": "http://127.0.0.1:12346"},
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
