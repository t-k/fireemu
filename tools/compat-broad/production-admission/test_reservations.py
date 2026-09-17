# ruff: noqa: I001 -- reservations bootstraps the shared module path.
"""Real filesystem/process tests of bounded shared admission; no production I/O."""

import multiprocessing
import threading
import time
from pathlib import Path

import pytest
from reservations import Ledger, conflicts
from broad_contract import digest
from shared_gate import Gate, create


def envelope():
    return {
        "permissionDigest": "a" * 64,
        "issuedAt": 1000,
        "expiresAt": 10000,
        "limits": {
            "requests": 100,
            "accounts": 10,
            "resources": 10,
            "costMicrousd": 10000,
        },
        "concurrency": 4,
        "scopes": [{"key": "project/p", "mode": "EXCLUSIVE"}],
    }


def plan(label="a"):
    operation = {
        "service": "firestore",
        "method": "GET",
        "path": f"/v1/projects/p/databases/(default)/documents/owned/{label}",
        "body": None,
        "privileged": True,
    }
    return {
        "contract": "shared-local-v2",
        "nonce": digest(label)[:32],
        "wallSeconds": 100,
        "recoverySeconds": 40,
        "intervalSeconds": 0.25,
        "observationRequests": 0,
        "requestCostMicrousd": 1,
        "costMicrousd": 10,
        "jobs": {
            "limits": {
                "observation": [],
                "recovery": [operation],
                "resources": [operation["path"].removeprefix("/v1/")],
            }
        },
    }


def claim(tmp_path, label, locks=None):
    owned = {
        "key": f"project/p/firestore/(default)/documents/owned/{label}",
        "mode": "WRITE",
    }
    locks = list(locks or [])
    if owned not in locks:
        locks.append(owned)
    return {
        "campaignId": label,
        "manifestDigest": digest(label),
        "nonceDigest": digest(plan(label)["nonce"]),
        "gatePath": str((tmp_path / label).resolve()),
        "gatePlanDigest": digest(plan(label)),
        "locks": locks,
        "budget": {"requests": 2, "accounts": 0, "resources": 1, "costMicrousd": 10},
        "durationSeconds": 100,
    }


@pytest.mark.parametrize(
    "left,right,expected",
    [
        (("project/p/config", "READ"), ("project/p/config/policy", "READ"), False),
        (("project/p/config", "WRITE"), ("project/p/config/policy", "READ"), True),
        (("project/p/config", "READ"), ("project/p/config/policy", "WRITE"), True),
        (("project/p/data/a/*", "EXCLUSIVE"), ("project/p/data/a/doc", "READ"), True),
        (("project/p/data/a", "WRITE"), ("project/p/data/ab", "WRITE"), False),
        (("project/p/data/a", "WRITE"), ("project/q/data/a", "WRITE"), False),
    ],
)
def test_segment_aware_lock_conflicts(left, right, expected):
    assert (
        conflicts(
            {"key": left[0], "mode": left[1]}, {"key": right[0], "mode": right[1]}
        )
        is expected
    )


@pytest.mark.parametrize(
    "key",
    [
        "project/p//data",
        "project/p/../data",
        "project/p/data%2Fa",
        "project/p/*/a",
        "/project/p/data",
        "project/p/data/",
    ],
)
def test_ambiguous_scope_refused_without_mutation(tmp_path, key):
    ledger = Ledger.create(tmp_path / "ledger")
    before = ledger.snapshot()
    with pytest.raises(ValueError):
        ledger.reserve(
            envelope(),
            claim(tmp_path, "a", [{"key": key, "mode": "READ"}]),
            plan(),
            now=1100,
        )
    assert ledger.snapshot() == before


def test_atomic_capacity_and_cross_envelope_conflicts(tmp_path):
    ledger = Ledger.create(tmp_path / "ledger")
    first = claim(tmp_path, "a", [{"key": "project/p/config", "mode": "WRITE"}])
    ledger.reserve(envelope(), first, plan(), now=1100)
    before = ledger.snapshot()
    other = envelope()
    other["permissionDigest"] = "b" * 64
    with pytest.raises(ValueError):
        ledger.reserve(
            other,
            claim(tmp_path, "b", [{"key": "project/p/config/policy", "mode": "READ"}]),
            plan("b"),
            now=1100,
        )
    assert ledger.snapshot() == before
    too_large = claim(tmp_path, "c")
    too_large["budget"]["accounts"] = 11
    with pytest.raises(ValueError):
        ledger.reserve(envelope(), too_large, plan("c"), now=1100)
    assert ledger.snapshot() == before


def test_expiry_never_releases_locks_and_nonce_is_never_reused(tmp_path):
    ledger = Ledger.create(tmp_path / "ledger")
    first = claim(tmp_path, "a")
    ticket = ledger.reserve(envelope(), first, plan(), now=1100)
    with pytest.raises(ValueError):
        ledger.validate(ticket, now=1201)
    second = claim(tmp_path, "b", first["locks"])
    with pytest.raises(ValueError):
        ledger.reserve(envelope(), second, plan("b"), now=1201)
    second["locks"] = [
        {"key": "project/p/data/b", "mode": "WRITE"},
        {
            "key": "project/p/firestore/(default)/documents/owned/a",
            "mode": "WRITE",
        },
    ]
    second["nonceDigest"] = first["nonceDigest"]
    second["gatePlanDigest"] = first["gatePlanDigest"]
    with pytest.raises(ValueError, match="reuse"):
        ledger.reserve(envelope(), second, plan("a"), now=1201)


def test_cleanup_releases_scope_but_never_returns_budget(tmp_path):
    ledger = Ledger.create(tmp_path / "ledger")
    first = claim(tmp_path, "a")
    ticket = ledger.reserve(envelope(), first, plan(), now=1100)
    create(Path(first["gatePath"]), plan())
    gate = Gate(first["gatePath"], "limits")
    gate.claim()
    with pytest.raises(ValueError):
        ledger.finish(ticket)
    operation = plan()["jobs"]["limits"]["recovery"][0]
    gate.dispatch(
        operation, True, lambda: (404, {"error": {"code": 404, "status": "NOT_FOUND"}})
    )
    gate.finish()
    ledger.finish(ticket)
    state = ledger.snapshot()
    assert state["envelopes"][digest(envelope())]["allocated"] == first["budget"]
    with pytest.raises(ValueError):
        ledger.validate(ticket, now=1110)
    with pytest.raises(ValueError):
        ledger.finish(ticket)
    ledger.reserve(
        envelope(), claim(tmp_path, "b", first["locks"]), plan("b"), now=1110
    )


def contender(root, barrier, queue, label):
    ledger = Ledger(Path(root) / "ledger")
    request = claim(Path(root), label, [{"key": "project/p/shared", "mode": "WRITE"}])
    barrier.wait(timeout=10)
    try:
        ledger.reserve(envelope(), request, plan(label), now=1100)
        queue.put("accepted")
    except ValueError:
        queue.put("refused")


def test_two_processes_cannot_both_reserve_conflicting_scope(tmp_path):
    ledger = Ledger.create(tmp_path / "ledger")
    ctx = multiprocessing.get_context("spawn")
    barrier, queue = ctx.Barrier(2), ctx.Queue()
    children = [
        ctx.Process(target=contender, args=(str(tmp_path), barrier, queue, label))
        for label in ("a", "b")
    ]
    try:
        for child in children:
            child.start()
        for child in children:
            child.join(timeout=15)
            assert child.exitcode == 0
        assert sorted([queue.get(timeout=2), queue.get(timeout=2)]) == [
            "accepted",
            "refused",
        ]
        assert len(ledger.snapshot()["reservations"]) == 1
        assert (
            ledger.snapshot()["envelopes"][digest(envelope())]["allocated"]["requests"]
            == 2
        )
    finally:
        for child in children:
            if child.is_alive():
                child.terminate()
                child.join(timeout=5)
        queue.close()
        queue.join_thread()


def test_same_permission_cannot_multiply_its_envelope(tmp_path):
    ledger = Ledger.create(tmp_path / "ledger")
    ledger.reserve(envelope(), claim(tmp_path, "a"), plan(), now=1100)
    before = ledger.snapshot()
    changed = envelope()
    changed["limits"]["requests"] += 100
    with pytest.raises(ValueError, match="another envelope"):
        ledger.reserve(changed, claim(tmp_path, "b"), plan("b"), now=1100)
    assert ledger.snapshot() == before


def test_readers_share_scope_but_concurrency_still_bounds_admission(tmp_path):
    ledger = Ledger.create(tmp_path / "ledger")
    policy = envelope()
    policy["concurrency"] = 2
    locks = [{"key": "project/p/config", "mode": "READ"}]
    ledger.reserve(policy, claim(tmp_path, "a", locks), plan(), now=1100)
    ledger.reserve(policy, claim(tmp_path, "b", locks), plan("b"), now=1100)
    before = ledger.snapshot()
    with pytest.raises(ValueError, match="concurrency"):
        ledger.reserve(policy, claim(tmp_path, "c"), plan("c"), now=1100)
    assert ledger.snapshot() == before


def test_ticket_cannot_move_to_copied_or_missing_ledger(tmp_path):
    import shutil

    ledger = Ledger.create(tmp_path / "ledger")
    ticket = ledger.reserve(envelope(), claim(tmp_path, "a"), plan(), now=1100)
    shutil.copytree(tmp_path / "ledger", tmp_path / "copy")
    with pytest.raises(ValueError, match="ticket"):
        Ledger(tmp_path / "copy").validate(ticket, now=1100)
    with pytest.raises(FileNotFoundError):
        Ledger(tmp_path / "missing")
    (tmp_path / "alias").symlink_to(tmp_path / "ledger", target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        Ledger(tmp_path / "alias")


def interrupted_worker(root, connection):
    ledger = Ledger(Path(root) / "ledger")
    request = claim(Path(root), "a")
    ticket = ledger.reserve(envelope(), request, plan(), now=1100)
    create(Path(request["gatePath"]), plan())
    gate = Gate(request["gatePath"], "limits")
    gate.claim()

    def interrupted():
        connection.send(ticket)
        connection.close()
        raise SystemExit(23)

    gate.dispatch(plan()["jobs"]["limits"]["recovery"][0], True, interrupted)


def test_exited_worker_keeps_uncertain_gate_and_shared_ownership(tmp_path):
    ledger = Ledger.create(tmp_path / "ledger")
    ctx = multiprocessing.get_context("spawn")
    receiver, sender = ctx.Pipe(duplex=False)
    child = ctx.Process(target=interrupted_worker, args=(str(tmp_path), sender))
    try:
        child.start()
        sender.close()
        assert receiver.poll(10)
        ticket = receiver.recv()
        child.join(timeout=10)
        assert child.exitcode == 23
        gate = Gate(tmp_path / "a", "limits").snapshot()
        assert gate["total"] == 1
        assert gate["jobs"]["limits"]["inflight"] is True
        with pytest.raises(ValueError, match="cleanup"):
            ledger.finish(ticket)
        row = ledger.snapshot()["reservations"][ticket["reservation"]]
        assert row["state"] == "held"
        with pytest.raises(ValueError, match="conflict"):
            ledger.reserve(
                envelope(),
                claim(tmp_path, "b", row["claim"]["locks"]),
                plan("b"),
                now=5000,
            )
    finally:
        receiver.close()
        if child.is_alive():
            child.terminate()
            child.join(timeout=5)


def test_closing_refuses_dispatch_without_gate_ledger_lock_inversion(tmp_path):
    import threading
    import time

    ledger = Ledger.create(tmp_path / "ledger")
    request = claim(tmp_path, "a")
    ticket = ledger.reserve(envelope(), request, plan(), now=1100)
    create(Path(request["gatePath"]), plan())
    gate = Gate(request["gatePath"], "limits")
    gate.claim()
    gate.dispatch(
        plan()["jobs"]["limits"]["recovery"][0],
        True,
        lambda: (404, {"error": {"code": 404, "status": "NOT_FOUND"}}),
    )
    gate.finish()
    errors = []

    def finish():
        try:
            ledger.finish(ticket)
        except Exception as error:  # noqa: BLE001 -- Preserve thread failures for assertions.
            errors.append(error)

    worker = threading.Thread(target=finish)
    with gate.locked():
        worker.start()
        until = time.monotonic() + 5
        while (
            ledger.snapshot()["reservations"][ticket["reservation"]]["state"]
            != "closing"
        ):
            assert time.monotonic() < until
            time.sleep(0.01)
        with pytest.raises(ValueError, match="unavailable"):
            ledger.validate(ticket, now=1110)
    worker.join(timeout=5)
    assert not worker.is_alive()
    assert errors == []
    assert (
        ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "released"
    )


def test_production_gate_cannot_borrow_another_permission_budget(tmp_path):
    ledger = Ledger.create(tmp_path / "ledger")
    frozen = plan()
    frozen["permissionDigest"] = "b" * 64
    request = claim(tmp_path, "a")
    request["gatePlanDigest"] = digest(frozen)
    before = ledger.snapshot()
    with pytest.raises(ValueError, match="permission differs"):
        ledger.reserve(envelope(), request, frozen, now=1100)
    assert ledger.snapshot() == before


def test_validate_samples_default_clock_after_waiting_for_ledger_lock(tmp_path):
    now = time.time()
    policy = envelope()
    policy.update(issuedAt=now - 1, expiresAt=now + 4.5)
    request = claim(tmp_path, "a")
    short_plan = plan()
    short_plan["wallSeconds"] = 3
    short_plan["recoverySeconds"] = 0.5
    request["gatePlanDigest"] = digest(short_plan)
    request["durationSeconds"] = 3
    ledger = Ledger.create(tmp_path / "ledger")
    ticket = ledger.reserve(policy, request, short_plan, now=now)
    entered = threading.Event()
    errors = []

    def validate():
        entered.set()
        try:
            ledger.validate(ticket, duration=1)
        except ValueError as error:
            assert "unavailable" in str(error)
            errors.append(error)
        else:
            errors.append(
                AssertionError("validate accepted after the reservation deadline")
            )

    with ledger._locked():
        worker = threading.Thread(target=validate)
        worker.start()
        assert entered.wait(2)
        time.sleep(2.2)
    worker.join(timeout=3)
    assert not worker.is_alive()
    assert errors and isinstance(errors[0], ValueError)


def test_reserve_samples_default_clock_after_waiting_for_ledger_lock(tmp_path):
    now = time.time()
    policy = envelope()
    policy.update(issuedAt=now - 1, expiresAt=now + 3.5)
    request = claim(tmp_path, "a")
    short_plan = plan()
    short_plan["wallSeconds"] = 3
    short_plan["recoverySeconds"] = 0.5
    request["gatePlanDigest"] = digest(short_plan)
    request["durationSeconds"] = 3
    ledger = Ledger.create(tmp_path / "ledger")
    entered = threading.Event()
    errors = []

    def reserve():
        entered.set()
        try:
            ledger.reserve(policy, request, short_plan)
        except ValueError as error:
            errors.append(error)

    with ledger._locked():
        worker = threading.Thread(target=reserve)
        worker.start()
        assert entered.wait(2)
        time.sleep(3.2)
    worker.join(timeout=3)
    assert not worker.is_alive()
    assert any("permission window" in str(error) for error in errors)
    assert ledger.snapshot()["reservations"] == {}


@pytest.mark.parametrize(
    "locks",
    [
        [],
        [{"key": "project/p/firestore/(default)/documents/other", "mode": "WRITE"}],
        [{"key": "project/p/firestore/(default)/documents/owned/a", "mode": "READ"}],
        [{"key": "project/q/firestore/(default)/documents/owned/a", "mode": "WRITE"}],
    ],
)
def test_gate_firestore_resources_require_covering_write_lock(tmp_path, locks):
    ledger = Ledger.create(tmp_path / "ledger")
    request = claim(tmp_path, "a", locks)
    request["locks"] = locks
    before = ledger.snapshot()
    with pytest.raises(ValueError):
        ledger.reserve(envelope(), request, plan(), now=1100)
    assert ledger.snapshot() == before


@pytest.mark.parametrize("covered", [True, False])
def test_gate_resource_lock_prevents_same_document_escape(tmp_path, covered):
    ledger = Ledger.create(tmp_path / "ledger")
    ledger.reserve(envelope(), claim(tmp_path, "a"), plan(), now=1100)
    before = ledger.snapshot()
    other_plan = plan("b")
    other_plan["jobs"]["limits"]["recovery"][0]["path"] = plan()["jobs"]["limits"][
        "recovery"
    ][0]["path"]
    other_plan["jobs"]["limits"]["resources"] = [
        other_plan["jobs"]["limits"]["recovery"][0]["path"].removeprefix("/v1/")
    ]
    request = claim(
        tmp_path,
        "b",
        [
            {"key": "project/p/data/alternate", "mode": "WRITE"},
            {
                "key": "project/p/firestore/(default)/documents/owned/*",
                "mode": "WRITE",
            },
        ],
    )
    if not covered:
        request["locks"] = claim(tmp_path, "b")["locks"]
    request["gatePlanDigest"] = digest(other_plan)
    request["nonceDigest"] = digest(other_plan["nonce"])
    with pytest.raises(ValueError, match="conflict" if covered else "not covered"):
        ledger.reserve(envelope(), request, other_plan, now=1100)
    assert ledger.snapshot() == before


@pytest.mark.parametrize(
    "body",
    [
        {"nonJson": "<html>not found</html>"},
        {"error": {"code": 404, "status": "PERMISSION_DENIED"}},
        {"error": {"code": "404", "status": "NOT_FOUND"}},
        {"error": {"code": 404.0, "status": "NOT_FOUND"}},
    ],
)
def test_untyped_absence_never_releases_shared_ownership(tmp_path, body):
    ledger = Ledger.create(tmp_path / "ledger")
    first = claim(tmp_path, "a")
    ticket = ledger.reserve(envelope(), first, plan(), now=1100)
    create(Path(first["gatePath"]), plan())
    gate = Gate(first["gatePath"], "limits")
    gate.claim()
    operation = plan()["jobs"]["limits"]["recovery"][0]
    with pytest.raises(ValueError, match="typed.*absence"):
        gate.dispatch(operation, True, lambda: (404, body))
    with pytest.raises(ValueError):
        gate.finish()
    with pytest.raises(ValueError):
        ledger.finish(ticket)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"
    with pytest.raises(ValueError):
        ledger.reserve(
            envelope(), claim(tmp_path, "b", first["locks"]), plan("b"), now=1110
        )


def test_absent_boolean_cannot_replace_bound_cleanup_evidence(tmp_path):
    from shared_gate import _save

    ledger = Ledger.create(tmp_path / "ledger")
    first = claim(tmp_path, "a")
    ticket = ledger.reserve(envelope(), first, plan(), now=1100)
    create(Path(first["gatePath"]), plan())
    gate = Gate(first["gatePath"], "limits")
    gate.claim()
    with gate.locked() as state:
        job = state["jobs"]["limits"]
        job.update(complete=True, absent=list(job["resources"]), recovery=1)
        _save(gate.path, state)
    with pytest.raises(ValueError):
        ledger.finish(ticket)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"


@pytest.mark.parametrize(
    "field,value",
    [
        ("requestDigest", "wrong-resource"),
        ("responseDigest", "wrong-body"),
        ("completed", False),
        ("phase", "observation"),
    ],
)
def test_absence_release_checks_request_response_and_completion(tmp_path, field, value):
    from shared_gate import _save

    ledger = Ledger.create(tmp_path / "ledger")
    first = claim(tmp_path, "a")
    ticket = ledger.reserve(envelope(), first, plan(), now=1100)
    create(Path(first["gatePath"]), plan())
    gate = Gate(first["gatePath"], "limits")
    gate.claim()
    operation = plan()["jobs"]["limits"]["recovery"][0]
    gate.dispatch(
        operation, True, lambda: (404, {"error": {"code": 404, "status": "NOT_FOUND"}})
    )
    gate.finish()
    with gate.locked() as state:
        state["events"][0][field] = value
        _save(gate.path, state)
    with pytest.raises(ValueError):
        ledger.finish(ticket)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"
