"""Offline deadline obligations across the Gate-to-worker boundary."""

import io
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import request_bytes_collector as collector
import request_bytes_descriptor as campaign
import request_bytes_https_worker as worker
import request_bytes_o8 as launcher
import request_bytes_remote_transport as remote
import shared_gate
from test_request_bytes_production import built, offline, wire_fixture  # noqa: F401
from test_request_bytes_remote_transport import FakeClock, FakeResponse, plan_and_commit


@pytest.mark.parametrize("delay", [0.23, 2.5, 3.0])
def test_preparation_spends_the_small_request_deadline(monkeypatch, delay):
    plan, _ = plan_and_commit()
    operation = plan["observation"][0]
    clock, calls = FakeClock(), []
    prepare = remote.prepare

    def delayed_prepare(*args):
        result = prepare(*args)
        clock.advance(delay)
        return result

    def exchange(*args):
        calls.append(args[4])
        return FakeResponse(404, {}, b"{}")

    monkeypatch.setattr(remote, "prepare", delayed_prepare)
    receipt = remote._request_impl(
        plan,
        "observation",
        0,
        operation,
        "token",
        exchange=exchange,
        timeout=2.5,
        clock=clock,
    )
    if delay < 2.5:
        assert calls == [pytest.approx(2.5 - delay)]
    else:
        assert calls == []
        assert receipt["failure"] == "timeout"


@pytest.mark.parametrize("phase", ["observation", "recovery"])
@pytest.mark.parametrize("delay_kind", ["slot", "phase"])
def test_gate_save_delay_cannot_send_past_slot_or_phase(
    built,  # noqa: F811
    tmp_path,
    monkeypatch,
    phase,
    delay_kind,
):
    monkeypatch.setattr(collector, "time", shared_gate.time, raising=False)
    save, wire, delayed = shared_gate._save, [], []
    wire_fixture(monkeypatch)
    fixture_request = remote.request

    def delayed_save(path, state):
        result = save(path, state)
        events = state.get("events", [])
        if not delayed and events and events[-1]["phase"] == phase:
            delayed.append(True)
            shared_gate.time.now = (
                shared_gate.time.now + 3.1
                if delay_kind == "slot"
                else state["started"]
                + (
                    state["plan"]["wallSeconds"] - state["plan"]["recoverySeconds"]
                    if phase == "observation"
                    else state["plan"]["wallSeconds"]
                )
                + 0.1
            )
        return result

    def request(plan, phase, index, operation, token, **kwargs):
        def exchange(*args):
            wire.append((phase, index))
            receipt = fixture_request(plan, phase, index, operation, token)
            return FakeResponse(
                receipt["status"], {}, json.dumps(receipt["body"]).encode()
            )

        return remote._request_impl(
            plan,
            phase,
            index,
            operation,
            token,
            exchange=exchange,
            timeout=kwargs["timeout"],
            clock=shared_gate.time.monotonic,
            **({"deadline": kwargs["deadline"]} if "deadline" in kwargs else {}),
        )

    monkeypatch.setattr(shared_gate, "_save", delayed_save)
    monkeypatch.setattr(remote, "request", request)
    assert launcher.main(built.argv(tmp_path)) in (1, 2)
    assert delayed
    assert (phase, 0) not in wire


@pytest.mark.parametrize("delay_at", ["start", "input", "connection"])
def test_worker_expiry_before_request_opens_no_network(monkeypatch, delay_at):
    clock, opened = FakeClock(), []
    message = {
        "method": "GET",
        "path": "/v1/projects/fireemu-35fe6/databases/(default)/documents/oracle/"
        + "0123456789abcdef0123456789abcdef/request-bytes-01/probe-u01/items/control",
        "authorization": "Bearer token",
        "project": "fireemu-35fe6",
        "bodyBytes": 0,
        "deadline": clock() + 2.5,
    }

    class Input(io.BytesIO):
        def readline(self, size=-1):
            result = super().readline(size)
            if delay_at == "start":
                clock.advance(3)
            return result

        def read(self, size=-1):
            result = super().read(size)
            if delay_at == "input":
                clock.advance(3)
            return result

    class Connection:
        def __init__(self, *_args, **_kwargs):
            if delay_at == "connection":
                clock.advance(3)

        def request(self, *_args, **_kwargs):
            opened.append(True)
            raise OSError("offline network sentinel")

        def close(self):
            pass

    output = io.BytesIO()
    monkeypatch.setattr(worker.time, "monotonic", clock)
    monkeypatch.setattr(
        worker.sys,
        "stdin",
        SimpleNamespace(buffer=Input(json.dumps(message).encode() + b"\n")),
    )
    monkeypatch.setattr(worker.sys, "stdout", SimpleNamespace(buffer=output))
    monkeypatch.setattr(worker.http.client, "HTTPSConnection", Connection)
    worker.run()
    assert opened == []
    assert (
        b"worker-failure" if delay_at == "start" else b"timeout"
    ) in output.getvalue()


def test_gate_reserves_three_seconds_inside_published_phase_windows(built):  # noqa: F811
    plan = campaign.gate_plan(
        built.execution_plan,
        upload_seconds=60,
        observation_slot_seconds=3,
        recovery_slot_seconds=3,
    )
    assert plan["wallSeconds"] == 1150
    assert plan["recoverySeconds"] == 550
    sums = {
        phase: sum(
            slot["seconds"] + plan["intervalSeconds"]
            for job in plan["jobs"].values()
            for slot in job["schedule"]
            if slot["phase"] == phase
        )
        for phase in ("observation", "recovery")
    }
    management = plan["management"]["phaseSeconds"]
    assert management == {"observation": 53.0, "recovery": 39.75}
    assert sums["observation"] + management["observation"] <= 600
    assert sums["recovery"] + management["recovery"] <= 550


@pytest.mark.parametrize("deadline", [None, True, float("inf"), float("nan")])
def test_bound_production_call_requires_a_finite_absolute_deadline(
    monkeypatch, deadline
):
    binding, sha = campaign.worker_binding()
    monkeypatch.setattr(campaign, "authorize_transport", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        remote,
        "request",
        lambda *args, **kwargs: pytest.fail("invalid deadline reached transport"),
    )
    with pytest.raises(ValueError, match="absolute deadline"):
        campaign.transport_bound(
            {
                "plan": {},
                "phase": "observation",
                "index": 0,
                "operation": {},
                "token": "token",
                "deadline": deadline,
            },
            binding=binding,
            binding_digest=sha,
            capability=object(),
        )


@pytest.mark.parametrize("commit,expected", [(False, 2.5), (True, 60)])
def test_later_caller_deadline_cannot_extend_per_operation_cap(commit, expected):
    plan, operation = plan_and_commit()
    index = 17 if commit else 0
    operation = plan["observation"][index]
    clock, calls = FakeClock(), []

    def exchange(*args):
        calls.append(args[4])
        return FakeResponse(200, {}, b"{}")

    remote._request_impl(
        plan,
        "observation",
        index,
        operation,
        "token",
        exchange=exchange,
        timeout=60,
        deadline=clock() + 600,
        clock=clock,
    )
    assert calls == [expected]
