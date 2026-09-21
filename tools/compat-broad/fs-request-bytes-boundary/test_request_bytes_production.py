"""Offline O8 integration: real capabilities, Gate journals and shared Ledger."""

import base64
import copy
import hashlib
import json
import shutil
import socket
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import request_bytes_admission as admission
import request_bytes_collector as collector
import request_bytes_descriptor as campaign
import request_bytes_o8 as launcher
import request_bytes_preflight as preflight
import request_bytes_production as production
import request_bytes_remote_transport as remote
import reservations
import shared_gate
from broad_contract import digest
from test_request_bytes_admission import (
    AUTH_BODY,
    DATABASE_BODY,
    PROJECT_BODY,
    Admission,
)


class Clock:
    def __init__(self):
        self.now = 1000.0

    def monotonic(self):
        return self.now

    def time(self):
        return __import__("time").time()

    def sleep(self, seconds):
        self.now += seconds


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    monkeypatch.setattr(shared_gate, "time", Clock())
    monkeypatch.setattr(collector, "time", shared_gate.time)
    monkeypatch.setattr(preflight, "time", shared_gate.time)

    def management_fixture(slot, token, **_kwargs):
        assert token == "offline-fixture-token"
        body = {
            "project": PROJECT_BODY,
            "database": DATABASE_BODY,
            "auth": AUTH_BODY,
        }.get(slot)
        if slot == "oauth-tokeninfo":
            body = {
                "issued_to": "offline-client",
                "user_id": "offline-subject",
                "scope": preflight.SCOPE,
                "expires_in": 3600,
            }
        return {
            "status": 200,
            "complete": True,
            "workerReaped": True,
            "bodyKind": "json",
            "body": body,
        }

    monkeypatch.setattr(preflight, "management_transport", management_fixture)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("network forbidden in O8 regression")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)


@pytest.fixture
def built(tmp_path):
    fixture = Admission(tmp_path)
    shutil.rmtree(fixture.ledger)
    reservations.Ledger.create(fixture.ledger)
    return fixture


def wire_fixture(monkeypatch, *, fault=None, over_status=400):
    calls, live = [], {}
    version = "2026-01-01T00:00:00.123456789Z"

    def request(plan, phase, index, operation, token, **_kwargs):
        assert token == "offline-fixture-token"
        remote._operation_for_slot(plan, phase, index, operation)
        calls.append((phase, index, copy.deepcopy(operation)))
        kind, resource = operation["kind"], operation.get("resource")
        if fault == "preflight" and len(calls) == 1:
            return {"complete": False, "failure": "offline-preflight-failure"}
        if kind == "conditional-create-commit":
            if fault == "commit":
                return {"complete": False, "failure": "offline-lost-response"}
            if operation["probe"] == "over":
                status = over_status
                body = {"error": {"code": status, "status": "INVALID_ARGUMENT"}}
            else:
                writes = operation["body"]["writes"]
                for write in writes:
                    live[write["update"]["name"]] = write["update"]["fields"]
                status, body = (
                    200,
                    {"writeResults": [{"updateTime": version} for _ in writes]},
                )
        elif kind == "cleanup-version-bound-delete":
            assert resource in live
            assert "versionFrom" not in operation
            assert "?currentDocument.updateTime=" in operation["path"]
            del live[resource]
            status, body = 200, {}
        elif resource in live:
            status, body = (
                200,
                {"name": resource, "fields": live[resource], "updateTime": version},
            )
        else:
            status, body = 404, {"error": {"code": 404, "status": "NOT_FOUND"}}
        raw = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode()
        if fault == "forged-raw" and kind == "conditional-create-commit":
            raw = b"{}"
        return {
            "complete": True,
            "failure": None,
            "status": status,
            "body": body,
            "rawBodyBase64": base64.b64encode(raw).decode(),
            "bodyBytes": len(raw),
        }

    monkeypatch.setattr(remote, "request", request)
    return calls, live


def test_all_three_probe_jobs_finish_before_real_ledger_release(
    built, tmp_path, monkeypatch
):
    calls, live = wire_fixture(monkeypatch)
    read = launcher._read_handoff

    def read_after_reservation(args):
        state = reservations.Ledger(built.ledger).snapshot()
        assert len(state["reservations"]) == 1
        row = next(iter(state["reservations"].values()))
        assert row["state"] == "held"
        snapshot = shared_gate.Gate(
            tmp_path / "output/gate", row["claim"]["gateJob"]
        ).snapshot()
        assert all(job["pid"] is not None for job in snapshot["jobs"].values())
        return read(args)

    monkeypatch.setattr(launcher, "_read_handoff", read_after_reservation)
    result = launcher.execute(launcher.build_parser().parse_args(built.argv(tmp_path)))
    assert result["reservationReleased"] is True
    output = tmp_path / "output"
    receipt = json.loads((output / "receipt.json").read_bytes())
    release = json.loads((output / "release.json").read_bytes())
    gate = shared_gate.Gate(
        output / "gate", campaign.gate_job_name("probe-u01")
    ).snapshot()
    assert len(calls) == 241
    assert [index for phase, index, op in calls if op["method"] == "POST"] == [
        17,
        52,
        87,
    ]
    assert len([op for _, _, op in calls if op["method"] == "DELETE"]) == 34
    assert not live
    assert all(
        job["complete"] and job["scheduleDone"] == 86 for job in gate["jobs"].values()
    )
    assert len(gate["skips"]) == 17
    for name in gate["jobs"]:
        shared_gate.validate_absence_proofs(gate, name)
    assert receipt["releaseEligible"] is True
    assert receipt["productionExecuted"] is True
    assert len(receipt["metadata"]) == len(calls)
    assert receipt["routeDigest"] == digest(receipt["metadata"])
    assert receipt["gateDigest"] == digest(gate)
    assert release["receiptDigest"] == digest(receipt)
    final = reservations.Ledger(built.ledger).snapshot()["reservations"][
        receipt["ticket"]["reservation"]
    ]
    assert final == release["reservationFinal"]
    assert final["state"] == "released"
    assert final["finalGateDigest"] == receipt["gateDigest"]
    assert final["claimDigest"] == receipt["claimDigest"]
    for name, expected in receipt["evidenceFiles"].items():
        assert hashlib.sha256((output / name).read_bytes()).hexdigest() == expected
    assert "offline-fixture-token" not in (output / "receipt.json").read_text()


@pytest.mark.parametrize("refusal", ["output", "reserve"])
def test_refusable_checks_precede_credential_reader(
    built, tmp_path, monkeypatch, refusal
):
    calls = []
    monkeypatch.setattr(
        launcher, "_read_handoff", lambda _args: calls.append("credential")
    )
    if refusal == "output":
        (tmp_path / "output").mkdir()
    else:
        binding, sha = campaign.worker_binding()
        cap = admission.issue_production_capability(
            **built.bindings(), binding=binding, binding_digest=sha
        )
        plan = admission.gate_plan_for(built.inputs, built.permission)
        claim = admission.reservation_claim(
            built.inputs, gate_path=tmp_path / "prior-gate", gate_plan=plan
        )
        reservations.Ledger(built.ledger).reserve(
            production._envelope(built.permission, claim),
            claim,
            plan,
            generation=admission.abort_generation(built.inputs),
        )
        admission.revoke_production_capability(cap)
        # Simulate the competing reservation landing after the advisory read.
        monkeypatch.setattr(admission, "validate_fresh_admission", lambda *_: None)
    assert launcher.main(built.argv(tmp_path)) == 2
    assert calls == []


@pytest.mark.parametrize("fault", ["preflight", "commit", "forged-raw"])
def test_stopped_runs_persist_evidence_and_retain_reservation(
    built, tmp_path, monkeypatch, fault
):
    calls, _live = wire_fixture(monkeypatch, fault=fault)
    assert launcher.main(built.argv(tmp_path)) == (2 if fault == "preflight" else 1)
    receipt = json.loads((tmp_path / "output/receipt.json").read_bytes())
    assert receipt["failure"]
    assert receipt["releaseEligible"] is False
    assert receipt["productionExecuted"] is True
    assert receipt["metadata"]
    assert receipt["stopPoint"] == (
        "probe-u01-preflight" if fault == "preflight" else "probe-u01-commit-deadline"
    )
    row = reservations.Ledger(built.ledger).snapshot()["reservations"][
        receipt["ticket"]["reservation"]
    ]
    assert row["state"] == "held"
    assert all(op["probe"] == "under" for _, _, op in calls)
    assert not any(op["method"] == "DELETE" for _, _, op in calls)
    gate = shared_gate.Gate(
        tmp_path / "output/gate", row["claim"]["gateJob"]
    ).snapshot()
    if fault != "preflight":
        assert shared_gate.unconfirmed_creates(gate, row["claim"]["gateJob"])


def test_auth_baseline_drift_stops_the_gate_before_any_data(
    built, tmp_path, monkeypatch
):
    """A drifted Auth config is recorded in the Gate, not only in memory."""
    calls, _live = wire_fixture(monkeypatch)
    real = preflight.management_transport

    def drifted(slot, token, **kwargs):
        response = real(slot, token, **kwargs)
        if slot == "auth":
            response = {**response, "body": {**AUTH_BODY, "mfa": {"state": "ENABLED"}}}
        return response

    monkeypatch.setattr(preflight, "management_transport", drifted)
    assert launcher.main(built.argv(tmp_path)) != 0
    assert calls == []
    receipt = json.loads((tmp_path / "output/receipt.json").read_bytes())
    assert receipt["preflightComplete"] is False
    assert receipt["releaseEligible"] is False
    rows = receipt["managementEvidence"]
    assert [row["id"] for row in rows] == [
        "observation:oauth-tokeninfo",
        "observation:project",
        "observation:database",
        "observation:auth",
    ]
    assert rows[-1]["response"]["complete"] is False
    assert rows[-1]["response"]["body"]["baselineVerified"] is False
    # The raw Auth config never reaches the receipt, drifted or not.
    assert "ENABLED" not in json.dumps(receipt)
    assert "DISABLED" not in json.dumps(receipt)
    row = reservations.Ledger(built.ledger).snapshot()["reservations"][
        receipt["ticket"]["reservation"]
    ]
    assert row["state"] == "held"
    gate = shared_gate.Gate(
        tmp_path / "output/gate", row["claim"]["gateJob"]
    ).snapshot()
    assert gate["stopped"] is True
    assert gate["managementEvents"][-1]["completed"] is False
    assert gate["events"] == []


def test_invalid_private_handoff_publishes_held_no_data_receipt(built, tmp_path):
    built.handoff_path.write_text("{}")
    assert launcher.main(built.argv(tmp_path)) == 2
    receipt = json.loads((tmp_path / "output/receipt.json").read_bytes())
    assert receipt["productionExecuted"] is False
    assert receipt["collection"] is None
    assert receipt["metadata"] == []
    assert receipt["stopPoint"] == "schedule-not-started"
    row = reservations.Ledger(built.ledger).snapshot()["reservations"][
        receipt["ticket"]["reservation"]
    ]
    assert row["state"] == "held"
    assert not (tmp_path / "output/abort.json").exists()


def test_cli_returns_zero_only_after_complete_release(built, tmp_path, monkeypatch):
    wire_fixture(monkeypatch)
    assert launcher.main(built.argv(tmp_path)) == 0
    release = json.loads((tmp_path / "output/release.json").read_bytes())
    assert release["reservationFinal"]["state"] == "released"


def test_gate_validation_failure_never_reads_private_handoff(
    built, tmp_path, monkeypatch
):
    reads = []
    monkeypatch.setattr(launcher, "_read_handoff", lambda _args: reads.append(True))

    def refuse(*_args):
        raise ValueError("offline Gate admission failure")

    monkeypatch.setattr(shared_gate, "create", refuse)
    assert launcher.main(built.argv(tmp_path)) == 2
    assert reads == []
    receipt = json.loads((tmp_path / "output/receipt.json").read_bytes())
    assert receipt["productionExecuted"] is False
    assert receipt["failure"] == "ValueError"
    assert (
        reservations.Ledger(built.ledger).snapshot()["reservations"][
            receipt["ticket"]["reservation"]
        ]["state"]
        == "held"
    )


def test_source_path_is_validated_before_private_handoff(built, tmp_path, monkeypatch):
    reads = []
    monkeypatch.setattr(launcher, "_read_handoff", lambda _args: reads.append(True))
    (built.source / campaign.COLLECTOR_ENTRY).write_text("changed offline source")
    assert launcher.main(built.argv(tmp_path)) == 2
    assert reads == []
    assert not (tmp_path / "output").exists()


def test_typed_413_remains_held_under_existing_shared_gate_contract(
    built, tmp_path, monkeypatch
):
    wire_fixture(monkeypatch, over_status=413)
    assert launcher.main(built.argv(tmp_path)) == 1
    receipt = json.loads((tmp_path / "output/receipt.json").read_bytes())
    row = reservations.Ledger(built.ledger).snapshot()["reservations"][
        receipt["ticket"]["reservation"]
    ]
    assert row["state"] == "held"
    assert receipt["stopPoint"] == "probe-o01-commit-deadline"


def test_receipt_publication_failure_never_reports_no_data_or_releases(
    built, tmp_path, monkeypatch
):
    calls, _live = wire_fixture(monkeypatch)
    write = production._write_receipt

    def fail_receipt(path, value):
        if path.name == "receipt.json":
            raise OSError("offline publication failure")
        return write(path, value)

    monkeypatch.setattr(production, "_write_receipt", fail_receipt)
    assert launcher.main(built.argv(tmp_path)) == 1
    assert any(operation["method"] == "POST" for _, _, operation in calls)
    rows = reservations.Ledger(built.ledger).snapshot()["reservations"]
    assert len(rows) == 1
    assert next(iter(rows.values()))["state"] == "held"
    assert not (tmp_path / "output/release.json").exists()


@pytest.mark.parametrize(
    "target",
    [
        "receipt",
        "release",
        "gate-snapshot",
        "response",
        "rehashed-response",
        "rehashed-request",
    ],
)
def test_saved_verifier_rejects_tampered_evidence(built, tmp_path, monkeypatch, target):
    wire_fixture(monkeypatch)
    assert launcher.main(built.argv(tmp_path)) == 0
    output = tmp_path / "output"
    production.verify_saved(
        output,
        expected_inputs_digest=built.inputs["inputsDigest"],
        ledger_root=built.ledger,
    )
    if target in {"response", "rehashed-response", "rehashed-request"}:
        path = output / (
            "collection/request-under.body"
            if target == "rehashed-request"
            else "collection/response-000.body"
        )
        path.write_bytes(b"{}")
        if target.startswith("rehashed-"):
            receipt_path, release_path = (
                output / "receipt.json",
                output / "release.json",
            )
            receipt = json.loads(receipt_path.read_bytes())
            receipt["evidenceFiles"][str(path.relative_to(output))] = hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
            receipt_path.write_text(json.dumps(receipt))
            release = json.loads(release_path.read_bytes())
            release["receiptDigest"] = digest(receipt)
            release_path.write_text(json.dumps(release))
    else:
        path = output / f"{target}.json"
        value = json.loads(path.read_bytes())
        value["tampered"] = True
        path.write_text(json.dumps(value))
    with pytest.raises(ValueError):
        production.verify_saved(
            output,
            expected_inputs_digest=built.inputs["inputsDigest"],
            ledger_root=built.ledger,
        )


def test_saved_verifier_requires_independent_inputs_digest(tmp_path):
    with pytest.raises(ValueError):
        production.verify_saved(
            tmp_path, expected_inputs_digest="", ledger_root=tmp_path / "ledger"
        )


@pytest.mark.parametrize("damage", ["plan", "permission"])
def test_direct_execution_rechecks_frozen_inputs_before_consumption(
    built, tmp_path, damage
):
    binding, sha = campaign.worker_binding()
    cap = admission.issue_production_capability(
        **built.bindings(), binding=binding, binding_digest=sha
    )
    inputs, permission = copy.deepcopy(built.inputs), copy.deepcopy(built.permission)
    if damage == "plan":
        inputs["plan"] = campaign.plan_compiler("c" * 32)
    else:
        permission["expiresAt"] += 10
    reads = []

    def forbidden_reader():
        reads.append(True)
        raise ValueError("offline credential reader must remain unreachable")

    try:
        with pytest.raises(ValueError):
            production.execute(
                capability=cap,
                inputs=inputs,
                permission=permission,
                credential_reader=forbidden_reader,
                ledger_root=built.ledger,
                output=tmp_path / "output",
            )
        assert reads == []
        assert cap.consumed is False
        assert reservations.Ledger(built.ledger).snapshot()["reservations"] == {}
        assert not (tmp_path / "output").exists()
    finally:
        admission.revoke_production_capability(cap)


@pytest.mark.parametrize("failure_kind", ["row", "sidecar"])
def test_recording_failure_after_commit_still_cleans_owned_documents(
    built, tmp_path, monkeypatch, failure_kind
):
    import request_bytes_collector as collector

    calls, live = wire_fixture(monkeypatch)
    publish, open_file = collector._publish, collector.os.open
    failed = False

    def fail_row(directory, name, value, *, bounded=True):
        nonlocal failed
        if failure_kind == "row" and name == "row-017.json" and not failed:
            failed = True
            raise OSError("offline row persistence failure")
        return publish(directory, name, value, bounded=bounded)

    def fail_sidecar(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal failed
        if failure_kind == "sidecar" and path == "response-017.body" and not failed:
            failed = True
            raise OSError("offline body persistence failure")
        return open_file(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(collector, "_publish", fail_row)
    monkeypatch.setattr(collector.os, "open", fail_sidecar)
    assert launcher.main(built.argv(tmp_path)) == 1
    assert failed
    assert not live
    assert sum(operation["method"] == "DELETE" for _, _, operation in calls) == 17
    assert all(operation["probe"] == "under" for _, _, operation in calls)
    receipt = json.loads((tmp_path / "output/receipt.json").read_bytes())
    assert receipt["releaseEligible"] is False
    row = reservations.Ledger(built.ledger).snapshot()["reservations"][
        receipt["ticket"]["reservation"]
    ]
    assert row["state"] == "held"
    snapshot = shared_gate.Gate(
        tmp_path / "output/gate", row["claim"]["gateJob"]
    ).snapshot()
    assert snapshot["jobs"][row["claim"]["gateJob"]]["recovery"] == 51
    shared_gate.validate_absence_proofs(snapshot, row["claim"]["gateJob"])


def test_release_publication_failure_reconciles_without_any_further_wire(
    built, tmp_path, monkeypatch
):
    calls, _live = wire_fixture(monkeypatch)
    write = production._write_receipt

    def fail_release(path, value):
        if path.name == "release.json":
            raise OSError("offline release publication failure")
        return write(path, value)

    monkeypatch.setattr(production, "_write_receipt", fail_release)
    assert launcher.main(built.argv(tmp_path)) == 1
    output = tmp_path / "output"
    receipt_bytes = (output / "receipt.json").read_bytes()
    receipt = json.loads(receipt_bytes)
    row = reservations.Ledger(built.ledger).snapshot()["reservations"][
        receipt["ticket"]["reservation"]
    ]
    assert row["state"] == "released"
    assert not (output / "release.json").exists()
    with pytest.raises((ValueError, OSError)):
        production.verify_saved(
            output,
            expected_inputs_digest=built.inputs["inputsDigest"],
            ledger_root=built.ledger,
        )
    before = len(calls)
    monkeypatch.setattr(production, "_write_receipt", write)
    release = production.recover_release(
        output,
        expected_inputs_digest=built.inputs["inputsDigest"],
        ledger_root=built.ledger,
    )
    assert release["reservationFinal"] == row
    assert len(calls) == before
    assert (output / "receipt.json").read_bytes() == receipt_bytes
    assert (
        production.verify_saved(
            output,
            expected_inputs_digest=built.inputs["inputsDigest"],
            ledger_root=built.ledger,
        )
        == receipt
    )
    with pytest.raises(ValueError):
        production.recover_release(
            output,
            expected_inputs_digest=built.inputs["inputsDigest"],
            ledger_root=built.ledger,
        )


@pytest.mark.parametrize("damage", ["held", "gate", "receipt", "ticket", "symlink"])
def test_release_reconciliation_refuses_unproven_or_occupied_evidence(
    built, tmp_path, monkeypatch, damage
):
    wire_fixture(monkeypatch, fault="preflight" if damage == "held" else None)
    write = production._write_receipt

    def fail_release(path, value):
        if path.name == "release.json":
            raise OSError("offline release publication failure")
        return write(path, value)

    monkeypatch.setattr(production, "_write_receipt", fail_release)
    assert launcher.main(built.argv(tmp_path)) == (2 if damage == "held" else 1)
    monkeypatch.setattr(production, "_write_receipt", write)
    output = tmp_path / "output"
    if damage == "gate":
        path = output / "gate-snapshot.json"
        value = json.loads(path.read_bytes())
        value["total"] += 1
        path.write_text(json.dumps(value))
    elif damage == "receipt":
        path = output / "receipt.json"
        value = json.loads(path.read_bytes())
        value["inputsDigest"] = "0" * 64
        path.write_text(json.dumps(value))
    elif damage == "ticket":
        path = output / "receipt.json"
        value = json.loads(path.read_bytes())
        value["ticket"]["claimDigest"] = "0" * 64
        path.write_text(json.dumps(value))
    elif damage == "symlink":
        (output / "release.json").symlink_to(output / "receipt.json")
    with pytest.raises(ValueError):
        production.recover_release(
            output,
            expected_inputs_digest=built.inputs["inputsDigest"],
            ledger_root=built.ledger,
        )
    assert (
        not (output / "release.json").exists() or (output / "release.json").is_symlink()
    )


def test_partial_release_write_remains_unpublished_and_can_be_reconciled(
    built, tmp_path, monkeypatch
):
    from contextlib import contextmanager
    from types import SimpleNamespace

    calls, _live = wire_fixture(monkeypatch)
    fdopen, finish = production.os.fdopen, reservations.Ledger.finish
    armed = False
    finishes = 0

    def finish_and_arm(ledger, ticket):
        nonlocal armed, finishes
        finish(ledger, ticket)
        finishes += 1
        armed = True

    @contextmanager
    def partial_fdopen(fd, *args, **kwargs):
        with fdopen(fd, *args, **kwargs) as stream:
            if not armed:
                yield stream
                return

            def partial_write(data):
                stream.write(data[:11])
                stream.flush()
                raise OSError("offline partial release write")

            yield SimpleNamespace(
                write=partial_write, flush=stream.flush, fileno=stream.fileno
            )

    monkeypatch.setattr(reservations.Ledger, "finish", finish_and_arm)
    monkeypatch.setattr(production.os, "fdopen", partial_fdopen)
    assert launcher.main(built.argv(tmp_path)) == 1
    output = tmp_path / "output"
    assert not (output / "release.json").exists()
    assert not list(output.glob(".release.json.*"))
    before = len(calls)
    monkeypatch.setattr(production.os, "fdopen", fdopen)
    production.recover_release(
        output,
        expected_inputs_digest=built.inputs["inputsDigest"],
        ledger_root=built.ledger,
    )
    production.verify_saved(
        output,
        expected_inputs_digest=built.inputs["inputsDigest"],
        ledger_root=built.ledger,
    )
    assert len(calls) == before
    assert finishes == 1


@pytest.mark.parametrize("symlink", [False, True])
def test_evidence_publication_never_clobbers_existing_files_or_symlinks(
    tmp_path, symlink
):
    original = tmp_path / "original.json"
    original.write_bytes(b"immutable original")
    target = tmp_path / "release.json"
    if symlink:
        target.symlink_to(original)
    else:
        target.write_bytes(b"immutable original")
    with pytest.raises(FileExistsError):
        production._write_receipt(target, {"replacement": True})
    assert target.read_bytes() == b"immutable original"
    assert original.read_bytes() == b"immutable original"
    assert not list(tmp_path.glob(".release.json.*"))
