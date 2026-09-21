"""Offline contract tests for the closed G0 local recovery facade."""

from __future__ import annotations

import json
import hashlib
import os
import subprocess
from pathlib import Path

import pytest
from batch_adapter import Adapter, observer_digest
from batch_contract import candidate
from broad_contract import digest
from shared_gate import _save, create
from shared_production_pair import frozen_g0_manifest

from g0_local_recovery import G0RecoveryGate, _expected_fields, _resources, _freshness_handshake, _owned_argv, execute
from shared_cases import run_scenario


NONCE = "68012694f81df504600f8e67301410c6"
ORIGINS = {"firestore": "http://127.0.0.1:18080", "auth": "http://127.0.0.1:19090"}


def plan():
    value = frozen_g0_manifest(NONCE)
    value["observerSha256"] = observer_digest()
    value["localOrigins"] = ORIGINS
    return value


def _write_valid_launch_artifacts(output: Path, value: dict) -> None:
    output.chmod(0o700)
    binary = b"owned-fireemu-artifact"
    config = b'{"profile":"strict"}\n'
    rules = b"rules_version = '2';\n"
    (output / "fireemu").write_bytes(binary)
    (output / "fireemu.json").write_bytes(config)
    (output / "firestore.rules").write_bytes(rules)
    python_pid = os.getppid()
    child_pid = int(
        subprocess.check_output(["ps", "-ww", "-p", str(python_pid), "-o", "ppid="], text=True).strip()
    )
    parent_pid = int(
        subprocess.check_output(["ps", "-ww", "-p", str(child_pid), "-o", "ppid="], text=True).strip()
    )
    run_info = output.stat()
    receipt = {
        "schema": "fireemu-g0-launch-v1",
        "pid": parent_pid,
        "command": str(output / "fireemu"),
        "args": ["exec"],
        "binarySha256": hashlib.sha256(binary).hexdigest(),
        "sourceCommit": "source-bound",
        "configSha256": hashlib.sha256(config).hexdigest(),
        "rulesSha256": hashlib.sha256(rules).hexdigest(),
        "environmentSha256": "e" * 64,
        "retainedManifestSha256": "m" * 64,
        "artifactProfile": "current-test",
        "runtimeSourceCommit": "source-bound",
        "sourceInputsDigest": "i" * 64,
        "runDirectory": {"path": str(output), "dev": run_info.st_dev, "ino": run_info.st_ino, "mode": run_info.st_mode & 0o777},
        "import": None,
        "exportOnExit": None,
    }
    receipt_bytes = json.dumps(receipt, separators=(",", ":")).encode() + b"\n"
    receipt_path = output / "launch-receipt.json"
    receipt_path.write_bytes(receipt_bytes)
    receipt_path.chmod(0o600)
    (output / "freshness-handshake.json").write_text(
        json.dumps(
            {
                "schema": "fireemu-g0-freshness-v1",
                "parentPid": parent_pid,
                "childPid": child_pid,
                "receiptSha256": hashlib.sha256(receipt_bytes).hexdigest(),
                "programDigest": digest(value),
                "argv": [receipt["command"], *receipt["args"]],
                "binarySha256": receipt["binarySha256"],
                "sourceCommit": receipt["sourceCommit"],
                "configSha256": receipt["configSha256"],
                "rulesSha256": receipt["rulesSha256"],
                "environmentSha256": receipt["environmentSha256"],
                "retainedManifestSha256": receipt["retainedManifestSha256"],
                "artifactProfile": receipt["artifactProfile"],
                "runtimeSourceCommit": receipt["runtimeSourceCommit"],
                "sourceInputsDigest": receipt["sourceInputsDigest"],
                "runDirectory": receipt["runDirectory"],
                "import": None,
                "exportOnExit": None,
                "origins": ORIGINS,
                "pythonArgv": _owned_argv(python_pid),
            }
        )
    )


def test_frozen_projection_derives_exact_four_resources_without_owner_marker():
    value = plan()
    resources = _resources(value)
    fields = _expected_fields(value)
    assert len(resources) == 4
    assert set(fields) == resources
    assert all("_owner" not in item for item in fields.values())


def test_frozen_projection_preserves_conditional_setup_values_over_later_batch_mutations():
    fields = _expected_fields(plan())
    partial = plan()["jobs"]["partial"]["resources"]
    guard = plan()["jobs"]["transaction-field"]["resources"][0]
    assert fields[partial[0]]["a"]["integerValue"] == "1"
    assert fields[partial[1]]["a"]["integerValue"] == "7"
    assert fields[partial[2]]["a"]["integerValue"] == "9"
    assert fields[guard]["a"]["integerValue"] == "3"


def test_real_gate_facade_constructs_from_frozen_plan(tmp_path: Path):
    value = plan()
    gate_path = tmp_path / "gate"
    create(gate_path, value)
    gate = G0RecoveryGate(gate_path, "partial")
    gate.claim()
    assert gate.snapshot()["plan"]["localOrigins"] == ORIGINS


@pytest.mark.parametrize("mutation", ["origin", "nonce", "fields", "updateTime"])
def test_cleanup_ownership_refuses_mutated_capture(tmp_path: Path, mutation: str):
    value = plan()
    gate_path = tmp_path / "gate"
    create(gate_path, value)
    gate = G0RecoveryGate(gate_path, "partial")
    resource = value["jobs"]["partial"]["resources"][0]
    expected = _expected_fields(value)[resource]
    capture = {
        "status": 200,
        "name": resource,
        "fieldsDigest": digest(expected),
        "updateTime": "2026-01-02T03:04:05.000001Z",
    }
    operation = {
        "method": "DELETE",
        "path": "/v1/" + resource + "?currentDocument.updateTime=" + capture["updateTime"],
    }
    if mutation == "origin":
        bad = plan()
        bad["localOrigins"] = {**ORIGINS, "auth": "http://example.invalid:19091"}
        bad_path = tmp_path / "bad-origin"
        create(bad_path, bad)
        with pytest.raises(ValueError):
            G0RecoveryGate(bad_path, "partial")
        return
    elif mutation == "nonce":
        bad = plan()
        bad["nonce"] = "0" * 32
        bad_path = tmp_path / "bad-nonce"
        create(bad_path, bad)
        with pytest.raises(ValueError):
            G0RecoveryGate(bad_path, "partial")
        return
    elif mutation == "fields":
        capture["fieldsDigest"] = "f" * 64
    else:
        capture["updateTime"] = "not-a-version"
    with gate.locked() as state:
        state["jobs"]["partial"]["captures"]["0"] = capture
    with pytest.raises(ValueError, match="g0-cleanup-ownership-refused"):
        gate._validate_cleanup_ownership(operation, True, resource, 0, gate.snapshot()["jobs"]["partial"])


def test_freshness_handshake_rejects_missing_or_imported_receipt(tmp_path: Path):
    value = plan()
    (tmp_path / "program.json").write_text(json.dumps(value))
    with pytest.raises(ValueError, match="g0-freshness-handshake-missing"):
        _freshness_handshake(tmp_path, ORIGINS)
    (tmp_path / "freshness-handshake.json").write_text(
        json.dumps(
            {
                "schema": "fireemu-g0-freshness-v1",
                "parentPid": 1,
                "childPid": os.getppid(),
                "receiptSha256": "a" * 64,
                "programDigest": digest(value),
                "argv": ["fireemu", "exec"],
                "import": "unexpected",
                "exportOnExit": None,
                "origins": ORIGINS,
            }
        )
    )
    with pytest.raises(ValueError, match="g0-freshness-handshake-invalid"):
        _freshness_handshake(tmp_path, ORIGINS)


def test_freshness_handshake_rejects_mutated_program_and_child_identity(tmp_path: Path):
    value = plan()
    (tmp_path / "program.json").write_text(json.dumps(value))
    _write_valid_launch_artifacts(tmp_path, value)
    _freshness_handshake(tmp_path, ORIGINS)
    changed = {**value, "nonce": "0" * 32}
    (tmp_path / "program.json").write_text(json.dumps(changed))
    with pytest.raises(ValueError, match="g0-freshness-handshake-invalid"):
        _freshness_handshake(tmp_path, ORIGINS)
    (tmp_path / "program.json").write_text(json.dumps(value))
    handshake = json.loads((tmp_path / "freshness-handshake.json").read_text())
    handshake["childPid"] = os.getpid()
    (tmp_path / "freshness-handshake.json").write_text(json.dumps(handshake))
    with pytest.raises(ValueError, match="g0-launch-chain-invalid"):
        _freshness_handshake(tmp_path, ORIGINS)


@pytest.mark.parametrize("mutation", ["path", "inode", "mode", "import", "argv", "pid", "source", "hash"])
def test_freshness_handshake_rejects_tampered_owned_receipt_fields(tmp_path: Path, mutation: str):
    value = plan()
    (tmp_path / "program.json").write_text(json.dumps(value))
    _write_valid_launch_artifacts(tmp_path, value)
    receipt_path = tmp_path / "launch-receipt.json"
    receipt = json.loads(receipt_path.read_text())
    if mutation == "path":
        receipt["runDirectory"]["path"] = str(tmp_path / "elsewhere")
    elif mutation == "inode":
        receipt["runDirectory"]["ino"] += 1
    elif mutation == "mode":
        receipt_path.chmod(0o644)
    elif mutation == "import":
        receipt["import"] = "substituted"
    elif mutation == "argv":
        receipt["args"] = ["exec", "--import"]
    elif mutation == "pid":
        receipt["pid"] += 1
    elif mutation == "source":
        receipt["sourceCommit"] = "other-source"
    else:
        receipt["binarySha256"] = "0" * 64
    if mutation != "mode":
        receipt_path.write_text(json.dumps(receipt) + "\n")
    elif receipt_path.is_symlink():
        raise AssertionError("test setup unexpectedly created a symlink")
    with pytest.raises(ValueError):
        _freshness_handshake(tmp_path, ORIGINS)


def test_freshness_handshake_rejects_receipt_symlink_before_read(tmp_path: Path):
    value = plan()
    (tmp_path / "program.json").write_text(json.dumps(value))
    _write_valid_launch_artifacts(tmp_path, value)
    receipt_path = tmp_path / "launch-receipt.json"
    target = tmp_path / "receipt-copy.json"
    target.write_bytes(receipt_path.read_bytes())
    receipt_path.unlink()
    receipt_path.symlink_to(target)
    with pytest.raises(ValueError, match="g0-launch-file-invalid"):
        _freshness_handshake(tmp_path, ORIGINS)


def test_execute_refuses_missing_handshake_before_starting_workers(tmp_path: Path):
    value = plan()
    (tmp_path / "program.json").write_text(json.dumps(value))
    with pytest.raises(ValueError, match="g0-freshness-handshake-missing"):
        execute(tmp_path, ORIGINS)


class FixtureAdapter(Adapter):
    """Real Adapter/Gate dispatch with a bounded local response fixture."""

    def __init__(self, manifest, nonce, output, expected, mode=None):
        super().__init__(manifest, nonce, output, local_origins=ORIGINS)
        self.expected = expected
        self.mode = mode
        self.reads = {}
        self.calls = []
        self.sent = 0
        self.sent_operations = []
        self.wrong_resource = None

    def request(self, service, path, body=None, *, method="POST", privileged=False, form=False):
        operation = {
            "service": service,
            "path": path,
            "body": body,
            "method": method,
            "privileged": privileged,
            "form": form,
        }
        self.calls.append(operation)
        return self.shared_gate.adapter_request(self, operation, lambda: self.reply(operation))

    def reply(self, operation):
        self.sent += 1
        self.sent_operations.append(operation)
        resource = operation["path"].split("?", 1)[0].removeprefix("/v1/")
        if not self.budget.recovery:
            if operation["method"] == "GET":
                count = self.reads.get(resource, 0)
                self.reads[resource] = count + 1
                if count == 0:
                    return 404, {"error": {"code": 404, "status": "NOT_FOUND"}}
                return 200, {"name": resource, "fields": self.expected[resource], "updateTime": "2026-01-02T03:04:05.000001Z"}
            if operation["method"] == "PATCH":
                name = resource
                return 200, {"name": name, "fields": operation["body"]["fields"], "updateTime": "2026-01-02T03:04:05.000001Z"}
            writes = operation["body"]["writes"]
            return 200, {
                "status": [{"code": 0} for _ in writes],
                "writeResults": [{"updateTime": "2026-01-02T03:04:05.000001Z"} for _ in writes],
            }
        if operation["method"] == "GET":
            count = self.reads.get("recovery:" + resource, 0)
            self.reads["recovery:" + resource] = count + 1
            if count == 0:
                if self.mode == "wrong-fields" and resource == next(iter(self.expected)):
                    self.wrong_resource = resource
                    return 200, {"name": resource, "fields": {"a": {"integerValue": "999"}}, "updateTime": "2026-01-02T03:04:05.000001Z"}
                return 200, {"name": resource, "fields": self.expected[resource], "updateTime": "2026-01-02T03:04:05.000001Z"}
            if self.mode == "final-present" and resource == next(iter(self.expected)):
                return 200, {"name": resource, "fields": self.expected[resource], "updateTime": "2026-01-02T03:04:05.000001Z"}
            return 404, {"error": {"code": 404, "status": "NOT_FOUND"}}
        if self.mode == "version-409" and operation["method"] == "DELETE":
            return 409, {"error": {"code": 409, "status": "ABORTED"}}
        return 200, {}


def test_real_gate_adapter_path_consumes_all_twelve_recovery_slots(tmp_path: Path):
    value = plan()
    gate_path = tmp_path / "gate"
    create(gate_path, value)
    expected = _expected_fields(value)
    for key in value["jobs"]:
        gate = G0RecoveryGate(gate_path, key)
        gate.claim()
        adapter = FixtureAdapter(candidate(), value["nonce"], tmp_path / key, expected)
        adapter.shared_gate = gate
        result = run_scenario(adapter, value, key)
        assert len(result["rows"]) == len(value["jobs"][key]["observation"])
        assert len(result["cleanup"]) == len(value["jobs"][key]["recovery"])
        assert result["cleanupComplete"] is True, result
    state = G0RecoveryGate(gate_path, "partial").snapshot()
    assert state["recovery"] == 12
    assert not any(state["jobs"][key]["creationProofs"] for key in value["jobs"])


def test_finish_refuses_unknown_recovery_wire_outcome_after_full_dispatch(tmp_path: Path):
    value = plan()
    gate_path = tmp_path / "gate"
    create(gate_path, value)
    expected = _expected_fields(value)
    for key in value["jobs"]:
        gate = G0RecoveryGate(gate_path, key)
        gate.claim()
        adapter = FixtureAdapter(candidate(), value["nonce"], tmp_path / key, expected)
        adapter.shared_gate = gate
        run_scenario(adapter, value, key)
    with G0RecoveryGate(gate_path, "partial").locked() as state:
        state["jobs"]["partial"]["complete"] = False
        recovery_event = next(event for event in reversed(state["events"]) if event.get("phase") == "recovery")
        recovery_event["creationOutcome"] = "unknown"
        _save(gate_path, state)
    with pytest.raises(ValueError, match="g0 cleanup incomplete"):
        G0RecoveryGate(gate_path, "partial").finish()


@pytest.mark.parametrize("mode", ["wrong-fields", "version-409", "final-present"])
def test_recovery_refuses_nonterminal_dispatch_and_never_reports_cleanup_complete(tmp_path: Path, mode: str):
    value = plan()
    gate_path = tmp_path / "gate"
    create(gate_path, value)
    expected = _expected_fields(value)
    gate = G0RecoveryGate(gate_path, "partial")
    gate.claim()
    adapter = FixtureAdapter(candidate(), value["nonce"], tmp_path / "partial", expected, mode=mode)
    adapter.shared_gate = gate
    result = run_scenario(adapter, value, "partial")
    assert result["cleanupComplete"] is False
    assert gate.snapshot()["jobs"]["partial"]["complete"] is False
    if mode == "wrong-fields":
        resource = adapter.wrong_resource
        assert resource is not None
        assert not any(
            call["method"] == "DELETE" and call["path"].startswith("/v1/" + resource)
            for call in adapter.sent_operations
        )


def test_real_dispatch_refuses_foreign_resource_without_transport_call(tmp_path: Path):
    value = plan()
    gate_path = tmp_path / "gate"
    create(gate_path, value)
    gate = G0RecoveryGate(gate_path, "partial")
    gate.claim()
    adapter = FixtureAdapter(candidate(), value["nonce"], tmp_path / "partial", _expected_fields(value))
    adapter.shared_gate = gate
    operation = {
        "service": "firestore",
        "path": "/v1/projects/fireemu/databases/(default)/documents/foreign/doc",
        "method": "GET",
        "body": None,
        "privileged": True,
        "form": False,
    }
    with pytest.raises(ValueError):
        adapter.request(**operation)
    assert adapter.calls == [operation]
    assert adapter.sent == 0
    assert gate.snapshot()["events"] == []
