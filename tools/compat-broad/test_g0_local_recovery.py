"""Offline contract tests for the closed G0 local recovery facade."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from batch_adapter import Adapter, observer_digest
from batch_contract import candidate
from broad_contract import digest
from shared_gate import create
from shared_production_pair import frozen_g0_manifest

from g0_local_recovery import G0RecoveryGate, _expected_fields, _resources, _freshness_handshake
from shared_cases import run_scenario


NONCE = "68012694f81df504600f8e67301410c6"
ORIGINS = {"firestore": "http://127.0.0.1:18080", "auth": "http://127.0.0.1:19090"}


def plan():
    value = frozen_g0_manifest(NONCE)
    value["observerSha256"] = observer_digest()
    value["localOrigins"] = ORIGINS
    return value


def test_frozen_projection_derives_exact_four_resources_without_owner_marker():
    value = plan()
    resources = _resources(value)
    fields = _expected_fields(value)
    assert len(resources) == 4
    assert set(fields) == resources
    assert all("_owner" not in item for item in fields.values())


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
    with pytest.raises(ValueError, match="g0-freshness-handshake-missing"):
        _freshness_handshake(tmp_path, ORIGINS)
    (tmp_path / "freshness-handshake.json").write_text(
        json.dumps(
            {
                "schema": "fireemu-g0-freshness-v1",
                "parentPid": 1,
                "receiptSha256": "a" * 64,
                "import": "unexpected",
                "exportOnExit": None,
                "origins": ORIGINS,
            }
        )
    )
    with pytest.raises(ValueError, match="g0-freshness-handshake-invalid"):
        _freshness_handshake(tmp_path, ORIGINS)


class FixtureAdapter(Adapter):
    """Real Adapter/Gate dispatch with a bounded local response fixture."""

    def __init__(self, manifest, nonce, output, expected):
        super().__init__(manifest, nonce, output, local_origins=ORIGINS)
        self.expected = expected
        self.reads = {}

    def request(self, service, path, body=None, *, method="POST", privileged=False, form=False):
        operation = {
            "service": service,
            "path": path,
            "body": body,
            "method": method,
            "privileged": privileged,
            "form": form,
        }
        return self.shared_gate.adapter_request(self, operation, lambda: self.reply(operation))

    def reply(self, operation):
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
                return 200, {"name": resource, "fields": self.expected[resource], "updateTime": "2026-01-02T03:04:05.000001Z"}
            return 404, {"error": {"code": 404, "status": "NOT_FOUND"}}
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
