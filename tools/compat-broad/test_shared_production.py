"""Whole transport simulations, never production observations or owner permissions."""

import copy
import json
import os
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

import batch_adapter
import pytest
import shared_production as production
from broad_contract import digest
from shared_cases import field, manifest
from shared_production_pair import (
    G0_NORMALIZATION_VERSION,
    _compare,
    compare,
    compare_g0_runtime_recompare,
    normalize_g0,
)
from test_second_production import fixture_permission as old_permission


def local_fixture():
    from urllib.parse import quote

    plan = manifest("a" * 32)
    backend = Backend(old_permission())
    jobs, events, states = {}, [], {}
    headers = {
        "x-goog-user-project": production.PROJECT,
        "Authorization": "Bearer fixture-token",
    }
    for key, job in plan["jobs"].items():
        rows, cleanup = [], []
        for phase, operations, target in (
            ("observation", job["observation"], rows),
            ("recovery", job["recovery"], cleanup),
        ):
            for i, declared in enumerate(operations):
                operation = copy.deepcopy(declared)
                source = operation.pop("versionFrom", None)
                if source is not None:
                    operation["path"] += "?currentDocument.updateTime=" + quote(
                        cleanup[source]["body"]["updateTime"], safe=""
                    )
                status, body, _ = backend.wire(
                    "https://firestore.googleapis.com" + operation["path"],
                    operation["method"],
                    operation["body"],
                    headers,
                )
                target.append(
                    {"index": i, "request": operation, "status": status, "body": body}
                )
                events.append(
                    {
                        "job": key,
                        "phase": phase,
                        "index": i,
                        "completed": True,
                        "status": status,
                        "requestDigest": digest(operation),
                        "responseDigest": digest(body),
                    }
                )
        jobs[key] = {
            "recordingComplete": True,
            "cleanupComplete": True,
            "safety": True,
            "stateVerified": True,
            "rows": rows,
            "cleanup": cleanup,
        }
        states[key] = {"complete": True, "inflight": False, "absent": job["resources"]}
    return {
        "gate": {
            "plan": plan,
            "events": events,
            "jobs": states,
            "total": 26,
            "observation": 12,
            "costMicrousd": 42600,
        },
        "jobs": jobs,
        "completed": True,
        "productionExecuted": False,
        "wireHistoryMatchesReservations": True,
        "sharedConstraints": True,
    }


class Backend:
    def __init__(self, permission):
        self.permission = permission
        self.variant = None
        self.calls, self.commands, self.docs = [], [], {}
        self.now = 1000.0

    def command(self, args, **kwargs):
        assert args == ["gcloud", "auth", "application-default", "print-access-token"]
        self.commands.append(args)
        if self.variant == "auth-command":
            raise subprocess.TimeoutExpired(args, 60)
        return subprocess.CompletedProcess(args, 0, "fixture-token\n", "")

    def wire(self, url, method, body, headers, **kwargs):
        self.calls.append((url, method, copy.deepcopy(body), headers.copy()))
        if "tokeninfo" in url:
            return 200, {"expires_in": "3600"}, "application/json"
        assert headers["x-goog-user-project"] == production.PROJECT
        assert headers["Authorization"] == "Bearer fixture-token"
        if "cloudresourcemanager" in url:
            return (
                200,
                {"projectId": production.PROJECT, "projectNumber": production.NUMBER},
                "application/json",
            )
        if url.endswith("databases/(default)"):
            database = copy.deepcopy(self.permission["databaseProjection"])
            if self.variant == "drift":
                database["uid"] = "changed"
            return 200, database, "application/json"
        if "lookupKey" in url:
            return (
                200,
                {
                    "parent": f"projects/{production.NUMBER}/locations/global",
                    "name": f"projects/{production.NUMBER}/locations/global/keys/fixture",
                },
                "application/json",
            )
        if url.endswith("/config"):
            return 200, {"name": "fixture-auth"}, "application/json"
        path = urlsplit(url).path.removeprefix("/v1/")
        assert "/shared_runs/" in path or path.endswith(":batchWrite")
        if self.variant == "auth-denied":
            return 403, {"error": {"code": 403}}, "application/json"
        if self.variant == "timeout":
            raise ValueError("bounded transport timeout")
        if method == "GET":
            result = copy.deepcopy(self.docs.get(path))
            if (
                result is not None
                and self.variant == "readback"
                and len(self.calls) > 10
            ):
                result["name"] = "wrong-document"
            return (
                (200, result, "application/json")
                if result is not None
                else (404, {"error": {"code": 404}}, "application/json")
            )
        if method == "PATCH":
            self.docs[path] = {
                "name": path,
                "fields": body["fields"],
                "updateTime": "2026-09-13T01:00:00Z",
            }
            return 200, copy.deepcopy(self.docs[path]), "application/json"
        if method == "DELETE":
            if self.variant == "unrecovered":
                return 400, {"error": {"code": 400}}, "application/json"
            self.docs.pop(path, None)
            return 200, {}, "application/json"
        assert method == "POST" and path.endswith(":batchWrite")
        if self.variant == "interrupt":
            raise KeyboardInterrupt()
        if self.variant == "budget":
            self.now += 901
            raise ValueError("transport exceeded observation budget")
        if (
            self.variant == "whole-refusal"
            or "transaction" in body
            and self.variant != "unexpected-success"
        ):
            return (
                400,
                {"error": {"code": 400, "status": "INVALID_ARGUMENT"}},
                "application/json",
            )
        statuses = []
        for write in body["writes"]:
            document = copy.deepcopy(write["update"])
            if (
                write.get("currentDocument", {}).get("exists") is False
                and document["name"] in self.docs
            ):
                statuses.append({"code": 6})
                continue
            document["updateTime"] = "2026-09-13T01:00:01Z"
            self.docs[document["name"]] = document
            statuses.append({"code": 0})
        return 200, {"status": statuses}, "application/json"


@pytest.fixture
def boundary(monkeypatch, tmp_path):
    local = local_fixture()
    p = old_permission()
    p.update(
        observerSha256=production.observer_digest(),
        kind="shared-two-owner-permission-v1",
        manifestSha256=digest(production.manifest()),
        comparisonContractDigest=digest(production.binding()),
        localRecordSha256=digest(local),
        recoveryOwner="fixture-only",
        costAssumptions={
            "ownerConfirmed": True,
            "maximumUsd": 1,
            "fixedStorageAndNetworkUpperUsd": 0.04,
            "retentionHours": 24,
        },
    )
    backend = Backend(p)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setattr(production.time, "time", lambda: backend.now)
    monkeypatch.setattr(production.time, "monotonic", lambda: backend.now)
    monkeypatch.setattr(
        production.time, "sleep", lambda n: setattr(backend, "now", backend.now + n)
    )
    monkeypatch.setattr(
        production.subprocess,
        "check_output",
        lambda args, **kw: "c" * 40 if args[1] == "rev-parse" else b"",
    )
    monkeypatch.setattr(batch_adapter.subprocess, "run", backend.command)
    monkeypatch.setattr(batch_adapter, "wire", backend.wire)
    return p, backend, local


def run(boundary, tmp_path):
    p, _backend, local = boundary
    return production.execute(p, p["nonce"], tmp_path / "run", "fixture-key", local)


def test_management_and_data_share_budget(boundary, tmp_path):
    result = run(boundary, tmp_path)
    assert result["completed"], result
    assert (
        result["recordingComplete"]
        and result["stateVerified"]
        and result["cleanupComplete"]
    )
    p, backend, _ = boundary
    assert len(backend.commands) == 1
    assert result["gate"]["total"] == len(backend.commands) + len(backend.calls) == 34
    assert result["gate"]["observation"] == 18
    assert result["gate"]["recovery"] == 16
    assert not backend.docs
    assert result["compatibility"] == "not-compared"
    with pytest.raises(FileExistsError):
        production.execute(
            p, p["nonce"], tmp_path / "again", "fixture-key", boundary[2]
        )
    assert len(backend.commands) == 1


@pytest.mark.parametrize("variant", ["whole-refusal", "unexpected-success"])
def test_other_diagnostic_results_are_observations(boundary, tmp_path, variant):
    boundary[1].variant = variant
    result = run(boundary, tmp_path)
    assert result["completed"] and result["cleanupComplete"]
    assert not all(j["safety"] for j in result["jobs"].values())
    assert not boundary[1].docs


@pytest.mark.parametrize(
    "variant",
    [
        "auth-command",
        "auth-denied",
        "drift",
        "timeout",
        "readback",
        "budget",
        "unrecovered",
    ],
)
def test_failed_collection_keeps_evidence(boundary, tmp_path, variant):
    boundary[1].variant = variant
    result = run(boundary, tmp_path)
    assert not result["completed"]
    assert (tmp_path / "run/execution-inputs.json").exists()
    assert (tmp_path / "run/result.json").exists()
    assert result["gate"]["total"] <= 36
    if variant == "unrecovered":
        assert not result["cleanupComplete"] and boundary[1].docs
    if variant in ("auth-command", "drift"):
        assert not any(":batchWrite" in call[0] for call in boundary[1].calls)


def test_interruption_retains_uncertainty_and_stops_successors(boundary, tmp_path):
    boundary[1].variant = "interrupt"
    with pytest.raises(KeyboardInterrupt):
        run(boundary, tmp_path)
    import json

    result = json.loads((tmp_path / "run/result.json").read_bytes())
    assert not result["completed"] and not result["cleanupComplete"]
    assert result["gate"]["jobs"]["partial"]["inflight"]
    assert not result["gate"]["jobs"]["transaction-field"]["pid"]


def test_comparator_uses_closed_inputs_and_typed_responses(boundary, tmp_path):
    result = run(boundary, tmp_path)
    local = copy.deepcopy(boundary[2])
    assert compare(result, local)["compatibility"] == "match"
    changed = copy.deepcopy(result)
    changed["jobs"]["partial"]["rows"][-1]["body"]["fields"] = field(99)
    for event in changed["gate"]["events"]:
        if (
            event["job"] == "partial"
            and event["phase"] == "observation"
            and event["index"] == 7
        ):
            event["responseDigest"] = digest(
                changed["jobs"]["partial"]["rows"][-1]["body"]
            )
    assert compare(changed, local)["compatibility"] == "mismatch"
    for record in (changed, local):
        record["jobs"]["partial"]["rows"][4]["request"]["body"]["writes"][1][
            "currentDocument"
        ]["exists"] = 0
    assert compare(changed, local)["compatibility"] == "indeterminate"
    result["completed"] = False
    assert compare(result, local)["compatibility"] == "indeterminate"


def test_g0_status_message_normalization_is_exact_and_owned():
    parent = "projects/p/databases/(default)/documents/shared_runs/a-partial/docs"
    resource = parent + "/existing"
    names = {
        "firestoreParents": {"partial": parent},
        "firestoreResources": {"partial": [resource]},
    }
    equivalent = {
        "status": [{}, {"code": 6, "message": "Document already exists: " + resource}]
    }
    changed_parent = parent.replace("a-partial", "b-partial")
    changed_resource = resource.replace("a-partial", "b-partial")
    changed_names = {
        "firestoreParents": {"partial": changed_parent},
        "firestoreResources": {"partial": [changed_resource]},
    }
    assert normalize_g0(equivalent, names, service="firestore") == normalize_g0(
        {
            "status": [
                {},
                {"code": 6, "message": "Document already exists: " + changed_resource},
            ]
        },
        changed_names,
        service="firestore",
    )
    for message in [
        "x" + resource,
        resource + "-suffix",
        "Document already exists: projects/foreign/docs/existing",
    ]:
        body = {"status": [{}, {"code": 6, "message": message}]}
        assert normalize_g0(body, names, service="firestore") == body
    assert normalize_g0(
        {"status": [{"code": "6", "message": resource}]},
        names,
        service="firestore",
    ) == {"status": [{"code": "6", "message": "documents/partial/existing"}]}


def _g0_local_runtime_fixture(production, local):
    """Derive a local-shaped receipt from the pinned bodies without changing its inputs."""
    from batch_adapter import observer_digest

    result = copy.deepcopy(local)
    result["gate"]["plan"]["observerSha256"] = observer_digest()
    for key, production_job in production["jobs"].items():
        local_job = result["jobs"][key]
        production_resources = production["gate"]["plan"]["jobs"][key]["resources"]
        local_resources = result["gate"]["plan"]["jobs"][key]["resources"]
        sources = tuple(production_resources)
        targets = tuple(local_resources)

        def remap(value, *, sources=sources, targets=targets):
            if isinstance(value, str):
                for source, target in zip(sources, targets, strict=True):
                    value = value.replace(source, target)
                return value
            if isinstance(value, list):
                return [remap(item) for item in value]
            if isinstance(value, dict):
                return {name: remap(item) for name, item in value.items()}
            return value

        for production_row, local_row in zip(
            production_job["rows"], local_job["rows"], strict=True
        ):
            local_row["body"] = remap(production_row["body"])
            event = next(
                event
                for event in result["gate"]["events"]
                if event["job"] == key
                and event["phase"] == "observation"
                and event["index"] == local_row["index"]
            )
            event["responseDigest"] = digest(local_row["body"])
    return result


def _g0_production_source():
    source = Path(os.environ.get("FIREEMU_G0_PRODUCTION_RESULT", ""))
    if not source.exists():
        pytest.skip("private G0 production record is unavailable")
    return source


def test_g0_runtime_recompare_pins_production_and_does_not_reuse_old_local_hash(
    tmp_path,
):
    source = _g0_production_source()
    production = json.loads(source.read_bytes())
    local = _g0_local_runtime_fixture(production, local_fixture())
    pinned = tmp_path / "g0-production.json"
    pinned.write_bytes(source.read_bytes())
    result = compare_g0_runtime_recompare(pinned, local)
    assert result["compatibility"] == "match", result
    assert result["mode"] == "g0-runtime-recomparison"
    assert result["contract"]["normalizationVersion"] == G0_NORMALIZATION_VERSION
    assert result["source"]["oldLocalRecordSha256"] == production["localRecordSha256"]
    assert (
        result["source"]["newComparisonContractDigest"]
        == result["comparisonContractDigest"]
    )
    tampered = tmp_path / "tampered.json"
    tampered.write_bytes(source.read_bytes() + b" ")
    with pytest.raises(ValueError, match="G0 production result hash mismatch"):
        compare_g0_runtime_recompare(tampered, local)


@pytest.mark.parametrize("field", ["safety", "stateVerified", "cleanupComplete"])
def test_g0_runtime_recompare_rejects_missing_production_safety_or_cleanup(field):
    source = _g0_production_source()
    production = json.loads(source.read_bytes())
    local = _g0_local_runtime_fixture(production, local_fixture())
    production["jobs"]["partial"][field] = False
    result = _compare(production, local, g0_recompare=True)
    assert result["compatibility"] == "indeterminate"


@pytest.mark.parametrize(
    "field,value",
    [
        ("safety", False),
        ("safety", None),
        ("stateVerified", False),
        ("stateVerified", None),
    ],
)
def test_g0_runtime_recompare_rejects_local_safety_or_state_without_true_value(
    field, value
):
    source = _g0_production_source()
    production = json.loads(source.read_bytes())
    local = _g0_local_runtime_fixture(production, local_fixture())
    local["jobs"]["partial"][field] = value
    result = _compare(production, local, g0_recompare=True)
    assert result["compatibility"] == "indeterminate"


@pytest.mark.parametrize(
    "field",
    [
        "ownerIdentity",
        "expiresAt",
        "nonce",
        "manifestSha256",
        "databaseProjectionDigest",
        "localRecordSha256",
    ],
)
def test_admission_fails_before_authentication(boundary, tmp_path, field):
    boundary[0][field] = None
    with pytest.raises((ValueError, TypeError)):
        run(boundary, tmp_path)
    assert not boundary[1].commands and not boundary[1].calls


def test_management_capacity_and_credential_recovery(boundary, tmp_path):
    from shared_gate import _save, create

    p, backend, _ = boundary
    plan = production.schedule(p["nonce"])
    plan["permissionDigest"] = digest(p)
    create(tmp_path / "gate", plan)
    gate = production.ProductionGate(tmp_path / "gate", "partial")
    coordinator = production.Coordinator(
        p, p["nonce"], tmp_path / "coordinator", gate, "fixture-key"
    )
    coordinator.acquire()
    coordinator.credential.expiry = backend.now + 12.5
    coordinator.recover_credentials()
    assert len(backend.commands) == 2
    assert gate.snapshot()["total"] == 4
    assert gate.snapshot()["recovery"] == 2
    coordinator.credential.expiry = backend.now
    with pytest.raises(ValueError):
        coordinator.recover_credentials()
    assert len(backend.commands) == 2
    assert gate.snapshot()["total"] == 4
    with gate.locked() as state:
        state["observation"] = 18
        _save(gate.path, state)
    coordinator.budget.recovery = False
    with pytest.raises(ValueError):
        coordinator.preflight()
    assert len(backend.calls) == 2


def test_comparison_rejects_claimed_success_without_receipts(boundary, tmp_path):
    result = run(boundary, tmp_path)
    result["stateVerified"] = False
    assert compare(result, boundary[2])["compatibility"] == "indeterminate"
    result["stateVerified"] = True
    result["gate"]["events"] = []
    assert compare(result, boundary[2])["compatibility"] == "indeterminate"


@pytest.mark.parametrize(
    "change",
    [
        "unconditional-delete",
        "management",
        "auth-baseline",
        "state",
        "missing-row",
        "typed-body",
    ],
)
def test_comparison_detects_corrupt_evidence(boundary, tmp_path, change):
    result = run(boundary, tmp_path)
    local = boundary[2]
    if change == "unconditional-delete":
        row = result["jobs"]["partial"]["cleanup"][1]
        row["request"]["path"] = row["request"]["path"].split("?")[0]
        for event in result["gate"]["events"]:
            if (
                event["job"] == "partial"
                and event["phase"] == "recovery"
                and event["index"] == 1
            ):
                event["requestDigest"] = digest(row["request"])
    elif change == "management":
        result["gate"]["managementEvents"] = [{"id": "bogus"}] * 10
    elif change == "auth-baseline":
        next(e for e in result["metadataEvidence"] if e["id"] == "recovery:auth")[
            "responseDigest"
        ] = "0" * 64
    elif change == "state":
        result["stateVerified"] = False
    elif change == "missing-row":
        result["jobs"]["partial"]["rows"].pop()
    else:
        result["jobs"]["partial"]["rows"][4]["request"]["privileged"] = 1
    assert compare(result, local)["compatibility"] == "indeterminate"


def test_compare_cli_preserves_existing_inputs(boundary, tmp_path, monkeypatch):
    import json
    import sys

    import shared_production_pair as pair

    result = run(boundary, tmp_path)
    p, l, output = (
        tmp_path / "production.json",
        tmp_path / "local.json",
        tmp_path / "comparison.json",
    )
    p.write_text(json.dumps(result))
    l.write_text(json.dumps(boundary[2]))
    argv = [
        "compare",
        "--production",
        str(p),
        "--local",
        str(l),
        "--output",
        str(output),
        "--check",
    ]
    monkeypatch.setattr(sys, "argv", argv)
    assert pair.main() == 0
    original = p.read_bytes()
    argv[-2] = str(p)
    with pytest.raises(FileExistsError):
        pair.main()
    assert p.read_bytes() == original
