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

    from shared_gate import _creation_proofs

    plan = manifest("a" * 32)
    backend = Backend(old_permission())
    jobs, events, states = {}, [], {}
    headers = {
        "x-goog-user-project": production.PROJECT,
        "Authorization": "Bearer fixture-token",
    }
    for key, job in plan["jobs"].items():
        rows, cleanup = [], []
        proofs = {}
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
                if phase == "observation":
                    for proof in _creation_proofs(operation, status, body, job, plan):
                        proofs.setdefault(proof["name"], proof)
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
        states[key] = {
            "complete": True,
            "inflight": False,
            "absent": job["resources"],
            "owned": list(proofs),
            "creationProofs": proofs,
        }
    return {
        "gate": {
            "plan": plan,
            "planDigest": digest(plan),
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
                else (404, {"error": {"code": 404, "status": "NOT_FOUND"}}, "application/json")
            )
        if method == "PATCH":
            self.docs[path] = {
                "name": path,
                "fields": body["fields"],
                "updateTime": "2026-09-13T01:00:00Z",
            }
            if self.variant == "lost-create":
                raise ValueError("creation acknowledgement lost after commit")
            if self.variant == "interrupted-create":
                raise KeyboardInterrupt()
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
        statuses, results = [], []
        for write in body["writes"]:
            document = copy.deepcopy(write["update"])
            if (
                write.get("currentDocument", {}).get("exists") is False
                and document["name"] in self.docs
            ):
                statuses.append({"code": 6})
                results.append({})
                continue
            document["updateTime"] = "2026-09-13T01:00:01Z"
            self.docs[document["name"]] = document
            statuses.append({"code": 0})
            results.append({"updateTime": document["updateTime"]})
        return 200, {"status": statuses, "writeResults": results}, "application/json"


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
    assert not all(j["safety"] for j in result["jobs"].values())
    if variant == "unexpected-success":
        # The invalid transaction write unexpectedly changed the created version.
        # An observation of that new version cannot grant cleanup ownership.
        assert not result["completed"] and not result["cleanupComplete"]
        assert len(boundary[1].docs) == 1
        assert not any(
            method == "DELETE" and "transaction-field" in url
            for url, method, _body, _headers in boundary[1].calls
        )
    else:
        assert result["completed"] and result["cleanupComplete"]
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
    """Build synthetic test responses over a copied frozen-v1 local fixture."""
    result = copy.deepcopy(local)
    batch = result.get("batch", result)
    for key, production_job in production["jobs"].items():
        local_job = batch["jobs"][key]
        production_resources = production["gate"]["plan"]["jobs"][key]["resources"]
        local_resources = batch["gate"]["plan"]["jobs"][key]["resources"]
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
                for event in batch["gate"]["events"]
                if event["job"] == key
                and event["phase"] == "observation"
                and event["index"] == local_row["index"]
            )
            event["responseDigest"] = digest(local_row["body"])
    return result


def _g0_production_source():
    configured = os.environ.get("FIREEMU_G0_PRODUCTION_RESULT")
    source = Path(configured) if configured else None
    if source is None or not source.is_file():
        pytest.skip("private G0 production record is unavailable")
    return source


def test_g0_production_source_skips_without_a_private_file(monkeypatch, tmp_path):
    monkeypatch.delenv("FIREEMU_G0_PRODUCTION_RESULT", raising=False)
    with pytest.raises(pytest.skip.Exception):
        _g0_production_source()
    monkeypatch.setenv("FIREEMU_G0_PRODUCTION_RESULT", str(tmp_path))
    with pytest.raises(pytest.skip.Exception):
        _g0_production_source()


def test_g0_runtime_recompare_pins_production_and_does_not_reuse_old_local_hash(
    tmp_path,
):
    source = _g0_production_source()
    production = json.loads(source.read_bytes())
    local = _g0_local_runtime_fixture(production, frozen_g0_local_fixture())
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
    local = _g0_local_runtime_fixture(production, frozen_g0_local_fixture())
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
    local = _g0_local_runtime_fixture(production, frozen_g0_local_fixture())
    local["batch"]["jobs"]["partial"][field] = value
    result = _compare(production, local, g0_recompare=True)
    assert result["compatibility"] == "indeterminate"


@pytest.mark.parametrize("field", ["safety", "stateVerified"])
def test_g0_runtime_recompare_rejects_missing_local_safety_or_state(field):
    source = _g0_production_source()
    production = json.loads(source.read_bytes())
    local = _g0_local_runtime_fixture(production, frozen_g0_local_fixture())
    del local["batch"]["jobs"]["partial"][field]
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


@pytest.mark.parametrize("variant", ["lost-create", "interrupted-create"])
def test_unacknowledged_creation_never_reports_top_level_cleanup_complete(boundary, tmp_path, variant):
    boundary[1].variant = variant
    if variant == "interrupted-create":
        with pytest.raises(KeyboardInterrupt):
            run(boundary, tmp_path)
        result = json.loads((tmp_path / "run/result.json").read_bytes())
    else:
        result = run(boundary, tmp_path)
        assert result["jobs"]["partial"]["cleanupComplete"] is False
    assert len(boundary[1].docs) == 1
    assert result["gate"]["jobs"]["partial"]["owned"] == []
    assert result["cleanupComplete"] is False
    assert result["recordingComplete"] is False
    assert result["completed"] is False
    assert compare(result, boundary[2])["compatibility"] == "indeterminate"
    assert not any(method == "DELETE" for _url, method, _body, _headers in boundary[1].calls)
    assert json.loads((tmp_path / "run/result.json").read_bytes())["cleanupComplete"] is False


def test_no_data_dispatch_does_not_claim_uncertain_document_cleanup(boundary, tmp_path):
    boundary[1].variant = "auth-command"
    result = run(boundary, tmp_path)
    assert not boundary[1].docs
    assert all(job["pid"] is None for job in result["gate"]["jobs"].values())
    assert result["cleanupComplete"] is True
    assert result["completed"] is False


def frozen_g0_local_fixture():
    """Copy the immutable public v1 receipt, never rebuild it with the v2 collector."""
    return json.loads((Path(__file__).parents[2] / "spec/compatibility/broad-runs/a35f85b4-shared-local-reference.json").read_bytes())


def test_frozen_g0_contract_is_accepted_only_by_explicit_historical_validation():
    from shared_production_pair import validate_record

    frozen = frozen_g0_local_fixture()
    before = digest(frozen)
    assert validate_record(frozen, local=True, historical_observer=True) == frozen["batch"]
    assert digest(frozen) == before
    with pytest.raises(ValueError):
        validate_record(frozen, local=True)
    with pytest.raises(ValueError):
        validate_record(local_fixture(), local=True, historical_observer=True)


@pytest.mark.parametrize("field,value", [("contract", "shared-local-v1"), ("collector", "existing-batch-adapter-shared-v1"), ("contract", None), ("collector", None)])
def test_current_v2_validation_rejects_relabeling_even_with_rebound_plan_digest(field, value):
    from shared_production_pair import validate_record

    record = local_fixture()
    validate_record(record, local=True)
    record["gate"]["plan"][field] = value
    record["gate"]["planDigest"] = digest(record["gate"]["plan"])
    with pytest.raises(ValueError):
        validate_record(record, local=True)


@pytest.mark.parametrize("variant", ["missing", "wrong", "unbound-plan"])
def test_current_v2_validation_requires_persisted_plan_digest(variant):
    from shared_production_pair import validate_record

    record = local_fixture()
    record["gate"]["planDigest"] = digest(record["gate"]["plan"])
    validate_record(record, local=True)
    if variant == "missing":
        del record["gate"]["planDigest"]
    elif variant == "wrong":
        record["gate"]["planDigest"] = "0" * 64
    else:
        record["gate"]["plan"]["intervalSeconds"] += 0.25
    with pytest.raises(ValueError):
        validate_record(record, local=True)


@pytest.mark.parametrize("variant", ["source-missing", "source-unknown", "source-other-observer", "observer-rebound", "contract-rebound", "collector-rebound", "plan-digest-missing"])
def test_historical_g0_validation_binds_frozen_source_observer_and_plan(variant):
    from shared_production_pair import validate_record

    record = frozen_g0_local_fixture()
    plan = record["batch"]["gate"]["plan"]
    if variant == "source-missing":
        del record["executionCommit"]
    elif variant == "source-unknown":
        record["executionCommit"] = "0" * 40
    elif variant == "source-other-observer":
        record["executionCommit"] = "68012694f81df504600f8e67301410c63ec9e2e7"
    elif variant == "observer-rebound":
        record["observerSha256"] = plan["observerSha256"] = production.observer_digest()
    elif variant == "contract-rebound":
        plan["contract"] = "shared-local-v2"
    elif variant == "collector-rebound":
        plan["collector"] = "existing-batch-adapter-shared-v2"
    record["batch"]["gate"]["planDigest"] = digest(plan)
    if variant == "plan-digest-missing":
        del record["batch"]["gate"]["planDigest"]
    with pytest.raises(ValueError):
        validate_record(record, local=True, historical_observer=True)


def test_g0_contract_retains_frozen_v1_admission_without_current_builder():
    from shared_production_pair import (
        G0_ORIGINAL_COMPARISON_CONTRACT_DIGEST,
        frozen_g0_manifest,
        g0_contract,
    )

    plan = frozen_g0_manifest("a" * 32)
    assert plan["contract"] == "shared-local-v1"
    assert plan["collector"] == "existing-batch-adapter-shared-v1"
    writes = plan["jobs"]["partial"]["observation"][4]["body"]["writes"]
    assert "currentDocument" not in writes[0]
    assert writes[1]["currentDocument"] == {"exists": False}
    assert "currentDocument" not in writes[2]
    assert all("_sharedOwner" not in write["update"]["fields"] for write in writes)
    contract = g0_contract()
    assert (
        contract["baseAdmissionContractDigest"]
        == G0_ORIGINAL_COMPARISON_CONTRACT_DIGEST
    )
    assert contract["baseAdmissionContractDigest"] != digest(production.binding())


def rebind_fixture_events(record):
    for event in record["gate"]["events"]:
        job = record["jobs"][event["job"]]
        rows = job["rows"] if event["phase"] == "observation" else job["cleanup"]
        row = rows[event["index"]]
        event["requestDigest"] = digest(row["request"])
        event["responseDigest"] = digest(row["body"])
        event["status"] = row["status"]


@pytest.mark.parametrize("replace", [False, True])
def test_current_v2_requires_creation_proofs_even_when_foreign_cleanup_is_rebound(
    replace,
):
    from urllib.parse import quote

    from shared_production_pair import validate_record

    record = local_fixture()
    validate_record(record, local=True)
    record["gate"]["jobs"]["partial"].pop("creationProofs", None)
    if replace:
        rows = record["jobs"]["partial"]["cleanup"]
        rows[0]["body"]["updateTime"] = "2026-09-14T01:00:00Z"
        rows[1]["request"]["path"] = (
            rows[1]["request"]["path"].split("?")[0]
            + "?currentDocument.updateTime="
            + quote(rows[0]["body"]["updateTime"], safe="")
        )
        rebind_fixture_events(record)
    with pytest.raises(ValueError):
        validate_record(record, local=True)


@pytest.mark.parametrize(
    "variant",
    [
        "empty",
        "extra",
        "owned-missing",
        "name",
        "updateTime",
        "fieldsDigest",
        "requestDigest",
        "responseDigest",
    ],
)
def test_current_v2_creation_journal_must_match_acknowledged_exact_proofs(variant):
    from shared_production_pair import validate_record

    record = local_fixture()
    state = record["gate"]["jobs"]["partial"]
    name = record["gate"]["plan"]["jobs"]["partial"]["resources"][1]
    if variant == "empty":
        state["creationProofs"] = {}
    elif variant == "extra":
        state["creationProofs"][name + "-foreign"] = copy.deepcopy(
            state["creationProofs"][name]
        )
    elif variant == "owned-missing":
        state["owned"].remove(name)
    else:
        state["creationProofs"][name][variant] = "foreign"
    with pytest.raises(ValueError):
        validate_record(record, local=True)


@pytest.mark.parametrize(
    "variant", ["version", "fields", "name", "skipped-status", "bool-status"]
)
def test_current_v2_rebound_cleanup_cannot_replace_created_resource_state(variant):
    from urllib.parse import quote

    from shared_production_pair import validate_record

    record = local_fixture()
    rows = record["jobs"]["partial"]["cleanup"]
    if variant == "version":
        rows[0]["body"]["updateTime"] = "2026-09-14T01:00:00Z"
        rows[1]["request"]["path"] = (
            rows[1]["request"]["path"].split("?")[0]
            + "?currentDocument.updateTime="
            + quote(rows[0]["body"]["updateTime"], safe="")
        )
    elif variant == "fields":
        rows[0]["body"]["fields"] = {"foreign": {"booleanValue": True}}
    elif variant == "name":
        rows[0]["body"]["name"] += "-foreign"
    else:
        rows[1]["status"] = None if variant == "skipped-status" else True
    rebind_fixture_events(record)
    with pytest.raises(ValueError):
        validate_record(record, local=True)


@pytest.mark.parametrize(
    "variant",
    [
        "conflict",
        "lost",
        "bool-status",
        "foreign-name",
        "missing-version",
        "invalid-version",
        "bool-version",
        "foreign-marker",
        "bool-batch-code",
        "missing-batch-result",
    ],
)
def test_current_v2_rebound_creation_response_cannot_grant_destructive_authority(
    variant,
):
    from shared_production_pair import validate_record

    record = local_fixture()
    job = record["jobs"]["partial"]
    row = job["rows"][3]
    state = record["gate"]["jobs"]["partial"]
    name = row["body"]["name"]
    if variant == "conflict":
        row["status"] = 409
    elif variant == "lost":
        row["status"] = None
    elif variant == "bool-status":
        row["status"] = True
    elif variant == "foreign-name":
        row["body"]["name"] += "-foreign"
    elif variant == "missing-version":
        del row["body"]["updateTime"]
    elif variant == "invalid-version":
        row["body"]["updateTime"] = "invalid"
    elif variant == "bool-version":
        row["body"]["updateTime"] = True
    elif variant == "foreign-marker":
        row["body"]["fields"]["_sharedOwner"] = {"referenceValue": name + "-foreign"}
    elif variant == "bool-batch-code":
        job["rows"][4]["body"]["status"][0]["code"] = False
    else:
        job["rows"][4]["body"]["writeResults"].pop()
    state["creationProofs"][name]["responseDigest"] = digest(row["body"])
    state["creationProofs"][name]["fieldsDigest"] = digest(row["body"].get("fields"))
    state["creationProofs"][name]["updateTime"] = row["body"].get("updateTime")
    rebind_fixture_events(record)
    with pytest.raises(ValueError):
        validate_record(record, local=True)


@pytest.mark.parametrize("variant", ["read-status", "final-status", "incomplete-event"])
def test_current_v2_cleanup_chain_requires_typed_completed_receipts(variant):
    from shared_production_pair import validate_record

    record = local_fixture()
    rows = record["jobs"]["partial"]["cleanup"]
    if variant == "read-status":
        rows[0]["status"] = 200.0
    elif variant == "final-status":
        rows[2]["status"] = 404.0
    rebind_fixture_events(record)
    if variant == "incomplete-event":
        next(
            event for event in record["gate"]["events"] if event["phase"] == "recovery"
        )["completed"] = False
    with pytest.raises(ValueError):
        validate_record(record, local=True)

@pytest.mark.parametrize("status", [{}, {"code": 0}])
def test_v2_batch_creation_accepts_archived_protobuf_default_status(status):
    from shared_production_pair import validate_record

    record = local_fixture()
    row = record["jobs"]["partial"]["rows"][4]
    # Frozen G0 production successes have {}, unlike the explicit local default 0.
    row["body"]["status"][0] = row["body"]["status"][2] = status
    for index in (0, 2):
        resource = record["gate"]["plan"]["jobs"]["partial"]["resources"][index]
        record["gate"]["jobs"]["partial"]["creationProofs"][resource][
            "responseDigest"
        ] = digest(row["body"])
    rebind_fixture_events(record)
    assert validate_record(record, local=True) == record


@pytest.mark.parametrize(
    "status",
    [
        {"code": False},
        {"code": "0"},
        {"code": None},
        {"code": 6},
        {"code": []},
        {"code": {}},
        None,
        [],
    ],
)
def test_v2_batch_creation_rejects_explicit_nonsuccess_or_malformed_status(status):
    from shared_production_pair import validate_record

    record = local_fixture()
    row = record["jobs"]["partial"]["rows"][4]
    row["body"]["status"][0] = row["body"]["status"][2] = status
    for index in (0, 2):
        resource = record["gate"]["plan"]["jobs"]["partial"]["resources"][index]
        record["gate"]["jobs"]["partial"]["creationProofs"][resource][
            "responseDigest"
        ] = digest(row["body"])
    rebind_fixture_events(record)
    with pytest.raises(ValueError):
        validate_record(record, local=True)


@pytest.mark.parametrize(
    "target", ["skipped", "unknown-index", "unknown-job", "unknown-phase"]
)
def test_skipped_cleanup_rejects_foreign_dispatch_receipt(boundary, tmp_path, target):
    from shared_production_pair import validate_record

    boundary[1].variant = "whole-refusal"
    record = run(boundary, tmp_path)
    assert validate_record(record) == record
    skipped = record["gate"]["skips"][0]
    row = record["jobs"][skipped["job"]]["cleanup"][skipped["index"]]
    assert row["status"] is None
    foreign = copy.deepcopy(row["request"])
    foreign["path"] = "/v1/projects/foreign/databases/(default)/documents/foreign/doc"
    record["gate"]["events"].append(
        {
            "job": skipped["job"],
            "phase": "recovery",
            "index": skipped["index"],
            "completed": True,
            "status": 200,
            "requestDigest": digest(foreign),
            "responseDigest": digest({}),
        }
    )
    event = record["gate"]["events"][-1]
    if target == "unknown-index":
        event["index"] = -1
    elif target == "unknown-job":
        event["job"] = "unrelated"
    elif target == "unknown-phase":
        event["phase"] = "unrelated"
    record["gate"]["total"] += 1
    record["gate"]["recovery"] += 1
    record["gate"]["costMicrousd"] += record["gate"]["plan"]["requestCostMicrousd"]
    with pytest.raises(ValueError, match="recovery receipt"):
        validate_record(record)


@pytest.mark.parametrize(
    "mutation", ["body", "missing-journal", "duplicate-journal", "foreign-journal"]
)
def test_skipped_cleanup_requires_exact_nondispatch_evidence(
    boundary, tmp_path, mutation
):
    from shared_production_pair import validate_record

    boundary[1].variant = "whole-refusal"
    record = run(boundary, tmp_path)
    assert validate_record(record) == record
    skipped = record["gate"]["skips"][0]
    row = record["jobs"][skipped["job"]]["cleanup"][skipped["index"]]
    if mutation == "body":
        row["body"] = {}
    elif mutation == "missing-journal":
        record["gate"]["skips"].pop(0)
    elif mutation == "duplicate-journal":
        record["gate"]["skips"].append(copy.deepcopy(skipped))
    else:
        skipped["job"] = "unrelated"
    with pytest.raises(ValueError, match="skipped cleanup"):
        validate_record(record)


def test_the_metadata_route_table_comes_from_the_campaign(boundary, tmp_path):
    """One core serves several campaigns, so the closed table cannot be a literal."""
    from shared_gate import create

    p, _backend, _ = boundary
    plan = production.schedule(p["nonce"])
    plan["permissionDigest"] = digest(p)
    create(tmp_path / "gate", plan)
    gate = production.ProductionGate(tmp_path / "gate", "partial")
    default = production.Coordinator(
        p, p["nonce"], tmp_path / "default", gate, "fixture-key"
    )
    assert sorted(default.metadata_routes().values()) == [
        "auth",
        "database",
        "key",
        "project",
    ]
    routes = {"example.googleapis.com/v1/owned/thing": "thing"}
    custom = production.Coordinator(
        p, p["nonce"], tmp_path / "custom", gate, "fixture-key", routes=routes
    )
    assert custom.metadata_routes() == routes
    before = gate.snapshot()
    for coordinator, path in (
        (custom, next(iter(default.metadata_routes()))),
        (default, next(iter(routes))),
    ):
        with pytest.raises(ValueError, match="closed metadata request"):
            coordinator.request("metadata", path, None, method="GET", privileged=True)
    assert gate.snapshot() == before
