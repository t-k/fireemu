# ruff: noqa: I001 -- Import production bootstrap before shared modules.
"""Offline admission tests; fixture permissions grant no production access."""

import pytest
from production import approve, contract, manifest
from broad_contract import digest
from production_bridge import source_digest
from test_second_production import fixture_permission


def permission():
    result = fixture_permission()
    result.update(
        kind="fs-write-limits-owner-permission-v1",
        manifestSha256=digest(manifest()),
        comparisonContractDigest=digest(contract()),
        collectorSourceDigest=source_digest(),
        observerSha256=source_digest(),
        localBundleDigest="1" * 64,
        artifactSha256="2" * 64,
        frozenCommit="3" * 40,
        apiKeyDigest="4" * 64,
        ledgerIdentity="5" * 64,
        recoveryOwner="offline-fixture",
        allowedReobservations=0,
        requestUpperBound=40,
        accountUpperBound=0,
        resourceUpperBound=4,
        concurrencyUpperBound=1,
        timeUpperBound=960,
        costUpperMicrousd=44000,
        safetyClass="OWNED_DATA",
        database="(default)",
        tenant=None,
        costAssumptions={
            "ownerConfirmed": True,
            "retentionHours": 24,
            "maximumUsd": 0.044,
            "fixedStorageAndNetworkUpperUsd": 0.04,
        },
    )
    return result


def test_closed_limits_permission_admits_only_exact_frozen_bindings():
    value = permission()
    approve(
        value,
        value["nonce"],
        "1" * 64,
        "2" * 64,
        "3" * 40,
        "4" * 64,
        "5" * 64,
        now=1000,
    )


@pytest.mark.parametrize(
    "key,value",
    [
        ("requestUpperBound", 41),
        ("requestUpperBound", True),
        ("artifactSha256", "a" * 64),
        ("localBundleDigest", "a" * 64),
        ("allowedReobservations", 1),
        ("database", "other"),
        ("tenant", "tenant-a"),
        ("collectorSourceDigest", "a" * 64),
        ("ledgerIdentity", "a" * 64),
        ("expiresAt", 1100),
    ],
)
def test_incomplete_or_expanded_permission_is_refused(key, value):
    candidate = permission()
    candidate[key] = value
    with pytest.raises(ValueError):
        approve(
            candidate,
            candidate["nonce"],
            "1" * 64,
            "2" * 64,
            "3" * 40,
            "4" * 64,
            "5" * 64,
            now=1000,
        )


def acquired_fixture(tmp_path, *, mismatch=False):
    """Real Gate transitions around finite in-memory wire fixtures, never a cloud receipt."""
    import time
    from compiler import compile_limits_plan
    from collector import collect
    from production_bridge import LimitsGate, bind_wire, execution_plan
    from shared_gate import create
    from shared_production import Coordinator

    value = permission()
    value.update(issuedAt=time.time() - 1, expiresAt=time.time() + 2000)
    plan = execution_plan(value, value["nonce"])
    create(tmp_path / "gate", plan)
    gate = LimitsGate(tmp_path / "gate")
    gate.claim()
    coordinator = Coordinator(
        value, value["nonce"], tmp_path / "coordinator", gate, "synthetic-key"
    )
    metadata = []

    def phase_metadata():
        phase = "recovery" if coordinator.budget.recovery else "observation"
        for key in ("project", "database", "auth", "key"):
            gate.manage(coordinator, key, lambda: coordinator.reserve("metadata"))
            metadata.append(
                {
                    "id": f"{phase}:{key}",
                    "status": 200,
                    "responseDigest": value["authConfigDigest"]
                    if key == "auth"
                    else digest({}),
                    "value": {
                        "project": {
                            "projectId": value["project"],
                            "projectNumber": value["projectNumber"],
                        },
                        "database": {
                            "projection": value["databaseProjection"],
                            "projectionDigest": value["databaseProjectionDigest"],
                        },
                        "auth": {},
                        "key": {
                            "parent": f"projects/{value['projectNumber']}/locations/global",
                            "name": f"projects/{value['projectNumber']}/locations/global/keys/fixture",
                        },
                    }[key],
                }
            )

    def credential_attempts():
        coordinator.reserve("metadata", 86)
        coordinator.reserve("metadata", 12)

    gate.manage(coordinator, "credentials", credential_attempts)
    coordinator.credential.accept(
        "synthetic-token", {"expires_in": 2000}, time.monotonic()
    )
    phase_metadata()
    coordinator.ready = True
    compiled = compile_limits_plan(value["project"], "(default)", value["nonce"])
    stored = {}
    negatives = {
        d["resource"] for k, d in compiled["documents"].items() if k.startswith("over-")
    }

    def transport(request):
        operation = request["operation"]
        name = operation["path"].split("?")[0].removeprefix("/v1/")
        status, body = 404, {"error": {"code": 404, "status": "NOT_FOUND"}}
        if operation["method"] == "PATCH":
            if name in negatives and mismatch != "accepted":
                status, body = (
                    400,
                    {
                        "error": {
                            "code": 400,
                            "status": "INVALID_ARGUMENT",
                            "message": "different" if mismatch else "expected",
                        }
                    },
                )
            else:
                stored[name] = {
                    **operation["body"],
                    "updateTime": "2026-09-17T00:00:00Z",
                }
                status, body = 200, stored[name]
        elif operation["method"] == "DELETE":
            del stored[name]
            status, body = 200, {}
        elif name in stored:
            status, body = 200, stored[name]
        return {"complete": True, "status": status, "body": body}

    collected = collect(
        gate,
        compiled,
        tmp_path / "collection",
        bind_wire(coordinator, plan, transmit=transport),
        before_recovery=coordinator.recover_credentials,
    )
    phase_metadata()
    inputs = {"permission": value, "plan": plan}
    receipt = {
        "productionExecuted": True,
        "inputsDigest": digest(inputs),
        "failure": None,
        "sourceDigestAfter": source_digest(),
        "configurationUnchanged": True,
        "collection": collected,
        "gate": gate.snapshot(),
        "metadataEvidence": metadata,
    }
    assert stored == {}
    return receipt, inputs, compiled


@pytest.mark.parametrize("mismatch", [True, "accepted"])
def test_complete_acquisition_reaches_semantic_mismatch_without_losing_cleanup(
    tmp_path, mismatch
):
    from production import validate_acquisition
    from comparator import compare_rows
    from test_shadow import fixture_rows

    receipt, inputs, compiled = acquired_fixture(tmp_path, mismatch=mismatch)
    validate_acquisition(receipt, inputs)
    compared = compare_rows(
        compiled, receipt["collection"]["rows"], compiled, fixture_rows(compiled)
    )
    assert compared["classification"] == "SEMANTIC_MISMATCH"


def test_acquisition_rejects_forged_completion_and_journal_tampering(tmp_path):
    import copy
    from production import validate_acquisition

    receipt, inputs, _ = acquired_fixture(tmp_path)
    validate_acquisition(receipt, inputs)
    for mutation in ("metadata", "event", "count", "cleanup", "source", "failure"):
        changed = copy.deepcopy(receipt)
        if mutation == "metadata":
            changed["metadataEvidence"].pop()
        elif mutation == "event":
            changed["gate"]["events"][0]["responseDigest"] = "0" * 64
        elif mutation == "count":
            changed["gate"]["total"] = True
        elif mutation == "cleanup":
            changed["collection"]["cleanup"][-1]["body"] = {}
        elif mutation == "source":
            changed["sourceDigestAfter"] = "0" * 64
        else:
            changed["failure"] = "TransportFailure"
        with pytest.raises(ValueError):
            validate_acquisition(changed, inputs)


def local_fixture(tmp_path):
    from production import sha_file
    from compiler import compile_limits_plan
    from shadow import save, source_inputs
    from test_shadow import fixture_receipt
    from evidence_common import runtime_inputs
    from owned_runner import BUILD_COMMAND
    from broad_contract import ROOT

    tmp_path.mkdir()
    artifact = tmp_path / "synthetic-artifact"
    artifact.write_bytes(b"offline-fixture-not-a-runtime")
    plan = compile_limits_plan("demo-firestore-probe", "(default)", "a" * 32)
    result = fixture_receipt(plan)
    child = {
        "sourceInputs": source_inputs(),
        "sourceInputsAfter": source_inputs(),
        "nonce": plan["nonce"],
    }
    result.update(
        manifest=child,
        infrastructureFailures=[],
        injectedFault=None,
        planDigest=digest(plan),
    )
    # Complete locally divergent observations remain eligible for saved-reference comparison.
    result["stateValidation"] = False
    result["completed"] = False
    cases = {"manifest": child, "localObservations": result["rows"]}
    save(tmp_path / "cases.json", cases)
    save(tmp_path / "result.json", result)
    parent = {
        "executionCommit": "3" * 40,
        "artifactSha256": sha_file(artifact),
        "build": {
            "command": BUILD_COMMAND,
            "exitCode": 0,
            "artifactSha256": sha_file(artifact),
            "inputs": runtime_inputs(ROOT),
        },
        "partialResultSha256": sha_file(tmp_path / "cases.json"),
        "manifest": child,
        "localObservations": result["rows"],
        "productionExecuted": False,
        "recordingComplete": True,
        "stopReason": "child-completed",
        "ownedProcess": {"stopped": True, "listenersClosed": True},
    }
    parent["parentManifestSha256"] = digest(parent)
    save(tmp_path / "manifest.json", parent)
    save(
        tmp_path / "shadow-binding.json",
        {
            "bound": True,
            "sourceInputsBefore": source_inputs(),
            "sourceInputsAfter": source_inputs(),
            "childSourceInputs": source_inputs(),
            "supervisorManifestSha256": sha_file(tmp_path / "manifest.json"),
        },
    )
    return artifact


def test_local_bundle_preserves_complete_failed_semantics_and_refuses_tampering(
    tmp_path,
):
    from production import local_bundle

    directory = tmp_path / "local"
    artifact = local_fixture(directory)
    bundle = local_bundle(directory, artifact, "3" * 40)
    assert bundle["result"]["stateValidation"] is False
    artifact.write_bytes(b"different artifact")
    with pytest.raises(ValueError):
        local_bundle(directory, artifact, "3" * 40)


def test_frozen_receipt_requires_exact_reservation_and_manifest(tmp_path):
    import copy
    from production import SHARED_ROOT, envelope, validate_frozen
    from production_plan import production_plan

    receipt, inputs, _ = acquired_fixture(tmp_path)
    value, plan = inputs["permission"], inputs["plan"]
    allocation = production_plan(value["nonce"])
    claim = {
        "campaignId": allocation["campaignId"],
        "manifestDigest": digest(manifest()),
        "nonceDigest": digest(value["nonce"]),
        "gatePath": str(tmp_path / "gate"),
        "gatePlanDigest": digest(plan),
        "locks": allocation["resourceLocks"],
        "budget": {
            "requests": 40,
            "accounts": 0,
            "resources": 4,
            "costMicrousd": 44000,
        },
        "durationSeconds": 960,
    }
    approved_envelope = envelope(value, claim["locks"])
    ticket = {
        "ledgerPath": str(SHARED_ROOT.resolve()),
        "ledgerIdentity": value["ledgerIdentity"],
        "claimDigest": digest(claim),
        "envelopeDigest": digest(approved_envelope),
        "reservation": "a" * 64,
    }
    inputs.update(
        reservationClaim=claim,
        reservationTicket=ticket,
        envelope=approved_envelope,
        manifest=manifest(),
        comparisonContract=contract(),
    )
    receipt.update(
        reservationReleased=True,
        reservationFinal={
            "claim": claim,
            "claimDigest": digest(claim),
            "envelopeDigest": digest(approved_envelope),
            "state": "released",
            "finalGateDigest": digest(receipt["gate"]),
        },
    )
    validate_frozen(inputs, receipt)
    for field in (
        "ledgerPath",
        "ledgerIdentity",
        "claimDigest",
        "envelopeDigest",
        "reservation",
    ):
        changed = copy.deepcopy(inputs)
        changed["reservationTicket"][field] = "wrong"
        with pytest.raises(ValueError):
            validate_frozen(changed, receipt)
    changed = copy.deepcopy(inputs)
    changed["reservationClaim"]["locks"].pop()
    with pytest.raises(ValueError):
        validate_frozen(changed, receipt)


def test_exclusive_comparison_save_never_overwrites_inputs(tmp_path):
    from shadow import save

    original = tmp_path / "receipt.json"
    save(original, {"historical": True})
    before = original.read_bytes()
    link = tmp_path / "link.json"
    link.symlink_to(original)
    for path in (original, link):
        with pytest.raises(FileExistsError):
            save(path, {"classification": "MATCH"})
    assert original.read_bytes() == before


def test_incomplete_comparison_is_indeterminate_and_cannot_overwrite_receipt(tmp_path):
    from production import compare
    from shadow import save

    directory = tmp_path / "production"
    directory.mkdir()
    save(directory / "inputs.json", {})
    save(directory / "receipt.json", {"recordingComplete": False})
    before = (directory / "receipt.json").read_bytes()
    result = compare(
        directory,
        tmp_path / "missing-local",
        tmp_path / "missing-artifact",
        tmp_path / "comparison.json",
    )
    assert result["classification"] == "INDETERMINATE"
    assert result["acquisitionValidated"] is False
    with pytest.raises(FileExistsError):
        compare(
            directory,
            tmp_path / "missing-local",
            tmp_path / "missing-artifact",
            directory / "receipt.json",
        )
    assert (directory / "receipt.json").read_bytes() == before


def test_admission_failure_keeps_immutable_sanitized_recovery_record(tmp_path):
    import json

    from production import admission_journal

    inputs = {"reservationTicket": {"reservation": "owned-ticket"}}
    with pytest.raises(ValueError), admission_journal(tmp_path, inputs):
        raise ValueError("credential-like text must not enter evidence")
    record = json.loads((tmp_path / "admission-failure.json").read_text())
    assert record["productionExecuted"] is False
    assert record["reservationReleased"] is False
    assert record["recoveryRequired"] is True
    assert record["failure"] == "ValueError"
    assert record["inputsDigest"] == digest(inputs)
    assert "credential-like" not in (tmp_path / "admission-failure.json").read_text()
    before = (tmp_path / "admission-failure.json").read_bytes()
    with pytest.raises(RuntimeError) as failure, admission_journal(tmp_path, inputs):
        raise RuntimeError("later failure")
    assert isinstance(failure.value.__cause__, FileExistsError)
    assert (tmp_path / "admission-failure.json").read_bytes() == before
