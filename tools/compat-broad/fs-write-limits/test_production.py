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


def acquired_fixture(tmp_path, *, mismatch=False, commit=None, artifact_hash=None):
    """Real Gate transitions around finite in-memory wire fixtures, never a cloud receipt."""
    import time
    from compiler import compile_limits_plan
    from collector import collect
    from production_bridge import LimitsGate, bind_wire, execution_plan
    from shared_gate import create
    from shared_production import Coordinator

    value = permission()
    value.update(issuedAt=time.time() - 1, expiresAt=time.time() + 2000)
    value["frozenCommit"] = commit or value["frozenCommit"]
    value["artifactSha256"] = artifact_hash or value["artifactSha256"]
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
    inputs = {
        "permission": value,
        "plan": plan,
        "sourceCommit": value["frozenCommit"],
        "artifactSha256": value["artifactSha256"],
        "localBundleDigest": value["localBundleDigest"],
        "admittedAt": value["issuedAt"] + 1,
    }
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
    receipt.update(
        kind="fs-write-limits-production-receipt-v2",
        acquisitionValidated=True,
        finalBinding={
            "sourceCommit": inputs["sourceCommit"],
            "dirty": False,
            "artifactSha256": inputs["artifactSha256"],
            "collectorSourceDigest": value["collectorSourceDigest"],
            "captureFailures": {},
        },
    )
    bind_frozen_fixture(tmp_path, receipt, inputs)
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


def local_fixture(tmp_path, *, commit="3" * 40):
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
        "executionCommit": commit,
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


def bind_frozen_fixture(tmp_path, receipt, inputs):
    from production import SHARED_ROOT, envelope
    from production_plan import production_plan

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
    receipt["inputsDigest"] = digest(inputs)


def test_frozen_receipt_requires_exact_reservation_and_manifest(tmp_path):
    import copy
    from production import validate_frozen

    receipt, inputs, _ = acquired_fixture(tmp_path)
    bind_frozen_fixture(tmp_path, receipt, inputs)
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


@pytest.mark.parametrize("failure", ["ValueError", None, "", False])
def test_saved_acquisition_failure_is_permanent_even_with_true_marker(
    tmp_path, failure
):
    from production import validate_acquisition

    receipt, inputs, _ = acquired_fixture(tmp_path)
    receipt.update(acquisitionValidated=True, acquisitionFailure=failure)
    with pytest.raises(ValueError):
        validate_acquisition(receipt, inputs)


@pytest.mark.parametrize(
    "field,value",
    [
        ("sourceCommit", "0" * 40),
        ("dirty", True),
        ("dirty", 0),
        ("artifactSha256", "0" * 64),
        ("collectorSourceDigest", "0" * 64),
        ("captureFailures", {"artifactSha256": "OSError"}),
    ],
)
def test_saved_v2_requires_exact_final_observations(tmp_path, field, value):
    from production import validate_acquisition

    receipt, inputs, _ = acquired_fixture(tmp_path)
    receipt["finalBinding"][field] = value
    with pytest.raises(ValueError):
        validate_acquisition(receipt, inputs)


@pytest.mark.parametrize(
    "mutation", ["missing-binding", "unvalidated", "unreleased", "legacy", "wrong-gate"]
)
def test_saved_receipt_requires_validated_v2_and_released_final_gate(
    tmp_path, mutation
):
    from production import validate_acquisition

    receipt, inputs, _ = acquired_fixture(tmp_path)
    if mutation == "missing-binding":
        del receipt["finalBinding"]
    elif mutation == "unvalidated":
        receipt["acquisitionValidated"] = False
    elif mutation == "unreleased":
        receipt["reservationReleased"] = False
    elif mutation == "legacy":
        receipt["kind"] = "fs-write-limits-production-receipt-v1"
    else:
        receipt["reservationFinal"]["finalGateDigest"] = "0" * 64
    with pytest.raises(ValueError):
        validate_acquisition(receipt, inputs)


@pytest.mark.parametrize("drift", [None, "artifact", "checkout", "missing-artifact"])
def test_finalization_persists_actual_facts_before_drift_is_restored(tmp_path, drift):
    import subprocess
    from production import (
        finalize_acquisition,
        sha_file,
        validate_acquisition,
        compare,
        comparison_local_bundle,
        frozen_checkout,
        load,
    )
    from shadow import save

    checkout = tmp_path / "checkout"
    checkout.mkdir()
    subprocess.run(["git", "init", "-q", str(checkout)], check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "--allow-empty",
            "-qm",
            "fixture",
        ],
        cwd=checkout,
        check=True,
    )
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=checkout, text=True
    ).strip()
    try:
        local_commit = frozen_checkout()
    except ValueError:
        pytest.skip("current-source comparison requires a committed clean checkout")
    local_directory = tmp_path / "local"
    artifact = local_fixture(local_directory, commit=local_commit)
    admitted_artifact = artifact.read_bytes()
    receipt, inputs, _ = acquired_fixture(
        tmp_path, commit=commit, artifact_hash=sha_file(artifact)
    )
    receipt["acquisitionValidated"] = False
    if drift == "artifact":
        artifact.write_bytes(b"final drift")
    elif drift == "checkout":
        (checkout / "unexpected").write_text("dirty")
    elif drift == "missing-artifact":
        artifact.unlink()
    finalize_acquisition(receipt, inputs, artifact, checkout_root=checkout)
    assert receipt["reservationReleased"] is True
    artifact.write_bytes(admitted_artifact)
    if drift == "checkout":
        (checkout / "unexpected").unlink()
    if drift is None:
        assert receipt["acquisitionValidated"] is True
        assert "acquisitionFailure" not in receipt
        validate_acquisition(receipt, inputs)
    else:
        assert receipt["acquisitionValidated"] is False
        assert receipt["acquisitionFailure"]
        with pytest.raises(ValueError):
            validate_acquisition(receipt, inputs)
    # Restoration leaves a completely valid downstream local bundle. The success
    # case traverses the same comparator, so missing local inputs cannot explain
    # the failed cases' INDETERMINATE results.
    comparison_local_bundle(local_directory, artifact)
    directory = tmp_path / "production"
    directory.mkdir()
    save(directory / "inputs.json", inputs)
    save(directory / "receipt.json", receipt)
    result = compare(directory, local_directory, artifact, tmp_path / "comparison.json")
    assert result["acquisitionValidated"] is (drift is None)
    assert (result["classification"] == "INDETERMINATE") is (drift is not None)
    import sys
    from pathlib import Path

    sys.path.insert(
        0, str(Path(__file__).resolve().parent.parent / "fs-write-limits-recompare")
    )
    from recompare import recompare

    derived = recompare(directory, local_directory, artifact, tmp_path / "derived")
    binding = load(tmp_path / "derived/binding.json")
    assert binding["acquisitionValidated"] is (drift is None)
    assert (derived["classification"] == "INDETERMINATE") is (drift is not None)
    final = receipt["finalBinding"]
    assert final["sourceCommit"] == commit
    assert final["dirty"] is (drift == "checkout")
    if drift == "artifact":
        assert final["artifactSha256"] != inputs["artifactSha256"]
    if drift == "missing-artifact":
        assert final["artifactSha256"] is None
        assert final["captureFailures"] == {"artifactSha256": "FileNotFoundError"}


def test_new_local_bundle_uses_current_strict_validator_when_checkout_is_frozen(
    tmp_path,
):
    from production import comparison_local_bundle, frozen_checkout

    try:
        commit = frozen_checkout()
    except ValueError:
        pytest.skip("current-source comparison requires a committed clean checkout")
    artifact = local_fixture(tmp_path / "local", commit=commit)
    result = comparison_local_bundle(tmp_path / "local", artifact)
    assert result["result"]["recordingComplete"] is True
    artifact.write_bytes(b"tampered")
    with pytest.raises(ValueError):
        comparison_local_bundle(tmp_path / "local", artifact)
