"""Offline communication fixtures through real permission, Gate and Ledger paths."""

import copy
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import batch_adapter
import commit_acquisition as acquisition
import commit_reserved_adapter as reserved
from batch_contract import DATABASE_PROJECTION, NUMBER, PROJECT
from broad_contract import digest
from commit_reserved_adapter import ROOT, source_inputs
from gate_adapter import compiler_plan
from reservations import Ledger
from test_transform_comparator import _recovery_rows, _rows


def fixture(tmp_path, monkeypatch):
    assert hasattr(acquisition, "freeze_inputs"), "file-bound admission missing"
    source = tmp_path / "source"
    source.mkdir()
    for name in source_inputs():
        target = source / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / name).read_bytes())
    for args in (
        ["init", "-q"],
        ["add", "."],
        [
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ],
    ):
        subprocess.run(["git", "-C", str(source), *args], check=True)
    commit = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
    ).strip()
    artifact = tmp_path / "artifact"
    artifact.write_bytes(b"offline retained artifact")
    plan = compiler_plan(PROJECT, "(default)", "a" * 32)
    database = {
        "name": f"projects/{PROJECT}/databases/(default)",
        "uid": "fixture",
        "type": "FIRESTORE_NATIVE",
        "databaseEdition": "STANDARD",
        "locationId": "us-central1",
    }
    adc = {
        "type": "authorized_user",
        "client_id": "offline-client",
        "client_secret": "offline-secret",
        "refresh_token": "offline-refresh",
    }
    permission = {
        **acquisition.permission_bindings(
            plan,
            commit,
            hashlib.sha256(artifact.read_bytes()).hexdigest(),
            source_inputs(),
        ),
        "authorizedUserDigest": digest(adc),
        "apiKeyDigest": digest("offline-key"),
        "credentialPrincipal": {
            "clientId": "offline-client",
            "requiredScopes": ["https://www.googleapis.com/auth/cloud-platform"],
        },
        "issuedAt": time.time() - 1,
        "expiresAt": time.time() + 2400,
        "ownerIdentity": "offline-fixture-not-permission",
        "permissionReference": "offline-fixture",
        "recoveryOwner": "offline-recovery",
        "authConfigDigest": digest({"name": "fixture-auth"}),
        "databaseProjection": database,
        "databaseProjectionDigest": digest(database),
        "databaseProjectionContractDigest": digest(DATABASE_PROJECTION),
        "pricingLocation": "us-central1",
        "pricingCheckedAt": "fixture-only",
    }
    permission_path = tmp_path / "permission.json"
    permission_path.write_text(json.dumps(permission))
    inputs = acquisition.freeze_inputs(
        permission_path, plan, source_root=source, artifact_path=artifact
    )
    ledger = Ledger.create(tmp_path / "shared")
    calls = []
    original_run = subprocess.run

    def command(args, **kwargs):
        if args == ["gcloud", "auth", "application-default", "print-access-token"]:
            pytest.fail("gcloud credential acquisition is not bounded OAuth")
        return original_run(args, **kwargs)

    def metadata(url, method, body, headers, **kwargs):
        assert method == "GET"
        assert body is None
        assert headers["Content-Type"] == "application/json"
        assert headers["Authorization"] == "Bearer offline-token"
        assert headers["x-goog-user-project"] == PROJECT
        if "tokeninfo" in url:
            calls.append("tokeninfo")
            return 200, {"expires_in": "3600"}, "application/json"
        if "cloudresourcemanager" in url:
            action, response = (
                "project",
                {"projectId": PROJECT, "projectNumber": NUMBER},
            )
        elif "firestore" in url:
            action, response = "database", database
        elif "apikeys" in url:
            action, response = (
                "key",
                {
                    "parent": f"projects/{NUMBER}/locations/global",
                    "name": f"projects/{NUMBER}/locations/global/keys/fixture",
                },
            )
        else:
            action, response = "auth", {"name": "fixture-auth"}
        calls.append(action)
        return 200, response, "application/json"

    assert hasattr(reserved, "credential_preparation"), (
        "bounded OAuth preparation missing"
    )

    def oauth(slot, secret, **options):
        calls.append(slot)
        body = (
            {
                "access_token": "offline-token",
                "token_type": "Bearer",
                "expires_in": 3600,
            }
            if slot == "refresh"
            else {
                "issued_to": "offline-client",
                "scope": "https://www.googleapis.com/auth/cloud-platform",
                "expires_in": 3600,
            }
        )
        return {
            "complete": True,
            "status": 200,
            "workerReaped": True,
            "receivedBytes": 100,
            "body": body,
        }

    monkeypatch.setattr(reserved.credential_preparation, "_private_request", oauth)
    monkeypatch.setattr(batch_adapter.subprocess, "run", command)
    monkeypatch.setattr(batch_adapter, "wire", metadata)
    rows = {"observation": _rows(plan), "recovery": _recovery_rows(plan)}

    def transmit(value):
        calls.append(value["phase"])
        row = rows[value["phase"]][value["index"]]
        return {
            key: copy.deepcopy(row[key])
            for key in ("complete", "failure", "status", "body")
        }

    kwargs = {
        "permission_path": permission_path,
        "source_root": source,
        "artifact_path": artifact,
        "ledger_root": ledger.path,
        "api_key": "offline-key",
        "credential_handoff": {
            "kind": "commit-authorized-user-v1",
            "permissionDigest": digest(permission),
            "apiKey": "offline-key",
            "adc": adc,
        },
        "injected_transport": transmit,
    }
    return inputs, ledger, calls, kwargs


def test_real_admission_charges_metadata_around_collection_and_releases(
    tmp_path, monkeypatch
):
    inputs, ledger, calls, kwargs = fixture(tmp_path, monkeypatch)
    result = acquisition.run_acquisition(tmp_path / "output", inputs, **kwargs)
    assert result["failure"] is None
    assert calls == [
        "refresh",
        "tokeninfo",
        "project",
        "database",
        "auth",
        "key",
    ] + ["observation"] * 11 + ["recovery"] * 6 + ["project", "database", "auth", "key"]
    assert result["chargedCalls"] == 27
    assert result["productionExecuted"] is False
    assert result["executionKind"] == "injected-transport"
    assert result["workerArchiveSha256"] is None
    assert result["reservationReleased"] is True
    assert (
        ledger.snapshot()["reservations"][result["ticket"]["reservation"]]["state"]
        == "released"
    )
    assert result["collection"]["collectionComplete"] is True
    for index in (1, 4):
        entry = result["collection"]["cleanup"][index]
        assert entry["request"]["versionFrom"] == index - 1
        assert "versionFrom" not in entry["wireRequest"]
        assert "currentDocument.updateTime=" in entry["wireRequest"]["path"]
    assert (
        json.loads((tmp_path / "output/receipt.json").read_text())[
            "reservationStateAtPublication"
        ]
        == "held"
    )
    assert (
        json.loads((tmp_path / "output/release.json").read_text())["reservationFinal"][
            "state"
        ]
        == "released"
    )
    with pytest.raises(ValueError):
        acquisition.run_acquisition(tmp_path / "again", inputs, **kwargs)


@pytest.mark.parametrize(
    "field", ["ownerIdentity", "nonce", "project", "sourceInputs", "artifactSha256"]
)
def test_independent_permission_and_source_rebinding_rejected_before_io(
    tmp_path, monkeypatch, field
):
    inputs, ledger, calls, kwargs = fixture(tmp_path, monkeypatch)
    inputs = copy.deepcopy(inputs)
    inputs["permission"][field] = "rebound"
    inputs["permissionDigest"] = digest(inputs["permission"])
    inputs["inputsDigest"] = digest(
        {k: v for k, v in inputs.items() if k != "inputsDigest"}
    )
    with pytest.raises(ValueError):
        acquisition.run_acquisition(tmp_path / "output", inputs, **kwargs)
    assert calls == []
    assert ledger.snapshot()["reservations"] == {}


@pytest.mark.parametrize(
    "failure", ["postflight", "receipt-exists", "incomplete", "uncertain-owner"]
)
def test_failures_keep_shared_responsibility_and_never_replace_receipts(
    tmp_path, monkeypatch, failure
):
    inputs, ledger, calls, kwargs = fixture(tmp_path, monkeypatch)
    output = tmp_path / "output"
    metadata = batch_adapter.wire
    wire = kwargs["injected_transport"]
    data_kinds = []

    def metadata_failure(*args, **options):
        if (
            failure == "postflight"
            and calls.count("project") == 1
            and "cloudresourcemanager" in args[0]
        ):
            raise ValueError("offline postflight failure")
        return metadata(*args, **options)

    def data(value):
        data_kinds.append(value["operation"]["kind"])
        if (
            failure == "receipt-exists"
            and value["phase"] == "observation"
            and value["index"] == 0
        ):
            (output / "receipt.json").write_text("occupied\n")
        result = wire(value)
        if failure == "incomplete" and value["operation"]["kind"] == "commit-transform":
            return {"complete": False, "failure": "offline-timeout"}
        if (
            failure == "uncertain-owner"
            and value["operation"]["kind"] == "cleanup-ownership-read"
        ):
            result["body"]["fields"]["_sharedOwner"] = {"referenceValue": "foreign"}
        return result

    kwargs["injected_transport"] = data
    monkeypatch.setattr(batch_adapter, "wire", metadata_failure)
    result = acquisition.run_acquisition(output, inputs, **kwargs)
    assert result["reservationReleased"] is False
    state = ledger.snapshot()["reservations"][result["ticket"]["reservation"]]
    assert state["state"] == "held"
    assert not (output / "release.json").exists()
    if failure == "receipt-exists":
        assert (output / "receipt.json").read_text() == "occupied\n"
        assert (
            json.loads((output / "failure.json").read_text())["releaseEligible"]
            is False
        )
    if failure == "uncertain-owner":
        assert "cleanup-conditional-delete" not in data_kinds


def test_saved_comparison_is_frozen_and_credential_free(tmp_path, monkeypatch):
    inputs, _, _, kwargs = fixture(tmp_path, monkeypatch)
    output = tmp_path / "output"
    result = acquisition.run_acquisition(output, inputs, **kwargs)
    assert result["reservationReleased"] is True
    assert hasattr(acquisition, "compare_saved"), "saved evidence validation missing"
    reference = tmp_path / "reference.json"
    reference.write_text(
        json.dumps(
            {
                "plan": inputs["plan"],
                "rows": _rows(inputs["plan"]),
                "cleanup": _recovery_rows(inputs["plan"]),
            }
        )
    )
    monkeypatch.setattr(
        batch_adapter,
        "wire",
        lambda *_a, **_k: pytest.fail("saved comparison contacted wire"),
    )
    kwargs["permission_path"].unlink()
    kwargs["artifact_path"].unlink()
    with pytest.raises(ValueError, match="saved execution kind"):
        # An injected fixture must never pass as production evidence.
        acquisition.compare_saved(
            output, reference, expected_inputs_digest=inputs["inputsDigest"]
        )
    value = acquisition.compare_saved(
        output,
        reference,
        expected_inputs_digest=inputs["inputsDigest"],
        expected_execution_kind="injected-transport",
    )
    assert value["classification"] == "MATCH"
    assert value["acquisitionValidated"] is False
    assert value["executionKind"] == "injected-transport"
    assert value["productionExecuted"] is False
    receipt_path, release_path = output / "receipt.json", output / "release.json"
    original_receipt, original_release = (
        receipt_path.read_text(),
        release_path.read_text(),
    )
    for release_reference in (None, "alternate-release.json", "../release.json"):
        receipt, release = json.loads(original_receipt), json.loads(original_release)
        receipt["releaseRecord"] = release_reference
        # Rebind the link so this tests the fixed filename contract itself.
        release["receiptDigest"] = digest(receipt)
        receipt_path.write_text(json.dumps(receipt))
        release_path.write_text(json.dumps(release))
        with pytest.raises(ValueError, match="saved acquisition binding incomplete"):
            acquisition.compare_saved(
                output,
                tmp_path / "reference.json",
                expected_inputs_digest=inputs["inputsDigest"],
                expected_execution_kind="injected-transport",
            )
    receipt_path.write_text(original_receipt)
    release_path.write_text(original_release)
    journal_path = output / "coordinator/oauth-refresh-receipt.json"
    original_journal = journal_path.read_text()
    journal_path.write_text("{}")
    with pytest.raises(ValueError):
        acquisition.compare_saved(
            output,
            reference,
            expected_inputs_digest=inputs["inputsDigest"],
            expected_execution_kind="injected-transport",
        )
    journal_path.write_text(original_journal)
    (output / "transform_comparator.py").write_text("raise RuntimeError('changed')")
    with pytest.raises(ValueError):
        acquisition.compare_saved(
            output,
            reference,
            expected_inputs_digest=inputs["inputsDigest"],
            expected_execution_kind="injected-transport",
        )


@pytest.mark.parametrize("drift", ["permission", "artifact", "source"])
def test_live_frozen_file_drift_blocks_the_next_wire_call(tmp_path, monkeypatch, drift):
    inputs, ledger, calls, kwargs = fixture(tmp_path, monkeypatch)
    original = kwargs["injected_transport"]

    def transmit(value):
        response = original(value)
        if value["phase"] == "observation" and value["index"] == 0:
            if drift == "permission":
                path = kwargs["permission_path"]
                permission = json.loads(path.read_text())
                permission["ownerIdentity"] = "rebound"
                path.write_text(json.dumps(permission))
            elif drift == "artifact":
                kwargs["artifact_path"].write_bytes(b"changed artifact")
            else:
                (
                    kwargs["source_root"]
                    / "tools/compat-broad/fs-commit-transform-limits/transform_compiler.py"
                ).write_text("changed source")
        return response

    kwargs["injected_transport"] = transmit
    result = acquisition.run_acquisition(tmp_path / "output", inputs, **kwargs)
    assert calls.count("observation") == 1
    assert calls.count("recovery") == 0
    assert result["reservationReleased"] is False
    assert (
        ledger.snapshot()["reservations"][result["ticket"]["reservation"]]["state"]
        == "held"
    )


@pytest.mark.parametrize(
    "failure", ["refresh-incomplete", "wrong-principal", "missing-scope"]
)
def test_bounded_oauth_failure_keeps_reservation_without_data(
    tmp_path, monkeypatch, failure
):
    inputs, ledger, calls, kwargs = fixture(tmp_path, monkeypatch)
    original = reserved.credential_preparation._private_request

    def oauth(slot, secret, **options):
        result = original(slot, secret, **options)
        if slot == "refresh" and failure == "refresh-incomplete":
            return {"complete": False, "workerReaped": True, "status": None}
        if slot == "tokeninfo" and failure == "wrong-principal":
            result["body"]["issued_to"] = "foreign-client"
        if slot == "tokeninfo" and failure == "missing-scope":
            result["body"]["scope"] = "unrelated"
        return result

    monkeypatch.setattr(reserved.credential_preparation, "_private_request", oauth)
    result = acquisition.run_acquisition(tmp_path / "output", inputs, **kwargs)
    assert result["reservationReleased"] is False
    assert calls in (["refresh"], ["refresh", "tokeninfo"])
    assert (
        ledger.snapshot()["reservations"][result["ticket"]["reservation"]]["state"]
        == "held"
    )
    assert result["credentialEvidence"][-1]["verified"] is False


def test_retained_comparator_evidence_comes_from_the_frozen_checkout(tmp_path):
    """Evidence bytes must be read from source_root, not from this module's tree."""
    names = ("transform_comparator.py", "transform_compiler.py")
    checkout = tmp_path / "checkout"
    frozen = {}
    for name in names:
        relative = f"tools/compat-broad/fs-commit-transform-limits/{name}"
        target = checkout / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        # Deliberately different from the bytes next to commit_acquisition.py.
        data = f"# frozen checkout copy of {name}\n".encode()
        target.write_bytes(data)
        frozen[relative] = hashlib.sha256(data).hexdigest()
    output = tmp_path / "evidence"
    output.mkdir()
    acquisition._copy_frozen_sources(output, checkout, frozen)
    for name in names:
        relative = f"tools/compat-broad/fs-commit-transform-limits/{name}"
        written = (output / name).read_bytes()
        assert written == (checkout / relative).read_bytes()
        assert written != (acquisition.HERE / name).read_bytes()
        assert hashlib.sha256(written).hexdigest() == frozen[relative]
    drifted = dict(frozen)
    drifted[f"tools/compat-broad/fs-commit-transform-limits/{names[0]}"] = "0" * 64
    second = tmp_path / "evidence-drift"
    second.mkdir()
    with pytest.raises(ValueError, match="comparator source"):
        acquisition._copy_frozen_sources(second, checkout, drifted)
