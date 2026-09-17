"""File-bound outer Commit acquisition; no production command-line entrypoint.

The caller supplies an independent owner permission, retained artifact, clean
source snapshot and existing shared Ledger. Injectable communication is only a
transport boundary; it cannot replace permission, reservations or Gate charging.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/production-admission"))

from batch_contract import DATABASE_PROJECTION, NUMBER, PROJECT, validate_owner_baseline
from broad_contract import digest
from commit_production import _save, collect_commit
from commit_remote_transport import request as remote_request
from commit_reserved_adapter import (
    CommitReservedCoordinator,
    credential_preparation,
    source_digest,
    source_inputs,
    validate_handoff,
)
from gate_adapter import (
    compiler_plan,
    create_production_commit_gate,
    production_cost_model,
    production_gate_plan,
)
from reservations import Ledger

DATA_REQUESTS = 17
METADATA_ACTIONS = ("project", "database", "auth", "key")
BUDGET = {
    "requests": 27,
    "accounts": 0,
    "resources": 2,
    "costMicrousd": production_cost_model()["totalCostMicrousd"],
}


def _read(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 8 * 1024 * 1024:
        raise ValueError("bounded regular input file required")
    return json.loads(path.read_bytes())


def _artifact(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
        raise ValueError("retained regular artifact required")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _provenance(source_root, expected_commit, expected_inputs):
    source_root = Path(source_root).resolve()

    def git(*args):
        return subprocess.check_output(["git", "-C", str(source_root), *args])

    if (
        git("rev-parse", "HEAD").decode().strip() != expected_commit
        or git("status", "--porcelain", "--untracked-files=all").strip()
        or expected_inputs != source_inputs()
    ):
        raise ValueError("clean frozen source snapshot required")
    for name, sha in expected_inputs.items():
        path = source_root / name
        if path.is_symlink() or not path.is_file() or _artifact(path) != sha:
            raise ValueError("source input differs")
        if hashlib.sha256(git("show", f"{expected_commit}:{name}")).hexdigest() != sha:
            raise ValueError("source input not in frozen commit")


def permission_bindings(plan, source_commit, artifact_digest, inputs):
    """Required non-authorizing fields for an independently supplied permission."""
    if digest(plan) != digest(compiler_plan(PROJECT, "(default)", plan["nonce"])):
        raise ValueError("fixed production project/database required")
    return {
        "kind": "commit-owner-execution-permission-v1",
        "project": PROJECT,
        "projectNumber": NUMBER,
        "quotaProject": PROJECT,
        "database": "(default)",
        "nonce": plan["nonce"],
        "planDigest": digest(plan),
        "sourceCommit": source_commit,
        "sourceInputs": inputs,
        "collectorSourceDigest": digest(inputs),
        "artifactSha256": artifact_digest,
        "comparatorSha256": inputs[
            "tools/compat-broad/fs-commit-transform-limits/transform_comparator.py"
        ],
        "budget": BUDGET,
        "wallSeconds": 1200,
        "recoverySeconds": 180,
        "concurrency": 1,
        "retentionHours": 24,
        "tariffsConfirmedBelowPlanningCeilings": True,
        "costModel": production_cost_model(),
        "credentialMode": "commit-bounded-authorized-user-v1",
        "credentialPreparationSha256": inputs[
            "tools/compat-broad/fs-write-txn/credential_prep.py"
        ],
        "databaseProjectionContractDigest": digest(DATABASE_PROJECTION),
    }


def _approve(permission, plan, source_commit, artifact_digest, inputs):
    required = permission_bindings(plan, source_commit, artifact_digest, inputs)
    validate_owner_baseline(permission, required, time.time())
    credential_preparation.validate_principal(permission.get("credentialPrincipal"))
    if digest({key: permission.get(key) for key in required}) != digest(required):
        raise ValueError("typed owner permission binding differs")
    if (
        not isinstance(permission.get("recoveryOwner"), str)
        or not permission["recoveryOwner"].strip()
    ):
        raise ValueError("independent recovery owner required")


def freeze_inputs(permission_path, plan, *, source_root, artifact_path):
    """Freeze independently read permission and verified on-disk source/artifact."""
    permission = _read(permission_path)
    inputs = source_inputs()
    commit = subprocess.check_output(
        ["git", "-C", str(source_root), "rev-parse", "HEAD"], text=True
    ).strip()
    artifact = _artifact(artifact_path)
    _provenance(source_root, commit, inputs)
    _approve(permission, plan, commit, artifact, inputs)
    value = {
        "kind": "commit-frozen-inputs-v2",
        "permission": permission,
        "permissionDigest": digest(permission),
        "plan": copy.deepcopy(plan),
        "planDigest": digest(plan),
        "sourceCommit": commit,
        "sourceInputs": inputs,
        "artifactSha256": artifact,
        "bounds": {
            "dataRequests": 17,
            "metadataRequests": 8,
            "credentialRequests": 2,
            "totalRequests": 27,
        },
    }
    value["inputsDigest"] = digest(value)
    return value


def _validate(inputs, permission_path, source_root, artifact_path):
    if inputs.get("inputsDigest") != digest(
        {k: v for k, v in inputs.items() if k != "inputsDigest"}
    ):
        raise ValueError("frozen inputs differ")
    permission = _read(permission_path)
    if digest(permission) != inputs["permissionDigest"] or digest(permission) != digest(
        inputs["permission"]
    ):
        raise ValueError("independent permission differs")
    expected = freeze_inputs(
        permission_path,
        inputs["plan"],
        source_root=source_root,
        artifact_path=artifact_path,
    )
    if digest(inputs) != digest(expected):
        raise ValueError("frozen binding differs")


def _validate_live(inputs, permission_path, source_root, artifact_path):
    if (
        digest(_read(permission_path)) != inputs["permissionDigest"]
        or _artifact(artifact_path) != inputs["artifactSha256"]
    ):
        raise ValueError("live permission or artifact differs")
    for name, expected in inputs["sourceInputs"].items():
        if _artifact(Path(source_root) / name) != expected:
            raise ValueError("live source input differs")
    head = subprocess.check_output(
        ["git", "-C", str(source_root), "rev-parse", "HEAD"], text=True
    ).strip()
    dirty = subprocess.check_output(
        [
            "git",
            "-C",
            str(source_root),
            "status",
            "--porcelain",
            "--untracked-files=all",
        ]
    )
    if head != inputs["sourceCommit"] or dirty.strip():
        raise ValueError("live source snapshot differs")


def _locks(plan):
    scope = f"project/{PROJECT}"
    firestore = f"{scope}/firestore/(default)"
    return [
        {
            "key": f"{firestore}/documents/oracle/{plan['nonce']}/commit-limits-03/*",
            "mode": "WRITE",
        },
        *[
            {"key": f"{firestore}/{kind}", "mode": "READ"}
            for kind in ("indexes", "ruleset", "database")
        ],
        {"key": f"{scope}/auth/config", "mode": "READ"},
        {"key": f"{scope}/api-key-binding", "mode": "READ"},
    ]


def run_acquisition(
    output,
    inputs,
    *,
    permission_path,
    source_root,
    artifact_path,
    ledger_root,
    api_key,
    credential_handoff,
    transmit,
):
    """Run an admitted acquisition. There is deliberately no implicit wire/ADC call.

    A production caller must explicitly bind the fixed remote_request function;
    every other callback is labeled injected transport, never production evidence.
    """
    inputs = copy.deepcopy(inputs)
    _validate(inputs, permission_path, source_root, artifact_path)
    validate_handoff(credential_handoff, inputs["permission"], api_key)
    ledger = Ledger(ledger_root)
    permission, plan = (
        copy.deepcopy(inputs["permission"]),
        copy.deepcopy(inputs["plan"]),
    )
    output = Path(output)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    _save(output / "inputs.json", inputs)
    for name in ("transform_comparator.py", "transform_compiler.py"):
        with (output / name).open("xb") as stream:
            stream.write((HERE / name).read_bytes())
            stream.flush()
            os.fsync(stream.fileno())
    binding = {
        "permissionDigest": inputs["permissionDigest"],
        "collectorSourceDigest": source_digest(),
    }
    projected = production_gate_plan(plan, binding)
    locks = _locks(plan)
    envelope = {
        "permissionDigest": inputs["permissionDigest"],
        "issuedAt": permission["issuedAt"],
        "expiresAt": permission["expiresAt"],
        "limits": copy.deepcopy(BUDGET),
        "concurrency": 1,
        "scopes": locks,
    }
    claim = {
        "campaignId": plan["campaignId"],
        "manifestDigest": inputs["planDigest"],
        "nonceDigest": digest(plan["nonce"]),
        "gatePath": str((output / "gate").resolve()),
        "gatePlanDigest": digest(projected),
        "locks": locks,
        "budget": copy.deepcopy(BUDGET),
        "durationSeconds": 1200,
    }
    ticket = ledger.reserve(envelope, claim, projected)
    gate = coordinator = collection = None
    failure = None
    postflight = False
    wire_ran = False
    try:
        gate = create_production_commit_gate(output / "gate", plan, binding)
        gate.claim()
        coordinator = CommitReservedCoordinator(
            permission,
            plan["nonce"],
            output / "coordinator",
            gate,
            api_key,
            ledger=ledger,
            ticket=ticket,
            credential_handoff=credential_handoff,
            binding_check=lambda: _validate_live(
                inputs, permission_path, source_root, artifact_path
            ),
        )
        coordinator.acquire()
        coordinator.preflight()

        def wire(value):
            nonlocal wire_ran
            wire_ran = True
            return transmit(value)

        collection = collect_commit(
            gate, plan, output / "collection", transmit=coordinator.bind_wire(wire)
        )
        coordinator.budget.recovery = True
        coordinator.recover_credentials()
        coordinator.preflight()
        postflight = True
        _validate(inputs, permission_path, source_root, artifact_path)
    except Exception as error:  # noqa: BLE001 -- sanitized receipt; retain ownership
        failure = type(error).__name__
    snapshot = gate.snapshot() if gate is not None else None
    ready = (
        failure is None
        and postflight
        and collection is not None
        and collection["collectionComplete"]
    )
    receipt = {
        "kind": "commit-acquisition-receipt-v2",
        "inputsDigest": inputs["inputsDigest"],
        "permissionDigest": inputs["permissionDigest"],
        "planDigest": digest(projected),
        "claimDigest": digest(claim),
        "collection": collection,
        "credentialEvidence": coordinator.credential_evidence if coordinator else [],
        "metadata": coordinator.metadata_evidence if coordinator else [],
        "ticket": ticket,
        "reservationStateAtPublication": "held",
        "releaseRecord": "release.json" if ready else None,
        "chargedCalls": snapshot["total"] if snapshot else 0,
        "gate": snapshot,
        "executionKind": "fixed-production-wire"
        if transmit is remote_request
        else "injected-transport",
        "productionExecuted": wire_ran and transmit is remote_request,
        "acquisitionValidated": False,
        "promotionReady": False,
        "failure": failure,
        "postflightComplete": postflight,
        "releaseEligible": ready,
    }
    try:
        _save(output / "receipt.json", receipt)
    except OSError as error:
        failure_receipt = {
            **receipt,
            "failure": f"receipt-persistence:{type(error).__name__}",
            "releaseEligible": False,
            "releaseRecord": None,
        }
        _save(output / "failure.json", failure_receipt)
        return {**failure_receipt, "reservationReleased": False}
    released = False
    release = None
    if ready:
        try:
            ledger.finish(ticket)
            released = True
        except Exception as error:  # noqa: BLE001 -- actual ledger state retained
            failure = type(error).__name__
        release = {
            "receiptDigest": digest(receipt),
            "ticket": ticket,
            "failure": failure,
            "reservationFinal": ledger.snapshot()["reservations"][
                ticket["reservation"]
            ],
        }
        _save(output / "release.json", release)
    return {
        **receipt,
        "failure": failure,
        "reservationReleased": released,
        "release": release,
    }


def compare_saved(output, reference_path, *, expected_inputs_digest):
    """Validate linked saved records and run only their source-frozen comparator.

    The caller supplies the independently retained frozen-input digest. This
    does not establish owner identity or turn transport fixtures into evidence.
    No current permission, checkout, artifact, credential or wire is consulted.
    """
    output = Path(output)
    inputs, receipt = _read(output / "inputs.json"), _read(output / "receipt.json")
    unsigned = {key: value for key, value in inputs.items() if key != "inputsDigest"}
    if (
        digest(unsigned) != expected_inputs_digest
        or inputs["inputsDigest"] != expected_inputs_digest
        or receipt["inputsDigest"] != expected_inputs_digest
        or receipt["permissionDigest"] != digest(inputs["permission"])
        or inputs["permissionDigest"] != digest(inputs["permission"])
        or receipt.get("releaseEligible") is not True
        or receipt.get("releaseRecord") != "release.json"
        or receipt.get("failure") is not None
        or receipt.get("chargedCalls") != 27
        or receipt.get("postflightComplete") is not True
        or [entry["id"] for entry in receipt["metadata"]]
        != [
            phase + ":" + action
            for phase in ("observation", "recovery")
            for action in METADATA_ACTIONS
        ]
        or any(entry["status"] != 200 for entry in receipt["metadata"])
    ):
        raise ValueError("saved acquisition binding incomplete")
    release = _read(output / "release.json")
    final = release["reservationFinal"]
    gate = receipt["gate"]
    if (
        release["receiptDigest"] != digest(receipt)
        or release["ticket"] != receipt["ticket"]
        or release.get("failure") is not None
        or final["state"] != "released"
        or final["finalGateDigest"] != digest(gate)
        or final["claimDigest"] != receipt["claimDigest"]
        or final["claim"]["gatePlanDigest"] != receipt["planDigest"]
        or digest(gate["plan"]) != receipt["planDigest"]
    ):
        raise ValueError("saved release binding incomplete")
    credential_evidence = receipt.get("credentialEvidence")
    if not isinstance(credential_evidence, list) or len(credential_evidence) != 2:
        raise ValueError("saved bounded credential evidence incomplete")
    for ordinal, slot in enumerate(("refresh", "tokeninfo"), 1):
        charge = _read(output / "coordinator" / f"oauth-{slot}-charge.json")
        evidence = _read(output / "coordinator" / f"oauth-{slot}-receipt.json")
        if (
            digest(evidence) != digest(credential_evidence[ordinal - 1])
            or evidence.get("chargeDigest") != digest(charge)
            or evidence.get("verified") is not True
            or evidence.get("workerReaped") is not True
            or evidence.get("complete") is not True
            or type(evidence.get("status")) is not int
            or evidence["status"] != 200
            or charge.get("ticketDigest") != digest(receipt["ticket"])
            or charge.get("permissionDigest") != inputs["permissionDigest"]
            or charge.get("ordinal") != ordinal
            or charge.get("slot") != slot
        ):
            raise ValueError("saved bounded credential journal differs")
    collection = _read(output / "collection/collection.json")
    if (
        digest(collection) != digest(receipt["collection"])
        or collection["collectionComplete"] is not True
    ):
        raise ValueError("saved collection differs")
    for phase, entries in (
        ("observation", collection["rows"]),
        ("recovery", collection["cleanup"]),
    ):
        for index, entry in enumerate(entries):
            if digest(
                _read(output / "collection" / f"{phase}-{index:02d}.json")
            ) != digest(entry):
                raise ValueError("saved row journal differs")
    for name in ("transform_compiler.py", "transform_comparator.py"):
        expected = inputs["sourceInputs"][
            f"tools/compat-broad/fs-commit-transform-limits/{name}"
        ]
        if _artifact(output / name) != expected:
            raise ValueError("saved comparator source differs")
    reference = _read(reference_path)
    script = (
        "import json,sys;sys.path.insert(0,sys.argv[1]);"
        "from transform_comparator import compare_rows;v=json.load(sys.stdin);"
        "print(json.dumps(compare_rows(v['plan'],v['rows'],v['reference']['plan'],v['reference']['rows'],"
        "left_recovery=v['cleanup'],right_recovery=v['reference']['cleanup'])))"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", script, str(output.resolve())],
        input=json.dumps(
            {
                "plan": inputs["plan"],
                "rows": collection["rows"],
                "cleanup": collection["cleanup"],
                "reference": reference,
            }
        ),
        text=True,
        capture_output=True,
        timeout=15,
        check=True,
        env={},
    )
    return json.loads(result.stdout)
