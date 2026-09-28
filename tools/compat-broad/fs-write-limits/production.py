# ruff: noqa: I001 -- Load the limits/shared import bootstrap first.
"""Closed limits execution and immutable comparison admission; no implicit approval."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import os
import re
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path

from production_bridge import (
    LimitsGate,
    ReservedCoordinator,
    bind_reserved_wire,
    execution_plan,
    source_digest,
)
from production_plan import production_plan, PROJECT, DATABASE
from compiler import compile_limits_plan
from comparator import _validated, compare_rows
from collector import collect
from shadow import _validate_cleanup, save, source_inputs
from reservations import Ledger
from batch_contract import DATABASE_PROJECTION, NUMBER, validate_owner_baseline
from broad_contract import ROOT, digest
from evidence_common import runtime_inputs
from owned_runner import reject_mutation_artifact, validate_build
from shared_gate import create
from limits_evidence_history import SOURCE_SHA256 as HISTORICAL_VALIDATOR_SHA256

SHARED_ROOT = Path.home() / ".local/state/fireemu-broad/production-admission-v1"
MAX_INPUT_BYTES = 128 * 1024 * 1024


def sha_file(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def load(path):
    path = Path(path)
    if path.is_symlink() or path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError("bounded regular evidence input required")
    return json.loads(path.read_bytes())


def manifest():
    return {
        "kind": "fs-write-limits-production-manifest-v1",
        "allocation": production_plan("0" * 32),
    }


def contract():
    return {
        "kind": "fs-write-limits-acquisition-comparison-v2",
        "receiptKind": "fs-write-limits-production-receipt-v2",
        "historicalValidatorSha256": HISTORICAL_VALIDATOR_SHA256,
        "semanticKernelSha256": sha_file(Path(__file__).with_name("comparator.py")),
        "acquisitionSha256": sha_file(Path(__file__)),
        "databaseProjectionContractDigest": digest(DATABASE_PROJECTION),
        "completeMismatchEligible": True,
        "parentPromotion": False,
    }


def approve(
    permission,
    nonce,
    local_digest,
    artifact,
    commit,
    key_digest,
    ledger_identity,
    *,
    now,
):
    if not isinstance(nonce, str) or re.fullmatch(r"[a-f0-9]{32}", nonce) is None:
        raise ValueError("fresh nonce required")
    required = {
        "kind": "fs-write-limits-owner-permission-v1",
        "manifestSha256": digest(manifest()),
        "comparisonContractDigest": digest(contract()),
        "observerSha256": source_digest(),
        "collectorSourceDigest": source_digest(),
        "nonce": nonce,
        "project": PROJECT,
        "projectNumber": NUMBER,
        "quotaProject": PROJECT,
        "database": DATABASE,
        "tenant": None,
        "databaseProjectionContractDigest": digest(DATABASE_PROJECTION),
        "tariffsConfirmedBelowPlanningCeilings": True,
        "localBundleDigest": local_digest,
        "artifactSha256": artifact,
        "frozenCommit": commit,
        "apiKeyDigest": key_digest,
        "ledgerIdentity": ledger_identity,
        "allowedReobservations": 0,
        "requestUpperBound": 40,
        "accountUpperBound": 0,
        "resourceUpperBound": 4,
        "concurrencyUpperBound": 1,
        "timeUpperBound": 960,
        "costUpperMicrousd": 44000,
        "safetyClass": "OWNED_DATA",
    }
    validate_owner_baseline(permission, required, now)
    costs = permission.get("costAssumptions", {})
    ceiling = costs.get("maximumUsd")
    if (
        costs.get("ownerConfirmed") is not True
        or costs.get("retentionHours") != 24
        or type(ceiling) not in (int, float)
        or not math.isfinite(ceiling)
        or not 0.044 <= ceiling <= 1
        or costs.get("fixedStorageAndNetworkUpperUsd") != 0.04
        or any(
            not isinstance(permission.get(k), str) or not permission[k].strip()
            for k in ("ownerIdentity", "permissionReference", "recoveryOwner")
        )
    ):
        raise ValueError("explicit bounded cost and recovery acceptance required")


def local_bundle(directory, artifact, commit):
    """Verify owned shadow provenance without treating semantic agreement as completeness."""
    directory = Path(directory)
    files = {
        name: directory / name
        for name in (
            "manifest.json",
            "cases.json",
            "result.json",
            "shadow-binding.json",
        )
    }
    values = {name: load(path) for name, path in files.items()}
    parent, cases, result, binding = (values[name] for name in files)
    artifact_hash = sha_file(artifact)
    reject_mutation_artifact(Path(artifact))
    validate_build(parent["build"], artifact_hash, runtime_inputs(ROOT))
    unsigned = {k: v for k, v in parent.items() if k != "parentManifestSha256"}
    child = result["manifest"]
    if (
        parent.get("executionCommit") != commit
        or parent.get("artifactSha256") != artifact_hash
        or parent.get("parentManifestSha256") != digest(unsigned)
        or parent.get("partialResultSha256") != sha_file(files["cases.json"])
        or binding.get("supervisorManifestSha256") != sha_file(files["manifest.json"])
        or binding.get("bound") is not True
        or any(
            binding.get(k) != source_inputs()
            for k in ("sourceInputsBefore", "sourceInputsAfter", "childSourceInputs")
        )
        or digest(cases.get("localObservations")) != digest(result.get("rows"))
        or digest(parent.get("localObservations")) != digest(result.get("rows"))
        or parent.get("recordingComplete") is not True
        or parent.get("productionExecuted") is not False
        or child != cases.get("manifest")
        or child != parent.get("manifest")
        or child.get("sourceInputs") != source_inputs()
        or child.get("sourceInputsAfter") != source_inputs()
        or parent.get("stopReason") != "child-completed"
        or any(
            parent.get(k)
            for k in (
                "cleanupFailure",
                "parentCleanupFailure",
                "terminationVerificationFailure",
                "partialResultFailure",
            )
        )
        or parent.get("ownedProcess", {}).get("stopped") is not True
        or parent.get("ownedProcess", {}).get("listenersClosed") is not True
        or result.get("productionExecuted") is not False
        or result.get("recordingComplete") is not True
        or result.get("cleanupComplete") is not True
        or result.get("infrastructureFailures") != []
        or result.get("injectedFault") is not None
    ):
        raise ValueError("local artifact acquisition binding incomplete")
    plan = compile_limits_plan("demo-firestore-probe", DATABASE, child["nonce"])
    _validated(plan, result["rows"])
    if (
        result.get("planDigest") != digest(plan)
        or not _validate_cleanup(result, plan)
        or digest(result.get("resourceAbsence"))
        != digest({d["resource"]: True for d in plan["documents"].values()})
    ):
        raise ValueError("local acquisition/cleanup incomplete")
    return {
        "digest": digest({name: sha_file(path) for name, path in files.items()}),
        "artifactSha256": artifact_hash,
        "plan": plan,
        "result": result,
    }


def envelope(permission, locks):
    return {
        "permissionDigest": digest(permission),
        "issuedAt": permission["issuedAt"],
        "expiresAt": permission["expiresAt"],
        "limits": {
            "requests": 40,
            "accounts": 0,
            "resources": 4,
            "costMicrousd": 44000,
        },
        "concurrency": 1,
        "scopes": locks,
    }


def metadata_valid(entries, events, permission):
    expected = [
        f"{phase}:{key}"
        for phase in ("observation", "recovery")
        for key in ("project", "database", "auth", "key")
    ]
    ids = [e["id"] for e in events]
    credentials = ["observation:access-command", "observation:tokeninfo"]
    if sorted(e["id"] for e in entries) != sorted(expected) or sorted(ids) not in (
        sorted(expected + credentials),
        sorted(
            expected + credentials + ["recovery:access-command", "recovery:tokeninfo"]
        ),
    ):
        return False
    for entry in entries:
        value, action = entry["value"], entry["id"].split(":")[1]
        if type(entry.get("status")) is not int or entry["status"] != 200:
            return False
        if action == "project" and digest(value) != digest(
            {"projectId": PROJECT, "projectNumber": NUMBER}
        ):
            return False
        if action == "database" and (
            value["projectionDigest"] != permission["databaseProjectionDigest"]
            or digest(value["projection"]) != permission["databaseProjectionDigest"]
        ):
            return False
        if (
            action == "auth"
            and entry["responseDigest"] != permission["authConfigDigest"]
        ):
            return False
        if action == "key" and (
            value.get("parent") != f"projects/{NUMBER}/locations/global"
            or re.fullmatch(
                f"projects/{NUMBER}/locations/global/keys/[A-Za-z0-9_-]+",
                value.get("name", ""),
            )
            is None
        ):
            return False
    return True


def validate_acquisition(receipt, inputs):
    """Validate persisted success, never reconstructing final facts from this checkout."""
    if receipt.get("acquisitionValidated") is not True:
        raise ValueError("saved acquisition was not validated")
    return _validate_acquisition(receipt, inputs)


def _validate_acquisition(receipt, inputs):
    """Validate live completion before setting the persisted success marker."""
    if (
        "acquisitionFailure" in receipt
        or "reservationFailure" in receipt
        or receipt.get("kind") != "fs-write-limits-production-receipt-v2"
    ):
        raise ValueError("failed or unsupported acquisition receipt")
    final = receipt.get("finalBinding")
    if (
        not isinstance(final, dict)
        or final.get("sourceCommit") != inputs["sourceCommit"]
        or final.get("dirty") is not False
        or final.get("artifactSha256") != inputs["artifactSha256"]
        or final.get("collectorSourceDigest")
        != inputs["permission"]["collectorSourceDigest"]
        or final.get("captureFailures") != {}
    ):
        raise ValueError("final acquisition binding incomplete or different")
    validate_frozen(inputs, receipt)
    permission, plan = inputs["permission"], inputs["plan"]
    compiled = compile_limits_plan(PROJECT, DATABASE, plan["nonce"])
    collection, state = receipt["collection"], receipt["gate"]
    if (
        digest(plan) != digest(execution_plan(permission, permission["nonce"]))
        or receipt.get("productionExecuted") is not True
        or receipt.get("inputsDigest") != digest(inputs)
        or receipt.get("failure") is not None
        or receipt.get("sourceDigestAfter") != permission["collectorSourceDigest"]
        or receipt.get("configurationUnchanged") is not True
        or collection.get("collectionComplete") is not True
        or collection.get("infrastructureFailures") != []
        or state.get("planDigest") != digest(plan)
        or digest(state.get("plan")) != digest(plan)
        or state.get("coordinatorInflight") is not False
        or state.get("managementUsed") != [e["id"] for e in state["managementEvents"]]
        or not metadata_valid(
            receipt["metadataEvidence"], state["managementEvents"], permission
        )
    ):
        raise ValueError("production acquisition incomplete or unbound")
    _validated(compiled, collection["rows"])
    if any(row.get("dispatchFailure") is not None for row in collection["rows"]):
        raise ValueError("production transport incomplete")
    cleanup_plan = copy.deepcopy(compiled)
    cleanup_plan["localGatePlan"] = plan
    merged = {**collection, "gate": state}
    if not _validate_cleanup(merged, cleanup_plan):
        raise ValueError("production cleanup incomplete")
    expected_events = []
    expected_skips = []
    for phase, rows in (
        ("observation", collection["rows"]),
        ("recovery", collection["cleanup"]),
    ):
        for row in rows:
            if row.get("skipped") is True:
                expected_skips.append(
                    {
                        "job": "limits",
                        "index": row["index"],
                        "reason": "absent-or-unavailable-cleanup-read",
                    }
                )
                continue
            expected_events.append(
                {
                    "job": "limits",
                    "phase": phase,
                    "index": row["index"],
                    "requestDigest": digest(row["request"]),
                    "status": row["status"],
                    "responseDigest": digest(row["body"]),
                    "completed": True,
                    "service": row["request"]["service"],
                    "method": row["request"]["method"],
                }
            )
    events = state.get("events", [])
    if len(events) != len(expected_events) or digest(state.get("skips", [])) != digest(
        expected_skips
    ):
        raise ValueError("data journal coverage differs")
    for event, expected in zip(events, expected_events, strict=True):
        if (
            digest({k: event.get(k) for k in expected}) != digest(expected)
            or event.get("failure") is not None
        ):
            raise ValueError("data journal binding differs")
    data_sent = sum(
        row.get("skipped") is not True
        for row in collection["rows"] + collection["cleanup"]
    )
    expected_total = data_sent + len(state["managementEvents"])
    numeric = {
        "total": expected_total,
        "observation": 22,
        "recovery": expected_total - 22,
        "costMicrousd": 40000 + expected_total * plan["requestCostMicrousd"],
    }
    # Recovery credential reuse legitimately avoids the two reserved management attempts.
    if (
        any(type(state.get(k)) is not int or state[k] != v for k, v in numeric.items())
        or expected_total > 40
    ):
        raise ValueError("production accounting differs")
    if digest(collection.get("resourceAbsence")) != digest(
        {d["resource"]: True for d in compiled["documents"].values()}
    ):
        raise ValueError("production absence incomplete")
    return compiled


def frozen_checkout():
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT).strip():
        raise ValueError("clean frozen checkout required")
    return subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()


@contextmanager
def admission_journal(output, inputs):
    """Journal pre-network failures without silently releasing uncertain ownership."""
    try:
        yield
    except BaseException as error:
        try:
            save(
                Path(output) / "admission-failure.json",
                {
                    "kind": "fs-write-limits-admission-failure-v1",
                    "inputsDigest": digest(inputs),
                    "reservationTicket": inputs["reservationTicket"],
                    "productionExecuted": False,
                    "acquisitionValidated": False,
                    "reservationReleased": False,
                    "recoveryRequired": True,
                    "failure": type(error).__name__,
                },
            )
        except Exception as journal_error:
            error.add_note(
                "Admission journal unavailable; shared reservation remains held."
            )
            raise error from journal_error
        raise


def execute(permission, local_directory, artifact, output, api_key):
    """O8: execute only this closed permission once; do not classify semantics."""
    commit = frozen_checkout()
    local = local_bundle(local_directory, artifact, commit)
    if not isinstance(api_key, str) or not api_key:
        raise ValueError("bound API key required")
    ledger = Ledger(SHARED_ROOT)
    nonce = permission["nonce"]
    started = time.time()
    approve(
        permission,
        nonce,
        local["digest"],
        local["artifactSha256"],
        commit,
        digest(api_key),
        ledger.identity,
        now=started,
    )
    plan = execution_plan(permission, nonce)
    allocation = production_plan(nonce)
    compiled = compile_limits_plan(PROJECT, DATABASE, nonce)
    output = Path(output).absolute()
    if output != output.resolve() or output.is_relative_to(
        Path(local_directory).resolve()
    ):
        raise ValueError("independent canonical output directory required")
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    claim = {
        "campaignId": allocation["campaignId"],
        "manifestDigest": digest(manifest()),
        "nonceDigest": digest(nonce),
        "gatePath": str(output / "gate"),
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
    ticket = ledger.reserve(envelope(permission, claim["locks"]), claim, plan)
    inputs = {
        "kind": "fs-write-limits-frozen-inputs-v1",
        "permission": permission,
        "sourceCommit": commit,
        "artifactSha256": local["artifactSha256"],
        "localBundleDigest": local["digest"],
        "manifest": manifest(),
        "comparisonContract": contract(),
        "plan": plan,
        "reservationClaim": claim,
        "reservationTicket": ticket,
        "envelope": envelope(permission, claim["locks"]),
        "admittedAt": started,
    }
    with admission_journal(output, inputs):
        save(output / "inputs.json", inputs)
        # Preserve the existing cross-tool replay fence in addition to the canonical shared ledger.
        consumed = Path.home() / ".local/state/fireemu-broad/consumed"
        consumed.mkdir(mode=0o700, parents=True, exist_ok=True)
        with (consumed / nonce).open("x") as stream:
            stream.write(digest(permission))
            stream.flush()
            os.fsync(stream.fileno())
        create(output / "gate", plan)
        gate = LimitsGate(output / "gate")
        gate.claim()
        coordinator = ReservedCoordinator(
            permission,
            nonce,
            output / "coordinator",
            gate,
            api_key,
            ledger=ledger,
            ticket=ticket,
        )
    collection, failure = None, None
    try:
        coordinator.acquire()
        coordinator.preflight()
        wire = bind_reserved_wire(
            coordinator,
            plan,
            artifact=artifact,
            artifact_sha256=local["artifactSha256"],
            production=True,
        )
        try:
            collection = collect(
                gate,
                compiled,
                output / "collection",
                wire,
                before_recovery=coordinator.recover_credentials,
            )
        finally:
            close = getattr(wire, "close", None)
            if close is not None:
                close()
    except Exception as error:  # noqa: BLE001 -- Keep failed acquisition evidence without credential-bearing messages.
        failure = type(error).__name__
    finally:
        import sys

        if sys.exc_info()[0] is not None:
            failure = "InterruptedExecution"
        if coordinator.ready:
            try:
                coordinator.recover_credentials()
                coordinator.preflight()
                coordinator.configuration_unchanged = True
            except Exception as error:  # noqa: BLE001 -- Preserve cleanup admission failure separately.
                failure = failure or type(error).__name__
        receipt = {
            "kind": "fs-write-limits-production-receipt-v2",
            "inputsDigest": digest(inputs),
            "productionExecuted": gate.snapshot()["total"] > 0,
            "sourceDigestAfter": None,
            "collection": collection,
            "metadataEvidence": coordinator.metadata_evidence,
            "gate": gate.snapshot(),
            "configurationUnchanged": coordinator.configuration_unchanged,
            "failure": failure,
            "acquisitionValidated": False,
            "reservationReleased": False,
        }
        try:
            ledger.finish(ticket)
            receipt["reservationFinal"] = ledger.snapshot()["reservations"][
                ticket["reservation"]
            ]
            receipt["reservationReleased"] = True
        except Exception as error:  # noqa: BLE001 -- Retain shared ownership on uncertain cleanup.
            receipt["acquisitionValidated"] = False
            receipt["reservationFailure"] = type(error).__name__
        finalize_acquisition(receipt, inputs, artifact)
        save(output / "receipt.json", receipt)
    return receipt


def capture_final_binding(artifact, *, checkout_root=ROOT):
    """Persist independent final observations, including unavailable measurements."""
    observations = {
        "sourceCommit": lambda: subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=checkout_root, text=True
        ).strip(),
        "dirty": lambda: bool(
            subprocess.check_output(
                ["git", "status", "--porcelain"], cwd=checkout_root
            ).strip()
        ),
        "artifactSha256": lambda: sha_file(artifact),
        "collectorSourceDigest": source_digest,
    }
    final = {"captureFailures": {}}
    for field, observe in observations.items():
        final[field] = None
        try:
            final[field] = observe()
        except Exception as error:  # noqa: BLE001 -- Record unavailable facts without sensitive messages.
            final["captureFailures"][field] = type(error).__name__
    return final


def finalize_acquisition(receipt, inputs, artifact, *, checkout_root=ROOT):
    """Run after independently attempted ledger release; failure is permanent."""
    receipt["acquisitionValidated"] = False
    receipt["finalBinding"] = capture_final_binding(
        artifact, checkout_root=checkout_root
    )
    receipt["sourceDigestAfter"] = receipt["finalBinding"]["collectorSourceDigest"]
    try:
        _validate_acquisition(receipt, inputs)
        receipt["acquisitionValidated"] = True
    except Exception as error:  # noqa: BLE001 -- Keep finalization failures separate from cleanup.
        receipt["acquisitionFailure"] = type(error).__name__


def validate_frozen(inputs, receipt):
    permission, plan = inputs["permission"], inputs["plan"]
    allocation = production_plan(permission["nonce"])
    claim, ticket, final = (
        inputs["reservationClaim"],
        inputs["reservationTicket"],
        receipt["reservationFinal"],
    )
    expected_claim = {
        "campaignId": allocation["campaignId"],
        "manifestDigest": digest(manifest()),
        "nonceDigest": digest(permission["nonce"]),
        "gatePath": claim["gatePath"],
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
    if (
        digest(claim) != digest(expected_claim)
        or digest(inputs["envelope"])
        != digest(envelope(permission, allocation["resourceLocks"]))
        or ticket.get("ledgerPath") != str(SHARED_ROOT.resolve())
        or ticket.get("ledgerIdentity") != permission["ledgerIdentity"]
        or ticket.get("claimDigest") != digest(claim)
        or ticket.get("envelopeDigest") != digest(inputs["envelope"])
        or not isinstance(ticket.get("reservation"), str)
        or re.fullmatch(r"[a-f0-9]{64}", ticket["reservation"]) is None
        or digest(final.get("claim")) != digest(claim)
        or final.get("claimDigest") != ticket["claimDigest"]
        or final.get("envelopeDigest") != ticket["envelopeDigest"]
        or final.get("state") != "released"
        or final.get("finalGateDigest") != digest(receipt["gate"])
        or receipt.get("reservationReleased") is not True
    ):
        raise ValueError("shared reservation provenance differs")
    if (
        digest(plan) != digest(execution_plan(permission, permission["nonce"]))
        or digest(inputs["manifest"]) != digest(manifest())
        or digest(inputs["comparisonContract"]) != digest(contract())
    ):
        raise ValueError("frozen contract drift")


def load_hashed(path):
    """Parse exactly the bounded evidence bytes whose hash is returned."""
    path = Path(path)
    if path.is_symlink() or path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError("bounded regular evidence input required")
    data = path.read_bytes()
    if len(data) > MAX_INPUT_BYTES:
        raise ValueError("bounded evidence input required")
    return json.loads(data), hashlib.sha256(data).hexdigest()


def validate_saved_acquisition(receipt, inputs, receipt_hash, inputs_hash):
    """Select the current contract or the single immutable legacy acquisition."""
    if (
        "acquisitionFailure" in receipt
        or receipt.get("acquisitionValidated") is not True
    ):
        raise ValueError("saved acquisition failed")
    if receipt.get("kind") == "fs-write-limits-production-receipt-v1":
        from limits_evidence_history import validate_production

        validate_production(receipt, inputs, receipt_hash, inputs_hash)
        return compile_limits_plan(PROJECT, DATABASE, inputs["plan"]["nonce"])
    permission = inputs["permission"]
    approve(
        permission,
        permission["nonce"],
        inputs["localBundleDigest"],
        inputs["artifactSha256"],
        inputs["sourceCommit"],
        permission["apiKeyDigest"],
        permission["ledgerIdentity"],
        now=inputs["admittedAt"],
    )
    return validate_acquisition(receipt, inputs)


def comparison_local_bundle(directory, artifact):
    """Keep new local admission strict; preserve only the exact retained old bundle."""
    from limits_evidence_history import LOCAL_COMMIT, validate_local

    parent = load(Path(directory) / "manifest.json")
    if parent.get("executionCommit") != LOCAL_COMMIT:
        return local_bundle(directory, artifact, frozen_checkout())
    validated = validate_local(directory, artifact)
    result = validated["result"]
    plan = compile_limits_plan(
        "demo-firestore-probe", DATABASE, result["manifest"]["nonce"]
    )
    return {
        "digest": validated["digest"],
        "artifactSha256": validated["artifactSha256"],
        "plan": plan,
        "result": result,
    }


def compare(production_directory, local_directory, artifact, output):
    """Credential-free comparison; incomplete acquisition produces INDETERMINATE."""
    result = {
        "kind": "fs-write-limits-production-comparison-v1",
        "promotionReady": False,
        "acquisitionValidated": False,
        "classification": "INDETERMINATE",
    }
    try:
        directory = Path(production_directory)
        inputs, inputs_hash = load_hashed(directory / "inputs.json")
        receipt, receipt_hash = load_hashed(directory / "receipt.json")
        production_compiled = validate_saved_acquisition(
            receipt, inputs, receipt_hash, inputs_hash
        )
        local = comparison_local_bundle(local_directory, artifact)
        result = {
            "kind": "fs-write-limits-production-comparison-v1",
            "promotionReady": False,
            "productionReceiptSha256": receipt_hash,
            "frozenInputsSha256": inputs_hash,
            "localBundleDigest": local["digest"],
            "artifactSha256": local["artifactSha256"],
            "acquisitionValidated": True,
            "semantic": compare_rows(
                production_compiled,
                receipt["collection"]["rows"],
                local["plan"],
                local["result"]["rows"],
            ),
        }
        result["classification"] = result["semantic"]["classification"]
    except (
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        OSError,
        subprocess.SubprocessError,
    ) as error:
        result["acquisitionFailure"] = type(error).__name__
    save(Path(output), result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--execute", type=Path, metavar="PERMISSION")
    mode.add_argument("--compare", type=Path, metavar="PRODUCTION_DIRECTORY")
    parser.add_argument("--local", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.execute is not None:
        result = execute(
            load(args.execute),
            args.local,
            args.artifact,
            args.output,
            os.environ.get("PRODUCTION_ORACLE_API_KEY"),
        )
        print(json.dumps({"acquisitionValidated": result["acquisitionValidated"]}))
        return 0 if result["acquisitionValidated"] else 2
    result = compare(args.compare, args.local, args.artifact, args.output)
    print(json.dumps({"classification": result["classification"]}))
    return 0 if result["classification"] in {"MATCH", "EXPECTED_NONDETERMINISM"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
