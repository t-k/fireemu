"""Freeze the FS-WRITE-LIMITS-03 preparation package from its sources.

The package is three published records: the manifest, its binding and the
local shadow record. Every figure and digest in them is computed here, from
the compiler, the descriptor, the committed tree and a private shadow output
directory; the narrative members are carried from the previous package so a
regeneration changes exactly what the sources changed.

    package_03.py freeze --shadow-run <private shadow output directory>
    package_03.py freeze --keep-shadow-record

The first form publishes a new shadow record from a completed run and then
the manifest and binding over it; the second rebuilds the manifest and binding
over the shadow record already published. Both refuse a dirty checkout: the
digests are bound to HEAD, and a record frozen over uncommitted bytes would
never resolve.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(HERE))

import compiler_03
import limits_03_admission as admission
import limits_03_descriptor as campaign
import limits_03_indexes
import limits_03_preflight as preflight
from broad_contract import digest
from compiler_03 import CAMPAIGN, DOCUMENT_NAME_MAX, name_charge_floor
from shadow_03 import source_inputs

PACKAGE = ROOT / "spec/compatibility/broad-runs"
MANIFEST = PACKAGE / "fs-write-limits-03.json"
BINDING = PACKAGE / "fs-write-limits-03-binding.json"
SHADOW = PACKAGE / "fs-write-limits-03-local-shadow.json"
RUNTIME_SOURCES = (
    "crates/fireemu-adapter-grpc/src/local.rs",
    "crates/fireemu-adapter-grpc/tests/rest.rs",
    "crates/fireemu-core-firestore/src/field_path.rs",
    "crates/fireemu-core-firestore/src/index_usage.rs",
    "crates/fireemu-core-firestore/src/path.rs",
    "crates/fireemu-core-firestore/src/size.rs",
)
_COMMIT = re.compile(r"\b[0-9a-f]{40}\b")
_NONCE = re.compile(r"\b[0-9a-f]{32}\b")
LANE = "tools/compat-broad/fs-write-limits"

OPEN_GATE_DEFECTS = [
    (
        "shared_gate._creation_outcome settles a BatchWrite as an unknown create "
        "as soon as one item is not a create-shaped write, so the R3 batch that "
        "carries an empty item leaves one create unconfirmed and the normal "
        "close is refused although every owned document is proven absent. The "
        "proposed rule, applied in the lane tests as a fixture, accounts an "
        "empty item only when production refused it per item with "
        "INVALID_ARGUMENT and the empty result slot."
    ),
    (
        "shared_gate.abandoned_cleanup_complete compares the creation proofs, not "
        "only the absence proofs, against every declared resource. This campaign "
        "declares resources it expects production to refuse, so a run that "
        "created and then abandoned can never reach the abandoned close even "
        "with absence proven for the whole assignment."
    ),
    (
        "After an abandon the collector still walks the recovery schedule and "
        "the Gate consumes each slot of an uncreated resource as a zero-wire "
        "skip, so a stop inside the typed-absence preflight leaves a non-zero "
        "recovery count and shared_gate.non_creating_dispatches no longer holds; "
        "the lane classifies the stop as no-data from the journal instead."
    ),
]


def _load(path: Path) -> dict:
    return json.loads(path.read_bytes())


def _write(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def head_commit() -> str:
    if subprocess.run(
        ["git", "-C", str(ROOT), "status", "--porcelain", "--untracked-files=all"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip():
        raise SystemExit("the checkout is dirty; commit before freezing the package")
    return subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _rebind_text(value, commit: str):
    """Replace the commit every narrative member names with the current one."""
    if isinstance(value, str):
        return _COMMIT.sub(commit, value)
    if isinstance(value, list):
        return [_rebind_text(item, commit) for item in value]
    if isinstance(value, dict):
        return {key: _rebind_text(item, commit) for key, item in value.items()}
    return value


def shadow_record(run: Path, commit: str) -> dict:
    """The published local shadow record for one completed private run.

    The executed nonce, the owned resource names, the retained binary and the
    response journal stay in the private directory: only the summary, the
    artifact digest and the source bindings are published.
    """
    supervisor = _load(run / "manifest.json")
    result = _load(run / "result.json")
    binding = _load(run / "shadow-binding.json")
    if (
        result.get("recordingComplete") is not True
        or result.get("stateValidation") is not True
        or binding.get("bound") is not True
        or result.get("campaignId") != CAMPAIGN
    ):
        raise SystemExit("a fully recorded, source-bound shadow run is required")
    # A run whose schedule and cleanup completed but whose Gate close was
    # refused is published as what it is: recorded, every owned document
    # proven absent, and not closed. HEAD's shared Gate refuses the close of
    # this campaign, see OPEN_GATE_DEFECTS, so the record says so rather than
    # being withheld until the Gate changes.
    completed = result.get("completed") is True and supervisor.get("status") == (
        "completed"
    )
    sources = binding["sourceInputsBefore"]
    if sources != source_inputs():
        raise SystemExit("the shadow ran under other lane sources than HEAD's")
    # The run may predate HEAD by commits that touch nothing the shadow sweeps
    # (the check above is what proves that); the commit it executed at is
    # recorded beside the commit the record binds.
    execution_commit = supervisor.get("executionCommit")
    if not isinstance(execution_commit, str) or len(execution_commit) != 40:
        raise SystemExit("the shadow run records no execution commit")
    execution = {
        key: result[key]
        for key in (
            "recordingComplete",
            "stateValidation",
            "cleanupComplete",
            "cleanupValidated",
            "receiptValidated",
            "semanticMismatches",
            "pendingDifferences",
            "pendingRows",
            "infrastructureFailures",
            "project",
        )
    }
    execution["allOwnedResourcesAbsentAfterRecovery"] = all(
        result["resourceAbsence"].values()
    )
    execution["database"] = "(default)"
    execution["target"] = "owned-local-artifact-on-loopback"
    execution["observationRequests"] = len(result["rows"])
    execution["recoveryRequests"] = len(result["cleanup"])
    execution["ownedDocuments"] = len(result["resourceAbsence"])
    execution["configurationDigest"] = supervisor["configurationDigest"]
    execution["indexConfiguration"] = {
        key: supervisor["indexConfiguration"][key] for key in ("sha256", "sourceCommit")
    }
    execution["ownedProcess"] = {
        key: supervisor["ownedProcess"][key]
        for key in ("pid", "stopped", "listenersClosed")
    }
    build = supervisor["build"]
    execution["supervisorStatus"] = supervisor.get("status")
    execution["completed"] = completed
    execution["gateCloseRefused"] = not completed and any(
        failure.get("phase") == "finish" for failure in result["infrastructureFailures"]
    )
    record = {
        "kind": "fs-write-limits-03-local-shadow-v2",
        "campaignId": CAMPAIGN,
        "status": "completed-local-only"
        if completed
        else "recorded-local-only-gate-close-refused",
        "productionExecuted": False,
        "formalCompatibilityClaim": False,
        "sourceCommit": commit,
        "campaignSources": sources,
        "note": (
            "Local artifact evidence only. The executed nonces, the owned resource "
            "names and the retained binaries live in private output directories "
            "and are not published here. This is not a production observation and "
            "promotes nothing. The local shadow supervisor pins the historical "
            "index configuration and verifies its digest, so it cannot apply the "
            "declared exemption; the document-name rows are pending for exactly "
            "that reason."
        )
        + (
            ""
            if completed
            else " The schedule and the cleanup ran to the end and every owned "
            "document was proven absent, but HEAD's shared Gate refused the "
            "terminal close: it settles the R3 BatchWrite that carries an empty "
            "item as an unknown create. The record is published as recorded, "
            "not completed."
        ),
        "execution": {
            "ALL": {
                "campaignId": CAMPAIGN,
                "executionCommit": execution_commit,
                "artifact": {
                    "buildCommand": build["command"],
                    "runtimeInputCount": len(build["inputs"]),
                    "runtimeInputsDigest": digest(build["inputs"]),
                    "rustc": build["rustc"],
                    "sha256": build["artifactSha256"],
                },
                "digests": {
                    "parentManifestSha256": _sha(run / "manifest.json"),
                    "supervisorManifestSha256": binding["supervisorManifestSha256"],
                    "sourceInputsBound": True,
                },
                "execution": execution,
            }
        },
    }
    if _NONCE.search(json.dumps(record)):
        raise SystemExit("the shadow record must not publish a nonce")
    return record


def restore_binding(
    record_path: Path | None,
    *,
    root: Path = ROOT,
    production_receipt: Path | None = None,
) -> dict:
    """How the package binds the restore evidence, or says it is still owed.

    The restore is verified by a field readback after the run, never by the
    deploy's exit status, and the campaign does not close until this member
    names a verified record bound to the production receipt it restores. When
    `production_receipt` is given, the record's binding is cross-checked
    against that receipt and a record produced from a different run is
    refused; `root` is the base a record's published path is relative to
    (tests may pass a scratch directory so no write touches the tracked tree).
    """
    value = {
        "required": True,
        "verified": False,
        "record": None,
        "recordKind": campaign.RESTORE_RECORD_KIND,
        "expectedProjectionDigest": preflight.expected_index_restored_digest(),
        "closureRequires": "a verified restore record bound to the production "
        "receipt it restores",
    }
    if record_path is None:
        return value
    record = _load(record_path)
    limits_03_indexes.validate_restore_record(record)
    if production_receipt is not None:
        receipt = _load(production_receipt)
        ticket = receipt.get("ticket")
        reservation = ticket.get("reservation") if isinstance(ticket, dict) else None
        if (
            record["receiptDigest"] != digest(receipt)
            or record["reservationTicket"] != reservation
        ):
            raise ValueError(
                "restore record is not bound to the given production receipt"
            )
    value.update(
        verified=True,
        record={
            "path": str(record_path.resolve().relative_to(root)),
            "sha256": _sha(record_path),
            "projectionDigest": record["projectionDigest"],
            "readbackSha256": record["readbackSha256"],
            "receiptDigest": record["receiptDigest"],
            "reservationTicket": record["reservationTicket"],
        },
    )
    return value


def manifest(
    previous: dict,
    shadow: dict,
    commit: str,
    *,
    restore_record: Path | None = None,
    production_receipt: Path | None = None,
) -> dict:
    """The manifest, with every computed member recomputed over HEAD."""
    value = _rebind_text(copy.deepcopy(previous), commit)
    figures = campaign.budget_figures()
    plan = campaign.figure_plan()
    contract = compiler_03.management_contract()
    value["budgets"] = {
        "campaignId": CAMPAIGN,
        "part": "ALL",
        "observationRequests": figures["observationRequests"],
        "recoveryRequests": figures["recoveryRequests"],
        "managementObservationRequests": figures["managementObservationRequests"],
        "managementRecoveryRequests": figures["managementRecoveryRequests"],
        "managementSlots": {
            "observation": list(compiler_03.MANAGEMENT_OBSERVATION_IDS),
            "recovery": list(compiler_03.MANAGEMENT_RECOVERY_IDS),
            "slotSeconds": contract["slotSeconds"],
            "phaseSeconds": contract["phaseSeconds"],
        },
        "requestUpperBound": figures["requestUpperBound"],
        "maxOwnedDocuments": figures["maxOwnedDocuments"],
        "maxProbedNames": figures["maxProbedNames"],
        "maxConcurrency": 1,
        "maxRequestBodyBytes": figures["maxRequestBodyBytes"],
        "maxResponseBytes": figures["maxResponseBytes"],
        "maxWallSeconds": figures["maxWallSeconds"],
        "recoveryReserveSeconds": figures["recoveryReserveSeconds"],
        "slotReservationSeconds": {
            "body": compiler_03.TRANSPORT_CEILING_SECONDS,
            "readback": compiler_03.READBACK_SECONDS,
            "small": compiler_03.SMALL_REQUEST_SECONDS,
            "management": compiler_03.MANAGEMENT_SLOT_SECONDS,
        },
        "requestCostMicrousd": figures["requestCostMicrousd"],
        "fixedCostMicrousd": figures["fixedCostMicrousd"],
        "dataCostMicrousd": figures["dataCostMicrousd"],
        "envelopeCostMicrousd": figures["envelopeCostMicrousd"],
        "dataCostIsIncludedInEnvelope": True,
        "costNote": previous["budgets"]["costNote"],
        "costCapUsd": figures["costCapUsd"],
        "planningCostUsd": figures["planningCostUsd"],
        "tariffsConfirmed": False,
    }
    value["allocation"] = {
        **previous["allocation"],
        "gateWallCapSeconds": compiler_03.GATE_WALL_SECONDS_MAX,
        "managementCharged": (
            "The shared Gate charges the closed management slots against the "
            "same allocation as the data schedule: five before the first data "
            "request and four after the last cleanup, thirteen seconds and one "
            "request each, all inside the published wall and recovery reserve."
        ),
        "openGateDefect": " ".join(OPEN_GATE_DEFECTS),
    }
    value.pop("scheduleDeclined", None)
    value.pop("supersededPartitionReason", None)
    value["schedule"] = {
        "declared": True,
        "reason": (
            "Every slot declares its own reservation and whether it can create, "
            "so the Gate charges the schedule rather than the lane default and a "
            "stop inside the non-creating prefix is admissible as no data. An "
            "observation that ends early uses the Gate's abandon transition, "
            "which reopens the recovery slots in their declared order."
        ),
    }
    value["partition"] = {
        "parts": 1,
        "reason": (
            "One allocation carries every case. With management charged the "
            "bodyless slots reserve by their response ceiling instead of a flat "
            "five seconds, which is what keeps the allocation under the Gate's "
            "1200-second cap; the A and B selections stay compilable for a run "
            "that has to be split for some other reason."
        ),
    }
    precondition = campaign.index_exemption_precondition()
    value["indexConfiguration"] = {
        **previous["indexConfiguration"],
        "conformanceIndexesSha256Before": precondition[
            "conformanceIndexesSha256Before"
        ],
        "conformanceIndexesSha256After": precondition["conformanceIndexesSha256After"],
        "precondition": precondition,
        "afterStateNeverCommitted": (
            "The after state is written to the tracked file only as the deploy "
            "input and is checked out again before admission; the committed file "
            "stays at the before digest, which is also what the restore deploys."
        ),
        "restore": restore_binding(
            restore_record, production_receipt=production_receipt
        ),
        "shadowRanUnder": {
            "ALL": shadow["execution"]["ALL"]["execution"]["indexConfiguration"]
        },
    }
    for case in value["cases"]:
        if case.get("limitId") == "FS-LIMIT-DOCUMENT-NAME-BYTES":
            prefix = len("projects/fireemu-35fe6/databases/(default)/documents/")
            floors = name_charge_floor(prefix, DOCUMENT_NAME_MAX)
            document = plan["documents"]["document-name-accept"]
            case["derivedFigures"] = {
                **floors,
                "compiledDocumentEntry": compiler_03.largest_index_entry_bytes(
                    document["resource"], document["fields"]
                ),
            }
    value["pendingLocalImplementation"] = {
        **previous["pendingLocalImplementation"],
        "differences": shadow["execution"]["ALL"]["execution"]["pendingDifferences"],
    }
    value["collectorBinding"] = {
        **previous["collectorBinding"],
        "digest": _sha(ROOT / campaign.COLLECTOR_ENTRY),
        "productionCollector": None,
        "productionRunner": f"{LANE}/limits_03_production.py",
        "status": "local-only",
        "technicalBlocker": (
            "The O8 launcher exists and drives collector_03 through the shared "
            "Gate, but HEAD's shared_gate settles the R3 malformed-item BatchWrite "
            "as an unknown create, so a production run could not reach its normal "
            "close until the proposed accounting rule lands."
        ),
    }
    value["comparatorBinding"] = {
        **previous["comparatorBinding"],
        "digest": _sha(ROOT / campaign.COMPARATOR_ENTRY),
        "productionComparator": None,
    }
    value["sourceBinding"] = {
        **previous["sourceBinding"],
        "codeSourceHead": commit,
        "featureHead": commit,
        "campaignSourceDigests": campaign.source_map(),
        "runtimeSourceDigests": {name: _sha(ROOT / name) for name in RUNTIME_SOURCES},
        "shadowArtifactSha256": {
            "ALL": shadow["execution"]["ALL"]["artifact"]["sha256"]
        },
    }
    value["localShadow"] = {
        **previous["localShadow"],
        "recordStatus": shadow["status"],
        "commands": [
            "uv run --project tools/compat-inventory --locked --python 3.12 -m "
            "pytest -q -p no:cacheprovider tools/compat-broad/fs-write-limits",
            "uv run --project tools/compat-inventory --locked --python 3.12 python "
            f"{LANE}/shadow_03.py --output <new-private-directory>",
            "uv run --project tools/compat-inventory --locked --python 3.12 python "
            f"{LANE}/package_03.py freeze --shadow-run <that-directory>",
        ],
        "status": "completed"
        if shadow["status"] == "completed-local-only"
        else "recorded; Gate close refused",
    }
    value["o8"] = {
        "descriptor": f"{LANE}/limits_03_descriptor.py",
        "admission": f"{LANE}/limits_03_admission.py",
        "launcher": f"{LANE}/limits_03_o8.py",
        "preflight": f"{LANE}/limits_03_preflight.py",
        "transport": f"{LANE}/limits_03_remote_transport.py",
        "worker": campaign.WORKER_ENTRY,
        "workerSha256": _sha(ROOT / campaign.WORKER_ENTRY),
        "indexTool": f"{LANE}/limits_03_indexes.py",
        "kinds": {
            "frozenInputs": campaign.FROZEN_INPUTS_KIND,
            "permission": campaign.PERMISSION_KIND,
            "approval": campaign.APPROVAL_KIND,
            "manifest": campaign.MANIFEST_KIND,
            "receipt": campaign.RECEIPT_KIND,
        },
        "approvalFields": sorted(campaign.CAMPAIGN_APPROVAL_FIELDS),
        "artifactProfile": campaign.artifact_profile(),
        "ledgerBudget": campaign.ledger_budget(),
        "lockScopes": campaign.lock_scopes({"nonce": "{freshNonce}"}),
        "managementContract": contract,
        "stopPoints": admission.stop_points(),
        "exitCodes": {
            "0": "verified cleanup and Ledger release",
            "1": "stopped; a create may have been applied or documents were created and the row stays held",
            "2": "refused before execution, or stopped with no create dispatched",
        },
    }
    value["executionBlockers"] = [
        "owner permission envelope, window, nonce reservation and tariff acceptance",
        "no production release artifact SHA-256 is bound",
        "the declared index exemption is not deployed",
        "the index exemption restore is not verified (no restore record bound)",
        "frozen artifact, collector and comparator bindings through O7",
        OPEN_GATE_DEFECTS[0],
        OPEN_GATE_DEFECTS[1],
    ]
    value["promotion"] = {
        **previous["promotion"],
        "remaining": [
            "land the shared-Gate accounting rule for the R3 malformed-item batch",
            "freeze artifact, collector and comparator bindings",
            "obtain the owner envelope fields and tariff acceptance",
            "deploy the declared index exemption and verify the field readback",
            "production observation and immutable receipt through limits_03_o8.py",
            "restore the index configuration, verify the field readback with "
            "limits_03_indexes.py --verify-restored and bind the record with "
            "package_03.py freeze --restore-record",
            "comparison against the private shadow journal and mismatch triage",
            "cleanup verification",
            "independent review",
            "final artifact regression",
        ],
    }
    value["status"] = "BLOCKED_OWNER"
    value["technicalStatus"] = "BLOCKED_TECHNICAL"
    value["productionExecuted"] = False
    return value


def binding(previous: dict, manifest_value: dict, shadow: dict, commit: str) -> dict:
    value = _rebind_text(copy.deepcopy(previous), commit)
    value["blockingReasons"] = [
        "owner permission envelope fields are unset",
        "no production release artifact SHA-256 is bound",
        "no fresh production nonce is reserved",
        "the declared index exemption is not deployed",
        "shared_gate settles the R3 malformed-item BatchWrite as an unknown create",
        "shared_gate's abandoned close requires a creation proof for every declared resource",
    ]
    value["collector"] = {
        **value["collector"],
        "digest": manifest_value["collectorBinding"]["digest"],
        "technicalBlocker": manifest_value["collectorBinding"]["technicalBlocker"],
    }
    value["comparator"] = {
        **value["comparator"],
        "digest": manifest_value["comparatorBinding"]["digest"],
    }
    value["gateEnvelope"] = copy.deepcopy(manifest_value["gate"])
    value["localShadow"] = {
        "path": str(SHADOW.relative_to(ROOT)),
        "productionExecuted": False,
        "sha256": _sha(SHADOW),
        "status": manifest_value["localShadow"]["status"],
    }
    value["manifest"] = {
        "path": str(MANIFEST.relative_to(ROOT)),
        "sha256": _sha(MANIFEST),
    }
    value["source"] = {
        "codeSourceHead": commit,
        "commit": commit,
        "productionArtifactSha256": None,
        "shadowArtifactSha256": manifest_value["sourceBinding"]["shadowArtifactSha256"],
    }
    value["o8"] = {
        "launcher": manifest_value["o8"]["launcher"],
        "launcherSha256": _sha(ROOT / manifest_value["o8"]["launcher"]),
        "descriptor": manifest_value["o8"]["descriptor"],
        "workerSha256": manifest_value["o8"]["workerSha256"],
    }
    value["status"] = "BLOCKED_OWNER"
    value["technicalStatus"] = "BLOCKED_TECHNICAL"
    value["productionExecuted"] = False
    return value


def freeze(
    shadow_run: Path | None,
    restore_record: Path | None = None,
    production_receipt: Path | None = None,
) -> None:
    commit = head_commit()
    previous_manifest, previous_binding = _load(MANIFEST), _load(BINDING)
    if shadow_run is not None:
        _write(SHADOW, shadow_record(shadow_run.resolve(), commit))
    shadow = _load(SHADOW)
    if shadow["sourceCommit"] != commit:
        raise SystemExit("the shadow record was frozen at another commit; rerun it")
    _write(
        MANIFEST,
        manifest(
            previous_manifest,
            shadow,
            commit,
            restore_record=restore_record,
            production_receipt=production_receipt,
        ),
    )
    _write(BINDING, binding(previous_binding, _load(MANIFEST), shadow, commit))
    for path in (SHADOW, MANIFEST, BINDING):
        print(f"{_sha(path)}  {path.relative_to(ROOT)}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    freeze_parser = commands.add_parser("freeze")
    source = freeze_parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--shadow-run", type=Path)
    source.add_argument("--keep-shadow-record", action="store_true")
    freeze_parser.add_argument(
        "--restore-record",
        type=Path,
        help="bind a verified index-exemption restore record written by "
        "limits_03_indexes.py --verify-restored",
    )
    freeze_parser.add_argument(
        "--production-receipt",
        type=Path,
        help="cross-check --restore-record against this production "
        "receipt.json; refuses a record bound to a different run",
    )
    args = parser.parse_args(argv)
    freeze(args.shadow_run, args.restore_record, args.production_receipt)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
