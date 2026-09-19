"""File-bound O8 admission for the request-byte boundary campaign.

This module freezes the campaign's inputs, runs the shared O7 admission check
set through the campaign-generic core, and adapts the reviewed remote transport
to a capability-bound wire call. It has no command line; the launcher is
`request_bytes_o8.py`.

The shared Gate now hosts this campaign: the descriptor declares its job count,
its per-slot reservations and its own execution schedule, and the Ledger claim
names the Gate job. What still stops a run is the owner's side, a fresh approval
for an unreserved nonce, which is exactly where a campaign should stop.
"""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/production-admission"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/o8-core"))
sys.path.insert(0, str(HERE))

import o8_admission
import request_bytes_descriptor as campaign
from broad_contract import digest
from o8_admission import (
    ProductionWireCapability,
    execution_host,
    issued_capability,
    revoke_production_capability,
    validate_owner_identity,
)
from request_bytes_descriptor import commit_baseline

MAX_INPUT_BYTES = 8 * 1024 * 1024
# The shared Gate hosts this campaign since the descriptor may declare its job
# count, its per-request reservation and its own execution schedule. What still
# stops a run is the owner's side: a fresh approval for a fresh nonce.
MISSING_APPROVAL = "a fresh owner approval for an unreserved nonce is required"

__all__ = [
    "MEASURED_SHADOW",
    "MISSING_APPROVAL",
    "NO_DATA_STOP_POINTS",
    "PLANNING_ASSUMPTION",
    "UNCERTAIN_STOP_POINTS",
    "ProductionWireCapability",
    "abort_generation",
    "bind_execute",
    "build_receipt",
    "classify_stop",
    "descriptor",
    "execution_host",
    "freeze_inputs",
    "gate_plan_for",
    "gate_reservations",
    "issue_production_capability",
    "permission_bindings",
    "reservation_claim",
    "revoke_production_capability",
    "stop_points",
    "validate_fresh_admission",
    "validate_frozen_inputs",
    "validate_no_data_receipt",
    "validate_o7_admission",
]


def descriptor():
    return campaign.descriptor()


def permission_bindings(plan, source_commit, artifact_digest, inputs, baseline=None):
    return campaign.permission_bindings(
        plan, source_commit, artifact_digest, inputs, baseline
    )


def validate_frozen_inputs(inputs) -> None:
    o8_admission.validate_frozen_inputs(descriptor(), inputs)


def abort_generation(inputs):
    return o8_admission.abort_generation(descriptor(), inputs)


def validate_o7_admission(**bindings):
    return o8_admission.validate_o7_admission(descriptor(), **bindings)


def issue_production_capability(**bindings):
    return o8_admission.issue_production_capability(descriptor(), **bindings)


def _read(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError("bounded regular input file required")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("bounded JSON object required")  # noqa: TRY004 -- refusal class, not a type report
    return value


def _artifact(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
        raise ValueError("retained regular artifact required")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _provenance(source_root, expected_commit, expected_inputs) -> None:
    """Every frozen source must be clean, current and present in the named commit."""
    source_root = Path(source_root).resolve()

    def git(*args):
        return subprocess.check_output(["git", "-C", str(source_root), *args])

    if (
        git("rev-parse", "HEAD").decode().strip() != expected_commit
        or git("status", "--porcelain", "--untracked-files=all").strip()
        or expected_inputs != campaign.source_map()
    ):
        raise ValueError("clean frozen source snapshot required")
    for name, sha in expected_inputs.items():
        path = source_root / name
        if path.is_symlink() or not path.is_file() or _artifact(path) != sha:
            raise ValueError("source input differs")
        if hashlib.sha256(git("show", f"{expected_commit}:{name}")).hexdigest() != sha:
            raise ValueError("source input not in frozen commit")


# How a per-slot reservation came to be. There is no third option: a figure
# with no record behind it is the v10 baseline failure in a different costume.
PLANNING_ASSUMPTION = "owner-planning-assumption"
MEASURED_SHADOW = "measured-shadow-percentile"
RESERVATION_BASES = (PLANNING_ASSUMPTION, MEASURED_SHADOW)


def gate_reservations(permission) -> dict:
    """The per-slot reservations the owner declared, checked but never invented.

    No single reservation covers this campaign: the three 10 MiB Commits are
    bounded by the transport at 60 seconds while the recovery window allows at
    most 1.71 seconds a slot once the Gate's 0.25 second spacing is taken off
    the 1.96 the window allows. The upload figure is the published ceiling,
    which the transport enforces. Observation and recovery declare separately,
    because the recovery phase is where a reservation that is too tight does the
    most damage: the Gate refuses mid-cleanup and leaves documents behind. The small-slot figure has no measurement behind it:
    the lane records outcomes, not durations, so nothing in the tree says how
    long a small request takes. It is therefore an owner planning bound, and the
    permission has to say which it is. A figure declared as measured must name
    the shadow record it was read from, so the claim is checkable; a planning
    assumption is admitted and labelled, never silently promoted.
    """
    declared = permission.get("gateReservationSeconds")
    if not isinstance(declared, dict) or set(declared) - {"slotBasisRecord"} != {
        "upload",
        "observationSlot",
        "recoverySlot",
        "slotBasis",
    }:
        raise ValueError("owner declared Gate reservations required")
    for name in ("upload", "observationSlot", "recoverySlot"):
        value = declared[name]
        if type(value) not in (int, float) or isinstance(value, bool) or value <= 0:
            raise ValueError("owner declared Gate reservations required")
    if declared["upload"] != campaign.transport_deadline_seconds():
        raise ValueError("upload reservation differs from the enforced ceiling")
    basis = declared["slotBasis"]
    if basis not in RESERVATION_BASES:
        raise ValueError("declared basis for the slot reservation required")
    if basis == MEASURED_SHADOW and not isinstance(
        declared.get("slotBasisRecord"), str
    ):
        raise ValueError("a measured slot reservation must name its record")
    if basis == PLANNING_ASSUMPTION and "slotBasisRecord" in declared:
        raise ValueError("a planning assumption names no record")
    return dict(declared)


def gate_plan_for(inputs, permission) -> dict:
    """Compile this campaign's Gate plan from the frozen inputs and permission."""
    declared = gate_reservations(permission)
    return campaign.gate_plan(
        campaign.execution_plan(inputs["plan"]),
        upload_seconds=declared["upload"],
        observation_slot_seconds=declared["observationSlot"],
        recovery_slot_seconds=declared["recoverySlot"],
    )


def _validate_owner_window(permission) -> None:
    """An owner permission is short-lived and must still cover the whole run."""
    issued, expiry = permission.get("issuedAt"), permission.get("expiresAt")
    now = time.time()
    if (
        type(issued) not in (int, float)
        or type(expiry) not in (int, float)
        or isinstance(issued, bool)
        or isinstance(expiry, bool)
        or not 0 <= now - issued <= 86400
        or not now + campaign.campaign_seconds() + campaign.recovery_seconds()
        <= expiry
        <= issued + 86400
    ):
        raise ValueError("owner permission expired or too short for recovery")


def _approve(
    permission, plan, source_commit, artifact_digest, inputs, baseline=None
) -> None:
    required = permission_bindings(
        plan, source_commit, artifact_digest, inputs, baseline
    )
    if digest({key: permission.get(key) for key in required}) != digest(required):
        raise ValueError("typed owner permission binding differs")
    _validate_owner_window(permission)
    # The Gate reservations are owner-declared planning bounds, and compiling
    # the Gate plan here proves they fit the campaign's wall and recovery split
    # before anything is frozen around them.
    declared = gate_reservations(permission)
    campaign.gate_plan(
        campaign.execution_plan(plan),
        upload_seconds=declared["upload"],
        observation_slot_seconds=declared["observationSlot"],
        recovery_slot_seconds=declared["recoverySlot"],
    )
    # A permission always names where its production baseline came from, even
    # where the observation journals themselves are not available to re-read.
    commit_baseline.validate_provenance(permission.get("baselineProvenance"))
    if baseline is not None:
        commit_baseline.validate_permission_baseline(permission, baseline)
    validate_owner_identity(permission.get("ownerIdentity"), field="ownerIdentity")
    # The recovery owner carries the same provenance weight as the execution
    # identity: it names who answers for a campaign that stops mid-flight, and
    # this campaign can leave up to 17 documents behind when a request times out.
    validate_owner_identity(permission.get("recoveryOwner"), field="recoveryOwner")
    if (
        not isinstance(permission.get("permissionReference"), str)
        or not permission["permissionReference"].strip()
    ):
        raise ValueError("owner supplied permissionReference required")


def freeze_inputs(permission_path, plan, *, source_root, artifact_path, baseline=None):
    """Freeze an independently read permission over a verified source snapshot.

    `plan` is the reference, not the 63 MB compiled plan. Recompiling it here
    proves the reference names exactly one plan the reviewed compiler produces.
    """
    campaign.execution_plan(plan)
    permission = _read(permission_path)
    inputs = campaign.source_map()
    commit = subprocess.check_output(
        ["git", "-C", str(source_root), "rev-parse", "HEAD"], text=True
    ).strip()
    artifact = _artifact(artifact_path)
    _provenance(source_root, commit, inputs)
    _approve(permission, plan, commit, artifact, inputs, baseline)
    return o8_admission.freeze_inputs(
        descriptor(),
        permission,
        plan,
        source_commit=commit,
        artifact_sha256=artifact,
    )


def validate_fresh_admission(ledger_root, plan, permission) -> dict:
    """Refuse a reused nonce or a reused owner permission, reading only.

    A campaign that re-entered an owned namespace, or that spent a permission a
    previous reservation already spent, would make its own absence proofs
    meaningless. The shared Ledger is the record of both, and this check reads
    it without taking a reservation.
    """
    root = Path(ledger_root)
    state_path = root / "state.json"
    if root.is_symlink() or not state_path.is_file():
        raise ValueError("existing shared Ledger required")
    state = json.loads(state_path.read_bytes())
    nonce_digest = digest(plan["nonce"])
    permission_digest = digest(permission)
    for row in state.get("reservations", {}).values():
        claim = row.get("claim", {})
        if claim.get("nonceDigest") == nonce_digest:
            raise ValueError("campaign nonce already reserved")
        for lock in claim.get("locks", []):
            if plan["nonce"] in str(lock.get("key", "")):
                raise ValueError("campaign nonce already reserved")
    for entry in state.get("envelopes", {}).values():
        envelope = entry.get("envelope", entry)
        if envelope.get("permissionDigest") == permission_digest:
            raise ValueError("owner permission already spent")
    return {
        "ledgerRoot": str(root.resolve(strict=False)),
        "nonceDigest": nonce_digest,
        "permissionDigest": permission_digest,
    }


def reservation_claim(inputs, *, gate_path, gate_plan):
    """The shared Ledger claim for this campaign, with its Gate binding.

    `gate_plan` is the campaign's own projection onto the shared Gate schema,
    compiled by the descriptor because the timing and the cost are the
    campaign's, not the shared module's. The claim addresses one job by name;
    the Ledger validates every job of the reserved Gate regardless, so the name
    only says which job the retirement path binds its Gate handle to.
    """
    descriptor_ = descriptor()
    plan = inputs["plan"]
    if (
        digest(gate_plan.get("nonce")) != digest(plan["nonce"])
        or gate_plan.get("campaignId") != descriptor_.campaign_id
    ):
        raise ValueError("Gate plan belongs to another campaign or nonce")
    return {
        "campaignId": descriptor_.campaign_id,
        "manifestDigest": inputs["planDigest"],
        "nonceDigest": digest(plan["nonce"]),
        "gatePath": str(Path(gate_path).resolve()),
        "gatePlanDigest": digest(gate_plan),
        "gateJob": campaign.gate_job_name(campaign.PROBE_SCOPES[0]),
        "locks": descriptor_.lock_scopes(plan),
        "budget": campaign.ledger_budget(),
        "durationSeconds": descriptor_.campaign_seconds,
    }


def transport_call(plan, phase, index, operation, token) -> dict:
    """The closed value one bound wire call carries."""
    return {
        "plan": plan,
        "phase": phase,
        "index": index,
        "operation": operation,
        "token": token,
    }


def bind_execute(capability, plan, token, *, schedule=None):
    """Adapt the collector's one-argument callable onto an admitted capability.

    The collector drives the frozen schedule and hands each operation here. The
    slot coordinates come from the schedule, never from the operation, so a
    caller cannot move a request to another slot by reshaping it.
    """
    if not issued_capability(capability) and not getattr(capability, "consumed", False):
        raise ValueError("unissued O7 production capability")
    if schedule is None and "executionSchedule" not in plan:
        raise ValueError("bind_execute requires the compiled plan, not its reference")
    order = list(schedule if schedule is not None else plan["executionSchedule"])
    position = {"index": 0}

    def execute(operation):
        if position["index"] >= len(order):
            raise ValueError("request-byte schedule exhausted")
        slot = order[position["index"]]
        position["index"] += 1
        return capability._transmit(
            transport_call(plan, slot["phase"], slot["index"], operation, token)
        )

    return execute


# Every point this campaign can stop at with nothing of its own left behind.
# The schedule runs three probes; each opens with the ownership preflight reads
# that prove the owned namespace is empty, then makes its one Commit, then its
# version-bound cleanup. A stop anywhere in a probe's preflight has created
# nothing. A stop at the Commit's transport deadline has NOT: the Commit may
# have been applied while the receipt was lost, which is the one outcome that is
# uncertain by construction and must never be retired as a no-data abort.
PROBES = ("u", "e", "o")
NO_DATA_STOP_POINTS = tuple(f"probe-{probe}01-preflight" for probe in PROBES) + (
    "schedule-not-started",
)
UNCERTAIN_STOP_POINTS = tuple(f"probe-{probe}01-commit-deadline" for probe in PROBES)


def stop_points() -> dict[str, tuple[str, ...]]:
    """The reachable terminal states, split by whether data may exist."""
    return {"noData": NO_DATA_STOP_POINTS, "uncertain": UNCERTAIN_STOP_POINTS}


def classify_stop(receipt) -> dict:
    """Name the terminal disposition a stopped run is entitled to.

    A no-data stop is retirable: the run holds no creation proof and its own
    journal shows no document was written. An uncertain stop is not, however it
    is labelled, because a Commit whose receipt was lost may have been applied.
    """
    if not isinstance(receipt, dict):
        raise ValueError("bounded receipt required")  # noqa: TRY004 -- refusal class, not a type report
    stop = receipt.get("stopPoint")
    collection = receipt.get("collection") or {}
    created = int(collection.get("rowCount") or 0)
    uncertain = bool(collection.get("uncertainCommit"))
    if stop in UNCERTAIN_STOP_POINTS or uncertain:
        return {
            "stopPoint": stop,
            "disposition": "owner-escalation",
            "retirableAsNoData": False,
            "reason": (
                "a Commit whose receipt was lost may have been applied; up to "
                "17 documents can remain under the owned scope"
            ),
        }
    if stop not in NO_DATA_STOP_POINTS:
        raise ValueError("unknown request-byte stop point")
    if (
        created
        or receipt.get("productionExecuted") is not True
        or collection.get("cleanupComplete") is False
        or any(collection.get(key) for key in ("overRefusal", "untypedOverRefusal"))
    ):
        return {
            "stopPoint": stop,
            "disposition": "owner-escalation",
            "retirableAsNoData": False,
            "reason": "the journal does not prove that nothing was written",
        }
    return {
        "stopPoint": stop,
        "disposition": "aborted-no-data",
        "retirableAsNoData": True,
        "reason": "no Commit was dispatched and no document was created",
    }


def validate_no_data_receipt(receipt) -> dict:
    """Accept only a receipt that proves this campaign wrote nothing."""
    verdict = classify_stop(receipt)
    if not verdict["retirableAsNoData"]:
        raise ValueError(f"receipt is not a no-data stop: {verdict['reason']}")
    generation = receipt.get("generation")
    if not isinstance(generation, dict) or set(generation) != {
        "sourceCommit",
        "collectorSourceDigest",
        "sourceDigests",
    }:
        raise ValueError("receipt records no acquisition generation")
    metadata = receipt.get("metadata")
    if not isinstance(metadata, list) or any(
        not isinstance(item, dict) or not isinstance(item.get("responseDigest"), str)
        for item in metadata
    ):
        raise ValueError("receipt records no per-route response digests")
    if receipt.get("routeDigest") != digest(metadata):
        raise ValueError("receipt route journal differs")
    return verdict


def build_receipt(
    inputs, result, *, capability, rows, generation, failure=None, stop_point=None
):
    """The campaign receipt, binding every route it observed by response digest."""
    metadata = [
        {
            "id": f"{row['phase']}:{row['index']:03d}",
            "route": row["route"],
            "status": row.get("status"),
            "responseDigest": row["responseDigest"],
        }
        for row in rows
    ]
    return {
        "kind": "request-bytes-acquisition-receipt-v1",
        "campaignId": descriptor().campaign_id,
        "inputsDigest": inputs["inputsDigest"],
        "permissionDigest": inputs["permissionDigest"],
        "planDigest": inputs["planDigest"],
        "collection": result,
        "metadata": metadata,
        "routeDigest": digest(metadata),
        "generation": copy.deepcopy(generation),
        "executionKind": "fixed-production-wire"
        if capability is not None
        else "injected-transport",
        "productionExecuted": capability is not None,
        "workerSha256": capability.binding_digest if capability is not None else None,
        "transportDeadlineSeconds": campaign.transport_deadline_seconds(),
        "stopPoint": stop_point,
        "failure": failure,
    }
