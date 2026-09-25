"""File-bound O8 admission for the partition/cursor campaign.

This module freezes the campaign's inputs, runs the shared O7 admission check
set through the campaign-generic core, compiles the Gate plan and the Ledger
claim, and classifies a stopped run's terminal disposition. It has no command
line; the launcher is `partition_cursor_o8.py`.

What still stops a run is the owner's side: a fresh approval for an unreserved
nonce, minted outside the packet after an independent review.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
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

import o4_partition_cursor_descriptor as campaign
import o8_admission
import partition_cursor_preflight as preflight
from broad_contract import digest
from o8_admission import (
    ProductionWireCapability,
    execution_host,
    issued_capability,
    revoke_production_capability,
    validate_owner_identity,
)
from partition_cursor_gate import JOB, SLOT_FLOOR_SECONDS

commit_baseline = campaign.commit_baseline

MAX_INPUT_BYTES = 8 * 1024 * 1024
MISSING_APPROVAL = "a fresh owner approval for an unreserved nonce is required"

# How a per-slot reservation came to be. A figure with no record behind it is
# a planning assumption and is admitted as such, never silently promoted.
PLANNING_ASSUMPTION = "owner-planning-assumption"
MEASURED_SHADOW = "measured-shadow-percentile"
RESERVATION_BASES = (PLANNING_ASSUMPTION, MEASURED_SHADOW)

__all__ = [
    "ESCALATION_ONLY_STOP_POINTS",
    "MEASURED_SHADOW",
    "MISSING_APPROVAL",
    "NO_DATA_STOP_POINTS",
    "PLANNING_ASSUMPTION",
    "UNCERTAIN_STOP_POINTS",
    "ProductionWireCapability",
    "abort_generation",
    "build_receipt",
    "classify_stop",
    "descriptor",
    "execution_host",
    "freeze_inputs",
    "gate_plan_for",
    "gate_reservations",
    "issue_production_capability",
    "issued_capability",
    "permission_bindings",
    "reservation_claim",
    "revoke_production_capability",
    "stop_points",
    "transport_call",
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


def gate_reservations(permission) -> dict:
    """The per-slot reservation the owner declared, checked but never invented.

    Every slot of this campaign is a small request, so one reservation covers
    them all. It must be at least the whole-worker wire ceiling plus one second
    of spawn and Gate slack. The permission says whether the figure is a
    planning assumption or a measured shadow percentile; a measured figure must
    name the record it was read from.
    """
    declared = permission.get("gateReservationSeconds")
    if not isinstance(declared, dict) or set(declared) - {"slotBasisRecord"} != {
        "slot",
        "slotBasis",
    }:
        raise ValueError("owner declared Gate reservations required")
    value = declared["slot"]
    if (
        type(value) not in (int, float)
        or isinstance(value, bool)
        or not math.isfinite(value)
        or value < SLOT_FLOOR_SECONDS
    ):
        raise ValueError("slot reservation below the wire ceiling plus slack")
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
    plan = campaign.gate_plan(inputs["plan"], slot_seconds=declared["slot"])
    expiry = permission.get("expiresAt")
    if type(expiry) not in (int, float) or isinstance(expiry, bool):
        raise ValueError("permission expiry required for management dispatch")
    plan["permissionExpiresAt"] = expiry
    return plan


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
        or not now + campaign.CAMPAIGN_SECONDS + campaign.RECOVERY_SECONDS
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
    # Compiling the Gate plan here proves the declared reservation fits the
    # campaign's wall and recovery split before anything is frozen around it.
    campaign.gate_plan(plan, slot_seconds=gate_reservations(permission)["slot"])
    # A permission always names where its production baseline came from, even
    # where the observation journals themselves are not available to re-read.
    commit_baseline.validate_provenance(permission.get("baselineProvenance"))
    if baseline is not None:
        commit_baseline.validate_permission_baseline(permission, baseline)
    validate_owner_identity(permission.get("ownerIdentity"), field="ownerIdentity")
    # The recovery owner answers for a run that stops mid-flight; this campaign
    # can leave up to 21 documents behind when a seed Commit's answer is lost.
    validate_owner_identity(permission.get("recoveryOwner"), field="recoveryOwner")
    principal = permission.get("credentialPrincipal")
    identity_keys = (
        {"clientId", "subject", "requiredScopes"}
        if isinstance(principal, dict) and "subject" in principal
        else {"clientId", "verifiedEmail", "requiredScopes"}
    )
    if (
        not isinstance(principal, dict)
        or set(principal) != identity_keys
        or principal["requiredScopes"] != [campaign.PRINCIPAL_SCOPE]
    ):
        raise ValueError("owner-frozen credential principal required")
    preflight.validate_principal(principal)
    preflight.validate_frozen_baselines(permission)
    if (
        not isinstance(permission.get("permissionReference"), str)
        or not permission["permissionReference"].strip()
    ):
        raise ValueError("owner supplied permissionReference required")


def freeze_inputs(permission_path, plan, *, source_root, artifact_path, baseline=None):
    """Freeze an independently read permission over a verified source snapshot."""
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
        descriptor(), permission, plan, source_commit=commit, artifact_sha256=artifact
    )


def validate_fresh_admission(ledger_root, plan, permission) -> dict:
    """Refuse a reused nonce or a reused owner permission, reading only."""
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
    """The shared Ledger claim for this campaign, with its Gate binding."""
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
        "gateJob": JOB,
        "locks": descriptor_.lock_scopes(plan),
        "budget": campaign.ledger_budget(),
        "durationSeconds": descriptor_.campaign_seconds,
    }


def transport_call(request, token, *, deadline) -> dict:
    """The closed value one bound data wire call carries."""
    return {"request": request, "token": token, "deadline": deadline}


# Every point this campaign can stop at, split by what may exist afterwards.
# A stop during the management preflight, before any data slot, is retirable
# as no data. The first data slot is the typed-absence preflight read of the
# root; it creates nothing, but once it was sent the receipt carries a
# collector bundle and `productionExecuted` is true, which the shared Ledger's
# no-data contract refuses, so that stop is escalation-only in practice and is
# named as such rather than promised. The next two slots create: a lost answer
# to either may have been applied, and that is the one outcome that must never
# be retired as no data. Any later stop follows a seed Commit whose outcome is
# known; its cleanup ladder either proves every document absent, or leaves the
# row with the owner.
NO_DATA_STOP_POINTS = ("schedule-not-started",)
ESCALATION_ONLY_STOP_POINTS = ("preflight-absence",)
UNCERTAIN_STOP_POINTS = ("create-uncertain", "seed-uncertain")
ABANDONED_STOP_POINTS = ("observation-incomplete", "recovery-incomplete")


def stop_points() -> dict[str, tuple[str, ...]]:
    return {
        "noData": NO_DATA_STOP_POINTS,
        "escalationOnly": ESCALATION_ONLY_STOP_POINTS,
        "uncertain": UNCERTAIN_STOP_POINTS,
        "abandoned": ABANDONED_STOP_POINTS,
    }


def _escalation(stop, reason):
    return {
        "stopPoint": stop,
        "disposition": "owner-escalation",
        "retirableAsNoData": False,
        "reason": reason,
    }


def classify_stop(receipt) -> dict:
    """Name the terminal disposition a stopped run is entitled to.

    The abandoned-cleanup close is named only when the shared Ledger will
    accept it: every assigned resource carries a creation proof and every one
    is proven absent. A partial creation, the seed Commit refused after the
    root was created, has proofs for fewer resources than the job holds, and
    `close_after_abandon` refuses it; that stop is the owner's.
    """
    if not isinstance(receipt, dict):
        raise ValueError("bounded receipt required")  # noqa: TRY004 -- refusal class, not a type report
    stop = receipt.get("stopPoint")
    if stop in UNCERTAIN_STOP_POINTS or (
        receipt.get("mayHaveCreated") is True and stop not in ABANDONED_STOP_POINTS
    ):
        return _escalation(
            stop,
            "a create whose answer was lost may have been applied; up to 21 documents can remain",
        )
    if stop in ABANDONED_STOP_POINTS:
        residual = receipt.get("residualSummary") or {}
        if residual.get("complete") is True and residual.get("documents") != 0:
            return _escalation(
                stop,
                "the residual scan found documents under the owned scope that this run did not prove absent",
            )
        absent = receipt.get("ladderAbsenceComplete") is True
        proofs = receipt.get("creationProofCount")
        resources = receipt.get("resourceCount")
        fully_created = (
            type(proofs) is int and type(resources) is int and proofs == resources
        )
        if absent and fully_created:
            return {
                "stopPoint": stop,
                "disposition": "abandoned-cleanup-close",
                "retirableAsNoData": False,
                "reason": "every document was created and every one is proven absent by the recovery ladder",
            }
        if absent:
            return _escalation(
                stop,
                "documents were partially created; the shared Ledger closes an abandoned run only when every resource has a creation proof",
            )
        return _escalation(
            stop,
            "documents were created and the recovery ladder did not prove every one absent",
        )
    if stop in ESCALATION_ONLY_STOP_POINTS:
        return _escalation(
            stop,
            "a data read was dispatched; the shared no-data contract cannot retire a receipt that carries a collector bundle",
        )
    if stop not in NO_DATA_STOP_POINTS:
        raise ValueError("unknown partition/cursor stop point")
    if (
        receipt.get("productionExecuted") is not False
        or receipt.get("collection") is not None
        or receipt.get("mayHaveCreated") is not False
        or receipt.get("dataDispatches") != 0
    ):
        return _escalation(stop, "the journal does not prove that nothing was written")
    return {
        "stopPoint": stop,
        "disposition": "aborted-no-data",
        "retirableAsNoData": True,
        "reason": "no data request was dispatched and no document was created",
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
        not isinstance(item, dict)
        or not isinstance(item.get("responseDigest"), str)
        or item.get("status") != 200
        for item in metadata
    ):
        raise ValueError("receipt records no per-slot management digests")
    return verdict


def no_data_abort_record(receipt, receipt_path, gate_snapshot) -> dict:
    """The shared Ledger's no-data abort record for one persisted receipt."""
    validate_no_data_receipt(receipt)
    generation = receipt["generation"]
    return {
        "kind": "shared-no-data-abort-v1",
        "ticket": receipt["ticket"],
        "planDigest": receipt["planDigest"],
        "gateDigest": digest(gate_snapshot),
        "receiptPath": str(Path(receipt_path).resolve()),
        "receiptDigest": digest(receipt),
        "collectorSourceDigest": generation["collectorSourceDigest"],
        "sourceCommit": generation["sourceCommit"],
        "sourceDigests": copy.deepcopy(generation["sourceDigests"]),
    }


def build_receipt(
    inputs,
    result,
    *,
    capability,
    routes,
    generation,
    management,
    failure=None,
    stop_point=None,
):
    """The campaign receipt: every route by response digest, management by slot."""
    return {
        "kind": campaign.RECEIPT_KIND,
        "campaignId": descriptor().campaign_id,
        "inputsDigest": inputs["inputsDigest"],
        "permissionDigest": inputs["permissionDigest"],
        "planDigest": inputs["planDigest"],
        "collection": result,
        "routes": copy.deepcopy(routes),
        "routeDigest": digest(routes),
        "metadata": management.metadata_rows() if management is not None else [],
        "generation": copy.deepcopy(generation),
        "executionKind": "fixed-production-wire"
        if capability is not None
        else "injected-transport",
        "productionExecuted": capability is not None,
        "workerSha256": capability.binding_digest if capability is not None else None,
        "transportDeadlineSeconds": campaign.wire.PRODUCTION_REQUEST_SECONDS,
        "stopPoint": stop_point,
        "failure": failure,
    }
