"""File-bound O8 admission for the transaction expiry campaign.

This module freezes the campaign's inputs over a verified source snapshot,
runs the shared O7 admission check set through the campaign-generic core,
compiles the Gate plan the reservation is bound to, and classifies how a
stopped run may be retired. It has no command line; the launcher is
`txn_expiry_o8.py`.

Nothing here grants authority. What still stops a run is the owner's side: a
fresh approval for an unreserved nonce, a private credential handoff, and a
reservation in the shared Ledger.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import re
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
import shared_gate
import txn_expiry_descriptor as campaign
import txn_expiry_preflight as preflight
from broad_contract import digest
from o8_admission import (
    ProductionWireCapability,
    execution_host,
    issued_capability,
    revoke_production_capability,
    validate_owner_identity,
)
from txn_expiry_descriptor import commit_baseline

MAX_INPUT_BYTES = 8 * 1024 * 1024
MISSING_APPROVAL = "a fresh owner approval for an unreserved nonce is required"
_HEX64 = re.compile(r"[a-f0-9]{64}")

__all__ = [
    "MISSING_APPROVAL",
    "ProductionWireCapability",
    "abort_generation",
    "build_abandon_record",
    "build_abort_record",
    "build_receipt",
    "classify_stop",
    "descriptor",
    "execution_host",
    "freeze_inputs",
    "gate_plan_for",
    "issue_production_capability",
    "issued_capability",
    "permission_bindings",
    "reservation_claim",
    "revoke_production_capability",
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


def transport_call(request, token, *, deadline) -> dict:
    """The closed value one bound data wire call carries."""
    if not isinstance(request, dict) or not isinstance(token, str) or not token:
        raise ValueError("closed transaction expiry wire call required")
    if (
        type(deadline) not in (int, float)
        or isinstance(deadline, bool)
        or not math.isfinite(deadline)
    ):
        raise ValueError("finite absolute deadline required")
    return {"kind": "data", "request": request, "token": token, "deadline": deadline}


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


def gate_plan_for(inputs, permission) -> dict:
    """Compile this campaign's Gate plan from the frozen inputs and permission."""
    plan = campaign.gate_plan(campaign.execution_plan(inputs["plan"]))
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
    if permission.get("timing") != "wall-clock":
        raise ValueError("production elapsed time cannot be simulated")
    _validate_owner_window(permission)
    # Compiling the Gate plan here proves the reservations fit the campaign's
    # wall and recovery split before anything is frozen around them.
    campaign.gate_plan(campaign.execution_plan(plan))
    commit_baseline.validate_provenance(permission.get("baselineProvenance"))
    if baseline is not None:
        commit_baseline.validate_permission_baseline(permission, baseline)
    validate_owner_identity(permission.get("ownerIdentity"), field="ownerIdentity")
    # The recovery owner answers for a run that stops mid-flight with up to
    # five documents and several open transactions behind it.
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
        "gateJob": campaign.JOB,
        "locks": descriptor_.lock_scopes(plan),
        "budget": campaign.ledger_budget(),
        # The Gate wall, recovery included, is what the Ledger bounds. The
        # collector's recovery window past that wall is inside the owner's
        # 1380-second permission window, checked by the O7 admission.
        "durationSeconds": campaign.GATE_WALL_SECONDS,
    }


# -- receipts and stop classification -----------------------------------------

#: Where a stopped run may have stopped with nothing of its own left behind:
#: before any request, during the five ownership preflight reads, or at the
#: first create's transport before it was dispatched. Anything later has sent
#: a request that could create.
NO_DATA_STOP_POINTS = (
    "schedule-not-started",
    "management-preflight",
    "ownership-preflight",
)
ABANDONED_STOP_POINT = "abandoned-after-create"
UNCERTAIN_STOP_POINT = "create-outcome-unknown"


def stop_point(snapshot, ready):
    """Name the terminal state the Gate journal is entitled to."""
    if ready:
        return None
    if snapshot is None:
        return "schedule-not-started"
    job = snapshot["jobs"][campaign.JOB]
    if shared_gate.unconfirmed_creates(snapshot, campaign.JOB):
        return UNCERTAIN_STOP_POINT
    outcome = shared_gate.creating_outcome(snapshot, campaign.JOB)
    if outcome == "none":
        return "ownership-preflight" if job["observation"] else "management-preflight"
    return ABANDONED_STOP_POINT


def classify_stop(receipt) -> dict:
    """Name the terminal disposition a stopped run is entitled to.

    A no-data stop is retirable through `Ledger.abort_no_data`: no creating
    request was dispatched. A run that created and then proved every created
    document absent again is retirable through `Ledger.close_after_abandon`.
    A create whose answer was lost, or a document that could not be proven
    absent, stays with the owner-attested escalation close.
    """
    if not isinstance(receipt, dict):
        raise ValueError("bounded receipt required")  # noqa: TRY004 -- refusal class, not a type report
    stop = receipt.get("stopPoint")
    if stop is None:
        released = receipt.get("releaseEligible") is True
        return {
            "stopPoint": None,
            "disposition": "released" if released else "owner-escalation",
            "retirableAsNoData": False,
            "reason": (
                "the run completed and its reservation is released by Ledger.finish"
                if released
                else "the run names no stop point and is not release-eligible"
            ),
        }
    if (
        stop == UNCERTAIN_STOP_POINT
        or receipt.get("mayHaveCreated")
        and stop in NO_DATA_STOP_POINTS
    ):
        return {
            "stopPoint": stop,
            "disposition": "owner-escalation",
            "retirableAsNoData": False,
            "reason": "a create whose answer was lost may have been applied",
        }
    if stop in NO_DATA_STOP_POINTS:
        if (
            receipt.get("productionExecuted") is not False
            or receipt.get("collection") is not None
        ):
            return {
                "stopPoint": stop,
                "disposition": "owner-escalation",
                "retirableAsNoData": False,
                "reason": "the receipt does not prove that nothing was written",
            }
        return {
            "stopPoint": stop,
            "disposition": "aborted-no-data",
            "retirableAsNoData": True,
            "reason": "no creating request was dispatched",
        }
    if stop == ABANDONED_STOP_POINT:
        collection = receipt.get("collection")
        gate = receipt.get("gate")
        if not isinstance(collection, dict):
            # A run that stopped in Python after a create, before the collector
            # produced a receipt, has no cleanup record at all; the Ledger will
            # refuse the abandoned close and so does this classification.
            return {
                "stopPoint": stop,
                "disposition": "owner-escalation",
                "retirableAsNoData": False,
                "reason": "the run created documents and recorded no cleanup",
            }
        recovered = (
            collection.get("unrecovered") == []
            and collection.get("openTransactions") == []
            and (
                gate is None or shared_gate.abandoned_cleanup_complete(gate) is not None
            )
        )
        reason = (
            "the run created documents and proved every one absent again"
            if recovered
            else "a created document or an open transaction remains"
        )
        if recovered and collection.get("unconfirmedTransactionStarts"):
            reason += (
                "; a transaction whose start was never confirmed holds no document "
                "and expires on its own"
            )
        return {
            "stopPoint": stop,
            "disposition": "closed-after-abandon" if recovered else "owner-escalation",
            "retirableAsNoData": False,
            "reason": reason,
        }
    raise ValueError("unknown transaction expiry stop point")


def validate_no_data_receipt(receipt) -> dict:
    """Accept only a receipt that proves this campaign dispatched no create."""
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
        raise ValueError("receipt records no per-slot response digests")
    return verdict


def _persisted_receipt(output):
    output = Path(output)
    if output.is_symlink():
        raise ValueError("regular evidence directory required")
    path = (output / "receipt.json").resolve()
    if path.is_symlink() or not path.is_file():
        raise ValueError("persisted canonical receipt required")
    raw = path.read_bytes()
    receipt = json.loads(raw)
    if not isinstance(receipt, dict):
        raise ValueError("bounded receipt required")  # noqa: TRY004 -- refusal class, not a type report
    return path, receipt


def build_abort_record(output) -> dict:
    """The `shared-no-data-abort-v1` record for one persisted no-data receipt.

    Every field is read from the run's own receipt, which recorded the source
    closure at acquisition time; nothing is taken from the current tree.
    """
    path, receipt = _persisted_receipt(output)
    validate_no_data_receipt(receipt)
    generation = receipt["generation"]
    return {
        "kind": "shared-no-data-abort-v1",
        "ticket": receipt["ticket"],
        "planDigest": receipt["planDigest"],
        "gateDigest": receipt["gateDigest"],
        "receiptPath": str(path),
        "receiptDigest": digest(receipt),
        "collectorSourceDigest": generation["collectorSourceDigest"],
        "sourceCommit": generation["sourceCommit"],
        "sourceDigests": copy.deepcopy(generation["sourceDigests"]),
    }


def build_abandon_record(output) -> dict:
    """The `shared-abandoned-cleanup-close-v1` record for one persisted receipt."""
    path, receipt = _persisted_receipt(output)
    verdict = classify_stop(receipt)
    if verdict["disposition"] != "closed-after-abandon":
        raise ValueError(f"receipt is not an abandoned cleanup: {verdict['reason']}")
    return {
        "kind": "shared-abandoned-cleanup-close-v1",
        "ticket": receipt["ticket"],
        "gateDigest": receipt["gateDigest"],
        "receiptPath": str(path),
        "receiptDigest": digest(receipt),
    }


def build_receipt(
    inputs, result, *, rows, management, generation, failure=None, stop=None
):
    """The campaign receipt, binding every request it sent by digest.

    `metadata` carries the charged management metadata slots, the vocabulary
    the shared Ledger reads a no-data stop from; the data requests are under
    `dataRoutes`. `productionExecuted` is the Ledger's term for "a request
    that could create was dispatched"; a run that stopped inside its
    ownership preflight reads did send data requests, and `dataRequestsSent`
    says how many, but it executed no acquisition.
    """
    data_routes = [
        {
            "id": f"{row['phase']}:{row['index']:03d}",
            "site": row["site"],
            "route": row["route"],
            "status": row.get("status"),
            "requestDigest": row["requestDigest"],
            "responseDigest": row["responseDigest"],
        }
        for row in rows
    ]
    evidence = list(management.evidence) if management is not None else []
    metadata = [
        {
            "id": row["id"],
            "status": row["response"].get("status"),
            "responseDigest": row["responseDigest"],
        }
        for row in evidence
        if not row["id"].endswith(":oauth-tokeninfo")
        and row["response"].get("complete") is True
    ]
    attestations = (
        list(management.credential_evidence) if management is not None else []
    )
    credential_evidence = [
        {
            "slot": "tokeninfo",
            "status": 200,
            "complete": True,
            "workerReaped": True,
            "verified": True,
            "attestationDigest": digest(body),
        }
        for body in attestations
    ]
    return {
        "kind": campaign.RECEIPT_KIND,
        "campaignId": descriptor().campaign_id,
        "inputsDigest": inputs["inputsDigest"],
        "permissionDigest": inputs["permissionDigest"],
        "campaignPlanDigest": inputs["planDigest"],
        "collection": result,
        "dataRoutes": data_routes,
        "dataRouteDigest": digest(data_routes),
        "dataRequestsSent": len(data_routes),
        "metadata": metadata,
        "routeDigest": digest(metadata),
        "managementEvidence": evidence,
        "credentialAttestations": attestations,
        "credentialEvidence": credential_evidence,
        "preflightComplete": bool(
            management is not None and management.preflight_complete
        ),
        "postflightComplete": bool(
            management is not None and management.postflight_complete
        ),
        "generation": copy.deepcopy(generation),
        "timing": "wall-clock",
        "workerSha256": inputs["sourceInputs"][campaign.WORKER_ENTRY],
        "stopPoint": stop,
        "failure": failure,
    }
