"""File-bound O8 admission for FS-WRITE-LIMITS-03.

This module freezes the campaign's inputs, runs the shared O7 admission check
set through the campaign-generic core, and names the terminal states a stopped
run is entitled to. It has no command line; the launcher is `limits_03_o8.py`.

The shared Gate hosts this campaign: the descriptor projects the compiler's
per-slot schedule onto the Gate schema and adds the closed management contract,
and the Ledger claim names the one Gate job. What still stops a run is the
owner's side: a fresh approval for an unreserved nonce, and the declared index
exemption deployed before admission.
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

import limits_03_descriptor as campaign
import limits_03_preflight as preflight
import o8_admission
from broad_contract import digest
from compiler_03 import GATE_WALL_SECONDS_MAX
from o8_admission import (
    ProductionWireCapability,
    execution_host,
    issued_capability,
    revoke_production_capability,
    validate_owner_identity,
)

MAX_INPUT_BYTES = 8 * 1024 * 1024
MISSING_APPROVAL = "a fresh owner approval for an unreserved nonce is required"
PREPARED_PERMISSION_KIND = "limits-03-prepared-owner-execution-permission-v1"

__all__ = [
    "MISSING_APPROVAL",
    "NO_DATA_RECEIPT_SHAPE",
    "NO_DATA_STOP_POINTS",
    "UNCERTAIN_STOP_POINTS",
    "ProductionWireCapability",
    "abort_generation",
    "build_receipt",
    "classify_stop",
    "descriptor",
    "execution_host",
    "freeze_inputs",
    "gate_plan_for",
    "issue_production_capability",
    "issued_capability",
    "management_call",
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


def descriptor(permission=None):
    value = campaign.descriptor()
    if (
        isinstance(permission, dict)
        and permission.get("kind") == PREPARED_PERMISSION_KIND
    ):
        from o8_campaign import CampaignDescriptor

        members = value.members()
        members.update(
            permission_kind=PREPARED_PERMISSION_KIND,
            frozen_inputs_kind="limits-03-prepared-frozen-inputs-v1",
            approval_kind="limits-03-prepared-o8-approval-v1",
            manifest_kind="limits-03-prepared-o8-manifest-v1",
        )
        return CampaignDescriptor(**members)
    return value


def permission_bindings(plan, source_commit, artifact_digest, inputs, baseline=None):
    return campaign.permission_bindings(
        plan, source_commit, artifact_digest, inputs, baseline
    )


def validate_frozen_inputs(inputs) -> None:
    permission = inputs.get("permission", {}) if isinstance(inputs, dict) else {}
    o8_admission.validate_frozen_inputs(descriptor(permission), inputs)
    _validate_preparation_permission(permission)


def abort_generation(inputs):
    return o8_admission.abort_generation(descriptor(), inputs)


def validate_o7_admission(**bindings):
    _validate_preparation_permission(
        bindings["permission"], ledger_root=bindings["ledger_root"]
    )
    return o8_admission.validate_o7_admission(
        descriptor(bindings["permission"]), **bindings
    )


def issue_production_capability(**bindings):
    _validate_preparation_permission(
        bindings["permission"], ledger_root=bindings["ledger_root"]
    )
    return o8_admission.issue_production_capability(
        descriptor(bindings["permission"]), **bindings
    )


def _validate_preparation_permission(permission, *, ledger_root=None):
    """Bind the prepared variant to an actually released same-family baseline."""
    reference = permission.get("baselinePreparation")
    if permission.get("kind") != PREPARED_PERMISSION_KIND:
        if reference is not None:
            raise ValueError("PREP baseline requires prepared permission kind")
        return
    if not isinstance(reference, dict) or set(reference) != {
        "packet",
        "ticket",
        "receiptPath",
    }:
        raise ValueError("terminal PREP baseline required")
    from limits_03_baseline_prep import validate_packet
    from reservations import Ledger

    packet, ticket = reference["packet"], reference["ticket"]
    validate_packet(packet)
    if not isinstance(ticket, dict) or digest(ticket) != packet["ticketDigest"]:
        raise ValueError("terminal PREP baseline ticket differs")
    if ledger_root is not None and ticket.get("ledgerPath") != str(
        Path(ledger_root).resolve()
    ):
        raise ValueError("terminal PREP baseline Ledger differs")
    ledger = Ledger(ticket["ledgerPath"])
    state = ledger.snapshot()
    if ticket.get("ledgerIdentity") != state["identity"]:
        raise ValueError("terminal PREP baseline Ledger identity differs")
    row = state["reservations"].get(ticket.get("reservation"))
    if (
        not isinstance(row, dict)
        or row.get("state") != "released"
        or row.get("claimDigest") != ticket.get("claimDigest")
        or row.get("envelopeDigest") != ticket.get("envelopeDigest")
        or row.get("claim", {}).get("campaignId") != campaign.CAMPAIGN
        or row.get("claim", {}).get("nonceDigest") != digest(packet["nonce"])
        or row.get("generation", {}).get("sourceCommit") != packet["sourceCommit"]
        or row.get("generation", {}).get("collectorSourceDigest")
        != packet["sourceDigest"]
    ):
        raise ValueError("terminal PREP baseline was not released")
    receipt_path = Path(reference["receiptPath"])
    if (
        str(receipt_path.resolve()) != str(receipt_path)
        or str(receipt_path.parent / "gate") != row["claim"]["gatePath"]
    ):
        raise ValueError("terminal PREP baseline receipt path differs")
    receipt = ledger._read_bounded_json(receipt_path)
    original_packet = {
        key: value
        for key, value in packet.items()
        if key not in {"packetDigest", "reservationReleased", "terminalReceiptDigest"}
    }
    original_packet["packetDigest"] = digest(original_packet)
    if (
        digest(receipt) != packet["terminalReceiptDigest"]
        or receipt.get("ticket") != ticket
        or receipt.get("collection") != original_packet
        or receipt.get("releaseEligible") is not True
        or receipt.get("failure") is not None
        or row.get("evidence", {}).get("receiptSha256") != digest(receipt)
        or row.get("evidence", {}).get("collectionDigest") != digest(original_packet)
        or permission.get("nonce") == packet["nonce"]
        or permission.get("authConfigDigest") != packet["authConfigDigest"]
        or permission.get("databaseProjectionDigest")
        != packet["database"]["projectionDigest"]
        or digest(permission.get("credentialPrincipal")) != packet["principalDigest"]
        or digest(permission.get("ownerIdentity")) != packet["ownerIdentityDigest"]
    ):
        raise ValueError("terminal PREP baseline binding differs")


management_call = preflight.management_call


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
    expiry = permission.get("expiresAt")
    if type(expiry) not in (int, float) or isinstance(expiry, bool):
        raise ValueError("permission expiry required for management dispatch")
    plan = campaign.gate_plan(
        campaign.execution_plan(inputs["plan"]), permission_expires_at=expiry
    )
    if plan["wallSeconds"] > GATE_WALL_SECONDS_MAX:
        raise ValueError("campaign wall above the Gate ceiling")
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


def _validate_index_precondition(permission) -> None:
    """The permission must carry the declared exemption step, deploy and restore.

    The step is a shared configuration change, so it is locked and bound here
    rather than assumed: the before and after digests, the field readback the
    preflight compares, and the restore that is owed after the run.
    """
    declared = permission.get("indexExemptionPrecondition")
    expected = campaign.index_exemption_precondition()
    if not isinstance(declared, dict) or digest(declared) != digest(expected):
        raise ValueError("declared index exemption precondition differs")
    if declared.get("restoreRequiredAfterRun") is not True:
        raise ValueError("the index exemption restore must be declared owed")
    if (
        permission.get("indexExemptionProjectionDigest")
        != expected["readback"]["projectionDigest"]
    ):
        raise ValueError("index exemption digest is not the declared after state")
    acknowledged = permission.get("indexExemptionDeployedBy")
    if not isinstance(acknowledged, str) or not acknowledged.strip():
        raise ValueError("owner acknowledgement of the deployed exemption required")


def _validate_index_lifecycle_contract(permission) -> None:
    declared = permission.get("indexLifecycleContract")
    expected = campaign.lifecycle_contract()
    if not isinstance(declared, dict) or digest(declared) != digest(expected):
        raise ValueError("declared index lifecycle contract differs")
    if (
        declared.get("pollLimit") != 1
        or declared.get("observationSlots") != 4
        or declared.get("recoverySlots") != 3
    ):
        raise ValueError("one-poll lifecycle reservation required")


def _approve(permission, plan, source_commit, artifact_digest, inputs) -> None:
    required = permission_bindings(plan, source_commit, artifact_digest, inputs)
    if permission.get("kind") == PREPARED_PERMISSION_KIND:
        required["kind"] = PREPARED_PERMISSION_KIND
    _validate_preparation_permission(permission)
    if digest({key: permission.get(key) for key in required}) != digest(required):
        raise ValueError("typed owner permission binding differs")
    _validate_owner_window(permission)
    # Compiling the Gate plan here proves the allocation fits the Gate's
    # ceiling before anything is frozen around it.
    gate_plan_for({"plan": plan}, permission)
    validate_owner_identity(permission.get("ownerIdentity"), field="ownerIdentity")
    # The recovery owner answers for a campaign that stops mid-flight: this one
    # can leave up to 29 documents behind when a request times out.
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
    _validate_index_precondition(permission)
    _validate_index_lifecycle_contract(permission)
    if (
        not isinstance(permission.get("permissionReference"), str)
        or not permission["permissionReference"].strip()
    ):
        raise ValueError("owner supplied permissionReference required")


def freeze_inputs(permission_path, plan, *, source_root, artifact_path):
    """Freeze an independently read permission over a verified source snapshot."""
    campaign.execution_plan(plan)
    permission = _read(permission_path)
    inputs = campaign.source_map()
    commit = subprocess.check_output(
        ["git", "-C", str(source_root), "rev-parse", "HEAD"], text=True
    ).strip()
    artifact = _artifact(artifact_path)
    _provenance(source_root, commit, inputs)
    _approve(permission, plan, commit, artifact, inputs)
    return o8_admission.freeze_inputs(
        descriptor(permission),
        permission,
        plan,
        source_commit=commit,
        artifact_sha256=artifact,
    )


def freeze_prepared_inputs(permission_path, plan, *, source_root, artifact_path):
    """The strict final-permission freeze for a newly captured PREP packet."""
    if _read(permission_path).get("kind") != PREPARED_PERMISSION_KIND:
        raise ValueError("prepared owner permission kind required")
    return freeze_inputs(
        permission_path, plan, source_root=source_root, artifact_path=artifact_path
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
        "gateJob": campaign.GATE_JOB,
        "locks": descriptor_.lock_scopes(plan),
        "budget": campaign.ledger_budget(),
        "durationSeconds": descriptor_.campaign_seconds,
    }


def transport_call(plan, phase, index, operation, token, *, deadline) -> dict:
    """The closed value one bound wire call carries."""
    return {
        "plan": plan,
        "phase": phase,
        "index": index,
        "operation": operation,
        "token": token,
        "deadline": deadline,
    }


# Every point this campaign can stop at with nothing of its own left behind.
# The schedule opens with the typed-absence preflight of every owned name,
# which cannot create; a stop anywhere in that prefix, or before the schedule
# started, is a no-data stop. A stop at a create's transport deadline is NOT: the
# write may have been applied while the receipt was lost. A stop after a
# confirmed create is neither: the run abandons and cleans what it created.
NO_DATA_STOP_POINTS = ("schedule-not-started", "namespace-preflight")
UNCERTAIN_STOP_POINTS = ("create-deadline",)
ABANDONED_STOP_POINTS = ("observation-incomplete", "recovery-incomplete")
# The shape of this lane's receipt for a no-data stop, stated once so the
# shared Ledger's receipt-kind map can carry it. `metadata` is the data journal
# (one row per charged data request), `managementEvidence` the charged
# management journal, and `credentialEvidence` the token attestation bodies the
# shared Gate admits. A stop before the schedule started has an empty data
# journal and no collection at all; a stop inside the typed-absence preflight
# has data rows that could not create, which the Gate journal proves through
# its `creates: false` schedule declarations.
NO_DATA_RECEIPT_SHAPE = {
    "kind": campaign.RECEIPT_KIND,
    "dataJournal": "metadata",
    "managementJournal": "managementEvidence",
    "credentialEvidence": "credentialEvidence",
    "credentialAttestationKind": "request-byte-token-attestation-v1",
    "credentialSlots": ["tokeninfo"],
    "stopPointField": "stopPoint",
    "noDataStopPoints": list(NO_DATA_STOP_POINTS),
    "scheduleNotStarted": {
        "metadata": [],
        "collection": None,
        "productionExecuted": False,
        "createdResources": [],
        "mayHaveCreated": False,
    },
    "namespacePreflight": {
        "productionExecuted": True,
        "createdResources": [],
        "mayHaveCreated": False,
        "gate": "every consumed slot declared creates: false, no recovery wire event",
    },
}


def stop_points() -> dict[str, tuple[str, ...]]:
    return {
        "noData": NO_DATA_STOP_POINTS,
        "uncertain": UNCERTAIN_STOP_POINTS,
        "abandoned": ABANDONED_STOP_POINTS,
    }


def classify_stop(receipt) -> dict:
    """Name the terminal disposition a stopped run is entitled to."""
    if not isinstance(receipt, dict):
        raise ValueError("bounded receipt required")  # noqa: TRY004 -- refusal class, not a type report
    stop = receipt.get("stopPoint")
    collection = receipt.get("collection") or {}
    created = receipt.get("createdResources") or []
    if stop in UNCERTAIN_STOP_POINTS or receipt.get("mayHaveCreated") and not created:
        return {
            "stopPoint": stop,
            "disposition": "owner-escalation",
            "retirableAsNoData": False,
            "reason": (
                "a create whose receipt was lost may have been applied; up to "
                "29 documents can remain under the owned scope"
            ),
        }
    if stop in ABANDONED_STOP_POINTS:
        closable = (
            collection.get("cleanupComplete") is True
            and receipt.get("abandonedCleanupComplete") is True
        )
        return {
            "stopPoint": stop,
            "disposition": "abandoned-cleanup-close"
            if closable
            else "owner-escalation",
            "retirableAsNoData": False,
            "reason": (
                "documents were created and the run abandoned; the Gate journal "
                "proves every one of them absent and the abandoned close applies"
                if closable
                else "documents were created and the run abandoned; the Gate's "
                "abandoned close compares creation proofs against every declared "
                "resource, so a campaign that declares resources it may refuse to "
                "create stays with the owner-attested exit"
            ),
        }
    if stop not in NO_DATA_STOP_POINTS:
        raise ValueError("unknown limits-03 stop point")
    if stop == "schedule-not-started":
        # No data request was ever sent: the data journal is empty and there
        # is no collection. The Gate journal behind such a receipt has no
        # events at all, which is what exit 2 already states.
        proven = (
            receipt.get("metadata") == []
            and receipt.get("collection") is None
            and receipt.get("productionExecuted") is False
        )
    else:
        proven = receipt.get("productionExecuted") is True
    if created or receipt.get("mayHaveCreated") or not proven:
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
        "reason": "no creating request was dispatched and no document was created",
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
        "kind": campaign.RECEIPT_KIND,
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
