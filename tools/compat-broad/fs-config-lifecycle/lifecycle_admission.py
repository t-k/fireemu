"""File-bound O8 admission for the FS-CONFIG-LIFECYCLE campaign.

This module freezes the campaign's inputs over a verified source snapshot, runs the
shared O7 admission check set through the campaign-generic core, compiles the shared
Ledger claim with the EXCLUSIVE field-configuration locks, and classifies a stopped
run's terminal disposition. It has no command line; the launcher is `lifecycle_o8.py`.

What still stops a run is the owner's side: a fresh approval for an unreserved nonce
and a frozen database projection digest. A clean run can retire through the typed
configuration-management finalizer; document campaigns retain the shared Gate's
document-absence contract.
"""

from __future__ import annotations

import copy
import hashlib
import json
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

import _lane

_lane.ensure_package()

import o8_admission
from broad_contract import digest
from fs_config_lifecycle import lifecycle_descriptor as campaign
from fs_config_lifecycle.lifecycle_gate import (
    FINISHED_STATES,
    LEDGER_JOB,
    RESTORED,
    gate_plan,
    validate_plan,
)
from o8_admission import (
    ProductionWireCapability,
    execution_host,
    issued_capability,
    revoke_production_capability,
    validate_owner_identity,
)

MAX_INPUT_BYTES = 8 * 1024 * 1024
MISSING_APPROVAL = "a fresh owner approval for an unreserved nonce is required"
RELEASE_BLOCKED_KIND = "fs-config-lifecycle-release-blocked-v1"
UNRECOVERED_DISPOSITION = "owner-restore"
RESTORED_DISPOSITION = "release-blocked-restored"
NO_MUTATION_DISPOSITION = "held-no-mutation"
ESCALATION_DISPOSITION = "owner-escalation"
_HEX64 = re.compile(r"[a-f0-9]{64}")

RELEASE_BLOCKER = {
    "kind": "configuration-management-finalizer-v1",
    "reason": "typed-configuration-restoration-proof",
    "detail": (
        "reservations.Ledger.finish_management_only() retires only after attached "
        "receipt evidence and the registered lifecycle Gate prove before/after "
        "restoration and reconciliation"
    ),
}

__all__ = [
    "MISSING_APPROVAL",
    "RELEASE_BLOCKED_KIND",
    "RELEASE_BLOCKER",
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
    "permission_bindings",
    "release_supported",
    "reservation_claim",
    "revoke_production_capability",
    "validate_fresh_admission",
    "validate_frozen_inputs",
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


def release_supported() -> tuple[bool, dict]:
    """Whether the typed configuration-management finalizer is available."""
    return True, copy.deepcopy(RELEASE_BLOCKER)


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


def validate_baseline(permission, baseline=None) -> str:
    """The frozen database projection digest the first read must equal."""
    frozen = permission.get("databaseProjectionDigest")
    if not isinstance(frozen, str) or _HEX64.fullmatch(frozen) is None:
        raise ValueError("frozen database projection digest required")
    if baseline is not None and baseline.get("projectionDigest") != frozen:
        raise ValueError("frozen database projection digest differs from the baseline")
    return frozen


def _approve(permission, plan, source_commit, artifact_digest, inputs, baseline=None):
    required = permission_bindings(
        plan, source_commit, artifact_digest, inputs, baseline
    )
    if digest({key: permission.get(key) for key in required}) != digest(required):
        raise ValueError("typed owner permission binding differs")
    _validate_owner_window(permission)
    validate_baseline(permission, baseline)
    validate_owner_identity(permission.get("ownerIdentity"), field="ownerIdentity")
    # The recovery owner answers for a field configuration this campaign could not
    # put back; it carries the same provenance weight as the execution identity.
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
        or any(
            not isinstance(principal[key], str) or not principal[key].strip()
            for key in identity_keys - {"requiredScopes"}
        )
    ):
        raise ValueError("owner-frozen credential principal required")
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
    short = plan["nonce"][:12]
    for row in state.get("reservations", {}).values():
        claim = row.get("claim", {})
        if claim.get("nonceDigest") == nonce_digest:
            raise ValueError("campaign nonce already reserved")
        for lock in claim.get("locks", []):
            key = str(lock.get("key", ""))
            if plan["nonce"] in key or f"fsconfig_ttl_{short}" in key:
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


def gate_plan_for(inputs, permission) -> dict:
    """The configuration gate plan one admitted run journals and the Ledger binds."""
    plan = campaign.execution_plan(inputs["plan"])
    expiry = permission.get("expiresAt")
    if type(expiry) not in (int, float) or isinstance(expiry, bool):
        raise ValueError("permission expiry required for the gate")
    value = gate_plan(
        plan["nonce"],
        baseline_projection_digest=validate_baseline(permission),
        permission_expires_at=expiry,
    )
    validate_plan(value)
    return value


def reservation_claim(inputs, *, gate_path, gate_plan):
    """The shared Ledger claim for this campaign, with its gate binding."""
    descriptor_ = descriptor()
    plan = inputs["plan"]
    if (
        digest(gate_plan.get("nonce")) != digest(plan["nonce"])
        or gate_plan.get("campaignId") != descriptor_.campaign_id
    ):
        raise ValueError("gate plan belongs to another campaign or nonce")
    return {
        "campaignId": descriptor_.campaign_id,
        "manifestDigest": inputs["planDigest"],
        "nonceDigest": digest(plan["nonce"]),
        "gatePath": str(Path(gate_path).resolve()),
        "gatePlanDigest": digest(gate_plan),
        "gateJob": LEDGER_JOB,
        "locks": descriptor_.lock_scopes(plan),
        "budget": campaign.ledger_budget(),
        "durationSeconds": descriptor_.campaign_seconds,
    }


def envelope(permission, claim) -> dict:
    return {
        "permissionDigest": digest(permission),
        "issuedAt": permission["issuedAt"],
        "expiresAt": permission["expiresAt"],
        "limits": copy.deepcopy(claim["budget"]),
        "concurrency": 1,
        "scopes": copy.deepcopy(claim["locks"]),
    }


def classify_stop(receipt) -> dict:
    """Name the terminal disposition a run is entitled to.

    A run whose every locked step is back at its baseline and whose reconciliation
    passed is restored; it would be release-eligible, and today it is release-blocked
    by the shared core. A run with any unrestored step needs the owner to restore the
    field by hand; its reservation stays held with the typed unrecovered record. A run
    that cannot say which is escalated.
    """
    if not isinstance(receipt, dict):
        raise ValueError("bounded receipt required")  # noqa: TRY004 -- refusal class, not a type report
    collection = receipt.get("collection") or {}
    steps = collection.get("steps") or {}
    unrecovered = collection.get("unrecovered") or []
    restored = bool(steps) and all(
        step.get("restore") in FINISHED_STATES for step in steps.values()
    )
    if unrecovered or (steps and not restored):
        return {
            "stopPoint": collection.get("stopPoint"),
            "disposition": UNRECOVERED_DISPOSITION,
            "releaseEligible": False,
            "reason": "a patched field configuration is not proven back at its baseline",
            "resources": [item.get("resource") for item in unrecovered],
        }
    if restored and collection.get("mutationAttempted") is False:
        # Stopped before any patch left (credential preflight, projection drift,
        # an unavailable control): nothing to restore, nothing released either.
        return {
            "stopPoint": collection.get("stopPoint"),
            "disposition": NO_MUTATION_DISPOSITION,
            "releaseEligible": False,
            "reason": "no patch was sent; the reservation is held with an empty ledger",
        }
    if restored and collection.get("cleanupComplete") is True:
        supported, blocker = release_supported()
        supported = supported and collection.get("completed") is True
        return {
            "stopPoint": collection.get("stopPoint"),
            "disposition": "release-eligible" if supported else RESTORED_DISPOSITION,
            "releaseEligible": supported,
            "reason": blocker["reason"] if not supported else "restore verified",
            "restoredSteps": [
                name for name, step in steps.items() if step.get("restore") == RESTORED
            ],
        }
    return {
        "stopPoint": collection.get("stopPoint"),
        "disposition": ESCALATION_DISPOSITION,
        "releaseEligible": False,
        "reason": "the journal does not prove that every field is back at its baseline",
    }


def build_receipt(
    inputs, result, *, production, worker_sha256, generation, failure=None
):
    """The campaign receipt: digests, restore states and the typed disposition."""
    steps = (result or {}).get("steps") or {}
    return {
        "kind": campaign.RECEIPT_KIND,
        "campaignId": descriptor().campaign_id,
        "inputsDigest": inputs["inputsDigest"],
        "permissionDigest": inputs["permissionDigest"],
        "planDigest": inputs["planDigest"],
        "collection": result,
        "restore": {
            name: {
                "restore": step["restore"],
                "preDigest": step["preDigest"],
                "postDigest": step["postDigest"],
                "verifyDigest": step["verifyDigest"],
            }
            for name, step in steps.items()
        },
        "generation": copy.deepcopy(generation),
        "executionKind": "fixed-production-wire"
        if production
        else "injected-transport",
        "productionExecuted": bool(production),
        "workerSha256": worker_sha256,
        "stopPoint": (result or {}).get("stopPoint"),
        "failure": failure,
    }
