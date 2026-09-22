"""File-bound O8 admission for the AUTH-CREDENTIAL campaign.

This module freezes the campaign's inputs, runs the shared O7 admission check set
through the campaign-generic core, validates the owner's permission and the private
credential handoff, and compiles the Ledger claim. It has no command line; the
launcher is `credential_o8.py`.

The handoff carries two secrets and one optional capability: the owner's OAuth
bearer for the privileged Identity Toolkit calls, the project's Web API key for the
end-user calls, and, when the bearer may sign for the oracle service account, the
signing declaration that lets the run mint RS256 custom tokens. Without it the plan
must have been frozen without signing, and the eleven signing-dependent cases are
recorded as not run.
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

import credential_descriptor as campaign
import credential_gate as gate_module
import credential_preflight as preflight
import o8_admission
from broad_contract import digest
from o8_admission import (
    ProductionWireCapability,
    execution_host,
    issued_capability,
    revoke_production_capability,
    validate_owner_identity,
)

MAX_INPUT_BYTES = 8 * 1024 * 1024
HANDOFF_KIND = "auth-credential-handoff-v1"
BOOTSTRAP_PERMISSION_KIND = "auth-credential-bootstrap-permission-v1"
HANDOFF_FIELDS = frozenset({"kind", "permissionDigest", "token", "apiKey", "signing"})
SIGNING_FIELDS = frozenset({"serviceAccount"})
MISSING_APPROVAL = "a fresh owner approval for an unreserved nonce is required"

__all__ = [
    "HANDOFF_KIND",
    "MISSING_APPROVAL",
    "ProductionWireCapability",
    "abort_generation",
    "bootstrap_reservation_claim",
    "validate_bootstrap_permission",
    "build_receipt",
    "descriptor",
    "execution_host",
    "freeze_inputs",
    "gate_plan_for",
    "issue_production_capability",
    "issued_capability",
    "permission_bindings",
    "reservation_claim",
    "revoke_production_capability",
    "validate_fresh_admission",
    "validate_frozen_inputs",
    "validate_handoff",
    "validate_o7_admission",
]


def descriptor():
    return campaign.descriptor()


def permission_bindings(plan, source_commit, artifact_digest, inputs, baseline=None):
    return campaign.permission_bindings(plan, source_commit, artifact_digest, inputs, baseline)


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


def gate_plan_for(inputs, permission) -> dict:
    """Compile this campaign's Gate plan from the frozen inputs and permission."""
    plan = campaign.execution_plan(inputs["plan"])
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
        or not now + campaign.campaign_seconds() + campaign.recovery_seconds() <= expiry <= issued + 86400
    ):
        raise ValueError("owner permission expired or too short for recovery")


def _approve(permission, plan, source_commit, artifact_digest, inputs) -> None:
    required = permission_bindings(plan, source_commit, artifact_digest, inputs)
    if digest({key: permission.get(key) for key in required}) != digest(required):
        raise ValueError("typed owner permission binding differs")
    _validate_owner_window(permission)
    # Compiling the Gate plan here proves the frozen reference names a plan the
    # shared Gate would admit, before anything is frozen around it.
    campaign.execution_plan(plan)
    validate_owner_identity(permission.get("ownerIdentity"), field="ownerIdentity")
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
    preflight.validate_frozen_baseline(permission)
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
            if plan["nonce"][:8] in str(lock.get("key", "")):
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
    if digest(gate_plan.get("nonce")) != digest(plan["nonce"]) or gate_plan.get("campaignId") != descriptor_.campaign_id:
        raise ValueError("Gate plan belongs to another campaign or nonce")
    return {
        "campaignId": descriptor_.campaign_id,
        "manifestDigest": inputs["planDigest"],
        "nonceDigest": digest(plan["nonce"]),
        "gatePath": str(Path(gate_path).resolve()),
        "gatePlanDigest": digest(gate_plan),
        "gateJob": gate_module.JOB,
        "locks": descriptor_.lock_scopes(plan),
        "budget": campaign.ledger_budget(),
        "durationSeconds": descriptor_.campaign_seconds,
    }


def validate_bootstrap_permission(permission, *, plan) -> dict:
    """Validate the independent four-request preparation authority.

    This does not issue the observation permission or an O8 capability. Its
    only authority is the preparation Gate/Ledger claim bound to this nonce and
    this exact compiler-produced four-row plan.
    """
    if not isinstance(permission, dict) or set(permission) != {
        "kind", "project", "projectNumber", "nonce", "credentialPrincipal",
        "authorizedUserDigest", "preparationPlanDigest", "issuedAt", "expiresAt",
    } or permission.get("kind") != BOOTSTRAP_PERMISSION_KIND:
        raise ValueError("independent bootstrap permission required")
    bootstrap = plan.get("bootstrap") if isinstance(plan, dict) else None
    if (
        plan.get("project") != campaign.PROJECT
        or plan.get("nonce") != permission.get("nonce")
        or not isinstance(bootstrap, dict)
        or bootstrap.get("kind") != "auth-credential-bootstrap-v1"
        or bootstrap.get("permissionDigest") != digest(permission)
        or permission.get("project") != campaign.PROJECT
        or permission.get("projectNumber") != "592603257417"
        or permission.get("preparationPlanDigest") != gate_module.bootstrap_plan_digest(plan)
    ):
        raise ValueError("bootstrap plan binding differs")
    principal = permission.get("credentialPrincipal")
    if not isinstance(principal, dict) or set(principal) != {"clientId", "subject", "requiredScopes"}:
        raise ValueError("bootstrap principal required")
    preflight.validate_principal(principal)
    if (
        not isinstance(permission.get("authorizedUserDigest"), str)
        or len(permission["authorizedUserDigest"]) != 64
        or type(permission.get("issuedAt")) not in (int, float)
        or type(permission.get("expiresAt")) not in (int, float)
        or permission["expiresAt"] - permission["issuedAt"] < plan["wallSeconds"]
        + plan["recoverySeconds"]
        or permission["expiresAt"] < time.time()
    ):
        raise ValueError("bootstrap permission window or ADC binding differs")
    return copy.deepcopy(permission)


def bootstrap_reservation_claim(inputs, *, permission, gate_plan, gate_path):
    """Derive a separate stable-task Ledger claim for preparation."""
    validate_bootstrap_permission(permission, plan=gate_plan)
    claim = reservation_claim(inputs, gate_path=gate_path, gate_plan=gate_plan)
    claim["manifestDigest"] = digest(permission)
    return claim


def _private_string(value, maximum):
    return (
        isinstance(value, str)
        and 0 < len(value) <= maximum
        and value.isascii()
        and not any(char.isspace() or ord(char) < 33 or ord(char) == 127 for char in value)
    )


def validate_handoff(handoff, permission, plan) -> dict:
    """Validate the private handoff against the permission and the frozen plan.

    The shape is `{kind, permissionDigest, token, apiKey, signing}`. `signing` is
    either null or `{serviceAccount}` naming the oracle service account the bearer
    may sign for. A plan frozen with signing needs the declaration; a plan frozen
    without it refuses one, so the run that executes is the run that was approved.
    Nothing here reaches the wire; the tokeninfo slot verifies the bearer's
    principal, scope and lifetime before any data call.
    """
    if not isinstance(handoff, dict) or set(handoff) != HANDOFF_FIELDS or handoff["kind"] != HANDOFF_KIND:
        raise ValueError("bound credential handoff required")
    if handoff["permissionDigest"] != digest(permission):
        raise ValueError("bound credential handoff required")
    if not _private_string(handoff["token"], 8192) or not _private_string(handoff["apiKey"], 256):
        raise ValueError("bound credential handoff required")
    signing = handoff["signing"]
    if signing is not None and (
        not isinstance(signing, dict)
        or set(signing) != SIGNING_FIELDS
        or signing["serviceAccount"] != campaign.SERVICE_ACCOUNT
    ):
        raise ValueError("signing declaration must name the campaign service account")
    if bool(signing) != bool(plan.get("signing")):
        raise ValueError("signing capability differs from the frozen plan")
    return {"kind": handoff["kind"], "token": handoff["token"], "apiKey": handoff["apiKey"], "signing": signing}


# The points a run can stop at with nothing of its own left behind: before the first
# sign-up. Any later stop may have created an account and is settled by the account
# evidence, never by a no-data abort.
NO_DATA_STOP_POINTS = ("schedule-not-started", "preflight")


def stop_points() -> dict[str, tuple[str, ...]]:
    return {"noData": NO_DATA_STOP_POINTS, "uncertain": ("sign-up-unsettled",)}


def build_receipt(inputs, result, *, rows, generation, failure=None, stop_point=None):
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
        "signing": inputs["plan"]["signing"],
        "collection": result,
        "metadata": metadata,
        "routeDigest": digest(metadata),
        "generation": copy.deepcopy(generation),
        "transportDeadlineSeconds": campaign.transport_deadline_seconds(),
        "stopPoint": stop_point,
        "failure": failure,
    }


def bounded_number(value) -> bool:
    return type(value) in (int, float) and not isinstance(value, bool) and math.isfinite(value)
