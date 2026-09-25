"""File-bound O8 admission for AUTH-MFA-AGE-TOTP-01.

This module freezes the campaign's inputs, runs the shared O7 admission check set
through the campaign-generic core, derives the Ledger claim with its exclusive
configuration lock, and screens every receipt for secret-shaped material. It has no
command line; the launcher is `mfa_o8.py`.

One check here has no counterpart in the Firestore lanes: `hosting_check` asks the
shared Ledger and Gate, as they are today, whether they can host this campaign at
all, and names every structural refusal. The answer is recorded rather than worked
around, because the alternative, a lane-private ledger, would be a second authority.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
for entry in (
    ROOT / "tools/compat-broad",
    ROOT / "tools/compat-broad/production-admission",
    ROOT / "tools/compat-broad/o8-core",
    HERE,
):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

import o8_admission
import reservations
import shared_gate
from broad_contract import digest
from o8_admission import (
    ProductionWireCapability,
    execution_host,
    issued_capability,
    revoke_production_capability,
    validate_owner_identity,
)

import mfa_descriptor as campaign
import mfa_gate
from mfa_collector import assert_no_sensitive_material
from mfa_config_lock import validate_evidence
from mfa_timing import WALL_CLOCK

MAX_INPUT_BYTES = 8 * 1024 * 1024
_HEX64 = re.compile(r"^[a-f0-9]{64}$")
# Values that look like credentials wherever they appear in a receipt. Field names are
# screened by the collector's policy; this screens the values, because a secret in a
# field called `note` is still a secret.
_SECRET_SHAPES = (
    re.compile(r"^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$"),  # JWT
    re.compile(r"^ya29\.[A-Za-z0-9_.-]+$"),  # OAuth bearer
    re.compile(r"^AIza[0-9A-Za-z_-]{35}$"),  # Web API key
    re.compile(r"^1//[0-9A-Za-z_-]{20,}$"),  # refresh token
    re.compile(r"^[A-Z2-7]{16,}=*$"),  # base32 shared secret
    re.compile(r"^Aa9![A-Za-z0-9_-]{16,}$"),  # this campaign's password shape
)
LEDGER_DURATION_CAP_SECONDS = 1200


class ReceiptScreenError(ValueError):
    """A receipt carried a value shaped like a credential."""


class HostingRefused(ValueError):
    """The shared Ledger or Gate cannot host this campaign as they stand."""


def descriptor(sleeper=None):
    return campaign.descriptor(sleeper)


def descriptor_for_plan(plan, sleeper=None):
    return campaign.descriptor_for_plan(plan, sleeper)


def permission_bindings(plan, source_commit, artifact_digest, inputs, baseline=None):
    return campaign.permission_bindings(
        plan, source_commit, artifact_digest, inputs, baseline
    )


def validate_frozen_inputs(inputs, descriptor_=None) -> None:
    if descriptor_ is None:
        plan = inputs.get("plan") if isinstance(inputs, dict) else None
        descriptor_ = descriptor_for_plan(plan)
    o8_admission.validate_frozen_inputs(descriptor_, inputs)
    campaign.execution_plan(inputs["plan"])
    if inputs.get("bounds") != descriptor_.frozen_bounds:
        raise ValueError("frozen campaign bounds differ")
    permission = inputs["permission"]
    required = descriptor_.permission_bindings(
        inputs["plan"],
        inputs["sourceCommit"],
        inputs["artifactSha256"],
        inputs["sourceInputs"],
        permission.get("authConfigBaselineDigest"),
    )
    if digest({key: permission.get(key) for key in required}) != digest(required):
        raise ValueError("typed owner permission binding differs")


def abort_generation(inputs, descriptor_=None):
    return o8_admission.abort_generation(descriptor_ or descriptor(), inputs)


def validate_o7_admission(descriptor_=None, **bindings):
    inputs = bindings.get("inputs")
    if descriptor_ is None:
        plan = inputs.get("plan") if isinstance(inputs, dict) else None
        descriptor_ = descriptor_for_plan(plan)
    validate_frozen_inputs(inputs, descriptor_)
    return o8_admission.validate_o7_admission(descriptor_, **bindings)


def issue_production_capability(descriptor_=None, **bindings):
    inputs = bindings.get("inputs")
    if descriptor_ is None:
        plan = inputs.get("plan") if isinstance(inputs, dict) else None
        descriptor_ = descriptor_for_plan(plan)
    validate_frozen_inputs(inputs, descriptor_)
    return o8_admission.issue_production_capability(descriptor_, **bindings)


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


def _validate_owner_window(permission, descriptor_) -> None:
    issued, expiry = permission.get("issuedAt"), permission.get("expiresAt")
    now = time.time()
    if (
        type(issued) not in (int, float)
        or type(expiry) not in (int, float)
        or isinstance(issued, bool)
        or isinstance(expiry, bool)
        or not 0 <= now - issued <= 86400
        or not now + descriptor_.window_seconds <= expiry <= issued + 86400
    ):
        raise ValueError("owner permission expired or too short for recovery")


def validate_baseline_provenance(value) -> None:
    """The permission says where its Auth configuration baseline digest came from."""
    if (
        not isinstance(value, dict)
        or set(value) != {"method", "observedAt", "recordReference"}
        or value["method"] != "admin-v2-getConfig-readback"
        or not isinstance(value["observedAt"], str)
        or not value["observedAt"].strip()
        or not isinstance(value["recordReference"], str)
        or not value["recordReference"].strip()
    ):
        raise ValueError("Auth configuration baseline provenance required")


def _approve(
    permission, plan, source_commit, artifact_digest, inputs, descriptor_
) -> None:
    baseline = permission.get("authConfigBaselineDigest")
    if not isinstance(baseline, str) or _HEX64.fullmatch(baseline) is None:
        raise ValueError("frozen Auth configuration baseline digest required")
    required = descriptor_.permission_bindings(
        plan, source_commit, artifact_digest, inputs, baseline
    )
    if digest({key: permission.get(key) for key in required}) != digest(required):
        raise ValueError("typed owner permission binding differs")
    _validate_owner_window(permission, descriptor_)
    validate_baseline_provenance(permission.get("baselineProvenance"))
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
        or not campaign.transport.private_string(principal["clientId"], 512)
        or not campaign.transport.private_string(
            principal.get("subject", principal.get("verifiedEmail")), 512
        )
    ):
        raise ValueError("owner-frozen credential principal required")
    if (
        not isinstance(permission.get("permissionReference"), str)
        or not permission["permissionReference"].strip()
    ):
        raise ValueError("owner supplied permissionReference required")
    if permission.get("configurationChangeAcknowledged") is not True:
        raise ValueError("owner acknowledgement of the configuration change required")


def freeze_inputs(
    permission_path, plan, *, source_root, artifact_path, descriptor_=None
):
    """Freeze an independently read permission over a verified source snapshot."""
    descriptor_ = descriptor_ or descriptor()
    campaign.execution_plan(plan)
    permission = _read(permission_path)
    inputs = campaign.source_map()
    commit = subprocess.check_output(
        ["git", "-C", str(source_root), "rev-parse", "HEAD"], text=True
    ).strip()
    artifact = _artifact(artifact_path)
    _provenance(source_root, commit, inputs)
    _approve(permission, plan, commit, artifact, inputs, descriptor_)
    return o8_admission.freeze_inputs(
        descriptor_, permission, plan, source_commit=commit, artifact_sha256=artifact
    )


def require_production_timing(inputs) -> None:
    """A production launch admits only a wall-clock plan reference."""
    plan = inputs.get("plan") if isinstance(inputs, dict) else None
    if not isinstance(plan, dict) or plan.get("timingMode") != WALL_CLOCK:
        raise ValueError(
            "production launch requires a wall-clock plan reference; a rehearsal's "
            "frozen inputs cannot be launched against production"
        )


def validate_fresh_admission(ledger_root, plan, permission) -> dict:
    """Refuse a reused nonce, a respent permission, or a held Auth configuration lock.

    Read-only. The exclusive configuration lock is checked here as well as at
    reservation time so the refusal is named before any credential is read.
    """
    root = Path(ledger_root)
    state_path = root / "state.json"
    if root.is_symlink() or not state_path.is_file():
        raise ValueError("existing shared Ledger required")
    state = json.loads(state_path.read_bytes())
    nonce_digest = digest(plan["nonce"])
    permission_digest = digest(permission)
    config_lock = {
        "key": f"project/{campaign.PROJECT}/auth/config",
        "mode": "EXCLUSIVE",
    }
    for row in state.get("reservations", {}).values():
        claim = row.get("claim", {})
        if claim.get("nonceDigest") == nonce_digest:
            raise ValueError("campaign nonce already reserved")
        for lock in claim.get("locks", []):
            if plan["nonce"] in str(lock.get("key", "")):
                raise ValueError("campaign nonce already reserved")
        if row.get("state") in {"held", "closing"}:
            for lock in claim.get("locks", []):
                try:
                    conflict = reservations.conflicts(lock, config_lock)
                except (TypeError, ValueError):
                    conflict = False
                if conflict:
                    raise ValueError(
                        "Auth configuration lock is held by another active reservation"
                    )
    for entry in state.get("envelopes", {}).values():
        envelope = entry.get("envelope", entry)
        if envelope.get("permissionDigest") == permission_digest:
            raise ValueError("owner permission already spent")
    return {
        "ledgerRoot": str(root.resolve(strict=False)),
        "nonceDigest": nonce_digest,
        "permissionDigest": permission_digest,
    }


GATE_JOB = mfa_gate.JOB


def gate_plan_for(inputs, permission, descriptor_=None) -> dict:
    """This campaign projected onto the shared Gate schema through the lane facade.

    Every request the walk sends is a frozen slot with run-time placeholders; the
    accounts and the configuration lock are named as `projects/<project>/auth/...`
    resources beside the two cleanup routes the base Gate requires. Whether the
    shared modules accept the projection is `hosting_check`'s answer, not this one's.
    """
    descriptor_ = descriptor_ or descriptor()
    campaign.execution_plan(inputs["plan"])
    expiry = permission.get("expiresAt")
    if type(expiry) not in (int, float) or isinstance(expiry, bool):
        raise ValueError("permission expiry required for management dispatch")
    selector = inputs["plan"].get("selector", {}).get("name")
    selected_wall_seconds = (
        inputs["plan"]["selector"]["maxWallSeconds"]
        if selector is not None
        else descriptor_.campaign_seconds
    )
    plan = mfa_gate.gate_plan(
        inputs["plan"]["nonce"],
        wall_seconds=selected_wall_seconds,
        recovery_seconds=descriptor_.recovery_seconds,
        cost_microusd=campaign.ledger_budget()["costMicrousd"],
        selector=selector,
    )
    plan["permissionExpiresAt"] = expiry
    return plan


def reservation_claim(inputs, *, gate_path, gate_plan, descriptor_=None):
    """The shared Ledger claim: nonce, exclusive configuration lock, budget, duration."""
    descriptor_ = descriptor_ or descriptor()
    plan = inputs["plan"]
    if (
        digest(gate_plan.get("nonce")) != digest(plan["nonce"])
        or gate_plan.get("campaignId") != descriptor_.campaign_id
    ):
        raise ValueError("Gate plan belongs to another campaign or nonce")
    selector = plan.get("selector")
    duration_seconds = (
        selector["maxWallSeconds"] if selector is not None else descriptor_.campaign_seconds
    )
    return {
        "campaignId": descriptor_.campaign_id,
        "manifestDigest": inputs["planDigest"],
        "nonceDigest": digest(plan["nonce"]),
        "gatePath": str(Path(gate_path).resolve()),
        "gatePlanDigest": digest(gate_plan),
        "gateJob": GATE_JOB,
        "locks": descriptor_.lock_scopes(plan),
        "budget": campaign.ledger_budget(),
        "durationSeconds": duration_seconds,
    }


def hosting_check(claim, gate_plan) -> list[dict]:
    """Every structural reason the shared Ledger and Gate refuse this campaign today.

    Each entry is produced by exercising the shared module, not by restating it: the
    claim goes through the Ledger's own claim validator and its resource scope
    derivation, and the Gate plan through the Gate's own `create` in a temporary
    directory that is removed again. An empty list means the shared modules accept
    the campaign's shapes.
    """
    refusals = []
    try:
        reservations._claim(claim)
    except (ValueError, TypeError) as error:
        refusals.append(
            {
                "refusal": "ledger-claim-refused",
                "module": "tools/compat-broad/production-admission/reservations.py",
                "detail": str(error),
                "value": {
                    "durationSeconds": claim.get("durationSeconds"),
                    "cap": LEDGER_DURATION_CAP_SECONDS,
                },
            }
        )
    if gate_plan["wallSeconds"] > shared_gate.WALL_CAP_SECONDS:
        refusals.append(
            {
                "refusal": "gate-wall-cap",
                "module": "tools/compat-broad/shared_gate.py",
                "detail": "campaign wall exceeds WALL_CAP_SECONDS",
                "value": {
                    "wallSeconds": gate_plan["wallSeconds"],
                    "cap": shared_gate.WALL_CAP_SECONDS,
                },
            }
        )
    else:
        with tempfile.TemporaryDirectory() as scratch:
            try:
                mfa_gate.create(Path(scratch) / "gate", copy.deepcopy(gate_plan))
            except (ValueError, TypeError, KeyError) as error:
                refusals.append(
                    {
                        "refusal": "gate-plan-refused",
                        "module": "tools/compat-broad/shared_gate.py",
                        "detail": f"{type(error).__name__}: {error}",
                        "value": {"job": GATE_JOB},
                    }
                )
    resources = (
        [name for job in gate_plan["jobs"].values() for name in job["resources"]]
        + list(gate_plan.get("accountResources", []))
        + [gate_plan.get("configResource")]
    )
    refused = []
    selected = gate_plan.get("selector") is not None
    for name in resources:
        try:
            if selected:
                reservations._resource_scope(name)
            else:
                reservations._firestore_resource_scope(name)
        except (ValueError, TypeError):
            refused.append(name)
    if refused:
        refusals.append(
            {
                "refusal": "ledger-resource-refused",
                "module": "tools/compat-broad/production-admission/reservations.py",
                "detail": (
                    "the selected Auth account resources are supported by the shared "
                    "resource scope, but the project Auth configuration resource still "
                    "has no canonical scope; the full campaign retains its historical "
                    "Firestore-only refusal"
                ),
                "value": {"refusedResources": len(refused), "sample": refused[:3]},
            }
        )
    return refusals


def require_hosted(claim, gate_plan) -> None:
    refusals = hosting_check(claim, gate_plan)
    if refusals:
        raise HostingRefused(
            "shared Ledger/Gate cannot host this campaign: "
            + ", ".join(item["refusal"] for item in refusals)
        )


# --- receipts -----------------------------------------------------------------------
def _walk_values(value, path=""):
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _walk_values(item, f"{path}.{key}" if path else str(key))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _walk_values(item, f"{path}[{index}]")
    else:
        yield path, value


def screen_receipt(receipt) -> None:
    """Refuse a receipt carrying a credential-shaped value or a sensitive field name."""
    assert_no_sensitive_material(receipt, "receipt")
    for path, value in _walk_values(receipt):
        if isinstance(value, str) and any(
            shape.fullmatch(value) for shape in _SECRET_SHAPES
        ):
            raise ReceiptScreenError(
                f"receipt value at {path} is shaped like a credential"
            )


# Where a run can stop, and whether the stop can have changed anything.
NO_DATA_STOP_POINTS = (
    "schedule-not-started",
    "preflight-tokeninfo",
    "preflight-key-project",
    "preflight-config-readback",
)
CONFIG_CHANGED_STOP_POINTS = (
    "config-apply",
    "acquisition",
    "cases",
    "cleanup",
    "restore",
    "resume-prior-state",
    "recover-unsettled",
)


def stop_points() -> dict:
    return {
        "noData": NO_DATA_STOP_POINTS,
        "configOrAccounts": CONFIG_CHANGED_STOP_POINTS,
    }


def classify_stop(receipt) -> dict:
    """The terminal disposition a stopped run is entitled to.

    A stop before the configuration change and before any signup is retirable as
    no-data. Any later stop has changed the project configuration or created an
    account, and is retirable only when the receipt proves the restore verified and
    every owned account absent; otherwise it stays with the owner.
    """
    if not isinstance(receipt, dict):
        raise ValueError("bounded receipt required")  # noqa: TRY004 -- refusal class
    stop = receipt.get("stopPoint")
    configuration = receipt.get("configuration") or {}
    cleanup = receipt.get("cleanup") or {}
    resumed = bool(receipt.get("resumeCount") or receipt.get("abandonCount"))
    if stop in NO_DATA_STOP_POINTS and not resumed:
        if configuration.get("changeAttempted") or cleanup.get("ownedAccounts"):
            return {
                "stopPoint": stop,
                "disposition": "owner-escalation",
                "retirableAsNoData": False,
                "reason": "the journal does not prove that nothing was changed",
            }
        return {
            "stopPoint": stop,
            "disposition": "aborted-no-data",
            "retirableAsNoData": True,
            "reason": "no configuration change and no signup was dispatched",
        }
    if (
        stop not in CONFIG_CHANGED_STOP_POINTS
        and stop not in NO_DATA_STOP_POINTS
        and stop is not None
    ):
        raise ValueError("unknown MFA stop point")
    baseline = configuration.get("frozenBaselineDigest")
    restored = (
        isinstance(baseline, str)
        and validate_evidence(configuration, frozen_baseline_digest=baseline)
        and (
            configuration.get("changeAttempted") is True
            or configuration.get("restoreStatus") == "not-attempted"
        )
    )
    # The walk's ledger and the Gate's must agree: the Gate's finish is the proof
    # that every account it journaled as created was read back absent.
    evidence = receipt.get("accountEvidence") or {}
    gate_agrees = receipt.get("gateComplete") is True or (
        # A run that created nothing has nothing for the Gate to finish; its
        # journal must then show no creation and no signup left unsettled.
        evidence.get("createdAccounts") == 0
        and evidence.get("unsettledSignups") == 0
        and cleanup.get("ownedAccounts") == 0
    )
    absent = (
        cleanup.get("complete") is True
        and not receipt.get("untrackedIntents")
        and gate_agrees
    )
    if restored and absent:
        return {
            "stopPoint": stop,
            "disposition": "abandoned-cleanup-complete",
            "retirableAsNoData": False,
            "reason": "configuration restored and every owned account proven absent",
        }
    return {
        "stopPoint": stop,
        "disposition": "owner-escalation",
        "retirableAsNoData": False,
        "reason": (
            "a signup without an address was sent and never answered; the owner "
            "must find and delete the account"
            if receipt.get("untrackedIntents")
            else "configuration restore or account absence is unproven"
        ),
    }


def build_receipt(
    inputs,
    *,
    walk_state,
    rows,
    configuration,
    credential,
    cleanup,
    generation,
    execution_kind,
    timing_mode,
    stop_point=None,
    failure=None,
    resumable=False,
):
    """The campaign receipt. Screened before it is returned."""
    steps = walk_state["steps"] if walk_state else []
    receipt = {
        "kind": campaign.RECEIPT_KIND,
        "campaignId": campaign.CAMPAIGN,
        "inputsDigest": inputs["inputsDigest"],
        "permissionDigest": inputs["permissionDigest"],
        "campaignPlanDigest": inputs["planDigest"],
        "rows": copy.deepcopy(rows),
        "collection": None
        if walk_state is None
        else {
            "requests": walk_state["requests"],
            "maxRequests": walk_state["maxRequests"],
            "aborted": walk_state["aborted"],
            "abortReason": walk_state["abortReason"],
            "done": sum(step["status"] == "done" for step in steps),
            "skipped": sum(step["status"] == "skipped" for step in steps),
            "pending": sum(step["status"] == "pending" for step in steps),
        },
        "configuration": copy.deepcopy(configuration),
        "principalAttestation": copy.deepcopy(credential),
        "cleanup": copy.deepcopy(cleanup),
        "generation": copy.deepcopy(generation),
        "executionKind": execution_kind,
        "productionExecuted": execution_kind == "fixed-production-wire",
        "timingMode": timing_mode,
        "stopPoint": stop_point,
        "failure": failure,
        "resumable": resumable,
    }
    screen_receipt(receipt)
    return receipt


__all__ = [
    "CONFIG_CHANGED_STOP_POINTS",
    "GATE_JOB",
    "NO_DATA_STOP_POINTS",
    "HostingRefused",
    "ProductionWireCapability",
    "ReceiptScreenError",
    "abort_generation",
    "build_receipt",
    "classify_stop",
    "descriptor",
    "execution_host",
    "freeze_inputs",
    "gate_plan_for",
    "hosting_check",
    "issue_production_capability",
    "issued_capability",
    "permission_bindings",
    "require_hosted",
    "require_production_timing",
    "reservation_claim",
    "revoke_production_capability",
    "screen_receipt",
    "stop_points",
    "validate_fresh_admission",
    "validate_frozen_inputs",
    "validate_o7_admission",
]
