"""Campaign descriptor for AUTH-MFA-AGE-TOTP-01 under the shared O8 admission core.

This module declares, in one hard-coded place, every binding the shared core checks
for the MFA age-causality campaign: the schema kinds, the window, the source map, the
plan reference, the budget with its management and configuration slots, the Ledger
lock scopes including the exclusive lock on the project's Auth configuration, the
walk and comparator the campaign runs, the cost model, the abort closure, and the
integrity binding of the production transport.

It authorizes nothing. Two things are specific to this campaign and are enforced
here rather than described: production time is wall-clock time, so the descriptor
refuses to bind a simulated sleeper to production; and the project configuration is
changed inside the envelope, so the permission must carry the frozen baseline digest
the restore is verified against.
"""

from __future__ import annotations

import copy
import functools
import hashlib
import json
import math
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
for entry in (ROOT / "tools/compat-broad", ROOT / "tools/compat-broad/o8-core", HERE):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

import mfa_gate
import mfa_production_transport as transport
from broad_contract import digest
from mfa_cases import (
    CAMPAIGN_ID,
    critical_path_seconds,
    observation_cases,
    owned_accounts,
)
from mfa_comparator import compare
from mfa_config_lock import CONFIG_PATH, UPDATE_MASK, campaign_patch
from mfa_manifest import (
    LIMITS,
    PROJECT,
    PROVISIONING_SECONDS,
    SELECTED_REQUEST_CONTINGENCY,
    compile_campaign,
    validate_campaign,
)
from mfa_provenance import BOUND_PATHS
from mfa_timing import VIRTUAL_CLOCK, WALL_CLOCK, require_wall_clock, timing_mode
from o8_admission import authorize_transport
from o8_campaign import CAMPAIGN_APPROVAL_FIELDS, CampaignDescriptor

CAMPAIGN = CAMPAIGN_ID
PROJECT_NUMBER = "592603257417"
_NONCE = re.compile(r"^[0-9a-f]{32}$")
FROZEN_INPUTS_KIND = "mfa-frozen-inputs-v1"
PERMISSION_KIND = "mfa-owner-execution-permission-v1"
APPROVAL_KIND = "mfa-o8-approval-v1"
MANIFEST_KIND = "mfa-o8-manifest-v1"
RECEIPT_KIND = "mfa-acquisition-receipt-v1"
PRINCIPAL_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
# The versioned shadow record this campaign's production run is compared against. The
# historical `o2-mfa-local-shadow.json` stays as it is; this one binds the modules at
# the commit its own receipt names.
SHADOW_RECORD = "spec/compatibility/broad-runs/auth-totp-enroll-local-shadow-v2.json"
LANE_DIRECTORY = "tools/compat-broad/auth-totp-enroll"
COLLECTOR_ENTRY = f"{LANE_DIRECTORY}/mfa_walk.py"
COMPARATOR_ENTRY = f"{LANE_DIRECTORY}/mfa_comparator.py"
WORKER_ENTRY = f"{LANE_DIRECTORY}/mfa_production_transport.py"
SHARED_SOURCES = (
    "tools/compat-broad/broad_contract.py",
    "tools/compat-broad/batch_adapter.py",
    "tools/compat-broad/batch_wire.py",
    "tools/compat-broad/batch_contract.py",
    "tools/compat-broad/shared_gate.py",
    "tools/compat-broad/production-admission/reservations.py",
    "tools/compat-broad/o8-core/o8_admission.py",
    "tools/compat-broad/o8-core/o8_campaign.py",
    "tools/compat-broad/fs-write-txn/credential_prep.py",
    "tools/compat-inventory/pyproject.toml",
    "tools/compat-inventory/uv.lock",
)
ABORT_CLOSURE_SOURCES = (
    "tools/compat-broad/shared_gate.py",
    "tools/compat-broad/production-admission/reservations.py",
    "tools/compat-broad/o8-core/o8_admission.py",
    f"{LANE_DIRECTORY}/mfa_admission.py",
    f"{LANE_DIRECTORY}/mfa_descriptor.py",
)

# --- management and configuration slots ------------------------------------------
# What the run sends before its first data request and after its last, on top of the
# thirty-three cases. Every one is charged against `maxRequests`; nothing here is a
# separate allowance. The slot lists are the Gate facade's, so the budget and the
# frozen plan cannot disagree.
MANAGEMENT_PREFLIGHT = mfa_gate.MANAGEMENT_OBSERVATION_IDS[:2]
CONFIG_APPLY = mfa_gate.MANAGEMENT_OBSERVATION_IDS[2:]
CONFIG_RESTORE = mfa_gate.MANAGEMENT_RECOVERY_IDS
# How many times a paused run may be resumed under its reservation.
RESUME_ALLOWANCE = SELECTED_REQUEST_CONTINGENCY["resumeTokeninfoRequests"]
# Each owned account is deleted, then proven absent by UID and, where it has one, by
# address; the anonymous account has no address.
RECOVERY_REQUESTS_PER_ACCOUNT = 4
# The service may lag its configuration readback; the earlier production recorder for
# the same change waited this long before the first request that needed it.
CONFIG_ENFORCEMENT_LAG_SECONDS = 30
# The nonce only shapes addresses, never the request count, so any nonce sizes the
# frozen plan.
_SIZING_NONCE = "0" * 32


def shadow_record() -> dict:
    """The published versioned shadow this campaign's production run is compared to."""
    path = ROOT / SHADOW_RECORD
    if path.is_symlink() or not path.is_file():
        raise ValueError("published versioned local shadow record required")
    value = json.loads(path.read_bytes())
    worktree = value.get("worktree") if isinstance(value, dict) else None
    if (
        not isinstance(worktree, dict)
        or value.get("campaignId") != CAMPAIGN
        or value.get("side") != "local"
        or value.get("productionExecuted") is not False
        or not isinstance(worktree.get("commit"), str)
        or len(worktree["commit"]) != 40
        or worktree.get("clean") is not True
        or not validate_campaign(value.get("campaign"))
    ):
        raise ValueError("published versioned local shadow record required")
    return value


ARTIFACT_PROFILE_BASIS = {
    "kind": "mfa-artifact-profile-v1",
    "registry": "none",
    "derivedFrom": "the published versioned local shadow record's worktree.commit",
    "establishes": (
        "which commit the comparison reference was recorded at, and that the retained "
        "bytes hash to the digest the approval binds"
    ),
    "doesNotEstablish": (
        "that the build was reviewed; no profile registry entry exists for this lane "
        "and O7 must accept the profile explicitly"
    ),
    "ownerAcceptanceRequired": True,
}


def artifact_profile() -> str:
    return "auth-totp-enroll-" + shadow_record()["worktree"]["commit"][:9]


def artifact_profile_basis() -> dict:
    record = shadow_record()
    return {
        **copy.deepcopy(ARTIFACT_PROFILE_BASIS),
        "profile": artifact_profile(),
        "sourceCommit": record["worktree"]["commit"],
        "shadowProvenanceDigest": record["provenance"]["digest"],
    }


# --- budget -------------------------------------------------------------------------
def campaign_seconds() -> int:
    return int(LIMITS["maxWallSeconds"])


def recovery_seconds() -> int:
    return int(LIMITS["recoveryReserveSeconds"])


def management_requests() -> int:
    """Preflight, configuration change and restore: the Gate's closed slots."""
    return len(mfa_gate.MANAGEMENT_OBSERVATION_IDS) + len(
        mfa_gate.MANAGEMENT_RECOVERY_IDS
    )


def data_requests() -> int:
    """The observation slots of the frozen Gate plan."""
    return len(mfa_gate.observation_operations(_SIZING_NONCE))


def recovery_requests() -> int:
    return len(mfa_gate.recovery_operations(_SIZING_NONCE))


def request_budget() -> dict:
    """The 400-request bound, re-derived slot by slot so the headroom is visible."""
    data = data_requests()
    management = management_requests()
    recovery = recovery_requests()
    total = int(LIMITS["maxRequests"])
    if data + management + recovery > total:
        raise ValueError("re-derived request budget exceeds the frozen bound")
    if recovery > RECOVERY_REQUESTS_PER_ACCOUNT * len(owned_accounts()):
        raise ValueError("recovery slots exceed the per-account allowance")
    return {
        "maxRequests": total,
        "dataRequests": data,
        "managementRequests": management,
        "recoveryRequests": recovery,
        "headroom": total - data - management - recovery,
        "managementSlots": {
            "preflight": list(MANAGEMENT_PREFLIGHT),
            "configurationApply": list(CONFIG_APPLY),
            "configurationRestore": list(CONFIG_RESTORE),
            "resumeAllowance": RESUME_ALLOWANCE,
        },
    }


def wall_budget(
    *,
    max_wall_seconds: int | None = None,
    critical_path: int | None = None,
    recovery_reserve: int | None = None,
) -> dict:
    """The wall split: provisioning, the concurrent aging critical path, recovery."""
    critical = critical_path_seconds() if critical_path is None else critical_path
    total = campaign_seconds() if max_wall_seconds is None else max_wall_seconds
    recovery = recovery_seconds() if recovery_reserve is None else recovery_reserve
    used = PROVISIONING_SECONDS + CONFIG_ENFORCEMENT_LAG_SECONDS + critical + recovery
    if used > total:
        raise ValueError("wall budget does not hold the critical path and recovery")
    return {
        "maxWallSeconds": total,
        "provisioningSeconds": PROVISIONING_SECONDS,
        "configurationEnforcementLagSeconds": CONFIG_ENFORCEMENT_LAG_SECONDS,
        "criticalPathSeconds": critical,
        "recoveryReserveSeconds": recovery,
        "slackSeconds": total - used,
        "timingMode": WALL_CLOCK,
    }


def cost_model() -> dict:
    """Planning ceilings from the frozen manifest limits, never a quoted tariff.

    Nothing in the campaign is metered per message: TOTP verification sends nothing
    and the test phone number delivers no SMS. The configuration change has no tariff
    but is charged as management slots, so it appears in the accounting rather than
    outside it.
    """
    estimated = math.ceil(LIMITS["estimatedCostUsd"] * 1_000_000)
    ceiling = math.ceil(LIMITS["hardCostCeilingUsd"] * 1_000_000)
    management = management_requests()
    return {
        "campaignId": CAMPAIGN,
        "estimatedCostMicrousd": estimated,
        "hardCeilingMicrousd": ceiling,
        "managementRequestCostMicrousd": 1,
        "managementRequests": management,
        "configurationChangeMicrousd": len(CONFIG_APPLY) + len(CONFIG_RESTORE),
        "totalCostMicrousd": estimated + management,
        "basis": (
            "manifest planning estimate plus one micro-USD per management slot; the "
            "configuration change is inside the management slots"
        ),
    }


def ledger_budget() -> dict:
    """The four Ledger dimensions. Recovery and management are inside every one."""
    return {
        "requests": int(LIMITS["maxRequests"]),
        "accounts": int(LIMITS["maxOwnedAccounts"]),
        "resources": int(LIMITS["maxOwnedAccounts"]),
        "costMicrousd": cost_model()["totalCostMicrousd"],
    }


def budget() -> dict:
    return {
        **request_budget(),
        **wall_budget(),
        "maxOwnedAccounts": int(LIMITS["maxOwnedAccounts"]),
        "maxConcurrency": 1,
        "estimatedCostUsd": LIMITS["estimatedCostUsd"],
        "hardCostCeilingUsd": LIMITS["hardCostCeilingUsd"],
    }


def configuration_change() -> dict:
    """What the campaign writes to the project configuration, declared for review."""
    return {
        "path": CONFIG_PATH,
        "updateMask": UPDATE_MASK,
        "applied": campaign_patch(),
        "preValueSaved": "private run directory only; receipt carries digest and redacted reference",
        "restoreProof": "readback plus whole-configuration digest equality with the frozen baseline",
        "restoreOnEveryStopPath": True,
        "lock": {"key": f"project/{PROJECT}/auth/config", "mode": "EXCLUSIVE"},
    }


def frozen_bounds(
    *,
    case_count: int | None = None,
    account_count: int | None = None,
    limits: dict | None = None,
) -> dict:
    wall = wall_budget(
        max_wall_seconds=None if limits is None else limits["maxWallSeconds"],
        critical_path=None if limits is None else limits["criticalPathSeconds"],
        recovery_reserve=(None if limits is None else limits["recoveryReserveSeconds"]),
    )
    return {
        **request_budget(),
        **wall,
        "caseCount": (len(observation_cases()) if case_count is None else case_count),
        "ownedAccounts": (
            len(owned_accounts()) if account_count is None else account_count
        ),
        "concurrency": 1,
        "configurationChange": configuration_change(),
    }


# --- plan ---------------------------------------------------------------------------
def plan_compiler(
    nonce: str, *, timing: str = WALL_CLOCK, selector: str | None = None
) -> dict:
    """The plan as the admission sees it: a reference to the frozen manifest.

    Every field is derived from the nonce by the reviewed manifest compiler, so the
    reference names exactly one manifest and an executor can rebuild it. The timing
    mode is part of the reference so a rehearsal's frozen inputs can never be read as
    a production plan.
    """
    if not isinstance(nonce, str) or _NONCE.fullmatch(nonce) is None:
        raise ValueError("fresh 128-bit lowercase hexadecimal nonce required")
    if timing not in (WALL_CLOCK, VIRTUAL_CLOCK):
        raise ValueError("declared timing mode required")
    manifest = compile_campaign(nonce, selector=selector)
    reference = {
        "schema": "mfa-plan-reference-v1",
        "campaignId": manifest["campaignId"],
        "project": manifest["project"],
        "nonce": nonce,
        "manifestDigest": digest(manifest),
        "ownerNamespace": manifest["owner"]["namespace"],
        "nonceDigest": manifest["owner"]["nonceDigest"],
        "caseCount": manifest["caseCount"],
        "ownedAccounts": len(manifest["owner"]["accounts"]),
        "limits": copy.deepcopy(manifest["limits"]),
        "agingSchedule": manifest["agingSchedule"]["mode"],
        "timingMode": timing,
    }
    if selector is not None:
        reference["selector"] = copy.deepcopy(manifest["selector"])
        reference["selectedCaseCount"] = len(manifest["selector"]["caseIds"])
        reference["selectedAccountCount"] = len(manifest["selector"]["accountRoles"])
        reference["caseCount"] = reference["selectedCaseCount"]
        reference["ownedAccounts"] = reference["selectedAccountCount"]
    return reference


def execution_plan(reference: dict) -> dict:
    """Recompile the manifest a frozen reference names, and refuse any other bytes."""
    nonce = reference.get("nonce") if isinstance(reference, dict) else None
    if not isinstance(nonce, str) or _NONCE.fullmatch(nonce) is None:
        raise ValueError("frozen MFA plan reference required")
    timing = reference.get("timingMode")
    if timing not in (WALL_CLOCK, VIRTUAL_CLOCK):
        raise ValueError("frozen MFA plan reference differs")
    selector = (
        reference.get("selector", {}).get("name") if "selector" in reference else None
    )
    canonical = plan_compiler(nonce, timing=timing, selector=selector)
    if digest(reference) != digest(canonical):
        raise ValueError("frozen MFA plan reference differs")
    manifest = compile_campaign(nonce, selector=selector)
    if digest(manifest) != reference["manifestDigest"] or not validate_campaign(
        manifest
    ):
        raise ValueError("frozen MFA plan reference differs")
    return manifest


def lock_scopes(plan: dict) -> list[dict]:
    """The owned account namespace, the exclusive configuration lock, and the read scope.

    The configuration lock is EXCLUSIVE because the campaign writes the project's
    multi-factor configuration: no other campaign, read or write, may hold the Auth
    configuration while this one has changed it and not yet restored it.
    """
    nonce = plan["nonce"]
    scope = f"project/{PROJECT}"
    selector = plan.get("selector")
    account_key = (
        f"{scope}/auth/accounts/o2-mfa-pending-age-300-{nonce}"
        if isinstance(selector, dict) and selector.get("name") == "pending-age-300-v1"
        else f"{scope}/auth/accounts/o2/{CAMPAIGN}/{nonce}/*"
    )
    return [
        {"key": account_key, "mode": "WRITE"},
        {"key": f"{scope}/auth/config", "mode": "EXCLUSIVE"},
        {"key": f"{scope}/identity", "mode": "READ"},
    ]


def lane_sources() -> tuple[str, ...]:
    directory = ROOT / LANE_DIRECTORY
    return tuple(sorted(f"{LANE_DIRECTORY}/{p.name}" for p in directory.glob("*.py")))


def source_map() -> dict[str, str]:
    """Digest every source this campaign binds: the whole lane plus the closure."""
    values = {}
    for name in (*lane_sources(), *SHARED_SOURCES):
        path = ROOT / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("frozen campaign source missing")
        values[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    if any(name not in values for name in BOUND_PATHS):
        raise ValueError("frozen source map omits a provenance-bound path")
    return values


# --- callables ----------------------------------------------------------------------
def collector(session, plan, output, *, sleeper, resume=False, stop_requested=None):
    """The reviewed walk, driven by whoever holds the session and the sleeper."""
    from mfa_walk import Walk

    return Walk(
        plan=plan,
        session=session,
        sleeper=sleeper,
        directory=output,
        resume=resume,
        stop_requested=stop_requested,
    )


def comparator(production_record, shadow=None, root=None, *, runtime_anchor=None):
    """Compare a production record with the published versioned shadow.

    The comparator establishes agreement under the lane's projection, never a
    compatibility claim; that remains an owner decision on the evidence.
    """
    published = shadow_record() if shadow is None else shadow
    result = compare(
        published,
        production_record,
        root,
        runtime_anchor=runtime_anchor,
    )
    return {
        "campaignId": CAMPAIGN,
        "comparison": result,
        "shadowRecordDigest": digest(published),
        "formalCompatibilityClaim": False,
    }


def transport_bound(value, *, binding, binding_digest, capability=None):
    """Adapt one bound wire call to the production transport.

    The binding is the transport source itself, re-checked here as well as at
    issuance, so a capability issued against other bytes cannot reach the wire.
    """
    if capability is None:
        raise ValueError("active O7 production capability required")
    transport.validate_call(value)
    authorize_transport(capability, binding=binding, binding_digest=binding_digest)
    verify_worker_binding(binding, binding_digest, None)
    return transport.send(value)


def verify_worker_binding(binding, binding_digest, frozen) -> None:
    """The reviewed transport bytes, stated three independent ways."""
    if not isinstance(binding, bytes) or not binding:
        raise ValueError("reviewed transport source required")
    observed = hashlib.sha256(binding).hexdigest()
    _source, pinned = transport.transport_source()
    if observed != binding_digest or observed != pinned:
        raise ValueError("transport source digest differs from the reviewed transport")
    if frozen is not None and frozen.get(WORKER_ENTRY) != observed:
        raise ValueError("transport source digest differs from the frozen inputs")


def worker_binding() -> tuple[bytes, str]:
    return transport.transport_source()


def retained_artifact_validator(artifact_path, manifest_path, profile):
    if profile != artifact_profile():
        raise ValueError("retained artifact profile differs")
    values = {}
    for key, path in (
        ("artifactSha256", artifact_path),
        ("retainedManifestSha256", manifest_path),
    ):
        path = Path(path)
        if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
            raise ValueError("retained regular artifact required")
        values[key] = hashlib.sha256(path.read_bytes()).hexdigest()
    return values


def forbidden_transports():
    """Objects an injected rehearsal transport must not be able to reach."""
    return (
        transport,
        transport.send,
        transport.batch_adapter.wire,
        transport.credential_prep._private_request,
        transport_bound,
    )


def permission_bindings(
    plan,
    source_commit,
    artifact_digest,
    inputs,
    baseline=None,
    *,
    window=None,
    timing=WALL_CLOCK,
):
    """Required non-authorizing fields for an independently supplied permission.

    `window` is the descriptor's own (campaign, recovery) seconds; the production
    descriptor binds the manifest's, a rehearsal descriptor binds its short one.
    """
    selector = plan.get("selector")
    if selector is None:
        selector_name = None
    elif isinstance(selector, dict):
        selector_name = selector.get("name")
    else:
        raise ValueError("fixed production project and timing mode required")
    canonical = plan_compiler(plan["nonce"], timing=timing, selector=selector_name)
    if digest(plan) != digest(canonical):
        raise ValueError("frozen MFA plan reference differs")
    manifest = execution_plan(plan)
    account_roles = (
        manifest["selector"]["accountRoles"]
        if "selector" in manifest
        else [account["role"] for account in manifest["owner"]["accounts"]]
    )
    plan_seconds = manifest["limits"]["maxWallSeconds"]
    plan_recovery = manifest["limits"]["recoveryReserveSeconds"]
    seconds, recovery = window if window is not None else (plan_seconds, plan_recovery)
    seconds = min(seconds, plan_seconds)
    recovery = min(recovery, plan_recovery)
    required = {
        "kind": PERMISSION_KIND,
        "campaignId": CAMPAIGN,
        "project": PROJECT,
        "projectNumber": PROJECT_NUMBER,
        "quotaProject": PROJECT,
        "nonce": plan["nonce"],
        "planDigest": digest(plan),
        "manifestDigest": plan["manifestDigest"],
        "sourceCommit": source_commit,
        "sourceInputs": inputs,
        "collectorSourceDigest": digest(inputs),
        "artifactSha256": artifact_digest,
        "collectorSha256": inputs[COLLECTOR_ENTRY],
        "comparatorSha256": inputs[COMPARATOR_ENTRY],
        "workerSha256": inputs[WORKER_ENTRY],
        "budget": budget(),
        "ledgerBudget": ledger_budget(),
        "ownedNamespace": plan["ownerNamespace"],
        "ownedAccounts": plan["ownedAccounts"],
        "wallSeconds": seconds,
        "campaignSeconds": seconds,
        "recoverySeconds": recovery,
        "criticalPathSeconds": critical_path_seconds(),
        "perRequestTimeoutSeconds": transport.REQUEST_SECONDS,
        "concurrency": 1,
        "timingMode": timing,
        "selector": selector_name,
        "caseCount": plan["caseCount"],
        "ownedAccountRoles": list(account_roles),
        "configurationChange": configuration_change(),
        "costModel": cost_model(),
        "artifactProfileBasis": artifact_profile_basis(),
        "credentialPrincipalContract": {
            "alternatives": [
                ["clientId", "subject", "requiredScopes"],
                ["clientId", "verifiedEmail", "requiredScopes"],
            ],
            "requiredScopes": [PRINCIPAL_SCOPE],
            "requiredRole": "roles/firebaseauth.admin",
            "handoff": ["bearer token", "Web API key"],
            "identitySource": "owner-frozen permission; never inferred from tokeninfo",
        },
        "managementContract": {
            "version": "mfa-preflight-v1",
            "preflight": list(MANAGEMENT_PREFLIGHT),
            "configurationApply": list(CONFIG_APPLY),
            "configurationRestore": list(CONFIG_RESTORE),
            "resumeAllowance": RESUME_ALLOWANCE,
            "baselineRefusal": (
                "the run refuses to start when the Auth configuration readback digest "
                "differs from authConfigBaselineDigest"
            ),
        },
    }
    if baseline is not None:
        required["authConfigBaselineDigest"] = baseline
    return required


def _descriptor(
    sleeper, *, seconds: int, recovery: int, bounds: dict, timing: str
) -> CampaignDescriptor:
    return CampaignDescriptor(
        campaign_id=CAMPAIGN,
        frozen_inputs_kind=FROZEN_INPUTS_KIND,
        permission_kind=PERMISSION_KIND,
        approval_kind=APPROVAL_KIND,
        manifest_kind=MANIFEST_KIND,
        approval_fields=CAMPAIGN_APPROVAL_FIELDS,
        artifact_profile=artifact_profile(),
        campaign_seconds=seconds,
        recovery_seconds=recovery,
        source_map=source_map,
        abort_closure_sources=ABORT_CLOSURE_SOURCES,
        required_source_entries=(COLLECTOR_ENTRY, COMPARATOR_ENTRY, WORKER_ENTRY),
        frozen_bounds=bounds,
        budget=budget(),
        plan_compiler=functools.partial(plan_compiler, timing=timing),
        lock_scopes=lock_scopes,
        collector=collector,
        comparator=comparator,
        cost_model=cost_model,
        permission_bindings=functools.partial(
            permission_bindings, window=(seconds, recovery), timing=timing
        ),
        transport_bound=transport_bound,
        binding_verifier=verify_worker_binding,
        retained_artifact_validator=retained_artifact_validator,
        forbidden_transports=forbidden_transports,
    )


def descriptor(sleeper=None) -> CampaignDescriptor:
    """The production descriptor. Refuses any sleeper that is not wall-clock time."""
    from mfa_timing import WallClockSleeper

    require_wall_clock(WallClockSleeper() if sleeper is None else sleeper)
    return _descriptor(
        sleeper,
        seconds=campaign_seconds(),
        recovery=recovery_seconds(),
        bounds=frozen_bounds(),
        timing=WALL_CLOCK,
    )


def descriptor_for_plan(plan: dict, sleeper=None) -> CampaignDescriptor:
    """Build the production descriptor for one canonical frozen plan reference."""
    from mfa_timing import WallClockSleeper

    manifest = execution_plan(plan)
    if plan["timingMode"] != WALL_CLOCK:
        raise ValueError("wall-clock plan reference required")
    active_sleeper = WallClockSleeper() if sleeper is None else sleeper
    require_wall_clock(active_sleeper)
    bounds = frozen_bounds(
        case_count=plan["caseCount"],
        account_count=plan["ownedAccounts"],
        limits=manifest["limits"],
    )
    return _descriptor(
        active_sleeper,
        seconds=manifest["limits"]["maxWallSeconds"],
        recovery=manifest["limits"]["recoveryReserveSeconds"],
        bounds=bounds,
        timing=WALL_CLOCK,
    )


def rehearsal_descriptor(
    sleeper, *, seconds: int = 1200, recovery: int = 300
) -> CampaignDescriptor:
    """A descriptor for an injected-transport rehearsal under a virtual clock.

    It carries the same campaign identity and bindings, so the admission checks run
    unchanged, but its bounds say `virtual-clock` and its window is the shared
    Gate's 1200 s cap, which is what lets the Gate side of a rehearsal be proven. It is the
    only way a simulated sleeper enters a descriptor, and it can never be the
    production descriptor: `descriptor()` refuses the sleeper it accepts.
    """
    if timing_mode(sleeper) != VIRTUAL_CLOCK:
        raise ValueError("a rehearsal descriptor requires a virtual-clock sleeper")
    bounds = frozen_bounds()
    bounds["timingMode"] = VIRTUAL_CLOCK
    bounds["rehearsal"] = True
    return _descriptor(
        sleeper, seconds=seconds, recovery=recovery, bounds=bounds, timing=VIRTUAL_CLOCK
    )
