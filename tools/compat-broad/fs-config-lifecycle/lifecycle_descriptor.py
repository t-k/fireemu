"""Campaign descriptor for the FS-CONFIG-LIFECYCLE management-contract observation.

This module declares, in one hard-coded place, every binding the shared O8 admission
core checks for `FS-CONFIG-LIFECYCLE-01`: the schema kinds, the window, the source
map, the plan compiler, the budget, the Ledger lock scopes, the collector and
comparator the campaign runs, the cost model, the abort closure and the integrity
binding of the worker that performs the HTTPS exchange.

It authorizes nothing. The reviewed lane modules are used exactly as they are; the
transport member only adapts the core's one-argument wire call to the remote
transport's own signature on a consumed capability.

The artifact profile is derived from the published local rehearsal record, which
names the fireemu source commit and artifact digest the local comparison reference
was produced by. The lane has no reviewed build profile registry; the code below says
what the profile does and does not establish, so accepting it is an O7 decision made
on the record rather than an omission.
"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/o8-core"))
sys.path.insert(0, str(HERE))

import _lane

_lane.ensure_package()

from batch_contract import NUMBER, PROJECT
from broad_contract import digest
from fs_config_lifecycle import lifecycle_remote_transport
from fs_config_lifecycle.cases import DEFAULT_DATABASE, NONCE_PATTERN, cases_digest
from fs_config_lifecycle.comparator import compare_rows
from fs_config_lifecycle.lifecycle_collector import collect
from fs_config_lifecycle.manifest import (
    MAX_WALL_SECONDS,
    RECOVERY_RESERVE_SECONDS,
    compile_manifest,
)
from fs_config_lifecycle.manifest import budget as manifest_budget
from fs_config_lifecycle.manifest import lock_scopes as manifest_lock_scopes
from fs_config_lifecycle.surface_matrix import CASE_ID
from o8_admission import authorize_transport
from o8_campaign import CAMPAIGN_APPROVAL_FIELDS, CampaignDescriptor

CAMPAIGN = CASE_ID
FROZEN_INPUTS_KIND = "fs-config-lifecycle-frozen-inputs-v1"
PERMISSION_KIND = "fs-config-lifecycle-owner-execution-permission-v1"
APPROVAL_KIND = "fs-config-lifecycle-o8-approval-v1"
MANIFEST_KIND = "fs-config-lifecycle-o8-manifest-v1"
RECEIPT_KIND = "fs-config-lifecycle-acquisition-receipt-v1"
LOCAL_RECORD = (
    "spec/compatibility/broad-runs/fs-config-lifecycle-local-rehearsal-v7.json"
)
PRINCIPAL_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
HANDOFF_KIND = "fs-config-lifecycle-bearer-token-v1"

LANE_DIRECTORY = "tools/compat-broad/fs-config-lifecycle"
COLLECTOR_ENTRY = f"{LANE_DIRECTORY}/lifecycle_collector.py"
COMPARATOR_ENTRY = f"{LANE_DIRECTORY}/comparator.py"
WORKER_ENTRY = lifecycle_remote_transport.WORKER_ENTRY
GATE_ENTRY = f"{LANE_DIRECTORY}/lifecycle_gate.py"
SHARED_SOURCES = (
    "tools/compat-broad/broad_contract.py",
    "tools/compat-broad/batch_contract.py",
    "tools/compat-broad/production-admission/reservations.py",
    "tools/compat-broad/o8-core/o8_admission.py",
    "tools/compat-broad/o8-core/o8_campaign.py",
    lifecycle_remote_transport.EXCHANGE_MODULE,
)
# The closure a reservation records, so a later retirement proves it runs the same
# sources the acquisition ran.
ABORT_CLOSURE_SOURCES = (
    "tools/compat-broad/production-admission/reservations.py",
    "tools/compat-broad/o8-core/o8_admission.py",
    f"{LANE_DIRECTORY}/lifecycle_admission.py",
    f"{LANE_DIRECTORY}/lifecycle_descriptor.py",
    GATE_ENTRY,
    COLLECTOR_ENTRY,
)

ARTIFACT_PROFILE_BASIS = {
    "kind": "fs-config-lifecycle-artifact-profile-v1",
    "registry": "none",
    "derivedFrom": "the published local rehearsal record's runtime.sourceCommit",
    "establishes": (
        "which fireemu build the local comparison reference was produced by, and "
        "that the retained bytes hash to the digest the approval binds"
    ),
    "doesNotEstablish": (
        "that the build was reviewed; no profile registry entry exists for this "
        "lane and O7 must accept the profile explicitly"
    ),
    "ownerAcceptanceRequired": True,
}


def local_record() -> dict:
    """The published local rehearsal this campaign's production run is compared to."""
    path = ROOT / LOCAL_RECORD
    if path.is_symlink() or not path.is_file():
        raise ValueError("published local rehearsal record required")
    value = json.loads(path.read_bytes())
    runtime = value.get("runtime") if isinstance(value, dict) else None
    if (
        not isinstance(runtime, dict)
        or value.get("campaignId") != CAMPAIGN
        or not isinstance(runtime.get("sourceCommit"), str)
        or len(runtime["sourceCommit"]) != 40
        or not isinstance(runtime.get("artifactSha256"), str)
        or len(runtime["artifactSha256"]) != 64
    ):
        raise ValueError("published local rehearsal record required")
    return value


def artifact_profile() -> str:
    return "fs-config-lifecycle-" + local_record()["runtime"]["sourceCommit"][:9]


def artifact_profile_basis() -> dict:
    record = local_record()
    return {
        **copy.deepcopy(ARTIFACT_PROFILE_BASIS),
        "profile": artifact_profile(),
        "sourceCommit": record["runtime"]["sourceCommit"],
        "localArtifactSha256": record["runtime"]["artifactSha256"],
    }


def campaign_seconds() -> int:
    return int(MAX_WALL_SECONDS)


def recovery_seconds() -> int:
    return int(RECOVERY_RESERVE_SECONDS)


def budget() -> dict:
    return manifest_budget()


def ledger_budget() -> dict:
    """The four Ledger dimensions. No document resource is owned; one principal is."""
    published = budget()
    return {
        "requests": int(published["maxRequests"]),
        "accounts": int(published["maxAccounts"]),
        "resources": 0,
        "costMicrousd": int(published["reservedMicrousd"]),
    }


def frozen_bounds() -> dict:
    published = budget()
    return {
        "totalRequests": int(published["maxRequests"]),
        "wallSeconds": int(published["maxWallSeconds"]),
        "recoverySeconds": int(published["recoveryReserveSeconds"]),
        "requestSlotSeconds": float(published["requestSlotSeconds"]),
        "patchedFieldConfigurations": int(published["maxPatchedFieldConfigurations"]),
        "operations": int(published["maxOperations"]),
        "documentOperations": 0,
        "createdDatabases": 0,
        "maxRequestBytes": lifecycle_remote_transport.MAX_REQUEST_BYTES,
        "maxResponseBytes": lifecycle_remote_transport.RESPONSE_BYTES,
        "perRequestTimeoutSeconds": lifecycle_remote_transport.TIMEOUT,
    }


def cost_model() -> dict:
    published = budget()
    return {
        "campaignId": CAMPAIGN,
        "estimatedCostMicrousd": int(published["estimatedCostMicrousd"]),
        "requestAllowanceMicrousd": int(published["requestAllowanceMicrousd"]),
        "totalCostMicrousd": int(published["reservedMicrousd"]),
        "hardCeilingMicrousd": int(published["hardCeilingMicrousd"]),
        "requests": int(published["maxRequests"]),
        "basis": published["basis"],
    }


def plan_compiler(nonce: str) -> dict:
    """The plan as the admission sees it; every field derives from the nonce."""
    if not isinstance(nonce, str) or NONCE_PATTERN.fullmatch(nonce) is None:
        raise ValueError("nonce must be exactly 32 lowercase hexadecimal characters")
    manifest = compile_manifest(nonce)
    return {
        "schemaVersion": manifest["schema"],
        "campaignId": CAMPAIGN,
        "project": PROJECT,
        "database": DEFAULT_DATABASE,
        "nonce": nonce,
        "manifestDigest": digest(manifest),
        "casesDigest": cases_digest(nonce),
        "executionOrder": list(manifest["executionOrder"]),
        "lockedSteps": manifest["lockedSteps"],
        "lockScopes": manifest["lockScopes"],
        "bounds": frozen_bounds(),
    }


def execution_plan(reference: dict) -> dict:
    """Recompile the plan a frozen reference names, and refuse any other bytes."""
    nonce = reference.get("nonce") if isinstance(reference, dict) else None
    if not isinstance(nonce, str) or NONCE_PATTERN.fullmatch(nonce) is None:
        raise ValueError("frozen lifecycle plan reference required")
    canonical = plan_compiler(nonce)
    if digest(reference) != digest(canonical):
        raise ValueError("frozen lifecycle plan reference differs")
    return canonical


def lock_scopes(plan: dict) -> list[dict]:
    return manifest_lock_scopes(plan["nonce"])


def lane_sources() -> tuple[str, ...]:
    directory = ROOT / LANE_DIRECTORY
    return tuple(
        sorted(f"{LANE_DIRECTORY}/{path.name}" for path in directory.glob("*.py"))
    )


def source_map() -> dict[str, str]:
    """Digest every source this campaign binds: the whole lane, plus the closure."""
    values = {}
    for name in (*lane_sources(), *SHARED_SOURCES):
        path = ROOT / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("frozen campaign source missing")
        values[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return values


def collector(gate, plan, output, *, transmit):
    """Drive the reviewed collector through the supplied configuration gate."""
    return collect(plan["nonce"], transmit, output, gate=gate)


def comparator(result, reference=None):
    """Compare a production collection's rows with the published local rehearsal.

    This establishes per-case agreement on status, typed error and shape; it is not a
    compatibility claim, which remains an owner decision on the evidence.
    """
    record = local_record() if reference is None else reference
    nonce = record.get("runtime", {}).get("nonce")
    if not isinstance(nonce, str) or NONCE_PATTERN.fullmatch(nonce) is None:
        raise ValueError("local rehearsal record names no nonce")
    return {
        "campaignId": CAMPAIGN,
        "rows": compare_rows(record["collection"], result, nonce),
        "localRecordDigest": digest(record),
        "formalCompatibilityClaim": False,
    }


def verify_worker_binding(binding, binding_digest, frozen) -> None:
    """Three independent statements of the same reviewed worker bytes."""
    if not isinstance(binding, bytes) or not binding:
        raise ValueError("reviewed worker source required")
    observed = hashlib.sha256(binding).hexdigest()
    pinned = lifecycle_remote_transport._WORKER_SHA256
    if observed != binding_digest or observed != pinned:
        raise ValueError("worker source digest differs from the reviewed transport")
    if frozen is not None and frozen.get(WORKER_ENTRY) != observed:
        raise ValueError("worker source digest differs from the frozen inputs")


def worker_binding() -> tuple[bytes, str]:
    source = (ROOT / WORKER_ENTRY).read_bytes()
    return source, hashlib.sha256(source).hexdigest()


def transport_bound(value, *, binding, binding_digest, capability=None):
    """Adapt one bound wire call to the remote transport on a consumed capability."""
    if not isinstance(value, dict) or set(value) != {"request", "token", "deadline"}:
        raise ValueError("closed lifecycle wire call required")
    if capability is None:
        raise ValueError("active O7 production capability required")
    authorize_transport(capability, binding=binding, binding_digest=binding_digest)
    verify_worker_binding(binding, binding_digest, None)
    return lifecycle_remote_transport.request(
        value["request"],
        value["token"],
        deadline=value["deadline"],
        capability=capability,
        binding=binding,
        binding_digest=binding_digest,
    )


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
    return (
        lifecycle_remote_transport,
        lifecycle_remote_transport.request,
        transport_bound,
    )


def permission_bindings(plan, source_commit, artifact_digest, inputs, baseline=None):
    """Required non-authorizing fields for an independently supplied permission.

    `databaseProjectionDigest` is owner-supplied and checked separately: it is the
    frozen baseline the collector's first read must equal before any mutation.
    """
    canonical = plan_compiler(plan["nonce"])
    if digest(plan) != digest(canonical):
        raise ValueError("fixed production project/database required")
    required = {
        "kind": PERMISSION_KIND,
        "campaignId": CAMPAIGN,
        "project": PROJECT,
        "projectNumber": NUMBER,
        "quotaProject": PROJECT,
        "database": DEFAULT_DATABASE,
        "nonce": plan["nonce"],
        "manifestDigest": plan["manifestDigest"],
        "casesDigest": plan["casesDigest"],
        "sourceCommit": source_commit,
        "sourceInputs": inputs,
        "collectorSourceDigest": digest(inputs),
        "artifactSha256": artifact_digest,
        "collectorSha256": inputs[COLLECTOR_ENTRY],
        "comparatorSha256": inputs[COMPARATOR_ENTRY],
        "workerSha256": inputs[WORKER_ENTRY],
        "gateSha256": inputs[GATE_ENTRY],
        "budget": budget(),
        "ledgerBudget": ledger_budget(),
        "lockScopes": lock_scopes(plan),
        "lockedSteps": plan["lockedSteps"],
        "wallSeconds": campaign_seconds(),
        "campaignSeconds": campaign_seconds(),
        "recoverySeconds": recovery_seconds(),
        "perRequestTimeoutSeconds": lifecycle_remote_transport.TIMEOUT,
        "maxRequestBytes": lifecycle_remote_transport.MAX_REQUEST_BYTES,
        "maxResponseBytes": lifecycle_remote_transport.RESPONSE_BYTES,
        "concurrency": 1,
        "documentOperations": 0,
        "createdDatabases": 0,
        "costModel": cost_model(),
        "artifactProfileBasis": artifact_profile_basis(),
        "credentialPrincipalContract": {
            "alternatives": [
                ["clientId", "subject", "requiredScopes"],
                ["clientId", "verifiedEmail", "requiredScopes"],
            ],
            "requiredScopes": [PRINCIPAL_SCOPE],
            "identitySource": "owner-frozen permission; never inferred from tokeninfo",
        },
        "restoreContract": {
            "everyPatchReverted": True,
            "verifyReadbackEqualsBaseline": True,
            "unrecoveredHoldsReservation": True,
            "reconciliation": ["field-listings-empty", "enumeration-unchanged"],
        },
    }
    if baseline is not None:
        required["databaseProjectionDigest"] = baseline["projectionDigest"]
    return required


def descriptor() -> CampaignDescriptor:
    """The lifecycle campaign as the shared admission core sees it."""
    return CampaignDescriptor(
        campaign_id=CAMPAIGN,
        frozen_inputs_kind=FROZEN_INPUTS_KIND,
        permission_kind=PERMISSION_KIND,
        approval_kind=APPROVAL_KIND,
        manifest_kind=MANIFEST_KIND,
        approval_fields=CAMPAIGN_APPROVAL_FIELDS,
        artifact_profile=artifact_profile(),
        campaign_seconds=campaign_seconds(),
        recovery_seconds=recovery_seconds(),
        source_map=source_map,
        abort_closure_sources=ABORT_CLOSURE_SOURCES,
        required_source_entries=(
            COLLECTOR_ENTRY,
            COMPARATOR_ENTRY,
            WORKER_ENTRY,
            GATE_ENTRY,
        ),
        frozen_bounds=frozen_bounds(),
        budget=budget(),
        plan_compiler=plan_compiler,
        lock_scopes=lock_scopes,
        collector=collector,
        comparator=comparator,
        cost_model=cost_model,
        permission_bindings=permission_bindings,
        transport_bound=transport_bound,
        binding_verifier=verify_worker_binding,
        retained_artifact_validator=retained_artifact_validator,
        forbidden_transports=forbidden_transports,
    )
