"""O8 campaign descriptor for the FS-RULES user-token observation matrix.

This module declares, in one hard-coded place, every binding the shared O8
admission core checks for ``FS-RULES-USER-TOKEN-MATRIX-01``: the schema kinds,
the window, the source map, the plan compiler, the budget, the Ledger lock
scopes, the collector and comparator the campaign runs, the cost model and the
abort closure.

It authorizes nothing and opens nothing. The lane's own ``admission()`` still
raises. The transport and binding members require an independently issued O7
capability and the reviewed worker bytes; descriptor construction alone cannot
reach a production wire. The collector and acquisition comparator are the
lane's real modules, reached only through an injected transport that the
core's ``reject_production_transport`` has inspected.

The window contains 300 seconds of observation and 300 seconds of recovery,
with a 600 second absolute wall allocation. The transport adapter is closed over one
request bundle and delegates wire execution to the reviewed remote transport.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import sys
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/o8-core"))
sys.path.insert(0, str(HERE))

from broad_contract import digest
from o5_user_token_campaign import (
    PERMISSION_ENVELOPE,
    admitted_manifest_digest,
    gate_management_plan,
    rules_management_contract,
    rules_management_plan,
)
from o5_user_token_campaign import (
    budget as campaign_budget,
)
from o5_user_token_case import CAMPAIGN, compile_case, validate_case
from o5_user_token_collector import ROLE_PRODUCTION, collect
from o5_user_token_comparator_v2 import COMPARATOR_CONTRACT, REFUSED, compare
from o8_campaign import CAMPAIGN_APPROVAL_FIELDS, CampaignDescriptor

PROJECT = "fireemu-35fe6"
DATABASE = "(default)"
# The tenant a real run gets is assigned by Identity Platform, so the frozen
# plan carries the compiler's placeholder and the executor recompiles with
# the assigned identifier; the acquisition comparator recompiles per side.
PLACEHOLDER_TENANT = "o5-user-token-tenant"

FROZEN_INPUTS_KIND = "o5-user-token-frozen-inputs-v1"
PERMISSION_KIND = "o5-user-token-owner-execution-permission-v1"
APPROVAL_KIND = "o5-user-token-o8-approval-v1"
MANIFEST_KIND = "o5-user-token-o8-manifest-v1"
SHADOW_RECORD = "spec/compatibility/fs-rules-user-token-local-shadow.json"
LANE_DIRECTORY = "tools/compat-broad/fs-rules-publication"

CAMPAIGN_SECONDS = 300
RECOVERY_SECONDS = 300
# The campaign manifest's ceiling, in micro-USD: US$1.00.
COST_CEILING_MICROUSD = 1_000_000

COLLECTOR_ENTRY = f"{LANE_DIRECTORY}/o5_user_token_collector.py"
COMPARATOR_ENTRY = f"{LANE_DIRECTORY}/o5_user_token_comparator_v2.py"
CASE_ENTRY = f"{LANE_DIRECTORY}/o5_user_token_case.py"
CAMPAIGN_ENTRY = f"{LANE_DIRECTORY}/o5_user_token_campaign.py"
DESCRIPTOR_ENTRY = f"{LANE_DIRECTORY}/o5_user_token_descriptor.py"
SHARED_SOURCES = (
    "tools/compat-broad/broad_contract.py",
    "tools/compat-broad/shared_gate.py",
    "tools/compat-broad/production-admission/reservations.py",
    "tools/compat-broad/o8-core/o8_admission.py",
    "tools/compat-broad/o8-core/o8_campaign.py",
)
ABORT_CLOSURE_SOURCES = (
    "tools/compat-broad/shared_gate.py",
    "tools/compat-broad/production-admission/reservations.py",
    "tools/compat-broad/o8-core/o8_admission.py",
    COLLECTOR_ENTRY,
    f"{LANE_DIRECTORY}/o5_user_token_remote_transport.py",
    f"{LANE_DIRECTORY}/o5_user_token_https_worker.py",
    COMPARATOR_ENTRY,
    DESCRIPTOR_ENTRY,
)


def shadow_record() -> dict[str, Any]:
    """The published local shadow this campaign's production run is compared to."""
    path = ROOT / SHADOW_RECORD
    if path.is_symlink() or not path.is_file():
        raise ValueError("published local shadow record required")
    value = json.loads(path.read_bytes())
    artifact = value.get("artifact") if isinstance(value, dict) else None
    if (
        not isinstance(artifact, dict)
        or value.get("status") != "LOCAL_SHADOW_ONLY"
        or value.get("productionExecuted") is not False
        or not isinstance(artifact.get("sourceCommit"), str)
        or len(artifact["sourceCommit"]) != 40
        or not isinstance(artifact.get("artifactSha256"), str)
        or len(artifact["artifactSha256"]) != 64
    ):
        raise ValueError("published local shadow record required")
    return value


def artifact_profile() -> str:
    """The build the comparison reference was produced by, named by its commit.

    There is no reviewed build profile registry for this lane. The profile
    names the shadow's source commit so that O7 accepts, on the record, that
    the reference it compares against was built from that commit; the digest
    proves only which bytes were retained, not that the build was reviewed.
    """
    return "o5-user-token-" + shadow_record()["artifact"]["sourceCommit"][:9]


def lane_sources() -> tuple[str, ...]:
    """Every top-level module of the lane, tests included, in a stable order."""
    directory = ROOT / LANE_DIRECTORY
    return tuple(
        sorted(f"{LANE_DIRECTORY}/{path.name}" for path in directory.glob("*.py"))
    )


def source_map() -> dict[str, str]:
    """Digest every source this campaign binds: the whole lane and the closure."""
    values: dict[str, str] = {}
    for name in (*lane_sources(), *SHARED_SOURCES):
        path = ROOT / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("frozen campaign source missing")
        values[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return values


def plan_compiler(nonce: str) -> dict[str, Any]:
    """The lane's own compiled observation plan, bound to one fresh nonce."""
    return compile_case(PROJECT, DATABASE, nonce, PLACEHOLDER_TENANT)


def budget() -> dict[str, Any]:
    """The four Ledger dimensions, from the campaign manifest's own budget."""
    estimate = campaign_budget(plan_compiler("0" * 32))
    plan = plan_compiler("0" * 32)
    return {
        "requests": int(estimate["requestUpperBound"]),
        "accounts": len(plan["ownedAccounts"]),
        "resources": len(plan["ownedResources"]),
        "costMicrousd": COST_CEILING_MICROUSD,
    }


def frozen_bounds() -> dict[str, Any]:
    """The bounded shape of one run, every figure from the campaign manifest."""
    estimate = campaign_budget(plan_compiler("0" * 32))
    return {
        "observationRequests": int(estimate["observationRequests"]),
        "fixtureRequests": int(estimate["fixtureRequests"]),
        "authRequests": int(estimate["authRequests"]),
        "rulesRequests": int(estimate["rulesRequests"]),
        "recoveryRequests": int(estimate["recoveryRequests"]),
        "totalRequests": int(estimate["requestUpperBound"]),
        "concurrency": int(estimate["concurrencyUpperBound"]),
        "perRequestTimeoutSeconds": float(estimate["perRequestTimeoutSeconds"]),
        "wallClockDeadlineSeconds": float(estimate["wallClockDeadlineSeconds"]),
        "recoveryDeadlineSeconds": float(estimate["recoveryDeadlineSeconds"]),
        "rulesManagementRequests": int(estimate["rulesRequests"]),
        "rulesManagement": rules_management_plan(),
    }


def lock_scopes(plan: dict[str, Any]) -> list[dict[str, str]]:
    """What a run of this campaign holds in the shared Ledger.

    Publishing a Ruleset changes the Rules state of the whole database, so the
    database's ruleset key is held exclusively; the nonce subtree and the
    throwaway accounts are written; the preexisting tenant binding and all
    remaining configuration are read.
    """
    validate_case(plan)
    scope = f"project/{PROJECT}"
    firestore = f"{scope}/firestore/{DATABASE}"
    nonce = plan["nonce"]
    return [
        {
            "key": f"{firestore}/documents/o5-user-token/n{nonce}/cases/*",
            "mode": "WRITE",
        },
        {"key": f"{firestore}/ruleset", "mode": "EXCLUSIVE"},
        *[
            {"key": f"{firestore}/{kind}", "mode": "READ"}
            for kind in ("indexes", "database")
        ],
        {"key": f"{scope}/auth/config", "mode": "READ"},
        {"key": f"{scope}/auth/accounts/o5-user-token/{nonce}/*", "mode": "WRITE"},
        {"key": f"{scope}/auth/tenants/*", "mode": "READ"},
        {"key": f"{scope}/api-key-binding", "mode": "READ"},
    ]


def cost_model() -> dict[str, Any]:
    """The campaign manifest's ceiling, not a quoted tariff."""
    estimate = campaign_budget(plan_compiler("0" * 32))
    return {
        "campaignId": CAMPAIGN,
        "estimatedCostMicrousd": round(estimate["estimatedCostUsd"] * 1_000_000),
        "totalCostMicrousd": COST_CEILING_MICROUSD,
        "basis": estimate["estimateBasis"],
    }


def gate_plan(
    plan: dict[str, Any], *, permission_expires_at: float | None = None
) -> dict[str, Any]:
    """Freeze the Rules management envelope consumed by ``Gate``."""
    validate_case(plan)
    management = gate_management_plan(plan)
    value = {
        "contract": "shared-local-v1",
        "kind": "fs-rules-user-token-gate-plan-v1",
        "campaignId": CAMPAIGN,
        "project": PROJECT,
        "database": DATABASE,
        "nonce": plan["nonce"],
        "planDigest": plan["planDigest"],
        "management": management,
        "rulesManagementContract": rules_management_contract(plan),
        "rulesCompilerSources": {
            name: hashlib.sha256((HERE / name).read_bytes()).hexdigest()
            for name in ("o5_user_token_case.py", "o5_user_token_campaign.py")
        },
        "observationRequests": len(management["observation"]),
        "dataRequests": len(plan["observation"]),
        "managementRequests": management["totalRequests"],
        "requestCostMicrousd": management["requestCostMicrousd"],
        "costMicrousd": management["totalRequests"],
        "requestSeconds": 12.0,
        "wallSeconds": 600.0,
        "recoverySeconds": 300.0,
        "intervalSeconds": 0.25,
        "receiptKind": "fs-rules-management-receipt-v1",
        "transport": "bounded-rules-worker",
        "jobs": {
            "rules-management": {
                "resources": [],
                "observation": [],
                "recovery": [],
            }
        },
        "jobSlots": 1,
        "coordinatorRequests": 0,
        "fixedCostMicrousd": 0,
    }
    if permission_expires_at is not None:
        value["permissionExpiresAt"] = permission_expires_at
    return value


def permission_bindings(
    plan: dict[str, Any],
    source_commit: str,
    artifact_digest: str,
    inputs: dict[str, str],
) -> dict[str, Any]:
    """Required, non-authorizing fields an owner execution permission carries."""
    validate_case(plan)
    return {
        "kind": PERMISSION_KIND,
        "campaignId": CAMPAIGN,
        "project": PROJECT,
        "database": DATABASE,
        "nonce": plan["nonce"],
        "planDigest": plan["planDigest"],
        "campaignManifestDigest": admitted_manifest_digest(
            plan["project"], plan["database"], plan["nonce"]
        ),
        "sourceCommit": source_commit,
        "sourceInputs": inputs,
        "collectorSourceDigest": digest(inputs),
        "artifactSha256": artifact_digest,
        "collectorSha256": inputs[COLLECTOR_ENTRY],
        "comparatorSha256": inputs[COMPARATOR_ENTRY],
        "budget": budget(),
        "frozenBounds": frozen_bounds(),
        "permissionEnvelope": copy.deepcopy(PERMISSION_ENVELOPE),
        "wallSeconds": CAMPAIGN_SECONDS,
        "recoverySeconds": RECOVERY_SECONDS,
        "concurrency": 1,
        "costModel": cost_model(),
        "artifactProfile": artifact_profile(),
    }


def collector(
    plan: dict[str, Any],
    transmit: Any,
    *,
    run_id: str,
    acquisition: dict[str, Any],
    journal_path: Any = None,
    management_session: Any = None,
    journal: Any = None,
    ownership: Any = None,
    recovery_dispatch: Any = None,
    context: Any = None,
) -> dict[str, Any]:
    """Drive the lane's collector as the production side, bound.

    The transport is whatever the admitted execution injects; this descriptor
    has none of its own. The run is always bound, so an unbound transport is
    refused by the collector on its first receipt.
    """
    return collect(
        plan,
        transmit,
        role=ROLE_PRODUCTION,
        run_id=run_id,
        deadline_seconds=float(CAMPAIGN_SECONDS),
        recovery_deadline_seconds=float(CAMPAIGN_SECONDS + RECOVERY_SECONDS),
        journal_path=journal_path,
        acquisition=acquisition,
        management_session=management_session,
        journal=journal,
        ownership=ownership,
        context=context,
        recovery_dispatch=recovery_dispatch,
    )


def comparator(
    production: dict[str, Any],
    plan: dict[str, Any],
    local: dict[str, Any] | None = None,
    *,
    manifest_digest: str | None = None,
    production_cleanup_gate: Any = None,
) -> dict[str, Any]:
    """Classify a production bundle against the published local shadow.

    The published shadow is the reference this campaign is bound to. A record
    that is not a complete local run of this campaign yields no reference, and
    the acquisition comparator then refuses rather than compares.
    """
    record = shadow_record()
    reference = local if local is not None else record.get("bundle")
    # The reference must be the build the record names. A bundle whose
    # artifact binding differs from the record's is another run, whatever
    # else it carries, and is refused before any row is read.
    expected_artifact = {
        "artifactSha256": record["artifact"]["artifactSha256"],
        "sourceCommit": record["artifact"]["sourceCommit"],
    }
    if production_cleanup_gate is not None:
        from o5_user_token_production_bridge import validated_cleanup_gate

        production_cleanup_gate = validated_cleanup_gate(
            plan, production_cleanup_gate
        )
    acquisition = reference.get("acquisition") if isinstance(reference, dict) else None
    bound = acquisition.get("artifact") if isinstance(acquisition, dict) else None
    if bound != expected_artifact:
        return {
            "contract": COMPARATOR_CONTRACT,
            "classification": REFUSED,
            "rows": [],
            "conditions": {},
            "errors": ["local:reference-artifact-mismatch"],
            "acquisitionValidated": False,
            "productionObserved": False,
            "promotionReady": False,
        }
    return compare(
        production,
        reference,
        plan,
        manifest_digest=manifest_digest,
        production_cleanup_gate=production_cleanup_gate,
    )


def unwired(member: str):
    """A descriptor member this lane has not earned yet."""

    def refuse(*args: Any, **kwargs: Any) -> None:
        raise PermissionError(f"O5 user-token {member} is not wired")

    return refuse


_WORKER_TIMEOUT_SECONDS = 8.0


def binding_verifier(binding: Any, binding_digest: Any, frozen: Any) -> None:
    """Verify the reviewed worker bytes and the frozen source-map entry."""
    from o5_user_token_remote_transport import verify_worker_binding

    verify_worker_binding(binding, binding_digest, frozen)


def transport_bound(
    value: Any,
    *,
    binding: bytes,
    binding_digest: str,
    capability: Any = None,
) -> dict[str, Any]:
    """Run one closed Rules request through the admitted worker.

    Credentials and identity proofs are accepted only in this in-memory call
    bundle; collector receipts never receive the bundle. The O8 capability and
    worker binding remain the authority for dispatch.
    """
    required = {
        "plan",
        "operation",
        "credentials",
        "frozenInputs",
        "accountBindings",
        "identityProofs",
        "fixtureOrigin",
        "deadline",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("closed Rules wire call required")
    if capability is None:
        raise ValueError("active O7 production capability required")
    if (
        not isinstance(value["plan"], dict)
        or not isinstance(value["operation"], dict)
        or not isinstance(value["credentials"], dict)
        or not isinstance(value["frozenInputs"], dict)
        or not isinstance(value["accountBindings"], dict)
        or not isinstance(value["identityProofs"], dict)
        or value["fixtureOrigin"] is not None
        and not isinstance(value["fixtureOrigin"], str)
    ):
        raise ValueError("closed Rules wire call required")
    deadline = value["deadline"]
    if (
        type(deadline) not in (int, float)
        or not math.isfinite(deadline)
        or deadline - time.monotonic() < _WORKER_TIMEOUT_SECONDS
    ):
        raise TimeoutError("Rules worker cannot fit within Gate deadline")
    binding_verifier(binding, binding_digest, value["frozenInputs"].get("sourceInputs"))
    from o5_user_token_remote_transport import make_transport
    from o8_admission import authorize_transport

    authorize_transport(capability, binding=binding, binding_digest=binding_digest)
    transmit = make_transport(
        value["plan"],
        credentials=value["credentials"],
        frozen_inputs=value["frozenInputs"],
        account_bindings=value["accountBindings"],
        identity_proofs=value["identityProofs"],
        fixture_origin=value["fixtureOrigin"],
    )
    return transmit(
        value["operation"],
        binding=binding,
        binding_digest=binding_digest,
        capability=capability,
    )


def retained_artifact_validator(
    artifact_path: Any, manifest_path: Any, profile: str
) -> dict[str, str]:
    """Bind the retained artifact and manifest by digest.

    The profile is a label derived from the shadow's commit, and the retained
    artifact must be the very build the shadow ran: its digest must equal the
    record's `artifact.artifactSha256`. The digests prove which bytes the
    owner retained and that they are the comparison reference's build, not
    that the build was reviewed.
    """
    if profile != artifact_profile():
        raise ValueError("retained artifact profile differs")
    values: dict[str, str] = {}
    for key, path in (
        ("artifactSha256", artifact_path),
        ("retainedManifestSha256", manifest_path),
    ):
        path = Path(path)
        if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
            raise ValueError("retained regular artifact required")
        values[key] = hashlib.sha256(path.read_bytes()).hexdigest()
    if values["artifactSha256"] != shadow_record()["artifact"]["artifactSha256"]:
        raise ValueError("retained artifact is not the shadow's build")
    return values


def forbidden_transports() -> tuple[Any, ...]:
    """Objects an injected preparation transport must not be able to reach."""
    return (transport_bound,)


def descriptor() -> CampaignDescriptor:
    """The user-token campaign as the shared admission core sees it."""
    return CampaignDescriptor(
        campaign_id=CAMPAIGN,
        frozen_inputs_kind=FROZEN_INPUTS_KIND,
        permission_kind=PERMISSION_KIND,
        approval_kind=APPROVAL_KIND,
        manifest_kind=MANIFEST_KIND,
        approval_fields=CAMPAIGN_APPROVAL_FIELDS,
        artifact_profile=artifact_profile(),
        campaign_seconds=CAMPAIGN_SECONDS,
        recovery_seconds=RECOVERY_SECONDS,
        source_map=source_map,
        abort_closure_sources=ABORT_CLOSURE_SOURCES,
        required_source_entries=(
            COLLECTOR_ENTRY,
            COMPARATOR_ENTRY,
            CASE_ENTRY,
            CAMPAIGN_ENTRY,
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
        binding_verifier=binding_verifier,
        retained_artifact_validator=retained_artifact_validator,
        forbidden_transports=forbidden_transports,
    )
