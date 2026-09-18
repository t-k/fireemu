"""Campaign descriptor for the request-byte boundary observation.

This module declares, in one hard-coded place, every binding the shared O8
admission core checks for `FS-LIMIT-API-REQUEST-BYTES`: the schema kinds, the
window, the source map, the plan compiler, the budget, the Ledger lock scopes,
the collector and comparator the campaign runs, the cost model, the abort
closure, and the integrity binding of the worker that performs the HTTPS
exchange.

It authorizes nothing. It changes none of the reviewed lane modules: the
compiler, the collector and the remote transport are used exactly as they are,
and the transport member below only adapts the core's one-argument wire call to
the transport's own `(plan, phase, index, operation, token)` signature.

The worker integrity binding is this lane's own, not the Commit lane's. The
Commit worker runs from an unlinked read-only archive descriptor; this lane's
worker is a single reviewed source file whose bytes the transport pins by
digest before it spawns an isolated interpreter. The core takes either, because
it treats the binding as opaque and asks the descriptor to verify it.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/o8-core"))
sys.path.insert(0, str(HERE))

import request_bytes_remote_transport
from batch_contract import NUMBER, PROJECT
from broad_contract import digest
from o8_campaign import BASE_APPROVAL_FIELDS, CampaignDescriptor
from request_bytes_collector import collect_local
from request_bytes_compiler import (
    CAMPAIGN,
    compile_request_bytes_plan,
    validate_request_bytes_plan,
)
from request_bytes_shadow import classify_local_result

DATABASE = "(default)"
_NONCE = re.compile(r"^[0-9a-f]{32}$")
BUDGET_PATH = "spec/compatibility/fs-request-bytes-budget.json"
FROZEN_INPUTS_KIND = "request-bytes-frozen-inputs-v1"
PERMISSION_KIND = "request-bytes-owner-execution-permission-v1"
APPROVAL_KIND = "request-bytes-o8-approval-v1"
MANIFEST_KIND = "request-bytes-o8-manifest-v1"
# The lane has no reviewed build profile registry of its own. The retained
# artifact is bound by digest, which proves which bytes the owner retained and
# nothing about whether that build was reviewed.
ARTIFACT_PROFILE = "request-bytes-retained-artifact-v1"

COLLECTOR_ENTRY = (
    "tools/compat-broad/fs-request-bytes-boundary/request_bytes_collector.py"
)
COMPARATOR_ENTRY = (
    "tools/compat-broad/fs-request-bytes-boundary/request_bytes_shadow.py"
)
WORKER_ENTRY = (
    "tools/compat-broad/fs-request-bytes-boundary/request_bytes_https_worker.py"
)
TRANSPORT_ENTRY = (
    "tools/compat-broad/fs-request-bytes-boundary/request_bytes_remote_transport.py"
)
# The lane modules the budget declares as bound, plus the admission surface this
# campaign executes. Test modules are deliberately excluded: they are not run by
# an acquisition, and including them would churn the frozen digest on every
# test edit.
LANE_SOURCES = (
    "tools/compat-broad/fs-request-bytes-boundary/request_bytes_compiler.py",
    COLLECTOR_ENTRY,
    "tools/compat-broad/fs-request-bytes-boundary/request_bytes_campaign.py",
    "tools/compat-broad/fs-request-bytes-boundary/request_bytes_local_transport.py",
    TRANSPORT_ENTRY,
    WORKER_ENTRY,
    "tools/compat-broad/fs-request-bytes-boundary/request_bytes_process_exchange.py",
    COMPARATOR_ENTRY,
    "tools/compat-broad/fs-request-bytes-boundary/request_bytes_descriptor.py",
    "tools/compat-broad/fs-request-bytes-boundary/request_bytes_admission.py",
)
SHARED_SOURCES = (
    "tools/compat-broad/broad_contract.py",
    "tools/compat-broad/batch_contract.py",
    "tools/compat-broad/shared_gate.py",
    "tools/compat-broad/production-admission/reservations.py",
    "tools/compat-broad/o8-core/o8_admission.py",
    "tools/compat-broad/o8-core/o8_campaign.py",
)
# The closure a reservation records, so a later abort proves it runs the same
# sources the acquisition ran.
ABORT_CLOSURE_SOURCES = (
    "tools/compat-broad/shared_gate.py",
    "tools/compat-broad/production-admission/reservations.py",
    "tools/compat-broad/o8-core/o8_admission.py",
    "tools/compat-broad/fs-request-bytes-boundary/request_bytes_admission.py",
    "tools/compat-broad/fs-request-bytes-boundary/request_bytes_descriptor.py",
)


def budget_document() -> dict:
    """The published budget, read from the spec rather than restated here."""
    path = ROOT / BUDGET_PATH
    if path.is_symlink() or not path.is_file():
        raise ValueError("published request-byte budget required")
    value = json.loads(path.read_bytes())
    if (
        not isinstance(value, dict)
        or value.get("schema") != "fs-request-bytes-budget-v1"
        or value.get("campaignId") != CAMPAIGN
    ):
        raise ValueError("published request-byte budget required")
    return value


def _budget_numbers():
    published = budget_document()
    budget = published["budget"]
    cost = published["cost"]
    micro = math.ceil(cost["estimatedCostUsd"] * 1_000_000)
    return published, budget, cost, micro


def campaign_seconds() -> int:
    return int(_budget_numbers()[1]["maxDurationSeconds"])


def recovery_seconds() -> int:
    return int(_budget_numbers()[1]["recoveryWindow"]["reserveSeconds"])


def transport_deadline_seconds() -> float:
    """The per-request wire ceiling, taken from the spec and checked against code."""
    published = budget_document()
    declared = published["transportDeadline"]["perRequestSeconds"]
    enforced = request_bytes_remote_transport.TIMEOUT
    if declared != enforced or published["budget"]["perRequestTimeoutSeconds"] != (
        enforced
    ):
        raise ValueError("published transport deadline differs from the enforced one")
    return float(enforced)


def budget() -> dict:
    """The Ledger budget dimensions, derived from the published budget."""
    _published, published_budget, _cost, micro = _budget_numbers()
    return {
        "requests": int(published_budget["maxHttpRequests"]),
        "accounts": int(published_budget["maxAccounts"]),
        "resources": int(published_budget["maxDistinctResources"]),
        "costMicrousd": micro,
    }


def frozen_bounds() -> dict:
    published, published_budget, _cost, _micro = _budget_numbers()
    accounting = published["accounting"]
    return {
        "dataRequests": int(accounting["httpRequests"]),
        "documentWrites": int(accounting["documentWrites"]),
        "documentReads": int(accounting["documentReads"]),
        "documentDeletes": int(accounting["documentDeletes"]),
        "uploadedBytes": int(accounting["uploadedBytes"]),
        "totalRequests": int(published_budget["maxHttpRequests"]),
        "perRequestTimeoutSeconds": transport_deadline_seconds(),
    }


def cost_model() -> dict:
    """Planning ceilings from the published budget, never a quoted tariff."""
    _published, published_budget, cost, micro = _budget_numbers()
    return {
        "campaignId": CAMPAIGN,
        "estimatedCostMicrousd": micro,
        "hardCeilingMicrousd": math.ceil(cost["hardCostCeilingUsd"] * 1_000_000),
        "unitPricesUsd": dict(cost["unitPricesUsd"]),
        "totalCostMicrousd": micro,
        "requests": int(published_budget["maxHttpRequests"]),
        "basis": cost["basis"],
    }


_PLAN_CACHE: dict[str, tuple[dict, str]] = {}


def compile_execution_plan(nonce: str) -> tuple[dict, str]:
    """The lane's real compiled plan and its published digest, for one nonce.

    The plan carries the three canonical request bodies and is about 63 MB of
    JSON, so it is never written into a frozen record; it is recompiled from the
    nonce, which is the only free variable, and checked against the digest the
    record froze.
    """
    cached = _PLAN_CACHE.get(nonce)
    if cached is None:
        plan = compile_request_bytes_plan(PROJECT, DATABASE, nonce)
        cached = (plan, _plan_digest(plan))
        _PLAN_CACHE[nonce] = cached
    return cached


def _plan_digest(plan: dict) -> str:
    """The lane's own published plan digest, computed the way the lane computes it."""
    payload = json.dumps(
        plan, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def plan_compiler(nonce: str) -> dict:
    """The plan as the admission sees it: a reference, not 63 MB of request bodies.

    Every field here is derived from the nonce by the reviewed compiler, so the
    reference names exactly one compiled plan and an executor can rebuild it.
    """
    plan, plan_digest = compile_execution_plan(nonce)
    return {
        "schemaVersion": plan["schemaVersion"],
        "campaignId": plan["campaignId"],
        "catalogId": plan["catalogId"],
        "project": plan["project"],
        "database": plan["database"],
        "nonce": nonce,
        "planDigest": plan_digest,
        "ownedScope": plan["ownedScope"],
        "ownedResourceCount": len(plan["ownedResources"]),
        "bounds": copy.deepcopy(plan["bounds"]),
    }


def execution_plan(reference: dict) -> dict:
    """Recompile the plan a frozen reference names, and refuse any other bytes."""
    nonce = reference.get("nonce") if isinstance(reference, dict) else None
    if not isinstance(nonce, str) or _NONCE.fullmatch(nonce) is None:
        raise ValueError("frozen request-byte plan reference required")
    canonical = plan_compiler(nonce)
    plan, plan_digest = compile_execution_plan(nonce)
    if digest(reference) != digest(canonical) or reference["planDigest"] != plan_digest:
        raise ValueError("frozen request-byte plan reference differs")
    validate_request_bytes_plan(plan)
    return plan


def lock_scopes(plan: dict) -> list[dict]:
    """The owned document namespace, plus the read scopes a preflight observes."""
    nonce = plan["nonce"]
    scope = f"project/{PROJECT}"
    firestore = f"{scope}/firestore/{DATABASE}"
    return [
        {
            "key": (f"{firestore}/documents/oracle/{nonce}/request-bytes-01/*"),
            "mode": "WRITE",
        },
        *[
            {"key": f"{firestore}/{kind}", "mode": "READ"}
            for kind in ("indexes", "ruleset", "database")
        ],
        {"key": f"{scope}/auth/config", "mode": "READ"},
        {"key": f"{scope}/api-key-binding", "mode": "READ"},
    ]


def source_map() -> dict[str, str]:
    """Digest every source this campaign executes, by name rather than by glob."""
    values = {}
    for name in (*LANE_SOURCES, *SHARED_SOURCES):
        path = ROOT / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("frozen campaign source missing")
        values[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return values


def collector(gate, plan, output, *, transmit):
    """Drive the reviewed collector; the Gate argument is accepted, never used.

    The collector's own contract is a plan, a one-argument callable and an
    output directory. It is not given the Gate, because this lane's charging
    authority is unresolved; see `request_bytes_admission.reservation_claim`.
    """
    return collect_local(plan, transmit, output)


def comparator(result):
    return classify_local_result(result)


def transport_bound(value, *, binding, binding_digest):
    """Adapt one bound wire call to the reviewed transport's own signature.

    `value` carries the frozen slot coordinates and the bearer token for exactly
    one request. The binding is the reviewed worker source, and its digest is
    re-checked here as well as inside the transport, so a capability issued
    against other bytes cannot reach the wire through this path.
    """
    if not isinstance(value, dict) or set(value) != {
        "plan",
        "phase",
        "index",
        "operation",
        "token",
    }:
        raise ValueError("closed request-byte wire call required")
    verify_worker_binding(binding, binding_digest, None)
    return request_bytes_remote_transport.request(
        value["plan"],
        value["phase"],
        value["index"],
        value["operation"],
        value["token"],
        timeout=transport_deadline_seconds(),
    )


def verify_worker_binding(binding, binding_digest, frozen) -> None:
    """Check the reviewed worker bytes against the transport and the frozen map.

    The binding is the worker source itself. It must hash to the digest the
    capability carries, that digest must be the one the reviewed transport pins,
    and, when a frozen source map is supplied, it must equal the digest the O7
    inputs froze for that file. Three independent statements of the same bytes.
    """
    if not isinstance(binding, bytes) or not binding:
        raise ValueError("reviewed worker source required")
    observed = hashlib.sha256(binding).hexdigest()
    pinned = request_bytes_remote_transport._WORKER_SHA256
    if observed != binding_digest or observed != pinned:
        raise ValueError("worker source digest differs from the reviewed transport")
    if frozen is not None and frozen.get(WORKER_ENTRY) != observed:
        raise ValueError("worker source digest differs from the frozen inputs")


def worker_binding() -> tuple[bytes, str]:
    """Read the reviewed worker source and its digest from the lane."""
    source = (ROOT / WORKER_ENTRY).read_bytes()
    return source, hashlib.sha256(source).hexdigest()


def retained_artifact_validator(artifact_path, manifest_path, profile):
    """Bind the retained artifact and manifest by digest.

    This is weaker than the Commit lane's validator, which resolves a reviewed
    build profile registry. Here the profile is a label: the digests prove which
    bytes the owner retained, not that the build behind them was reviewed.
    """
    if profile != ARTIFACT_PROFILE:
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
    """Objects an injected preparation transport must not be able to reach."""
    return (
        request_bytes_remote_transport,
        request_bytes_remote_transport.request,
        request_bytes_remote_transport.prepare,
        transport_bound,
    )


def permission_bindings(plan, source_commit, artifact_digest, inputs) -> dict:
    """Required non-authorizing fields for an independently supplied permission."""
    canonical = plan_compiler(plan["nonce"])
    if digest(plan) != digest(canonical):
        raise ValueError("fixed production project/database required")
    return {
        "kind": PERMISSION_KIND,
        "campaignId": CAMPAIGN,
        "project": PROJECT,
        "projectNumber": NUMBER,
        "quotaProject": PROJECT,
        "database": DATABASE,
        "nonce": plan["nonce"],
        "planDigest": plan["planDigest"],
        "sourceCommit": source_commit,
        "sourceInputs": inputs,
        "collectorSourceDigest": digest(inputs),
        "artifactSha256": artifact_digest,
        "collectorSha256": inputs[COLLECTOR_ENTRY],
        "comparatorSha256": inputs[COMPARATOR_ENTRY],
        "workerSha256": inputs[WORKER_ENTRY],
        "budget": budget(),
        "ownedScope": plan["ownedScope"],
        "ownedResourceCount": plan["ownedResourceCount"],
        "wallSeconds": campaign_seconds(),
        "recoverySeconds": recovery_seconds(),
        "perRequestTimeoutSeconds": transport_deadline_seconds(),
        "concurrency": 1,
        "tariffsConfirmedBelowPlanningCeilings": True,
        "costModel": cost_model(),
    }


def descriptor() -> CampaignDescriptor:
    """The request-byte campaign as the shared admission core sees it."""
    return CampaignDescriptor(
        campaign_id=CAMPAIGN,
        frozen_inputs_kind=FROZEN_INPUTS_KIND,
        permission_kind=PERMISSION_KIND,
        approval_kind=APPROVAL_KIND,
        manifest_kind=MANIFEST_KIND,
        approval_fields=BASE_APPROVAL_FIELDS,
        artifact_profile=ARTIFACT_PROFILE,
        campaign_seconds=campaign_seconds(),
        recovery_seconds=recovery_seconds(),
        source_map=source_map,
        abort_closure_sources=ABORT_CLOSURE_SOURCES,
        required_source_entries=(COLLECTOR_ENTRY, COMPARATOR_ENTRY, WORKER_ENTRY),
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
