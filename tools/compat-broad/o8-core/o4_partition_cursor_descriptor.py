"""Campaign descriptor for the bounded PartitionQuery and cursor observation.

This module declares, in one hard-coded place, every binding the shared O8
admission core checks for `FS-QUERY-PARTITION-CURSOR-04`: the schema kinds, the
window, the source map, the plan compiler, the budget, the Ledger lock scopes,
the collector and comparator the campaign runs, the cost model, the abort
closure, and the integrity binding of the worker that performs the HTTPS
exchange.

It authorizes nothing. The lane's compiled case set is used exactly as it is:
the plan compiler is the lane's, the collector is the lane's production entry
point, and the transport member below only adapts the core's one-argument wire
call to the lane's fixed-host worker. The projection of the 37 compiled slots
onto the shared Gate, with its Gate-native recovery ladder, lives in the lane
(`partition_cursor_gate.py`) and is bound here by digest.

The worker integrity binding is the lane's own wire module: a single reviewed
source file whose bytes the transport re-hashes before every spawn, so a
capability issued against other bytes cannot reach the wire through this path.
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
sys.path.insert(0, str(ROOT / "tools/compat-broad/fs-query-partition-cursor"))
sys.path.insert(0, str(HERE))

import partition_cursor_gate as gate_projection
import partition_cursor_wire as wire
from batch_contract import NUMBER, PROJECT
from broad_contract import digest
from o8_admission import authorize_transport
from o8_campaign import CAMPAIGN_APPROVAL_FIELDS, CampaignDescriptor
from partition_cursor_case import (
    CAMPAIGN,
    CURSOR_DOCUMENTS,
    OBSERVATION_COUNT,
    PARTITION_DOCUMENTS,
    RECOVERY_COUNT,
    compile_plan,
    validate_plan,
)
from partition_cursor_collector import collect_production
from partition_cursor_comparator import compare_evidence
from partition_cursor_shadow import SHADOW_RECORD


def _load(name: str, path: Path):
    """Load one reviewed module by exact path, without touching sys.path."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"reviewed module unavailable: {name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# The baseline derivation is the Commit lane's reviewed implementation, reused
# rather than reimplemented: it already refuses a literal, a replay journal and
# a recovery-phase line.
BASELINE_MODULE = "tools/compat-broad/fs-commit-transform-limits/commit_baseline.py"
commit_baseline = _load("_partition_cursor_commit_baseline", ROOT / BASELINE_MODULE)

DATABASE = "(default)"
_NONCE = re.compile(r"^[0-9a-f]{32}$")
OWNED_DOCUMENTS = PARTITION_DOCUMENTS + CURSOR_DOCUMENTS + 1
PLAN_SLOTS = OBSERVATION_COUNT + RECOVERY_COUNT
LADDER_SLOTS = gate_projection.LADDER_DOCUMENTS * gate_projection.LADDER_STEPS
RESIDUAL_SLOTS = gate_projection.RESIDUAL_SLOTS
DATA_REQUESTS = PLAN_SLOTS + LADDER_SLOTS + RESIDUAL_SLOTS
MANAGEMENT_REQUESTS = len(gate_projection.MANAGEMENT_OBSERVATION_IDS) + len(
    gate_projection.MANAGEMENT_RECOVERY_IDS
)
TOTAL_REQUESTS = DATA_REQUESTS + MANAGEMENT_REQUESTS
# The lane's planning ceiling, US$0.01. The Gate charges one micro-USD per
# request as its accounting unit; the ceiling is what the reservation charges
# against the shared envelope, and no tariff is confirmed below it.
COST_CEILING_MICROUSD = 10_000
CAMPAIGN_SECONDS = 840
RECOVERY_SECONDS = 520
MINIMUM_WINDOW_SECONDS = 1360
FROZEN_INPUTS_KIND = "o4-partition-cursor-frozen-inputs-v1"
PERMISSION_KIND = "o4-partition-cursor-owner-execution-permission-v1"
APPROVAL_KIND = "o4-partition-cursor-o8-approval-v1"
MANIFEST_KIND = "o4-partition-cursor-o8-manifest-v1"
RECEIPT_KIND = gate_projection.RECEIPT_KIND
PRINCIPAL_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
INDEX_FILE = "conformance/firestore.indexes.json"

LANE_DIRECTORY = "tools/compat-broad/fs-query-partition-cursor"
COLLECTOR_ENTRY = f"{LANE_DIRECTORY}/partition_cursor_collector.py"
COMPARATOR_ENTRY = f"{LANE_DIRECTORY}/partition_cursor_comparator.py"
WORKER_ENTRY = f"{LANE_DIRECTORY}/partition_cursor_wire.py"
GATE_ENTRY = f"{LANE_DIRECTORY}/partition_cursor_gate.py"
PREFLIGHT_ENTRY = f"{LANE_DIRECTORY}/partition_cursor_preflight.py"
ADMISSION_ENTRY = f"{LANE_DIRECTORY}/partition_cursor_admission.py"
PRODUCTION_ENTRY = f"{LANE_DIRECTORY}/partition_cursor_production.py"
LAUNCHER_ENTRY = f"{LANE_DIRECTORY}/partition_cursor_o8.py"
DESCRIPTOR_ENTRY = "tools/compat-broad/o8-core/o4_partition_cursor_descriptor.py"
# Every top-level module of the lane is swept, test modules included, so that a
# test edit is visible in the frozen digest rather than silently outside it.
SHARED_SOURCES = (
    BASELINE_MODULE,
    DESCRIPTOR_ENTRY,
    "tools/compat-broad/broad_contract.py",
    "tools/compat-broad/batch_contract.py",
    "tools/compat-broad/batch_adapter.py",
    "tools/compat-broad/batch_wire.py",
    "tools/compat-broad/shared_gate.py",
    "tools/compat-broad/production-admission/reservations.py",
    "tools/compat-broad/o8-core/o8_admission.py",
    "tools/compat-broad/o8-core/o8_campaign.py",
    "tools/compat-broad/fs-write-txn/credential_prep.py",
    "tools/compat-broad/fs-request-bytes-boundary/request_bytes_preflight.py",
)
# The closure a reservation records, so a later abort proves it runs the same
# sources the acquisition ran.
ABORT_CLOSURE_SOURCES = (
    "tools/compat-broad/shared_gate.py",
    "tools/compat-broad/production-admission/reservations.py",
    "tools/compat-broad/o8-core/o8_admission.py",
    ADMISSION_ENTRY,
    DESCRIPTOR_ENTRY,
    GATE_ENTRY,
    PRODUCTION_ENTRY,
)
BUDGET = {
    "requests": TOTAL_REQUESTS,
    # One authorized principal's quota is spent, as in the request-byte lane.
    "accounts": 1,
    "resources": OWNED_DOCUMENTS,
    "costMicrousd": COST_CEILING_MICROUSD,
}
FROZEN_BOUNDS = {
    "planSlots": PLAN_SLOTS,
    "observationSlots": OBSERVATION_COUNT,
    "recoverySlots": RECOVERY_COUNT,
    "ladderSlots": LADDER_SLOTS,
    "residualSlots": RESIDUAL_SLOTS,
    "dataRequests": DATA_REQUESTS,
    "managementRequests": MANAGEMENT_REQUESTS,
    "totalRequests": TOTAL_REQUESTS,
    # Every plan slot dispatched, every ladder delete skipped as already absent.
    "expectedWireRequests": PLAN_SLOTS
    + 2 * gate_projection.LADDER_DOCUMENTS
    + RESIDUAL_SLOTS
    + MANAGEMENT_REQUESTS,
    "distinctResources": OWNED_DOCUMENTS,
    "documentWrites": OWNED_DOCUMENTS,
    "documentDeletes": OWNED_DOCUMENTS,
    "perRequestTimeoutSeconds": wire.PRODUCTION_REQUEST_SECONDS,
    "maxResponseBytes": wire.MAX_RAW_BYTES,
    "concurrency": 1,
}


def shadow_record() -> dict:
    """The published local shadow this campaign's production run is compared to."""
    path = SHADOW_RECORD
    if path.is_symlink() or not path.is_file():
        raise ValueError("published local shadow record required")
    value = json.loads(path.read_bytes())
    artifact = value.get("artifact") if isinstance(value, dict) else None
    if (
        not isinstance(artifact, dict)
        or value.get("campaignId") != CAMPAIGN
        or not isinstance(artifact.get("sourceCommit"), str)
        or len(artifact["sourceCommit"]) != 40
        or not isinstance(artifact.get("sha256"), str)
    ):
        raise ValueError("published local shadow record required")
    return value


ARTIFACT_PROFILE_BASIS = {
    "kind": "partition-cursor-artifact-profile-v1",
    "registry": "none",
    "derivedFrom": "the published local shadow record's artifact.sourceCommit",
    "establishes": (
        "which build the comparison reference was produced by, and that the "
        "retained bytes hash to the digest the approval binds"
    ),
    "doesNotEstablish": (
        "that the build was reviewed; no profile registry entry exists for this "
        "lane and O7 must accept the profile explicitly"
    ),
    "ownerAcceptanceRequired": True,
}


def artifact_profile() -> str:
    """The build the comparison is bound to, named by the shadow's own Rust SHA."""
    return "partition-cursor-" + shadow_record()["artifact"]["sourceCommit"][:9]


def artifact_profile_basis() -> dict:
    return {
        **copy.deepcopy(ARTIFACT_PROFILE_BASIS),
        "profile": artifact_profile(),
        "sourceCommit": shadow_record()["artifact"]["sourceCommit"],
        "shadowArtifactSha256": shadow_record()["artifact"]["sha256"],
    }


def index_prerequisites() -> dict:
    """What the campaign needs of the production index configuration: nothing.

    Partition queries order by `__name__` only. Cursor cases use single-field
    orders at collection scope, which automatic single-field indexes cover. The
    ordering control is deliberately unindexed. The index file is digested so
    the preflight's database projection is compared against a named baseline
    rather than against whatever is deployed at run time.
    """
    path = ROOT / INDEX_FILE
    if path.is_symlink() or not path.is_file():
        raise ValueError("conformance index file required")
    return {
        "indexFile": INDEX_FILE,
        "indexFileSha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "requiredCompositeIndexes": [],
        "indexFileChangeRequired": False,
        "deliberatelyUnindexed": ["partition-order-non-name"],
        "baseline": "production index set as deployed on 2026-09-08",
    }


def cost_model() -> dict:
    """The lane's planning ceiling, not a quoted tariff."""
    return {
        "campaignId": CAMPAIGN,
        "totalCostMicrousd": COST_CEILING_MICROUSD,
        "gateAccountingMicrousd": TOTAL_REQUESTS
        * gate_projection.REQUEST_COST_MICROUSD,
        "requests": TOTAL_REQUESTS,
        "basis": (
            "planning ceiling from the lane manifest: at most 21 document "
            "creates, 21 deletes and a few hundred document reads; no tariff is "
            "confirmed"
        ),
    }


def budget() -> dict:
    return copy.deepcopy(BUDGET)


def ledger_budget() -> dict:
    return copy.deepcopy(BUDGET)


def plan_compiler(nonce: str) -> dict:
    """The lane's own compiled observation plan, bound to one fresh nonce."""
    if not isinstance(nonce, str) or _NONCE.fullmatch(nonce) is None:
        raise ValueError("fresh 32-hex nonce required")
    return compile_plan(PROJECT, DATABASE, nonce)


def execution_plan(plan: dict) -> dict:
    """The frozen plan, refused unless it is exactly what the compiler produces."""
    validate_plan(plan)
    if plan.get("project") != PROJECT or plan.get("database") != DATABASE:
        raise ValueError("fixed production project/database required")
    return copy.deepcopy(plan)


def lock_scopes(plan: dict) -> list[dict]:
    """Firestore document lock scopes for the nonce-unique owned namespace.

    The WRITE scope is the compiled owned scope itself, so the Ledger's own
    coverage check proves every assigned resource lies under it. The READ scopes
    name what the preflight observes and what the campaign must not see change.
    """
    scope = f"project/{PROJECT}"
    firestore = f"{scope}/firestore/{DATABASE}"
    nonce = plan["nonce"]
    owned = plan["ownedScope"].removeprefix(
        f"projects/{PROJECT}/databases/{DATABASE}/documents/"
    )
    if owned != f"oracle/{nonce}/o4-query-partition-cursor/root":
        raise ValueError("owned scope differs from the compiled case")
    return [
        {"key": f"{firestore}/documents/{owned}/*", "mode": "WRITE"},
        *[
            {"key": f"{firestore}/{kind}", "mode": "READ"}
            for kind in ("indexes", "ruleset", "database")
        ],
        {"key": f"{scope}/auth/config", "mode": "READ"},
        {"key": f"{scope}/api-key-binding", "mode": "READ"},
    ]


def lane_sources() -> tuple[str, ...]:
    """Every top-level module of the lane, in a stable order."""
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


def gate_plan(plan: dict, *, slot_seconds: float) -> dict:
    """Project the compiled campaign onto the shared Gate schema."""
    return gate_projection.gate_plan(
        execution_plan(plan),
        slot_seconds=slot_seconds,
        wall_seconds=CAMPAIGN_SECONDS,
        recovery_seconds=RECOVERY_SECONDS,
        cost_microusd=COST_CEILING_MICROUSD,
    )


def collector(plan, transmit, output):
    """The lane's production collector, fixed-host only."""
    return collect_production(plan, transmit, output)


def comparator(production, local, *, production_directory=None, local_directory=None):
    """The lane's retained-bundle comparator; semantic evidence only."""
    return compare_evidence(
        production,
        local,
        production_directory=production_directory,
        local_directory=local_directory,
    )


def verify_worker_binding(binding, binding_digest, frozen) -> None:
    """Check the reviewed worker bytes against the disk and the frozen map.

    The binding is the wire module source itself. It must hash to the digest
    the capability carries, that digest must be what the file on disk hashes to
    right now, since the worker is spawned from that path, and, when a frozen
    source map is supplied, it must equal the digest the O7 inputs froze.
    """
    if not isinstance(binding, bytes) or not binding:
        raise ValueError("reviewed worker source required")
    observed = hashlib.sha256(binding).hexdigest()
    on_disk = hashlib.sha256((ROOT / WORKER_ENTRY).read_bytes()).hexdigest()
    if observed != binding_digest or observed != on_disk:
        raise ValueError("worker source digest differs from the reviewed transport")
    if frozen is not None and frozen.get(WORKER_ENTRY) != observed:
        raise ValueError("worker source digest differs from the frozen inputs")


def worker_binding() -> tuple[bytes, str]:
    """Read the reviewed worker source and its digest from the lane."""
    source = (ROOT / WORKER_ENTRY).read_bytes()
    return source, hashlib.sha256(source).hexdigest()


def transport_bound(value, *, binding, binding_digest, capability=None):
    """Adapt one bound wire call to the lane's fixed-host worker.

    `value` carries the frozen request, the bearer token and an absolute
    deadline for exactly one request, or a closed management call. The binding
    is re-checked here as well as inside the core, so a capability issued
    against other bytes cannot reach the wire through this path.
    """
    if not isinstance(value, dict):
        raise ValueError("closed partition/cursor wire call required")  # noqa: TRY004 -- refusal class, not a type report
    if capability is None:
        raise ValueError("active O7 production capability required")
    if value.get("kind") == "management":
        if set(value) != {"kind", "phase", "slot", "token", "deadline"}:
            raise ValueError("closed management wire call required")
        if value["phase"] not in ("observation", "recovery"):
            raise ValueError("closed management phase required")
        if (
            type(value["deadline"]) not in (int, float)
            or isinstance(value["deadline"], bool)
            or not math.isfinite(value["deadline"])
        ):
            raise ValueError("finite management deadline required")
        authorize_transport(capability, binding=binding, binding_digest=binding_digest)
        verify_worker_binding(binding, binding_digest, None)
        import partition_cursor_preflight

        return partition_cursor_preflight.management_transport(
            value["slot"],
            value["token"],
            deadline=value["deadline"],
            capability=capability,
            binding=binding,
            binding_digest=binding_digest,
        )
    if set(value) != {"request", "token", "deadline"}:
        raise ValueError("closed partition/cursor wire call required")
    if (
        type(value["deadline"]) not in (int, float)
        or isinstance(value["deadline"], bool)
        or not math.isfinite(value["deadline"])
    ):
        raise ValueError("finite absolute deadline required")
    authorize_transport(capability, binding=binding, binding_digest=binding_digest)
    verify_worker_binding(binding, binding_digest, None)
    return wire.production_request(
        value["request"],
        value["token"],
        timeout=wire.PRODUCTION_REQUEST_SECONDS,
        deadline=value["deadline"],
    )


def retained_artifact_validator(artifact_path, manifest_path, profile):
    """Bind the retained artifact and manifest by digest.

    The profile is a label: the digests prove which bytes the owner retained,
    not that the build behind them was reviewed.
    """
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
    """Objects an injected preparation transport must not be able to reach."""
    return (wire, wire.production_request, wire.request, wire._spawn, transport_bound)


def gate_projection_summary(plan: dict) -> dict:
    """What the frozen Gate schedule adds to the 37 compiled slots, on the record."""
    return {
        "job": gate_projection.JOB,
        "contract": gate_projection.GATE_CONTRACT,
        "ownershipEvidence": gate_projection.OWNERSHIP_EVIDENCE,
        "planSlots": PLAN_SLOTS,
        "ladderSlots": LADDER_SLOTS,
        "residualSlots": RESIDUAL_SLOTS,
        "managementRequests": MANAGEMENT_REQUESTS,
        "totalRequests": TOTAL_REQUESTS,
        "creatingDeclarationGap": gate_projection.creating_declaration_gap(plan),
    }


def permission_bindings(
    plan, source_commit, artifact_digest, inputs, baseline=None
) -> dict:
    """Required non-authorizing fields an independently supplied permission carries.

    When a derived production baseline is supplied, the values the repository
    cannot recompute are required to equal what a named production observation
    produced. A literal that no recorded observation produces is refused here,
    offline, rather than after a run spends its budget discovering it.
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
        "gateProjectionSha256": inputs[GATE_ENTRY],
        "budget": budget(),
        "ledgerBudget": ledger_budget(),
        "ownedScope": plan["ownedScope"],
        "ownedResourceCount": len(plan["ownedResources"]),
        "wallSeconds": CAMPAIGN_SECONDS,
        "campaignSeconds": CAMPAIGN_SECONDS,
        "recoverySeconds": RECOVERY_SECONDS,
        "perRequestTimeoutSeconds": wire.PRODUCTION_REQUEST_SECONDS,
        "maxResponseBytes": wire.MAX_RAW_BYTES,
        "productionOrigin": wire.PRODUCTION_ORIGIN,
        "concurrency": 1,
        "tariffsConfirmedBelowPlanningCeilings": False,
        "costModel": cost_model(),
        "artifactProfileBasis": artifact_profile_basis(),
        "indexPrerequisites": index_prerequisites(),
        "gateProjection": gate_projection_summary(plan),
        "credentialPrincipalContract": {
            "alternatives": [
                ["clientId", "subject", "requiredScopes"],
                ["clientId", "verifiedEmail", "requiredScopes"],
            ],
            "requiredScopes": [PRINCIPAL_SCOPE],
            "identitySource": "owner-frozen permission; never inferred from tokeninfo",
        },
        "productionPreflight": {
            "version": "partition-cursor-preflight-v1",
            "managementRequests": MANAGEMENT_REQUESTS,
            "credentialIds": list(gate_projection.CREDENTIAL_IDS),
            "credentialSlots": list(gate_projection.CREDENTIAL_SLOTS),
            "source": PREFLIGHT_ENTRY,
        },
    }
    if baseline is not None:
        required.update(commit_baseline.permission_baseline(baseline))
        required["baselineProvenance"] = baseline["provenance"]
    return required


def descriptor() -> CampaignDescriptor:
    """The partition/cursor campaign as the shared admission core sees it."""
    if CAMPAIGN_SECONDS + RECOVERY_SECONDS < MINIMUM_WINDOW_SECONDS:
        raise ValueError("approved window below the campaign minimum")
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
            WORKER_ENTRY,
            GATE_ENTRY,
        ),
        frozen_bounds=copy.deepcopy(FROZEN_BOUNDS),
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
