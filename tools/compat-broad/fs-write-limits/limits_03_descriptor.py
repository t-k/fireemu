"""Campaign descriptor for FS-WRITE-LIMITS-03.

This module declares, in one hard-coded place, every binding the shared O8
admission core checks for the campaign: the schema kinds, the window, the
source map, the plan compiler, the budget, the Ledger lock scopes, the
collector and comparator the campaign runs, the cost model, the abort closure,
the integrity binding of the worker that performs the HTTPS exchange, and the
index-configuration precondition the campaign cannot run without.

It authorizes nothing. The reviewed limits-03 compiler, collector and
comparator are used exactly as they are; the figures published here are read
from the compiler rather than typed in, so a change to the plan moves them.

The index exemption is the one precondition that is a shared configuration
change. It is declared as its own locked step: the descriptor names the before
and after digests of `conformance/firestore.indexes.json`, the exact deploy and
restore commands, and the field readback the preflight must see. The permission
carries the same declaration, and the launcher refuses to start unless the
preflight readback matches the after state.
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

import compiler_03
import limits_03_preflight as preflight
import limits_03_remote_transport as remote
from broad_contract import digest
from collector_03 import collect
from comparator_03 import compare_rows
from compiler_03 import (
    CAMPAIGN,
    EXEMPT_COLLECTION,
    MANAGEMENT_OBSERVATION_IDS,
    MANAGEMENT_RECOVERY_IDS,
    MANAGEMENT_REQUEST_COST_MICROUSD,
    compile_limits_plan,
    management_contract,
)
from o8_admission import authorize_transport
from o8_campaign import CAMPAIGN_APPROVAL_FIELDS, CampaignDescriptor

PROJECT = "fireemu-35fe6"
NUMBER = "592603257417"
DATABASE = "(default)"
FROZEN_INPUTS_KIND = "limits-03-frozen-inputs-v1"
PERMISSION_KIND = "limits-03-owner-execution-permission-v1"
APPROVAL_KIND = "limits-03-o8-approval-v1"
MANIFEST_KIND = "limits-03-o8-manifest-v1"
RECEIPT_KIND = "limits-03-acquisition-receipt-v1"
PRINCIPAL_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
SHADOW_RECORD = "spec/compatibility/broad-runs/fs-write-limits-03-local-shadow.json"
MANIFEST_RECORD = "spec/compatibility/broad-runs/fs-write-limits-03.json"
INDEXES_FILE = "conformance/firestore.indexes.json"
RESTORE_RECORD = "spec/compatibility/broad-runs/fs-write-limits-03-index-restore.json"
RESTORE_RECORD_KIND = "limits-03-index-exemption-restore-v1"
# Owner planning figures the compiler does not decide: the fixed reserve the
# envelope carries above the per-request tariff, and the cap the whole run must
# stay under. Both are ceilings, never quoted tariffs.
FIXED_COST_MICROUSD = 40_000
COST_CAP_USD = 1.0
PLANNING_COST_USD = 0.02
REQUEST_COST_MICROUSD = 100
LIFECYCLE_CONTRACT = {
    "kind": "limits-03-index-lifecycle-production-v1",
    "project": PROJECT,
    "database": DATABASE,
    "fieldName": "projects/fireemu-35fe6/databases/(default)/collectionGroups/nx/fields/*",
    "pollLimit": 1,
    "observationSlots": 4,
    "recoverySlots": 3,
    "updateMask": "indexConfig",
    "operationDeadlineSeconds": 12.0,
    "recoveryDeadlineSeconds": 12.0,
}


def lifecycle_contract() -> dict:
    return copy.deepcopy(LIFECYCLE_CONTRACT)

LANE_DIRECTORY = "tools/compat-broad/fs-write-limits"
COLLECTOR_ENTRY = f"{LANE_DIRECTORY}/collector_03.py"
COMPARATOR_ENTRY = f"{LANE_DIRECTORY}/comparator_03.py"
COMPILER_ENTRY = f"{LANE_DIRECTORY}/compiler_03.py"
WORKER_ENTRY = remote.WORKER_ENTRY
PREFLIGHT_ENTRY = f"{LANE_DIRECTORY}/limits_03_preflight.py"
TRANSPORT_ENTRY = f"{LANE_DIRECTORY}/limits_03_remote_transport.py"
# Every module of the lane is swept, the limits-02 modules and the tests
# included, so that an edit anywhere in the directory is visible in the frozen
# digest rather than silently outside it.
SHARED_SOURCES = (
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
    "tools/compat-broad/fs-request-bytes-boundary/request_bytes_process_exchange.py",
    "spec/limits/firestore-standard-2026-08-25.json",
)
ABORT_CLOSURE_SOURCES = (
    "tools/compat-broad/shared_gate.py",
    "tools/compat-broad/production-admission/reservations.py",
    "tools/compat-broad/o8-core/o8_admission.py",
    f"{LANE_DIRECTORY}/limits_03_admission.py",
    f"{LANE_DIRECTORY}/limits_03_descriptor.py",
)
# The nonce the figures are read at. Every compiled figure is independent of
# the nonce, which has a fixed length, and a test pins that.
FIGURE_NONCE = "0" * 32
GATE_JOB = "limits"


def _published(relative: str, kind_key: str, expected: str) -> dict:
    path = ROOT / relative
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"published record required: {relative}")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict) or value.get(kind_key) != expected:
        raise ValueError(f"published record required: {relative}")
    return value


def shadow_record() -> dict:
    """The published local shadow this campaign's production run is compared to."""
    value = _published(SHADOW_RECORD, "campaignId", CAMPAIGN)
    commit = value.get("sourceCommit")
    if not isinstance(commit, str) or len(commit) != 40:
        raise ValueError("published local shadow record required")
    return value


ARTIFACT_PROFILE_BASIS = {
    "kind": "limits-03-artifact-profile-v1",
    "registry": "none",
    "derivedFrom": "the published local shadow record's sourceCommit",
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
    return "limits-03-" + shadow_record()["sourceCommit"][:9]


def artifact_profile_basis() -> dict:
    record = shadow_record()
    return {
        **copy.deepcopy(ARTIFACT_PROFILE_BASIS),
        "profile": artifact_profile(),
        "sourceCommit": record["sourceCommit"],
        "shadowArtifactSha256": record["execution"]["ALL"]["artifact"]["sha256"],
    }


_FIGURES: dict | None = None


def figure_plan() -> dict:
    """The compiled plan the published figures are read from."""
    return compile_limits_plan(PROJECT, DATABASE, FIGURE_NONCE)


def budget_figures() -> dict:
    """Every published budget figure, computed from the compiler.

    The envelope charges every request, data and management alike, at the
    per-request tariff on top of the fixed reserve. `dataCostMicrousd` is the
    data breakdown of that same charge, not an additional term.
    """
    global _FIGURES
    if _FIGURES is None:
        plan = figure_plan()
        accounting, gate = plan["budgetAccounting"], plan["localGatePlan"]
        management = management_contract()["totalRequests"]
        requests = accounting["requestUpperBound"] + management
        _FIGURES = {
            "campaignId": CAMPAIGN,
            "part": "ALL",
            "observationRequests": accounting["observationRequests"],
            "recoveryRequests": accounting["recoveryRequests"],
            "managementObservationRequests": len(MANAGEMENT_OBSERVATION_IDS),
            "managementRecoveryRequests": len(MANAGEMENT_RECOVERY_IDS),
            "requestUpperBound": requests,
            "dataRequests": accounting["requestUpperBound"],
            "maxOwnedDocuments": accounting["ownedDocuments"],
            "maxProbedNames": accounting["probedNames"],
            "maxConcurrency": 1,
            "maxRequestBodyBytes": accounting["requestBodyUpperBoundBytes"],
            "maxResponseBytes": accounting["responseUpperBoundBytes"],
            "maxWallSeconds": gate["wallSeconds"],
            "recoveryReserveSeconds": gate["recoverySeconds"],
            "managementSeconds": management_contract()["phaseSeconds"],
            "requestCostMicrousd": REQUEST_COST_MICROUSD,
            "fixedCostMicrousd": FIXED_COST_MICROUSD,
            "dataCostMicrousd": accounting["requestUpperBound"] * REQUEST_COST_MICROUSD,
            "envelopeCostMicrousd": FIXED_COST_MICROUSD
            + requests * REQUEST_COST_MICROUSD,
            "dataCostIsIncludedInEnvelope": True,
            "costCapUsd": COST_CAP_USD,
            "planningCostUsd": PLANNING_COST_USD,
            "tariffsConfirmed": False,
        }
        if _FIGURES["envelopeCostMicrousd"] >= COST_CAP_USD * 1_000_000:
            raise ValueError("the envelope does not fit under the cost cap")
        if gate["costMicrousd"] != requests * REQUEST_COST_MICROUSD:
            raise ValueError("the Gate allocation and the envelope disagree")
        if MANAGEMENT_REQUEST_COST_MICROUSD != REQUEST_COST_MICROUSD:
            raise ValueError("management requests are charged at the data tariff")
    return copy.deepcopy(_FIGURES)


def campaign_seconds() -> int:
    return int(budget_figures()["maxWallSeconds"])


def recovery_seconds() -> int:
    return int(budget_figures()["recoveryReserveSeconds"])


def transport_deadline_seconds() -> float:
    """The per-request wire ceiling, from the compiler and checked in the transport."""
    if remote.TIMEOUT != compiler_03.TRANSPORT_CEILING_SECONDS:
        raise ValueError("transport ceiling differs from the compiled reservation")
    return float(compiler_03.TRANSPORT_CEILING_SECONDS)


def budget() -> dict:
    return budget_figures()


def ledger_budget() -> dict:
    """The four Ledger dimensions, with recovery and management inside every one."""
    figures = budget_figures()
    return {
        "requests": figures["requestUpperBound"],
        "accounts": 1,
        "resources": figures["maxOwnedDocuments"],
        "costMicrousd": figures["envelopeCostMicrousd"],
    }


def frozen_bounds() -> dict:
    plan = figure_plan()
    figures = budget_figures()
    requests = plan["requests"]
    bodies = [row for row in requests if row["body"] is not None]
    return {
        "dataRequests": figures["dataRequests"],
        "managementRequests": figures["managementObservationRequests"]
        + figures["managementRecoveryRequests"],
        "observationRequests": figures["observationRequests"],
        "recoveryRequests": figures["recoveryRequests"],
        "documentWrites": len(bodies),
        "documentReads": sum(1 for row in requests if row["method"] == "GET"),
        "documentDeletes": sum(1 for row in requests if row["method"] == "DELETE"),
        "uploadedBytes": sum(len(json.dumps(row["body"]).encode()) for row in bodies),
        "expectedCreates": figures["maxOwnedDocuments"],
        "expectedDeletes": figures["maxOwnedDocuments"],
        "totalRequests": figures["requestUpperBound"],
        "distinctResources": figures["maxOwnedDocuments"],
        "peakLiveDocuments": figures["maxOwnedDocuments"],
        "maxRequestBytes": figures["maxRequestBodyBytes"],
        "maxResponseBytes": figures["maxResponseBytes"],
        "perRequestTimeoutSeconds": transport_deadline_seconds(),
        "smallRequestSeconds": compiler_03.SMALL_REQUEST_SECONDS,
        "readbackSeconds": compiler_03.READBACK_SECONDS,
    }


def cost_model() -> dict:
    figures = budget_figures()
    return {
        "campaignId": CAMPAIGN,
        "estimatedCostMicrousd": int(PLANNING_COST_USD * 1_000_000),
        "maximumCostMicrousd": figures["envelopeCostMicrousd"],
        "fixedReserveMicrousd": FIXED_COST_MICROUSD,
        "hardCeilingMicrousd": int(COST_CAP_USD * 1_000_000),
        "requestCostMicrousd": REQUEST_COST_MICROUSD,
        "totalCostMicrousd": ledger_budget()["costMicrousd"],
        "requests": figures["requestUpperBound"],
        "basis": (
            "one planning tariff per request, data and management alike, on top "
            "of a fixed reserve; ceilings for admission, never quoted tariffs"
        ),
    }


# The index configuration the campaign was prepared against, and the same file
# with the declared exemption appended. Both are pinned rather than read, so a
# checkout that already carries the deployed after state names the same step.
INDEXES_SHA256_BEFORE = (
    "62d5387f860555c8a966d115ea95c2619c907c498b75e4c2e7a465503b452ec7"
)
INDEXES_SHA256_AFTER = (
    "1e645c04419ac8418e9d05ebceb7a11d641f7127260de5cd1f307570cc93f332"
)


def indexes_digest() -> str:
    return hashlib.sha256((ROOT / INDEXES_FILE).read_bytes()).hexdigest()


def indexes_after_bytes() -> bytes:
    """The index configuration with the declared exemption appended.

    Serialized the way `firebase deploy` reads it and the package declares it:
    two-space indent and a trailing newline. Refused unless the file on disk is
    the declared before state, so the exemption is never appended twice.
    """
    raw = (ROOT / INDEXES_FILE).read_bytes()
    if hashlib.sha256(raw).hexdigest() != INDEXES_SHA256_BEFORE:
        raise ValueError("index configuration is not in the declared before state")
    value = json.loads(raw)
    value.setdefault("fieldOverrides", []).append(index_exemption_override())
    content = (json.dumps(value, indent=2) + "\n").encode()
    if hashlib.sha256(content).hexdigest() != INDEXES_SHA256_AFTER:
        raise ValueError("computed after state differs from the declared digest")
    return content


def index_exemption_override() -> dict:
    return {"collectionGroup": EXEMPT_COLLECTION, "fieldPath": "*", "indexes": []}


def index_exemption_precondition() -> dict:
    """The one shared configuration change, as its own locked step.

    Deployed by the commander before admission and restored after the run. The
    launcher's preflight and postflight both read the exempt group's field
    configuration and compare its projection to the after state; the receipt
    records that the restore is still owed.
    """
    before, after = INDEXES_SHA256_BEFORE, INDEXES_SHA256_AFTER
    return {
        "kind": "limits-03-index-exemption-precondition-v1",
        "step": "deploy-single-field-exemption",
        "file": INDEXES_FILE,
        "override": index_exemption_override(),
        "conformanceIndexesSha256Before": before,
        "conformanceIndexesSha256After": after,
        "lockScope": {
            "key": f"project/{PROJECT}/firestore/{DATABASE}/indexes",
            "mode": "WRITE",
        },
        "readback": {
            "route": preflight.INDEX_FIELD_ROUTE,
            "projection": preflight.EXPECTED_INDEX_EXEMPTION_PROJECTION,
            "projectionDigest": preflight.expected_index_exemption_digest(),
            "slots": ["observation:index-exemption", "recovery:index-exemption"],
        },
        "deploy": [
            "uv run --project tools/compat-inventory --locked --python 3.12 python "
            f"{LANE_DIRECTORY}/limits_03_indexes.py --write-after {INDEXES_FILE}",
            "uv run --project tools/compat-inventory --locked --python 3.12 python "
            f"{LANE_DIRECTORY}/limits_03_indexes.py --verify after  # {after}",
            "cd conformance && firebase deploy --only firestore:indexes "
            f"--project {PROJECT} --non-interactive",
            f"gcloud firestore operations list --project {PROJECT} --format=json"
            "  # wait until no operation on the field is pending",
            f"curl -sS -H 'Authorization: Bearer $(gcloud auth print-access-token)' "
            f"-H 'x-goog-user-project: {PROJECT}' '{preflight.INDEX_FIELD_ROUTE}'"
            " > <private>/nx-field-deployed.json",
            "uv run --project tools/compat-inventory --locked --python 3.12 python "
            f"{LANE_DIRECTORY}/limits_03_indexes.py --verify-deployed "
            "<private>/nx-field-deployed.json  # exit 0 before admission",
            f"git checkout -- {INDEXES_FILE}  # the after state is the deploy input, "
            "never committed; the tree must be clean for freeze and provenance",
            "uv run --project tools/compat-inventory --locked --python 3.12 python "
            f"{LANE_DIRECTORY}/limits_03_indexes.py --verify before  # {before}",
        ],
        "restore": [
            "uv run --project tools/compat-inventory --locked --python 3.12 python "
            f"{LANE_DIRECTORY}/limits_03_indexes.py --verify before  # {before}",
            f"gcloud firestore indexes composite list --project {PROJECT} "
            "--format=json  # every listed index must be in the file: a forced "
            "deploy removes what the file does not list",
            "cd conformance && firebase deploy --only firestore:indexes "
            f"--project {PROJECT} --non-interactive --force",
            f"gcloud firestore operations list --project {PROJECT} --format=json"
            "  # wait until no operation on the field is pending",
            f"curl -sS -H 'Authorization: Bearer $(gcloud auth print-access-token)' "
            f"-H 'x-goog-user-project: {PROJECT}' '{preflight.INDEX_FIELD_ROUTE}'"
            " > <private>/nx-field-restored.json",
            "uv run --project tools/compat-inventory --locked --python 3.12 python "
            f"{LANE_DIRECTORY}/limits_03_indexes.py --verify-restored "
            "<private>/nx-field-restored.json --receipt <private>/receipt.json "
            f"--record {RESTORE_RECORD}",
            "uv run --project tools/compat-inventory --locked --python 3.12 python "
            f"{LANE_DIRECTORY}/package_03.py freeze --keep-shadow-record "
            f"--restore-record {RESTORE_RECORD} "
            "--production-receipt <private>/receipt.json",
        ],
        "restoreNote": (
            "Without --force the deploy never removes an exemption the file no "
            "longer lists, so the restore must pass --force; --force also removes "
            "every composite index and override the file does not list, so the "
            "listing must be checked against the file first. The restore is "
            "verified by the field readback, not by the deploy's exit status, and "
            "bound to the production receipt.json of the run it restores -- a "
            "record cannot be produced before that run's postflight confirmed "
            "the exemption was in force, and the campaign does not close until "
            "the record is bound here."
        ),
        "restoreEvidence": {
            "recordKind": RESTORE_RECORD_KIND,
            "record": RESTORE_RECORD,
            "expectedProjection": preflight.EXPECTED_INDEX_RESTORED_PROJECTION,
            "expectedProjectionDigest": preflight.expected_index_restored_digest(),
        },
        "restoreRequiredAfterRun": True,
    }


def compile_execution_plan(nonce: str) -> tuple[dict, str]:
    plan = remote.compiled_plan(nonce)
    return plan, digest(plan)


def plan_compiler(nonce: str) -> dict:
    """The plan as the admission sees it: a reference, not the request bodies."""
    plan, plan_digest = compile_execution_plan(nonce)
    return {
        "campaignId": plan["campaignId"],
        "part": plan["part"],
        "catalogSha256": digest(plan["catalog"]),
        "project": PROJECT,
        "database": DATABASE,
        "nonce": nonce,
        "planDigest": plan_digest,
        "ownedScope": f"projects/{PROJECT}/databases/{DATABASE}/documents/oracle/{nonce}/limits-03",
        "ownedResourceCount": plan["budgetAccounting"]["ownedDocuments"],
        "requestUpperBound": plan["budgetAccounting"]["requestUpperBound"],
        "gatePlanDigest": digest(plan["localGatePlan"]),
        "bounds": frozen_bounds(),
    }


def execution_plan(reference: dict) -> dict:
    """Recompile the plan a frozen reference names, and refuse any other."""
    nonce = reference.get("nonce") if isinstance(reference, dict) else None
    if not isinstance(nonce, str) or not compiler_03._NONCE.fullmatch(nonce):
        raise ValueError("frozen limits-03 plan reference required")
    canonical = plan_compiler(nonce)
    plan, plan_digest = compile_execution_plan(nonce)
    if digest(reference) != digest(canonical) or reference["planDigest"] != plan_digest:
        raise ValueError("frozen limits-03 plan reference differs")
    return plan


def lock_scopes(plan: dict) -> list[dict]:
    """The owned namespace, the read scopes, and the index configuration.

    The index scope is taken in WRITE mode although the run never writes it: the
    configuration is in a declared non-baseline state for the whole run, and
    the Ledger then refuses to admit this campaign beside any other that reads
    the index configuration, which is the serialization the exemption needs.
    """
    nonce = plan["nonce"]
    scope = f"project/{PROJECT}"
    firestore = f"{scope}/firestore/{DATABASE}"
    return [
        {"key": f"{firestore}/documents/oracle/{nonce}/limits-03/*", "mode": "WRITE"},
        {"key": f"{scope}/identity", "mode": "READ"},
        index_exemption_precondition()["lockScope"],
        {"key": f"{firestore}/ruleset", "mode": "READ"},
        {"key": f"{firestore}/database", "mode": "READ"},
        {"key": f"{scope}/auth/config", "mode": "READ"},
    ]


def lane_sources() -> tuple[str, ...]:
    directory = ROOT / LANE_DIRECTORY
    return tuple(
        sorted(f"{LANE_DIRECTORY}/{path.name}" for path in directory.glob("*.py"))
    )


def source_map() -> dict[str, str]:
    values = {}
    for name in (*lane_sources(), *SHARED_SOURCES):
        path = ROOT / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("frozen campaign source missing")
        values[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return values


def gate_plan(plan: dict, *, permission_expires_at=None) -> dict:
    """Project the compiled campaign onto the shared Gate schema for production.

    The local plan is the compiler's; production adds the closed management
    contract, the campaign identity and the receipt kind, and counts the
    management observation slots in the observation allowance the Gate checks.
    """
    local = copy.deepcopy(plan["localGatePlan"])
    contract = management_contract()
    value = {
        **local,
        "campaignId": CAMPAIGN,
        "jobSlots": 1,
        # The compiled documents name themselves in `_sharedOwner`, which is
        # the shared-local-v2 convention, so no marker override is declared.
        "observationRequests": local["observationRequests"]
        + len(contract["observation"]),
        "dataRequests": plan["budgetAccounting"]["requestUpperBound"],
        "managementRequests": contract["totalRequests"],
        "receiptKind": RECEIPT_KIND,
        "management": {
            **contract,
            "observationWindowSeconds": local["wallSeconds"] - local["recoverySeconds"],
            "recoveryWindowSeconds": local["recoverySeconds"],
            "principalBinding": {
                "required": ["clientId", "subject", "requiredScopes"],
                "claims": ["issued_to", "audience", "user_id", "scope", "expires_in"],
            },
            "permissionExpiryBound": True,
        },
        "transport": "fixed-production-wire",
    }
    if permission_expires_at is not None:
        value["permissionExpiresAt"] = permission_expires_at
    return value


def collector(gate, plan, output, *, transmit):
    return collect(gate, plan, output, transmit)


def comparator(result, shadow=None):
    """Compare a production journal with a local shadow journal, row by row.

    The published shadow record carries no journal: the executed nonce and the
    owned resource names stay in the private output directory. So the
    comparison takes that directory's `result.json`, checks that it is the run
    the published record describes, and hands both journals to the reviewed
    comparator. This establishes agreement, never a compatibility claim.
    """
    if not isinstance(shadow, dict) or not isinstance(shadow.get("rows"), list):
        raise ValueError("private local shadow result with its journal required")
    published = shadow_record()
    manifest = shadow.get("manifest") or {}
    nonce = manifest.get("nonce")
    if (
        shadow.get("campaignId") != CAMPAIGN
        or shadow.get("productionExecuted") is not False
        or not isinstance(nonce, str)
        or compiler_03._NONCE.fullmatch(nonce) is None
        or manifest.get("sourceInputs") != published.get("campaignSources")
    ):
        raise ValueError("local shadow result does not match the published record")
    left_plan = execution_plan(result["planReference"])
    right_plan = compile_limits_plan(shadow["project"], DATABASE, nonce)
    if digest(right_plan) != shadow.get("planDigest"):
        raise ValueError("local shadow plan digest differs")
    comparison = compare_rows(left_plan, result["rows"], right_plan, shadow["rows"])
    return {
        "campaignId": CAMPAIGN,
        "comparison": comparison,
        "shadowRecordDigest": digest(published),
        "shadowResultDigest": digest(shadow),
        "formalCompatibilityClaim": False,
    }


def verify_worker_binding(binding, binding_digest, frozen) -> None:
    if not isinstance(binding, bytes) or not binding:
        raise ValueError("reviewed worker source required")
    observed = hashlib.sha256(binding).hexdigest()
    if observed != binding_digest or observed != remote._WORKER_SHA256:
        raise ValueError("worker source digest differs from the reviewed transport")
    if frozen is not None and frozen.get(WORKER_ENTRY) != observed:
        raise ValueError("worker source digest differs from the frozen inputs")


def worker_binding() -> tuple[bytes, str]:
    source = (ROOT / WORKER_ENTRY).read_bytes()
    return source, hashlib.sha256(source).hexdigest()


def transport_bound(value, *, binding, binding_digest, capability=None):
    """Adapt one bound wire call to the reviewed transport's own signature."""
    if not isinstance(value, dict):
        raise ValueError("closed limits-03 wire call required")
    if capability is None:
        raise ValueError("active O7 production capability required")
    authorize_transport(capability, binding=binding, binding_digest=binding_digest)
    verify_worker_binding(binding, binding_digest, None)
    if value.get("kind") == "management":
        allowed = {"kind", "phase", "slot", "token", "deadline"}
        if value.get("slot") in preflight.LIFECYCLE_SLOTS:
            allowed.add("operation")
        if set(value) != allowed:
            raise ValueError("closed management wire call required")
        if value["phase"] not in ("observation", "recovery"):
            raise ValueError("closed management phase required")
        return preflight.management_transport(
            value["slot"],
            value["token"],
            deadline=value["deadline"],
            capability=capability,
            binding=binding,
            binding_digest=binding_digest,
            operation=value.get("operation"),
        )
    if set(value) != {"plan", "phase", "index", "operation", "token", "deadline"}:
        raise ValueError("closed limits-03 wire call required")
    return remote.request(
        value["plan"],
        value["phase"],
        value["index"],
        value["operation"],
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
    return (remote, remote.request, remote.prepare, transport_bound)


def permission_bindings(plan, source_commit, artifact_digest, inputs, baseline=None):
    """Required non-authorizing fields for an independently supplied permission."""
    canonical = plan_compiler(plan["nonce"])
    if digest(plan) != digest(canonical):
        raise ValueError("fixed production project/database required")
    figures = budget_figures()
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
        "compilerSha256": inputs[COMPILER_ENTRY],
        "workerSha256": inputs[WORKER_ENTRY],
        "budget": budget(),
        "ledgerBudget": ledger_budget(),
        "ownedScope": plan["ownedScope"],
        "ownedResourceCount": plan["ownedResourceCount"],
        "wallSeconds": campaign_seconds(),
        "campaignSeconds": campaign_seconds(),
        "recoverySeconds": recovery_seconds(),
        "perRequestTimeoutSeconds": transport_deadline_seconds(),
        "maxRequestBytes": figures["maxRequestBodyBytes"],
        "maxResponseBytes": figures["maxResponseBytes"],
        "concurrency": 1,
        "tariffsConfirmedBelowPlanningCeilings": True,
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
        "managementContract": management_contract(),
        "productionPreflight": {
            "version": "limits-03-preflight-v1",
            "managementRequests": management_contract()["totalRequests"],
            "credentialIds": ["oauth-tokeninfo"],
            "credentialSlots": ["tokeninfo"],
            "source": PREFLIGHT_ENTRY,
        },
        "indexExemptionPrecondition": index_exemption_precondition(),
        "indexExemptionProjectionDigest": preflight.expected_index_exemption_digest(),
        "indexLifecycleContract": lifecycle_contract(),
    }


def descriptor_members() -> dict:
    """Every member the descriptor is built from, so a test can drop each one."""
    if campaign_seconds() > compiler_03.GATE_WALL_SECONDS_MAX:
        raise ValueError("campaign wall above the Gate ceiling")
    return {
        "campaign_id": CAMPAIGN,
        "frozen_inputs_kind": FROZEN_INPUTS_KIND,
        "permission_kind": PERMISSION_KIND,
        "approval_kind": APPROVAL_KIND,
        "manifest_kind": MANIFEST_KIND,
        "approval_fields": CAMPAIGN_APPROVAL_FIELDS,
        "artifact_profile": artifact_profile(),
        "campaign_seconds": campaign_seconds(),
        "recovery_seconds": recovery_seconds(),
        "source_map": source_map,
        "abort_closure_sources": ABORT_CLOSURE_SOURCES,
        "required_source_entries": (
            COLLECTOR_ENTRY,
            COMPARATOR_ENTRY,
            COMPILER_ENTRY,
            WORKER_ENTRY,
        ),
        "frozen_bounds": frozen_bounds(),
        "budget": budget(),
        "plan_compiler": plan_compiler,
        "lock_scopes": lock_scopes,
        "collector": collector,
        "comparator": comparator,
        "cost_model": cost_model,
        "permission_bindings": permission_bindings,
        "transport_bound": transport_bound,
        "binding_verifier": verify_worker_binding,
        "retained_artifact_validator": retained_artifact_validator,
        "forbidden_transports": forbidden_transports,
    }


def descriptor() -> CampaignDescriptor:
    """The limits-03 campaign as the shared admission core sees it."""
    return CampaignDescriptor(**descriptor_members())
