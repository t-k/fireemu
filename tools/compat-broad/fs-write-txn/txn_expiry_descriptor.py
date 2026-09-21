"""Campaign descriptor for `FS-TRANSACTION-EXPIRY-RETRY-04`.

This module declares, in one hard-coded place, every binding the shared O8
admission core checks for the transaction expiry, finished-token and retry-token
campaign: the schema kinds, the window, the source map, the plan compiler, the
budget, the Ledger lock scopes, the projection of the compiled plan onto the
shared Gate, the collector and comparator the campaign runs, the cost model, the
abort closure and the integrity binding of the HTTPS worker.

It authorizes nothing and changes none of the reviewed lane modules: the case
table, the plan compiler, the collector and the comparator are used exactly as
they are. The two things that make this campaign different from the request-byte
one are stated here rather than assumed:

- Timing is wall-clock only. The rehearsal reaches the idle limit by advancing
  the emulator's virtual clock; production has no such control and waits real
  seconds. The collector member refuses a clock advance callable outright and
  admits a shortened sleeper only for an injected local transport, never for the
  capability-bound production wire.
- The frozen plan carries `$binding:` placeholders where a request carries a
  transaction token or an observed update time, because neither exists before
  the run. The campaign's own Gate facade resolves them from journaled answers.
"""

from __future__ import annotations

import base64
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

import txn_expiry_cases as cases
import txn_expiry_collector as collector
import txn_expiry_comparison as comparison
import txn_expiry_gate as gate_module
import txn_expiry_plan as plan_module
import txn_expiry_preflight as preflight
import txn_expiry_remote_transport as remote
from batch_contract import NUMBER, PROJECT
from broad_contract import digest
from o8_admission import authorize_transport
from o8_campaign import CAMPAIGN_APPROVAL_FIELDS, CampaignDescriptor


def _load(name: str, path: Path):
    """Load one reviewed module by exact path, without touching sys.path."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"reviewed module unavailable: {name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# The baseline derivation and provenance check are the Commit lane's reviewed
# implementation, reused rather than reimplemented.
BASELINE_MODULE = "tools/compat-broad/fs-commit-transform-limits/commit_baseline.py"
commit_baseline = _load("_txn_expiry_commit_baseline", ROOT / BASELINE_MODULE)

CAMPAIGN = cases.CAMPAIGN
DATABASE = plan_module.DATABASE
JOB = gate_module.JOB
_NONCE = re.compile(r"^[0-9a-f]{32}$")
FROZEN_INPUTS_KIND = "txn-expiry-frozen-inputs-v1"
PERMISSION_KIND = "txn-expiry-owner-execution-permission-v1"
APPROVAL_KIND = "txn-expiry-o8-approval-v1"
MANIFEST_KIND = "txn-expiry-o8-manifest-v1"
RECEIPT_KIND = "txn-expiry-acquisition-receipt-v1"
HANDOFF_KIND = "txn-expiry-bearer-token-v1"
SHADOW_RECORD = (
    "spec/compatibility/broad-runs/fs-transaction-expiry-retry-04-local-shadow-v3.json"
)
PRINCIPAL_SCOPE = preflight.SCOPE

LANE_DIRECTORY = "tools/compat-broad/fs-write-txn"
COLLECTOR_ENTRY = f"{LANE_DIRECTORY}/txn_expiry_collector.py"
COMPARATOR_ENTRY = f"{LANE_DIRECTORY}/txn_expiry_comparison.py"
WORKER_ENTRY = remote.WORKER_ENTRY
GATE_ENTRY = f"{LANE_DIRECTORY}/txn_expiry_gate.py"
TRANSPORT_ENTRY = f"{LANE_DIRECTORY}/txn_expiry_remote_transport.py"
PREFLIGHT_ENTRY = f"{LANE_DIRECTORY}/txn_expiry_preflight.py"
# Every top-level module of the lane is swept, test modules included, so that a
# test edit is visible in the frozen digest rather than silently outside it.
SHARED_SOURCES = (
    BASELINE_MODULE,
    "tools/compat-broad/broad_contract.py",
    "tools/compat-broad/batch_contract.py",
    "tools/compat-broad/batch_adapter.py",
    "tools/compat-broad/batch_wire.py",
    "tools/compat-broad/shared_gate.py",
    "tools/compat-broad/production-admission/reservations.py",
    "tools/compat-broad/o8-core/o8_admission.py",
    "tools/compat-broad/o8-core/o8_campaign.py",
    "tools/compat-broad/fs-request-bytes-boundary/request_bytes_preflight.py",
    "tools/compat-broad/fs-request-bytes-boundary/request_bytes_process_exchange.py",
)
# The closure a reservation records, so a later abort proves it runs the same
# sources the acquisition ran.
ABORT_CLOSURE_SOURCES = (
    "tools/compat-broad/shared_gate.py",
    "tools/compat-broad/production-admission/reservations.py",
    "tools/compat-broad/o8-core/o8_admission.py",
    f"{LANE_DIRECTORY}/txn_expiry_admission.py",
    f"{LANE_DIRECTORY}/txn_expiry_descriptor.py",
    f"{LANE_DIRECTORY}/txn_expiry_gate.py",
)

# -- time -------------------------------------------------------------------
#
# The shared Gate caps one run at 1200 seconds, recovery included. The plan's
# own observation envelope is 1200 seconds and its recovery window 180, so the
# owner window the descriptor asks for is 1380 seconds: the Gate wall plus the
# recovery the collector may still be spending when the Gate wall ends. Inside
# the Gate the recovery reserve is 240 seconds, which covers 29 recovery slots
# at six seconds plus the three postflight management slots; the observation
# window that leaves is 960 seconds against 732.5 seconds of reserved slots.
GATE_WALL_SECONDS = plan_module.WALL_SECONDS
GATE_RECOVERY_SECONDS = 240
GATE_INTERVAL_SECONDS = 0.25
RECOVERY_SLOT_SECONDS = 6.0
#: The collector's own observation deadline, started after the four preflight
#: management slots: the Gate observation window less their worst case.
MANAGEMENT_PREFLIGHT_ALLOWANCE_SECONDS = 60
OBSERVATION_DEADLINE_SECONDS = (
    GATE_WALL_SECONDS - GATE_RECOVERY_SECONDS - MANAGEMENT_PREFLIGHT_ALLOWANCE_SECONDS
)
GATE_CONTRACT = "shared-local-v2"
REQUEST_COST_MICROUSD = plan_module.REQUEST_COST_MICROUSD


def campaign_seconds() -> int:
    return int(plan_module.WALL_SECONDS)


def recovery_seconds() -> int:
    return int(plan_module.RECOVERY_SECONDS)


# -- plan -------------------------------------------------------------------


def owner_id_for(nonce: str) -> str:
    """The run's owner marker identity, derived from the nonce.

    The collector marks every document it creates with an owner identity as
    well as the nonce. In production the identity is a function of the nonce
    rather than a second free variable, so the frozen plan reference names
    exactly one compiled plan.
    """
    if not isinstance(nonce, str) or _NONCE.fullmatch(nonce) is None:
        raise ValueError("32-character lowercase hex nonce required")
    return hashlib.sha256(
        f"{plan_module.CAMPAIGN_SEGMENT}:{nonce}".encode()
    ).hexdigest()[:32]


def owned_scope(nonce: str) -> str:
    return (
        f"project/{PROJECT}/firestore/{DATABASE}/documents/"
        f"{plan_module.document_prefix(nonce)}/*"
    )


def resource_name(nonce: str, role: str) -> str:
    return collector.document_name(
        PROJECT, DATABASE, f"{plan_module.document_prefix(nonce)}/{role}"
    )


_PLAN_CACHE: dict[str, tuple[dict, str]] = {}


def compile_execution_plan(nonce: str) -> tuple[dict, str]:
    """The lane's real compiled plan and its digest, for one nonce."""
    cached = _PLAN_CACHE.get(nonce)
    if cached is None:
        plan = plan_module.compile_plan(nonce, owner_id_for(nonce))
        cached = (plan, digest(plan))
        _PLAN_CACHE[nonce] = cached
    return copy.deepcopy(cached[0]), cached[1]


def plan_compiler(nonce: str) -> dict:
    """The plan as the admission sees it: a reference every field of which is
    derived from the nonce by the reviewed compiler."""
    plan, plan_digest = compile_execution_plan(nonce)
    return {
        "contract": plan["contract"],
        "campaignId": plan["campaign"],
        "casesDigest": plan["casesDigest"],
        "project": plan["projectId"],
        "projectNumber": plan["projectNumber"],
        "database": plan["database"],
        "nonce": nonce,
        "ownerId": plan["ownerId"],
        "planDigest": plan_digest,
        "documentPrefix": plan["documentPrefix"],
        "ownedScope": owned_scope(nonce),
        "ownedResources": [resource_name(nonce, role) for role in cases.RESOURCE_ROLES],
        "ownedResourceCount": len(plan["resources"]),
        "operationCount": len(plan["operations"]),
        "bounds": copy.deepcopy(plan["bounds"]),
        "budget": copy.deepcopy(plan["budget"]),
    }


def execution_plan(reference: dict) -> dict:
    """Recompile the plan a frozen reference names, and refuse any other bytes."""
    nonce = reference.get("nonce") if isinstance(reference, dict) else None
    if not isinstance(nonce, str) or _NONCE.fullmatch(nonce) is None:
        raise ValueError("frozen transaction expiry plan reference required")
    canonical = plan_compiler(nonce)
    plan, plan_digest = compile_execution_plan(nonce)
    if digest(reference) != digest(canonical) or reference["planDigest"] != plan_digest:
        raise ValueError("frozen transaction expiry plan reference differs")
    if plan["projectId"] != PROJECT or plan["database"] != DATABASE:
        raise ValueError("fixed production project/database required")
    return plan


def lock_scopes(plan: dict) -> list[dict]:
    """One EXCLUSIVE lock on the owned collection, five READ locks on what the
    campaign observes but never changes."""
    nonce = plan["nonce"]
    scope = f"project/{PROJECT}"
    firestore = f"{scope}/firestore/{DATABASE}"
    return [
        {"key": owned_scope(nonce), "mode": "EXCLUSIVE"},
        {"key": f"{firestore}/indexes", "mode": "READ"},
        {"key": f"{firestore}/ruleset", "mode": "READ"},
        {"key": f"{firestore}/database", "mode": "READ"},
        {"key": f"{scope}/auth/config", "mode": "READ"},
        {"key": f"{scope}/api-key-binding", "mode": "READ"},
    ]


# -- budget -----------------------------------------------------------------


def budget() -> dict:
    """The plan's own budget object, unmodified, for the reference nonce."""
    plan, _ = compile_execution_plan("0" * 32)
    return copy.deepcopy(plan["budget"])


def ledger_budget() -> dict:
    """The four Ledger dimensions. Recovery and management are inside every one:
    the plan's 95 request slots already hold 20 recovery rollbacks, eight
    metadata and two credential slots."""
    value = budget()
    return {
        "requests": int(value["requests"]),
        "accounts": int(value["accounts"]),
        "resources": int(value["resources"]),
        "costMicrousd": int(value["costMicrousd"]),
    }


def cost_model() -> dict:
    plan, _ = compile_execution_plan("0" * 32)
    estimate = plan_module.budget_estimate(plan)
    return {
        "campaignId": CAMPAIGN,
        "estimatedCostMicrousd": int(estimate["totalPlanningMicrousd"]),
        "maximumCostMicrousd": int(estimate["totalPlanningMicrousd"]),
        "networkReserveMicrousd": int(estimate["networkPlanningMicrousd"]),
        "requestCostMicrousd": int(estimate["requestCostMicrousd"]),
        "hardCeilingMicrousd": int(estimate["totalPlanningMicrousd"]),
        "totalCostMicrousd": ledger_budget()["costMicrousd"],
        "requests": int(estimate["requestSlots"]),
        "basis": estimate["basis"],
        "isExpectedInvoice": False,
    }


def frozen_bounds() -> dict:
    plan, _ = compile_execution_plan("0" * 32)
    operations = plan["operations"]
    observation = [step for step in operations if step["phase"] != "cleanup"]
    return {
        "dataRequests": int(plan["budget"]["dataRequests"]),
        "managementRequests": preflight.contract()["totalRequests"],
        "observationRequests": len(observation),
        "recoveryRequests": len(operations) - len(observation) + _release_count(plan),
        "totalRequests": int(plan["budget"]["requests"]),
        "distinctResources": int(plan["budget"]["resources"]),
        "maxRequestBytes": int(plan["bounds"]["maxRequestBytes"]),
        "maxResponseBytes": int(plan["bounds"]["maxResponseBytes"]),
        "defaultRequestTimeoutSeconds": int(
            plan["bounds"]["defaultRequestTimeoutSeconds"]
        ),
        "contendedRequestTimeoutSeconds": int(
            plan_module.CONTENDED_REQUEST_TIMEOUT_SECONDS
        ),
        "worstCaseSeconds": int(plan["bounds"]["worstCaseSeconds"]),
        "observationDeadlineSeconds": OBSERVATION_DEADLINE_SECONDS,
        "gateWallSeconds": GATE_WALL_SECONDS,
        "gateRecoverySeconds": GATE_RECOVERY_SECONDS,
        "recoverySlotSeconds": RECOVERY_SLOT_SECONDS,
        "timing": collector.WALL_CLOCK,
    }


# -- Gate projection --------------------------------------------------------


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _placeholder(name: str) -> str:
    return gate_module.PLACEHOLDER + name


def _tag_of(step: dict) -> str:
    """The transaction tag a begin step registers, planned or not.

    The collector registers whatever token a begin returns, under the planned
    tag or under `unplanned/<slot>` when the case table expected a refusal.
    Recovery has to be able to release either, so the projection names both.
    """
    return step["opensTransaction"] or f"unplanned/{step['slot']}"


def _begin_steps(plan: dict) -> list[dict]:
    return [
        step
        for step in plan["operations"]
        if step["rpc"] == "BeginTransaction" and step["phase"] != "cleanup"
    ]


def _release_count(plan: dict) -> int:
    return len(_begin_steps(plan))


def _marker(plan: dict, role: str, state: str) -> dict:
    return collector._marker_fields(plan["ownerId"], role, plan["nonce"], state)


def _name(plan: dict, role: str) -> str:
    return collector.document_name(
        plan["projectId"], plan["database"], f"{plan['documentPrefix']}/{role}"
    )


def _rpc_path(plan: dict, rpc: str) -> str:
    return (
        f"/v1/projects/{plan['projectId']}/databases/{plan['database']}/documents"
        + remote.RPC_SUFFIX[rpc]
    )


def _get(plan: dict, step: dict, *, kind: str, transaction: str | None = None) -> dict:
    name = _name(plan, step["role"])
    operation = {
        "service": "firestore",
        "method": "GET",
        "path": f"/v1/{name}",
        "kind": kind,
        "site": step["slot"],
        "resource": name,
    }
    if transaction is not None:
        operation["query"] = {"transaction": _placeholder(f"txn:{transaction}")}
    return operation


def _post(plan: dict, step: dict, *, kind: str, body: dict, **extra) -> dict:
    return {
        "service": "firestore",
        "method": "POST",
        "path": _rpc_path(plan, step["rpc"]),
        "body": body,
        "kind": kind,
        "site": step["slot"],
        **extra,
    }


def _begin(plan: dict, step: dict, options: dict) -> dict:
    return _post(
        plan,
        step,
        kind="begin",
        body={"options": options},
        binds=f"txn:{_tag_of(step)}",
    )


def _rollback(plan: dict, step: dict, tag: str) -> dict:
    return _post(
        plan, step, kind="rollback", body={"transaction": _placeholder(f"txn:{tag}")}
    )


def _update(plan: dict, step: dict, role: str, state: str, tag: str | None) -> dict:
    body = {
        "writes": [
            {
                "update": {
                    "name": _name(plan, role),
                    "fields": _marker(plan, role, state),
                }
            }
        ]
    }
    if tag is not None:
        body["transaction"] = _placeholder(f"txn:{tag}")
    return _post(
        plan, step, kind="commit-update", body=body, resource=_name(plan, role)
    )


def _observation_operation(plan: dict, step: dict) -> dict:
    """One frozen Gate operation per observation step, mirroring the collector.

    The mapping is written out rather than derived by running the collector,
    so a reviewer reads exactly what each slot sends; a test drives the real
    collector against it and requires every request to land on its slot.
    """
    slot = step["slot"]
    tag = slot.rsplit("/", 1)[1]
    if slot.startswith("preflight/absence/"):
        return _get(plan, step, kind="preflight-read")
    if slot.startswith("setup/create/"):
        role = step["role"]
        body = {
            "writes": [
                {
                    "update": {
                        "name": _name(plan, role),
                        "fields": _marker(plan, role, "created"),
                    },
                    "currentDocument": {"exists": False},
                }
            ]
        }
        return _post(plan, step, kind="create", body=body, resource=_name(plan, role))
    if slot.startswith("idle/begin/"):
        return _begin(plan, step, {"readWrite": {}})
    if slot.startswith("idle/read/"):
        return _get(plan, step, kind="read-in-transaction", transaction=tag)
    if slot.startswith(("verify/", "readback/")):
        return _get(plan, step, kind="readback")
    if slot == "idle/lock-held":
        return _update(plan, step, "locked-c", "out-of-band-blocked", None)
    if slot == "idle/commit-before":
        return _update(plan, step, "locked-d", "committed-before-idle", "d")
    if slot == "idle/commit-after":
        return _update(plan, step, "locked-a", "committed-after-idle", "a")
    if slot == "idle/rollback-after":
        return _rollback(plan, step, "b")
    if slot == "idle/lock-released":
        return _update(plan, step, "locked-a", "written-after-expiry", None)
    if slot == "idle/release/c":
        return _rollback(plan, step, "c")
    if slot.startswith(("finished/begin/", "retry/begin/")):
        return _begin(plan, step, {"readOnly": {}} if tag == "j" else {"readWrite": {}})
    if slot in ("finished/rollback-after-begin", "finished/rollback-after-rollback"):
        return _rollback(plan, step, "e")
    if slot == "finished/rollback-after-commit":
        return _rollback(plan, step, "f")
    if slot.startswith(("retry/rollback/", "finished/rollback/")):
        return _rollback(plan, step, tag)
    if slot.startswith(("finished/commit/", "retry/commit/")):
        return _update(plan, step, step["role"], f"finished-{tag}", tag)
    if slot == "retry/rolled-back-previous":
        return _begin(
            plan, step, {"readWrite": {"retryTransaction": _placeholder("txn:g")}}
        )
    if slot == "retry/committed-previous":
        return _begin(
            plan, step, {"readWrite": {"retryTransaction": _placeholder("txn:i")}}
        )
    if slot == "retry/read-only-previous":
        return _begin(
            plan, step, {"readWrite": {"retryTransaction": _placeholder("txn:j")}}
        )
    if slot == "retry/unissued-previous":
        token = _b64(plan_module.unissued_retry_token(plan["nonce"]))
        return _begin(plan, step, {"readWrite": {"retryTransaction": token}})
    if slot == "retry/malformed-previous":
        return _begin(plan, step, {"readWrite": {"retryTransaction": "not base64!"}})
    raise ValueError(f"unprojected plan slot {slot}")


def _recovery_operations(plan: dict) -> list[dict]:
    """Every rollback the run might owe, then the three cleanup reads per document.

    Releases come first and in sorted tag order, because that is the order the
    collector releases open transactions in; a tag that is not open at cleanup
    is consumed as a zero-wire skip. The cleanup slots follow the plan's own
    cleanup operations.
    """
    operations = []
    for tag in sorted(_tag_of(step) for step in _begin_steps(plan)):
        operations.append(
            {
                "service": "firestore",
                "method": "POST",
                "path": _rpc_path(plan, "Rollback"),
                "body": {"transaction": _placeholder(f"txn:{tag}")},
                "kind": "release",
                "site": f"release/{tag}",
                "transaction": tag,
            }
        )
    for step in plan["operations"]:
        if step["phase"] != "cleanup":
            continue
        role = step["role"]
        name = _name(plan, role)
        if step["slot"].startswith("cleanup/owned-read/"):
            operations.append(
                {
                    "service": "firestore",
                    "method": "GET",
                    "path": f"/v1/{name}",
                    "kind": "owned-read",
                    "site": step["slot"],
                    "resource": name,
                    "binds": f"version:{role}",
                }
            )
        elif step["slot"].startswith("cleanup/conditional-delete/"):
            operations.append(
                {
                    "service": "firestore",
                    "method": "POST",
                    "path": _rpc_path(plan, "Commit"),
                    "body": {
                        "writes": [
                            {
                                "delete": name,
                                "currentDocument": {
                                    "updateTime": _placeholder(f"version:{role}")
                                },
                            }
                        ]
                    },
                    "kind": "conditional-delete",
                    "site": step["slot"],
                    "resource": name,
                    "bindsFrom": f"version:{role}",
                }
            )
        elif step["slot"].startswith("cleanup/typed-absence/"):
            operations.append(
                {
                    "service": "firestore",
                    "method": "GET",
                    "path": f"/v1/{name}",
                    "kind": "typed-absence",
                    "site": step["slot"],
                    "resource": name,
                }
            )
        else:
            raise ValueError(f"unprojected cleanup slot {step['slot']}")
    return operations


def gate_plan(plan: dict, *, wall_seconds: int | None = None) -> dict:
    """Project the compiled campaign onto the shared Gate schema.

    Every observation slot reserves the plan's own per-request timeout, so the
    two contended out-of-band commits reserve 120 seconds and everything else
    ten. Recovery slots reserve six seconds each: rollbacks, ownership reads,
    conditional deletes and absence reads are all small unary calls, and the
    production transport is clamped to the reservation so the schedule stays
    honest. The waits between observation slots are real wall time and are not
    reserved in any slot; the observation window's slack covers them.
    """
    if plan.get("contract") != plan_module.CONTRACT or plan.get("campaign") != CAMPAIGN:
        raise ValueError("compiled transaction expiry plan required")
    observation = [
        _observation_operation(plan, step)
        for step in plan["operations"]
        if step["phase"] != "cleanup"
    ]
    recovery = _recovery_operations(plan)
    schedule = []
    for index, (step, operation) in enumerate(
        zip(
            [s for s in plan["operations"] if s["phase"] != "cleanup"],
            observation,
            strict=True,
        )
    ):
        entry = {
            "phase": "observation",
            "index": index,
            "seconds": step["timeoutSeconds"],
        }
        if operation["method"] == "GET":
            entry["creates"] = False
        schedule.append(entry)
    for index, operation in enumerate(recovery):
        entry = {"phase": "recovery", "index": index, "seconds": RECOVERY_SLOT_SECONDS}
        if operation["method"] == "GET":
            entry["creates"] = False
        schedule.append(entry)
    wall = int(wall_seconds if wall_seconds is not None else GATE_WALL_SECONDS)
    management = preflight.gate_management(
        GATE_INTERVAL_SECONDS,
        observation_window=wall - GATE_RECOVERY_SECONDS,
        recovery_window=GATE_RECOVERY_SECONDS,
    )
    observation_time = math.ceil(
        sum(
            entry["seconds"] + GATE_INTERVAL_SECONDS
            for entry in schedule
            if entry["phase"] == "observation"
        )
    )
    recovery_time = math.ceil(
        sum(
            entry["seconds"] + GATE_INTERVAL_SECONDS
            for entry in schedule
            if entry["phase"] == "recovery"
        )
        + management["phaseSeconds"]["recovery"]
    )
    if (
        not 0 < GATE_RECOVERY_SECONDS < wall
        or recovery_time > GATE_RECOVERY_SECONDS
        or observation_time + management["phaseSeconds"]["observation"]
        > wall - GATE_RECOVERY_SECONDS
        or OBSERVATION_DEADLINE_SECONDS + MANAGEMENT_PREFLIGHT_ALLOWANCE_SECONDS
        > wall - GATE_RECOVERY_SECONDS
        or plan["bounds"]["recoverySeconds"] > GATE_RECOVERY_SECONDS
    ):
        raise ValueError(
            "declared reservations do not fit the campaign wall: observation "
            f"{observation_time} s and recovery {recovery_time} s against a Gate wall of "
            f"{wall} s with {GATE_RECOVERY_SECONDS} s of recovery"
        )
    resources = [_name(plan, role) for role in cases.RESOURCE_ROLES]
    return {
        "contract": GATE_CONTRACT,
        "campaignId": CAMPAIGN,
        "nonce": plan["nonce"],
        "ownerId": plan["ownerId"],
        "jobSlots": 1,
        "ownershipMarker": {"field": "nonce", "binding": "nonce"},
        "requestSeconds": plan_module.DEFAULT_REQUEST_TIMEOUT_SECONDS,
        "wallSeconds": wall,
        "recoverySeconds": GATE_RECOVERY_SECONDS,
        "intervalSeconds": GATE_INTERVAL_SECONDS,
        "observationRequests": len(observation) + len(preflight.OBSERVATION_SLOTS),
        "dataRequests": len(observation) + len(recovery),
        "managementRequests": len(preflight.OBSERVATION_SLOTS)
        + len(preflight.RECOVERY_SLOTS),
        "requestCostMicrousd": REQUEST_COST_MICROUSD,
        "fixedCostMicrousd": int(plan["budget"]["networkMicrousd"]),
        "costMicrousd": int(plan["budget"]["costMicrousd"]),
        "receiptKind": RECEIPT_KIND,
        "observationDeadlineSeconds": OBSERVATION_DEADLINE_SECONDS,
        "timing": collector.WALL_CLOCK,
        "management": management,
        "jobs": {
            JOB: {
                "resources": resources,
                "observation": observation,
                "recovery": recovery,
                "schedule": schedule,
            }
        },
    }


# -- sources ----------------------------------------------------------------


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
    for name in (COLLECTOR_ENTRY, COMPARATOR_ENTRY, WORKER_ENTRY, GATE_ENTRY):
        if name not in values:
            raise ValueError("frozen source map omits a campaign entry")
    return values


# -- artifact ---------------------------------------------------------------


def shadow_record() -> dict:
    """The published local shadow this campaign's production run is compared to."""
    path = ROOT / SHADOW_RECORD
    if path.is_symlink() or not path.is_file():
        raise ValueError("published local shadow record required")
    value = json.loads(path.read_bytes())
    runtime = value.get("runtime") if isinstance(value, dict) else None
    if (
        not isinstance(runtime, dict)
        or value.get("campaign") != CAMPAIGN
        or not isinstance(runtime.get("sourceCommit"), str)
        or len(runtime["sourceCommit"]) != 40
        or value.get("complete") is not True
    ):
        raise ValueError("published local shadow record required")
    return value


ARTIFACT_PROFILE_BASIS = {
    "kind": "txn-expiry-artifact-profile-v1",
    "registry": "none",
    "derivedFrom": "the published local shadow record's runtime.sourceCommit",
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
    return "txn-expiry-" + shadow_record()["runtime"]["sourceCommit"][:9]


def artifact_profile_basis() -> dict:
    record = shadow_record()
    return {
        **copy.deepcopy(ARTIFACT_PROFILE_BASIS),
        "profile": artifact_profile(),
        "sourceCommit": record["runtime"]["sourceCommit"],
        "runtimeInputsDigest": record["runtime"]["runtimeInputsDigest"],
        "shadowArtifactSha256": record["artifactSha256"],
    }


def retained_artifact_validator(artifact_path, manifest_path, profile):
    """Bind the retained artifact and manifest by digest.

    The profile is a label derived from the shadow's Rust commit: the digests
    prove which bytes the owner retained, not that the build behind them was
    reviewed.
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


# -- execution members ------------------------------------------------------


def verify_worker_binding(binding, binding_digest, frozen) -> None:
    """The reviewed worker bytes, checked against the transport and the frozen map."""
    if not isinstance(binding, bytes) or not binding:
        raise ValueError("reviewed worker source required")
    observed = hashlib.sha256(binding).hexdigest()
    if observed != binding_digest or observed != remote.WORKER_SHA256:
        raise ValueError("worker source digest differs from the reviewed transport")
    if frozen is not None and frozen.get(WORKER_ENTRY) != observed:
        raise ValueError("worker source digest differs from the frozen inputs")


def worker_binding() -> tuple[bytes, str]:
    source = remote.worker_source()
    return source, hashlib.sha256(source).hexdigest()


def transport_bound(value, *, binding, binding_digest, capability=None):
    """Adapt one bound wire call to the lane's own transports.

    A management call goes to the request-byte lane's reviewed management
    transport; a data call goes to this lane's fixed Firestore transport. Both
    require the admitted capability and the reviewed worker binding.
    """
    if not isinstance(value, dict):
        raise ValueError("closed transaction expiry wire call required")  # noqa: TRY004 -- admission boundary collapses malformed input to one refusal class
    if capability is None:
        raise ValueError("active O7 production capability required")
    authorize_transport(capability, binding=binding, binding_digest=binding_digest)
    verify_worker_binding(binding, binding_digest, None)
    if value.get("kind") == "management":
        return preflight.management_transport(
            value, capability=capability, binding=binding, binding_digest=binding_digest
        )
    if (
        set(value) != {"kind", "request", "token", "deadline"}
        or value["kind"] != "data"
    ):
        raise ValueError("closed transaction expiry wire call required")
    deadline = value["deadline"]
    if (
        type(deadline) not in (int, float)
        or isinstance(deadline, bool)
        or not math.isfinite(deadline)
    ):
        raise ValueError("finite absolute deadline required")
    return remote.request(
        {"request": value["request"], "token": value["token"]},
        deadline=deadline,
        capability=capability,
        binding=binding,
        binding_digest=binding_digest,
    )


def forbidden_transports():
    """Objects an injected preparation transport must not be able to reach."""
    return (remote, remote.request, remote._run_process_exchange, transport_bound)


def collector_options(
    plan: dict, *, target: str = "production", host: str | None = None, port=None
) -> dict:
    """The collector options one execution runs under. Wall-clock timing only."""
    return {
        "target": target,
        "host": collector.PRODUCTION_HOST if host is None else host,
        "port": port,
        "projectId": plan["projectId"],
        "database": plan["database"],
        "nonce": plan["nonce"],
        "ownerId": plan["ownerId"],
        "timing": collector.WALL_CLOCK,
        "deadlineSeconds": OBSERVATION_DEADLINE_SECONDS,
    }


def collector_member(gate, plan, output, *, transmit, rehearsal=None):
    """Drive the reviewed collector through the shared Gate.

    `transmit` is the capability's bound wire in production. A `rehearsal`
    shortens the real sleeper and is admitted only with an injected transport;
    the production wire refuses it. The clock advance callable the rehearsal
    shadow uses is never accepted here at all.
    """
    import txn_expiry_production as production

    return production.run_collection(
        gate, plan, output, transmit=transmit, rehearsal=rehearsal
    )


def comparator(result, shadow=None):
    """Compare a production receipt with the published shadow's receipt.

    The published local shadow is the reference this campaign is bound to. The
    comparator's own verdict is returned unchanged, with the digests of both
    sides; this establishes agreement or its absence, never a compatibility
    claim, which remains an owner decision on the evidence.
    """
    published = shadow_record() if shadow is None else shadow
    reference = published.get("receipt") if isinstance(published, dict) else None
    verdict = comparison.compare(result, reference)
    return {
        "campaignId": CAMPAIGN,
        "comparison": verdict,
        "classification": verdict.get("classification"),
        "shadowRecordDigest": digest(published),
        "productionReceiptDigest": digest(result),
        "formalCompatibilityClaim": False,
    }


def permission_bindings(plan, source_commit, artifact_digest, inputs, baseline=None):
    """Required non-authorizing fields for an independently supplied permission."""
    canonical = plan_compiler(plan["nonce"])
    if digest(plan) != digest(canonical):
        raise ValueError("fixed production project/database required")
    compiled, _ = compile_execution_plan(plan["nonce"])
    required = {
        "kind": PERMISSION_KIND,
        "campaignId": CAMPAIGN,
        "project": PROJECT,
        "projectNumber": NUMBER,
        "quotaProject": PROJECT,
        "database": DATABASE,
        "nonce": plan["nonce"],
        "ownerId": plan["ownerId"],
        "planDigest": plan["planDigest"],
        "casesDigest": cases.cases_digest(),
        "sourceCommit": source_commit,
        "sourceInputs": inputs,
        "collectorSourceDigest": digest(inputs),
        "artifactSha256": artifact_digest,
        "collectorSha256": inputs[COLLECTOR_ENTRY],
        "comparatorSha256": inputs[COMPARATOR_ENTRY],
        "workerSha256": inputs[WORKER_ENTRY],
        "gateSha256": inputs[GATE_ENTRY],
        "budget": copy.deepcopy(compiled["budget"]),
        "ledgerBudget": ledger_budget(),
        "resourceLocks": lock_scopes(plan),
        "ownedScope": plan["ownedScope"],
        "ownedResourceCount": plan["ownedResourceCount"],
        # `wallSeconds` is the name the shared admission core checks; the
        # plan's `observationSeconds` is the same number under its own name.
        "wallSeconds": campaign_seconds(),
        "campaignSeconds": campaign_seconds(),
        "recoverySeconds": recovery_seconds(),
        "gateWallSeconds": GATE_WALL_SECONDS,
        "gateRecoverySeconds": GATE_RECOVERY_SECONDS,
        "observationDeadlineSeconds": OBSERVATION_DEADLINE_SECONDS,
        "defaultRequestTimeoutSeconds": plan_module.DEFAULT_REQUEST_TIMEOUT_SECONDS,
        "contendedRequestTimeoutSeconds": plan_module.CONTENDED_REQUEST_TIMEOUT_SECONDS,
        "maxRequestBytes": plan_module.MAX_REQUEST_BYTES,
        "maxResponseBytes": plan_module.MAX_RESPONSE_BYTES,
        "concurrency": 1,
        "timing": collector.WALL_CLOCK,
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
        "managementContract": preflight.contract(),
        "productionPreflight": {
            "version": preflight.VERSION,
            "managementRequests": preflight.contract()["totalRequests"],
            "credentialIds": list(preflight.CREDENTIAL_IDS),
            "credentialSlots": list(preflight.CREDENTIAL_SLOTS),
            "source": PREFLIGHT_ENTRY,
        },
        "allowedReobservations": 0,
    }
    if baseline is not None:
        required.update(commit_baseline.permission_baseline(baseline))
        required["baselineProvenance"] = baseline["provenance"]
    return required


def descriptor() -> CampaignDescriptor:
    """The transaction expiry campaign as the shared admission core sees it."""
    if campaign_seconds() + recovery_seconds() != 1380:
        raise ValueError("the campaign window must be the plan's 1200 + 180 seconds")
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
        collector=collector_member,
        comparator=comparator,
        cost_model=cost_model,
        permission_bindings=permission_bindings,
        transport_bound=transport_bound,
        binding_verifier=verify_worker_binding,
        retained_artifact_validator=retained_artifact_validator,
        forbidden_transports=forbidden_transports,
    )
