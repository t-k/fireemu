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
import request_bytes_campaign as campaign
from batch_contract import NUMBER, PROJECT
from broad_contract import digest
from o8_admission import authorize_transport
from o8_campaign import CAMPAIGN_APPROVAL_FIELDS, CampaignDescriptor
from request_bytes_campaign import campaign_digest, compile_request_bytes_campaign
from request_bytes_collector import collect_local
from request_bytes_compiler import (
    CAMPAIGN,
    compile_request_bytes_plan,
    validate_request_bytes_plan,
)
from request_bytes_shadow import classify_local_result
from shared_gate import body_reference


def _load(name: str, path: Path):
    """Load one reviewed module by exact path, without touching sys.path.

    Prepending another lane's directory would outlive this import and shadow
    same-named modules for every lane loaded afterwards in the same process.
    """
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
commit_baseline = _load("_request_bytes_commit_baseline", ROOT / BASELINE_MODULE)

DATABASE = "(default)"
_NONCE = re.compile(r"^[0-9a-f]{32}$")
BUDGET_PATH = "spec/compatibility/fs-request-bytes-budget.json"
FROZEN_INPUTS_KIND = "request-bytes-frozen-inputs-v1"
PERMISSION_KIND = "request-bytes-owner-execution-permission-v1"
APPROVAL_KIND = "request-bytes-o8-approval-v1"
MANIFEST_KIND = "request-bytes-o8-manifest-v1"
SHADOW_RECORD = "spec/compatibility/broad-runs/fs-request-bytes-local-shadow.json"
PRINCIPAL_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
# The published local shadow is the comparison reference, so the artifact
# profile names the build that shadow ran, derived from the record rather than
# typed in. The digest still proves only which bytes the owner retained.
MINIMUM_WINDOW_SECONDS = 1200
RECEIPT_KIND = "request-bytes-acquisition-receipt-v1"

COLLECTOR_ENTRY = (
    "tools/compat-broad/fs-request-bytes-boundary/request_bytes_collector.py"
)
COMPARATOR_ENTRY = (
    "tools/compat-broad/fs-request-bytes-boundary/request_bytes_shadow.py"
)
WORKER_ENTRY = (
    "tools/compat-broad/fs-request-bytes-boundary/request_bytes_https_worker.py"
)
PREFLIGHT_ENTRY = (
    "tools/compat-broad/fs-request-bytes-boundary/request_bytes_preflight.py"
)
TRANSPORT_ENTRY = (
    "tools/compat-broad/fs-request-bytes-boundary/request_bytes_remote_transport.py"
)
# Every top-level module of the lane is swept, test modules included, so that a
# test edit is visible in the frozen digest rather than silently outside it.
# The seven boundSources of the published budget are a subset and are checked.
LANE_DIRECTORY = "tools/compat-broad/fs-request-bytes-boundary"
SHARED_SOURCES = (
    BASELINE_MODULE,
    "tools/compat-broad/broad_contract.py",
    "tools/compat-broad/batch_contract.py",
    "tools/compat-broad/shared_gate.py",
    "tools/compat-broad/production-admission/reservations.py",
    "tools/compat-broad/o8-core/o8_admission.py",
    "tools/compat-broad/o8-core/o8_campaign.py",
    "tools/compat-broad/fs-write-txn/credential_prep.py",
    "tools/compat-broad/batch_adapter.py",
    "tools/compat-broad/batch_wire.py",
    "tools/compat-broad/batch_contract.py",
)
# Management dispatch has two real worker paths: tokeninfo uses the private
# credential worker, while the project/database/Auth reads use batch_adapter's
# standalone batch_wire worker. Keep this explicit so the reservation
# generation cannot silently omit either transport implementation.
TRANSPORT_CLOSURE_SOURCES = (
    PREFLIGHT_ENTRY,
    "tools/compat-broad/fs-write-txn/credential_prep.py",
    "tools/compat-broad/batch_adapter.py",
    "tools/compat-broad/batch_wire.py",
)
# The closure a reservation records, so a later abort proves it runs the same
# sources the acquisition ran.
ABORT_CLOSURE_SOURCES = (
    "tools/compat-broad/shared_gate.py",
    "tools/compat-broad/production-admission/reservations.py",
    "tools/compat-broad/o8-core/o8_admission.py",
    "tools/compat-broad/fs-request-bytes-boundary/request_bytes_admission.py",
    "tools/compat-broad/fs-request-bytes-boundary/request_bytes_descriptor.py",
    *TRANSPORT_CLOSURE_SOURCES,
)
LEGACY_CLOSURE_SOURCES = ABORT_CLOSURE_SOURCES[:5]
# Immutable metadata from the retained 2026-09-21 O8 packet. This is the only
# historical generation accepted by this descriptor; it is intentionally kept
# as digests rather than importing or rewriting the private packet.
HISTORICAL_GENERATIONS = {
    (
        "a2d2db49cc097f3313008ef8eeb1b10672107427",
        "4e363c7276a266070f4aaf1b57ea96cff441b165a15d7ca3de1fa4bfcd433697",
    ): {
        "o8_admission.py": "1adf21e8815ff8131377a6d776f56027bb9a24a5201b22dbff98d9fabd70b334",
        "request_bytes_admission.py": "63e827dfad0af24f88ec35ebdbab1a9b47a4ad0da7c8ec95794b5c022b0e5c79",
        "request_bytes_descriptor.py": "dfd90f72ecfb6fa385f68c8813c1a1a3f44595fcb296ef73caab5d92157ab195",
        "reservations.py": "bed7d761805bbc565b09bda630ffef6d6af637fffd46344bb018b3b54abf2c93",
        "shared_gate.py": "74d0912a6cd1102e3b918511a98e67e01e442415f59a9e9f1e7def630a859045",
    }
}


def shadow_record() -> dict:
    """The published local shadow this campaign's production run is compared to."""
    path = ROOT / SHADOW_RECORD
    if path.is_symlink() or not path.is_file():
        raise ValueError("published local shadow record required")
    value = json.loads(path.read_bytes())
    runtime = value.get("runtime") if isinstance(value, dict) else None
    if (
        not isinstance(runtime, dict)
        or value.get("campaignId") != CAMPAIGN
        or not isinstance(runtime.get("sourceCommit"), str)
        or len(runtime["sourceCommit"]) != 40
    ):
        raise ValueError("published local shadow record required")
    return value


# The lane has no reviewed build profile registry. This states, in the code O7
# reads, exactly what the profile does and does not establish, so accepting it
# is a decision the gatekeeper makes on the record rather than an omission.
ARTIFACT_PROFILE_BASIS = {
    "kind": "request-bytes-artifact-profile-v1",
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
    """The build the comparison is bound to, named by the shadow's own Rust SHA."""
    return "request-bytes-" + shadow_record()["runtime"]["sourceCommit"][:9]


def artifact_profile_basis() -> dict:
    """What the profile establishes, for the record O7 accepts it on."""
    return {
        **copy.deepcopy(ARTIFACT_PROFILE_BASIS),
        "profile": artifact_profile(),
        "sourceCommit": shadow_record()["runtime"]["sourceCommit"],
        "shadowArtifactSha256": shadow_record()["runtime"]["artifactSha256"],
    }


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


def small_request_timeout_seconds() -> float:
    """The published ceiling for bodyless reads and deletes."""
    published = budget_document()
    declared = published["budget"]["smallRequestTimeoutSeconds"]
    if (
        type(declared) not in (int, float)
        or isinstance(declared, bool)
        or declared <= 0
    ):
        raise ValueError("published small-request timeout required")
    if declared != request_bytes_remote_transport.SMALL_REQUEST_TIMEOUT:
        raise ValueError(
            "published small-request timeout differs from enforced ceiling"
        )
    return float(declared)


def budget() -> dict:
    """The published budget object, unmodified."""
    return copy.deepcopy(budget_document()["budget"])


def management_contract() -> dict:
    """Closed management slots consumed by the shared Gate driver.

    This is declarative only. Sending is owned by the Gate's charged
    ``management_dispatch`` path; no transport callable is exposed here.
    """
    return {
        "version": "request-bytes-preflight-v1",
        "dispatchKind": "closed-v1",
        "observation": list(campaign.MANAGEMENT_OBSERVATION_IDS),
        "recovery": list(campaign.MANAGEMENT_RECOVERY_IDS),
        "credentialIds": ["oauth-tokeninfo"],
        "credentialSlots": ["tokeninfo"],
        "slotSeconds": campaign.MANAGEMENT_SLOT_SECONDS,
        "durationSeconds": 12.0,
        "intervalSeconds": campaign.MANAGEMENT_INTERVAL_SECONDS,
        "totalRequests": 7,
        "principal": {
            "alternatives": [
                ["clientId", "subject", "requiredScopes"],
                ["clientId", "verifiedEmail", "requiredScopes"],
            ],
            "claims": [
                "issued_to",
                "audience",
                "user_id",
                "email",
                "verified_email",
                "scope",
                "expires_in",
            ],
        },
    }


def recovery_reserve_microusd() -> int:
    """What the declared recovery reserve costs at the published unit prices."""
    published = budget_document()
    reserve = published["budget"]["recoveryWindow"]
    prices = published["cost"]["unitPricesUsd"]
    usd = (
        reserve["reserveDeletes"] * prices["documentDelete"]
        + reserve["reserveReads"] * prices["documentRead"]
    )
    return math.ceil(usd * 1_000_000)


def ledger_budget() -> dict:
    """The four Ledger dimensions, with recovery already inside every one.

    `requests` is 258 because the compiled schedule is 105 observation slots
    plus 153 recovery slots; a recovery reserve on top would double-count the
    same wire calls. `accounts` is 1, matching the published `maxAccounts`: this
    campaign spends one authorized principal's quota, where the Commit campaign
    claimed 0 because it consumed no account-scoped resource at all. The cost
    covers the maximum usage, every probe accepted, plus the declared recovery
    reserve, and not the expected forecast, which the published budget says
    binds nothing.
    """
    _published, published_budget, cost, _micro = _budget_numbers()
    maximum = math.ceil(cost["maximumCostUsd"] * 1_000_000)
    return {
        "requests": int(published_budget["maxHttpRequests"]),
        "accounts": int(published_budget["maxAccounts"]),
        "resources": int(published_budget["maxDistinctResources"]),
        # The shared Gate charges management slots as well as data slots. The
        # seven fixed management calls have no Firestore document tariff, but
        # they still consume the campaign's bounded admission allowance.
        "costMicrousd": maximum
        + recovery_reserve_microusd()
        + int(published_budget.get("maxManagementRequests", 0))
        * campaign.MANAGEMENT_REQUEST_COST_MICROUSD,
    }


def frozen_bounds() -> dict:
    """The bounded shape of one run, every figure taken from the published budget."""
    published, published_budget, _cost, _micro = _budget_numbers()
    # The maximum, every probe accepted, is what a bound must cover; the
    # published `accounting` is the forecast under the expected outcome, and the
    # budget itself says it binds nothing.
    maximum = published["maximumUsage"]
    accounting = published["accounting"]
    return {
        "dataRequests": int(maximum["dataRequests"]),
        "managementRequests": int(maximum["managementRequests"]),
        "observationRequests": 105,
        "recoveryRequests": 153,
        "documentWrites": int(maximum["documentWrites"]),
        "documentReads": int(maximum["documentReads"]),
        "documentDeletes": int(maximum["documentDeletes"]),
        "uploadedBytes": int(maximum["uploadedBytes"]),
        "expectedWrites": int(accounting["documentWrites"]),
        "expectedDeletes": int(accounting["documentDeletes"]),
        "totalRequests": int(published_budget["maxHttpRequests"]),
        "distinctResources": int(published_budget["maxDistinctResources"]),
        "peakLiveDocuments": int(published_budget["maxPeakLiveDocuments"]),
        "maxRequestBytes": int(published_budget["maxRequestBytes"]),
        "maxResponseBytes": int(published_budget["maxResponseBytes"]),
        "perRequestTimeoutSeconds": transport_deadline_seconds(),
    }


def cost_model() -> dict:
    """Planning ceilings from the published budget, never a quoted tariff."""
    _published, published_budget, cost, micro = _budget_numbers()
    return {
        "campaignId": CAMPAIGN,
        "estimatedCostMicrousd": micro,
        "maximumCostMicrousd": math.ceil(cost["maximumCostUsd"] * 1_000_000),
        "recoveryReserveMicrousd": recovery_reserve_microusd(),
        "hardCeilingMicrousd": math.ceil(cost["hardCostCeilingUsd"] * 1_000_000),
        "unitPricesUsd": dict(cost["unitPricesUsd"]),
        "totalCostMicrousd": ledger_budget()["costMicrousd"],
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
        {"key": f"{scope}/identity", "mode": "READ"},
        *[
            {"key": f"{firestore}/{kind}", "mode": "READ"}
            for kind in ("indexes", "ruleset", "database")
        ],
        {"key": f"{scope}/auth/config", "mode": "READ"},
    ]


def lane_sources() -> tuple[str, ...]:
    """Every top-level module of the lane, in a stable order."""
    directory = ROOT / LANE_DIRECTORY
    return tuple(
        sorted(f"{LANE_DIRECTORY}/{path.name}" for path in directory.glob("*.py"))
    )


PROBE_SCOPES = ("probe-u01", "probe-e01", "probe-o01")
PROBE_OBSERVATIONS = 35
PROBE_RECOVERY = 51
GATE_CONTRACT = "shared-local-v2"
GATE_INTERVAL_SECONDS = 0.25
GATE_REQUEST_COST_MICROUSD = 1


def gate_job_name(probe: str) -> str:
    return f"request-bytes-{probe}"


def _probe_slice(plan, probe_index):
    """One probe's own operations, in the compiler's fixed per-probe order."""
    observation = plan["observation"][
        probe_index * PROBE_OBSERVATIONS : (probe_index + 1) * PROBE_OBSERVATIONS
    ]
    recovery = plan["recovery"][
        probe_index * PROBE_RECOVERY : (probe_index + 1) * PROBE_RECOVERY
    ]
    if len(observation) != PROBE_OBSERVATIONS or len(recovery) != PROBE_RECOVERY:
        raise ValueError("compiled plan does not carry three equal probes")
    return observation, recovery


def _probe_schedule(
    plan,
    probe_index,
    *,
    upload_seconds,
    observation_slot_seconds,
    recovery_slot_seconds,
):
    """The campaign schedule projected onto one probe's own slot indices.

    The campaign's `executionSchedule` indexes the whole plan; a Gate job indexes
    its own lists. The projection keeps the campaign's order and renumbers, and
    each slot declares what the Gate needs in order to charge it honestly: its
    own reservation, and whether it can create a document. Only the one Commit
    per probe carries a body and can write; the 17 ownership reads, the 17
    readbacks and every recovery read and delete cannot.
    """
    bounds = {"observation": PROBE_OBSERVATIONS, "recovery": PROBE_RECOVERY}
    entries = []
    for entry in plan["executionSchedule"]:
        span = bounds[entry["phase"]]
        if entry["index"] // span != probe_index:
            continue
        operation = plan[entry["phase"]][entry["index"]]
        carries_body = operation.get("body") is not None
        small = (
            observation_slot_seconds
            if entry["phase"] == "observation"
            else recovery_slot_seconds
        )
        slot = {
            "phase": entry["phase"],
            "index": entry["index"] % span,
            "seconds": upload_seconds if carries_body else small,
        }
        if operation["method"] != "POST":
            # Absent means creating, so only a slot that cannot write says so.
            slot["creates"] = False
        entries.append(slot)
    return entries


def gate_plan(
    plan,
    *,
    upload_seconds,
    observation_slot_seconds,
    recovery_slot_seconds,
    wall_seconds=None,
):
    """Project the compiled campaign onto the shared Gate schema.

    The owner declares the 60-second Commit reservation and the small-request
    reservations. Their sums, including rate spacing, must fit the published
    observation and recovery windows. The full published recovery reserve is
    retained so the Gate and collector use the same phase cutoff.
    """
    for name, value in (
        ("upload_seconds", upload_seconds),
        ("observation_slot_seconds", observation_slot_seconds),
        ("recovery_slot_seconds", recovery_slot_seconds),
    ):
        if type(value) not in (int, float) or isinstance(value, bool) or value <= 0:
            raise ValueError(f"declared {name} required")
    if upload_seconds > transport_deadline_seconds():
        raise ValueError("upload reservation above the enforced transport ceiling")
    jobs = {}
    for index, probe in enumerate(PROBE_SCOPES):
        observation, recovery = _probe_slice(plan, index)
        schedule = _probe_schedule(
            plan,
            index,
            upload_seconds=upload_seconds,
            observation_slot_seconds=observation_slot_seconds,
            recovery_slot_seconds=recovery_slot_seconds,
        )
        observation = copy.deepcopy(observation)
        for operation in observation:
            if operation.get("body") is not None:
                operation["bodyRef"] = body_reference(operation.pop("body"))
        jobs[gate_job_name(probe)] = {
            "resources": [
                name for name in plan["ownedResources"] if f"/{probe}/" in name
            ],
            "observation": copy.deepcopy(observation),
            "recovery": copy.deepcopy(recovery),
            "schedule": schedule,
        }
    recovery_time = math.ceil(
        sum(
            slot["seconds"] + GATE_INTERVAL_SECONDS
            for job in jobs.values()
            for slot in job["schedule"]
            if slot["phase"] == "recovery"
        )
    )
    data_recovery_time = recovery_time
    if data_recovery_time > recovery_seconds():
        raise ValueError(
            "declared reservations do not fit the campaign wall: "
            f"recovery {recovery_time} s exceeds published reserve {recovery_seconds()} s"
        )
    recovery_time = recovery_seconds()
    wall = int(wall_seconds if wall_seconds is not None else campaign_seconds())
    observation_time = math.ceil(
        sum(
            slot["seconds"] + GATE_INTERVAL_SECONDS
            for job in jobs.values()
            for slot in job["schedule"]
            if slot["phase"] == "observation"
        )
    )
    management_observation_time = len(campaign.MANAGEMENT_OBSERVATION_IDS) * (
        campaign.MANAGEMENT_SLOT_SECONDS + campaign.MANAGEMENT_INTERVAL_SECONDS
    )
    management_recovery_time = len(campaign.MANAGEMENT_RECOVERY_IDS) * (
        campaign.MANAGEMENT_SLOT_SECONDS + campaign.MANAGEMENT_INTERVAL_SECONDS
    )
    # A wall narrower than the published one shrinks the observation window
    # with it; the published window is a ceiling, not a substitute.
    observation_window = min(
        int(budget_document()["budget"]["observationWindowSeconds"]),
        wall - recovery_time,
    )
    # The deficit is named, because "does not fit" is the message that sends
    # someone to guess at the numbers instead of reading them.
    if (
        not 0 < recovery_time < wall
        or observation_time + management_observation_time > observation_window
        or data_recovery_time + management_recovery_time > int(
            budget_document()["budget"]["recoveryWindow"]["reserveSeconds"]
        )
    ):
        raise ValueError(
            "declared reservations do not fit the campaign wall: observation "
            f"{observation_time} s and recovery {recovery_time} s need "
            f"{observation_time + recovery_time} s against a published wall of "
            f"{wall} s"
        )
    return {
        "contract": GATE_CONTRACT,
        "campaignId": CAMPAIGN,
        "nonce": plan["nonce"],
        "jobSlots": len(PROBE_SCOPES),
        "ownershipMarker": {"field": "_owner", "binding": "nonce"},
        # The plan-wide fallback for a slot that declares none; every slot in
        # this schedule declares its own, so this is the floor, not the figure.
        "requestSeconds": min(observation_slot_seconds, recovery_slot_seconds),
        "wallSeconds": wall,
        "recoverySeconds": recovery_time,
        "intervalSeconds": GATE_INTERVAL_SECONDS,
        "observationRequests": len(PROBE_SCOPES) * PROBE_OBSERVATIONS
        + len(campaign.MANAGEMENT_OBSERVATION_IDS),
        "dataRequests": len(PROBE_SCOPES) * PROBE_OBSERVATIONS
        + len(PROBE_SCOPES) * PROBE_RECOVERY,
        "managementRequests": len(campaign.MANAGEMENT_OBSERVATION_IDS)
        + len(campaign.MANAGEMENT_RECOVERY_IDS),
        "requestCostMicrousd": GATE_REQUEST_COST_MICROUSD,
        "costMicrousd": ledger_budget()["costMicrousd"],
        "receiptKind": RECEIPT_KIND,
        # The wire ceiling every body-carrying slot must reserve, so the 60 on
        # the three Commits is checkable rather than conventional and a later
        # edit cannot quietly shrink it.
        "transportCeilingSeconds": transport_deadline_seconds(),
        # The owner supplies the bearer token, so this campaign acquires no
        # credential and takes no management slot at all.
        "management": {
            "dispatchKind": "closed-v1",
            "observation": [
                {
                    "id": item,
                    "seconds": campaign.MANAGEMENT_SLOT_SECONDS,
                    "duration": 12.0,
                    "timeout": campaign.MANAGEMENT_SLOT_SECONDS,
                }
                for item in campaign.MANAGEMENT_OBSERVATION_IDS
            ],
            "recovery": [
                {
                    "id": item,
                    "seconds": campaign.MANAGEMENT_SLOT_SECONDS,
                    "duration": 12.0,
                    "timeout": campaign.MANAGEMENT_SLOT_SECONDS,
                }
                for item in campaign.MANAGEMENT_RECOVERY_IDS
            ],
            "credentialIds": ["oauth-tokeninfo"],
            "credentialSlots": ["tokeninfo"],
            "slotSeconds": campaign.MANAGEMENT_SLOT_SECONDS,
            "intervalSeconds": campaign.MANAGEMENT_INTERVAL_SECONDS,
            "totalRequests": len(campaign.MANAGEMENT_OBSERVATION_IDS)
            + len(campaign.MANAGEMENT_RECOVERY_IDS),
            "phaseSeconds": {
                "observation": len(campaign.MANAGEMENT_OBSERVATION_IDS)
                * (campaign.MANAGEMENT_SLOT_SECONDS + campaign.MANAGEMENT_INTERVAL_SECONDS),
                "recovery": len(campaign.MANAGEMENT_RECOVERY_IDS)
                * (campaign.MANAGEMENT_SLOT_SECONDS + campaign.MANAGEMENT_INTERVAL_SECONDS),
            },
            "observationWindowSeconds": observation_window,
            "recoveryWindowSeconds": int(
                budget_document()["budget"]["recoveryWindow"]["reserveSeconds"]
            ),
            "principalBinding": {
                "required": ["clientId", "subject", "requiredScopes"],
                "claims": ["issued_to", "audience", "user_id", "scope", "expires_in"],
            },
            "permissionExpiryBound": True,
        },
        "jobs": jobs,
    }


def source_map() -> dict[str, str]:
    """Digest every source this campaign binds: the whole lane, plus the closure."""
    values = {}
    for name in (*lane_sources(), *SHARED_SOURCES):
        path = ROOT / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("frozen campaign source missing")
        values[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    bound = budget_document()["boundSources"]
    if any(name not in values for name in bound):
        raise ValueError("frozen source map omits a published bound source")
    return values


def generation_source_digests(source_inputs: dict[str, str]) -> dict[str, str]:
    """Project the full closure to the Ledger's legacy basename-key schema."""
    if not isinstance(source_inputs, dict):
        raise ValueError("frozen source map required")
    names = [Path(name).name for name in ABORT_CLOSURE_SOURCES]
    if len(names) != len(set(names)):
        raise ValueError("source closure basename collision")
    if any(name not in source_inputs for name in ABORT_CLOSURE_SOURCES):
        raise ValueError("frozen acquisition source closure required")
    return {
        Path(name).name: source_inputs[name] for name in ABORT_CLOSURE_SOURCES
    }


def validate_generation(generation: dict, inputs: dict) -> None:
    """Validate current generations and one explicit historical schema."""
    if not isinstance(generation, dict) or not isinstance(inputs, dict):
        raise ValueError("saved generation binding required")
    source_digests = generation.get("sourceDigests")
    if not isinstance(source_digests, dict):
        raise ValueError("saved generation source closure required")
    source_inputs = inputs.get("sourceInputs")
    identity = (generation.get("sourceCommit"), generation.get("collectorSourceDigest"))
    if generation.get("sourceCommit") != inputs.get("sourceCommit"):
        raise ValueError("saved generation commit differs")
    if generation.get("collectorSourceDigest") != digest(source_inputs):
        raise ValueError("saved generation source map differs")
    historical = HISTORICAL_GENERATIONS.get(identity)
    if historical is not None:
        if source_digests != historical:
            raise ValueError("historical generation source closure differs")
        return
    # Any non-allowlisted identity is a current-schema packet and must carry
    # the complete closure, even when its source map is not today's checkout.
    current = generation_source_digests(source_inputs)
    if source_digests != current:
        raise ValueError("saved generation source closure incomplete")


def collector(gate, plan, output, *, transmit):
    """Drive the reviewed collector through the existing Gate when supplied."""
    return collect_local(plan, transmit, output, gate=gate)


def comparator(result, shadow=None):
    """Compare a production result's classification with the published shadow's.

    The published local shadow is the reference this campaign is bound to, so a
    comparison is not a classification of one result: it is whether the two
    classifications agree, and on what. This establishes agreement, never a
    compatibility claim; that remains an owner decision on the evidence.
    """
    published = shadow_record() if shadow is None else shadow
    observed = classify_local_result(result)
    reference = {
        "classification": published.get("shadow", {}).get("classification")
        if isinstance(published.get("shadow"), dict)
        else None,
        "probeOutcomes": published.get("probeOutcomes"),
    }
    if reference["classification"] is None:
        reference["classification"] = classify_local_result(
            published.get("observation", {})
        ).get("classification")
    return {
        "campaignId": CAMPAIGN,
        "production": observed,
        "shadow": reference,
        "classificationAgrees": observed.get("classification")
        == reference["classification"],
        "shadowRecordDigest": digest(published),
        "formalCompatibilityClaim": False,
    }


def transport_bound(value, *, binding, binding_digest, capability=None):
    """Adapt one bound wire call to the reviewed transport's own signature.

    `value` carries the frozen slot coordinates and the bearer token for exactly
    one request. The binding is the reviewed worker source, and its digest is
    re-checked here as well as inside the transport, so a capability issued
    against other bytes cannot reach the wire through this path.
    """
    if not isinstance(value, dict):
        raise ValueError("closed request-byte wire call required")
    if value.get("kind") == "management":
        if set(value) != {"kind", "phase", "slot", "token", "deadline"}:
            raise ValueError("closed management wire call required")
        if capability is None:
            raise ValueError("active O7 production capability required")
        if value["phase"] not in ("observation", "recovery"):
            raise ValueError("closed management phase required")
        if type(value["deadline"]) not in (int, float) or isinstance(value["deadline"], bool) or not math.isfinite(value["deadline"]):
            raise ValueError("finite management deadline required")
        authorize_transport(capability, binding=binding, binding_digest=binding_digest)
        verify_worker_binding(binding, binding_digest, None)
        import request_bytes_preflight

        return request_bytes_preflight.management_transport(
            value["slot"],
            value["token"],
            deadline=value["deadline"],
            capability=capability,
            binding=binding,
            binding_digest=binding_digest,
        )
    if set(value) != {
        "plan",
        "phase",
        "index",
        "operation",
        "token",
        "deadline",
    }:
        raise ValueError("closed request-byte wire call required")
    if capability is None:
        raise ValueError("active O7 production capability required")
    authorize_transport(
        capability,
        binding=binding,
        binding_digest=binding_digest,
    )
    verify_worker_binding(binding, binding_digest, None)
    bounds = budget_document()["budget"]
    if (
        request_bytes_remote_transport.MAX_REQUEST_BYTES != bounds["maxRequestBytes"]
        or request_bytes_remote_transport.RESPONSE_BYTES != bounds["maxResponseBytes"]
    ):
        raise ValueError("transport byte caps differ from the published budget")
    if type(value["deadline"]) not in (int, float) or not math.isfinite(
        value["deadline"]
    ):
        raise ValueError("finite absolute deadline required")
    operation = value["operation"]
    timeout = (
        transport_deadline_seconds()
        if isinstance(operation, dict) and operation.get("body") is not None
        else small_request_timeout_seconds()
    )
    return request_bytes_remote_transport.request(
        value["plan"],
        value["phase"],
        value["index"],
        value["operation"],
        value["token"],
        timeout=timeout,
        deadline=value["deadline"],
        capability=capability,
        binding=binding,
        binding_digest=binding_digest,
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
    return (
        request_bytes_remote_transport,
        request_bytes_remote_transport.request,
        request_bytes_remote_transport.prepare,
        transport_bound,
    )


def campaign_digest_for(nonce: str) -> str:
    """The lane's own campaign digest for one nonce, computed by the lane."""
    return campaign_digest(compile_request_bytes_campaign(PROJECT, DATABASE, nonce))


def permission_bindings(plan, source_commit, artifact_digest, inputs, baseline=None):
    """Required non-authorizing fields for an independently supplied permission.

    When a derived production baseline is supplied, the values the repository
    cannot recompute are required to equal what a named production observation
    produced. A literal that no recorded observation produces is refused here,
    offline, rather than after a run spends its budget discovering it.
    """
    canonical = plan_compiler(plan["nonce"])
    if digest(plan) != digest(canonical):
        raise ValueError("fixed production project/database required")
    published_budget = budget_document()["budget"]
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
        "campaignDigest": campaign_digest_for(plan["nonce"]),
        "budget": budget(),
        "ledgerBudget": ledger_budget(),
        "ownedScope": plan["ownedScope"],
        "ownedResourceCount": plan["ownedResourceCount"],
        # `wallSeconds` is the name the shared admission core checks; the
        # gatekeeper's `campaignSeconds` is the same number under its own name,
        # carried so both readings are explicit rather than assumed equal.
        "wallSeconds": campaign_seconds(),
        "campaignSeconds": campaign_seconds(),
        "recoverySeconds": recovery_seconds(),
        "perRequestTimeoutSeconds": transport_deadline_seconds(),
        "maxRequestBytes": int(published_budget["maxRequestBytes"]),
        "maxResponseBytes": int(published_budget["maxResponseBytes"]),
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
            "tokeninfoClaims": [
                "issued_to",
                "audience",
                "user_id",
                "email",
                "verified_email",
                "scope",
                "expires_in",
            ],
            "identitySource": "owner-frozen permission; never inferred from tokeninfo",
        },
        "managementContract": management_contract(),
        "productionPreflight": {
            "version": "request-bytes-preflight-v1",
            "managementRequests": 7,
            "credentialIds": ["oauth-tokeninfo"],
            "credentialSlots": ["tokeninfo"],
            "source": PREFLIGHT_ENTRY,
        },
    }
    if baseline is not None:
        required.update(commit_baseline.permission_baseline(baseline))
        required["baselineProvenance"] = baseline["provenance"]
    return required


def descriptor() -> CampaignDescriptor:
    """The request-byte campaign as the shared admission core sees it."""
    window = campaign_seconds() + recovery_seconds()
    if window < MINIMUM_WINDOW_SECONDS:
        raise ValueError("approved window below the campaign minimum")
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
