"""One-host, fixed-queue local admission. No production authorization is implied.

The lock covers transport completion: two scenario slots, one in-flight HTTP call.
An interrupted callback leaves a durable uncertain marker and blocks all dispatch.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import math
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

from broad_contract import digest

REQUEST_SECONDS = 13  # 12-second wire deadline plus adapter spacing allowance.
MAX_JOB_SLOTS = 8
# The floor on request spacing and the ceiling on a campaign wall. Named so a
# campaign can import them instead of keeping its own copy: a copied constant is
# how a lane once re-derived this module's charging formula and agreed with a
# Gate that no longer existed.
INTERVAL_FLOOR_SECONDS = 0.25
WALL_CAP_SECONDS = 1200
PHASES = ("observation", "recovery")


def request_seconds(plan, policy=None):
    """The per-request reservation, declared by the campaign or the lane default.

    Thirteen seconds is the Commit lane's wire deadline plus its spacing, not a
    property of every campaign. A plan may declare its own, and a stream plan may
    not, because its policy fixes the number.
    """
    if policy is not None:
        return policy.REQUEST_SECONDS
    if "requestSeconds" not in plan:
        return REQUEST_SECONDS
    return plan["requestSeconds"]


def _valid_request_seconds(plan, policy):
    if "requestSeconds" not in plan:
        return True
    declared = plan["requestSeconds"]
    return (
        policy is None
        and type(declared) in (int, float)
        and not isinstance(declared, bool)
        and math.isfinite(declared)
        and 0 < declared <= plan["wallSeconds"]
    )


def slot_seconds(entry, default):
    """The reservation for one scheduled slot.

    A campaign whose requests are not one population declares the bound per
    slot: a ten-mebibyte upload and a small cleanup read cannot share one
    honest upper bound, and a single plan-wide value would either under-reserve
    the upload or refuse the plan outright.
    """
    # A present-but-malformed value, None included, is refused by `create`, so
    # by the time a slot is dispatched the default only stands in for absence.
    return entry.get("seconds", default)


def job_schedule(job):
    """The campaign-declared dispatch order for one job, or None.

    A job without one keeps the historical order: every observation, then every
    recovery, with recovery a one-way transition. A job with one may interleave
    the two phases, and the Gate then admits only the next unconsumed slot.
    """
    return job.get("schedule")


def _valid_positive(value):
    return (
        type(value) in (int, float)
        and not isinstance(value, bool)
        and math.isfinite(value)
        and value > 0
    )


def published_allocation(plan):
    """The wall and recovery reserve the campaign's budget artifact publishes.

    `create` can prove a plan internally consistent but has no access to the
    artifact the campaign was approved against, so the two could drift: a Gate
    plan reserving 345 seconds of cleanup against a published 300 was admitted
    with nothing to compare them. A campaign that names its published allocation
    here makes that comparison part of admission.

    The binding is the two numbers, not the file. The Gate never reads the
    artifact, so this closes the drift only for a campaign that declares it; the
    place to require the declaration is the O7 admission of the Gate plan.
    """
    return plan.get("publishedAllocation")


def _valid_allocation(plan):
    if "publishedAllocation" not in plan:
        return True
    declared = plan["publishedAllocation"]
    return (
        isinstance(declared, dict)
        and set(declared) == {"wallSeconds", "recoverySeconds"}
        and all(_valid_positive(value) for value in declared.values())
    )


def _within_published(plan):
    declared = published_allocation(plan)
    if declared is None:
        return True
    return (
        plan["wallSeconds"] <= declared["wallSeconds"]
        and plan["recoverySeconds"] <= declared["recoverySeconds"]
    )


def _valid_ceiling(plan):
    if "transportCeilingSeconds" not in plan:
        return True
    return _valid_positive(plan["transportCeilingSeconds"])


def _valid_slot_seconds(entry):
    if "seconds" not in entry:
        return True
    return _valid_positive(entry["seconds"])


def _valid_schedule(job):
    schedule = job_schedule(job)
    if schedule is None:
        return True
    if not isinstance(schedule, list) or any(
        not isinstance(entry, dict)
        or not {"phase", "index"}
        <= set(entry)
        <= {"phase", "index", "seconds", "creates"}
        or entry["phase"] not in PHASES
        or type(entry["index"]) is not int
        or isinstance(entry["index"], bool)
        or not _valid_slot_seconds(entry)
        or ("creates" in entry and type(entry["creates"]) is not bool)
        for entry in schedule
    ):
        return False
    covered = sorted((entry["phase"], entry["index"]) for entry in schedule)
    return covered == sorted(
        (phase, index) for phase in PHASES for index in range(len(job[phase]))
    )


def _stream_policy(plan):
    if plan.get("contract") == "shared-stream-v1":
        if plan.get("protocol") != "firestore-grpc-stream-v1":
            raise ValueError("unknown shared stream protocol")
        import importlib.util

        module_path = Path(__file__).parent / "fs-write-txn" / "stream_bridge.py"
        spec = importlib.util.spec_from_file_location(
            "_shared_stream_policy", module_path
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    if plan.get("protocol") is not None:
        raise ValueError("unexpected shared protocol")
    return None


def typed_absence(status, body):
    error = body.get("error") if isinstance(body, dict) else None
    return (
        type(status) is int
        and status == 404
        and isinstance(error, dict)
        and type(error.get("code")) is int
        and error["code"] == 404
        and error.get("status") == "NOT_FOUND"
    )


def validate_absence_proofs(state, job_name):
    """Validate final typed readback against the registered recovery plan and journal."""
    policy = _stream_policy(state["plan"])
    if policy:
        return policy.validate_absence(state, job_name)
    job = state["jobs"][job_name]
    proofs = job.get("absenceProofs", {})
    if set(proofs) != set(job["resources"]):
        raise ValueError("typed cleanup absence evidence incomplete")
    operations = state["plan"]["jobs"][job_name]["recovery"]
    for resource, proof in proofs.items():
        candidates = [
            index
            for index, operation in enumerate(operations)
            if operation["method"] == "GET"
            and operation["service"] == "firestore"
            and operation["path"] == "/v1/" + resource
        ]
        index = proof.get("eventIndex")
        if (
            not candidates
            or type(index) is not int
            or not 0 <= index < len(state["events"])
        ):
            raise ValueError("typed cleanup absence event missing")
        event = state["events"][index]
        if (
            event.get("job") != job_name
            or event.get("phase") != "recovery"
            or type(event.get("index")) is not int
            or event["index"] != candidates[-1]
            or event.get("requestDigest") != digest(operations[candidates[-1]])
            or event.get("completed") is not True
            or event.get("failure") is not None
            or not typed_absence(event.get("status"), proof.get("body"))
            or event.get("responseDigest") != digest(proof["body"])
        ):
            raise ValueError("typed cleanup absence evidence differs")


def _save(path, state):
    temporary = path / "state.tmp"
    fd = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(fd, "w") as stream:
        json.dump(state, stream, allow_nan=False)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path / "state.json")
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _ceiling_honoured(plan, seconds):
    """A slot whose request carries a body must reserve the declared wire ceiling.

    Without this the per-slot reservation is a convention: an edit could shrink
    the allowance for a ten-mebibyte upload to whatever made the totals fit, and
    the Gate would admit the plan. The ceiling is the campaign's own transport
    deadline, so a slot that can spend it must reserve it.
    """
    if "transportCeilingSeconds" not in plan:
        return True
    ceiling = plan["transportCeilingSeconds"]
    for name, job in plan["jobs"].items():
        schedule = job_schedule(job)
        if schedule is None:
            continue
        for entry in schedule:
            operation = plan["jobs"][name][entry["phase"]][entry["index"]]
            if (
                isinstance(operation, dict)
                and (
                    operation.get("body") is not None
                    or operation.get("bodyRef") is not None
                )
                and slot_seconds(entry, seconds) < ceiling
            ):
                return False
    return True


def _observation_time(plan, seconds):
    """Time the scheduled observation slots reserve, for jobs that declared one."""
    interval = plan["intervalSeconds"]
    total = 0
    for job in plan["jobs"].values():
        schedule = job_schedule(job)
        if schedule is None:
            continue
        total += sum(
            slot_seconds(entry, seconds) + interval
            for entry in schedule
            if entry["phase"] == "observation"
        )
    return total


def creating_slots(plan, job_name):
    """The observation slots of a job that its plan says could write."""
    schedule = job_schedule(plan["jobs"][job_name])
    if schedule is None:
        # Legacy plans omit a schedule and use the fixed observation-then-
        # recovery order. Infer creating slots from the frozen operation shape
        # so uncertain writes remain owned in that format too.
        return {
            index
            for index, operation in enumerate(plan["jobs"][job_name]["observation"])
            if can_create(operation)
        }
    return {
        entry["index"]
        for entry in schedule
        if entry["phase"] == "observation" and entry.get("creates", True) is not False
    }


def creating_outcome(state, job_name):
    """How this job's creating requests ended, read from the journal.

    `"none"` when none was dispatched, `"refused"` when every one that was
    dispatched answered with a typed refusal, and `"unsettled"` otherwise, which
    covers a successful create and, importantly, a request whose answer was
    lost. The classification is by `completed` and status, never by whether a
    creation proof came back: no proof is also what a lost answer looks like.
    """
    indices = creating_slots(state["plan"], job_name)
    if not indices:
        return "unsettled" if indices is None else "none"
    seen = 0
    for event in state["events"]:
        if (
            event.get("job") != job_name
            or event.get("phase") != "observation"
            or event.get("index") not in indices
        ):
            continue
        seen += 1
        # New journals carry the result of the creation-specific response
        # validation.  A received HTTP response is not enough to establish
        # that a conditional write was refused: 5xx responses and malformed
        # success bodies can both follow a server-side write.
        outcome = event.get("creationOutcome")
        if outcome == "refused":
            continue
        if outcome == "created":
            return "unsettled"
        if outcome in ("pending", "unknown"):
            return "unsettled"
        # Archived journals predate creationOutcome.  They cannot carry the
        # response body needed to prove a refusal, so fail closed and retain
        # recovery responsibility instead of inferring it from the status.
        return "unsettled"
    return "refused" if seen else "none"


def unconfirmed_creates(state, job_name):
    """Creating requests this job dispatched whose outcome never came back.

    Derived from the journal at every read rather than kept as a counter, so it
    cannot drift from the events it describes. An event is counted while it is
    open and once it has failed; a typed answer, whether it created or refused,
    settles it.
    """
    indices = creating_slots(state["plan"], job_name)
    if not indices:
        return 0
    return sum(
        1
        for event in state["events"]
        if event.get("job") == job_name
        and event.get("phase") == "observation"
        and event.get("index") in indices
        and event.get("creationOutcome") != "refused"
        and event.get("creationOutcome") != "created"
    )


def abandoned_cleanup_complete(state):
    """The documents an abandoned run created, when every one is proven absent.

    `None` when the state cannot support that claim: a job that dispatched but
    proved no creation, a job with creation proofs that never abandoned or whose
    scheduled cleanup did not run to the end, or one whose typed absence journal
    does not cover exactly its assigned resources. A created document still
    present therefore stays with the owner-attested exit, which is the whole
    point of separating the two.
    """
    created = []
    abandoned_created = False
    for name, job in state["jobs"].items():
        if unconfirmed_creates(state, name):
            # A request that could have written and never confirmed an outcome
            # leaves documents that may exist and cannot be proven absent here.
            return None
        proofs = job.get("creationProofs") or {}
        if not proofs:
            if job.get("complete") is True and job.get("stopReason") is None:
                # A normally completed no-write job may be one member of a
                # campaign whose other job was stopped after creating data. Its
                # terminal state is already proven by Gate.finish(); do not make
                # the abandoned close pretend that this job was abandoned too.
                continue
            if job["observation"] or job["recovery"]:
                # It ran and proved no creation: that is a no-data stop or an
                # uncertain one, and neither is this.
                return None
            continue
        schedule = job_schedule(state["plan"]["jobs"][name])
        if (
            schedule is None
            or job.get("scheduleDone", 0) != len(schedule)
            or job["inflight"]
            or set(proofs) != set(job["resources"])
            or set(job.get("absent") or []) != set(job["resources"])
        ):
            return None
        stopped = job.get("stopReason") is not None
        if not stopped and job.get("complete") is not True:
            # A created job that was neither abandoned nor normally finished
            # has no terminal ownership proof for this close path.
            return None
        abandoned_created = abandoned_created or stopped
        try:
            validate_absence_proofs(state, name)
        except Exception:  # noqa: BLE001 -- any failure to validate means the claim is unsupported
            return None
        created.extend(proofs)
    # The abandoned close is deliberately disjoint from the normal close. A
    # campaign whose created jobs all finished normally must use Ledger.finish;
    # at least one created job must have an explicit stop reason here.
    return sorted(created) if created and abandoned_created else None


def non_creating_dispatches(state):
    """How many data slots ran, when every one of them could not create a document.

    `None` when the state cannot support that claim: any recovery dispatch, a
    job that dispatched without a declared schedule, or a consumed slot the plan
    did not declare non-creating. A slot is treated as creating unless it says
    otherwise, so a campaign that declares nothing keeps the older and stricter
    rule, which is that no data request may have been sent at all.

    The declaration is load-bearing and belongs to the reviewed plan. Empty
    creation proofs are a second line under it, but they only catch a
    mis-declared slot whose creation was conditional.
    """
    plan = state["plan"]
    total = 0
    for name, job in state["jobs"].items():
        if job["recovery"]:
            return None
        if not job["observation"]:
            continue
        schedule = job_schedule(plan["jobs"][name])
        if schedule is None:
            return None
        consumed = schedule[: job.get("scheduleDone", 0)]
        if len(consumed) != job["observation"] or any(
            entry.get("creates", True) is not False for entry in consumed
        ):
            return None
        total += job["observation"]
    return total


def _recovery_time(plan, seconds):
    """Time reserved for cleanup, taken per slot wherever the campaign declared one."""
    interval = plan["intervalSeconds"]
    total = 0
    for job in plan["jobs"].values():
        schedule = job_schedule(job)
        if schedule is None:
            total += len(job["recovery"]) * (seconds + interval)
            continue
        total += sum(
            slot_seconds(entry, seconds) + interval
            for entry in schedule
            if entry["phase"] == "recovery"
        )
    return total


def create(path, plan):
    path = Path(path)
    policy = _stream_policy(plan)
    if policy:
        policy.validate_plan(plan)
    if (
        not _valid_request_seconds(plan, policy)
        or not _valid_ceiling(plan)
        or not _valid_allocation(plan)
        or not _valid_marker(plan)
    ):
        # Checked before they are used, so a malformed value cannot reach arithmetic.
        raise ValueError("invalid shared allocation")
    seconds = request_seconds(plan, policy)
    jobs = plan["jobs"]
    slots = plan.get("jobSlots", 2)
    resources = [r for job in jobs.values() for r in job["resources"]]
    recovery = sum(len(job["recovery"]) for job in jobs.values())
    management_recovery = plan.get("management", {}).get("recovery", [])
    recovery_time = _recovery_time(plan, seconds) + sum(
        item["timeout"] + plan["intervalSeconds"] for item in management_recovery
    )
    recovery += len(management_recovery)
    overhead = plan.get("coordinatorRequests", 0)
    fixed_cost = plan.get("fixedCostMicrousd", 0)
    if (
        plan["contract"]
        not in {"shared-local-v1", "shared-local-v2", "shared-stream-v1"}
        or type(slots) is not int
        or isinstance(slots, bool)
        or not 1 <= slots <= MAX_JOB_SLOTS
        or not 1 <= len(jobs) <= slots
        or not _valid_request_seconds(plan, policy)
        or not _valid_bodies(plan)
        or any(not _valid_schedule(job) for job in jobs.values())
        or not _ceiling_honoured(plan, seconds)
        or not _within_published(plan)
        or not _nonce_scoped(plan)
        or _observation_time(plan, seconds)
        > plan["wallSeconds"] - plan["recoverySeconds"]
        or len(resources) != len(set(resources))
        or not resources
        or not 0 < plan["recoverySeconds"] < plan["wallSeconds"] <= WALL_CAP_SECONDS
        or plan["recoverySeconds"] < recovery_time
        or not math.isfinite(plan["intervalSeconds"])
        or plan["intervalSeconds"] < INTERVAL_FLOOR_SECONDS
        or type(plan["costMicrousd"]) is not int
        or type(plan["observationRequests"]) is not int
        or plan["observationRequests"] < 0
        or type(plan["requestCostMicrousd"]) is not int
        or plan["requestCostMicrousd"] <= 0
        or type(fixed_cost) is not int
        or fixed_cost < 0
        or type(overhead) is not int
        or not 0 <= overhead <= 2
        or plan["costMicrousd"]
        < fixed_cost + (recovery + overhead) * plan["requestCostMicrousd"]
    ):
        raise ValueError("invalid shared allocation")
    _resolve_all_aliases(plan)
    _check_creates_declarations(plan)
    path.mkdir(mode=0o700, parents=True, exist_ok=False)
    (path / "lock").touch(mode=0o600, exist_ok=False)
    state = {
        "plan": plan,
        "planDigest": digest(plan),
        "started": time.monotonic(),
        "total": overhead,
        "observation": 0,
        "recovery": 0,
        "reservedRecovery": recovery,
        "costMicrousd": fixed_cost + overhead * plan["requestCostMicrousd"],
        "lastSent": 0,
        "stopped": False,
        "coordinatorPid": os.getpid(),
        "coordinatorDone": 0,
        "managementUsed": [],
        "managementEvents": [],
        "coordinatorInflight": False,
        "events": [],
        "jobs": {},
    }
    for key, job in jobs.items():
        state["jobs"][key] = {
            "resources": job["resources"],
            "pid": None,
            "stopped": False,
            "inflight": False,
            "observation": 0,
            "recovery": 0,
            "owned": [],
            "creationProofs": {},
            "absent": [],
            "captures": {},
            "complete": False,
        }
        if job_schedule(job) is not None:
            state["jobs"][key]["skippedByStop"] = 0
            # Only a scheduled job carries a cursor, so every existing campaign's
            # job row keeps the exact shape its archived receipts record.
            state["jobs"][key]["scheduleDone"] = 0
    _save(path, state)


MARKER_BINDINGS = ("resource-name", "nonce")
BODY_REFERENCE_FIELDS = {"sha256", "bytes"}


def canonical_body_bytes(body):
    """The exact wire bytes of a request body, as the campaigns encode them."""
    return json.dumps(
        body, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def body_reference(body):
    """What a plan carries in place of a body too large to embed.

    A campaign that probes a ten-mebibyte request cannot put three of those in a
    plan that a bounded receipt has to carry, so the plan carries the digest and
    the length instead. The reference enters the digested plan, so the plan digest
    still binds the exact bytes, and `dispatch` refuses a body that does not
    reproduce it.
    """
    encoded = canonical_body_bytes(body)
    return {"sha256": hashlib.sha256(encoded).hexdigest(), "bytes": len(encoded)}


def _valid_body_reference(operation):
    reference = operation.get("bodyRef")
    if reference is None:
        return True
    return (
        isinstance(reference, dict)
        and set(reference) == BODY_REFERENCE_FIELDS
        and isinstance(reference["sha256"], str)
        and re.fullmatch(r"[0-9a-f]{64}", reference["sha256"]) is not None
        and type(reference["bytes"]) is int
        and not isinstance(reference["bytes"], bool)
        and reference["bytes"] > 0
        # A slot carries its body one way or the other, never both.
        and operation.get("body") is None
    )


def _valid_bodies(plan):
    """Every reference is well formed, and nothing oversized is carried inline."""
    threshold = plan.get("bodyReferenceThresholdBytes")
    if threshold is not None and (
        type(threshold) is not int or isinstance(threshold, bool) or threshold <= 0
    ):
        return False
    for job in plan["jobs"].values():
        for phase in PHASES:
            for operation in job[phase]:
                if not isinstance(operation, dict) or not _valid_body_reference(
                    operation
                ):
                    return False
                body = operation.get("body")
                if (
                    threshold is not None
                    and body is not None
                    and len(canonical_body_bytes(body)) > threshold
                ):
                    return False
    return True


# Why a slot was consumed without a wire call. Each names a fact from the
# journal, never the absence of a creation proof: "no proof" is also what a lost
# answer looks like, and that one must never be skippable.
NEVER_DISPATCHED_REASON = "creating-slot-never-dispatched"
REFUSED_CREATE_REASON = "skipped-refused-create"
ZERO_WIRE_REASON = "no-creation-proof"
GATE_SKIP_REASONS = (
    NEVER_DISPATCHED_REASON,
    REFUSED_CREATE_REASON,
    ZERO_WIRE_REASON,
)
MAX_STOP_REASON = 128


def can_create(operation):
    """Whether a request could bring a document into existence.

    The Ledger relaxes its retirement contract on a slot declared `creates`
    false, so the declaration is not the campaign's word alone: a plan whose
    slot could write is refused here. A request that carries a body is treated
    as able to create even when its shape is not one this module recognises,
    because the conservative direction is to refuse the declaration.
    """
    if not isinstance(operation, dict):
        return True
    path = operation.get("path")
    path = path if isinstance(path, str) else ""
    method = operation.get("method")
    body = operation.get("body")
    # A transform is non-creating only when every write is explicitly bound
    # to an existing document. Keep malformed or mixed batches conservative:
    # an incomplete precondition must retain ownership for recovery.
    if (
        isinstance(body, dict)
        and isinstance(body.get("writes"), list)
        and body["writes"]
        and all(
            isinstance(write, dict)
            and isinstance(write.get("transform"), dict)
            and write.get("currentDocument") == {"exists": True}
            for write in body["writes"]
        )
    ):
        return False
    return (
        body is not None
        or operation.get("bodyRef") is not None
        or (method == "PATCH" and path.endswith("?currentDocument.exists=false"))
        or (method == "POST" and path.endswith((":batchWrite", ":commit")))
    )


def _check_creates_declarations(plan):
    for job in plan["jobs"].values():
        schedule = job_schedule(job)
        if schedule is None:
            continue
        for entry in schedule:
            if entry.get("creates", True) is False and can_create(
                job[entry["phase"]][entry["index"]]
            ):
                raise ValueError(
                    "a slot whose request can create cannot declare creates false"
                )


def ownership_marker(plan):
    """How a created document proves it belongs to this campaign's owned namespace.

    The `shared-local-v2` convention is that a document names itself in
    `_sharedOwner`. A campaign whose documents are sized to the byte cannot add a
    field to carry that shape, so it may declare its own marker instead: a field
    and whether the value binds the resource name or the campaign nonce. A plan
    that declares nothing keeps the convention its contract implies.

    A nonce binding is weaker than a self-naming one: it proves the document came
    from this campaign, not that it is the document the request named. It is
    adequate only because the resource must also be in the job's assigned
    resources and under the nonce-scoped path, and that is worth a reviewer's
    attention rather than an assumption.
    """
    declared = plan.get("ownershipMarker")
    if declared is None:
        if plan["contract"] == "shared-local-v2":
            return "_sharedOwner", "resource-name"
        return None
    return declared["field"], declared["binding"]


def _nonce_scoped(plan):
    """Every assigned resource must carry the nonce that the marker binds to.

    The nonce binding proves a document came from this campaign, not that it is
    the document the request named. It is adequate only because the resource is
    also under the nonce-scoped path, so that part is checked rather than
    assumed.
    """
    marker = ownership_marker(plan)
    if marker is None or marker[1] != "nonce":
        return True
    segment = "/" + plan["nonce"] + "/"
    return all(
        isinstance(name, str) and segment in "/" + name + "/"
        for job in plan["jobs"].values()
        for name in job["resources"]
    )


def _valid_marker(plan):
    if "ownershipMarker" not in plan:
        return True
    declared = plan["ownershipMarker"]
    return (
        isinstance(declared, dict)
        and set(declared) == {"field", "binding"}
        and isinstance(declared["field"], str)
        and bool(declared["field"])
        and declared["binding"] in MARKER_BINDINGS
        and (declared["binding"] != "nonce" or isinstance(plan.get("nonce"), str))
    )


def resolve_version_source(operations, index, source):
    """The capture index a recovery slot reads its version from.

    A numeric `versionFrom` is canonical and names the slot directly. A named one
    is an alias for the kind of the earlier slot that captured the version,
    resolved within the same resource, so a campaign with one ownership read per
    document does not hard-code an index per document. It must resolve to exactly
    one earlier slot of that kind for that resource, or the plan is refused.
    """
    if source is None or type(source) is int:
        return source
    resource = operations[index].get("resource")
    if not isinstance(source, str) or not source or not isinstance(resource, str):
        raise ValueError("version source alias must name a kind and a resource")
    matches = [
        position
        for position, candidate in enumerate(operations[:index])
        if candidate.get("kind") == source and candidate.get("resource") == resource
    ]
    if len(matches) != 1:
        raise ValueError("version source alias must resolve to exactly one slot")
    return matches[0]


def _resolve_all_aliases(plan):
    for job in plan["jobs"].values():
        operations = job["recovery"]
        for index, operation in enumerate(operations):
            if isinstance(operation, dict):
                resolve_version_source(operations, index, operation.get("versionFrom"))


def _creation_proofs(operation, status, body, job, plan):
    """Only exact conditional-create acknowledgements grant destructive authority."""
    if status != 200 or operation["service"] != "firestore":
        return []
    request = operation.get("body")
    candidates = []
    if operation["method"] == "PATCH" and operation["path"].endswith(
        "?currentDocument.exists=false"
    ):
        name = operation["path"].split("?", 1)[0].removeprefix("/v1/")
        if not isinstance(body, dict) or body.get("name") != name:
            raise ValueError("conditional creation identity mismatch")
        fields = request.get("fields") if isinstance(request, dict) else None
        if digest(body.get("fields")) != digest(fields):
            raise ValueError("conditional creation fields mismatch")
        candidates.append((name, fields, body.get("updateTime")))
    elif operation["method"] == "POST" and operation["path"].endswith(":commit"):
        # A Commit is atomic: a 200 means every write in it applied, so there is
        # no per-write status to read, only one update version per write.
        writes = request.get("writes", []) if isinstance(request, dict) else []
        conditional = [
            write
            for write in writes
            if isinstance(write, dict)
            and write.get("currentDocument") == {"exists": False}
        ]
        if not conditional:
            return []
        results = body.get("writeResults") if isinstance(body, dict) else None
        if not isinstance(results, list) or len(results) != len(writes):
            raise ValueError("conditional commit acknowledgement incomplete")
        for write, result in zip(writes, results, strict=True):
            if (
                not isinstance(write, dict)
                or write.get("currentDocument", {}).get("exists") is not False
                or digest(write.get("currentDocument")) != digest({"exists": False})
            ):
                continue
            update = write.get("update", {})
            if not isinstance(update, dict) or not isinstance(result, dict):
                raise ValueError("conditional commit creation body mismatch")  # noqa: TRY004 -- Gate admission uses ValueError.
            candidates.append(
                (update.get("name"), update.get("fields"), result.get("updateTime"))
            )
    elif operation["method"] == "POST" and operation["path"].endswith(":batchWrite"):
        writes = request.get("writes", []) if isinstance(request, dict) else []
        conditional = [
            write
            for write in writes
            if isinstance(write, dict)
            and write.get("currentDocument") == {"exists": False}
            and write["currentDocument"]["exists"] is False
        ]
        if not conditional:
            return []
        statuses = body.get("status") if isinstance(body, dict) else None
        results = body.get("writeResults") if isinstance(body, dict) else None
        if (
            not isinstance(statuses, list)
            or not isinstance(results, list)
            or len(statuses) != len(writes)
            or len(results) != len(writes)
        ):
            raise ValueError("conditional batch creation acknowledgement incomplete")
        for write, result, entry in zip(writes, results, statuses, strict=True):
            # google.rpc.Status omits its protobuf-default zero on production success.
            if not isinstance(entry, dict) or type(entry.get("code", 0)) is not int:
                raise ValueError("typed conditional batch status required")
            if (
                not isinstance(write, dict)
                or write.get("currentDocument", {}).get("exists") is not False
                or digest(write.get("currentDocument")) != digest({"exists": False})
                or entry.get("code", 0) != 0
            ):
                continue
            update = write.get("update", {})
            if not isinstance(update, dict) or not isinstance(result, dict):
                raise ValueError("conditional batch creation body mismatch")  # noqa: TRY004 -- Gate admission uses ValueError.
            candidates.append(
                (update.get("name"), update.get("fields"), result.get("updateTime"))
            )
    proofs = []
    for name, fields, version in candidates:
        if (
            name not in job["resources"]
            or not isinstance(fields, dict)
            or not isinstance(version, str)
            or not re.fullmatch(
                r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z", version
            )
        ):
            raise ValueError("typed conditional creation resource/version required")
        datetime.fromisoformat(version)
        marker = ownership_marker(plan)
        if marker is not None:
            field, binding = marker
            expected = (
                {"referenceValue": name}
                if binding == "resource-name"
                else {"stringValue": plan["nonce"]}
            )
            if fields.get(field) != expected:
                raise ValueError("conditional creation namespace marker required")
        proofs.append(
            {
                "name": name,
                "updateTime": version,
                "fieldsDigest": digest(fields),
                "requestDigest": digest(operation),
                "responseDigest": digest(body),
            }
        )
    return proofs


def _typed_create_refusal(status, body):
    """Whether a completed create response proves that no write was applied.

    A transport-level status is not a write outcome.  In particular, a 500 or
    504 can be returned after the server has committed the write.  The shared
    Gate only treats the narrow, typed request rejection used by the reviewed
    boundary campaigns as a refusal; every other response remains recoverable
    as an outcome-unknown create.
    """
    error = body.get("error") if isinstance(body, dict) else None
    return (
        type(status) is int
        and status == 400
        and isinstance(error, dict)
        and type(error.get("code")) is int
        and error.get("code") == 400
        and error.get("status") == "INVALID_ARGUMENT"
    )


class Gate:
    def __init__(self, path, job):
        self.path, self.job = Path(path), job
        self.plan_digest = self.snapshot()["planDigest"]

    @contextlib.contextmanager
    def locked(self):
        # Never recreate missing state/lock: no unmanaged fallback or reset.
        if self.path.stat().st_mode & 0o077 or any(
            (self.path / name).is_symlink() for name in ("lock", "state.json")
        ):
            raise ValueError("private regular gate files required")
        with (self.path / "lock").open("r+") as stream:
            wait_until = time.monotonic() + 15
            while True:
                try:
                    fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= wait_until:
                        raise ValueError("gate lock deadline") from None
                    time.sleep(0.01)
            state = json.loads((self.path / "state.json").read_bytes())
            if digest(state["plan"]) != state["planDigest"] or state[
                "planDigest"
            ] != getattr(self, "plan_digest", state["planDigest"]):
                raise ValueError("shared plan changed")
            yield state

    def snapshot(self):
        with self.locked() as state:
            return state

    def coordinator_call(self, index, send):
        """Two prepaid local ownership-control calls, before worker claims."""
        with self.locked() as state:
            if (
                state.get("noDataAbort") is not None
                or state["coordinatorPid"] != os.getpid()
                or state["coordinatorInflight"]
                or index != state["coordinatorDone"]
                or index >= state["plan"].get("coordinatorRequests", 0)
                or any(job["pid"] is not None for job in state["jobs"].values())
            ):
                raise ValueError("coordinator admission")
            delay = max(
                0,
                state["lastSent"] + state["plan"]["intervalSeconds"] - time.monotonic(),
            )
            time.sleep(delay)
            if (
                time.monotonic() + REQUEST_SECONDS
                > state["started"]
                + state["plan"]["wallSeconds"]
                - state["plan"]["recoverySeconds"]
            ):
                raise ValueError("coordinator deadline")
            state["coordinatorInflight"] = True
            _save(self.path, state)
            try:
                result = send()
            except BaseException:
                state["stopped"] = True
                _save(self.path, state)
                raise
            state["coordinatorInflight"] = False
            state["coordinatorDone"] += 1
            state["lastSent"] = time.monotonic()
            state.setdefault("coordinatorResults", []).append(
                {"index": index, "status": result[0], "ended": state["lastSent"]}
            )
            _save(self.path, state)
            return result

    def claim(self):
        with self.locked() as state:
            job = state["jobs"][self.job]
            if (
                state.get("noDataAbort") is not None
                or job["pid"] is not None
                or job["complete"]
            ):
                raise ValueError("job already claimed; ownership retained")
            job["pid"] = os.getpid()
            _save(self.path, state)

    def skip_scheduled_slot(self, operation, recovery, reason):
        """Consume the next scheduled slot without a wire send.

        A campaign whose creating request was refused has nothing to delete, and
        its collector sends nothing for those slots by design. The Gate keeps its
        own cursor, so without this the schedule stalls behind the slot that will
        never be sent and every later request is refused as out of order.

        Admitted only when the slot itself cannot have written, when the resource
        it names has no creation proof, and when no earlier request that could
        have written is still unconfirmed. Those are facts the Gate holds, so the
        skip is checkable rather than taken on the caller's word.
        """
        if not isinstance(reason, str) or not 0 < len(reason) <= MAX_STOP_REASON:
            raise ValueError("bounded skip reason required")
        with self.locked() as state:
            job, plan = state["jobs"][self.job], state["plan"]
            phase = "recovery" if recovery else "observation"
            schedule = job_schedule(plan["jobs"][self.job])
            if (
                job["pid"] != os.getpid()
                or job["complete"]
                or job["inflight"]
                or state.get("noDataAbort") is not None
            ):
                raise ValueError("job or environment stopped/uncertain")
            if schedule is None:
                raise ValueError("a declared schedule is required to skip a slot")
            if unconfirmed_creates(state, self.job):
                # Checked before the cursor moves, so a refused skip changes
                # nothing.
                raise ValueError("an unconfirmed write is outstanding")
            index = job[phase]
            cursor = job["scheduleDone"]
            if job.get("stopReason") is not None:
                while (
                    cursor < len(schedule)
                    and schedule[cursor]["phase"] == "observation"
                ):
                    cursor += 1
                    job["skippedByStop"] += 1
                job["scheduleDone"] = cursor
            slot = schedule[cursor] if cursor < len(schedule) else None
            if (
                slot is None
                or slot["phase"] != phase
                or slot["index"] != index
                or index >= len(plan["jobs"][self.job][phase])
            ):
                raise ValueError("dispatch outside the frozen execution schedule")
            if slot.get("creates", True) is not False:
                raise ValueError("a slot that could have written cannot be skipped")
            expected = dict(plan["jobs"][self.job][phase][index])
            expected.pop("versionFrom", None)
            if digest(operation) != digest(expected):
                raise ValueError("request outside closed scenario")
            resource = operation["path"].split("?", 1)[0].removeprefix("/v1/")
            if resource in job.get("creationProofs", {}):
                raise ValueError("a created resource must be cleaned, not skipped")
            job["scheduleDone"] += 1
            job[phase] += 1
            if recovery:
                state["reservedRecovery"] -= 1
            state.setdefault("skips", []).append(
                {
                    "job": self.job,
                    "index": index,
                    "reason": ZERO_WIRE_REASON,
                    "note": reason,
                }
            )
            _save(self.path, state)
            return (None, {"skipped": ZERO_WIRE_REASON})

    def abandon_observation(self, reason):
        """End this job's observation early and open its scheduled cleanup.

        With a declared schedule a dispatch is admitted only in its frozen order,
        so a job that stops part way through observation could not reach its own
        recovery slots at all: every cleanup request was refused as outside the
        schedule, and a probe that had created documents had no admissible way to
        delete them. This is the transition that says the observation is over.

        It does not weaken the cleanup rules. Recovery still runs in its declared
        order, and a resource with no creation proof is still never deleted: its
        slots become zero-wire skips rather than refusals, so the ones that can
        be cleaned are still reachable behind them.
        """
        if not isinstance(reason, str) or not 0 < len(reason) <= MAX_STOP_REASON:
            raise ValueError("bounded stop reason required")
        with self.locked() as state:
            job = state["jobs"][self.job]
            if state.get("noDataAbort") is not None or job["complete"]:
                raise ValueError("terminal Gate abort")
            if job_schedule(state["plan"]["jobs"][self.job]) is None:
                raise ValueError("a declared schedule is required to abandon")
            if job.get("stopReason") is not None:
                raise ValueError("observation already abandoned")
            if job["inflight"]:
                raise ValueError("in-flight request; ownership retained")
            job["stopReason"] = reason
            job["stopped"] = True
            _save(self.path, state)

    def stop(self, *, environment=False):
        with self.locked() as state:
            if state.get("noDataAbort") is not None:
                raise ValueError("terminal Gate abort")
            state["jobs"][self.job]["stopped"] = True
            if environment:
                state["stopped"] = True
            _save(self.path, state)

    def _validate_cleanup_ownership(self, operation, recovery, resource, source, job):
        """Validate the immutable creation proof for a conditional cleanup."""
        proof = job.get("creationProofs", {}).get(resource)
        capture = job["captures"].get(str(source), {})
        if (
            not recovery
            or proof is None
            or capture.get("name") != resource
            or capture.get("fieldsDigest") != proof["fieldsDigest"]
            or operation["path"]
            != "/v1/"
            + resource
            + "?currentDocument.updateTime="
            + quote(proof["updateTime"], safe="")
        ):
            raise ValueError("cleanup requires journaled creation ownership/version")

    def _recovery_capture(self, operation, status, body):
        """Return the bounded default recovery read receipt."""
        return {
            "status": status,
            "name": body.get("name") if isinstance(body, dict) else None,
            "fieldsDigest": digest(body.get("fields"))
            if isinstance(body, dict)
            else None,
            "updateTime": body.get("updateTime") if isinstance(body, dict) else None,
        }

    def dispatch(self, operation, recovery, send):
        with self.locked() as state:
            job, plan = state["jobs"][self.job], state["plan"]
            phase = "recovery" if recovery else "observation"
            if (
                job["pid"] != os.getpid()
                or job["complete"]
                or state["coordinatorInflight"]
                or state["coordinatorDone"] != plan.get("coordinatorRequests", 0)
                or any(j["inflight"] for j in state["jobs"].values())
                or state.get("noDataAbort") is not None
                or (not recovery and (job["stopped"] or state["stopped"]))
            ):
                raise ValueError("job or environment stopped/uncertain")
            operations = plan["jobs"][self.job][phase]
            index = job[phase]
            if index >= len(operations):
                raise ValueError("scenario request capacity")
            schedule = job_schedule(plan["jobs"][self.job])
            if schedule is not None:
                cursor = job["scheduleDone"]
                if job.get("stopReason") is not None:
                    # The abandoned observation slots are consumed without a wire
                    # call, so the cleanup behind them becomes reachable.
                    while (
                        cursor < len(schedule)
                        and schedule[cursor]["phase"] == "observation"
                    ):
                        cursor += 1
                        job["skippedByStop"] += 1
                    job["scheduleDone"] = cursor
                slot = schedule[cursor] if cursor < len(schedule) else None
                if slot is None or slot["phase"] != phase or slot["index"] != index:
                    raise ValueError("dispatch outside the frozen execution schedule")
            policy = _stream_policy(plan)
            seconds = request_seconds(plan, policy)
            if schedule is not None:
                seconds = slot_seconds(slot, seconds)
            if policy:
                expected, resource, skip = policy.resolve(state, self.job, recovery)
                source = "stream-guard" if skip else None
                valid_version = False
                if digest(operation) != digest(expected):
                    raise ValueError("request outside closed stream scenario")
            else:
                expected = dict(operations[index])
                source = resolve_version_source(
                    operations, index, expected.pop("versionFrom", None)
                )
                reference = expected.pop("bodyRef", None)
                if reference is not None:
                    # Verify the buffer that was handed in, and let the caller
                    # send that same object: the Gate never re-reads a body from
                    # a path, so there is exactly one copy of these bytes.
                    encoded = canonical_body_bytes(operation.get("body"))
                    if (
                        len(encoded) != reference["bytes"]
                        or hashlib.sha256(encoded).hexdigest() != reference["sha256"]
                    ):
                        raise ValueError(
                            "request body differs from its frozen reference"
                        )
                    expected["body"] = operation.get("body")
                valid_version = False
                if source is not None:
                    capture = job["captures"].get(str(source))
                    valid_version = bool(
                        capture
                        and type(capture["status"]) is int
                        and capture["status"] == 200
                        and isinstance(capture.get("updateTime"), str)
                        and capture["updateTime"]
                    )
                    if valid_version:
                        version = capture.get("updateTime")
                        expected["path"] += "?currentDocument.updateTime=" + quote(
                            version, safe=""
                        )
                if digest(operation) != digest(expected):
                    raise ValueError("request outside closed scenario")
                resource = operation["path"].split("?", 1)[0].removeprefix("/v1/")
                if recovery and resource not in job["resources"]:
                    raise ValueError("cleanup target outside assigned resources")
                if operation["method"] == "DELETE" and (
                    source is None or valid_version
                ):
                    self._validate_cleanup_ownership(
                        operation, recovery, resource, source, job
                    )
            skip_reason = None
            if (
                recovery
                and schedule is not None
                and not unconfirmed_creates(state, self.job)
                and resource not in job.get("creationProofs", {})
            ):
                outcome = creating_outcome(state, self.job)
                if job.get("stopReason") is not None and outcome != "unsettled":
                    # The run is over, so no slot of an uncreated resource is
                    # worth a request.
                    skip_reason = (
                        NEVER_DISPATCHED_REASON
                        if outcome == "none"
                        else REFUSED_CREATE_REASON
                    )
                elif outcome == "refused" and source is not None:
                    # The normal path: the create was refused, so this delete has
                    # no version to bind and nothing to remove. The readbacks
                    # around it still run, because absence is what they prove.
                    skip_reason = REFUSED_CREATE_REASON
            if skip_reason is not None:
                # Nothing was created here, so there is nothing to clean and no
                # request to spend; the slot is consumed so the next one is
                # reachable.
                # `skippedByStop` counts only the observation slots the stop
                # passed over; a skipped recovery slot is already counted in
                # `job["recovery"]`, so counting it twice would break the
                # cursor invariant the no-data contract checks.
                job["scheduleDone"] += 1
                job[phase] += 1
                state["reservedRecovery"] -= 1
                state.setdefault("skips", []).append(
                    {"job": self.job, "index": index, "reason": skip_reason}
                )
                _save(self.path, state)
                return (None, {"skipped": skip_reason})
            if recovery and schedule is None:
                # Without a declared schedule, recovery is a one-way transition.
                # A scheduled campaign returns to observation by its own order,
                # which the cursor above is what admits.
                job["stopped"] = True
            if source is not None and not valid_version:
                job[phase] += 1
                if schedule is not None:
                    job["scheduleDone"] += 1
                state["reservedRecovery"] -= 1
                state.setdefault("skips", []).append(
                    {
                        "job": self.job,
                        "index": index,
                        "reason": "absent-or-unavailable-cleanup-read",
                    }
                )
                _save(self.path, state)
                return (
                    {"skipped": skip}
                    if policy
                    else (None, {"skipped": "absent-or-unavailable-cleanup-read"})
                )
            now = time.monotonic()
            delay = max(0, state["lastSent"] + plan["intervalSeconds"] - now)
            deadline = (
                state["started"]
                + plan["wallSeconds"]
                - (0 if recovery else plan["recoverySeconds"])
            )
            cost = plan["requestCostMicrousd"]
            remaining = state["reservedRecovery"] - (1 if recovery else 0)
            if (
                now + delay + seconds > deadline
                or (
                    not recovery and state["observation"] >= plan["observationRequests"]
                )
                or state["costMicrousd"] + cost * (1 + remaining) > plan["costMicrousd"]
            ):
                raise ValueError("global phase/time/cost capacity")
            time.sleep(delay)
            if time.monotonic() + seconds > deadline:
                raise ValueError("deadline after rate wait")
            if policy:
                policy.debit(state, job, operation)
            state["lastSent"] = time.monotonic()
            state["total"] += 1
            state[phase] += 1
            state["reservedRecovery"] = remaining
            state["costMicrousd"] += cost
            job[phase] += 1
            if schedule is not None:
                job["scheduleDone"] += 1
            if recovery and resource in job["absent"]:
                job["absent"].remove(resource)
            if recovery:
                job.setdefault("absenceProofs", {}).pop(resource, None)
            job["inflight"] = True
            event = {
                "job": self.job,
                "phase": phase,
                "index": index,
                "started": state["lastSent"],
                "requestDigest": digest(operation),
                "service": operation["service"],
                "method": operation["method"],
                "completed": False,
            }
            if not recovery and index in (creating_slots(plan, self.job) or ()):
                # Keep this pending until the response body has been checked.
                # A complete HTTP response alone does not settle a conditional
                # create: the server may have applied it before a 5xx or a
                # malformed acknowledgement was returned.
                event["creationOutcome"] = "pending"
            state["events"].append(event)
            _save(
                self.path, state
            )  # crash spends capacity and retains uncertain ownership
            try:
                result = send()
            except Exception as error:
                job["stopped"] = True
                event["failure"] = type(error).__name__
                raise
            else:
                if policy:
                    policy.record(state, self.job, operation, result, event)
                    return result
                status, body = result
                event.update(status=status, responseDigest=digest(body), completed=True)
                if type(status) is not int:
                    if not recovery and "creationOutcome" in event:
                        event["creationOutcome"] = "unknown"
                    job["stopped"] = True
                    raise ValueError("typed HTTP status required")
                if not recovery:
                    try:
                        proofs = _creation_proofs(operation, status, body, job, plan)
                    except ValueError:
                        if "creationOutcome" in event:
                            event["creationOutcome"] = "unknown"
                        job["stopped"] = True
                        raise
                    if "creationOutcome" in event:
                        if proofs:
                            event["creationOutcome"] = "created"
                        elif _typed_create_refusal(status, body):
                            event["creationOutcome"] = "refused"
                        else:
                            event["creationOutcome"] = "unknown"
                    for proof in proofs:
                        # Never replace a creation version with a later read or write.
                        job["creationProofs"].setdefault(proof["name"], proof)
                        if proof["name"] not in job["owned"]:
                            job["owned"].append(proof["name"])
                if operation["method"] == "GET" and resource in job["resources"]:
                    if status == 404:
                        if not typed_absence(status, body):
                            job["stopped"] = True
                            raise ValueError("typed Firestore absence required")
                        if recovery:
                            if resource not in job["absent"]:
                                job["absent"].append(resource)
                            job.setdefault("absenceProofs", {})[resource] = {
                                "eventIndex": len(state["events"]) - 1,
                                "body": body,
                            }
                    elif status == 200 and (
                        not isinstance(body, dict)
                        or body.get("name") != resource
                        or not isinstance(body.get("fields"), dict)
                    ):
                        job["stopped"] = True
                        raise ValueError("readback identity/body mismatch")
                if recovery:
                    job["captures"][str(index)] = self._recovery_capture(
                        operation, status, body
                    )
                return result
            finally:
                # Normal exception paths have returned from bounded transport. A killed
                # process never reaches here: its marker blocks every successor dispatch.
                interruption = sys.exc_info()[0]
                job["inflight"] = interruption is not None and (
                    policy is not None or not issubclass(interruption, Exception)
                )
                event["ended"] = time.monotonic()
                state["lastSent"] = event["ended"]
                _save(self.path, state)

    def finish(self):
        with self.locked() as state:
            job = state["jobs"][self.job]
            if (
                state.get("noDataAbort") is not None
                or job["pid"] != os.getpid()
                or job["inflight"]
                or unconfirmed_creates(state, self.job)
                or job["recovery"] != len(state["plan"]["jobs"][self.job]["recovery"])
                or set(job["absent"]) != set(job["resources"])
            ):
                raise ValueError("cleanup incomplete; ownership retained")
            if _stream_policy(state["plan"]):
                validate_absence_proofs(state, self.job)
            job["complete"] = True
            _save(self.path, state)

    def abort_no_data(self, plan_digest, pre_gate_digest, record_digest):
        """Stop all Gate paths after a bound, empty data journal is verified."""
        with self.locked() as state:
            existing = state.get("noDataAbort")
            if existing is not None:
                if existing != {
                    "preGateDigest": pre_gate_digest,
                    "recordDigest": record_digest,
                }:
                    raise ValueError("different Gate abort proof")
                return state
            if digest(state) != pre_gate_digest or state["planDigest"] != plan_digest:
                raise ValueError("Gate abort snapshot changed")
            dispatched = non_creating_dispatches(state)
            if (
                state["coordinatorInflight"] is not False
                or dispatched is None
                or len(state["events"]) != dispatched
                or any(
                    skip.get("reason") not in GATE_SKIP_REASONS
                    for skip in state.get("skips", [])
                )
                or state.get("managementUsed")
                != [
                    "observation:" + operation["id"]
                    for operation in state["plan"]
                    .get("management", {})
                    .get("observation", [])
                ][: len(state.get("managementUsed", []))]
                or [event.get("id") for event in state.get("managementEvents", [])]
                != state.get("managementUsed", [])
                or state["total"] != len(state.get("managementUsed", [])) + dispatched
                or state["observation"] != state["total"]
                or state["observation"] > state["plan"]["observationRequests"]
                or state["costMicrousd"]
                != state["plan"].get("fixedCostMicrousd", 0)
                + state["total"] * state["plan"]["requestCostMicrousd"]
                or state["recovery"] != 0
                or state["coordinatorDone"] != 0
                or any(
                    type(job[key]) is not int
                    for job in state["jobs"].values()
                    for key in ("observation", "recovery")
                )
                or any(
                    job.get("scheduleDone", 0)
                    != job["observation"]
                    + job["recovery"]
                    + job.get("skippedByStop", 0)
                    for job in state["jobs"].values()
                )
                or any(
                    job["inflight"] is not False
                    or job["owned"] != []
                    or job["creationProofs"] != {}
                    or job["absent"] != []
                    or job["captures"] != {}
                    or job["complete"] is not False
                    for job in state["jobs"].values()
                )
            ):
                raise ValueError("positive or uncertain data Gate evidence")
            pids = [
                state["coordinatorPid"],
                *[job["pid"] for job in state["jobs"].values()],
            ]
            for pid in pids:
                if type(pid) is not int or pid <= 0:
                    raise ValueError("recorded worker identity required")
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    continue
                raise ValueError("worker exit not proven")
            state["stopped"] = True
            for job in state["jobs"].values():
                job["stopped"] = True
            state["noDataAbort"] = {
                "preGateDigest": pre_gate_digest,
                "recordDigest": record_digest,
            }
            _save(self.path, state)
            return state

    def adapter_request(self, adapter, operation, send):
        if not adapter.local:
            raise ValueError("shared gate is local-only; production permission absent")

        plan = self.snapshot()["plan"]
        from batch_adapter import observer_digest

        if (
            adapter.local != plan.get("localOrigins")
            or adapter.nonce != plan.get("nonce")
            or observer_digest() != plan.get("observerSha256")
        ):
            raise ValueError("adapter origin/nonce/observer binding mismatch")

        def admitted():
            adapter._shared_dispatch = True
            try:
                return send()
            finally:
                adapter._shared_dispatch = False

        return self.dispatch(operation, adapter.budget.recovery, admitted)
