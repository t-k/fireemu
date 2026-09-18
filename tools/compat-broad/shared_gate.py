"""One-host, fixed-queue local admission. No production authorization is implied.

The lock covers transport completion: two scenario slots, one in-flight HTTP call.
An interrupted callback leaves a durable uncertain marker and blocks all dispatch.
"""

from __future__ import annotations

import contextlib
import fcntl
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
                and operation.get("body") is not None
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
        or any(not _valid_schedule(job) for job in jobs.values())
        or not _ceiling_honoured(plan, seconds)
        or not _within_published(plan)
        or _observation_time(plan, seconds)
        > plan["wallSeconds"] - plan["recoverySeconds"]
        or len(resources) != len(set(resources))
        or not resources
        or not 0 < plan["recoverySeconds"] < plan["wallSeconds"] <= 1200
        or plan["recoverySeconds"] < recovery_time
        or not math.isfinite(plan["intervalSeconds"])
        or plan["intervalSeconds"] < 0.25
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
            # Only a scheduled job carries a cursor, so every existing campaign's
            # job row keeps the exact shape its archived receipts record.
            state["jobs"][key]["scheduleDone"] = 0
    _save(path, state)


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
        if plan["contract"] == "shared-local-v2" and fields.get("_sharedOwner") != {
            "referenceValue": name
        }:
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
                source = expected.pop("versionFrom", None)
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
                    job["stopped"] = True
                    raise ValueError("typed HTTP status required")
                if not recovery:
                    try:
                        proofs = _creation_proofs(operation, status, body, job, plan)
                    except ValueError:
                        job["stopped"] = True
                        raise
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
                or state.get("skips", []) != []
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
                    job.get("scheduleDone", 0) != job["observation"]
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
