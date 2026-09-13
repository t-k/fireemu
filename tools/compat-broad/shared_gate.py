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
import sys
import time
from pathlib import Path

from broad_contract import digest

REQUEST_SECONDS = 13  # 12-second wire deadline plus adapter spacing allowance.


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


def create(path, plan):
    path = Path(path)
    jobs = plan["jobs"]
    resources = [r for job in jobs.values() for r in job["resources"]]
    recovery = sum(len(job["recovery"]) for job in jobs.values())
    management_recovery = plan.get("management", {}).get("recovery", [])
    recovery_time = recovery * (REQUEST_SECONDS + plan["intervalSeconds"]) + sum(
        item["timeout"] + plan["intervalSeconds"] for item in management_recovery
    )
    recovery += len(management_recovery)
    overhead = plan.get("coordinatorRequests", 0)
    fixed_cost = plan.get("fixedCostMicrousd", 0)
    if (
        plan["contract"] != "shared-local-v1"
        or not 1 <= len(jobs) <= 2
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
            "absent": [],
            "captures": {},
            "complete": False,
        }
    _save(path, state)


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
                state["coordinatorPid"] != os.getpid()
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
            if job["pid"] is not None or job["complete"]:
                raise ValueError("job already claimed; ownership retained")
            job["pid"] = os.getpid()
            _save(self.path, state)

    def stop(self, *, environment=False):
        with self.locked() as state:
            state["jobs"][self.job]["stopped"] = True
            if environment:
                state["stopped"] = True
            _save(self.path, state)

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
                or (not recovery and (job["stopped"] or state["stopped"]))
            ):
                raise ValueError("job or environment stopped/uncertain")
            operations = plan["jobs"][self.job][phase]
            index = job[phase]
            if index >= len(operations):
                raise ValueError("scenario request capacity")
            expected = dict(operations[index])
            source = expected.pop("versionFrom", None)
            valid_version = False
            if source is not None:
                capture = job["captures"].get(str(source))
                valid_version = bool(
                    capture
                    and capture["status"] == 200
                    and isinstance(capture.get("updateTime"), str)
                    and capture["updateTime"]
                )
                if valid_version:
                    from urllib.parse import quote

                    version = capture.get("updateTime")
                    expected["path"] += "?currentDocument.updateTime=" + quote(
                        version, safe=""
                    )
            if digest(operation) != digest(expected):
                raise ValueError("request outside closed scenario")
            resource = operation["path"].split("?", 1)[0].removeprefix("/v1/")
            if recovery and resource not in job["owned"]:
                raise ValueError("cleanup target has no absent-before-use proof")
            if recovery:
                job["stopped"] = True  # Recovery is a one-way transition.
            if source is not None and not valid_version:
                job[phase] += 1
                state["reservedRecovery"] -= 1
                state.setdefault("skips", []).append(
                    {
                        "job": self.job,
                        "index": index,
                        "reason": "absent-or-unavailable-cleanup-read",
                    }
                )
                _save(self.path, state)
                return None, {"skipped": "absent-or-unavailable-cleanup-read"}
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
                now + delay + REQUEST_SECONDS > deadline
                or (
                    not recovery and state["observation"] >= plan["observationRequests"]
                )
                or state["costMicrousd"] + cost * (1 + remaining) > plan["costMicrousd"]
            ):
                raise ValueError("global phase/time/cost capacity")
            time.sleep(delay)
            if time.monotonic() + REQUEST_SECONDS > deadline:
                raise ValueError("deadline after rate wait")
            state["lastSent"] = time.monotonic()
            state["total"] += 1
            state[phase] += 1
            state["reservedRecovery"] = remaining
            state["costMicrousd"] += cost
            job[phase] += 1
            if recovery and resource in job["absent"]:
                job["absent"].remove(resource)
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
                status, body = result
                event.update(status=status, responseDigest=digest(body), completed=True)
                if operation["method"] == "GET" and resource in job["resources"]:
                    if status == 404:
                        if resource not in job["owned"] and not recovery:
                            job["owned"].append(resource)
                        if recovery and resource not in job["absent"]:
                            job["absent"].append(resource)
                    elif status == 200 and (
                        not isinstance(body, dict)
                        or body.get("name") != resource
                        or not isinstance(body.get("fields"), dict)
                    ):
                        job["stopped"] = True
                        raise ValueError("readback identity/body mismatch")
                if recovery:
                    job["captures"][str(index)] = {
                        "status": status,
                        "updateTime": body.get("updateTime")
                        if isinstance(body, dict)
                        else None,
                    }
                return result
            finally:
                # Normal exception paths have returned from bounded transport. A killed
                # process never reaches here: its marker blocks every successor dispatch.
                interruption = sys.exc_info()[0]
                job["inflight"] = interruption is not None and not issubclass(
                    interruption, Exception
                )
                event["ended"] = time.monotonic()
                state["lastSent"] = event["ended"]
                _save(self.path, state)

    def finish(self):
        with self.locked() as state:
            job = state["jobs"][self.job]
            if (
                job["pid"] != os.getpid()
                or job["inflight"]
                or job["recovery"] != len(state["plan"]["jobs"][self.job]["recovery"])
                or set(job["absent"]) != set(job["resources"])
            ):
                raise ValueError("cleanup incomplete; ownership retained")
            job["complete"] = True
            _save(self.path, state)

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
