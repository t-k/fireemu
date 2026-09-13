"""One-host, fixed-queue local admission. No production authorization is implied.

The lock covers transport completion: two scenario slots, one in-flight HTTP call.
An interrupted callback leaves a durable uncertain marker and blocks all dispatch.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import time
from pathlib import Path

from broad_contract import digest


def _save(path, state):
    temporary = path / "state.tmp"
    with temporary.open("w") as stream:
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
    overhead = plan.get("coordinatorRequests", 0)
    if (
        plan["contract"] != "shared-local-v1"
        or not 1 <= len(jobs) <= 2
        or len(resources) != len(set(resources))
        or not resources
        or not 0 < plan["recoverySeconds"] < plan["wallSeconds"] <= 1200
        or plan["intervalSeconds"] < 0.25
        or type(plan["observationRequests"]) is not int
        or plan["observationRequests"] < 0
        or type(plan["requestCostMicrousd"]) is not int
        or plan["requestCostMicrousd"] <= 0
        or type(overhead) is not int
        or not 0 <= overhead <= 2
        or plan["costMicrousd"] < (recovery + overhead) * plan["requestCostMicrousd"]
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
        "costMicrousd": overhead * plan["requestCostMicrousd"],
        "lastSent": 0,
        "stopped": False,
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
        with (self.path / "lock").open("r+") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            state = json.loads((self.path / "state.json").read_bytes())
            if digest(state["plan"]) != state["planDigest"] or state[
                "planDigest"
            ] != getattr(self, "plan_digest", state["planDigest"]):
                raise ValueError("shared plan changed")
            yield state

    def snapshot(self):
        with self.locked() as state:
            return state

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
            if source is not None:
                capture = job["captures"].get(str(source))
                if not capture or capture["status"] not in (200, 404):
                    raise ValueError("cleanup readback unavailable")
                if capture["status"] == 200:
                    from urllib.parse import quote

                    version = capture.get("updateTime")
                    if not isinstance(version, str) or not version:
                        raise ValueError("cleanup version missing")
                    expected["path"] += "?currentDocument.updateTime=" + quote(
                        version, safe=""
                    )
            if operation != expected:
                raise ValueError("request outside closed scenario")
            resource = operation["path"].split("?", 1)[0].removeprefix("/v1/")
            if recovery and resource not in job["owned"]:
                raise ValueError("cleanup target has no absent-before-use proof")
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
                now + delay + 12 > deadline
                or (
                    not recovery and state["observation"] >= plan["observationRequests"]
                )
                or state["costMicrousd"] + cost * (1 + remaining) > plan["costMicrousd"]
            ):
                raise ValueError("global phase/time/cost capacity")
            time.sleep(delay)
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
                job["inflight"] = False
                event["ended"] = time.monotonic()
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

        def admitted():
            adapter._shared_dispatch = True
            try:
                return send()
            finally:
                adapter._shared_dispatch = False

        return self.dispatch(operation, adapter.budget.recovery, admitted)
