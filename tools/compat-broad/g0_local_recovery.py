"""Closed local-only recovery driver for the frozen G0 replay.

This lane deliberately uses the existing Gate journal and Adapter transport. It
only replaces the generic creation-proof cleanup predicate for the four
nonce-derived G0 resources; no generic Gate authority is widened.
"""

from __future__ import annotations

import itertools
import hashlib
import json
import multiprocessing as mp
import os
import stat
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import quote

from batch_adapter import Adapter
from batch_contract import candidate
from broad_contract import digest, local_origin
from shared_cases import run_scenario, save
from shared_gate import Gate, _save


def _expected_fields(plan: dict) -> dict[str, object]:
    """Derive the four final field projections from the frozen recipe itself."""
    expected: dict[str, object] = {}
    for job in plan["jobs"].values():
        for operation in job["observation"]:
            body = operation.get("body")
            if operation["method"] == "PATCH" and isinstance(body, dict):
                name = operation["path"].split("?", 1)[0].removeprefix("/v1/")
                fields = body.get("fields")
                if isinstance(name, str) and isinstance(fields, dict):
                    expected.setdefault(name, fields)
                continue
            if operation["method"] != "POST" or not isinstance(body, dict):
                continue
            for write in body.get("writes", []):
                update = write.get("update", {})
                name = update.get("name")
                fields = update.get("fields")
                if isinstance(name, str) and isinstance(fields, dict):
                    expected.setdefault(name, fields)
    if len(expected) != 4 or any("_owner" in fields for fields in expected.values()):
        raise ValueError("g0-frozen-fields-invalid")
    return expected


def _resources(plan: dict) -> set[str]:
    resources = [resource for job in plan["jobs"].values() for resource in job["resources"]]
    if len(resources) != 4 or len(set(resources)) != 4:
        raise ValueError("g0-resource-shape-invalid")
    nonce = plan.get("nonce")
    if not isinstance(nonce, str) or len(nonce) != 32 or any(c not in "0123456789abcdef" for c in nonce):
        raise ValueError("g0-nonce-invalid")
    if any(nonce not in resource for resource in resources):
        raise ValueError("g0-resource-nonce-mismatch")
    return set(resources)


def _bounded_regular_bytes(path: Path, limit: int) -> tuple[bytes, os.stat_result]:
    """Read one immutable regular file without following a substitution symlink."""
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise ValueError("g0-launch-file-invalid") from error
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("g0-launch-file-invalid")
        chunks = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > limit:
            raise ValueError("g0-launch-file-too-large")
        return data, info
    finally:
        os.close(descriptor)


def _pid_parent(pid: int) -> int:
    try:
        value = subprocess.check_output(
            ["ps", "-ww", "-p", str(pid), "-o", "ppid="],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=2,
        ).strip()
        return int(value)
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        raise ValueError("g0-launch-chain-unavailable") from error


def _owned_argv(pid: int) -> list[str]:
    try:
        if sys.platform.startswith("linux"):
            return [item.decode() for item in Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0") if item]
        if sys.platform == "darwin":
            script = "\n".join(
                [
                    "import ctypes, json, struct, sys",
                    "pid=int(sys.argv[1]); libc=ctypes.CDLL(None); mib=(ctypes.c_int*3)(1,49,pid); size=ctypes.c_size_t(0)",
                    "if libc.sysctl(mib,3,None,ctypes.byref(size),None,0)!=0: raise OSError()",
                    "buffer=ctypes.create_string_buffer(size.value)",
                    "if libc.sysctl(mib,3,buffer,ctypes.byref(size),None,0)!=0: raise OSError()",
                    "argc=struct.unpack_from('i',buffer.raw)[0]; parts=buffer.raw[4:].split(b'\\0'); first=parts[0]; rest=parts[1:]; start=next(i for i,value in enumerate(rest) if value); start=start+1 if rest[start]==first else start; print(json.dumps([first.decode()]+[value.decode() for value in rest[start:start+argc-1]]))",
                ]
            )
            return json.loads(subprocess.check_output(["python3", "-c", script, str(pid)], text=True, timeout=2))
    except (OSError, subprocess.SubprocessError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("g0-process-argv-unavailable") from error
    raise ValueError("g0-process-argv-unsupported")


def _validate_launch_receipt(output: Path, handshake: dict) -> None:
    receipt_bytes, receipt_info = _bounded_regular_bytes(output / "launch-receipt.json", 128 * 1024)
    if receipt_info.st_mode & 0o077 != 0:
        raise ValueError("g0-launch-receipt-permissions")
    try:
        receipt = json.loads(receipt_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("g0-launch-receipt-invalid") from error
    run_info = os.stat(output, follow_symlinks=False)
    if not stat.S_ISDIR(run_info.st_mode) or run_info.st_mode & 0o777 != 0o700:
        raise ValueError("g0-run-directory-invalid")
    binary_bytes, _ = _bounded_regular_bytes(output / "fireemu", 256 * 1024 * 1024)
    config_bytes, _ = _bounded_regular_bytes(output / "fireemu.json", 128 * 1024)
    rules_bytes, _ = _bounded_regular_bytes(output / "firestore.rules", 128 * 1024)
    binary_sha = hashlib.sha256(binary_bytes).hexdigest()
    config_sha = hashlib.sha256(config_bytes).hexdigest()
    rules_sha = hashlib.sha256(rules_bytes).hexdigest()
    parent_pid = receipt.get("pid")
    command = str(output / "fireemu")
    if (
        receipt.get("schema") != "fireemu-g0-launch-v1"
        or type(parent_pid) is not int
        or parent_pid <= 0
        or receipt.get("command") != command
        or not isinstance(receipt.get("args"), list)
        or any(not isinstance(item, str) for item in receipt["args"])
        or "--import" in receipt["args"]
        or "--export-on-exit" in receipt["args"]
        or receipt.get("binarySha256") != binary_sha
        or receipt.get("configSha256") != config_sha
        or receipt.get("rulesSha256") != rules_sha
        or receipt.get("environmentSha256") != handshake.get("environmentSha256")
        or receipt.get("sourceCommit") != handshake.get("sourceCommit")
        or any(
            not isinstance(handshake.get(key), str)
            or receipt.get(key) != handshake.get(key)
            for key in (
                "retainedManifestSha256",
                "artifactProfile",
                "runtimeSourceCommit",
                "sourceInputsDigest",
            )
        )
        or receipt.get("runDirectory")
        != {
            "path": str(output),
            "dev": run_info.st_dev,
            "ino": run_info.st_ino,
            "mode": run_info.st_mode & 0o777,
        }
        or receipt.get("import") is not None
        or receipt.get("exportOnExit") is not None
        or hashlib.sha256(receipt_bytes).hexdigest() != handshake.get("receiptSha256")
        or handshake.get("parentPid") != parent_pid
        or handshake.get("binarySha256") != binary_sha
        or handshake.get("configSha256") != config_sha
        or handshake.get("rulesSha256") != rules_sha
        or handshake.get("runDirectory") != receipt.get("runDirectory")
        or handshake.get("argv") != [receipt.get("command"), *receipt.get("args", [])]
    ):
        raise ValueError("g0-launch-receipt-invalid")
    child_pid = handshake.get("childPid")
    python_pid = os.getppid()
    if (
        child_pid != _pid_parent(python_pid)
        or _pid_parent(child_pid) != parent_pid
        or handshake.get("pythonArgv") != _owned_argv(python_pid)
    ):
        raise ValueError("g0-launch-chain-invalid")


class G0RecoveryGate(Gate):
    """G0-only Gate facade; generic Gate cleanup authority is untouched."""

    def __init__(self, path: Path, job: str):
        super().__init__(path, job)
        plan = self.snapshot()["plan"]
        self._resources = _resources(plan)
        self._expected = _expected_fields(plan)
        origins = plan.get("localOrigins")
        if not isinstance(origins, dict) or set(origins) != {"auth", "firestore"}:
            raise ValueError("g0-local-origins-missing")
        for origin in origins.values():
            local_origin(origin)

    def _validate_cleanup_ownership(self, operation, recovery, resource, source, job):
        if not recovery or resource not in self._resources or source is None:
            raise ValueError("g0-cleanup-ownership-refused")
        capture = job["captures"].get(str(source), {})
        expected_fields = self._expected.get(resource)
        if (
            capture.get("status") != 200
            or capture.get("name") != resource
            or capture.get("fieldsDigest") != digest(expected_fields)
            or not isinstance(capture.get("updateTime"), str)
            or not capture["updateTime"]
            or operation.get("method") != "DELETE"
            or operation.get("path")
            != "/v1/" + resource + "?currentDocument.updateTime=" + quote(capture["updateTime"], safe="")
        ):
            raise ValueError("g0-cleanup-ownership-refused")

    def _record_response(self, state, operation, recovery, event, status, body):
        """Keep G0's unconditional writes out of generic creation authority."""
        if not recovery:
            job = state["jobs"][self.job]
            job["creationProofs"].clear()
            job["owned"].clear()
        elif operation.get("method") == "DELETE" and status != 200:
            state["jobs"][self.job]["g0RecoveryFailure"] = "conditional-delete-failed"
            raise ValueError("g0-conditional-delete-failed")

    def finish(self):
        """Close only after this lane's readback evidence is terminal.

        The frozen batch update is not represented as a generic creation proof;
        the exact local readback/conditional-delete/final-absence sequence is
        the authority for this closed lane.
        """
        with self.locked() as state:
            job = state["jobs"][self.job]
            if (
                state.get("noDataAbort") is not None
                or state.get("managementAbort") is not None
                or job["pid"] != os.getpid()
                or job["inflight"]
                or job["recovery"] != len(state["plan"]["jobs"][self.job]["recovery"])
                or set(job["absent"]) != set(job["resources"])
                or job["creationProofs"]
                or job["owned"]
                or job.get("g0RecoveryFailure") is not None
                or any(
                    event.get("phase") == "recovery"
                    and event.get("creationOutcome") == "unknown"
                    for event in state["events"]
                )
            ):
                raise ValueError("g0 cleanup incomplete; ownership retained")
            self._validate_finish_evidence(state)
            job["complete"] = True
            _save(self.path, state)


def _freshness_handshake(output: Path, origins: dict[str, str]) -> None:
    path = output / "freshness-handshake.json"
    if path.is_symlink() or not path.is_file():
        raise ValueError("g0-freshness-handshake-missing")
    handshake = json.loads(path.read_bytes())
    plan = json.loads((output / "program.json").read_bytes())
    expected_digest = digest(plan)
    if (
        handshake.get("schema") != "fireemu-g0-freshness-v1"
        or handshake.get("origins") != origins
        or handshake.get("programDigest") != expected_digest
        or not isinstance(handshake.get("receiptSha256"), str)
        or not isinstance(handshake.get("parentPid"), int)
        or not isinstance(handshake.get("childPid"), int)
        or not isinstance(handshake.get("argv"), list)
        or "--import" in handshake["argv"]
        or "--export-on-exit" in handshake["argv"]
        or not isinstance(handshake.get("binarySha256"), str)
        or handshake.get("import") is not None
        or handshake.get("exportOnExit") is not None
    ):
        raise ValueError("g0-freshness-handshake-invalid")
    _validate_launch_receipt(output, handshake)


def _wire_history_matches_reservations(state: dict, results: dict) -> bool:
    """Derive the reservation proof from the immutable journal and saved rows."""
    events = state.get("events", [])
    for key, result in results.items():
        if not result.get("recordingComplete") or not result.get("cleanupComplete"):
            return False
        for phase, rows in (("observation", result.get("rows", [])), ("recovery", result.get("cleanup", []))):
            matching = [event for event in events if event.get("job") == key and event.get("phase") == phase]
            if len(matching) != len(rows):
                return False
            for row, event in zip(rows, matching, strict=True):
                if row.get("status") is None:
                    return False
                if (
                    event.get("completed") is not True
                    or event.get("requestDigest") != digest(row.get("request"))
                    or event.get("responseDigest") != digest(row.get("body"))
                    or event.get("status") != row.get("status")
                ):
                    return False
    return True


def _worker(output: Path, key: str, origins: dict[str, str]) -> None:
    plan = json.loads((output / "gate/state.json").read_bytes())["plan"]
    command = subprocess.check_output(
        ["ps", "-ww", "-p", str(os.getpid()), "-o", "args="], text=True
    ).strip()
    save(output / (key + "-process.json"), {"pid": os.getpid(), "argv": command.split(maxsplit=1)})
    gate = G0RecoveryGate(output / "gate", key)
    gate.claim()
    adapter = Adapter(candidate(), plan["nonce"], output / key, local_origins=origins)
    adapter.shared_gate = gate
    run_scenario(adapter, plan, key)
    result_path = output / key / "result.json"
    result = json.loads(result_path.read_bytes())
    expected = _expected_fields(plan)
    final_rows = result.get("rows", [])[-len(plan["jobs"][key]["resources"]):]
    result["safety"] = (
        len(result.get("rows", [])) == len(plan["jobs"][key]["observation"])
        and all(
            row.get("status") == 200
            and isinstance(row.get("body"), dict)
            and row["body"].get("name") in expected
            and row["body"].get("fields") == expected[row["body"]["name"]]
            for row in final_rows
        )
    )
    save(result_path, result)


def execute(output: Path, origins: dict[str, str]) -> bool:
    output = Path(output)
    _freshness_handshake(output, origins)
    fixed_plan = json.loads((output / "gate/state.json").read_bytes())["plan"]
    jobs = list(fixed_plan["jobs"])
    processes = [mp.get_context("spawn").Process(target=_worker, args=(output, key, origins)) for key in jobs]
    started = time.monotonic()
    try:
        for process in processes:
            process.start()
        for process in processes:
            process.join(max(0, fixed_plan["wallSeconds"] + 15 - (time.monotonic() - started)))
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(5)
                if process.is_alive():
                    process.kill()
                    process.join(5)
    state = G0RecoveryGate(output / "gate", jobs[0]).snapshot()
    results = {
        key: json.loads((output / key / "result.json").read_bytes())
        if (output / key / "result.json").exists()
        else {"recordingComplete": False, "cleanupComplete": False}
        for key in jobs
    }
    wire_history_matches = _wire_history_matches_reservations(state, results)
    events = state["events"]
    invariant = (
        state["total"] <= 26
        and state["recovery"] <= 12
        and state["costMicrousd"] <= 42600
        and all(b["started"] - a["started"] >= 0.25 for a, b in itertools.pairwise(events))
        and all(process.exitcode == 0 for process in processes)
    )
    completed = invariant and all(
        result["recordingComplete"] and result["cleanupComplete"] and result.get("safety")
        for result in results.values()
    )
    (output / "batch").mkdir(exist_ok=True)
    save(
        output / "batch/result.json",
        {
            "completed": completed,
            "failure": None if completed else "g0-local-recovery-incomplete",
            "unrecovered": [key for key, result in results.items() if not result["cleanupComplete"]],
            "productionExecuted": False,
            "sharedConstraints": invariant,
            "wireHistoryMatchesReservations": wire_history_matches,
            "jobs": results,
            "gate": state,
            "manifestSha256": digest(state["plan"]),
            "processExitCodes": [process.exitcode for process in processes],
            "elapsedSeconds": time.monotonic() - started,
        },
    )
    return completed
