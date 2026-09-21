"""Bound the local Listen SDK process, not just its cooperative Promise timers.

This launcher has no production mode, arbitrary-command flag or automatic
recovery capability. It records possible recovery responsibility before spawn,
then runs the fixed Node adapter on numeric loopback endpoints. Forced process
termination is never evidence that a document or an account was recovered.
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import math
import os
from pathlib import Path
import re
import secrets
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
import types
from typing import Any

# The CLI and pytest import exactly the same preparation modules. No network or
# credential provider is imported by this stdlib-only preparation package.
if not __package__:
    package = types.ModuleType("o6_local_supervisor")
    package.__path__ = [str(Path(__file__).resolve().parent)]
    sys.modules[package.__name__] = package
    __package__ = package.__name__
from .export_spec import budget_document, campaign_document, cases_document
from .campaign import owned_paths, secondary_paths

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
MAX_STDOUT = 8 * 1024 * 1024
MAX_STDERR = 64 * 1024
MAX_SECONDS = 820.0  # 600 observation + 180 recovery + 40 startup/finalization
TERM_SECONDS = 2.0
DRAIN_SECONDS = 1.0
SCHEMA = "local-listen-supervisor-v1"


class Refused(ValueError):
    """Only fixed diagnostic codes, never SDK exceptions or credentials."""


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _encode(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n").encode()


def _decode(raw: bytes) -> Any:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise Refused("duplicate-json-key")
            result[key] = value
        return result

    def number(value):
        result = float(value)
        if not math.isfinite(result):
            raise Refused("nonfinite-json-number")
        return result

    def constant(_):
        raise Refused("nonfinite-json-number")

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                          parse_float=number, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Refused("invalid-json-evidence") from error


def _publish(path: Path, value: Any) -> None:
    """Exclusive file + directory fsync; no overwrite and no symlink following."""
    raw = _encode(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _read(path: Path, limit: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise Refused("invalid-evidence-file")
        chunks = []
        remaining = limit + 1
        while remaining:
            part = os.read(fd, min(65536, remaining))
            if not part:
                break
            chunks.append(part)
            remaining -= len(part)
        raw = b"".join(chunks)
        if len(raw) != info.st_size or len(raw) > limit or os.fstat(fd).st_size != info.st_size:
            raise Refused("evidence-file-changed")
        return raw
    finally:
        os.close(fd)


def _endpoint(value: Any) -> str:
    if not isinstance(value, str):
        raise Refused("numeric-loopback-required")
    match = re.fullmatch(r"(?:127\.0\.0\.1|\[::1\]):([1-9][0-9]{0,4})", value)
    if not match or int(match[1]) > 65535:
        raise Refused("numeric-loopback-required")
    return value


def _seconds(value: Any) -> float:
    if type(value) not in (int, float) or not math.isfinite(value) or not 0 < value <= MAX_SECONDS:
        raise Refused("invalid-supervision-deadline")
    return float(value)


def _signal_owned(child: subprocess.Popen, sig: int) -> bool:
    # Poll is our only reaper. Until this live child is reaped, its PID cannot
    # name a replacement process. Never signal a group after leader exit.
    if child.poll() is not None:
        return False
    try:
        if os.getpgid(child.pid) != child.pid or os.getsid(child.pid) != child.pid:
            return False
        os.killpg(child.pid, sig)
        return True
    except ProcessLookupError:
        return False


def _group_absent(pid: int) -> bool:
    try:
        os.killpg(pid, 0)  # observation only, never a post-reap killing signal
    except ProcessLookupError:
        return True
    except OSError:
        return False
    return False


def _capture(command: list[str], env: dict[str, str], cwd: Path, output: Path,
             timeout: float, *, term_seconds: float = TERM_SECONDS,
             drain_seconds: float = DRAIN_SECONDS) -> dict[str, Any]:
    """Internal process primitive. The public launcher supplies a fixed script.

    Pipes use selectors, so an inherited pipe held by a descendant cannot make
    communicate()/read() block forever after the leader exits. On every failure
    we stop only the process group whose live leader we still own.
    """
    timeout = _seconds(timeout)
    for value in (term_seconds, drain_seconds):
        if type(value) not in (int, float) or not math.isfinite(value) or not 0 < value <= 5:
            raise Refused("invalid-stop-grace")
    started = time.monotonic()
    deadline = started + timeout
    child = None
    streams = {}
    files = {}
    digests = {name: hashlib.sha256() for name in ("stdout", "stderr")}
    counts = dict.fromkeys(digests, 0)
    issues: list[str] = []
    signals = []
    selector = selectors.DefaultSelector()
    limits = {"stdout": MAX_STDOUT, "stderr": MAX_STDERR}
    result = {"started": False, "returnCode": None, "leaderStopped": False,
              "groupAbsent": False, "pipesClosed": False, "signals": signals,
              "issues": issues, "streams": {}}
    try:
        for name in limits:
            fd = os.open(output / (name + ".bin"),
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            files[name] = os.fdopen(fd, "wb")
        child = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 start_new_session=True, close_fds=True)
        result.update(started=True, pid=child.pid)
        _publish(output / "process.json", {"schema": SCHEMA, "pid": child.pid,
                 "processGroup": child.pid, "authorizesCleanup": False})
        for name in limits:
            stream = getattr(child, name)
            os.set_blocking(stream.fileno(), False)
            streams[stream.fileno()] = stream
            selector.register(stream, selectors.EVENT_READ, name)
        exit_drain = None
        while selector.get_map() or child.poll() is None:
            now = time.monotonic()
            if now >= deadline:
                issues.append("execution-deadline")
                break
            if child.poll() is not None:
                if exit_drain is None:
                    exit_drain = now + drain_seconds
                if now >= exit_drain and selector.get_map():
                    issues.append("inherited-pipes-remain")
                    break
            for key, _ in selector.select(min(0.05, max(0, deadline - now))):
                name = key.data
                try:
                    part = os.read(key.fd, 65536)
                except BlockingIOError:
                    continue
                if not part:
                    selector.unregister(key.fileobj)
                    streams.pop(key.fd).close()
                    continue
                retained = part[:max(0, limits[name] - counts[name])]
                files[name].write(retained)
                digests[name].update(retained)
                counts[name] += len(retained)
                if len(part) != len(retained):
                    issues.append(name + "-limit")
                    break
            if issues:
                break
        result["pipesClosed"] = not selector.get_map()
    except Exception as error:
        # Output/disk failures and launch errors preserve the launch intent.
        issues.append("process-operation-" + type(error).__name__)
    except KeyboardInterrupt:
        # Ctrl-C still reaches the same stop and durable-result path. An OS
        # SIGKILL/power loss cannot run finally; launch.json remains unresolved.
        issues.append("supervisor-interrupted")
    finally:
        if child is not None:
            try:
                if child.poll() is None:
                    if _signal_owned(child, signal.SIGTERM):
                        signals.append("SIGTERM")
                    try:
                        child.wait(timeout=term_seconds)
                    except subprocess.TimeoutExpired:
                        if _signal_owned(child, signal.SIGKILL):
                            signals.append("SIGKILL")
                        try:
                            child.wait(timeout=term_seconds)
                        except subprocess.TimeoutExpired:
                            issues.append("leader-stop-unconfirmed")
                result["returnCode"] = child.poll()
                result["leaderStopped"] = result["returnCode"] is not None
                result["groupAbsent"] = _group_absent(child.pid)
                if not result["groupAbsent"]:
                    issues.append("process-group-remains-unconfirmed")
                if result["returnCode"] != 0:
                    issues.append("child-nonzero-exit")
            except Exception as error:
                issues.append("stop-operation-" + type(error).__name__)
        def close_capture(handle, label):
            # A failed finalizer must not discard the already-known spawn/stop
            # result or prevent the other descriptors and output files closing.
            try:
                handle.close()
            except Exception as error:
                issues.append(label + "-close-" + type(error).__name__)

        for stream in streams.values():
            close_capture(stream, "pipe")
        # Publication may fail immediately after spawn, before registration.
        if child is not None:
            for stream in (child.stdout, child.stderr):
                if stream is not None:
                    close_capture(stream, "pipe")
        close_capture(selector, "selector")
        for name, stream in files.items():
            try:
                stream.flush()
                os.fsync(stream.fileno())
                stream.close()
            except OSError:
                issues.append(name + "-save-failed")
                try:
                    stream.close()
                except OSError:
                    pass
        result["streams"] = {name: {"bytes": counts[name], "sha256": digests[name].hexdigest()}
                             for name in files}
        result["elapsedSeconds"] = time.monotonic() - started
    return result


def _executable_file(path: str) -> bool:
    return os.path.isfile(path) and os.access(path, os.X_OK)


def _is_volta_shim(path: str) -> bool:
    # `~/.volta/bin/node` is a symlink to `volta-shim`. Run with the private
    # empty HOME below, the shim tries to install a default Node and, when it
    # finds itself on PATH, spawns itself recursively. Only the resolved
    # basename decides; the candidate is never executed to find out.
    return os.path.basename(os.path.realpath(path)) == "volta-shim"


def _volta_image_node(env: dict[str, str]) -> str | None:
    """The real binary behind a volta shim, found on disk without running volta."""
    home = env.get("VOLTA_HOME") or os.environ.get("VOLTA_HOME") or os.path.join(Path.home(), ".volta")
    images = Path(home) / "tools" / "image" / "node"
    candidates: list[str] = []
    try:
        pinned = json.loads((Path(home) / "tools" / "user" / "platform.json").read_bytes())
        candidates.append(str(pinned["node"]["runtime"]))
    except (OSError, ValueError, KeyError, TypeError):
        pass
    try:
        versions = [d.name for d in images.iterdir() if re.fullmatch(r"\d+\.\d+\.\d+", d.name)]
    except OSError:
        versions = []
    candidates.extend(sorted(versions, key=lambda v: tuple(int(x) for x in v.split(".")), reverse=True))
    for version in candidates:
        binary = images / version / "bin" / "node"
        if _executable_file(str(binary)) and not _is_volta_shim(str(binary)):
            return str(binary)
    return None


def _resolve_node(env: dict[str, str]) -> str:
    """`FIREEMU_NODE` wins; otherwise PATH, with a volta shim replaced or refused."""
    explicit = env.get("FIREEMU_NODE")
    if explicit:
        if not _executable_file(explicit):
            raise Refused("node-not-found")
        if _is_volta_shim(explicit):
            raise Refused("volta-shim-refused")
        return explicit
    node = shutil.which("node", path=env.get("PATH", os.defpath))
    if node is None:
        raise Refused("node-not-found")
    if _is_volta_shim(node):
        node = _volta_image_node(env)
        if node is None:
            raise Refused("volta-shim-refused")
    return node


def _bindings() -> dict[str, str]:
    paths = list(budget_document()["boundSources"]) + [
        str((HERE / "local_supervisor.py").relative_to(ROOT)),
        str((HERE / "local_shadow_check.mjs").relative_to(ROOT)),
    ]
    return {p: _sha(_read(ROOT / p, MAX_STDOUT)) for p in sorted(set(paths))}


def _journal_summary(directory: Path, nonce: str, project: str) -> dict[str, Any]:
    phases = ["ready", "account-create-intent", "account-created",
              "documents-at-risk", "lifecycle-result"]
    previous = None
    last = -1
    rows = []
    path_digests = None
    entries = list(itertools.islice(directory.iterdir(), 6))
    if len(entries) > 5:
        raise Refused("too-many-lifecycle-checkpoints")
    for file in sorted(entries):
        raw = _read(file, 32768)
        item = _decode(raw)
        index = phases.index(item.get("phase"))
        if (file.name != f"{index}-{phases[index]}.json" or index <= last
                or (last < 0 and index != 0) or (index in (2, 3) and last != index - 1)
                or item.get("schema") != "local-listen-checkpoint-v1"
                or item.get("nonce") != nonce or item.get("projectId") != project
                or item.get("accountEmail") != f"o6-{nonce}@example.test"
                or item.get("authorizesCleanup") is not False
                or item.get("previousSha256") != previous):
            raise Refused("invalid-lifecycle-chain")
        if set(item) != {"schema", "phase", "nonce", "projectId", "accountEmail",
                         "previousSha256", "authorizesCleanup", "value"}:
            raise Refused("invalid-lifecycle-schema")
        value = item["value"]
        if not isinstance(value, dict):
            raise Refused("invalid-lifecycle-value")
        if index == 2:
            uid = value.get("uid")
            two = set(value) == {"uid", "paths", "secondaryUid", "secondaryPaths"}
            if (not isinstance(uid, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", uid)
                    or (not two and set(value) != {"uid", "paths"})
                    or value["paths"] != owned_paths(nonce, uid)):
                raise Refused("invalid-lifecycle-ownership")
            path_digests = {k: _sha(v.encode()) for k, v in value["paths"].items() if k != "run"}
            if two:
                second = value["secondaryUid"]
                if (not isinstance(second, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", second)
                        or second == uid
                        or value["secondaryPaths"] != secondary_paths(nonce, second)):
                    raise Refused("invalid-lifecycle-ownership")
                path_digests.update({k: _sha(v.encode()) for k, v in value["secondaryPaths"].items()})
        elif index == 4:
            if (set(value) != {"complete", "accountCleanupComplete", "clientsComplete",
                              "documentsCleanupComplete"}
                    or any(type(v) is not bool for v in value.values())):
                raise Refused("invalid-lifecycle-result")
            if value["complete"] and (last != 3 or not all(value.values())):
                raise Refused("contradictory-lifecycle-completion")
        elif value:
            raise Refused("unexpected-lifecycle-value")
        previous = _sha(raw)
        rows.append({"phase": phases[index], "sha256": previous, "file": file.name})
        last = index
    return {"checkpoints": rows, "lastPhase": phases[last] if last >= 0 else None,
            "result": item["value"] if last == 4 else None, "pathDigests": path_digests,
            "authorizesCleanup": False}


def run(output: Path, *, env: dict[str, str] | None = None,
        timeout: float = MAX_SECONDS) -> dict[str, Any]:
    """Public fixed local launcher, intended as a child of `fireemu exec`."""
    env = dict(os.environ if env is None else env)
    timeout = _seconds(timeout)
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise Refused("posix-supervision-required")
    if env.get("O6_LISTEN_MODE", "local") != "local" or env.get("O6_LISTEN_PERMISSION"):
        raise Refused("production-entry-forbidden")
    if any(env.get(k) for k in ("O6_LISTEN_NONCE", "O6_LISTEN_PASSWORD_FD",
                               "O6_LISTEN_CAMPAIGN_PATH", "O6_LISTEN_JOURNAL_DIR")):
        raise Refused("supervisor-owns-fresh-campaign-and-journal")
    firestore = _endpoint(env.get("FIRESTORE_EMULATOR_HOST"))
    auth = _endpoint(env.get("FIREBASE_AUTH_EMULATOR_HOST"))
    project = env.get("GOOGLE_CLOUD_PROJECT", "")
    if not re.fullmatch(r"demo-[a-zA-Z0-9_-]{1,123}", project):
        raise Refused("demo-project-required")
    module_dir = Path(env.get("O6_FIREBASE_MODULE_DIR", "")).resolve()
    if not env.get("O6_FIREBASE_MODULE_DIR") or not module_dir.is_dir():
        raise Refused("local-sdk-directory-required")
    node = _resolve_node(env)
    output = Path(os.path.abspath(output))
    # Reject an existing symlink (including dangling) before resolve().
    if output.exists() or output.is_symlink():
        raise Refused("fresh-output-required")
    if output.resolve().is_relative_to(ROOT):
        raise Refused("evidence-must-be-outside-checkout")
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    nonce = secrets.token_hex(16)
    report: dict[str, Any] = {"schema": SCHEMA, "completed": False,
        "productionExecuted": False, "currentArtifactVerified": False,
        "productionCompatibilityVerified": False, "authorizesCleanup": False,
        "nonceDigest": _sha(nonce.encode()), "resourceCleanupComplete": False,
        "processCleanupComplete": False, "recoveryRequired": False, "issues": []}
    try:
        source = _bindings()
        campaign = campaign_document(nonce)
        catalog = cases_document()
        budget = budget_document()
        inputs = {}
        for name, value in (("campaign.json", campaign), ("catalog.json", catalog), ("budget.json", budget)):
            _publish(output / name, value)
            inputs[name] = _sha(_encode(value))
        journal = output / "checkpoints"
        journal.mkdir(mode=0o700)
        (output / "home").mkdir(mode=0o700)
        # Durable before the first SDK process can create data. This is the
        # responsibility record even if the parent itself subsequently crashes.
        _publish(output / "launch.json", {"schema": SCHEMA, "nonce": nonce,
            "projectId": project, "accountEmail": f"o6-{nonce}@example.test",
            "firestoreEndpoint": firestore, "authEndpoint": auth,
            "timeoutSeconds": timeout, "sourceDigests": source, "inputDigests": inputs,
            "productionExecuted": False, "authorizesCleanup": False,
            "recoveryState": "possibly-outstanding-until-typed-completion"})
        child_env = {"PATH": os.path.dirname(node), "LANG": "C.UTF-8",
            "HOME": str(output / "home"), "O6_LISTEN_MODE": "local",
            "FIRESTORE_EMULATOR_HOST": firestore, "FIREBASE_AUTH_EMULATOR_HOST": auth,
            "GOOGLE_CLOUD_PROJECT": project, "O6_REPO_ROOT": str(ROOT),
            "O6_FIREBASE_MODULE_DIR": str(module_dir), "O6_LISTEN_NONCE": nonce,
            "O6_LISTEN_CAMPAIGN_PATH": str(output / "campaign.json"),
            "O6_LISTEN_CATALOG_PATH": str(output / "catalog.json"),
            "O6_LISTEN_BUDGET_PATH": str(output / "budget.json"),
            "O6_LISTEN_JOURNAL_DIR": str(journal)}
        # These are declared provenance/timeouts, not authentication inputs.
        for key in ("O6_LISTEN_SOURCE_COMMIT", "O6_LISTEN_SDK_VERSION", "O6_LISTEN_FIREEMU_BINARY",
                    "O6_LISTEN_FIREEMU_COMMIT", "O6_LISTEN_RULES_PATH", "O6_LISTEN_DEADLINE_MS",
                    "O6_LISTEN_STEP_TIMEOUT_MS"):
            if key in env:
                child_env[key] = env[key]
        # Submission itself crosses the possible-side-effect boundary. If the
        # capture primitive raises after spawn, its missing return value cannot
        # prove that no SDK process or data operation was started. Only a
        # returned started=False or accepted completion may clear this flag.
        report["recoveryRequired"] = True
        execution = _capture([node, str(HERE / "listen_sdk_adapter.mjs")], child_env, ROOT, output, timeout)
        report["execution"] = execution
        report["processCleanupComplete"] = (execution["started"] is True
            and execution["leaderStopped"] is True and execution["groupAbsent"] is True)
        report["recoveryRequired"] = execution["started"] is True
        report["issues"].extend(execution["issues"])
        if execution["pipesClosed"] is not True:
            report["issues"].append("output-eof-unconfirmed")
        if type(execution["returnCode"]) is not int or execution["returnCode"] != 0:
            report["issues"].append("sdk-exit-not-success")
        report["sourceDigests"] = source
        if _bindings() != source:
            report["issues"].append("source-changed-during-run")
        if any(_sha(_read(output / p, MAX_STDOUT)) != sha for p, sha in inputs.items()):
            report["issues"].append("input-changed-during-run")
        report["journal"] = _journal_summary(journal, nonce, project)
        if not report["issues"] and report["processCleanupComplete"]:
            raw = _read(output / "stdout.bin", MAX_STDOUT)
            receipt = _decode(raw)
            if (not isinstance(receipt, dict) or receipt.get("productionExecuted") is not False
                    or receipt.get("environment", {}).get("nonceDigest") != report["nonceDigest"]
                    or receipt.get("environment", {}).get("projectId") != project
                    or receipt.get("campaignDigest") != campaign["campaignDigest"]
                    or receipt.get("sourceDigests") != {k: source[k] for k in budget["boundSources"]}
                    or report["journal"]["lastPhase"] != "lifecycle-result"
                    or report["journal"]["result"] != {"complete": True, "accountCleanupComplete": True,
                        "clientsComplete": True, "documentsCleanupComplete": True}):
                raise Refused("child-receipt-binding-mismatch")
            # A receipt from another run cannot gain current ownership merely
            # by changing its environment/campaign fields. Bind every resource
            # digest to the same-run durable UID checkpoint as well.
            expected_paths = report["journal"]["pathDigests"]
            cleanup_rows = receipt.get("cleanup", {}).get("rows")
            if (expected_paths is None or not isinstance(cleanup_rows, list)
                    or len(cleanup_rows) != len(expected_paths)
                    or {r.get("name"): r.get("pathDigest") for r in cleanup_rows} != expected_paths):
                raise Refused("child-recovery-scope-mismatch")
            checker = output / "checker"
            checker.mkdir(mode=0o700)
            check = _capture([node, str(HERE / "local_shadow_check.mjs"), str(output / "stdout.bin")],
                             child_env, ROOT, checker, 10)
            report["expectationCheck"] = check
            checked = _decode(_read(checker / "stdout.bin", MAX_STDOUT))
            if (check["issues"] or not check["leaderStopped"] or not check["groupAbsent"]
                    or not check["pipesClosed"] or not isinstance(checked, dict)
                    or checked.get("kind") != "local-listen-expectation-check"
                    or checked.get("complete") is not True):
                report["issues"].append("local-expectations-incomplete")
            elif (_bindings() != source or any(
                    _sha(_read(output / p, MAX_STDOUT)) != sha for p, sha in inputs.items())):
                report["issues"].append("binding-changed-during-check")
            else:
                report["resourceCleanupComplete"] = True
                report["recoveryRequired"] = False
                report["completed"] = True
                report["childReceiptSha256"] = _sha(raw)
    except Exception as error:
        diagnostic = str(error) if isinstance(error, Refused) else type(error).__name__
        report["issues"].append("supervisor-" + diagnostic)
        report["completed"] = False
    # Failure to publish propagates: no success is printed, launch.json and the
    # private bounded streams/checkpoints remain available for diagnosis.
    _publish(output / "result.json", report)
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=float, default=MAX_SECONDS)
    args = parser.parse_args(argv)
    try:
        result = run(args.output, timeout=args.timeout_seconds)
    except Exception:
        print("Local Listen supervision refused or evidence could not be saved.", file=sys.stderr)
        return 2
    print(json.dumps({k: result[k] for k in ("completed", "processCleanupComplete",
        "resourceCleanupComplete", "recoveryRequired", "productionExecuted")}))
    return 0 if result["completed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
