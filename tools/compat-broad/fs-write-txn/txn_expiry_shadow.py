"""Owned local rehearsal of the transaction expiry / retry campaign.

The parent copies the built `fireemu` artifact into a private directory, runs it
as `fireemu exec --only firestore`, and launches itself as the child inside that
owned instance. The child drives the bounded collector over the emulator's REST
surface and reaches the idle limit by advancing the emulator's virtual clock,
because that clock does not follow wall time.

This is local evidence. It proves the collector, the plan, the cleanup contract
and the frozen expected local results against the real runtime. It is not a
production observation and establishes no parity.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import stat
import tempfile
import shlex
import signal
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "compat-inventory"))

import txn_expiry_cases as cases
import txn_expiry_collector as collector
import txn_expiry_comparison as comparison
import txn_expiry_plan as plan_module
from broad_contract import digest
from evidence_common import runtime_inputs
from owned_runner import local_addresses
import txn_wire

CONTRACT = "txn-expiry-local-shadow-v1"
PROJECT = "fireemu-test"
CONFIG = {
    "schemaVersion": 1,
    "profile": "strict",
    "firestore": {"edition": "standard", "apiMode": "native"},
    "daemon": {"clockStart": "2026-09-18T00:00:00Z"},
}

#: REST status names mapped to the gRPC codes the case table speaks.
STATUS_TO_CODE = {
    "OK": 0,
    "CANCELLED": 1,
    "UNKNOWN": 2,
    "INVALID_ARGUMENT": 3,
    "DEADLINE_EXCEEDED": 4,
    "NOT_FOUND": 5,
    "ALREADY_EXISTS": 6,
    "PERMISSION_DENIED": 7,
    "RESOURCE_EXHAUSTED": 8,
    "FAILED_PRECONDITION": 9,
    "ABORTED": 10,
    "OUT_OF_RANGE": 11,
    "UNIMPLEMENTED": 12,
    "INTERNAL": 13,
    "UNAVAILABLE": 14,
    "UNAUTHENTICATED": 16,
}

DEFAULT_TIMEOUT_SECONDS = plan_module.DEFAULT_REQUEST_TIMEOUT_SECONDS

#: What `sourceRoot` records. The artifact was built from the repository that
#: contains these campaign modules; which directory that is on disk is not part
#: of the evidence.
REPOSITORY_ROOT_MARKER = "repository-root"
CHILD_TIMEOUT_SECONDS = 600

PUBLICATION_NOTE = (
    "Owned local rehearsal only. The elapsed time was produced by advancing the "
    "emulator's virtual clock, not by waiting. No production request was sent "
    "and no parent group is promoted."
)

#: Keys whose values legitimately differ between two runs of the same tool.
#: Everything else in the published record must reproduce.
VOLATILE_KEYS = (
    "nonce",
    "ownerId",
    "elapsedSeconds",
    "documentPrefix",
    "startedAt",
    "finishedAt",
    "at",
    "updateTime",
    "readTime",
    "transaction",
    "pid",
    "parentPid",
    "firestoreOrigin",
    "controlOrigin",
    "artifactPath",
    "path",
    "name",
    "sourceCommit",
    "endedAt",
    "wallSeconds",
    # A debug build is not bit-reproducible, so rebuilding the same Rust source
    # yields a different binary. The stable cross-run binding is
    # runtimeInputsDigest, which is deliberately not listed here.
    "artifactSha256",
    "childObservedArtifactSha256",
    "sourceRoot",
)


def runtime_binding(artifact, root):
    """Bind the built artifact to the Rust source it was produced from.

    A binary built somewhere else describes somewhere else. The shadow records
    the commit, the hashed Rust inputs and whether those inputs were clean, so a
    later reader can tell which source the local evidence actually describes.
    """
    artifact = Path(artifact)
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True
    ).strip()
    dirty = subprocess.check_output(
        [
            "git",
            "status",
            "--porcelain",
            "--",
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain.toml",
            ".cargo",
            "crates",
        ],
        cwd=root,
        text=True,
    ).strip()
    inputs = runtime_inputs(Path(root))
    return {
        "artifactSha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        "sourceCommit": commit,
        # A repo-relative marker, never an absolute path. This record is
        # published, and an absolute path both leaks the operator's filesystem
        # and makes any assertion about it fail from another checkout. The
        # path-independent binding is runtimeInputsDigest.
        "sourceRoot": REPOSITORY_ROOT_MARKER,
        "runtimeInputsDigest": digest(inputs),
        "runtimeInputCount": len(inputs),
        "runtimeInputsClean": dirty == "",
    }


MAX_SAVED_BYTES = 8 * 1024 * 1024


def save(path, value):
    """Publish complete private JSON once; never truncate an existing receipt.

    A failure after link may leave a complete file, but is still a failed
    publication. This is not a power-loss or hostile-filesystem guarantee.
    """
    path = Path(path)
    raw = (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")
    if len(raw) > MAX_SAVED_BYTES:
        raise ValueError("local receipt exceeds limit")
    if path.exists() or path.is_symlink():
        raise FileExistsError("local receipt already exists")
    descriptor, temporary = tempfile.mkstemp(prefix=".txn-result-", dir=path.parent)
    try:
        try:
            view = memoryview(raw)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("local receipt write made no progress")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.link(temporary, path, follow_symlinks=False)
        os.unlink(temporary)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _read_result(path):
    """Bounded nonblocking read; no links/devices, duplicate keys or nonfinite JSON."""
    from batch_wire import _decode_json_response

    path = Path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid != os.getuid() or before.st_mode & 0o077
                or not 0 < before.st_size <= MAX_SAVED_BYTES):
            raise ValueError("private regular local receipt required")
        chunks, size = [], 0
        while size <= MAX_SAVED_BYTES:
            chunk = os.read(descriptor, min(65536, MAX_SAVED_BYTES + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        after, current = os.fstat(descriptor), path.lstat()
        identity = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_uid,
                                 item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        if (identity(before) != identity(after) or identity(before) != identity(current)
                or size != before.st_size or size > MAX_SAVED_BYTES):
            raise ValueError("local receipt changed while reading")
        raw = b"".join(chunks)
        value = _decode_json_response(raw)
        if not isinstance(value, dict):
            raise ValueError("local receipt object required")
        return value, hashlib.sha256(raw).hexdigest()
    finally:
        os.close(descriptor)


def _local_origin(origin):
    if not isinstance(origin, str) or any(ord(c) <= 32 or ord(c) == 127 for c in origin):
        raise ValueError("numeric loopback origin required")
    parsed = urllib.parse.urlsplit(origin)
    if (parsed.scheme != "http" or parsed.hostname not in collector.LOOPBACK_HOSTS
            or parsed.port is None or parsed.port < 1 or parsed.username is not None
            or parsed.password is not None or parsed.path or "?" in origin or "#" in origin):
        raise ValueError("numeric loopback origin required")


def rest_transport(origin, *, timeout=None):
    """One fixed worker per send, bounded by the collector's remaining timeout.

    HTTP status is retained even if the worker is killed during body reception.
    Process creation/kernel kill/reap and the emulator's work are separate.
    """
    from batch_wire import _decode_json_response

    _local_origin(origin)

    def send(request):
        observed_status = None
        try:
            deadline = request.get("timeoutSeconds", timeout or DEFAULT_TIMEOUT_SECONDS)
            if not collector.finite_seconds(deadline) or not 0 < deadline <= plan_module.CONTENDED_REQUEST_TIMEOUT_SECONDS:
                raise ValueError("request timeout outside envelope")
            limit = request["maxResponseBytes"]
            request_limit = request.get("maxRequestBytes", plan_module.MAX_REQUEST_BYTES)
            if (type(limit) is not int or not 1 <= limit <= plan_module.MAX_RESPONSE_BYTES
                    or type(request_limit) is not int or not 1 <= request_limit <= plan_module.MAX_REQUEST_BYTES):
                raise ValueError("request bounds invalid")
            database, project = request["database"], request["projectId"]
            if any(not isinstance(v, str) or not v or any(c in v for c in "/?#%\\")
                   or any(ord(c) <= 32 for c in v) for v in (database, project)):
                raise ValueError("invalid resource identity")
            base = f"{origin}/v1/projects/{project}/databases/{database}/documents"
            rpc = request["rpc"]
            if rpc == "GetDocument":
                name = request["name"]
                prefix = f"projects/{project}/databases/{database}/documents/"
                if not isinstance(name, str) or not name.startswith(prefix) or any(c in name for c in "?#%\\"):
                    raise ValueError("document resource mismatch")
                url, payload, method = f"{origin}/v1/{name}", None, "GET"
                query = request.get("query") or {}
                if not isinstance(query, dict) or set(query) - {"transaction"}:
                    raise ValueError("invalid document query")
                if "transaction" in query:
                    if not isinstance(query["transaction"], str) or not query["transaction"]:
                        raise ValueError("invalid transaction query")
                    url += "?transaction=" + urllib.parse.quote(query["transaction"], safe="")
            else:
                suffix = {"BeginTransaction": ":beginTransaction", "Commit": ":commit", "Rollback": ":rollback"}[rpc]
                if not isinstance(request["body"], dict):
                    raise ValueError("request object required")
                payload = json.dumps(request["body"], allow_nan=False).encode()
                if len(payload) > request_limit:
                    raise ValueError("request exceeds bound")
                url, method = base + suffix, "POST"
            wire = txn_wire.request(
                url, method=method, payload=None if payload is None else payload.decode("utf-8"),
                seconds=deadline, request_limit=request_limit, response_limit=limit,
            )
            observed_status = wire["httpStatus"]
            if wire["complete"] is not True:
                return {"complete": False, "code": None, "status": None,
                        "httpStatus": observed_status, "message": wire["failure"]}
            status = observed_status
            body = _decode_json_response(wire["rawBody"])
            if not isinstance(body, dict):
                raise ValueError("response object required")
            if status == 200:
                normalized = {"complete": True, "code": 0, "status": "OK", "message": None, "body": body}
            else:
                if set(body) != {"error"} or not isinstance(body["error"], dict):
                    raise ValueError("error envelope required")
                detail = body["error"]
                code = STATUS_TO_CODE.get(detail.get("status"))
                if type(code) is not int or type(detail.get("code")) is not int or detail["code"] != status:
                    raise ValueError("error status not confirmed")
                normalized = {"complete": True, "code": code, "status": detail["status"],
                              "message": detail.get("message"), "body": body}
            normalized["httpStatus"] = status
            return collector._checked_response(normalized, request)
        except (OSError, ValueError, TypeError, KeyError, RecursionError) as error:
            return {"complete": False, "code": None, "status": None,
                    "httpStatus": observed_status, "message": type(error).__name__}
    return send


def clock_advance(control_origin, token, *, timeout=15):
    """Measure the returned virtual clock; never substitute requested seconds.

    The current control API returns clock/backwardsSets, not advancedSeconds.
    A bounded GET before each POST supplies the observed baseline. These are
    local control requests, recorded separately from the Firestore data count.
    """
    from batch_wire import _decode_json_response

    _local_origin(control_origin)
    if not collector.finite_seconds(timeout) or not 0 < timeout <= 15:
        raise ValueError("invalid control timeout")

    def request(method, suffix, body=None):
        payload = None if body is None else json.dumps(body, allow_nan=False)
        advance.requests += 1
        wire = txn_wire.request(control_origin + "/v1/sessions/default" + suffix,
                                method=method, payload=payload, token=token, seconds=timeout)
        if wire["httpStatus"] != 200 or wire["complete"] is not True:
            raise ValueError("control response incomplete")
        value = _decode_json_response(wire["rawBody"])
        if not isinstance(value, dict) or "error" in value:
            raise ValueError("control response malformed")
        if method == "GET":
            if value.get("session") != "default":
                raise ValueError("control session mismatch")
            value = value.get("clock")
        if (not isinstance(value, dict) or not collector.valid_instant(value.get("clock"))
                or type(value.get("backwardsSets")) is not int or value["backwardsSets"] < 0):
            raise ValueError("control clock not observed")
        text = value["clock"]
        whole = datetime.datetime.fromisoformat(text[:19] + "+00:00")
        epoch = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
        delta = whole - epoch
        fraction = text[20:-1] if text[19] == "." else ""
        nanoseconds = (delta.days * 86400 + delta.seconds) * 1_000_000_000
        nanoseconds += int(fraction.ljust(9, "0") or "0")
        return nanoseconds, value["backwardsSets"]

    def advance(seconds):
        if type(seconds) is not int or not 0 <= seconds <= cases.maximum_elapsed_seconds():
            raise ValueError("invalid control advance")
        before, revision = request("GET", "")
        after, after_revision = request("POST", "/clock:advance", {"seconds": seconds})
        if after_revision != revision or after < before:
            raise ValueError("control clock moved backwards")
        return (after - before) / 1_000_000_000

    advance.requests = 0
    return advance


def _control_get(origin, path, token, *, timeout=15):
    from batch_wire import _decode_json_response

    _local_origin(origin)
    wire = txn_wire.request(origin + path, method="GET", token=token, seconds=timeout)
    if wire["complete"] is not True:
        raise ValueError("owned control response incomplete")
    body = _decode_json_response(wire["rawBody"])
    if not isinstance(body, dict):
        raise ValueError("owned control response object required")
    return wire["httpStatus"], body


def child(output, nonce, owner_id):
    firestore, control = local_addresses(
        os.environ["FIRESTORE_EMULATOR_HOST"], os.environ["FIREEMU_CONTROL_URL"]
    )
    token = os.environ["FIREEMU_CONTROL_TOKEN"]
    status, resources = _control_get(control, "/v1/sessions/default/resources", token)
    wrong, _ = _control_get(control, "/v1/sessions/default/resources", token + "-wrong")
    if status != 200 or wrong != 403 or resources.get("project") != PROJECT:
        raise ValueError("owned instance identity is not proven")
    argv = shlex.split(
        subprocess.check_output(
            ["ps", "-ww", "-p", str(os.getppid()), "-o", "args="], text=True, timeout=2
        ).strip()
    )
    origin = urllib.parse.urlsplit(firestore)
    host, port = origin.hostname, origin.port
    options = {
        "target": "local",
        "host": host,
        "port": int(port),
        "projectId": PROJECT,
        "database": plan_module.DATABASE,
        "nonce": nonce,
        "ownerId": owner_id,
        "timing": collector.CONTROL_CLOCK,
        "deadlineSeconds": 300,
    }
    advance = clock_advance(control, token)
    receipt = collector.collect(options, rest_transport(firestore), advance=advance)
    receipt["localControlRequestCount"] = advance.requests
    receipt["instance"] = {
        "pid": os.getpid(),
        "parentPid": os.getppid(),
        "firestoreOrigin": firestore,
        "controlOrigin": control,
        "wrongTokenStatus": wrong,
        # The basename only: the absolute path is the operator's filesystem and
        # this record is published. The digest below is the actual proof.
        "artifactName": Path(argv[0]).name,
        "artifactSha256": hashlib.sha256(Path(argv[0]).read_bytes()).hexdigest(),
    }
    save(Path(output) / "receipt.json", receipt)
    save(
        Path(output) / "self-contract.json",
        comparison.local_self_contract(receipt),
    )


def stop_child(process, artifact):
    """Stop the owned instance by PID after verifying it is the one we started."""
    if process.poll() is not None:
        return {"stopped": True, "signal": None, "exitCode": process.returncode}
    try:
        argv = subprocess.check_output(
            ["ps", "-ww", "-p", str(process.pid), "-o", "args="], text=True, timeout=2
        ).strip()
    except (OSError, subprocess.SubprocessError):
        exit_code = process.poll()
        return {"stopped": exit_code is not None, "signal": None,
                "exitCode": exit_code, "failure": "identity-unavailable"}
    arguments = shlex.split(argv)
    if not arguments or arguments[0] != str(artifact):
        raise RuntimeError("refusing to signal a process we did not start")
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=20)
        return {"stopped": True, "signal": "SIGTERM", "exitCode": process.returncode}
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=20)
        return {"stopped": True, "signal": "SIGKILL", "exitCode": process.returncode}


def scrub_run_identity(value, *, nonce, owner_id, prefix):
    """Replace this run's own identities inside every string with fixed slots.

    A run's nonce appears inside document resource names, and those names appear
    inside diagnostics. Two runs of the same tool therefore differ in their
    message text even when they observed exactly the same thing. Scrubbing makes
    the comparison about behaviour rather than about which run it was.
    """
    replacements = [
        (prefix, "<prefix>"),
        (nonce, "<nonce>"),
        (owner_id, "<owner>"),
    ]
    if isinstance(value, dict):
        return {
            key: scrub_run_identity(
                entry, nonce=nonce, owner_id=owner_id, prefix=prefix
            )
            for key, entry in value.items()
        }
    if isinstance(value, list):
        return [
            scrub_run_identity(entry, nonce=nonce, owner_id=owner_id, prefix=prefix)
            for entry in value
        ]
    if isinstance(value, str):
        for needle, slot in replacements:
            if needle:
                value = value.replace(needle, slot)
        return value
    return value


def build_shadow_document(
    *,
    before,
    after,
    artifact_sha,
    binding,
    version,
    nonce,
    owner_id,
    elapsed,
    child,
    receipt,
    contract,
):
    """Build the published shadow record.

    This is the only place the record's shape is decided, so the checked-in
    evidence is something the tool produces rather than something a person
    assembled afterwards.
    """
    runtime = dict(binding)
    runtime["version"] = version
    instance = (receipt or {}).get("instance") or {}
    runtime["wrongControlTokenStatus"] = instance.get("wrongTokenStatus")
    runtime["childObservedArtifactSha256"] = instance.get("artifactSha256")
    result = {
        "kind": CONTRACT,
        "campaign": cases.CAMPAIGN,
        "casesDigest": cases.cases_digest(),
        "sourceDigestBefore": before,
        "sourceDigestAfter": after,
        "artifactSha256": artifact_sha,
        "runtime": runtime,
        "nonce": nonce,
        "ownerId": owner_id,
        "elapsedSeconds": elapsed,
        "child": child,
        "receipt": receipt,
        "selfContract": contract,
        "productionExecuted": False,
        "note": PUBLICATION_NOTE,
        "acquisitionValidated": False,
        "promotionReady": False,
    }
    result["complete"] = bool(
        runtime["artifactSha256"] == artifact_sha
        and runtime["runtimeInputsClean"] is True
        and runtime["childObservedArtifactSha256"] == artifact_sha
        and receipt
        and receipt.get("complete") is True
        and isinstance(child, dict)
        and child.get("stopped") is True
        and type(child.get("exitCode")) is int and child["exitCode"] == 0
        and child.get("signal") is None
        and child.get("timedOut", False) is False
        and child.get("failure") is None
        and type(runtime["wrongControlTokenStatus"]) is int
        and runtime["wrongControlTokenStatus"] == 403
        and contract
        and contract.get("classification") == comparison.MATCH
        and before == after
    )
    return result


def run_shadow(artifact, output):
    artifact = Path(artifact).resolve(strict=True)
    source_root = Path(__file__).resolve().parents[3]
    binding = runtime_binding(artifact, source_root)
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    output.chmod(0o700)
    before = plan_module.source_digest()
    retained = output / "fireemu"
    retained.write_bytes(artifact.read_bytes())
    retained.chmod(0o500)
    artifact_sha = hashlib.sha256(retained.read_bytes()).hexdigest()
    config = output / "config.json"
    save(config, CONFIG)
    config.chmod(0o400)
    nonce = "o3expiry-" + os.urandom(8).hex()
    owner_id = os.urandom(16).hex()
    argv = [
        str(retained),
        "exec",
        "--config",
        str(config),
        "--project",
        PROJECT,
        "--only",
        "firestore",
        "--firestore-port",
        "0",
        "--http-port",
        "0",
        "--hub-port",
        "0",
        "--ui-port",
        "0",
        "--logging-port",
        "0",
        "--log-verbosity",
        "silent",
        "--",
        sys.executable,
        str(Path(__file__).resolve()),
        "--child",
        str(output),
        "--nonce",
        nonce,
        "--owner",
        owner_id,
    ]
    environment = {key: os.environ[key] for key in ("PATH", "LANG", "LC_ALL", "SYSTEMROOT", "TMPDIR")
                   if key in os.environ}
    version = subprocess.check_output(
        [str(retained), "--version"], cwd=output, text=True, timeout=30, env=environment
    ).strip()
    save(output / "launch.json", {"kind": "txn-local-launch-v1", "nonce": nonce,
                                 "ownerId": owner_id, "sourceDigest": before,
                                 "artifactSha256": artifact_sha, "productionExecuted": False,
                                 "authorizesCleanup": False})
    started = time.monotonic()
    process = subprocess.Popen(argv, cwd=output, env=environment)
    timed_out = False
    try:
        process.wait(timeout=CHILD_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        timed_out = True
    finally:
        stopped = stop_child(process, retained)
    if timed_out:
        stopped["timedOut"] = True
    failures, input_digests = [], {}
    receipt, contract = None, None
    for name in ("receipt.json", "self-contract.json"):
        try:
            value, raw_digest = _read_result(output / name)
            input_digests[name] = raw_digest
            if name == "receipt.json":
                receipt = value
            else:
                contract = value
        except (OSError, ValueError, TypeError, RecursionError):
            failures.append("unusable-" + name)
    if receipt is not None:
        expected = {"kind": collector.CONTRACT, "campaign": cases.CAMPAIGN,
                    "casesDigest": cases.cases_digest(), "sourceDigest": before,
                    "target": "local", "timing": collector.CONTROL_CLOCK,
                    "projectId": PROJECT, "database": plan_module.DATABASE,
                    "documentPrefix": plan_module.document_prefix(nonce), "nonce": nonce}
        if any(type(receipt.get(key)) is not type(val) or receipt.get(key) != val
               for key, val in expected.items()):
            failures.append("receipt-run-binding-mismatch")
        instance = receipt.get("instance")
        try:
            if (not isinstance(instance, dict) or type(instance.get("parentPid")) is not int
                    or instance["parentPid"] != process.pid or type(instance.get("pid")) is not int
                    or instance["pid"] <= 0):
                raise ValueError("process binding")
            _local_origin(instance.get("firestoreOrigin"))
            _local_origin(instance.get("controlOrigin"))
        except (ValueError, TypeError, KeyError):
            failures.append("receipt-instance-binding-mismatch")
        try:
            computed = comparison.local_self_contract(receipt)
            # Canonical JSON keeps bool/int/float distinctions, unlike dict equality.
            if (json.dumps(computed, sort_keys=True, allow_nan=False)
                    != json.dumps(contract, sort_keys=True, allow_nan=False)):
                failures.append("self-contract-recomputation-mismatch")
        except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
            failures.append("self-contract-unusable")
    result = build_shadow_document(
        before=before,
        after=plan_module.source_digest(),
        artifact_sha=artifact_sha,
        binding=binding,
        version=version,
        nonce=nonce,
        owner_id=owner_id,
        elapsed=round(time.monotonic() - started, 3),
        child=stopped,
        receipt=receipt if not failures else None,
        contract=contract if not failures else None,
    )
    result["publication"] = {"contract": "txn-local-publication-v1",
                             "inputDigests": input_digests, "failures": failures}
    if failures:
        result["complete"] = False
    save(output / "shadow.json", result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--child", type=Path)
    parser.add_argument("--nonce")
    parser.add_argument("--owner")
    args = parser.parse_args(argv)
    if args.child is not None:
        child(args.child, args.nonce, args.owner)
        return 0
    if args.artifact is None or args.output is None:
        parser.error("--artifact and --output are required")
    try:
        result = run_shadow(args.artifact, args.output)
    except (OSError, ValueError, TypeError, subprocess.SubprocessError) as error:
        print(json.dumps({"complete": False, "failure": type(error).__name__,
                          "productionExecuted": False}), file=sys.stderr)
        return 2
    print(json.dumps({k: v for k, v in result.items() if k != "receipt"}, indent=2))
    return 0 if result["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
