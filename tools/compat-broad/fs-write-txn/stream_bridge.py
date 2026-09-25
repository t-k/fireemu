"""Finite Firestore stream policy selected only by the versioned shared Gate."""

from __future__ import annotations

import base64
import copy
import re
import shutil

from broad_contract import digest

CONTRACT = "shared-stream-v1"
PROTOCOL = "firestore-grpc-stream-v1"
REQUEST_SECONDS = 31
BOUNDS = {
    "rpcSlots": 25,
    "writeRpcs": 8,
    "writeOutboundFrames": 16,
    "outboundFrames": 33,
    "acceptedFrames": 290,
    "writes": 9,
    "maxMessageBytes": 1048576,
    "acceptedBytes": 286261248,
}


def compile_plan(project, nonce, owner):
    if (
        not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{4,62}", project)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{7,127}", nonce)
        or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", owner)
    ):
        raise ValueError("closed stream identity required")
    database = f"projects/{project}/databases/(default)"
    prefix = f"compat/o3/{nonce}"
    names = {
        role: f"{database}/documents/{prefix}/{suffix}"
        for role, suffix in [
            ("control", "control"),
            ("locked", "locked"),
            ("suffix", "contended-tail"),
        ]
    }

    def fields(role, value=None):
        result = {
            "owner": {"stringValue": f"o3-stream:{owner}"},
            "role": {"stringValue": role},
        }
        if value is not None:
            result["value"] = {"stringValue": value}
        return result

    def update(role, value=None, create=False):
        result = {"update": {"name": names[role], "fields": fields(role, value)}}
        if create:
            result["currentDocument"] = {"exists": False}
        return result

    def op(slot, method, request, dynamic=None):
        result = {
            "service": "firestore",
            "protocol": PROTOCOL,
            "slot": slot,
            "method": method,
            "request": request,
        }
        if dynamic:
            result["dynamic"] = dynamic
        return result

    def read(slot, role, dynamic=None):
        return op(slot, "GetDocument", {"name": names[role]}, dynamic)

    def write(slot, writes):
        return op(slot, "Write", [{"writes": writes}])

    observation = [
        read("preflight-control", "control"),
        read("preflight-locked", "locked"),
        write("setup-control", [update("control", create=True)]),
        write("setup-locked", [update("locked", "before", True)]),
        write("positive-uncontended-stream", [update("control", "accepted")]),
        read("readback-control", "control"),
        op(
            "begin-rw-transaction",
            "BeginTransaction",
            {"database": database, "options": {"readWrite": {}}},
        ),
        read("get-locked-with-transaction", "locked", "transaction"),
        read("preflight-suffix-absence", "suffix"),
        write(
            "contended-multiwrite-stream",
            [
                update("locked", "must-not-commit"),
                update("suffix", "must-not-commit", True),
            ],
        ),
        read("readback-locked", "locked"),
        read("readback-suffix", "suffix"),
        op("rollback", "Rollback", {"database": database}, "transaction"),
        write("post-rollback-positive-stream", [update("locked", "after-rollback")]),
        read("readback-post-rollback", "locked"),
    ]
    recovery = [
        op(
            "rollback-finally",
            "Rollback",
            {"database": database},
            "optional-transaction",
        )
    ]
    for role, name in names.items():
        recovery += [
            read(f"owned-read-{role}", role),
            op(
                f"conditional-delete-{role}",
                "Write",
                [{"writes": [{"delete": name}]}],
                "owned-version",
            ),
            read(f"typed-absence-{role}", role),
        ]
    return {
        "contract": CONTRACT,
        "protocol": PROTOCOL,
        "projectId": project,
        "nonce": nonce,
        "ownerId": owner,
        "nodeRuntime": node_runtime(),
        "documentPrefix": prefix,
        "streamBounds": dict(BOUNDS),
        "wallSeconds": 1100,
        "recoverySeconds": 320,
        "observationRequests": 15,
        "costMicrousd": 2500,
        "requestCostMicrousd": 100,
        "intervalSeconds": 0.25,
        "jobs": {
            "stream": {
                "resources": list(names.values()),
                "observation": observation,
                "recovery": recovery,
            }
        },
    }


def validate_plan(plan):
    expected = compile_plan(plan["projectId"], plan["nonce"], plan["ownerId"])
    if plan.get("managementProfile") is not None:
        from stream_production import PROFILE, with_management

        if plan["managementProfile"] != PROFILE:
            raise ValueError("unknown stream management profile")
        expected = with_management(expected)
    # Permission/source bindings may be added by the parent; execution policy is closed.
    extra = {"permissionDigest", "observerSha256"}
    if set(plan) - set(expected) - extra or any(
        plan.get(k) != v for k, v in expected.items()
    ):
        raise ValueError("stream plan differs from compiled scenario")


def timestamp(value):
    if (
        not isinstance(value, dict)
        or set(value) != {"seconds", "nanos"}
        or not isinstance(value["seconds"], str)
        or not re.fullmatch(r"-?(0|[1-9][0-9]*)", value["seconds"])
        or type(value["nanos"]) is not int
        or not 0 <= value["nanos"] < 1_000_000_000
        or not -62135596800 <= int(value["seconds"]) <= 253402300799
    ):
        raise ValueError("canonical timestamp required")
    return value


def token(value):
    if not isinstance(value, str) or not value or len(value) > 16384:
        raise ValueError("canonical transaction bytes required")
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError as error:
        raise ValueError("canonical transaction bytes required") from error
    if not decoded or base64.b64encode(decoded).decode() != value:
        raise ValueError("canonical transaction bytes required")
    return value


def resolve(state, job_name, recovery):
    job = state["jobs"][job_name]
    phase = "recovery" if recovery else "observation"
    operation = copy.deepcopy(state["plan"]["jobs"][job_name][phase][job[phase]])
    dynamic = operation.pop("dynamic", None)
    resource = (
        operation["request"].get("name")
        if isinstance(operation["request"], dict)
        else operation["request"][0]["writes"][0].get("delete")
    )
    skip = None
    if dynamic in {"transaction", "optional-transaction"}:
        transaction = job.get("transaction")
        if (
            transaction is None
            and dynamic == "optional-transaction"
            and not job.get("transactionUnknown")
        ):
            skip = "transaction-not-held"
        elif transaction is None:
            raise ValueError("journaled transaction required")
        else:
            proof_index = job.get("transactionEventIndex")
            if type(proof_index) is not int or not 0 <= proof_index < len(
                state["events"]
            ):
                raise ValueError("journaled transaction event required")
            proof_event = state["events"][proof_index]
            proof_raw = proof_event.get("receipt", {}).get("raw", {})
            if (
                proof_event.get("job") != job_name
                or proof_event.get("method") != "BeginTransaction"
                or proof_event.get("completed") is not True
                or proof_event.get("failure") is not None
                or grpc_code(proof_raw) != 0
                or proof_raw.get("response", {}).get("transaction") != transaction
            ):
                raise ValueError("journaled transaction token differs")
            operation["request"]["transaction"] = token(transaction)
    if dynamic == "owned-version":
        owned = job.get("latestOwnedVersions", {}).get(resource)
        read = job.get("ownedReads", {}).get(resource)
        creation = job["creationProofs"].get(resource)
        if job.get("transaction") or job.get("transactionUnknown"):
            raise ValueError("transaction release unknown; ownership retained")
        if (
            not owned
            or not read
            or not creation
            or read["updateTime"] != owned["updateTime"]
            or read["fieldsDigest"] != owned["fieldsDigest"]
        ):
            skip = "no-acknowledged-owned-version"
        else:
            operation["request"][0]["writes"][0]["currentDocument"] = {
                "updateTime": owned["updateTime"]
            }
    if operation["slot"] == "post-rollback-positive-stream" and (
        job.get("transaction") or job.get("transactionUnknown")
    ):
        raise ValueError("transaction release unknown")
    return operation, resource, skip


def debit(state, job, operation):
    used = job.setdefault(
        "streamUsed", {key: 0 for key in BOUNDS if key != "maxMessageBytes"}
    )
    writes = operation["request"][0]["writes"] if operation["method"] == "Write" else []
    amounts = {
        "rpcSlots": 1,
        "writeRpcs": int(bool(writes)),
        "writeOutboundFrames": 2 if writes else 0,
        "outboundFrames": 2 if writes else 1,
        "acceptedFrames": 32 if writes else 2,
        "writes": len(writes),
        "acceptedBytes": (32 if writes else 1) * BOUNDS["maxMessageBytes"],
    }
    if any(used[key] + amount > BOUNDS[key] for key, amount in amounts.items()):
        raise ValueError("stream frame/write/byte capacity")
    for key, amount in amounts.items():
        used[key] += amount


def grpc_code(receipt):
    if (
        not isinstance(receipt, dict)
        or receipt.get("kind") != "grpc_status"
        or receipt.get("complete") is not True
    ):
        return None
    error = receipt.get("error")
    if error is not None and (
        not isinstance(error, dict) or type(error.get("code")) is not int
    ):
        return None
    status = receipt.get("status")
    if status is None and "response" in receipt:
        return 0
    code = status.get("code") if isinstance(status, dict) else None
    return (
        code
        if type(code) is int
        and 0 <= code <= 16
        and (error is None or error["code"] == code)
        else None
    )


def stop_after_credential_rejection(receipt, credential, gate):
    """Fail the parent credential after recording a typed authentication refusal."""
    code = grpc_code(receipt.get("raw")) if isinstance(receipt, dict) else None
    if code in {7, 16}:
        credential.fail()
        gate.stop(environment=True)
        raise ValueError("stream credential rejected; cleanup remains required")


def record(state, job_name, operation, receipt, event):
    job = state["jobs"][job_name]
    if (
        not isinstance(receipt, dict)
        or receipt.get("protocol") != PROTOCOL
        or receipt.get("requestDigest") != digest(operation)
        or not isinstance(receipt.get("raw"), dict)
    ):
        raise ValueError("bound canonical gRPC receipt required")
    raw = receipt["raw"]
    limit = (32 if operation["method"] == "Write" else 1) * BOUNDS["maxMessageBytes"]
    if len(json.dumps(raw, separators=(",", ":")).encode()) > limit:
        raise ValueError("accepted receipt byte bound exceeded")
    code = grpc_code(raw)
    if code is None:
        raise ValueError("complete typed gRPC terminal required")
    if operation["method"] != "Write":
        if (
            raw.get("operation") != operation["method"]
            or raw.get("request") != operation["request"]
        ):
            raise ValueError("unary receipt request differs")
    else:
        sends = [e["value"] for e in raw.get("events", []) if e.get("type") == "send"]
        if (
            raw.get("transportReceiptVersion") != 2
            or raw.get("sentFrames") != len(sends)
            or raw.get("completedSendFrames") != len(sends)
            or not 1 <= len(sends) <= 2
            or sends[0]
            != {
                "database": f"projects/{state['plan']['projectId']}/databases/(default)"
            }
        ):
            raise ValueError("actual Write frame evidence required")
        if len(sends) == 2:
            responses = [e["value"] for e in raw["events"] if e.get("type") == "data"]
            if not responses or sends[1].get("streamToken") != responses[0].get(
                "streamToken"
            ):
                raise ValueError(
                    "Write stream token does not follow handshake response"
                )
            token(sends[1].get("streamToken"))
            payload = dict(sends[1])
            payload.pop("streamToken", None)
            if payload != operation["request"][0]:
                raise ValueError("actual Write payload differs")
        if code == 0 and len(sends) != 2:
            raise ValueError("successful payload acknowledgement missing")
        if (
            type(raw.get("receivedFrames")) is not int
            or raw["receivedFrames"] + len(sends) > 32
        ):
            raise ValueError("accepted frame bound exceeded")
    event.update(
        protocol=PROTOCOL,
        grpcCode=code,
        responseDigest=digest(receipt),
        completed=True,
        receipt=receipt,
    )
    event_index = len(state["events"]) - 1
    method = operation["method"]
    if method == "BeginTransaction":
        job["transactionUnknown"] = True
        if code == 0:
            job["transaction"] = token(raw.get("response", {}).get("transaction"))
            job["transactionUnknown"] = False
            job["transactionEventIndex"] = event_index
    if method == "Rollback":
        if code == 0:
            job["transaction"] = None
            job["transactionUnknown"] = False
        else:
            job["transactionUnknown"] = True
    if method == "Write" and code == 0:
        responses = [e["value"] for e in raw["events"] if e.get("type") == "data"]
        writes = operation["request"][0]["writes"]
        results = responses[-1].get("writeResults") if responses else None
        if not isinstance(results, list) or len(results) != len(writes):
            raise ValueError("complete Write acknowledgement cardinality required")
        pending = []
        for write, result in zip(writes, results, strict=True):
            if "delete" in write:
                continue
            update = write["update"]
            name = update["name"]
            proof = {
                "name": name,
                "updateTime": timestamp(result.get("updateTime")),
                "fieldsDigest": digest(update["fields"]),
                "eventIndex": event_index,
                "requestDigest": digest(operation),
                "responseDigest": digest(receipt),
            }
            previous = job.get("latestOwnedVersions", {}).get(name)
            create = write.get("currentDocument") == {"exists": False}
            if not create and (name not in job["creationProofs"] or previous is None):
                raise ValueError("mutation without journaled creation")
            proof["predecessor"] = previous["eventIndex"] if previous else None
            pending.append((name, proof, create))
        for name, proof, create in pending:
            if create:
                job["creationProofs"].setdefault(name, copy.deepcopy(proof))
            job.setdefault("latestOwnedVersions", {})[name] = proof
            if name not in job["owned"]:
                job["owned"].append(name)
    if method == "GetDocument":
        resource = operation["request"]["name"]
        if code == 0:
            body = raw.get("response")
            if (
                not isinstance(body, dict)
                or body.get("name") != resource
                or not isinstance(body.get("fields"), dict)
            ):
                raise ValueError("readback identity/body mismatch")
            version = timestamp(body.get("updateTime"))
            if operation["slot"].startswith("owned-read-"):
                job.setdefault("ownedReads", {})[resource] = {
                    "updateTime": version,
                    "fieldsDigest": digest(body["fields"]),
                    "eventIndex": event_index,
                }
        if (
            event["phase"] == "recovery"
            and operation["slot"].startswith("typed-absence-")
            and code == 5
        ):
            job.setdefault("absenceProofs", {})[resource] = {
                "eventIndex": event_index,
                "receipt": receipt,
            }
            if resource not in job["absent"]:
                job["absent"].append(resource)


def validate_absence(state, job_name):
    if state["plan"].get("managementProfile"):
        from stream_production import metadata_valid

        metadata_valid(state)
    job = state["jobs"][job_name]
    slots = state["plan"]["jobs"][job_name]["recovery"]
    if (
        job.get("transaction")
        or job.get("transactionUnknown")
        or job["recovery"] != len(slots)
        or set(job.get("absenceProofs", {})) != set(job["resources"])
    ):
        raise ValueError("typed stream cleanup/release incomplete")
    for resource, proof in job["absenceProofs"].items():
        candidates = [
            i
            for i, op in enumerate(slots)
            if op["slot"].startswith("typed-absence-")
            and op["request"] == {"name": resource}
        ]
        index = proof.get("eventIndex")
        if (
            len(candidates) != 1
            or type(index) is not int
            or not 0 <= index < len(state["events"])
        ):
            raise ValueError("typed stream absence event missing")
        event = state["events"][index]
        receipt = proof.get("receipt", {})
        if (
            event.get("job") != job_name
            or event.get("phase") != "recovery"
            or event.get("index") != candidates[0]
            or event.get("requestDigest") != digest(slots[candidates[0]])
            or event.get("completed") is not True
            or event.get("failure") is not None
            or event.get("protocol") != PROTOCOL
            or event.get("grpcCode") != 5
            or receipt.get("requestDigest") != event["requestDigest"]
            or receipt.get("protocol") != PROTOCOL
            or grpc_code(receipt.get("raw")) != 5
            or receipt.get("raw", {}).get("request") != {"name": resource}
            or event.get("responseDigest") != digest(receipt)
            or event.get("receipt") != receipt
        ):
            raise ValueError("typed stream absence evidence differs")


# One bounded private socket; no bearer material is written to files or stdout.
import hashlib
import json
import socket
import struct
import subprocess
import time
from pathlib import Path

MAX_IPC_BYTES = 4 * 1024 * 1024


def read_message(channel):
    original_timeout = channel.gettimeout()
    deadline = time.monotonic() + REQUEST_SECONDS

    def exact(count):
        chunks = bytearray()
        while len(chunks) < count:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("private message deadline")
            channel.settimeout(min(remaining, original_timeout or REQUEST_SECONDS))
            chunk = channel.recv(count - len(chunks))
            if not chunk:
                raise ValueError("private stream channel closed")
            chunks.extend(chunk)
        return bytes(chunks)

    size = struct.unpack("!I", exact(4))[0]
    if not 0 < size <= MAX_IPC_BYTES:
        raise ValueError("bounded private message required")

    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate private message key")
            value[key] = item
        return value

    result = json.loads(
        exact(size),
        object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(
            ValueError("finite JSON required")
        ),
    )
    if not isinstance(result, dict):
        raise ValueError("private message object required")  # noqa: TRY004 -- Protocol failures share ValueError.
    return result


def write_message(channel, value):
    raw = json.dumps(value, separators=(",", ":"), allow_nan=False).encode()
    if not 0 < len(raw) <= MAX_IPC_BYTES:
        raise ValueError("bounded private message required")
    channel.sendall(struct.pack("!I", len(raw)) + raw)


def node_runtime():
    executable = shutil.which("node")
    if executable is None:
        raise ValueError("verified Node runtime required")
    path = Path(executable).resolve(strict=True)
    if not path.is_file() or path.stat().st_mode & 0o022:
        raise ValueError("private trusted Node runtime required")
    return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def verify_execution_bindings(source, runtime):
    path = Path(runtime["path"])
    if (
        not path.is_absolute()
        or path.is_symlink()
        or not path.is_file()
        or path.stat().st_mode & 0o022
        or hashlib.sha256(path.read_bytes()).hexdigest() != runtime["sha256"]
        or source_digest() != source
    ):
        raise ValueError("stream source/runtime binding changed")


def source_digest():
    directory = Path(__file__).parent
    paths = [
        directory / name
        for name in (
            "stream_bridge.py",
            "stream_worker.mjs",
            "stream_collector.mjs",
            "stream_node_transport.mjs",
            "transport_internal.mjs",
            "stream_production.py",
            "credential_prep.py",
            "stream_shadow.py",
            "stream_comparison.mjs",
        )
    ]
    paths += [
        directory.parent / "shared_gate.py",
        directory.parent / "shared_production.py",
        directory.parent / "batch_adapter.py",
        directory.parent / "batch_contract.py",
        directory.parent / "batch_wire.py",
        directory.parent.parent / "compat-inventory" / "owned_runner.py",
        directory.parent.parent / "compat-inventory" / "evidence_common.py",
        directory.parent / "production-admission" / "reservations.py",
    ]
    return digest(
        {
            str(path.relative_to(directory.parent.parent)): hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
            for path in paths
        }
    )


def _run_worker(
    plan,
    gate,
    ledger,
    ticket,
    *,
    mode,
    port,
    authorize,
    before_recovery=None,
    after_record=None,
    finalize=True,
):
    frozen = copy.deepcopy(plan)
    validate_plan(frozen)
    claim = ledger.bound_claim(ticket)
    if claim["gatePlanDigest"] != digest(frozen) or claim["gatePath"] != str(
        gate.path.resolve()
    ):
        raise ValueError("stream reservation Gate identity differs")
    # Reject an expired reservation before starting a worker or charging a slot.
    # Each wire grant still revalidates after any subsequent admission wait.
    ledger.validate(ticket, duration=REQUEST_SECONDS)
    ticket = copy.deepcopy(ticket)
    frozen_source = source_digest()
    parent, child = socket.socketpair()
    parent.settimeout(REQUEST_SECONDS)
    env = {"STREAM_CHANNEL_FD": str(child.fileno())}
    worker = None
    try:
        verify_execution_bindings(frozen_source, frozen["nodeRuntime"])
        worker = subprocess.Popen(
            [
                frozen["nodeRuntime"]["path"],
                str(Path(__file__).with_name("stream_worker.mjs")),
            ],
            pass_fds=(child.fileno(),),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        child.close()
        write_message(
            parent,
            {
                "type": "init",
                "protocol": PROTOCOL,
                "planDigest": digest(frozen),
                "job": "stream",
                "plan": frozen,
                "mode": mode,
                "port": port,
            },
        )
        message_id = 0
        recovery_started = False
        while True:
            message = read_message(parent)
            if message.get("type") == "done":
                if (
                    set(message)
                    != {"type", "protocol", "planDigest", "job", "id", "result"}
                    or message.get("id") != message_id
                    or message.get("protocol") != PROTOCOL
                    or message.get("planDigest") != digest(frozen)
                    or message.get("job") != "stream"
                ):
                    raise ValueError("private completion binding differs")
                write_message(parent, {"type": "shutdown"})
                worker.wait(timeout=1)
                if worker.returncode != 0:
                    raise ValueError("stream worker did not close")
                verify_execution_bindings(frozen_source, frozen["nodeRuntime"])
                if finalize:
                    gate.finish()
                    ledger.finish(ticket)
                return message["result"]
            message_id += 1
            if (
                set(message)
                != {
                    "type",
                    "protocol",
                    "planDigest",
                    "job",
                    "id",
                    "phase",
                    "index",
                    "operation",
                }
                or message.get("type") != "request"
                or message.get("protocol") != PROTOCOL
                or message.get("planDigest") != digest(frozen)
                or message.get("job") != "stream"
                or type(message.get("id")) is not int
                or message["id"] != message_id
                or message.get("phase") not in {"observation", "recovery"}
            ):
                raise ValueError("private request binding differs")
            recovery = message["phase"] == "recovery"
            if recovery and not recovery_started:
                recovery_started = True
                if before_recovery is not None:
                    before_recovery()
            snapshot = gate.snapshot()
            if (
                type(message["index"]) is not int
                or message["index"] != snapshot["jobs"]["stream"][message["phase"]]
            ):
                raise ValueError("private slot binding differs")
            operation, _, skip = resolve(snapshot, "stream", recovery)
            if not recovery and message["operation"] != operation:
                raise ValueError("private descriptor differs from compiled request")
            if recovery and message["operation"] is not None:
                raise ValueError("recovery request is parent-resolved")
            binding = {
                key: message[key]
                for key in ("protocol", "planDigest", "job", "id", "phase", "index")
            }
            used = False

            def send(
                recovery=recovery,
                snapshot=snapshot,
                operation=operation,
                binding=binding,
            ):
                nonlocal used
                if (
                    used
                    or source_digest() != frozen_source
                    or gate.plan_digest != digest(frozen)
                ):
                    raise ValueError("single-use source/plan binding differs")
                used = True
                verify_execution_bindings(frozen_source, frozen["nodeRuntime"])
                ledger.validate(ticket, duration=REQUEST_SECONDS)
                if ledger.bound_claim(ticket) != claim:
                    raise ValueError("stream claim changed")
                metadata, metadata_expiry, permission_expiry = authorize(recovery)
                now = time.time()
                phase_end = (
                    snapshot["started"]
                    + frozen["wallSeconds"]
                    - (0 if recovery else frozen["recoverySeconds"])
                )
                phase_expiry = now + phase_end - time.monotonic()
                if (
                    min(metadata_expiry, permission_expiry, phase_expiry)
                    < now + REQUEST_SECONDS
                ):
                    raise ValueError("stream grant lease expired")
                write_message(
                    parent,
                    {
                        **binding,
                        "type": "grant",
                        "operation": operation,
                        "requestDigest": digest(operation),
                        "metadata": metadata,
                        "metadataExpiresAt": int(metadata_expiry * 1000),
                        "permissionExpiresAt": int(permission_expiry * 1000),
                        "phaseDeadlineAt": int(phase_expiry * 1000),
                        "deadlineMs": 30000,
                    },
                )
                receipt = read_message(parent)
                if (
                    set(receipt) != set(binding) | {"type", "receipt"}
                    or receipt.get("type") != "receipt"
                    or any(receipt.get(k) != v for k, v in binding.items())
                ):
                    raise ValueError("private receipt binding differs")
                return receipt["receipt"]

            result = gate.dispatch(operation, recovery, send)
            write_message(
                parent,
                {
                    **binding,
                    "type": "recorded",
                    "receiptDigest": digest(result),
                    "skipped": skip,
                    "operation": operation,
                },
            )
            if after_record is not None:
                after_record(result)
    except BaseException:
        # The Gate conservatively retains uncertainty on all stream exceptions.
        try:
            write_message(parent, {"type": "denied"})
        except (OSError, ValueError):
            pass
        raise
    finally:
        parent.close()
        child.close()
        if worker is not None and worker.poll() is None:
            worker.terminate()
            try:
                worker.wait(timeout=1)
            except subprocess.TimeoutExpired:
                worker.kill()
                worker.wait(timeout=1)


def run_local(plan, path, ledger, ticket, *, port):
    from shared_gate import Gate, create

    if (
        not plan["projectId"].startswith("demo-")
        or type(port) is not int
        or not 1 <= port <= 65535
    ):
        raise ValueError("owned demo-project loopback fixture required")
    create(path, plan)
    gate = Gate(path, "stream")
    gate.claim()

    def authorize(_recovery):
        return {"authorization": "Bearer owner"}, time.time() + 1200, time.time() + 1200

    return _run_worker(
        plan, gate, ledger, ticket, mode="local", port=port, authorize=authorize
    )


def run_reserved(
    plan, gate, ledger, ticket, coordinator, *, before_recovery=None, finalize=True
):
    """Internal prepared-parent entrypoint. Never issues permission or obtains tokens."""
    from batch_contract import PROJECT, Credential
    from shared_production import Coordinator

    if not isinstance(coordinator, Coordinator):
        raise TypeError("existing prepared Coordinator required")
    permission = copy.deepcopy(coordinator.permission)
    credential = coordinator.credential
    if (
        not isinstance(credential, Credential)
        or plan.get("permissionDigest") != digest(permission)
        or plan.get("observerSha256") != source_digest()
        or permission.get("collectorSourceDigest") != source_digest()
        or permission.get("project") != PROJECT
        or plan["projectId"] != PROJECT
    ):
        raise ValueError("prepared stream permission/source required")

    def authorize(recovery):
        now = time.monotonic()
        if (
            coordinator.gate is not gate
            or coordinator.credential is not credential
            or coordinator.ready is not True
            or coordinator.local is not None
            or coordinator.nonce != plan["nonce"]
            or digest(coordinator.permission) != digest(permission)
            or not credential.usable(now, REQUEST_SECONDS)
        ):
            raise ValueError("prepared stream identity/credential changed")
        expiry = permission.get("expiresAt")
        if type(expiry) not in (float, int) or time.time() + REQUEST_SECONDS > expiry:
            raise ValueError("stream permission expired")
        return (
            {"authorization": "Bearer " + credential.token},
            time.time() + credential.expiry - now,
            expiry,
        )

    def after_record(receipt):
        stop_after_credential_rejection(receipt, credential, gate)

    authorize(False)
    return _run_worker(
        plan,
        gate,
        ledger,
        ticket,
        mode="fixed-tls",
        port=None,
        authorize=authorize,
        before_recovery=before_recovery,
        after_record=after_record,
        finalize=finalize,
    )


def write_private_json(path, value):
    path = Path(path)
    import os

    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream, allow_nan=False)
        stream.flush()
        os.fsync(stream.fileno())
