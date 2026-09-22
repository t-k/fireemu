"""Explicit owned first-batch adapter. CLI planning is offline; execution requires owner approval."""

from __future__ import annotations

# ruff: noqa: BLE001 -- Latch credential failures and retain independent cleanup failures.
import argparse
import hashlib
import json
import math
import os
import re
import selectors
import signal
import subprocess
import sys
import time
import urllib.parse
from datetime import datetime
from pathlib import Path

from batch_contract import (
    NUMBER,
    PROJECT,
    Budget,
    Credential,
    approve,
    candidate,
    compile_firestore,
    database_evidence,
    recording_exit_code,
)
from broad_contract import ROOT, digest, local_origin

HERE = Path(__file__).resolve().parent
HOSTS = {
    "identitytoolkit.googleapis.com",
    "securetoken.googleapis.com",
    "firestore.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "www.googleapis.com",
    "apikeys.googleapis.com",
}
MAX_WORKER_STDOUT = 131072
MAX_WORKER_STDERR = 8192
MAX_WORKER_URL = 65536
MAX_WORKER_HEADERS = 65536
MAX_WORKER_INPUT = 262144


class WorkerProcessError(ValueError):
    """A bounded worker failure with truthful, secret-free process state."""

    def __init__(self, message, process_receipt):
        super().__init__(message)
        self.process_receipt = process_receipt


def _process_receipt(
    *, pid, returncode, worker_reaped, termination, deadline_exceeded=False, started=True
):
    return {
        "pid": pid,
        "returncode": returncode,
        "workerReaped": worker_reaped,
        "termination": termination,
        "deadlineExceeded": deadline_exceeded,
        "started": started,
    }


def _cleanup_worker(worker, *, termination, deadline_exceeded=False):
    """Terminate this child and report only state confirmed by wait/poll."""
    if worker.poll() is None:
        try:
            worker.kill()
        except OSError:
            pass
    try:
        worker.communicate(timeout=1)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        try:
            worker.kill()
        except OSError:
            pass
        try:
            worker.wait(timeout=1)
        except (OSError, subprocess.TimeoutExpired):
            pass
    return _process_receipt(
        pid=worker.pid,
        returncode=worker.poll(),
        worker_reaped=worker.poll() is not None,
        termination=termination,
        deadline_exceeded=deadline_exceeded,
    )


def _bounded_worker_exchange(worker, payload, deadline):
    """Exchange bounded bytes with one worker without unbounded pipe reads."""
    selector = selectors.DefaultSelector()
    streams = {}
    output = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": MAX_WORKER_STDOUT, "stderr": MAX_WORKER_STDERR}
    input_bytes = payload.encode()
    input_offset = 0
    failure = None
    timed_out = False

    def close_stream(name):
        stream = streams.pop(name, None)
        if stream is not None:
            try:
                selector.unregister(stream)
            except (KeyError, ValueError):
                pass
            stream.close()

    try:
        for name, stream in (("stdout", worker.stdout), ("stderr", worker.stderr)):
            streams[name] = stream
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        stdin = worker.stdin
        if stdin is not None:
            os.set_blocking(stdin.fileno(), False)
            streams["stdin"] = stdin
            selector.register(stdin, selectors.EVENT_WRITE, "stdin")

        while streams:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            events = selector.select(remaining)
            if not events:
                timed_out = True
                break
            for key, mask in events:
                name = key.data
                stream = key.fileobj
                try:
                    if name == "stdin":
                        if input_offset == len(input_bytes):
                            close_stream("stdin")
                            continue
                        written = os.write(stream.fileno(), input_bytes[input_offset:])
                        input_offset += written
                        if input_offset == len(input_bytes):
                            close_stream("stdin")
                    else:
                        chunk = os.read(stream.fileno(), 65536)
                        if not chunk:
                            close_stream(name)
                            continue
                        output[name].extend(chunk)
                        if len(output[name]) > limits[name]:
                            failure = "output-limit"
                            break
                except (BrokenPipeError, OSError):
                    failure = "exchange-failed"
                    break
            if failure is not None:
                break
    finally:
        selector.close()

    if failure is not None or timed_out:
        if worker.poll() is None:
            try:
                worker.kill()
            except OSError:
                pass
        try:
            worker.wait(timeout=0.1)
        except (OSError, subprocess.TimeoutExpired):
            pass
    else:
        try:
            worker.wait(timeout=max(0.0, min(0.1, deadline - time.monotonic())))
        except (OSError, subprocess.TimeoutExpired):
            failure = "exchange-failed"
            if worker.poll() is None:
                try:
                    worker.kill()
                except OSError:
                    pass
                try:
                    worker.wait(timeout=0.1)
                except (OSError, subprocess.TimeoutExpired):
                    pass

    for stream in list(streams.values()):
        stream.close()
    receipt = _process_receipt(
        pid=worker.pid,
        returncode=worker.poll(),
        worker_reaped=worker.poll() is not None,
        termination="deadline" if timed_out else (failure or "exited"),
        deadline_exceeded=timed_out,
    )
    if failure is not None:
        raise WorkerProcessError(
            "bounded worker output exceeded"
            if failure == "output-limit"
            else "bounded worker exchange failed",
            receipt,
        ) from None
    if timed_out:
        raise WorkerProcessError("whole request deadline exceeded", receipt) from None
    try:
        return bytes(output["stdout"]).decode(), receipt
    except UnicodeDecodeError:
        raise WorkerProcessError("bounded worker returned malformed output", receipt) from None


def _utf8_size(value, limit, label):
    total = 0
    for offset in range(0, len(value), 4096):
        total += len(value[offset : offset + 4096].encode())
        if total > limit:
            raise ValueError(f"{label} bound exceeded")
    return total


def _validate_json_value(value, *, depth=0, nodes=None, active=None, budget=None):
    """Validate bounded JSON inputs before json.dumps can materialize them."""
    if nodes is None:
        nodes = [0]
    if active is None:
        active = set()
    if budget is None:
        budget = [0]

    def charge(amount):
        budget[0] += amount
        if budget[0] > 16384:
            raise ValueError("request body bound exceeded")

    nodes[0] += 1
    if nodes[0] > 4096 or depth > 64:
        raise ValueError("request JSON structure bound exceeded")
    if value is None or isinstance(value, (bool, int)):
        charge(len(json.dumps(value, allow_nan=False)))
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("request JSON contains non-finite number")
        charge(len(json.dumps(value, allow_nan=False)))
        return
    if isinstance(value, str):
        _utf8_size(value, 16384, "request body")
        charge(len(json.dumps(value, allow_nan=False)))
        return
    if not isinstance(value, (list, dict)):
        raise ValueError("request JSON type is invalid")
    identity = id(value)
    if identity in active:
        raise ValueError("request JSON cycle is invalid")
    active.add(identity)
    try:
        if isinstance(value, list):
            charge(1)
            first = True
            for item in value:
                if not first:
                    charge(2)
                first = False
                _validate_json_value(
                    item, depth=depth + 1, nodes=nodes, active=active, budget=budget
                )
            charge(1)
        else:
            charge(1)
            first = True
            for key, item in value.items():
                if not isinstance(key, str):
                    raise ValueError("request JSON object key is invalid")
                _utf8_size(key, 16384, "request body")
                if not first:
                    charge(2)
                first = False
                charge(len(json.dumps(key, allow_nan=False)) + 2)
                _validate_json_value(
                    item, depth=depth + 1, nodes=nodes, active=active, budget=budget
                )
            charge(1)
    finally:
        active.remove(identity)


def _run_worker(payload, timeout, *, include_process_receipt):
    if not include_process_receipt:
        try:
            result = subprocess.run(
                [sys.executable, "-I", "-S", "-B", str(HERE / "batch_wire.py")],
                input=payload,
                text=True,
                capture_output=True,
                timeout=timeout,
                env={k: os.environ[k] for k in ("PATH", "SYSTEMROOT", "LANG") if k in os.environ},
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise ValueError("whole request deadline exceeded") from None
        if result.returncode != 0:
            raise ValueError("bounded transport failed")
        return result.stdout, None

    deadline = time.monotonic() + timeout
    env = {k: os.environ[k] for k in ("PATH", "SYSTEMROOT", "LANG") if k in os.environ}
    try:
        worker = subprocess.Popen(
            [sys.executable, "-I", "-S", "-B", str(HERE / "batch_wire.py")],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
    except OSError:
        receipt = _process_receipt(
            pid=None,
            returncode=None,
            worker_reaped=False,
            termination="start-failed",
            started=False,
        )
        raise WorkerProcessError("bounded worker failed to start", receipt) from None

    stdout, receipt = _bounded_worker_exchange(worker, payload, deadline)
    returncode = receipt["returncode"]
    if not receipt["workerReaped"]:
        raise WorkerProcessError("bounded worker was not reaped", receipt)
    if returncode != 0:
        raise WorkerProcessError("bounded transport failed", receipt)
    return stdout, receipt


def _creation_version(name, fields, status, body):
    """Return a version only for an exact acknowledged conditional create."""
    if (
        status != 200
        or not isinstance(body, dict)
        or body.get("name") != name
        or digest(body.get("fields")) != digest(fields)
        or not isinstance(body.get("updateTime"), str)
        or not re.fullmatch(
            r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z",
            body["updateTime"],
        )
    ):
        raise ValueError("conditional creation acknowledgement mismatch")
    try:
        datetime.fromisoformat(body["updateTime"].replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("conditional creation version is invalid") from error
    return body["updateTime"]


def _document_version(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z", value
    ):
        raise ValueError("document write acknowledgement version is invalid")
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("document write acknowledgement version is invalid") from error
    return value


def request_headers(token, *, local, form):
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
        if form
        else "application/json"
    }
    if token:
        headers["Authorization"] = "Bearer " + token
        if not local:
            headers["x-goog-user-project"] = PROJECT
    return headers


def wire(
    url,
    method,
    body,
    headers,
    *,
    local=False,
    timeout=12,
    receipt=False,
    process_receipt=False,
):
    if not isinstance(url, str):
        raise ValueError("request URL is invalid")
    parsed = urllib.parse.urlsplit(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    if local:
        local_origin(origin)
    elif (
        parsed.scheme != "https"
        or parsed.hostname not in HOSTS
        or parsed.port
        or parsed.username
        or parsed.password
    ):
        raise ValueError("remote origin refused")
    if parsed.fragment or timeout <= 0 or timeout > 12:
        raise ValueError("invalid request boundary")
    if not isinstance(method, str) or not method or len(method.encode()) > 128:
        raise ValueError("request method bound exceeded")
    try:
        _utf8_size(url, MAX_WORKER_URL, "request URL")
    except UnicodeEncodeError:
        raise ValueError("request URL is invalid") from None
    if not isinstance(headers, dict):
        raise ValueError("request headers are invalid")
    header_size = 0
    for key, value in headers.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ValueError("request headers are invalid")
        try:
            header_size += _utf8_size(key, MAX_WORKER_HEADERS, "request headers")
            header_size += _utf8_size(value, MAX_WORKER_HEADERS, "request headers")
        except UnicodeEncodeError:
            raise ValueError("request headers are invalid") from None
    if header_size > MAX_WORKER_HEADERS:
        raise ValueError("request headers bound exceeded")
    if body is None:
        data = None
    elif isinstance(body, str):
        _validate_json_value(body)
        data = body
    else:
        _validate_json_value(body)
        data = json.dumps(body, allow_nan=False)
        _utf8_size(data, 16384, "request body")
    payload = json.dumps(
        {
            "url": url,
            "method": method,
            "body": data,
            "headers": headers,
            "receipt": receipt or process_receipt,
        }
    )
    try:
        payload_size = len(payload.encode())
    except UnicodeEncodeError:
        raise ValueError("request payload is invalid") from None
    if payload_size > MAX_WORKER_INPUT:
        raise ValueError("request payload bound exceeded")
    output, process = _run_worker(
        payload, timeout, include_process_receipt=process_receipt
    )
    try:
        decoded = json.loads(output)
    except (json.JSONDecodeError, UnicodeDecodeError):
        if process is not None:
            raise WorkerProcessError("bounded worker returned malformed output", process) from None
        raise ValueError("bounded transport returned malformed output") from None
    if process is None:
        return decoded
    if not isinstance(decoded, dict) or not isinstance(decoded.get("http"), dict):
        raise WorkerProcessError("bounded worker returned malformed output", process)
    http = decoded["http"]
    required = ("status", "complete", "bodyKind")
    if any(key not in http for key in required) or "body" not in decoded:
        raise WorkerProcessError("bounded worker returned malformed output", process)
    if (
        not isinstance(http["status"], int)
        or isinstance(http["status"], bool)
        or not isinstance(http["complete"], bool)
        or not isinstance(http["bodyKind"], str)
    ):
        raise WorkerProcessError("bounded worker returned malformed output", process)
    return {
        "status": http["status"],
        "complete": http["complete"],
        "workerReaped": process["workerReaped"],
        "bodyKind": http["bodyKind"],
        "body": decoded["body"],
        "process": process,
    }


def observer_digest():
    return digest(
        {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in HERE.glob("*.py")
            if p.name not in {"campaign_explain.py", "campaign_explain_shadow.py", "test_campaign_explain.py"}
        }
    )


class Adapter:
    def __init__(self, manifest, nonce, output, *, local_origins=None, permission=None):
        self.manifest = manifest
        self.nonce = nonce
        self.compiled = compile_firestore(manifest, nonce)
        self.permission = permission
        if local_origins is None:
            approve(manifest, permission or {}, nonce, observer_digest(), time.time())
            frozen = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
            ).strip()
            if (permission or {}).get(
                "frozenCommit"
            ) != frozen or subprocess.check_output(
                ["git", "status", "--porcelain"], cwd=ROOT
            ).strip():
                raise ValueError("approved frozen checkout required")
            if not os.environ.get("PRODUCTION_ORACLE_API_KEY"):
                raise ValueError("API key required")
            state = Path.home() / ".local/state/fireemu-broad/consumed"
            state.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(state / nonce, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as stream:
                stream.write(digest(permission))
                stream.flush()
                os.fsync(stream.fileno())
        self.api_key = (
            "fake" if local_origins else os.environ["PRODUCTION_ORACLE_API_KEY"]
        )
        self.ready = local_origins is not None
        self.local = local_origins
        if self.local:
            for value in self.local.values():
                local_origin(value)
            if set(self.local) != {"auth", "firestore"}:
                raise ValueError("two owned local origins required")
        self.initialize_state(output, nonce)

    def initialize_state(self, output, nonce):
        """Initialize inert bookkeeping only; admission belongs to each constructor."""
        self.shared_gate = None
        self.output = output
        output.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.journal = output / "ownership.jsonl"
        self.budget = Budget(time.monotonic())
        self.credential = Credential()
        self.last_request = 0
        self.documents = set()
        self.preflight_absent = set()
        self.accounts = {}
        self.token_roles = {}
        self.last_observation = None
        self.last_auth_operation = None
        self.tokens = set()
        self.refresh_tokens = set()
        self.creation_proofs = {}
        self.emails = {
            f"broad-{nonce}-{label}@example.invalid" for label in ("a", "b", "weak")
        }
        self.rows = []
        self.auth_evidence = []
        self.database_observations = []
        self.unrecovered = []

    def auth_query_key(self):
        return self.api_key

    def record(self, event):
        fd = os.open(self.journal, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a") as stream:
            stream.write(json.dumps(event, allow_nan=False) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        directory = os.open(self.output, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def reserve(self, service, duration=12):
        now = time.monotonic()
        delay = max(0, self.last_request + 0.25 - now)
        self.budget.reserve(service, now, duration + delay)
        time.sleep(delay)
        self.last_request = time.monotonic()

    def access(self):
        if self.credential.failed:
            raise ValueError("administrator credential rejected; failure latched")
        if self.local:
            return "owner"
        c = self.credential
        if c.failed:
            raise ValueError("authentication failure latched")
        if not c.usable(time.monotonic()):
            try:
                if c.attempts >= 2:
                    raise ValueError("refresh attempt limit")
                # Command + tokeninfo + following request + rate spacing must all fit.
                self.reserve("metadata", 86)
                c.attempts += 1
                value = subprocess.run(
                    ["gcloud", "auth", "application-default", "print-access-token"],
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=True,
                )
                token = value.stdout.strip()
                self.reserve("metadata")
                sent = time.monotonic()
                status, info, _ = wire(
                    "https://www.googleapis.com/oauth2/v1/tokeninfo",
                    "POST",
                    urllib.parse.urlencode({"access_token": token}),
                    {"Content-Type": "application/x-www-form-urlencoded"},
                )
                if status != 200:
                    raise ValueError("tokeninfo refused")
                c.accept(token, info, sent)
                if not c.usable(time.monotonic()):
                    raise ValueError("token expired during verification")
            except Exception:
                c.fail()
                raise ValueError("administrator credential unavailable") from None
        return c.token

    def request(
        self, service, path, body=None, *, method="POST", privileged=False, form=False
    ):
        gate = getattr(self, "shared_gate", None)
        if gate is not None and not getattr(self, "_shared_dispatch", False):
            operation = {
                "service": service,
                "path": path,
                "body": body,
                "method": method,
                "privileged": privileged,
                "form": form,
            }
            return gate.adapter_request(
                self,
                operation,
                lambda: self.request(
                    service, path, body, method=method, privileged=privileged, form=form
                ),
            )
        if service != "metadata" and not self.ready:
            raise ValueError("metadata preflight required")
        if self.budget.recovery and not privileged:
            raise ValueError("only verified cleanup allowed during recovery")
        token = self.access() if privileged else None
        self.reserve(service)
        headers = request_headers(token, local=bool(self.local), form=form)
        if token:
            if not self.local and not self.credential.usable(time.monotonic()):
                raise ValueError("credential no longer covers request")
            self.auth_evidence.append(
                {
                    "operation": path.split("?", 1)[0],
                    "phase": "recovery" if self.budget.recovery else "observation",
                    "verifiedRemainingSeconds": None
                    if self.local
                    else self.credential.expiry - time.monotonic(),
                    "basis": "local-owner" if self.local else "tokeninfo",
                }
            )
        if self.local:
            if service == "metadata":
                raise ValueError("metadata disabled in local adapter")
            origin = self.local[service]
            if service == "firestore":
                url = origin + path
            else:
                url = origin + "/" + path
        else:
            url = (
                "https://firestore.googleapis.com" + path
                if service == "firestore"
                else "https://" + path
            )
        status, result, content_type = wire(
            url,
            method,
            urllib.parse.urlencode(body or {}) if form else body,
            headers,
            local=bool(self.local),
        )
        observation = {
            "httpStatus": status,
            "mediaType": content_type.split(";", 1)[0].strip().lower(),
            "body": result,
        }
        if gate is not None:
            observation["sharedRequestDigest"] = digest(
                {
                    "service": service,
                    "path": path,
                    "body": body,
                    "method": method,
                    "privileged": privileged,
                    "form": form,
                }
            )
        self.last_observation = observation
        # Private bounded responses survive even when a stop condition prevents a row.
        fd = os.open(
            self.output / "responses.jsonl",
            os.O_WRONLY | os.O_APPEND | os.O_CREAT,
            0o600,
        )
        with os.fdopen(fd, "a") as stream:
            stream.write(
                json.dumps(
                    {
                        "service": service,
                        "route": path.split("?", 1)[0],
                        "phase": "recovery" if self.budget.recovery else "observation",
                        "response": observation,
                        "digest": digest(observation),
                    },
                    allow_nan=False,
                )
                + "\n"
            )
            stream.flush()
            os.fsync(stream.fileno())
        if privileged and status in {401, 403}:
            self.credential.fail()
            raise ValueError("administrator credential rejected")
        if status >= 500 or status == 429 or "nonJson" in result:
            raise ValueError("unexpected response; stop observations")
        return status, result

    def doc(self, name, *, method="GET", body=None, query=""):
        if name not in self.documents:
            raise ValueError("document not journaled")
        return self.request(
            "firestore", "/v1/" + name + query, body, method=method, privileged=True
        )

    def firestore(self):
        for program in self.compiled:
            # Admission includes every possible target, including refused/absent writes.
            for name in program["targets"]:
                status, _ = self.request(
                    "firestore", "/v1/" + name, method="GET", privileged=True
                )
                if status != 404:
                    raise ValueError("namespace is not empty")
                self.record(
                    {"kind": "document-attempt", "name": name, "preflightAbsent": True}
                )
                self.documents.add(name)
                self.preflight_absent.add(name)
            for seed in program["seed"]:
                status, body = self.doc(
                    seed["path"].removeprefix("/v1/"),
                    method="PATCH",
                    body={"fields": seed["fields"]},
                    query="?currentDocument.exists=false",
                )
                name = seed["path"].split("?", 1)[0].removeprefix("/v1/")
                version = _creation_version(name, seed["fields"], status, body)
                self.creation_proofs[name] = {
                    "name": name,
                    "updateTime": version,
                    "fieldsDigest": digest(seed["fields"]),
                    "responseDigest": digest(body),
                }
                self.record(
                    {
                        "kind": "document-created",
                        "name": name,
                        "updateTime": version,
                        "fieldsDigest": digest(seed["fields"]),
                        "responseDigest": digest(body),
                    }
                )
            for step in program["steps"]:
                status, result = self.request(
                    "firestore",
                    step["path"],
                    step.get("body"),
                    method=step["method"],
                    privileged=True,
                )
                self._record_document_writes(step, status, result)
                self._record_document_read(step, status, result)
                self.rows.append(
                    {
                        "id": "firestore:" + program["id"] + "#" + step["id"],
                        "status": status,
                        "body": result,
                        "mappedParent": program["parent"],
                        "principal": "administrator",
                        "operation": self.normal_operation(
                            step["path"], step["method"], step.get("body"), "firestore"
                        ),
                        "observation": self.normal_observation("firestore"),
                    }
                )

    def _record_document_writes(self, step, status, result):
        """Bind every successful commit write to its acknowledged document version."""
        if (
            status != 200
            or step["method"] != "POST"
            or not step["path"].split("?", 1)[0].endswith(":commit")
        ):
            return
        body = step.get("body")
        writes = body.get("writes") if isinstance(body, dict) else None
        if writes == [] and result == {}:
            return
        results = result.get("writeResults") if isinstance(result, dict) else None
        if not isinstance(writes, list) or not isinstance(results, list) or len(writes) != len(results):
            raise ValueError("document commit acknowledgement incomplete")

        entries = []
        for write, write_result in zip(writes, results, strict=True):
            if not isinstance(write, dict) or not isinstance(write_result, dict):
                raise ValueError(  # noqa: TRY004 -- malformed wire data is a protocol failure
                    "document commit acknowledgement malformed"
                )
            if isinstance(write.get("update"), dict):
                document = write["update"].get("name")
                kind = "update"
                fields = write["update"].get("fields")
                complete_fields = (
                    isinstance(fields, dict)
                    and "updateMask" not in write
                    and "updateTransforms" not in write
                )
            elif isinstance(write.get("transform"), dict):
                document = write["transform"].get("document")
                kind = "transform"
                fields = None
                complete_fields = False
            elif isinstance(write.get("delete"), str):
                document = write["delete"]
                kind = "delete"
                fields = None
                complete_fields = False
            else:
                continue
            if document not in self.documents:
                raise ValueError("document write target not journaled")
            if kind == "delete":
                version = None
            else:
                version = _document_version(write_result.get("updateTime"))
            entries.append((document, kind, version, fields if complete_fields else None))

        for document, kind, version, fields in entries:
            if kind == "delete":
                self.creation_proofs.pop(document, None)
                continue
            if document not in self.creation_proofs and document not in self.preflight_absent:
                raise ValueError("document write ownership is unconfirmed")
            self.creation_proofs[document] = {
                "name": document,
                "updateTime": version,
                "fieldsDigest": digest(fields) if fields is not None else None,
                "responseDigest": digest(result),
            }

    def _record_document_read(self, step, status, result):
        if status != 200 or step["method"] != "GET":
            return
        document = step["path"].split("?", 1)[0].removeprefix("/v1/")
        proof = self.creation_proofs.get(document)
        if (
            proof is not None
            and isinstance(result, dict)
            and result.get("name") == document
            and result.get("updateTime") == proof["updateTime"]
            and isinstance(result.get("fields"), dict)
        ):
            proof["fieldsDigest"] = digest(result["fields"])

    def names(self):
        from batch_pair import namespace

        return namespace(self.manifest, self.nonce, self.accounts)

    def normal_observation(self, service):
        from batch_pair import normalize

        if self.last_observation is None:
            raise ValueError("missing response")
        return {
            **self.last_observation,
            "body": normalize(
                self.last_observation["body"], self.names(), service=service
            ),
        }

    def normal_operation(self, path, method, body, service):
        from batch_pair import canonical_operation

        return canonical_operation(
            path, method, body, service, self.names(), self.token_roles
        )

    def emit_auth(self, row, body):
        if self.last_auth_operation is None:
            raise ValueError("missing Auth operation")
        self.rows.append(
            {
                **row,
                **self.last_auth_operation,
                "observation": self.normal_observation("auth"),
            }
        )

    def lookup(self, email):
        if email not in self.emails:
            raise ValueError("unowned email")
        status, body = self.request(
            "auth",
            f"identitytoolkit.googleapis.com/v1/projects/{PROJECT}/accounts:lookup",
            {"email": [email]},
            privileged=True,
        )
        if status != 200 or not isinstance(body.get("users", []), list):
            raise ValueError("ownership lookup failed")
        users = body.get("users", [])
        if len(users) > 1 or (users and users[0].get("email") != email):
            raise ValueError("ownership mismatch")
        return users

    def owner(self, uid):
        email = next((e for e, u in self.accounts.items() if u == uid), None)
        if email is None:
            raise ValueError("unknown UID")
        users = self.lookup(email)
        if len(users) != 1 or users[0].get("localId") != uid:
            raise ValueError("UID/email binding changed")
        return email

    def auth_call(self, path, body, admin=False, form=False):
        # This receives only the closed scenario's inputs, with dynamic credentials bound below.
        path = path.removeprefix("/").replace("demo-firestore-probe", PROJECT)
        route = path.split("?", 1)[0]
        action = route.rsplit(":", 1)[-1]
        if form:
            if (
                route != "securetoken.googleapis.com/v1/token"
                or body.get("refresh_token") not in self.refresh_tokens
                or set(body) != {"grant_type", "refresh_token"}
                or body["grant_type"] != "refresh_token"
            ):
                raise ValueError("unowned refresh")
        else:
            prefix = (
                f"identitytoolkit.googleapis.com/v1/projects/{PROJECT}/accounts:"
                if admin
                else "identitytoolkit.googleapis.com/v1/accounts:"
            )
            allowed = {
                "signUp": {"email", "password", "returnSecureToken"},
                "signInWithPassword": {"email", "password", "returnSecureToken"},
                "lookup": {"email", "localId", "idToken"},
                "update": {
                    "idToken",
                    "localId",
                    "emailVerified",
                    "displayName",
                    "password",
                    "returnSecureToken",
                },
                "delete": {"localId"},
            }
            if (
                not route.startswith(prefix)
                or action not in allowed
                or set(body) - allowed[action]
            ):
                raise ValueError("Auth operation not allowed")
            if body.get("idToken") is not None and body["idToken"] not in self.tokens:
                raise ValueError("unowned user token")
            if "email" in body:
                emails = (
                    body["email"]
                    if isinstance(body["email"], list)
                    else [body["email"]]
                )
                if not set(emails) <= self.emails:
                    raise ValueError("unowned email selector")
            if "localId" in body:
                uids = (
                    body["localId"]
                    if isinstance(body["localId"], list)
                    else [body["localId"]]
                )
                if not set(uids) <= set(self.accounts.values()):
                    raise ValueError("unowned UID selector")
                if admin and action != "lookup":
                    for uid in uids:
                        self.owner(uid)
            if action == "signUp":
                email = body["email"]
                if email in self.accounts or self.lookup(email):
                    raise ValueError("account already exists")
                self.record(
                    {"kind": "account-attempt", "email": email, "preflightAbsent": True}
                )
                self.accounts[email] = None
        if "?" in path:
            key = self.auth_query_key()
            path = route + "?" + urllib.parse.urlencode({"key": key})
        role = next(
            (
                r
                for r, email in self.names()["authEmails"].items()
                if body.get("email") == email
            ),
            None,
        )
        principal = (
            "administrator"
            if admin
            else self.token_roles.get(body.get("idToken"))
            if "idToken" in body
            else self.token_roles.get(body.get("refresh_token"))
            if form
            else "password:" + role
            if action == "signInWithPassword" and role
            else "anonymous"
        )
        operation = self.normal_operation(path, "POST", body, "auth")
        status, result = self.request("auth", path, body, privileged=admin, form=form)
        self.last_auth_operation = {"principal": principal, "operation": operation}
        if status == 200:
            if action == "signUp":
                uid = result.get("localId")
                if not isinstance(uid, str) or not uid:
                    raise ValueError("missing created UID")
                self.record(
                    {"kind": "account-created", "email": body["email"], "uid": uid}
                )
                self.accounts[body["email"]] = uid
            for key in ("idToken", "id_token"):
                if isinstance(result.get(key), str):
                    self.tokens.add(result[key])
                    owner_role = role or (
                        principal.split(":", 1)[1]
                        if isinstance(principal, str) and ":" in principal
                        else None
                    )
                    if owner_role is not None:
                        self.token_roles[result[key]] = "self:" + owner_role
            for key in ("refreshToken", "refresh_token"):
                if isinstance(result.get(key), str):
                    self.refresh_tokens.add(result[key])
                    owner_role = role or (
                        principal.split(":", 1)[1]
                        if isinstance(principal, str) and ":" in principal
                        else None
                    )
                    if owner_role is not None:
                        self.token_roles[result[key]] = "refresh:" + owner_role
        return status, result

    def cleanup(self):
        self.budget.recovery = True
        for name in sorted(self.documents):
            try:
                status, body = self.doc(name)
                if status == 200:
                    proof = self.creation_proofs.get(name)
                    if (
                        proof is None
                        or body.get("name") != name
                        or body.get("updateTime") != proof["updateTime"]
                        or not isinstance(body.get("fields"), dict)
                    ):
                        raise ValueError("document readback mismatch")
                    fields_digest = proof.get("fieldsDigest")
                    if fields_digest is None:
                        fields_digest = digest(body["fields"])
                        proof["fieldsDigest"] = fields_digest
                    if (
                        not isinstance(fields_digest, str)
                        or digest(body["fields"]) != fields_digest
                    ):
                        raise ValueError("document readback mismatch")
                    query = "?" + urllib.parse.urlencode(
                        {"currentDocument.updateTime": proof["updateTime"]}
                    )
                    status, _ = self.doc(name, method="DELETE", query=query)
                    if status != 200:
                        raise ValueError("conditional cleanup failed")
                elif status != 404:
                    raise ValueError("document absence unknown")
                status, _ = self.doc(name)
                if status != 404:
                    raise ValueError("document absence unconfirmed")
                self.record({"kind": "document-absent", "name": name})
            except Exception:
                self.unrecovered.append({"kind": "document", "name": name})
        for email, uid in self.accounts.items():
            try:
                users = self.lookup(email)
                if users:
                    if uid is None or users[0].get("localId") != uid:
                        raise ValueError(
                            "uncertain creation retained for owner recovery"
                        )
                    self.owner(uid)
                    status, _ = self.request(
                        "auth",
                        f"identitytoolkit.googleapis.com/v1/projects/{PROJECT}/accounts:delete",
                        {"localId": uid},
                        privileged=True,
                    )
                    if status != 200:
                        raise ValueError("account deletion failed")
                if self.lookup(email):
                    raise ValueError("account absence unconfirmed")
                self.record({"kind": "account-absent", "email": email})
            except Exception:
                self.unrecovered.append({"kind": "account", "email": email})

    def preflight(self):
        if self.local:
            return
        permission = self.permission
        if permission is None:
            raise ValueError("owner permission required")
        metadata = [
            (f"cloudresourcemanager.googleapis.com/v1/projects/{PROJECT}", None),
            (
                f"firestore.googleapis.com/v1/projects/{PROJECT}/databases/(default)",
                "database-projection",
            ),
            (
                f"identitytoolkit.googleapis.com/admin/v2/projects/{PROJECT}/config",
                permission["authConfigDigest"],
            ),
        ]
        for path, expected in metadata:
            status, body = self.request("metadata", path, method="GET", privileged=True)
            if path.startswith("firestore") and status == 200:
                evidence = database_evidence(body)
                evidence["phase"] = (
                    "recovery" if self.budget.recovery else "observation"
                )
                self.database_observations.append(evidence)
                expected = permission["databaseProjectionDigest"]
                actual_digest = evidence["projectionDigest"]
            else:
                actual_digest = digest(body)
            if status != 200 or (expected and actual_digest != expected):
                raise ValueError("approved metadata baseline differs")
            if expected is None and (
                str(body.get("projectNumber")) != NUMBER
                or body.get("projectId") != PROJECT
            ):
                raise ValueError("wrong oracle project")
            if path.startswith("firestore") and (
                body.get("name") != f"projects/{PROJECT}/databases/(default)"
                or body.get("type") != "FIRESTORE_NATIVE"
                or body.get("databaseEdition") != "STANDARD"
                or body.get("locationId") != permission["pricingLocation"]
            ):
                raise ValueError("wrong database edition/location")
        path = "apikeys.googleapis.com/v2/keys:lookupKey?" + urllib.parse.urlencode(
            {"keyString": self.api_key}
        )
        status, body = self.request("metadata", path, method="GET", privileged=True)
        if (
            status != 200
            or body.get("parent") != f"projects/{NUMBER}/locations/global"
            or not body.get("name", "").startswith(
                f"projects/{NUMBER}/locations/global/keys/"
            )
        ):
            raise ValueError("API key does not belong to approved project")
        self.ready = True

    def execute(self):
        from broad_cases import auth_scenario

        failure = None
        try:
            self.preflight()
            self.firestore()
            auth_scenario(self.auth_call, self.nonce, on_row=self.emit_auth)
        except Exception as error:
            failure = type(error).__name__
        finally:
            self.cleanup()
        unchanged = None
        if not self.local:
            try:
                self.preflight()
                unchanged = True
            except Exception:
                unchanged = False
                failure = failure or "MetadataDriftOrUnconfirmed"
        from batch_pair import binding, row_table

        report = {
            "schemaVersion": 2,
            "comparisonBinding": binding(self.manifest),
            "namespace": self.names(),
            "configurationUnchanged": unchanged,
            "databaseObservations": self.database_observations,
            "manifestDigest": digest(self.manifest),
            "observerDigest": observer_digest(),
            "productionExecuted": not bool(self.local),
            "rows": self.rows,
            "failure": failure,
            "unrecovered": self.unrecovered,
            "counts": self.budget.counts,
            "privilegedRequests": self.auth_evidence,
            "completed": failure is None
            and not self.unrecovered
            and [row["id"] for row in self.rows]
            == [row["id"] for row in row_table(self.manifest)],
        }
        (self.output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
        return report


def execution_inputs(manifest):
    from batch_contract import DATABASE_PROJECTION, LIMITS
    from batch_pair import binding

    frozen = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT).strip():
        raise ValueError("freeze checkout before preparing execution inputs")
    return {
        "kind": "prepared-execution-inputs-not-permission",
        "productionExecuted": False,
        "frozenCommit": frozen,
        "observerSha256": observer_digest(),
        "manifestSha256": digest(manifest),
        "manifest": manifest,
        "comparisonContract": binding(manifest),
        "comparisonContractDigest": digest(binding(manifest)),
        "databaseProjectionContract": DATABASE_PROJECTION,
        "databaseProjectionContractDigest": digest(DATABASE_PROJECTION),
        "project": PROJECT,
        "projectNumber": NUMBER,
        "quotaProject": PROJECT,
        "limits": LIMITS,
        "recovery": {
            "reservedSeconds": 300,
            "reservedRequests": 300,
            "totalSeconds": 1200,
            "refreshAttempts": 2,
            "credentialFailure": "latched; no stale fallback",
            "unrecovered": "retain private ownership journal; report incomplete and stop",
        },
        "ownerInputs": {
            key: None
            for key in [
                "ownerIdentity",
                "permissionReference",
                "issuedAt",
                "expiresAt",
                "nonce",
                "databaseProjection",
                "databaseProjectionDigest",
                "authConfigDigest",
                "pricingLocation",
                "pricingCheckedAt",
                "tariffsConfirmedBelowPlanningCeilings",
            ]
        },
        "missingInputs": [
            "current database identity/settings projection and Auth config baseline",
            "target location and current applicable tariffs checked against manifest planning ceilings",
            "owner identity/reference, explicit permission, validity window and unused 32-hex nonce",
        ],
        "permission": None,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--write-candidate", action="store_true")
    parser.add_argument("--prepare-inputs", type=Path)
    parser.add_argument("--approval", type=Path)
    parser.add_argument("--nonce")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.write_candidate:
        args.manifest.write_text(json.dumps(candidate(), indent=2) + "\n")
        return
    manifest = json.loads(args.manifest.read_bytes())
    if args.prepare_inputs is not None:
        if args.approval is not None or digest(manifest) != digest(candidate()):
            raise ValueError(
                "offline preparation requires current candidate without permission"
            )
        args.prepare_inputs.write_text(
            json.dumps(execution_inputs(manifest), indent=2) + "\n"
        )
        return
    if args.approval is None:
        if digest(manifest) != digest(candidate()):
            raise ValueError("candidate drift")
        print(
            json.dumps(
                {
                    "status": "offline-candidate-valid",
                    "observerDigest": observer_digest(),
                    "manifestDigest": digest(manifest),
                }
            )
        )
        return
    permission = json.loads(args.approval.read_bytes())
    approve(manifest, permission, args.nonce, observer_digest(), time.time())
    if args.output is None or not os.environ.get("PRODUCTION_ORACLE_API_KEY"):
        raise ValueError("private output and API key required")
    adapter = Adapter(manifest, args.nonce, args.output, permission=permission)
    report = adapter.execute()
    print(
        json.dumps(
            {
                "completed": report["completed"],
                "rows": len(report["rows"]),
                "unrecovered": len(report["unrecovered"]),
            }
        )
    )

    return recording_exit_code(report)


def interrupted(_signum, _frame):
    raise InterruptedError("stop requested; unwind owned cleanup")


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    sys.exit(main())
