"""Execute the finite campaign through Gate and Adapter on loopback only."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from urllib.parse import parse_qs

import batch_adapter
from campaign_auth_list import SOURCE_COMMIT, campaign_manifest
from campaign_gate import CampaignGate, create
from batch_wire import _read_bounded_response
from shared_cases import save


class ShadowHandler(BaseHTTPRequestHandler):
    accounts: ClassVar[dict] = {}
    documents: ClassVar[dict] = {}
    page_token = "continuation-secret"
    tokens: ClassVar[dict] = {}
    token_counter: ClassVar[int] = 0

    def reply(self, status, value):
        payload = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def body(self):
        length = int(self.headers.get("content-length", "0"))
        value = self.rfile.read(length) or b"{}"
        if self.headers.get("content-type", "").startswith(
            "application/x-www-form-urlencoded"
        ):
            return {key: values[-1] for key, values in parse_qs(value.decode()).items()}
        return json.loads(value)

    def do_PATCH(self):
        body = self.body()
        name = self.path.split("?", 1)[0].removeprefix("/v1/")
        segments = name.split("/documents/", 1)[-1].split("/")
        if (
            "currentDocument.exists=false" not in self.path
            or name in self.documents
            or len(segments) % 2 != 0
            or not isinstance(body, dict)
            or not isinstance(body.get("fields"), dict)
        ):
            return self.reply(400, {"error": {"status": "FAILED_PRECONDITION"}})
        value = {
            "name": name,
            "fields": body["fields"],
            "updateTime": "2026-09-14T00:00:00Z",
        }
        self.documents[name] = value
        self.reply(200, value)

    def do_GET(self):
        name = self.path.removeprefix("/v1/")
        self.reply(200, self.documents[name]) if name in self.documents else self.reply(
            404, {"error": {"code": 404, "status": "NOT_FOUND"}}
        )

    def do_DELETE(self):
        name = self.path.split("?", 1)[0].removeprefix("/v1/")
        if name not in self.documents:
            return self.reply(404, {"error": {"code": 404, "status": "NOT_FOUND"}})
        del self.documents[name]
        self.reply(200, {})

    def do_POST(self):
        body = self.body()
        if self.path.endswith(":listCollectionIds"):
            parent = self.path.split("?", 1)[0].removeprefix("/v1/")[: -len(":listCollectionIds")]
            documents_root = "projects/demo-firestore-probe/databases/(default)/documents"
            parent_suffix = parent.removeprefix(documents_root)
            parent_segments = parent_suffix.strip("/").split("/") if parent_suffix else []
            if (
                not isinstance(body, dict)
                or "parent" in body
                or not parent.startswith(documents_root)
                or parent_segments
                and (
                    parent_suffix != "/" + "/".join(parent_segments)
                    or any(not segment for segment in parent_segments)
                    or len(parent_segments) % 2 != 0
                )
            ):
                return self.reply(400, {"error": {"status": "INVALID_ARGUMENT"}})
            if body.get("pageToken") not in (None, self.page_token):
                return self.reply(400, {"error": {"status": "INVALID_ARGUMENT"}})
            if parent.endswith("/documents"):
                ids = {
                    path.split("/documents/", 1)[1].split("/", 1)[0]
                    for path in self.documents
                    if path.startswith(parent + "/")
                }
            else:
                prefix = parent + "/"
                ids = {
                    path[len(prefix) :].split("/", 1)[0]
                    for path in self.documents
                    if path.startswith(prefix)
                }
            ordered = sorted(ids)
            if body.get("pageToken"):
                ordered = ordered[1:]
            page_size = body.get("pageSize")
            if page_size == 1:
                ordered = ordered[:1]
            value = {"collectionIds": ordered}
            if body.get("pageToken") is None and page_size == 1 and len(ids) > 1:
                value["nextPageToken"] = self.page_token
            return self.reply(200, value)
        if self.path.endswith("/token"):
            uid = ShadowHandler.tokens.get(body.get("refresh_token"), "owned")
            ShadowHandler.token_counter += 1
            id_token = f"id-secret-{ShadowHandler.token_counter}"
            ShadowHandler.tokens[id_token] = uid
            return self.reply(
                200,
                {
                    "id_token": id_token,
                    "refresh_token": f"refresh-secret-{ShadowHandler.token_counter}",
                    "expires_in": "3600",
                    "token_type": "Bearer",
                    "user_id": uid,
                },
            )
        if ":delete" in self.path:
            ShadowHandler.accounts.pop(body.get("localId"), None)
            return self.reply(200, {})
        if ":lookup" in self.path:
            uid = body.get("localId") or ShadowHandler.tokens.get(body.get("idToken"))
            return (
                self.reply(200, {"users": [{"localId": uid}]})
                if uid in ShadowHandler.accounts
                else self.reply(404, {"error": {"status": "USER_NOT_FOUND"}})
            )
        if self.path.endswith("accounts:signUp"):
            email, password = body.get("email"), body.get("password")
            if (
                not isinstance(email, str)
                or not isinstance(password, str)
                or len(password) < 6
                or any(record["email"] == email for record in ShadowHandler.accounts.values())
            ):
                return self.reply(400, {"error": {"status": "INVALID_ARGUMENT"}})
            uid = f"uid-{len(ShadowHandler.accounts) + 1}"
            ShadowHandler.accounts[uid] = {"email": email, "password": password}
        elif self.path.endswith("accounts:signInWithPassword"):
            email, password = body.get("email"), body.get("password")
            match = next(
                (
                    (uid, record)
                    for uid, record in ShadowHandler.accounts.items()
                    if record["email"] == email
                ),
                None,
            )
            if match is None or match[1]["password"] != password:
                return self.reply(400, {"error": {"status": "INVALID_PASSWORD"}})
            uid = match[0]
        else:
            return self.reply(404, {"error": {"code": 404, "status": "NOT_FOUND"}})
        ShadowHandler.tokens[f"id-{uid}"] = uid
        ShadowHandler.tokens[f"refresh-{uid}"] = uid
        self.reply(
            200,
            {"localId": uid, "idToken": f"id-{uid}", "refreshToken": f"refresh-{uid}"},
        )

    def log_message(self, *_args):
        return


def wire(url, method, body, headers, *, local=False, timeout=12, receipt=False):
    parsed = __import__("urllib.parse").parse.urlsplit(url)
    if (
        not local
        or parsed.hostname != "127.0.0.1"
        or parsed.scheme != "http"
        or parsed.port is None
    ):
        raise ValueError("loopback transport required")
    connection = http.client.HTTPConnection(
        parsed.hostname, parsed.port, timeout=min(timeout, 2)
    )
    encoded = (
        None if body is None else body if isinstance(body, str) else json.dumps(body)
    )
    try:
        connection.request(
            method,
            parsed.path + (("?" + parsed.query) if parsed.query else ""),
            body=encoded,
            headers=headers,
        )
        response = connection.getresponse()
        payload, failure = _read_bounded_response(response, method)
        if failure is not None or 300 <= response.status < 400:
            raise ValueError("incomplete, oversized or redirected local response")
        try:
            value = json.loads(payload)
        except (ValueError, UnicodeDecodeError):
            value = {"nonJson": True}
        return response.status, value, response.headers.get("content-type", "")
    finally:
        connection.close()


def replace(value, bindings):
    if isinstance(value, str) and value.startswith("$binding:"):
        return bindings.get(value.removeprefix("$binding:"), value)
    if isinstance(value, dict):
        return {key: replace(item, bindings) for key, item in value.items()}
    if isinstance(value, list):
        return [replace(item, bindings) for item in value]
    return value


class CampaignAdapter(batch_adapter.Adapter):
    def request(
        self,
        service,
        path,
        body=None,
        *,
        method="POST",
        privileged=False,
        form=False,
        **metadata,
    ):
        self.campaign_operation = metadata
        # A client SDK always sends its API key, and production (and strict fireemu) refuses a
        # caller without one; privileged Admin calls carry the owner's credential instead.
        if service == "auth" and not privileged and "?" not in path:
            path += "?key=" + urllib.parse.quote(self.auth_query_key(), safe="")
        try:
            return super().request(
                service, path, body, method=method, privileged=privileged, form=form
            )
        finally:
            self.campaign_operation = {}


def bind(gate, bindings, operation, body):
    kind, key = operation["operationType"], operation["resource"]
    if kind == "auth-sign-up":
        bindings[key + "Uid"] = body["localId"]
        bindings[key + "Principal"] = "owned-account:" + body["localId"]
        gate.bind(key + "Uid", body["localId"])
        gate.bind(key + "Principal", bindings[key + "Principal"])
    if kind == "auth-sign-in":
        bindings[key + "Refresh"] = body["refreshToken"]
        bindings[key + "IdToken"] = body["idToken"]
        gate.bind(key + "Refresh", body["refreshToken"])
        gate.bind(key + "IdToken", body["idToken"])
    if kind == "auth-refresh":
        bindings[key + "IdToken"] = body["id_token"]
        gate.bind(key + "IdToken", body["id_token"])
    if kind == "firestore-list-collection-ids" and "nextPageToken" in body:
        bindings["pagedToken"] = body["nextPageToken"]
        gate.bind("pagedToken", body["nextPageToken"])


def validate_auth_lookup(body, expected_uid: str) -> None:
    """Require a successful lookup for the account bound by this run."""
    if (
        not isinstance(body, dict)
        or not isinstance(body.get("users"), list)
        or len(body["users"]) != 1
        or not isinstance(body["users"][0], dict)
        or body["users"][0].get("localId") != expected_uid
    ):
        raise ValueError("owned account lookup did not return the bound user")


def validate_deleted_lookup(status: int, body) -> None:
    """Require an explicit, typed acknowledgement that the account is absent."""
    if type(status) is not int or not isinstance(body, dict):
        raise ValueError("owned account absence unconfirmed")
    kind = "identitytoolkit#GetAccountInfoResponse"
    empty_users = (
        set(body) <= {"users", "kind"}
        and type(body.get("users")) is list
        and body["users"] == []
        and ("kind" not in body or body["kind"] == kind)
    )
    kind_only = body == {"kind": kind}
    error = body.get("error")
    not_found = (
        status == 404
        and set(body) == {"error"}
        and isinstance(error, dict)
        and error.get("status") == "USER_NOT_FOUND"
        and ("code" not in error or type(error["code"]) is int and error["code"] == 404)
    )
    if not (status == 200 and (kind_only or empty_users)) and not not_found:
        raise ValueError("owned account absence unconfirmed")


def validate_list_observations(rows, nonce: str) -> None:
    """Validate the list case outcomes and the intentionally missing parent."""
    root = "projects/demo-firestore-probe/databases/(default)/documents"
    missing_parent = root + "/missing-parent-" + nonce + "/parent"
    paged_parent = root + "/paged-parent-" + nonce + "/rootdoc"
    expected_rows = [
        (root, [
            "child-" + nonce,
            "missing-parent-" + nonce,
            "paged-parent-" + nonce,
        ]),
        (missing_parent, ["children"]),
        (paged_parent, ["alpha"]),
        (paged_parent, ["beta"]),
    ]
    parent_reads = [
        row
        for row in rows
        if row.get("operationType") == "firestore-document-read"
        and row.get("resource") == missing_parent
    ]
    if len(parent_reads) != 1:
        raise ValueError("missing parent readback is missing or duplicated")
    parent_read = parent_reads[0]
    parent_body = parent_read.get("body")
    if (
        parent_read.get("status") != 404
        or not isinstance(parent_body, dict)
        or parent_body.get("error", {}).get("status") != "NOT_FOUND"
    ):
        raise ValueError("missing parent readback did not prove absence")

    list_rows = [
        row
        for row in rows
        if row.get("operationType") == "firestore-list-collection-ids"
    ]
    if len(list_rows) != len(expected_rows):
        raise ValueError("listCollectionIds observation count mismatch")
    for index, (row, (resource, expected_ids)) in enumerate(
        zip(list_rows, expected_rows, strict=True)
    ):
        if row.get("resource") != resource or row.get("status") != 200:
            raise ValueError(f"listCollectionIds row {index} has unexpected parent/status")
        body = row.get("body")
        if not isinstance(body, dict) or not isinstance(body.get("collectionIds"), list):
            raise ValueError(f"listCollectionIds row {index} has no collectionIds")
        ids = body["collectionIds"]
        if any(not isinstance(value, str) for value in ids) or len(ids) != len(set(ids)):
            raise ValueError(f"listCollectionIds row {index} has duplicate or invalid IDs")
        if ids != expected_ids:
            raise ValueError(f"listCollectionIds row {index} is missing or has unexpected IDs")
        if index == 2:
            token = body.get("nextPageToken")
            if not isinstance(token, str) or not token:
                raise ValueError("first page continuation token is missing")
        elif "nextPageToken" in body:
            raise ValueError("unexpected continuation token on complete page")

    pages = list_rows[2:]
    if [row["resource"] for row in pages] != [paged_parent, paged_parent]:
        raise ValueError("paged ListCollectionIds requests changed parent")
    page_ids = [value for row in pages for value in row["body"]["collectionIds"]]
    if page_ids != ["alpha", "beta"] or len(page_ids) != len(set(page_ids)):
        raise ValueError("paged ListCollectionIds results contain duplicates or omissions")


def scrub(path):
    if path.exists():
        value = path.read_text()
        for token in (
            "id-secret-1",
            "id-secret-2",
            "refresh-secret-1",
            "refresh-secret-2",
        ):
            value = value.replace(token, "[REDACTED]")
        path.write_text(value)


def run_fixture(output: Path) -> dict:
    ShadowHandler.accounts = {}
    ShadowHandler.documents = {}
    ShadowHandler.tokens = {}
    ShadowHandler.token_counter = 0
    original_wire = batch_adapter.wire
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    server = ThreadingHTTPServer(("127.0.0.1", 0), ShadowHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        origin = f"http://127.0.0.1:{server.server_port}"
        plan = campaign_manifest("c" * 32)
        plan["localOrigins"] = {"auth": origin, "firestore": origin}
        plan["observerSha256"] = batch_adapter.observer_digest()
        create(output / "gate", plan)
        gate = CampaignGate(output / "gate", "auth-list")
        gate.coordinator_call(0, lambda: (200, {}))
        gate.coordinator_call(1, lambda: (200, {}))
        gate.claim()
        batch_adapter.wire = wire
        adapter = CampaignAdapter(
            batch_adapter.candidate(),
            plan["nonce"],
            output / "worker",
            local_origins=plan["localOrigins"],
        )
        adapter.shared_gate = gate
        adapter.reserve = lambda *_args, **_kwargs: None
        bindings, rows = {}, []
        for declared in plan["jobs"]["auth-list"]["observation"]:
            operation = replace(declared, bindings)
            status, body = gate.adapter_request(
                adapter,
                operation,
                lambda op=operation: adapter.request(
                    op["service"],
                    op["path"],
                    op.get("body"),
                    method=op["method"],
                    privileged=op["privileged"],
                    form=op["form"],
                ),
            )
            scrub(output / "worker" / "responses.jsonl")
            rows.append(
                {
                    "operationType": operation["operationType"],
                    "principal": operation["principal"],
                    "status": status,
                    "bodyKeys": sorted(body) if isinstance(body, dict) else [],
                }
            )
            bind(gate, bindings, declared, body)
        adapter.budget.recovery = True
        for declared in plan["jobs"]["auth-list"]["recovery"]:
            operation = replace(declared, bindings)
            source = operation.pop("versionFrom", None)
            if source is not None:
                operation["path"] += (
                    "?currentDocument.updateTime=2026-09-14T00%3A00%3A00Z"
                )
            gate.adapter_request(
                adapter,
                operation,
                lambda op=operation: adapter.request(
                    op["service"],
                    op["path"],
                    op.get("body"),
                    method=op["method"],
                    privileged=op["privileged"],
                    form=op["form"],
                ),
            )
            scrub(output / "worker" / "responses.jsonl")
        gate.finish()
        state = gate.snapshot()
        result = {
            "completed": True,
            "productionExecuted": False,
            "rows": rows,
            "gate": {
                "total": state["total"],
                "recovery": state["recovery"],
                "bindings": sorted(gate.bindings),
            },
        }
    except (OSError, ValueError, KeyError, http.client.HTTPException) as error:
        result = {
            "completed": False,
            "productionExecuted": False,
            "failure": type(error).__name__ + ":" + str(error),
        }
    finally:
        batch_adapter.wire = original_wire
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        result["processCleanup"] = not thread.is_alive()
    result.update(
        sourceCommit=SOURCE_COMMIT,
        artifactSha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        sourceSha256=hashlib.sha256(
            Path(__file__).with_name("campaign_auth_list.py").read_bytes()
        ).hexdigest(),
        observerSha256=hashlib.sha256(
            Path(__file__).resolve().parents[1].joinpath("shared_gate.py").read_bytes()
        ).hexdigest(),
        manifestSha256=hashlib.sha256(
            json.dumps(plan, sort_keys=True).encode()
        ).hexdigest(),
    )
    save(output / "result.json", result)
    return result


def _owned_instance(output: Path, nonce: str) -> dict:
    """Verify the child is the fireemu artifact owned by this supervisor."""
    from owned_runner import control_get, local_addresses

    auth = "http://" + os.environ["FIREBASE_AUTH_EMULATOR_HOST"]
    firestore, control = local_addresses(
        os.environ["FIRESTORE_EMULATOR_HOST"], os.environ["FIREEMU_CONTROL_URL"]
    )
    token = os.environ["FIREEMU_CONTROL_TOKEN"]
    status, resources = control_get(control, "/v1/sessions/default/resources", token)
    wrong, _ = control_get(control, "/v1/sessions/default/resources", token + "-wrong")
    if (
        status != 200
        or wrong != 403
        or resources.get("project") != "demo-firestore-probe"
        or os.environ.get("GOOGLE_CLOUD_PROJECT") != "demo-firestore-probe"
    ):
        raise ValueError("owned campaign instance identity mismatch")
    parent_args = json.loads(
        (output / "runner-parent.json").read_bytes()
    ) if (output / "runner-parent.json").exists() else {}
    instance = {
        "pid": os.getpid(),
        "parentPid": os.getppid(),
        "argv": sys.argv,
        "nonce": nonce,
        "project": "demo-firestore-probe",
        "authOrigin": auth,
        "firestoreOrigin": firestore,
        "controlOrigin": control,
        "wrongTokenStatus": wrong,
        "parentArgs": parent_args,
    }
    save(output / "instance.json", instance)
    return instance


def _real_child(output: Path, nonce: str) -> None:
    """Run the fixed fireemu artifact through the campaign adapter on loopback."""
    # Import broad to install the repository's compat-inventory helper path.
    import broad  # noqa: F401
    from owned_runner import control_get

    _owned_instance(output, nonce)
    origins = {
        "auth": "http://" + os.environ["FIREBASE_AUTH_EMULATOR_HOST"],
        "firestore": "http://" + os.environ["FIRESTORE_EMULATOR_HOST"],
    }
    plan = campaign_manifest(nonce)
    plan["localOrigins"] = origins
    plan["observerSha256"] = batch_adapter.observer_digest()
    create(output / "gate", plan)
    gate = CampaignGate(output / "gate", "auth-list")
    control = json.loads((output / "instance.json").read_bytes())["controlOrigin"]
    token = os.environ["FIREEMU_CONTROL_TOKEN"]
    gate.coordinator_call(0, lambda: control_get(control, "/v1/sessions/default/resources", token))
    gate.coordinator_call(1, lambda: control_get(control, "/v1/sessions/default/resources", token))
    gate.claim()
    adapter = CampaignAdapter(
        batch_adapter.candidate(), nonce, output / "worker", local_origins=origins
    )
    adapter.shared_gate = gate
    bindings: dict[str, str] = {}
    rows: list[dict] = []
    for declared in plan["jobs"]["auth-list"]["observation"]:
        operation = replace(declared, bindings)

        def send(op=operation):
            return adapter.request(
                op["service"],
                op["path"],
                op.get("body"),
                method=op["method"],
                privileged=op["privileged"],
                form=op["form"],
                operationType=op["operationType"],
                principal=op["principal"],
                resource=op["resource"],
                provenance=op["provenance"],
            )

        status, body = gate.adapter_request(adapter, operation, send)
        rows.append(
            {
                "operationType": operation["operationType"],
                "resource": operation["resource"],
                "principal": operation["principal"],
                "status": status,
                "body": body,
            }
        )
        bind(gate, bindings, declared, body)
        if declared["operationType"] == "auth-sign-in":
            if body.get("localId") != bindings[declared["resource"] + "Uid"]:
                raise ValueError("sign-in returned a different UID")
        if declared["operationType"] == "auth-refresh":
            if body.get("user_id") != bindings[declared["resource"] + "Uid"]:
                raise ValueError("refresh returned a different UID")
        if declared["operationType"] == "auth-lookup":
            if status != 200:
                raise ValueError("owned account lookup failed")
            validate_auth_lookup(body, bindings[declared["resource"] + "Uid"])

    validate_list_observations(rows, nonce)

    adapter.budget.recovery = True
    versions: dict[str, str] = {}
    for declared in plan["jobs"]["auth-list"]["recovery"]:
        operation = replace(declared, bindings)
        source = operation.pop("versionFrom", None)
        if source is not None:
            version = versions.get(operation["resource"])
            if version is None:
                raise ValueError("missing same-run updateTime for cleanup")
            operation["path"] += "?currentDocument.updateTime=" + __import__(
                "urllib.parse"
            ).parse.quote(version, safe="")

        def send_recovery(op=operation):
            return adapter.request(
                op["service"],
                op["path"],
                op.get("body"),
                method=op["method"],
                privileged=op["privileged"],
                form=op["form"],
                operationType=op["operationType"],
                principal=op["principal"],
                resource=op["resource"],
                provenance=op["provenance"],
            )

        status, body = gate.adapter_request(adapter, operation, send_recovery)
        if operation["method"] == "GET" and status == 200 and isinstance(body, dict):
            versions[operation["resource"]] = body.get("updateTime", "")
        if operation["operationType"] == "auth-delete" and status != 200:
            raise ValueError("owned account deletion failed")
        if operation["operationType"] == "auth-lookup":
            validate_deleted_lookup(status, body)

    gate.finish()
    state = gate.snapshot()
    if set(state["jobs"]["auth-list"]["absent"]) != set(
        state["jobs"]["auth-list"]["resources"]
    ):
        raise ValueError("owned resources remain after recovery")
    report = {
        "schemaVersion": 1,
        "target": "owned-fireemu-artifact",
        "productionExecuted": False,
        "recordingComplete": True,
        "stateValidation": True,
        "cleanupComplete": True,
        "rows": rows,
        "gate": {
            "total": state["total"],
            "observation": state["observation"],
            "recovery": state["recovery"],
            "bindings": sorted(bindings),
        },
        "completed": True,
        "failure": None,
    }
    # broad.supervise consumes this compact shape and retains it as a partial result.
    save(
        output / "cases.json",
        {
            "schemaVersion": 1,
            "target": report["target"],
            "project": "demo-firestore-probe",
            "edition": "Standard Native",
            "profile": "strict",
            "productionExecuted": False,
            "formalCompatibilityClaim": False,
            "recordingComplete": True,
            "stateValidation": report["stateValidation"],
            "cases": [
                {
                    "id": f"auth-list:{index}",
                    "status": "observed",
                    "family": row["operationType"],
                    "basis": "local-fireemu-artifact",
                }
                for index, row in enumerate(rows)
            ],
            "localObservations": rows,
            "requestStats": report["gate"],
        },
    )
    save(output / "worker/result.json", report)


def run(output: Path) -> dict:
    """Run the campaign against a freshly built, owned fireemu artifact."""
    import broad

    report = broad.run(
        output,
        child_script=Path(__file__).resolve(),
        project="demo-firestore-probe",
        configuration={"daemon": {"authProjectNumbers": {}}},
        execution_timeout=600,
        recovery_grace=1,
    )
    worker = {}
    worker_path = output / "worker/result.json"
    receipt_issue = None
    if worker_path.is_symlink():
        receipt_issue = "worker-receipt-not-regular"
    elif not worker_path.exists():
        receipt_issue = "worker-receipt-missing"
    else:
        try:
            worker = json.loads(worker_path.read_bytes())
        except (OSError, ValueError, UnicodeDecodeError):
            receipt_issue = "worker-receipt-unreadable"
        if not isinstance(worker, dict):
            worker = {}
            receipt_issue = "worker-receipt-not-object"
    owned = report.get("ownedProcess")
    process_cleanup = isinstance(owned, dict) and owned.get("listenersClosed") is True
    local_worker = (
        type(worker.get("schemaVersion")) is int
        and worker["schemaVersion"] == 1
        and worker.get("target") == "owned-fireemu-artifact"
        and worker.get("productionExecuted") is False
    )
    resource_cleanup = local_worker and worker.get("cleanupComplete") is True
    issues = [] if receipt_issue is None else [receipt_issue]
    if report.get("status") != "completed":
        issues.append("runtime-incomplete")
    if report.get("recordingComplete") is not True:
        issues.append("runtime-recording-incomplete")
    if report.get("stateValidation") is not True:
        issues.append("runtime-state-unvalidated")
    if report.get("failure") is not None:
        issues.append("runtime-failure")
    if not process_cleanup:
        issues.append("process-cleanup-incomplete")
    if type(worker.get("schemaVersion")) is not int or worker.get("schemaVersion") != 1:
        issues.append("worker-schema-mismatch")
    if worker.get("target") != "owned-fireemu-artifact":
        issues.append("worker-target-mismatch")
    if worker.get("productionExecuted") is not False:
        issues.append("worker-not-local-only")
    for field in ("completed", "recordingComplete", "stateValidation", "cleanupComplete"):
        if worker.get(field) is not True:
            issues.append("worker-" + field + "-incomplete")
    if worker.get("failure") is not None:
        issues.append("worker-failure")
    safe_runtime = dict(report)
    # The private worker receipt retains full token-bearing responses. The checked-in
    # campaign result is a public summary and must not copy those bodies.
    safe_runtime.pop("localObservations", None)
    result = {
        # Do not hand off a campaign whose transport completed but whose
        # operation/state assertions were absent or failed. A semantic
        # mismatch is represented by a complete, state-validated report and
        # must still reach comparison.
        "completed": not issues,
        "completionIssues": issues,
        "productionExecuted": False,
        "target": "owned-fireemu-artifact",
        "runtime": safe_runtime,
        "recordingComplete": (
            report.get("recordingComplete") is True
            and local_worker
            and worker.get("recordingComplete") is True
        ),
        "cleanupComplete": resource_cleanup and process_cleanup,
        "resourceCleanupComplete": resource_cleanup,
        "processCleanupComplete": process_cleanup,
        "stateValidation": (
            report.get("stateValidation") is True
            and local_worker
            and worker.get("stateValidation") is True
        ),
        "rows": [
            {
                "operationType": row.get("operationType"),
                "resource": row.get("resource"),
                "principal": row.get("principal"),
                "status": row.get("status"),
                "bodyKeys": sorted(row.get("body", {}))
                if isinstance(row.get("body"), dict)
                else [],
            }
            for row in report.get("localObservations", [])
        ],
        "gate": worker.get("gate", {}),
        # A normal child completion is lifecycle metadata, not a failed
        # observation. Keep the stop reason separate so callers can distinguish
        # an incomplete run from a completed one without losing the reason.
        "failure": report.get("failure"),
        "stopReason": report.get("stopReason"),
        "artifactSha256": report.get("artifactSha256"),
        "executionCommit": report.get("executionCommit"),
    }
    save(output / "result.json", result)
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    parser.add_argument("--child", type=Path)
    parser.add_argument("--nonce")
    parser.add_argument("--legacy-fixture", action="store_true")
    args = parser.parse_args(argv)
    if args.child is not None:
        if not args.nonce:
            parser.error("--nonce is required with --child")
        _real_child(args.child.resolve(), args.nonce)
        return 0
    if args.output is not None:
        result = (run_fixture if args.legacy_fixture else run)(args.output.resolve())
        print(json.dumps(result))
        return 0 if result.get("completed") is True else 2
    parser.error("--output is required")


if __name__ == "__main__":
    raise SystemExit(main())
