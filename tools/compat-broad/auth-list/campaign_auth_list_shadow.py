"""Execute the finite campaign through Gate and Adapter on loopback only."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from urllib.parse import parse_qs

import batch_adapter
from campaign_auth_list import SOURCE_COMMIT, campaign_manifest
from campaign_gate import CampaignGate, create
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
        if "currentDocument.exists=false" not in self.path or name in self.documents:
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
            404, {"error": {"status": "NOT_FOUND"}}
        )

    def do_DELETE(self):
        name = self.path.split("?", 1)[0].removeprefix("/v1/")
        if name not in self.documents:
            return self.reply(404, {"error": {"status": "NOT_FOUND"}})
        del self.documents[name]
        self.reply(200, {})

    def do_POST(self):
        body = self.body()
        if self.path.endswith(":listCollectionIds"):
            value = {"collectionIds": ["beta"] if body.get("pageToken") else ["alpha"]}
            if not body.get("pageToken"):
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
        uid = f"uid-{len(ShadowHandler.accounts) + 1}"
        ShadowHandler.accounts[uid] = body.get("email")
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
    connection.request(
        method,
        parsed.path + (("?" + parsed.query) if parsed.query else ""),
        body=encoded,
        headers=headers,
    )
    response = connection.getresponse()
    payload = response.read(65537)
    connection.close()
    if len(payload) > 65536:
        raise ValueError("bounded transport response exceeded")
    try:
        value = json.loads(payload)
    except (ValueError, UnicodeDecodeError):
        value = {"nonJson": True}
    return response.status, value, response.headers.get("content-type", "")


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


def run(output: Path) -> dict:
    ShadowHandler.accounts = {}
    ShadowHandler.documents = {}
    ShadowHandler.tokens = {}
    ShadowHandler.token_counter = 0
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.output.resolve())))
