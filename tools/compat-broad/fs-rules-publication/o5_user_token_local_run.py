"""Run the user-token Rules matrix against an owned local `fireemu` instance.

This is the local shadow. It starts one `fireemu` built from this checkout,
creates the campaign's throwaway accounts and fixtures, publishes Ruleset A,
drives the compiled matrix with real end-user ID tokens, publishes Ruleset B
for the transition rows, then recovers every document and account.

It never contacts production. The instance is addressed only through the
loopback origins the child process inherits, and the environment handed to the
instance is an allowlist that excludes every production credential variable.

Local evidence only. The local Auth emulator mints unsigned tokens, so a local
allow proves a Rules decision and never production token verification.

Parent:  python o5_user_token_local_run.py --run <output-directory>
Child:   invoked by the parent through `fireemu exec -- ...`; not run by hand.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any

from o5_user_token_case import (
    PRINCIPAL_EMPTY,
    PRINCIPAL_EXPIRED,
    PRINCIPAL_MALFORMED,
    PRINCIPAL_UNAUTHENTICATED,
    compile_case,
)
from o5_user_token_collector import ROLE_LOCAL_SHADOW, collect
from o5_user_token_shadow import (
    ENVIRONMENT_ALLOWLIST,
    launch_specification,
    local_deviations,
    redact_principals,
    unredacted_identifiers,
)

ROOT = Path(__file__).resolve().parents[3]
PROJECT = "fireemu-35fe6"
API_KEY = "fake-api-key"
OWNER_TOKEN = "owner"
REQUEST_TIMEOUT = 12.0
STATUS_BY_HTTP = {
    200: "OK",
    401: "UNAUTHENTICATED",
    403: "PERMISSION_DENIED",
    404: "NOT_FOUND",
}


class Refused(RuntimeError):
    pass


# --------------------------------------------------------------------------
# Transport helpers. Credentials live here and never leave this module.
# --------------------------------------------------------------------------


def _request(
    method: str, url: str, body: Any = None, credential: str | None = None
) -> tuple[int, dict[str, Any]]:
    data = None if body is None else json.dumps(body).encode()
    headers = {"Content-Type": "application/json"} if data is not None else {}
    if credential is not None:
        headers["Authorization"] = "Bearer " + credential
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            parsed = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            parsed = {}
        return error.code, parsed
    except urllib.error.URLError as error:
        raise Refused(f"transport:{type(error.reason).__name__}") from error


def _encode(fields: dict[str, Any], uids: dict[str, str]) -> dict[str, Any]:
    encoded = {}
    for key, value in fields.items():
        if isinstance(value, dict):
            encoded[key] = {"stringValue": uids[value["$principal"]]}
        else:
            encoded[key] = {"stringValue": value}
    return encoded


def _decode(fields: Any) -> dict[str, Any]:
    if not isinstance(fields, dict):
        return {}
    return {
        key: value.get("stringValue")
        for key, value in fields.items()
        if isinstance(value, dict) and "stringValue" in value
    }


def _unsigned_jwt(payload: dict[str, Any]) -> str:
    import base64

    def segment(value: dict[str, Any]) -> str:
        raw = json.dumps(value, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    return segment({"alg": "none", "typ": "JWT"}) + "." + segment(payload) + "."


# --------------------------------------------------------------------------
# Child: everything that talks to the owned instance.
# --------------------------------------------------------------------------


class LocalShadow:
    def __init__(self, firestore: str, auth: str, project: str, nonce: str) -> None:
        self.firestore = firestore
        self.auth = auth
        self.project = project
        self.nonce = nonce
        self.tokens: dict[str, str] = {}
        self.uids: dict[str, str] = {}
        self.active_ruleset: str | None = None
        self.plan: dict[str, Any] = {}
        self.tenant: str | None = None
        self.wire_requests = 0

    # -- Auth ------------------------------------------------------------
    def _identity(self, path: str) -> str:
        return f"{self.auth}/identitytoolkit.googleapis.com/{path}"

    def create_tenant(self) -> str:
        status, body = _request(
            "POST",
            self._identity(f"v2/projects/{self.project}/tenants"),
            {"displayName": "o5usertoken", "allowPasswordSignup": True},
            OWNER_TOKEN,
        )
        if status != 200:
            raise Refused(f"tenant-create:{status}:{json.dumps(body)[:200]}")
        name = body.get("name", "")
        tenant = name.rsplit("/", 1)[-1]
        if not tenant:
            raise Refused("tenant-create:missing-identifier")
        self.tenant = tenant
        return tenant

    def sign_up(self, email: str | None, tenant: str | None) -> tuple[str, str]:
        payload: dict[str, Any] = {"returnSecureToken": True}
        if email is not None:
            payload["email"] = email
            payload["password"] = "o5-user-token-" + self.nonce[:12]
        if tenant is not None:
            payload["tenantId"] = tenant
        status, body = _request(
            "POST", self._identity(f"v1/accounts:signUp?key={API_KEY}"), payload
        )
        if status != 200:
            raise Refused(f"signup:{status}:{json.dumps(body)[:200]}")
        return body["localId"], body["idToken"]

    def sign_in(self, email: str, tenant: str | None) -> str:
        payload: dict[str, Any] = {
            "email": email,
            "password": "o5-user-token-" + self.nonce[:12],
            "returnSecureToken": True,
        }
        if tenant is not None:
            payload["tenantId"] = tenant
        status, body = _request(
            "POST",
            self._identity(f"v1/accounts:signInWithPassword?key={API_KEY}"),
            payload,
        )
        if status != 200:
            raise Refused(f"signin:{status}:{json.dumps(body)[:200]}")
        return body["idToken"]

    def set_claims(self, uid: str, claims: dict[str, Any], tenant: str | None) -> None:
        prefix = f"v1/projects/{self.project}"
        if tenant is not None:
            prefix = f"v1/projects/{self.project}/tenants/{tenant}"
        status, body = _request(
            "POST",
            self._identity(f"{prefix}/accounts:update"),
            {"localId": uid, "customAttributes": json.dumps(claims)},
            OWNER_TOKEN,
        )
        if status != 200:
            raise Refused(f"claims:{status}:{json.dumps(body)[:200]}")

    def account_prefix(self, tenant: str | None) -> str:
        if tenant is None:
            return f"v1/projects/{self.project}"
        return f"v1/projects/{self.project}/tenants/{tenant}"

    # -- Rules -----------------------------------------------------------
    def publish(self, label: str) -> None:
        source = self.plan["rulesets"][label]["source"]
        status, body = _request(
            "PUT",
            f"{self.firestore}/emulator/v1/projects/{self.project}:securityRules",
            {"rules": {"files": [{"name": "firestore.rules", "content": source}]}},
            OWNER_TOKEN,
        )
        if status != 200:
            raise Refused(f"publish:{status}:{json.dumps(body)[:400]}")
        self.active_ruleset = label

    # -- Firestore -------------------------------------------------------
    def document_url(self, resource: str) -> str:
        return f"{self.firestore}/v1/{resource}"

    def create_fixture(self, resource: str, fields: dict[str, Any]) -> None:
        status, body = _request(
            "PATCH",
            self.document_url(resource),
            {"fields": _encode(fields, self.uids)},
            OWNER_TOKEN,
        )
        if status != 200:
            raise Refused(f"fixture:{status}:{json.dumps(body)[:200]}")

    def credential_for(self, ref: str) -> str | None:
        if ref == PRINCIPAL_UNAUTHENTICATED:
            return None
        if ref == PRINCIPAL_EMPTY:
            return ""
        if ref == PRINCIPAL_MALFORMED:
            return "not-a-jwt"
        if ref == PRINCIPAL_EXPIRED:
            return _unsigned_jwt(
                {
                    "aud": self.project,
                    "iss": f"https://securetoken.google.com/{self.project}",
                    "sub": self.uids.get("owner-a", "unknown"),
                    "user_id": self.uids.get("owner-a", "unknown"),
                    "iat": 1000,
                    "exp": 2000,
                    "firebase": {"sign_in_provider": "password", "identities": {}},
                }
            )
        return self.tokens[ref]

    def execute(self, request: dict[str, Any]) -> dict[str, Any]:
        """The injected transport the collector calls. Resolves refs to tokens."""
        self.wire_requests += 1
        if request.get("phase") == "recovery":
            return self._recover(request)
        if request["ruleset"] != self.active_ruleset:
            self.publish(request["ruleset"])
        credential = self.credential_for(request["credentialRef"])
        if request["method"] == "get":
            status, body = _request(
                "GET", self.document_url(request["resources"][0]), None, credential
            )
            return {
                "complete": True,
                "status": STATUS_BY_HTTP.get(status, f"HTTP_{status}"),
                "httpStatus": status,
                "documentPresent": status == 200,
                "fields": _decode(body.get("fields")) if status == 200 else None,
            }
        writes = []
        for write in request["writes"]:
            resource = self._resource_of(write["document"])
            entry: dict[str, Any] = {
                "update": {
                    "name": resource,
                    "fields": _encode(write["fields"], self.uids),
                }
            }
            if write["operation"] == "create":
                entry["currentDocument"] = {"exists": False}
            else:
                entry["updateMask"] = {"fieldPaths": sorted(write["fields"])}
                entry["currentDocument"] = {"exists": True}
            writes.append(entry)
        status, body = _request(
            "POST",
            f"{self.firestore}/v1/projects/{self.project}"
            "/databases/(default)/documents:commit",
            {"writes": writes},
            credential,
        )
        return {
            "complete": True,
            "status": STATUS_BY_HTTP.get(status, f"HTTP_{status}"),
            "httpStatus": status,
            "documentPresent": status == 200,
            "fields": None,
        }

    def _resource_of(self, document: str) -> str:
        suffix = f"/cases/{document}"
        for resource in self.plan["ownedResources"]:
            if resource.endswith(suffix):
                return resource
        raise Refused("unknown-owned-document")

    def _recover(self, request: dict[str, Any]) -> dict[str, Any]:
        kind = request["kind"]
        if kind.startswith("account-"):
            return self._recover_account(kind, request)
        resource = request["resource"]
        if kind in ("readback", "absence"):
            status, body = _request(
                "GET", self.document_url(resource), None, OWNER_TOKEN
            )
            return {
                "complete": True,
                "status": STATUS_BY_HTTP.get(status, f"HTTP_{status}"),
                "documentPresent": status == 200,
                "version": body.get("updateTime") if status == 200 else None,
            }
        version = request["precondition"]["updateTime"]
        url = self.document_url(resource) + "?currentDocument.updateTime=" + version
        status, _ = _request("DELETE", url, None, OWNER_TOKEN)
        return {
            "complete": status == 200,
            "status": STATUS_BY_HTTP.get(status, f"HTTP_{status}"),
            "documentPresent": False,
        }

    def _recover_account(self, kind: str, request: dict[str, Any]) -> dict[str, Any]:
        ref = request["accountRef"]
        entry = next(row for row in self.plan["ownedAccounts"] if row["ref"] == ref)
        prefix = self.account_prefix(entry["tenant"])
        uid = self.uids.get(ref)
        if uid is None:
            return {"complete": True, "accountPresent": False, "uid": None}
        if kind in ("account-readback", "account-absence"):
            status, body = _request(
                "POST",
                self._identity(f"{prefix}/accounts:lookup"),
                {"localId": [uid]},
                OWNER_TOKEN,
            )
            present = status == 200 and bool(body.get("users"))
            return {
                "complete": True,
                "status": STATUS_BY_HTTP.get(status, f"HTTP_{status}"),
                "accountPresent": present,
                "uid": uid if present else None,
            }
        status, _ = _request(
            "POST",
            self._identity(f"{prefix}/accounts:delete"),
            {"localId": request["precondition"]["uid"]},
            OWNER_TOKEN,
        )
        return {
            "complete": status == 200,
            "status": STATUS_BY_HTTP.get(status, f"HTTP_{status}"),
            "accountPresent": False,
        }

    # -- Setup -----------------------------------------------------------
    def setup(self) -> None:
        for entry in self.plan["ownedAccounts"]:
            tenant = entry["tenant"]
            uid, token = self.sign_up(entry["email"], tenant)
            self.uids[entry["ref"]] = uid
            if entry["claims"]:
                self.set_claims(uid, entry["claims"], tenant)
                token = self.sign_in(entry["email"], tenant)
            self.tokens[entry["ref"]] = token
        for fixture in self.plan["fixtures"]:
            self.create_fixture(fixture["resource"], fixture["fields"])

    def delete_tenant(self) -> bool:
        if self.tenant is None:
            return True
        status, _ = _request(
            "DELETE",
            self._identity(f"v2/projects/{self.project}/tenants/{self.tenant}"),
            None,
            OWNER_TOKEN,
        )
        return status == 200


def run_child(output: Path, nonce: str) -> int:
    firestore = "http://" + os.environ["FIRESTORE_EMULATOR_HOST"]
    auth = "http://" + os.environ["FIREBASE_AUTH_EMULATOR_HOST"]
    output.mkdir(parents=True, exist_ok=True)
    shadow = LocalShadow(firestore, auth, PROJECT, nonce)
    record: dict[str, Any] = {
        "contract": "fs-rules-user-token-local-shadow-run-v1",
        "status": "LOCAL_SHADOW_ONLY",
        "productionExecuted": False,
        "productionReady": False,
        "parentPid": os.getppid(),
        "childPid": os.getpid(),
        "nonce": nonce,
        "firestoreOrigin": firestore,
        "authOrigin": auth,
    }
    try:
        tenant = shadow.create_tenant()
        record["tenant"] = tenant
        shadow.plan = compile_case(PROJECT, "(default)", nonce, tenant)
        record["planDigest"] = shadow.plan["planDigest"]
        shadow.publish("A")
        shadow.setup()
        bundle = collect(
            shadow.plan,
            shadow.execute,
            role=ROLE_LOCAL_SHADOW,
            run_id=f"local-{nonce}",
            deadline_seconds=300.0,
            recovery_deadline_seconds=600.0,
            journal_path=output / "journal.jsonl",
        )
        # Deviations are computed against the real uids, then everything that
        # gets written out is reduced to principal labels. The raw uids stay in
        # this process.
        deviations = local_deviations(bundle, shadow.plan, shadow.uids)
        bundle["journal"] = Path(bundle["journal"]).name
        record["bundle"] = redact_principals(bundle, shadow.uids)
        record["deviations"] = redact_principals(deviations, shadow.uids)
        record["tenantDeleted"] = shadow.delete_tenant()
        record["wireRequests"] = shadow.wire_requests
        record["launchSpecification"] = launch_specification(shadow.plan)
    except Refused as error:
        record["failure"] = str(error)
    except Exception as error:  # noqa: BLE001 - type name only
        record["failure"] = f"{type(error).__name__}"
    leaked = unredacted_identifiers(record)
    if leaked:
        record = {
            "contract": record["contract"],
            "status": record["status"],
            "productionExecuted": False,
            "productionReady": False,
            "failure": f"unredacted-identifier-count:{len(leaked)}",
        }
    (output / "local-shadow.json").write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n"
    )
    return 0 if "failure" not in record else 2


# --------------------------------------------------------------------------
# Parent: build, launch, stop.
# --------------------------------------------------------------------------


def _socket_closed(origin: str) -> bool:
    host, _, port = origin.rpartition(":")
    try:
        with socket.create_connection((host or "127.0.0.1", int(port)), timeout=1):
            return False
    except OSError:
        return True


def build() -> tuple[Path, dict[str, Any]]:
    completed = subprocess.run(
        ["cargo", "build", "--locked", "-p", "fireemu", "--message-format=json"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        check=True,
        timeout=1800,
    )
    paths = [
        Path(message["executable"])
        for line in completed.stdout.splitlines()
        if (message := json.loads(line)).get("reason") == "compiler-artifact"
        and message.get("target", {}).get("name") == "fireemu"
        and message.get("executable")
    ]
    if len(paths) != 1:
        raise Refused("build produced no single fireemu artifact")
    import hashlib

    return paths[0], {
        "artifactSha256": hashlib.sha256(paths[0].read_bytes()).hexdigest(),
        "rustc": subprocess.check_output(
            ["rustc", "--version"], cwd=ROOT, text=True
        ).strip(),
        "sourceCommit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        # Record only the checkout name: an absolute path would publish a personal directory.
        "worktree": ROOT.name,
    }


def run_parent(output: Path) -> int:
    output.mkdir(parents=True, exist_ok=True)
    binary, artifact = build()
    nonce = uuid.uuid4().hex
    environment = {
        key: os.environ[key] for key in ENVIRONMENT_ALLOWLIST if key in os.environ
    }
    with tempfile.TemporaryDirectory(prefix="o5-user-token-") as temporary:
        private = Path(temporary)
        owned = private / "fireemu"
        shutil.copyfile(binary, owned)
        owned.chmod(0o500)
        rules = private / "firestore.rules"
        rules.write_text(
            "rules_version = '2';\nservice cloud.firestore {\n"
            "  match /databases/{database}/documents {\n"
            "    match /{document=**} { allow read, write: if false; }\n"
            "  }\n}\n"
        )
        firebase_json = private / "firebase.json"
        firebase_json.write_text(
            json.dumps({"firestore": {"rules": "firestore.rules"}})
        )
        argv = [
            str(owned),
            "exec",
            "--firebase-json",
            str(firebase_json),
            "--project",
            PROJECT,
            "--only",
            "auth,firestore",
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
        ]
        (output / "launch.json").write_text(
            json.dumps(
                {
                    "argv": argv,
                    "artifact": artifact,
                    "environment": sorted(environment),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
        child = subprocess.Popen(argv, cwd=private, env=environment)
        try:
            code = child.wait(timeout=900)
        except subprocess.TimeoutExpired:
            child.send_signal(signal.SIGTERM)
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
            code = 124
    time.sleep(0.2)
    record = output / "local-shadow.json"
    if record.exists():
        value = json.loads(record.read_text())
        value["artifact"] = artifact
        value["exitCode"] = code
        value["originsClosed"] = all(
            _socket_closed(value[key].removeprefix("http://"))
            for key in ("firestoreOrigin", "authOrigin")
            if key in value
        )
        record.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    return code


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run")
    parser.add_argument("--child")
    parser.add_argument("--nonce")
    arguments = parser.parse_args()
    if arguments.child:
        return run_child(Path(arguments.child), arguments.nonce)
    if arguments.run:
        return run_parent(Path(arguments.run))
    parser.error("one of --run or --child is required")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
