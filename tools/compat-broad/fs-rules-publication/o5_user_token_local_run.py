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
import errno
import hashlib
import json
import math
import os
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import traceback
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

# Shared stdlib-only HTTP framing checks; no production credentials or worker
# entry point is imported or invoked by this local transport.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from batch_wire import NoRedirect, _read_bounded_response
from o5_user_token_campaign import admitted_manifest_digest
from o5_user_token_case import (
    POST_SIGN_IN_DELETE,
    POST_SIGN_IN_DISABLE,
    POST_SIGN_IN_REVOKE,
    PRINCIPAL_EMPTY,
    PRINCIPAL_EXPIRED,
    PRINCIPAL_MALFORMED,
    PRINCIPAL_REVOKED,
    PRINCIPAL_REVOKED_EXPIRED,
    PRINCIPAL_UNAUTHENTICATED,
    compile_case,
    digest,
)
from o5_user_token_collector import (
    ENVIRONMENT_LOCAL,
    READBACK_PUBLISH_ECHO,
    ROLE_LOCAL_SHADOW,
    collect,
)
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


# What this process's transport records about every HTTP request it makes:
# a running count, and the numeric loopback host and port the last request
# was opened against. A receipt carries these as its wire facts. They are
# written by ``_request`` after its loopback check, never by the caller.
_WIRE = {"sequence": 0, "endpoint": None}


# --------------------------------------------------------------------------
# Transport helpers. Credentials live here and never leave this module.
# --------------------------------------------------------------------------


def _request(
    method: str, url: str, body: Any = None, credential: str | None = None
) -> tuple[int, dict[str, Any]]:
    try:
        parsed = urllib.parse.urlsplit(url)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"127.0.0.1", "::1"}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or not parsed.port
            or method not in {"GET", "POST", "PATCH", "PUT", "DELETE"}
        ):
            raise ValueError("owned numeric loopback required")
        data = None if body is None else json.dumps(body, allow_nan=False).encode()
        if data is not None and len(data) > 1_048_576:
            raise ValueError("local request body exceeds its bound")
        headers = {"Content-Type": "application/json"} if data is not None else {}
        if credential is not None:
            headers["Authorization"] = "Bearer " + credential
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        opener = urllib.request.build_opener(
            NoRedirect(), urllib.request.ProxyHandler({})
        )
        _WIRE["sequence"] += 1
        _WIRE["endpoint"] = f"{parsed.hostname}:{parsed.port}"
        try:
            response = opener.open(request, timeout=REQUEST_TIMEOUT)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw, failure = _read_bounded_response(response, method)
            if failure is not None or 300 <= response.status < 400:
                raise ValueError("incomplete or redirected local response")
            # Empty or unparsable error bodies are not fabricated as {}.
            parsed_body = json.loads(raw)
            if not isinstance(parsed_body, dict):
                raise ValueError("object response required")  # noqa: TRY004 -- refused like every other malformed response
            return response.status, parsed_body
    except (ValueError, OSError, urllib.error.URLError) as error:
        # Never include URLs, request headers, assertions or raw error bodies.
        raise Refused(f"local-transport:{type(error).__name__}") from None


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


def _valid_version(value: Any) -> bool:
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z", value
    ):
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


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
        self.tenant_attempted = False
        self.wire_requests = 0
        self.releases = 0
        self.setup_accounts: list[str] = []
        self.setup_documents: dict[str, dict[str, Any]] = {}
        self.setup_journal: Path | None = None
        self.setup_recovery_started = False

    # -- Auth ------------------------------------------------------------
    def _identity(self, path: str) -> str:
        return f"{self.auth}/identitytoolkit.googleapis.com/{path}"

    def create_tenant(self) -> str:
        self.tenant_attempted = True
        status, body = _request(
            "POST",
            self._identity(f"v2/projects/{self.project}/tenants"),
            {"displayName": "o5usertoken", "allowPasswordSignup": True},
            OWNER_TOKEN,
        )
        if status != 200:
            raise Refused(f"tenant-create:{status}:{json.dumps(body)[:200]}")
        name = body.get("name")
        prefix = f"projects/{self.project}/tenants/"
        tenant = (
            name[len(prefix) :]
            if isinstance(name, str) and name.startswith(prefix)
            else ""
        )
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", tenant) or "error" in body:
            raise Refused("tenant-create:missing-or-foreign-identifier")
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

    def _auth_time(self, token: str) -> int | None:
        """The auth_time claim of a token this process minted locally, or None.

        The claim is read so that a revocation can be placed strictly after
        the second the token was issued in; nothing else of the token is used
        and nothing of it is recorded.
        """
        import base64

        segments = token.split(".")
        if len(segments) != 3:
            return None
        payload = segments[1] + "=" * (-len(segments[1]) % 4)
        try:
            claims = json.loads(base64.urlsafe_b64decode(payload))
        except (ValueError, json.JSONDecodeError):
            return None
        auth_time = claims.get("auth_time", claims.get("iat"))
        return auth_time if type(auth_time) is int and auth_time >= 0 else None

    def _principal_action(self, request: dict[str, Any]) -> dict[str, Any]:
        """Apply one administrator action to an owned account, then read it back.

        Revoke is what the Admin SDK's revokeRefreshTokens does, an
        accounts:update with validSince, placed strictly after the token's
        auth_time second so the token issued before it is revoked rather than
        issued in the same second. The readback is an administrator lookup;
        the receipt carries presence, the disabled flag and the uid
        fingerprint, never the uid or the token.
        """
        ref = request["principalRef"]
        action = request["action"]
        entry = next(row for row in self.plan["ownedAccounts"] if row["ref"] == ref)
        prefix = self.account_prefix(entry["tenant"])
        uid = self.uids.get(ref)
        token = self.tokens.get(ref)
        auth_time = self._auth_time(token) if isinstance(token, str) else None
        if not isinstance(uid, str) or not uid or auth_time is None:
            return {"complete": False, "failure": "principal-action:identity-unknown"}
        valid_since: int | None = None
        if action == POST_SIGN_IN_DELETE:
            status, body = _request(
                "POST",
                self._identity(f"{prefix}/accounts:delete"),
                {"localId": uid},
                OWNER_TOKEN,
            )
        elif action in (POST_SIGN_IN_REVOKE, POST_SIGN_IN_DISABLE):
            payload: dict[str, Any] = {"localId": uid}
            if action == POST_SIGN_IN_REVOKE:
                valid_since = max(int(time.time()), auth_time + 1)
                payload["validSince"] = str(valid_since)
            else:
                payload["disableUser"] = True
            status, body = _request(
                "POST",
                self._identity(f"{prefix}/accounts:update"),
                payload,
                OWNER_TOKEN,
            )
        else:
            return {"complete": False, "failure": "principal-action:unknown-action"}
        if status != 200 or "error" in body:
            return {"complete": False, "failure": f"principal-action:{action}"}
        self._record_setup("account-post-sign-in", account=ref, action=action)
        status, body = _request(
            "POST",
            self._identity(f"{prefix}/accounts:lookup"),
            {"localId": [uid]},
            OWNER_TOKEN,
        )
        users = body.get("users") if isinstance(body, dict) else None
        if (
            status != 200
            or "error" in body
            or not (users is None or isinstance(users, list))
        ):
            return {"complete": False, "failure": "principal-action:lookup"}
        users = users or []
        if len(users) > 1 or (users and users[0].get("localId") != uid):
            return {"complete": False, "failure": "principal-action:lookup"}
        present = bool(users)
        disabled = bool(users[0].get("disabled", False)) if present else None
        return {
            "complete": True,
            "status": "OK",
            "action": action,
            "authTime": auth_time,
            "validSince": valid_since,
            "present": present,
            "disabled": disabled,
            "uidFingerprint": digest(["uid", self.nonce, uid])[:16],
        }

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

    def _record_setup(self, kind: str, **value: Any) -> None:
        if self.setup_journal is None:
            return
        fd = os.open(
            self.setup_journal,
            os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW,
            0o600,
        )
        with os.fdopen(fd, "a", encoding="utf-8") as stream:
            stream.write(json.dumps({"kind": kind, **value}, allow_nan=False) + "\n")
            stream.flush()
            os.fsync(stream.fileno())

    def create_fixture(self, resource: str, fields: dict[str, Any]) -> None:
        encoded = _encode(fields, self.uids)
        # A failed send or lost acknowledgement stays unknown, not absent.
        proof: dict[str, Any] = {"outcome": "unknown", "version": None}
        self.setup_documents[resource] = proof
        self._record_setup("document-intent", resource=resource)
        status, body = _request(
            "PATCH",
            self.document_url(resource) + "?currentDocument.exists=false",
            {"fields": encoded},
            OWNER_TOKEN,
        )
        version = body.get("updateTime")
        valid_version = _valid_version(version)
        if (
            type(status) is not int
            or status != 200
            or "error" in body
            or body.get("name") != resource
            or body.get("fields") != encoded
            or not valid_version
        ):
            # A typed conditional conflict did not create this resource. Never
            # turn the pre-existing document into this run's deletion authority.
            error = body.get("error")
            if (
                status == 409
                and isinstance(error, dict)
                and error.get("status") == "ALREADY_EXISTS"
                and error.get("code") == 409
            ):
                proof["outcome"] = "rejected"
            raise Refused("fixture:creation-unconfirmed")
        proof.update(outcome="created", version=version)
        self._record_setup("document-created", resource=resource, version=version)

    def credential_for(self, ref: str) -> str | None:
        if ref == PRINCIPAL_UNAUTHENTICATED:
            return None
        if ref == PRINCIPAL_EMPTY:
            return ""
        if ref == PRINCIPAL_MALFORMED:
            return "not-a-jwt"
        if ref in (PRINCIPAL_EXPIRED, PRINCIPAL_REVOKED_EXPIRED):
            subject = "owner-a" if ref == PRINCIPAL_EXPIRED else PRINCIPAL_REVOKED
            return _unsigned_jwt(
                {
                    "aud": self.project,
                    "iss": f"https://securetoken.google.com/{self.project}",
                    "sub": self.uids.get(subject, "unknown"),
                    "user_id": self.uids.get(subject, "unknown"),
                    "iat": 1000,
                    "exp": 2000,
                    "firebase": {"sign_in_provider": "password", "identities": {}},
                }
            )
        return self.tokens[ref]

    def execute(self, request: dict[str, Any]) -> dict[str, Any]:
        """The injected transport the collector calls. Resolves refs to tokens.

        Every receipt carries the wire facts ``_request`` recorded for the
        last HTTP request it made: the loopback host and port reached and the
        process-wide request counter.
        """
        self.wire_requests += 1
        receipt = self._execute(request)
        receipt["endpoint"] = _WIRE["endpoint"]
        receipt["wireSequence"] = _WIRE["sequence"]
        return receipt

    def _release(self, request: dict[str, Any]) -> dict[str, Any]:
        """Publish the requested Ruleset and echo what was published.

        The local runtime answers a publication with an empty issue list and has
        no route that reads the active release back, so the readback is the
        digest of the bytes this transport sent, labelled as such. The
        collector checks it against the plan; the acquisition comparator
        accepts a publish echo on the local side only.
        """
        label = request["ruleset"]
        source = self.plan["rulesets"][label]["source"]
        if digest(source) != request.get("sourceDigest"):
            return {"complete": False, "failure": "ruleset-source-drift"}
        self.publish(label)
        self.releases += 1
        return {
            "complete": True,
            "status": "OK",
            "releaseName": f"local-{label}-{self.releases}",
            "readbackKind": READBACK_PUBLISH_ECHO,
            "readbackDigest": digest(source),
        }

    def _execute(self, request: dict[str, Any]) -> dict[str, Any]:
        if request.get("phase") == "recovery":
            return self._recover(request)
        if request.get("phase") == "ruleset":
            return self._release(request)
        if request.get("phase") == "principal":
            return self._principal_action(request)
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
            if status == 404:
                error = body.get("error")
                absent = (
                    set(body) == {"error"}
                    and isinstance(error, dict)
                    and type(error.get("code")) is int
                    and error["code"] == 404
                    and error.get("status") == "NOT_FOUND"
                )
                if absent:
                    return {
                        "complete": True,
                        "status": "NOT_FOUND",
                        "documentPresent": False,
                        "version": None,
                    }
            elif status == 200 and "error" not in body and body.get("name") == resource:
                version = body.get("updateTime")
                if _valid_version(version):
                    return {
                        "complete": True,
                        "status": "OK",
                        "documentPresent": True,
                        "version": version,
                    }
            return {"complete": False, "failure": "invalid-owned-document-readback"}
        version = request["precondition"]["updateTime"]
        url = (
            self.document_url(resource)
            + "?currentDocument.updateTime="
            + urllib.parse.quote(version, safe="")
        )
        status, body = _request("DELETE", url, None, OWNER_TOKEN)
        return {
            "complete": type(status) is int and status == 200 and body == {},
            "status": STATUS_BY_HTTP.get(status, f"HTTP_{status}"),
            "documentPresent": False,
        }

    def _recover_account(self, kind: str, request: dict[str, Any]) -> dict[str, Any]:
        ref = request["accountRef"]
        entry = next(row for row in self.plan["ownedAccounts"] if row["ref"] == ref)
        prefix = self.account_prefix(entry["tenant"])
        uid = self.uids.get(ref)
        if uid is None:
            # A lost sign-up response is not evidence that no account exists.
            return {"complete": False, "failure": "owned-account-identity-unknown"}
        if kind in ("account-readback", "account-absence"):
            status, body = _request(
                "POST",
                self._identity(f"{prefix}/accounts:lookup"),
                {"localId": [uid]},
                OWNER_TOKEN,
            )
            valid = (
                type(status) is int
                and status == 200
                and isinstance(body, dict)
                and "error" not in body
                and "nextPageToken" not in body
                and (
                    "kind" not in body
                    or body["kind"] == "identitytoolkit#GetAccountInfoResponse"
                )
            )
            if valid and "users" not in body:
                valid = body == {"kind": "identitytoolkit#GetAccountInfoResponse"}
                users = []
            else:
                users = body.get("users") if isinstance(body, dict) else None
            valid = valid and isinstance(users, list) and len(users) <= 1
            if valid and users:
                valid = isinstance(users[0], dict) and users[0].get("localId") == uid
            if not valid:
                return {"complete": False, "failure": "invalid-owned-account-lookup"}
            present = bool(users)
            return {
                "complete": True,
                "status": "OK",
                "accountPresent": present,
                "uid": uid if present else None,
            }
        status, body = _request(
            "POST",
            self._identity(f"{prefix}/accounts:delete"),
            {"localId": request["precondition"]["uid"]},
            OWNER_TOKEN,
        )
        return {
            "complete": type(status) is int
            and status == 200
            and body
            in (
                {},
                {"kind": "identitytoolkit#DeleteAccountResponse"},
            ),
            "status": STATUS_BY_HTTP.get(status, f"HTTP_{status}"),
            "accountPresent": False,
        }

    # -- Setup -----------------------------------------------------------
    def setup(self) -> None:
        for entry in self.plan["ownedAccounts"]:
            tenant = entry["tenant"]
            self._record_setup("account-intent", account=entry["ref"])
            self.setup_accounts.append(entry["ref"])
            uid, token = self.sign_up(entry["email"], tenant)
            if (
                not isinstance(uid, str)
                or not uid
                or not isinstance(token, str)
                or not token
            ):
                raise Refused("signup:invalid-identity")
            self.uids[entry["ref"]] = uid
            self._record_setup("account-created", account=entry["ref"], uid=uid)
            if entry["claims"]:
                self.set_claims(uid, entry["claims"], tenant)
                token = self.sign_in(entry["email"], tenant)
            self.tokens[entry["ref"]] = token
        for fixture in self.plan["fixtures"]:
            self.create_fixture(fixture["resource"], fixture["fields"])

    def recover_setup(self, *, deadline_seconds: float = 600.0) -> dict[str, Any]:
        """Rollback only effects attempted by incomplete setup, with no retry.

        Acknowledgement-less creates remain outstanding even after a 404: a
        request could still complete late. No namespace-wide sweep is allowed.
        This path does not run after observation began or refill its budget.
        """
        if (
            type(deadline_seconds) not in (int, float)
            or not math.isfinite(deadline_seconds)
            or not 0 < deadline_seconds <= 600
        ):
            raise Refused("invalid-setup-recovery-deadline")
        if self.setup_recovery_started:
            raise Refused("setup-recovery-already-started")
        self.setup_recovery_started = True
        started = time.monotonic()
        if not math.isfinite(started):
            raise Refused("invalid-setup-recovery-clock")
        deadline = started + deadline_seconds
        limit = 3 * (len(self.setup_documents) + len(self.setup_accounts))
        spent = 0
        last = started
        clock_failed = False
        rows: list[dict[str, Any]] = []

        def request(kind: str, **kwargs: Any) -> dict[str, Any]:
            nonlocal spent, last, clock_failed
            now = time.monotonic()
            clock_failed = clock_failed or not math.isfinite(now) or now < last
            if clock_failed or now + REQUEST_TIMEOUT > deadline or spent >= limit:
                raise Refused("setup-recovery-budget")
            last = now
            spent += 1
            result = self._recover({"kind": kind, **kwargs})
            after = time.monotonic()
            clock_failed = clock_failed or not math.isfinite(after) or after < last
            if clock_failed or after > deadline or result.get("complete") is not True:
                raise Refused("setup-recovery-unconfirmed")
            last = after
            return result

        for resource, proof in self.setup_documents.items():
            row = {"kind": "document", "subject": resource, "complete": False}
            rows.append(row)
            if proof["outcome"] == "rejected":
                row.update(complete=True, outcome="not-created-by-run")
                continue
            if proof["outcome"] != "created":
                row["outcome"] = "creation-unconfirmed"
                continue
            try:
                current = request("readback", resource=resource)
                if current.get("documentPresent") is False:
                    row.update(complete=True, outcome="already-absent")
                    continue
                if current.get("version") != proof["version"]:
                    raise Refused("setup-version-changed")
                request(
                    "delete",
                    resource=resource,
                    precondition={"updateTime": proof["version"]},
                )
                final = request("absence", resource=resource)
                row.update(
                    complete=final.get("documentPresent") is False,
                    outcome="final-readback",
                )
            except Exception as error:  # noqa: BLE001 -- keep independent rollback attempts
                row.update(outcome="unconfirmed", failure=type(error).__name__)
        for ref in self.setup_accounts:
            row = {"kind": "account", "subject": ref, "complete": False}
            rows.append(row)
            uid = self.uids.get(ref)
            if not uid:
                row["outcome"] = "creation-unconfirmed"
                continue
            try:
                current = request("account-readback", accountRef=ref)
                if current.get("accountPresent") is False:
                    row.update(complete=True, outcome="already-absent")
                    continue
                if current.get("uid") != uid:
                    raise Refused("setup-uid-changed")
                request("account-delete", accountRef=ref, precondition={"uid": uid})
                final = request("account-absence", accountRef=ref)
                row.update(
                    complete=final.get("accountPresent") is False,
                    outcome="final-readback",
                )
            except Exception as error:  # noqa: BLE001 -- recover unrelated accounts
                row.update(outcome="unconfirmed", failure=type(error).__name__)
        return {
            "complete": all(row["complete"] for row in rows),
            "rows": rows,
            "requestLimit": limit,
            "requests": spent,
            "deadlineSeconds": deadline_seconds,
        }

    def delete_tenant(self) -> bool:
        if self.tenant is None:
            return not self.tenant_attempted
        url = self._identity(f"v2/projects/{self.project}/tenants/{self.tenant}")
        # A deletion response is not a final resource readback. Preserve failure
        # even when the subsequent lookup independently proves absence.
        status, body = _request("DELETE", url, None, OWNER_TOKEN)
        deleted = type(status) is int and status == 200 and body == {}
        status, body = _request("GET", url, None, OWNER_TOKEN)
        error = body.get("error") if isinstance(body, dict) else None
        absent = (
            type(status) is int
            and status == 404
            and isinstance(body, dict)
            and set(body) == {"error"}
            and isinstance(error, dict)
            and type(error.get("code")) is int
            and error["code"] == 404
            and error.get("message") == "TENANT_NOT_FOUND"
            and ("status" not in error or error["status"] == "NOT_FOUND")
            and (
                "errors" not in error
                or error["errors"]
                == [
                    {
                        "message": "TENANT_NOT_FOUND",
                        "domain": "global",
                        "reason": "invalid",
                    }
                ]
            )
        )
        return deleted and absent


def _local_acquisition(output: Path, shadow: LocalShadow) -> dict[str, Any]:
    """The bindings a local shadow run carries into its bundle.

    The environment is local, there is no reservation and no owner permission,
    the artifact is what the parent recorded in ``launch.json`` before it
    started this child, and each principal is fingerprinted from the nonce and
    the uid the local Auth emulator assigned. No uid and no token is bound.
    """
    plan = shadow.plan
    artifact = None
    launch = output / "launch.json"
    if launch.is_file() and not launch.is_symlink():
        recorded = json.loads(launch.read_bytes()).get("artifact")
        if isinstance(recorded, dict):
            artifact = {
                "artifactSha256": recorded.get("artifactSha256"),
                "sourceCommit": recorded.get("sourceCommit"),
            }
    principals = {}
    for entry in plan["ownedAccounts"]:
        uid = shadow.uids.get(entry["ref"])
        if not isinstance(uid, str) or not uid:
            continue
        principals[entry["ref"]] = {
            "uidFingerprint": digest(["uid", plan["nonce"], uid])[:16],
            "provider": "anonymous" if entry["kind"] == "anonymous" else "email",
            "tenant": entry["tenant"],
            "claimsDigest": digest(entry["claims"]),
        }
    return {
        "environment": {"kind": ENVIRONMENT_LOCAL},
        "campaignManifestDigest": admitted_manifest_digest(
            plan["project"], plan["database"], plan["nonce"]
        ),
        "nonceReservation": None,
        "ownerPermission": None,
        "artifact": artifact,
        "principals": principals,
        "window": None,
    }


def run_child(output: Path, nonce: str) -> int:
    firestore = "http://" + os.environ["FIRESTORE_EMULATOR_HOST"]
    auth = "http://" + os.environ["FIREBASE_AUTH_EMULATOR_HOST"]
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Parent launch metadata may exist, but a child invocation is single-use.
    with (output / "child-started").open("x", encoding="utf-8") as stream:
        stream.write("local-only\n")
    if any(
        (output / name).exists() or (output / name).is_symlink()
        for name in ("local-shadow.json", "setup-journal.jsonl", "journal.jsonl")
    ):
        raise Refused("existing-child-evidence")
    shadow = LocalShadow(firestore, auth, PROJECT, nonce)
    shadow.setup_journal = output / "setup-journal.jsonl"
    setup_finished = False
    stage = "initialization"
    record: dict[str, Any] = {
        "contract": "fs-rules-user-token-local-shadow-run-v1",
        "status": "LOCAL_SHADOW_ONLY",
        "productionExecuted": False,
        "productionReady": False,
        "completed": False,
        "parentPid": os.getppid(),
        "childPid": os.getpid(),
        "nonce": nonce,
        "firestoreOrigin": firestore,
        "authOrigin": auth,
    }
    try:
        stage = "tenant-create"
        tenant = shadow.create_tenant()
        record["tenant"] = tenant
        stage = "plan-compile"
        shadow.plan = compile_case(PROJECT, "(default)", nonce, tenant)
        record["planDigest"] = shadow.plan["planDigest"]
        stage = "ruleset-publish"
        shadow.publish("A")
        stage = "fixture-setup"
        shadow.setup()
        setup_finished = True
        stage = "collector"
        bundle = collect(
            shadow.plan,
            shadow.execute,
            role=ROLE_LOCAL_SHADOW,
            run_id=f"local-{nonce}",
            deadline_seconds=300.0,
            recovery_deadline_seconds=600.0,
            journal_path=output / "journal.jsonl",
            acquisition=_local_acquisition(output, shadow),
        )
        # The collector has already replaced every uid its recovery readbacks
        # returned with the principal label, so the frozen-field check resolves
        # `$principal` to that label: a field equals the label exactly when it
        # equalled the uid the administrator lookup returned for that account.
        # The raw uids stay in this process.
        stage = "local-comparison"
        labels = {ref: f"principal:{ref}" for ref in shadow.uids}
        deviations = local_deviations(bundle, shadow.plan, labels)
        bundle["journal"] = Path(bundle["journal"]).name
        record["bundle"] = redact_principals(bundle, shadow.uids)
        record["deviations"] = redact_principals(deviations, shadow.uids)
        record["stateValidation"] = not deviations
        record["recordingComplete"] = bundle.get("recordingComplete") is True
        record["resourceCleanupComplete"] = (
            isinstance(bundle.get("cleanup"), dict)
            and bundle["cleanup"].get("cleanupComplete") is True
        )
        record["wireRequests"] = shadow.wire_requests
        record["httpRequests"] = _WIRE["sequence"]
        record["launchSpecification"] = launch_specification(shadow.plan)
    except Refused as error:
        record["failure"] = str(error).split(":", 1)[0]
    except Exception as error:  # noqa: BLE001 - type name only
        record["failure"] = f"{type(error).__name__}"
        frames = traceback.extract_tb(error.__traceback__)
        if frames:
            frame = frames[-1]
            record["failureDetail"] = {
                "type": type(error).__name__,
                "stage": stage,
                "file": Path(frame.filename).name,
                "line": frame.lineno,
                "function": frame.name,
            }
    finally:
        if not setup_finished and shadow.plan:
            try:
                recovery = shadow.recover_setup()
                record["setupRecovery"] = redact_principals(recovery, shadow.uids)
                record["resourceCleanupComplete"] = recovery.get("complete") is True
            except Exception as error:  # noqa: BLE001 -- retain rollback failure separately
                record["resourceCleanupComplete"] = False
                record["setupRecoveryFailure"] = type(error).__name__
        # Creating a tenant is an effect even if fixture setup never completed.
        # Attempt its owned cleanup once; failure is never swallowed or retried.
        try:
            record["tenantDeleted"] = shadow.delete_tenant() is True
        except Exception as error:  # noqa: BLE001 - retain the independent failure
            record["tenantDeleted"] = False
            record["tenantCleanupFailure"] = type(error).__name__
    record["completed"] = (
        "failure" not in record
        and record.get("recordingComplete") is True
        and record.get("stateValidation") is True
        and record.get("resourceCleanupComplete") is True
        and record.get("tenantDeleted") is True
    )
    if not record["completed"] and "failure" not in record:
        record["failure"] = "local-acceptance-incomplete"
    leaked = unredacted_identifiers(record)
    if leaked:
        record = {
            "contract": record["contract"],
            "status": record["status"],
            "productionExecuted": False,
            "productionReady": False,
            "failure": f"unredacted-identifier-count:{len(leaked)}",
        }
    _publish_new(output / "local-shadow.json", record)
    return 0 if record.get("completed") is True else 2


# --------------------------------------------------------------------------
# Parent: build, launch, stop.
# --------------------------------------------------------------------------


def _socket_closed(origin: str) -> bool:
    """Only connection refusal proves closure; timeout/invalid address is unknown."""
    try:
        value = urllib.parse.urlsplit(
            origin if origin.startswith("http://") else "http://" + origin
        )
        if (
            value.scheme != "http"
            or value.hostname not in {"127.0.0.1", "::1"}
            or not value.port
            or value.username is not None
            or value.password is not None
            or value.path
            or value.query
            or value.fragment
        ):
            return False
        with socket.create_connection((value.hostname, value.port), timeout=1):
            return False
    except OSError as error:
        return error.errno == errno.ECONNREFUSED
    except (ValueError, TypeError):
        return False


def _publish_new(path: Path, value: dict[str, Any]) -> None:
    """Exclusive, fsynced publication. Never overwrite another run's evidence."""
    temporary = None
    try:
        fd, name = tempfile.mkstemp(prefix=".receipt-", dir=path.parent)
        temporary = Path(name)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, allow_nan=False, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _read_child_receipt(path: Path) -> tuple[dict[str, Any], str]:
    # O_NONBLOCK avoids hanging on a FIFO substituted for the expected file.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 8 * 1024 * 1024:
            raise Refused("invalid-child-receipt-file")
        raw = stream.read(8 * 1024 * 1024 + 1)
    if len(raw) > 8 * 1024 * 1024:
        raise Refused("oversized-child-receipt")

    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise Refused("duplicate-child-receipt-key")
            value[key] = item
        return value

    def nonfinite(_value):
        raise Refused("nonfinite-child-receipt")

    value = json.loads(raw, object_pairs_hook=unique, parse_constant=nonfinite)
    if not isinstance(value, dict):
        raise Refused("invalid-child-receipt")
    return value, hashlib.sha256(raw).hexdigest()


def _stop_owned_process(child: subprocess.Popen) -> bool:
    """Stop only the new process group created by this parent's Popen.

    An unreaped live leader pins its PID. Never signal a group after the leader
    has been reaped; closed listeners are verified separately in either case.
    """

    def group_gone() -> bool:
        try:
            os.killpg(child.pid, 0)
        except ProcessLookupError:
            return True
        except OSError:
            return False
        return False

    for sig in (signal.SIGTERM, signal.SIGKILL):
        if child.poll() is not None:
            return group_gone()
        try:
            if os.getpgid(child.pid) != child.pid:
                return False
            os.killpg(child.pid, sig)
        except ProcessLookupError:
            pass
        except OSError:
            return False
        try:
            child.wait(timeout=10)
            return group_gone()
        except subprocess.TimeoutExpired:
            continue
    return child.poll() is not None and group_gone()


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


def _validated_child_python() -> str:
    """Use the same absolute Python 3.12 interpreter for the child driver."""
    executable = Path(sys.executable)
    if (
        not executable.is_absolute()
        or not executable.is_file()
        or sys.version_info[:2] != (3, 12)
    ):
        raise Refused("python-3.12-child-runtime-required")
    return str(executable)


def run_parent(output: Path) -> int:
    if output.exists() or output.is_symlink():
        raise Refused("fresh-parent-output-required")
    output = output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    python_executable = _validated_child_python()
    nonce = uuid.uuid4().hex
    environment = {
        key: os.environ[key] for key in ENVIRONMENT_ALLOWLIST if key in os.environ
    }
    parent: dict[str, Any] = {
        "contract": "fs-rules-user-token-parent-v2",
        "productionExecuted": False,
        "completed": False,
        "processStopped": False,
        "originsClosed": False,
        "childReceiptValid": False,
        "issues": [],
        "exitCode": None,
    }
    child = None
    artifact = None
    try:
        binary, artifact = build()
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
                python_executable,
                str(Path(__file__).resolve()),
                "--child",
                str(output),
                "--nonce",
                nonce,
            ]
            _publish_new(
                output / "launch.json",
                {
                    "artifact": artifact,
                    "pythonExecutable": python_executable,
                    "pythonVersion": "3.12",
                    "environment": sorted(environment),
                    "privateExecutable": "fireemu",
                    "newProcessGroup": True,
                },
            )
            try:
                child = subprocess.Popen(
                    argv, cwd=private, env=environment, start_new_session=True
                )
                try:
                    parent["exitCode"] = child.wait(timeout=900)
                except subprocess.TimeoutExpired:
                    parent["exitCode"] = 124
                    parent["issues"].append("child-timeout")
            finally:
                if child is not None:
                    parent["processStopped"] = _stop_owned_process(child)
                    if not parent["processStopped"]:
                        parent["issues"].append("owned-process-stop-unconfirmed")
    except Exception as error:  # noqa: BLE001 -- sanitized parent evidence
        parent["issues"].append("parent-operation:" + type(error).__name__)
    parent["artifact"] = artifact
    if child is not None:
        try:
            value, sha = _read_child_receipt(output / "local-shadow.json")
            parent["childReceiptSha256"] = sha
            required = {
                "contract": "fs-rules-user-token-local-shadow-run-v1",
                "status": "LOCAL_SHADOW_ONLY",
                "productionExecuted": False,
                "productionReady": False,
                "completed": True,
                "nonce": nonce,
                "recordingComplete": True,
                "stateValidation": True,
                "resourceCleanupComplete": True,
                "tenantDeleted": True,
            }
            parent["childReceiptValid"] = (
                all(
                    type(value.get(key)) is type(expected)
                    and value.get(key) == expected
                    for key, expected in required.items()
                )
                and value.get("failure") is None
                and type(value.get("childPid")) is int
                and value["childPid"] > 0
            )
            # Missing endpoints are never an empty conjunction proving closure.
            endpoints = [value.get(key) for key in ("firestoreOrigin", "authOrigin")]
            parent["originsClosed"] = all(
                isinstance(origin, str) and _socket_closed(origin)
                for origin in endpoints
            )
        except Exception as error:  # noqa: BLE001 -- retain absent/malformed receipt
            parent["issues"].append("child-receipt:" + type(error).__name__)
    for flag in ("processStopped", "originsClosed", "childReceiptValid"):
        if parent[flag] is not True:
            parent["issues"].append(flag + "-unconfirmed")
    if type(parent["exitCode"]) is not int or parent["exitCode"] != 0:
        parent["issues"].append("child-exit-unsuccessful")
    parent["completed"] = not parent["issues"]
    parent["returnCode"] = 0 if parent["completed"] else 2
    # Preserve the child bytes. A parent receipt points to them by hash instead
    # of relabeling them as the result of another process or rewriting history.
    _publish_new(output / "parent-result.json", parent)
    return parent["returnCode"]


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
