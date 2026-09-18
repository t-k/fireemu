"""Bounded, credential-free collector for the OOB action-code matrix.

The collector walks the frozen stages of `action_codes_plan`, holding every
action code, password and token in memory only. It writes a typed receipt that
records what each response *was shaped like*, never the secret it carried, and
it always runs its recovery finalizer, including after a failed stage.

Only a loopback origin is accepted. A supplied owner approval is refused rather
than honoured: this module has no production entry, and adding one is a
separate reviewed change.
"""

from __future__ import annotations

import argparse
import json
import re
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from action_codes_plan import (
    CAMPAIGN_ID,
    CONTRACT,
    SECRET_FIELDS,
    campaign_manifest,
    manifest_digest,
)

REDACTED = "[REDACTED]"
LOOPBACK = {"127.0.0.1", "::1", "localhost"}
_BASE64URL = re.compile(r"[A-Za-z0-9_-]+")
_SECRET_KEY = re.compile("|".join(SECRET_FIELDS), re.IGNORECASE)


class CollectorError(RuntimeError):
    """A bound, an ownership rule or the closed production entry was violated."""


class BindingError(RuntimeError):
    """A stage asked for a runtime value an earlier stage never produced."""


def redact(value: Any) -> Any:
    """Replace every secret-named value, at any depth, with a fixed marker."""
    if isinstance(value, dict):
        return {
            key: REDACTED if _SECRET_KEY.search(key) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def character_class(value: str) -> str:
    """Name the alphabet of a returned code without recording the code."""
    if not value:
        return "empty"
    return "base64url" if _BASE64URL.fullmatch(value) else "other"


def _loopback_origin(origin: str) -> str:
    url = urllib.parse.urlsplit(origin)
    if (
        url.scheme != "http"
        or url.hostname not in LOOPBACK
        or url.username
        or url.password
        or url.path
        or url.query
        or url.fragment
    ):
        raise CollectorError("only a bare loopback http origin may be collected")
    return origin


def _error(body: Any) -> tuple[str | None, str | None]:
    if not isinstance(body, dict) or not isinstance(body.get("error"), dict):
        return None, None
    message = body["error"].get("message")
    if not isinstance(message, str):
        return None, None
    return message.split(" : ", 1)[0].strip(), message


def _password(nonce: str, label: str) -> str:
    # Local throwaway credentials; never recorded, never passed as an argument.
    return f"Aa9!{label}-{nonce[:8]}-{secrets.token_urlsafe(12)}"


class _Run:
    """Mutable state of one collection: bindings, budget and owned resources."""

    def __init__(
        self,
        origin: str,
        project: str,
        nonce: str,
        send: Callable[..., tuple[int, Any]],
        request_budget: int,
        recovery_budget: int,
        wall_seconds: int,
        recovery_seconds: int,
        clock: Callable[[], float],
    ) -> None:
        self.origin = origin
        self.project = project
        self.nonce = nonce
        self.send = send
        self.request_budget = request_budget
        self.recovery_budget = recovery_budget
        self.wall_seconds = wall_seconds
        self.recovery_seconds = recovery_seconds
        self.clock = clock
        self.started = clock()
        self.requests = 0
        self.recovery_requests = 0
        # Recovery draws on its own reserve, so an exhausted observation budget
        # can never stop the owned accounts from being deleted.
        self.recovering = False
        self.secrets: dict[str, str] = {}
        self.owned: dict[str, dict[str, Any]] = {}

    def spend(self) -> None:
        if self.recovering:
            self.recovery_requests += 1
            if self.recovery_requests > self.recovery_budget:
                raise CollectorError("recovery request budget exhausted")
            if self.clock() - self.recovery_started > self.recovery_seconds:
                raise CollectorError("recovery wall clock budget exhausted")
            return
        self.requests += 1
        if self.requests > self.request_budget:
            raise CollectorError("request budget exhausted")
        if self.clock() - self.started > self.wall_seconds:
            raise CollectorError("wall clock budget exhausted")

    def begin_recovery(self) -> None:
        self.recovering = True
        self.recovery_started = self.clock()

    def resolve(self, value: Any) -> Any:
        if isinstance(value, str) and value.startswith("$binding:"):
            name = value.removeprefix("$binding:")
            if name not in self.secrets:
                raise BindingError("unbound stage input: " + name)
            return self.secrets[name]
        if isinstance(value, dict):
            return {key: self.resolve(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self.resolve(item) for item in value]
        return value

    def request(self, path: str, body: dict[str, Any], privileged: bool):
        self.spend()
        headers = {"content-type": "application/json"}
        if privileged:
            headers["authorization"] = "Bearer owner"
        url = self.origin + path.replace("{project}", self.project)
        return self.send("POST", url, headers, self.resolve(body))


def _bind_accounts(run: _Run, manifest: dict[str, Any]) -> None:
    for name, account in manifest["ownedAccounts"].items():
        run.secrets[name + ".email"] = account["email"]
        for slot in (
            "password",
            "nextPassword",
            "thirdPassword",
            "fourthPassword",
            "fifthPassword",
        ):
            run.secrets[f"{name}.{slot}"] = _password(run.nonce, slot)
    run.secrets["weakPassword"] = "a"
    run.secrets["wrongCode"] = "definitely-not-an-issued-code"
    run.secrets["unknownEmail"] = f"o1-oob-{run.nonce}-absent@example.invalid"


_CODE_BINDING = {
    "reset-link-generate": "resetCode",
    "reset-link-generate-second": "resetCodeSecond",
    "verify-link-generate": "verifyCode",
    "email-link-generate": "emailLinkCode",
    "email-link-generate-second": "emailLinkCodeSecond",
    "deleted-user-link-generate": "deletedUserCode",
}
_ACCOUNT_BINDING = {"account-a-create": "accountA", "account-b-create": "accountB"}
# Every stage that asks for a link, including the one whose address never existed.
_LINK_STAGES = frozenset(_CODE_BINDING) | {"link-generate-unknown-email"}


def _project_stage(
    run: _Run, stage: dict[str, Any], status: int, body: Any
) -> dict[str, Any]:
    """Record the shape and the semantics of one response, never its secrets."""
    code, message = _error(body)
    row: dict[str, Any] = {
        "id": stage["id"],
        "group": stage["group"],
        "basis": stage["basis"],
        "routeClass": stage["routeClass"],
        "status": status,
        "keys": sorted(body.keys()) if isinstance(body, dict) else None,
        "errorCode": code,
        "errorMessage": message,
    }
    if not isinstance(body, dict):
        row["bodyType"] = type(body).__name__
        return row
    if stage["id"] in _LINK_STAGES:
        value = body.get("oobCode")
        row["oobCodeReturned"] = isinstance(value, str) and bool(value)
        row["oobLinkReturned"] = isinstance(body.get("oobLink"), str)
        if row["oobCodeReturned"]:
            row["oobCodeLength"] = len(value)
            row["oobCodeCharacterClass"] = character_class(value)
            if stage["id"] in _CODE_BINDING:
                run.secrets[_CODE_BINDING[stage["id"]]] = value
        row["emailEchoesOwner"] = body.get("email") in {
            account["email"] for account in run.owned.values()
        }
    if stage["id"] in _ACCOUNT_BINDING:
        name = _ACCOUNT_BINDING[stage["id"]]
        local_id = body.get("localId")
        if isinstance(local_id, str) and local_id:
            run.secrets[name + ".localId"] = local_id
            run.owned[name] = {
                "email": run.secrets[name + ".email"],
                "localId": local_id,
            }
        row["accountCreated"] = name in run.owned
    for field in ("requestType", "emailVerified", "isNewUser"):
        if field in body:
            row[field] = body[field]
    if "idToken" in body or "refreshToken" in body:
        # Flat names, so no secret field ever occupies a key position.
        row["idTokenReturned"] = isinstance(body.get("idToken"), str)
        row["refreshTokenReturned"] = isinstance(body.get("refreshToken"), str)
    if "users" in body:
        users = body["users"] if isinstance(body["users"], list) else []
        row["userCount"] = len(users)
        if users and isinstance(users[0], dict):
            row["userEmailVerified"] = users[0].get("emailVerified")
    if "email" in body and isinstance(body["email"], str):
        row["emailMatchesRequest"] = body["email"].endswith("@example.invalid")
    return row


def _recover(
    run: _Run, manifest: dict[str, Any]
) -> tuple[list[dict[str, Any]], bool, int, int]:
    """Delete every owned account, then require typed absence for each one."""
    rows: list[dict[str, Any]] = []
    remaining = 0
    delete_failures = 0
    for row in manifest["recovery"]:
        account = row["account"]
        if account + ".localId" not in run.secrets:
            rows.append(
                {
                    "id": row["id"],
                    "account": account,
                    "status": None,
                    "skipped": "never-created",
                }
            )
            continue
        try:
            status, body = run.request(row["path"], row["body"], True)
        except Exception as error:  # noqa: BLE001 -- recovery records, never raises.
            rows.append(
                {
                    "id": row["id"],
                    "account": account,
                    "status": None,
                    "failure": type(error).__name__,
                }
            )
            delete_failures += 1
            continue
        record = {"id": row["id"], "account": account, "status": status}
        if row["operationType"] == "auth-lookup":
            users = body.get("users") if isinstance(body, dict) else None
            record["absent"] = status == 200 and not users
            if not record["absent"]:
                remaining += 1
        elif status != 200:
            # A delete can be refused because a stage already removed the
            # account. Absence, proven below, is the requirement; a refusal is
            # recorded but does not by itself fail recovery.
            record["deleted"] = False
            delete_failures += 1
        else:
            record["deleted"] = True
        rows.append(record)
    complete = remaining == 0 and not any("failure" in row for row in rows)
    return rows, complete, remaining, delete_failures


def collect(
    *,
    origin: str,
    project: str,
    nonce: str,
    send: Callable[..., tuple[int, Any]],
    approval: Any = None,
    request_budget: int | None = None,
    wall_seconds: int | None = None,
    clock: Callable[[], float] = time.monotonic,
    tolerate_failure: bool = False,
) -> dict[str, Any]:
    """Run the frozen matrix against one loopback origin and return a receipt."""
    if approval is not None:
        raise CollectorError("production entry is closed in this preparation package")
    origin = _loopback_origin(origin)
    manifest = campaign_manifest(nonce)
    budget = manifest["budget"]
    run = _Run(
        origin,
        project,
        nonce,
        send,
        request_budget if request_budget is not None else budget["observationRequests"],
        budget["recoveryRequests"],
        wall_seconds if wall_seconds is not None else budget["wallSeconds"],
        budget["recoverySeconds"],
        clock,
    )
    _bind_accounts(run, manifest)
    stages: list[dict[str, Any]] = []
    stop_reason: str | None = None
    failure: BaseException | None = None
    bound_failure: CollectorError | None = None
    for stage in manifest["stages"]:
        try:
            status, body = run.request(
                stage["path"], stage["body"], stage["routeClass"] == "admin"
            )
        except CollectorError as error:
            # A violated bound still recovers before it is reported.
            stop_reason = "bound-exceeded:" + stage["id"]
            bound_failure = error
            break
        except Exception as error:  # noqa: BLE001 -- a stage failure still recovers.
            stop_reason = "stage-failed:" + stage["id"]
            failure = error
            break
        stages.append(_project_stage(run, stage, status, body))
    run.begin_recovery()
    recovery, cleanup_complete, remaining, delete_failures = _recover(run, manifest)
    receipt = {
        "contract": CONTRACT,
        "campaignId": CAMPAIGN_ID,
        "side": "local",
        "nonce": nonce,
        "manifestDigest": manifest_digest(manifest),
        "sourceBinding": {"commit": None, "artifactSha256": None},
        "productionExecuted": False,
        "recordingComplete": stop_reason is None
        and len(stages) == len(manifest["stages"]),
        "stopReason": stop_reason,
        "stages": stages,
        "recovery": recovery,
        "cleanupComplete": cleanup_complete,
        "remainingAccounts": remaining,
        "deleteFailures": delete_failures,
        "requests": run.requests,
        "requestBudget": run.request_budget,
        "recoveryRequests": run.recovery_requests,
        "ownedAccounts": {
            name: {"email": account["email"]} for name, account in run.owned.items()
        },
        "deliveredMessages": 0,
    }
    _assert_no_secret_leaked(receipt, run)
    if bound_failure is not None:
        bound_failure.receipt = receipt
        raise bound_failure
    if failure is not None and not tolerate_failure:
        receipt["failure"] = type(failure).__name__
    return receipt


def _assert_no_secret_leaked(receipt: dict[str, Any], run: _Run) -> None:
    serialized = json.dumps(receipt, sort_keys=True)
    for name, value in run.secrets.items():
        if name.endswith(".email") or name == "unknownEmail":
            continue
        if isinstance(value, str) and len(value) > 3 and value in serialized:
            raise CollectorError("secret value reached the receipt: " + name)
    for field in SECRET_FIELDS:
        # A key position would carry a value; the same name inside a `keys`
        # list is the response shape this campaign exists to compare.
        if '"' + field + '":' in serialized:
            raise CollectorError("secret field name reached the receipt: " + field)


def build_parser() -> argparse.ArgumentParser:
    """The command line carries no code, no password and no credential."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", required=True, help="loopback Auth origin")
    parser.add_argument("--project", required=True)
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A credential-bearing request must never be replayed to a new location."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise CollectorError("a collected request may not be redirected")


def http_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(_NoRedirect)


def _http_send(method: str, url: str, headers: dict[str, str], body: dict[str, Any]):
    request = urllib.request.Request(
        url, data=json.dumps(body).encode(), method=method, headers=headers
    )
    try:
        with http_opener().open(request, timeout=20) as answer:
            return answer.status, json.loads(answer.read() or b"{}")
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read() or b"{}")


if __name__ == "__main__":
    arguments = build_parser().parse_args()
    result = collect(
        origin=arguments.origin,
        project=arguments.project,
        nonce=arguments.nonce,
        send=_http_send,
    )
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(
        json.dumps(
            {
                "recordingComplete": result["recordingComplete"],
                "cleanupComplete": result["cleanupComplete"],
                "requests": result["requests"],
            }
        )
    )
    raise SystemExit(
        0 if result["recordingComplete"] and result["cleanupComplete"] else 2
    )
