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
import math
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
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from batch_wire import _read_bounded_response

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
_COMMIT = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
UNBOUND_SOURCE = {
    "commit": None,
    "artifactSha256": None,
    "binding": "unbound",
    "builtFromSourceCommit": None,
}
# How the executed artifact relates to the commit the receipt names. Only
# `built-from-source` can ever carry a compatibility verdict.
BINDING_KINDS = ("unbound", "retained-external", "built-from-source")


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


def _source_binding(value: Any) -> dict[str, Any]:
    """Accept only a fully typed binding; silence about provenance is unbound."""
    if value is None:
        return dict(UNBOUND_SOURCE)
    if not isinstance(value, dict) or value.get("binding") not in BINDING_KINDS:
        raise CollectorError("typed source binding required")
    commit, digest = value.get("commit"), value.get("artifactSha256")
    if value["binding"] == "unbound":
        # Saying nothing about provenance is allowed; claiming half of it is not.
        named = ("commit", "artifactSha256", "builtFromSourceCommit")
        if any(value.get(key) is not None for key in named):
            raise CollectorError("unbound source binding may not name a commit")
        return dict(UNBOUND_SOURCE)
    if not isinstance(commit, str) or not _COMMIT.fullmatch(commit):
        raise CollectorError("source binding needs a commit")
    if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
        raise CollectorError("source binding needs an artifact digest")
    built = value.get("builtFromSourceCommit")
    if value["binding"] == "built-from-source" and built != commit:
        raise CollectorError("source binding claims a build it cannot show")
    if value["binding"] != "built-from-source" and built is not None:
        raise CollectorError("source binding names a build it did not make")
    return {
        "commit": commit,
        "artifactSha256": digest,
        "binding": value["binding"],
        "builtFromSourceCommit": built,
    }


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
        rate_per_second: int,
        sleep: Callable[[float], None],
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
        self.minimum_interval = 1 / rate_per_second if rate_per_second else 0.0
        self.sleep = sleep
        self.last_start: float | None = None
        self.started = clock()
        self.requests = 0
        self.recovery_requests = 0
        # Recovery draws on its own reserve, so an exhausted observation budget
        # can never stop the owned accounts from being deleted.
        self.recovering = False
        self.secrets: dict[str, str] = {}
        self.owned: dict[str, dict[str, Any]] = {}

    def pace(self) -> None:
        """Keep request starts at or under the published rate."""
        if self.last_start is not None and self.minimum_interval:
            waiting = self.last_start + self.minimum_interval - self.clock()
            if waiting > 0:
                self.sleep(waiting)
        self.last_start = self.clock()

    def check_deadline(self) -> None:
        now = self.clock()
        start = self.recovery_started if self.recovering else self.started
        limit = self.recovery_seconds if self.recovering else self.wall_seconds
        if not math.isfinite(now) or now < start or now - start >= limit:
            prefix = "recovery " if self.recovering else ""
            raise CollectorError(prefix + "wall clock budget exhausted")

    def spend(self) -> None:
        self.check_deadline()
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
        self.pace()
        # Rate-limiting is part of the phase, not an extension of its deadline.
        self.check_deadline()
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
    if status != 200 and message is None:
        # An error shape nobody predicted is worth keeping, redacted, because a
        # production run may answer in a form this matrix does not model yet.
        row["unexpectedBody"] = redact(body)
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
        if type(status) is int and status == 200 and isinstance(local_id, str) and local_id:
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
) -> tuple[list[dict[str, Any]], bool, int, int, bool]:
    """Discover owned addresses, delete what they name, then prove absence.

    Ownership is keyed on the address, never on a runtime identifier: a create
    whose response was lost still left a real account behind, and only a lookup
    by address can see it.
    """
    rows: list[dict[str, Any]] = []
    delete_failures = 0
    owned_emails = {
        run.secrets[name + ".email"]: name for name in manifest["ownedAccounts"]
    }

    def address_lookup(
        row: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, str | None] | None]:
        try:
            status, body = run.request(row["path"], row["body"], True)
        except Exception as error:  # noqa: BLE001 -- recovery records, never raises.
            return {
                "id": row["id"],
                "account": None,
                "status": None,
                "failure": type(error).__name__,
            }, None
        def invalid():
            return {
                "id": row["id"], "account": None, "status": status,
                "failure": "invalid-owned-address-lookup",
            }, None

        # Only an explicit typed users[] response proves absence. Never infer
        # absence from {}, a missing users member, null, errors or pagination.
        if type(status) is not int or status != 200 or not isinstance(body, dict):
            return invalid()
        if "error" in body or "nextPageToken" in body:
            return invalid()
        kind = "identitytoolkit#GetAccountInfoResponse"
        if body.get("kind", kind) != kind or not isinstance(body.get("users"), list):
            return invalid()
        users = body["users"]
        if not isinstance(users, list) or len(users) > len(owned_emails):
            return invalid()
        found: dict[str, str] = {}
        identifiers: set[str] = set()
        for user in users:
            if not isinstance(user, dict):
                return invalid()
            email, uid = user.get("email"), user.get("localId")
            if (
                not isinstance(email, str) or email not in owned_emails
                or not isinstance(uid, str) or not uid
                or any(ord(char) < 32 or ord(char) == 127 for char in uid)
                or email in found or uid in identifiers
            ):
                return invalid()
            known = run.secrets.get(owned_emails[email] + ".localId")
            # Discovery can confirm an immutable create UID, but it can never
            # create ownership. An address with no create event is held.
            if known is None or known != uid:
                return invalid()
            found[email] = uid
            identifiers.add(uid)
        return {
            "id": row["id"],
            "account": None,
            "status": status,
            "presentAddresses": len(found),
        }, found

    def uid_absence(
        row: dict[str, Any], name: str, discovery_valid: bool
    ) -> tuple[dict[str, Any], bool]:
        uid = run.secrets.get(name + ".localId")
        if uid is None:
            return {
                "id": row["id"],
                "account": name,
                "status": None,
                "skipped": "no immutable create UID",
                **({"failure": "unowned-identity"} if not discovery_valid else {}),
            }, discovery_valid
        try:
            status, body = run.request(row["path"], row["body"], True)
        except Exception as error:  # noqa: BLE001 -- recovery records, never raises.
            return {
                "id": row["id"],
                "account": name,
                "status": None,
                "failure": type(error).__name__,
            }, False
        valid = (
            type(status) is int
            and status == 200
            and isinstance(body, dict)
            and body.get("kind") == "identitytoolkit#GetAccountInfoResponse"
            and body.get("users") == []
        )
        if not valid:
            return {
                "id": row["id"],
                "account": name,
                "status": status,
                "failure": "uid-still-present-or-invalid-absence",
            }, False
        return {"id": row["id"], "account": name, "status": status, "uidAbsent": True}, True

    by_id = {row["id"]: row for row in manifest["recovery"]}
    discovery, discovered = address_lookup(by_id["recover-discover"])
    rows.append(discovery)
    for email, identifier in (discovered or {}).items():
        name = owned_emails[email]
        # The identifier a lost create response never delivered.
        if name + ".localId" not in run.secrets and isinstance(identifier, str):
            run.secrets[name + ".localId"] = identifier

    present_names = (
        {owned_emails[email] for email in discovered}
        if discovered is not None
        else None
    )
    for name in manifest["ownedAccounts"]:
        row = by_id["recover-delete-" + name]
        if discovered is None:
            # A previously issued UID does not override a failed/currently
            # conflicting discovery. Leave the responsibility open, not deleted.
            rows.append({
                "id": row["id"], "account": name, "status": None,
                "skipped": "owned identity not confirmed by discovery",
                "failure": "unverified-owned-identity",
            })
            continue
        if present_names is not None and name not in present_names:
            # A stage may delete an owned account on purpose. Asking the backend
            # to delete it again only collects a refusal for a run that did
            # everything right, so a proven-absent address is never deleted.
            rows.append(
                {
                    "id": row["id"],
                    "account": name,
                    "status": None,
                    "skipped": "absent at discovery",
                }
            )
            continue
        if name + ".localId" not in run.secrets:
            rows.append(
                {
                    "id": row["id"],
                    "account": name,
                    "status": None,
                    "skipped": "no identifier and no address present",
                }
            )
            continue
        try:
            status, _ = run.request(row["path"], row["body"], True)
        except Exception as error:  # noqa: BLE001 -- recovery records, never raises.
            rows.append(
                {
                    "id": row["id"],
                    "account": name,
                    "status": None,
                    "failure": type(error).__name__,
                }
            )
            delete_failures += 1
            continue
        record = {"id": row["id"], "account": name, "status": status}
        # A delete can be refused because a stage already removed the account;
        # the typed UID and address proofs still decide cleanup.
        record["deleted"] = status == 200
        if status != 200:
            delete_failures += 1
        rows.append(record)

    uid_proofs = []
    for name in manifest["ownedAccounts"]:
        proof, complete = uid_absence(
            by_id["recover-uid-absence-" + name], name, discovered is not None
        )
        rows.append(proof)
        uid_proofs.append(complete)

    absence, still_present = address_lookup(by_id["recover-absence"])
    rows.append(absence)
    proven = still_present is not None
    remaining = len(still_present) if proven else len(owned_emails)
    complete = (
        proven
        and remaining == 0
        and all(uid_proofs)
        and not any("failure" in row for row in rows)
    )
    return rows, complete, remaining, delete_failures, proven


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
    sleep: Callable[[float], None] = time.sleep,
    source_binding: dict[str, Any] | None = None,
    tolerate_failure: bool = False,
) -> dict[str, Any]:
    """Run the frozen matrix against one loopback origin and return a receipt."""
    if approval is not None:
        raise CollectorError("production entry is closed in this preparation package")
    origin = _loopback_origin(origin)
    binding = _source_binding(source_binding)
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
        budget["requestRatePerSecondMax"],
        sleep,
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
            stages.append(_project_stage(run, stage, status, body))
        except CollectorError as error:
            # A violated bound still recovers before it is reported.
            stop_reason = "bound-exceeded:" + stage["id"]
            bound_failure = error
            break
        except Exception as error:  # noqa: BLE001 -- a stage failure still recovers.
            stop_reason = "stage-failed:" + stage["id"]
            failure = error
            break
    run.begin_recovery()
    recovery, cleanup_complete, remaining, delete_failures, proven = _recover(
        run, manifest
    )
    receipt = {
        "contract": CONTRACT,
        "campaignId": CAMPAIGN_ID,
        "side": "local",
        "nonce": nonce,
        "manifestDigest": manifest_digest(manifest),
        "sourceBinding": binding,
        "productionExecuted": False,
        "recordingComplete": stop_reason is None
        and len(stages) == len(manifest["stages"]),
        "stopReason": stop_reason,
        "stages": stages,
        "recovery": recovery,
        "cleanupComplete": cleanup_complete,
        "remainingAccounts": remaining,
        "deleteFailures": delete_failures,
        "absenceProven": proven,
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
    # A secret-named key may only hold the redaction marker. The same name
    # inside a `keys` list is the response shape this campaign compares.
    for field in _secret_slots(receipt):
        raise CollectorError("secret field name reached the receipt: " + field)


def _secret_slots(value: Any, path: str = "$"):
    if isinstance(value, dict):
        for key, item in value.items():
            here = path + "." + key
            if key in SECRET_FIELDS and item != REDACTED:
                yield here
            else:
                yield from _secret_slots(item, here)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _secret_slots(item, f"{path}[{index}]")


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
    return urllib.request.build_opener(_NoRedirect(), urllib.request.ProxyHandler({}))


def _http_send(method: str, url: str, headers: dict[str, str], body: dict[str, Any]):
    parsed = urllib.parse.urlsplit(url)
    _loopback_origin(f"{parsed.scheme}://{parsed.netloc}")
    if parsed.fragment:
        raise CollectorError("request fragment is forbidden")
    payload = json.dumps(body, allow_nan=False).encode()
    if len(payload) > 65536:
        raise CollectorError("local request body exceeds its bound")
    request = urllib.request.Request(url, data=payload, method=method, headers=headers)
    try:
        try:
            answer = http_opener().open(request, timeout=20)
        except urllib.error.HTTPError as error:
            answer = error
        with answer:
            raw, failure = _read_bounded_response(answer, method)
            if failure is not None or 300 <= answer.status < 400:
                raise CollectorError("incomplete or redirected local response")
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise CollectorError("object response required")
            return answer.status, value
    except (ValueError, OSError, urllib.error.URLError) as error:
        raise CollectorError("local transport failed: " + type(error).__name__) from None


def run_cli(arguments: argparse.Namespace) -> dict[str, Any]:
    """Always leave a receipt behind, including when a bound was violated."""
    try:
        result = collect(
            origin=arguments.origin,
            project=arguments.project,
            nonce=arguments.nonce,
            send=_http_send,
        )
    except CollectorError as error:
        result = getattr(error, "receipt", None)
        if result is None:
            result = {"collectorError": str(error), "recordingComplete": False}
        result = {**result, "boundViolation": str(error)}
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


if __name__ == "__main__":
    arguments = build_parser().parse_args()
    result = run_cli(arguments)
    print(
        json.dumps(
            {
                "recordingComplete": result.get("recordingComplete"),
                "cleanupComplete": result.get("cleanupComplete"),
                "requests": result.get("requests"),
                "boundViolation": result.get("boundViolation"),
            }
        )
    )
    raise SystemExit(
        0 if result.get("recordingComplete") and result.get("cleanupComplete") else 2
    )
