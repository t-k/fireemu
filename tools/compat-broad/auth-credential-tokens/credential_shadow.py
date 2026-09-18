"""Local shadow of the AUTH-CREDENTIAL campaign against a running `fireemu`.

This runs every declared case against a locally owned `fireemu` process and records
what the local runtime actually does. It is local evidence only: it contacts no
production service, and a shadow row is never a production comparison.

The transport refuses any host but the loopback interface, so a mistyped target cannot
leave the machine. Credential material never reaches argv or the record: tokens live in
local variables, and only decoded non-secret claim shapes are written out.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from credential_cases import CAMPAIGN_ID, observation_cases
from credential_collector import (
    build_receipt,
    charge_request,
    claim_shape,
    mark_deleted,
    new_budget,
    new_tracker,
    owned_email,
    track_account,
)

LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "[::1]")
API_KEY = "local-shadow-key"
OWNER = "Bearer owner"
PROJECT = "demo-app"
PASSWORD = "shadow-Passw0rd!"
CUSTOM_TOKEN_AUDIENCE = "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit"
READY_PATTERN = re.compile(r"auth \(REST\):\s+(\S+)")
REQUEST_TIMEOUT_SECONDS = 5


class ShadowError(Exception):
    """The shadow could not carry out a step it needs to record a row."""


# --- transport ---------------------------------------------------------------------


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def unsigned_jwt(payload: dict[str, Any]) -> str:
    """Build the unsigned custom token the local runtime accepts."""
    header = _b64url(
        json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode()
    )
    body = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    return f"{header}.{body}."


def post(
    budget: dict[str, Any],
    base: str,
    path: str,
    body: dict[str, Any],
    *,
    owner: bool = False,
) -> tuple[int, dict[str, Any]]:
    """POST JSON to the owned local daemon and return the status and parsed body."""
    host = base.split("//", 1)[-1].split(":")[0]
    if host not in LOOPBACK_HOSTS:
        raise ShadowError(f"refusing a non-loopback target: {host}")
    request = urllib.request.Request(
        f"{base}{path}",
        data=json.dumps(body).encode(),
        headers={
            "Content-Type": "application/json",
            **({"Authorization": OWNER} if owner else {}),
        },
        method="POST",
    )
    started = time.monotonic()
    try:
        with urllib.request.urlopen(
            request, timeout=REQUEST_TIMEOUT_SECONDS
        ) as response:
            status, raw = response.status, response.read()
    except urllib.error.HTTPError as error:
        status, raw = error.code, error.read()
    finally:
        charge_request(budget, time.monotonic() - started)
    try:
        parsed = json.loads(raw or b"{}")
    except json.JSONDecodeError as error:
        raise ShadowError("response was not JSON") from error
    return status, parsed if isinstance(parsed, dict) else {}


def error_code(body: dict[str, Any]) -> str | None:
    """Extract the Identity Toolkit error code, dropping any trailing detail."""
    message = (
        body.get("error", {}).get("message")
        if isinstance(body.get("error"), dict)
        else None
    )
    return message.split(":")[0].strip() if isinstance(message, str) else None


# --- owned process -----------------------------------------------------------------


def start_daemon(binary: Path, workdir: Path) -> tuple[subprocess.Popen[str], str]:
    """Start an owned strict Auth-only daemon on an OS-assigned port."""
    config = workdir / "fireemu.shadow.json"
    config.write_text(json.dumps({"schemaVersion": 1, "profile": "strict"}))
    process = subprocess.Popen(
        [
            str(binary),
            "up",
            "--config",
            str(config),
            "--project",
            PROJECT,
            "--only",
            "auth",
            "--http-port",
            "0",
            "--hub-port",
            "0",
            "--ui-port",
            "0",
            "--logging-port",
            "0",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        cwd=str(workdir),
    )
    deadline = time.monotonic() + 60
    assert process.stdout is not None
    while time.monotonic() < deadline:
        line = process.stdout.readline()
        if not line:
            break
        found = READY_PATTERN.search(line)
        if found:
            return process, f"http://{found.group(1)}"
    stop_daemon(process)
    raise ShadowError("daemon did not report an auth address")


def stop_daemon(process: subprocess.Popen[str]) -> dict[str, Any]:
    """Stop the owned process and report whether it and its children are gone."""
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=20)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=20)
    children = subprocess.run(
        ["/usr/bin/pgrep", "-P", str(process.pid)],
        capture_output=True,
        text=True,
        check=False,
    )
    return {
        "exitCode": process.returncode,
        "processStopped": process.poll() is not None,
        "remainingChildren": len(children.stdout.split()),
    }


# --- case execution ----------------------------------------------------------------


def _row(
    case_id: str,
    status: int,
    body: dict[str, Any],
    assertions: dict[str, bool],
    **extra: Any,
) -> dict[str, Any]:
    return {
        "caseId": case_id,
        "status": status,
        "errorCode": error_code(body),
        "assertions": assertions,
        "trustRoot": "unsigned-emulator",
        **extra,
    }


def _sleep_to_next_second() -> None:
    time.sleep(1.05 - (time.time() % 1))


def run_cases(
    base: str, budget: dict[str, Any], tracker: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    """Run every declared case and return rows keyed by case id."""
    identity = f"{base}/identitytoolkit.googleapis.com/v1"
    secure = f"{base}/securetoken.googleapis.com/v1/token?key={API_KEY}"
    admin = f"{identity}/projects/{PROJECT}"
    rows: dict[str, dict[str, Any]] = {}

    def signup(index: int) -> dict[str, Any]:
        email = owned_email(tracker, index)
        status, body = post(
            budget,
            identity,
            f"/accounts:signUp?key={API_KEY}",
            {"email": email, "password": PASSWORD, "returnSecureToken": True},
        )
        if status != 200:
            raise ShadowError(f"sign-up failed: {error_code(body)}")
        track_account(tracker, body["localId"], email)
        return body

    def signin(email: str) -> dict[str, Any]:
        status, body = post(
            budget,
            identity,
            f"/accounts:signInWithPassword?key={API_KEY}",
            {"email": email, "password": PASSWORD, "returnSecureToken": True},
        )
        if status != 200:
            raise ShadowError(f"sign-in failed: {error_code(body)}")
        return body

    def lookup(id_token: str) -> tuple[int, dict[str, Any]]:
        return post(
            budget, identity, f"/accounts:lookup?key={API_KEY}", {"idToken": id_token}
        )

    # --- refresh -------------------------------------------------------------
    first = signup(0)
    base_shape = claim_shape(first["idToken"])
    time.sleep(2)
    status, body = post(
        budget,
        secure,
        "",
        {"grant_type": "refresh_token", "refresh_token": first["refreshToken"]},
    )
    refreshed = claim_shape(body["id_token"]) if status == 200 else None
    rows["refresh-preserves-auth-time"] = _row(
        "refresh-preserves-auth-time",
        status,
        body,
        {
            "acceptedResponse": status == 200,
            "idTokenReturned": bool(body.get("id_token")),
            "refreshTokenReturned": bool(body.get("refresh_token")),
            "authTimePreserved": bool(
                refreshed
                and refreshed["times"]["auth_time"] == base_shape["times"]["auth_time"]
            ),
            "iatAdvanced": bool(
                refreshed and refreshed["times"]["iat"] > base_shape["times"]["iat"]
            ),
            "expIsIatPlusHour": bool(
                refreshed
                and refreshed["times"]["exp"] - refreshed["times"]["iat"] == 3600
            ),
        },
    )
    time.sleep(1)
    status, body = post(
        budget,
        secure,
        "",
        {
            "grant_type": "refresh_token",
            "refresh_token": body.get("refresh_token", first["refreshToken"]),
        },
    )
    second = claim_shape(body["id_token"]) if status == 200 else None
    rows["refresh-repeat-preserves-auth-time"] = _row(
        "refresh-repeat-preserves-auth-time",
        status,
        body,
        {
            "acceptedResponse": status == 200,
            "idTokenReturned": bool(body.get("id_token")),
            "refreshTokenReturned": bool(body.get("refresh_token")),
            "authTimePreserved": bool(
                second
                and second["times"]["auth_time"] == base_shape["times"]["auth_time"]
            ),
            "iatAdvanced": bool(
                second
                and refreshed
                and second["times"]["iat"] > refreshed["times"]["iat"]
            ),
        },
    )
    status, body = post(
        budget,
        secure,
        "",
        {
            "grant_type": "refresh_token",
            "refresh_token": "rt1.0.0.demo-app.unissued0000000000000",
        },
    )
    rows["refresh-unknown-token-rejected"] = _row(
        "refresh-unknown-token-rejected", status, body, {}
    )

    # --- revocation ----------------------------------------------------------
    revoked = signup(1)
    revoked_email = owned_email(tracker, 1)
    revoked_shape = claim_shape(revoked["idToken"])
    valid_since = revoked_shape["times"]["auth_time"] + 2
    post(
        budget,
        admin,
        "/accounts:update",
        {"localId": revoked["localId"], "validSince": str(valid_since)},
        owner=True,
    )
    status, body = lookup(revoked["idToken"])
    rows["revocation-older-session-rejected"] = _row(
        "revocation-older-session-rejected", status, body, {}
    )

    # Pin the boundary from server-reported values: sign in, read the token's own
    # auth_time back, set validSince to exactly that whole second and confirm the
    # readback. Without all three the row is not a boundary observation.
    time.sleep(2)
    _sleep_to_next_second()
    boundary = signin(revoked_email)
    boundary_shape = claim_shape(boundary["idToken"])
    boundary_second = boundary_shape["times"]["auth_time"]
    post(
        budget,
        admin,
        "/accounts:update",
        {"localId": revoked["localId"], "validSince": str(boundary_second)},
        owner=True,
    )
    _, read_back = post(
        budget, admin, "/accounts:lookup", {"localId": [revoked["localId"]]}, owner=True
    )
    stored = read_back.get("users", [{}])[0].get("validSince")
    pinned = str(stored) == str(boundary_second)
    status, body = lookup(boundary["idToken"])
    rows["revocation-same-second-session"] = _row(
        "revocation-same-second-session",
        status,
        body,
        {"acceptedResponse": status == 200, "authTimePreserved": pinned},
        boundaryPinned=pinned,
        boundarySeconds={"authTime": boundary_second, "validSince": stored},
    )

    time.sleep(2)
    later = signin(revoked_email)
    status, body = lookup(later["idToken"])
    rows["revocation-newer-session-accepted"] = _row(
        "revocation-newer-session-accepted",
        status,
        body,
        {
            "acceptedResponse": status == 200,
            "idTokenReturned": bool(later.get("idToken")),
        },
    )

    # --- custom token --------------------------------------------------------
    custom_uid = f"custom-{tracker['nonce'][:8]}"
    now = int(time.time())
    custom = unsigned_jwt(
        {
            "aud": CUSTOM_TOKEN_AUDIENCE,
            "iss": "shadow@example.com",
            "sub": "shadow@example.com",
            "uid": custom_uid,
            "claims": {"role": "tester"},
            "iat": now,
            "exp": now + 3600,
        }
    )
    status, body = post(
        budget,
        identity,
        f"/accounts:signInWithCustomToken?key={API_KEY}",
        {"token": custom, "returnSecureToken": True},
    )
    if status != 200:
        raise ShadowError(f"custom-token sign-in failed: {error_code(body)}")
    track_account(tracker, body["localId"], owned_email(tracker, 2))
    custom_session = body
    custom_shape = claim_shape(body["idToken"], reveal=("role",))
    rows["custom-token-developer-claims-present"] = _row(
        "custom-token-developer-claims-present",
        status,
        body,
        {
            "acceptedResponse": status == 200,
            "idTokenReturned": bool(body.get("idToken")),
            "refreshTokenReturned": bool(body.get("refreshToken")),
            "developerClaimPresent": custom_shape["claimValues"].get("role")
            == "tester",
        },
    )
    reserved = unsigned_jwt(
        {
            "aud": CUSTOM_TOKEN_AUDIENCE,
            "iss": "shadow@example.com",
            "sub": "shadow@example.com",
            "uid": custom_uid,
            "claims": {"sub": "elevated"},
            "iat": now,
            "exp": now + 3600,
        }
    )
    status, body = post(
        budget,
        identity,
        f"/accounts:signInWithCustomToken?key={API_KEY}",
        {"token": reserved, "returnSecureToken": True},
    )
    rows["custom-token-reserved-claim-rejected"] = _row(
        "custom-token-reserved-claim-rejected", status, body, {}
    )
    expired = unsigned_jwt(
        {
            "aud": CUSTOM_TOKEN_AUDIENCE,
            "iss": "shadow@example.com",
            "sub": "shadow@example.com",
            "uid": custom_uid,
            "claims": {},
            "iat": now - 7200,
            "exp": now - 3600,
        }
    )
    status, body = post(
        budget,
        identity,
        f"/accounts:signInWithCustomToken?key={API_KEY}",
        {"token": expired, "returnSecureToken": True},
    )
    rows["custom-token-expired-rejected"] = _row(
        "custom-token-expired-rejected", status, body, {}
    )

    # --- session cookies -----------------------------------------------------
    cookie_token = custom_session["idToken"]
    cookie_source = claim_shape(cookie_token, reveal=("role",))
    for case_id, duration in (
        ("session-cookie-default-duration", None),
        ("session-cookie-min-duration-accepted", 300),
        ("session-cookie-below-min-rejected", 299),
        ("session-cookie-max-duration-accepted", 1209600),
        ("session-cookie-above-max-rejected", 1209601),
        ("session-cookie-claim-composition", 3600),
    ):
        payload: dict[str, Any] = {"idToken": cookie_token}
        if duration is not None:
            payload["validDuration"] = str(duration)
        status, body = post(budget, admin, ":createSessionCookie", payload, owner=True)
        cookie = (
            claim_shape(body["sessionCookie"], reveal=("role", "iss"))
            if status == 200 and body.get("sessionCookie")
            else None
        )
        lifetime = cookie["times"]["exp"] - cookie["times"]["iat"] if cookie else None
        rows[case_id] = _row(
            case_id,
            status,
            body,
            {
                "sessionCookieReturned": cookie is not None,
                "cookieLifetimeIsTwoWeeks": lifetime == 1209600,
                "cookieLifetimeMatchesRequest": lifetime == duration,
                "cookieIssuerIsSessionIssuer": bool(
                    cookie
                    and cookie["issuer"]
                    == f"https://session.firebase.google.com/{PROJECT}"
                ),
                "cookieSubjectMatchesIdToken": bool(
                    cookie and "sub" in cookie["claimNames"]
                ),
                "cookieAuthTimePreserved": bool(
                    cookie
                    and cookie["times"].get("auth_time")
                    == cookie_source["times"]["auth_time"]
                ),
                "developerClaimPresent": bool(
                    cookie and cookie["claimValues"].get("role") == "tester"
                ),
            },
        )
        # Only the assertions the case declares are reported.
        declared = set(
            next(c for c in observation_cases() if c["id"] == case_id)["expectedLocal"][
                "assertions"
            ]
        )
        rows[case_id]["assertions"] = {
            k: v for k, v in rows[case_id]["assertions"].items() if k in declared
        }

    status, body = post(
        budget,
        admin,
        ":createSessionCookie",
        {"idToken": revoked["idToken"], "validDuration": "3600"},
        owner=True,
    )
    rows["session-cookie-revoked-id-token-rejected"] = _row(
        "session-cookie-revoked-id-token-rejected", status, body, {}
    )

    # --- claim precedence ----------------------------------------------------
    post(
        budget,
        admin,
        "/accounts:update",
        {
            "localId": custom_session["localId"],
            "customAttributes": json.dumps({"role": "admin", "tier": "gold"}),
        },
        owner=True,
    )
    time.sleep(1)
    status, body = post(
        budget,
        secure,
        "",
        {
            "grant_type": "refresh_token",
            "refresh_token": custom_session["refreshToken"],
        },
    )
    refreshed_custom = (
        claim_shape(body["id_token"], reveal=("role", "tier"))
        if status == 200
        else None
    )
    rows["claim-precedence-session-over-account"] = _row(
        "claim-precedence-session-over-account",
        status,
        body,
        {
            "acceptedResponse": status == 200,
            "sessionClaimWinsOverAccountClaim": bool(
                refreshed_custom
                and refreshed_custom["claimValues"].get("role") == "tester"
            ),
            "accountOnlyClaimPresent": bool(
                refreshed_custom
                and refreshed_custom["claimValues"].get("tier") == "gold"
            ),
            "authTimePreserved": bool(
                refreshed_custom
                and refreshed_custom["times"]["auth_time"]
                == custom_shape["times"]["auth_time"]
            ),
        },
    )
    return rows


def cleanup(base: str, budget: dict[str, Any], tracker: dict[str, Any]) -> None:
    """Delete every owned account and read both its UID and address back as absent."""
    identity = f"{base}/identitytoolkit.googleapis.com/v1"
    admin = f"{identity}/projects/{PROJECT}"
    for uid, account in list(tracker["accounts"].items()):
        post(budget, admin, "/accounts:delete", {"localId": uid}, owner=True)
        _, by_uid = post(
            budget, admin, "/accounts:lookup", {"localId": [uid]}, owner=True
        )
        _, by_email = post(
            budget, admin, "/accounts:lookup", {"email": [account["email"]]}, owner=True
        )
        mark_deleted(
            tracker,
            uid,
            uid_absent=not by_uid.get("users"),
            email_absent=not by_email.get("users"),
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the local AUTH-CREDENTIAL shadow."
    )
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--nonce", default=os.urandom(16).hex())
    args = parser.parse_args(argv)

    tracker = new_tracker(args.nonce)
    budget = new_budget(max_requests=120, max_wall_seconds=600, max_cost_usd=0.0)
    workdir = args.output.parent
    workdir.mkdir(parents=True, exist_ok=True)
    process, base = start_daemon(args.binary, workdir)
    failure = None
    rows: dict[str, dict[str, Any]] = {}
    try:
        rows = run_cases(base, budget, tracker)
    except (ShadowError, KeyError, urllib.error.URLError) as error:
        failure = f"{type(error).__name__}: {error}"
    finally:
        try:
            cleanup(base, budget, tracker)
        except Exception as error:  # noqa: BLE001 - a cleanup failure must be recorded, never raised past here
            failure = failure or f"cleanup: {type(error).__name__}"
        shutdown = stop_daemon(process)

    ordered = [
        rows.get(
            case["id"],
            {
                "caseId": case["id"],
                "status": 0,
                "errorCode": "NOT_RUN",
                "assertions": {},
            },
        )
        for case in observation_cases()
    ]
    receipt = build_receipt(
        side="local",
        rows=ordered,
        tracker=tracker,
        budget=budget,
        source_binding={
            "commit": None,
            "artifactSha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
        },
    )
    record = {
        "campaignId": CAMPAIGN_ID,
        "kind": "local-shadow",
        "productionExecuted": False,
        "failure": failure,
        "shutdown": shutdown,
        "receipt": receipt,
        "expectedLocalAgreement": _agreement(ordered),
    }
    args.output.write_text(json.dumps(record, indent=2, sort_keys=True))
    return (
        0
        if failure is None and record["expectedLocalAgreement"]["unexpected"] == []
        else 1
    )


def _agreement(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Compare each observed row with the case's declared expected local result."""
    unexpected = []
    for case in observation_cases():
        row = next(r for r in rows if r["caseId"] == case["id"])
        expected = case["expectedLocal"]
        problems = []
        if row.get("status") != expected["status"]:
            problems.append(f"status {row.get('status')} != {expected['status']}")
        if expected["errorCode"] and row.get("errorCode") != expected["errorCode"]:
            problems.append(
                f"errorCode {row.get('errorCode')} != {expected['errorCode']}"
            )
        for name in expected["assertions"]:
            if row.get("assertions", {}).get(name) is not True:
                problems.append(f"assertion {name} not held")
        if problems:
            unexpected.append({"caseId": case["id"], "problems": problems})
    return {"cases": len(observation_cases()), "unexpected": unexpected}


if __name__ == "__main__":
    sys.exit(main())
