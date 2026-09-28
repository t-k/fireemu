"""Record a narrowly scoped Auth lifecycle as sanitized, unapproved observations."""

# ruff: noqa: BLE001 -- Boundaries retain only exception classes, never credentials.

import argparse
import hashlib
import json
import os
import re
import secrets
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

from auth_v2_contract import (
    CASES,
    cleanup_confirmed,
    complete,
    error_code,
    expiry_seconds,
    owned,
    require,
    tokens,
    users,
)

PROJECT = "fireemu-35fe6"
NUMBER = "592603257417"
ROOT = Path(__file__).resolve().parents[2]


def digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def inputs():
    return {
        str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(
            [
                *Path(__file__).parent.glob("*.py"),
                *(ROOT / "tools" / "compat-inventory").glob("*.py"),
            ]
        )
        if not p.name.startswith("test_")
    }


def save(path, value):
    with open(
        path, "x", opener=lambda name, flags: os.open(name, flags, 0o600)
    ) as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def origins(origin):
    if origin is None:
        return (
            "https://identitytoolkit.googleapis.com",
            "https://securetoken.googleapis.com",
        )
    parsed = urllib.parse.urlsplit(origin)
    require(
        parsed.scheme == "http"
        and parsed.hostname in {"127.0.0.1", "::1"}
        and parsed.port
        and not parsed.username
        and not parsed.password
        and not parsed.path
        and not parsed.query
        and not parsed.fragment
    )
    return (
        origin + "/identitytoolkit.googleapis.com",
        origin + "/securetoken.googleapis.com",
    )


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request(url, body=None, token=None, quota=False, form=False):
    headers = {}
    if token:
        headers["Authorization"] = "Bearer " + token
    if quota:
        require(
            url.startswith(
                (
                    "https://identitytoolkit.googleapis.com/",
                    "https://cloudresourcemanager.googleapis.com/",
                )
            )
        )
        headers["X-Goog-User-Project"] = PROJECT
    payload = None
    if body is not None:
        headers["Content-Type"] = (
            "application/x-www-form-urlencoded" if form else "application/json"
        )
        payload = (urllib.parse.urlencode(body) if form else json.dumps(body)).encode()
    req = urllib.request.Request(url, data=payload, headers=headers)
    try:
        response = urllib.request.build_opener(
            NoRedirect(), urllib.request.ProxyHandler({})
        ).open(req, timeout=20)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read(1024 * 1024 + 1)
        require(len(raw) <= 1024 * 1024)
        value = json.loads(raw)
        require(isinstance(value, dict))
        return response.status, value


def command(argv):
    return subprocess.check_output(
        argv, cwd=ROOT, text=True, stderr=subprocess.DEVNULL, timeout=60
    ).strip()


def config_projection(status, config):
    require(
        status == 200
        and isinstance(config, dict)
        and config.get("name") == f"projects/{NUMBER}/config"
        and "error" not in config
    )
    email = config.get("signIn", {}).get("email", {})
    require(email.get("enabled") is True and email.get("passwordRequired") is True)
    require(
        config.get("emailPrivacyConfig", {}).get("enableImprovedEmailPrivacy") is True
    )
    require(not config.get("blockingFunctions", {}).get("triggers"))
    return {
        "sha256": digest(config),
        "emailEnabled": True,
        "passwordRequired": True,
        "improvedEmailPrivacy": True,
        "blockingTriggersAbsent": True,
    }


def production_preflight():
    token = command(["gcloud", "auth", "application-default", "print-access-token"])
    status, project = request(
        f"https://cloudresourcemanager.googleapis.com/v1/projects/{PROJECT}",
        token=token,
        quota=True,
    )
    require(
        status == 200
        and project.get("projectId") == PROJECT
        and str(project.get("projectNumber")) == NUMBER
    )
    config = config_projection(
        *request(
            f"https://identitytoolkit.googleapis.com/admin/v2/projects/{PROJECT}/config",
            token=token,
            quota=True,
        )
    )
    functions = json.loads(
        command(
            [
                "gcloud",
                "functions",
                "list",
                f"--project={PROJECT}",
                "--format=json(name)",
            ]
        )
    )
    require(functions == [])
    names = command(
        [
            "gcloud",
            "services",
            "api-keys",
            "list",
            f"--project={PROJECT}",
            "--format=value(name)",
        ]
    ).splitlines()
    require(
        bool(names)
        and all(
            name.startswith(f"projects/{NUMBER}/locations/global/keys/")
            for name in names
        )
    )
    key = command(
        [
            "gcloud",
            "services",
            "api-keys",
            "get-key-string",
            names[0],
            f"--project={PROJECT}",
            "--format=value(keyString)",
        ]
    )
    require(bool(key))
    return token, key, config


def validate_journal(value):
    require(
        isinstance(value, dict)
        and value.get("project") == PROJECT
        and value.get("creationAttempted") is True
    )
    require(
        isinstance(value.get("email"), str)
        and re.fullmatch(r"fireemu-basic-[0-9a-f]{32}@example\.test", value["email"])
    )
    require(
        isinstance(value.get("marker"), str)
        and re.fullmatch(r"fireemu-owned-[0-9a-f]{48}", value["marker"])
    )


def cleanup_account(admin, email, marker, uid=None):
    def lookup(selector):
        return users(*admin("lookup", selector))

    records = lookup({"email": [email]})
    if records:
        recovered = owned(records, email, marker, uid)
        owned(lookup({"localId": [recovered]}), email, marker, recovered)
        uid = recovered
        try:
            admin("delete", {"localId": uid})
        except Exception:  # noqa: S110 -- Never log a credential-bearing transport error.
            pass  # Absence readback, not a DELETE response, is authoritative.
    email_absent = lookup({"email": [email]}) == []
    uid_absent = uid is not None and lookup({"localId": [uid]}) == []
    require(cleanup_confirmed(uid, uid_absent, email_absent))
    return {"uidAbsent": True, "emailAbsent": True}


def reconcile(journal):
    require(not journal.is_symlink() and journal.stat().st_mode & 0o077 == 0)
    value = json.loads(journal.read_bytes())
    validate_journal(value)
    token, _, _ = production_preflight()

    def admin(action, body):
        return request(
            f"https://identitytoolkit.googleapis.com/v1/projects/{PROJECT}/accounts:{action}",
            body,
            token,
            quota=True,
        )

    # An absent account with unknown UID remains unresolved; never close the journal.
    return cleanup_account(admin, value["email"], value["marker"])


def observe(output, origin=None):
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    identity, secure = origins(origin)
    production = origin is None
    before = inputs()
    report: dict = {
        "schemaVersion": 2,
        "acceptance": "candidate",
        "status": "incomplete",
        "target": "production" if production else "local",
        "recordedAt": datetime.now(UTC).isoformat(),
        "project": PROJECT,
        "projectNumber": NUMBER if production else None,
        "probeInputs": before,
        "probeSourceCommit": command(["git", "rev-parse", "HEAD"]),
        "corpus": {"revision": 2, "cases": list(CASES)},
        "cases": [],
        "limitations": [
            "Sanitized semantic observations, not retained raw responses or independently verified token signatures.",
            "Email/password REST only; excludes SDK, MFA, tenants, OOB, Rules and published npm artifacts.",
            "No approval; aggregation approvals do not apply.",
        ],
    }
    report["corpusSha256"] = digest(report["corpus"])
    email = "fireemu-basic-" + secrets.token_hex(16) + "@example.test"
    marker = "fireemu-owned-" + secrets.token_hex(24)
    password = "A9!" + secrets.token_urlsafe(32)
    uid = None
    attempted = False
    admin_token, key = "owner", "local-test-key"

    def admin(action, body):
        return request(
            f"{identity}/v1/projects/{PROJECT}/accounts:{action}",
            body,
            admin_token,
            quota=production,
        )

    def lookup(selector):
        return users(*admin("lookup", selector))

    def client(action, body):
        return request(
            f"{identity}/v1/accounts:{action}?key={urllib.parse.quote(key, safe='')}",
            body,
        )

    def record(name, status, checks, expiry=None):
        report["cases"].append(
            {
                "id": name,
                "httpStatus": status,
                "checks": checks,
                "passed": all(value is True for value in checks.values()),
            }
        )

        if "expiryIsPositiveInteger" in checks:
            report["cases"][-1]["expirySeconds"] = expiry

    def state(token):
        status, value = client("lookup", {"idToken": token})
        records = users(status, value)
        owned(records, email, marker, uid)
        user = records[0]
        stable = {
            field: user.get(field)
            for field in (
                "localId",
                "email",
                "displayName",
                "emailVerified",
                "disabled",
                "providerUserInfo",
            )
        }
        return status, stable

    try:
        if production:
            admin_token, key, report["configReadback"] = production_preflight()
        require(lookup({"email": [email]}) == [])
        save(
            output / "recovery.json",
            {
                "project": PROJECT,
                "email": email,
                "marker": marker,
                "creationAttempted": True,
            },
        )
        attempted = True
        status, signup = client(
            "signUp",
            {
                "email": email,
                "password": password,
                "displayName": marker,
                "returnSecureToken": True,
            },
        )
        uid = owned(lookup({"email": [email]}), email, marker)
        checks = tokens(signup, uid, email)
        record(
            "signup",
            status,
            {"httpOk": status == 200, **checks},
            expiry_seconds(signup),
        )
        require(
            status == 200
            and all(
                value for key, value in checks.items() if key != "expiryMatchesOneHour"
            )
        )
        status, _ = state(signup["idToken"])
        record("signup-token-lookup", status, {"ownedIdentity": True})
        status, signup_refreshed = request(
            f"{secure}/v1/token?key={urllib.parse.quote(key, safe='')}",
            {"grant_type": "refresh_token", "refresh_token": signup["refreshToken"]},
            form=True,
        )
        checks = tokens(signup_refreshed, uid, email, refresh=True)
        record(
            "signup-token-refresh",
            status,
            {"httpOk": status == 200, **checks},
            expiry_seconds(signup_refreshed, True),
        )
        require(
            status == 200
            and all(
                value for key, value in checks.items() if key != "expiryMatchesOneHour"
            )
        )
        status, _ = state(signup_refreshed["id_token"])
        record("signup-refreshed-lookup", status, {"ownedIdentity": True})
        status, signin = client(
            "signInWithPassword",
            {"email": email, "password": password, "returnSecureToken": True},
        )
        checks = tokens(signin, uid, email)
        record(
            "signin",
            status,
            {"httpOk": status == 200, **checks},
            expiry_seconds(signin),
        )
        require(
            status == 200
            and all(
                value for key, value in checks.items() if key != "expiryMatchesOneHour"
            )
        )
        status, prior = state(signin["idToken"])
        record("lookup", status, {"ownedIdentity": True})
        status, value = client(
            "signInWithPassword",
            {
                "email": email,
                "password": "wrong-" + password,
                "returnSecureToken": True,
            },
        )
        record(
            "wrong-password",
            status,
            {
                "rejected": status == 400,
                "expectedError": error_code(value) == "INVALID_LOGIN_CREDENTIALS",
            },
        )
        status, after = state(signin["idToken"])
        record(
            "unchanged-state", status, {"selectedStableFieldsUnchanged": prior == after}
        )
        status, refreshed = request(
            f"{secure}/v1/token?key={urllib.parse.quote(key, safe='')}",
            {"grant_type": "refresh_token", "refresh_token": signin["refreshToken"]},
            form=True,
        )
        checks = tokens(refreshed, uid, email, refresh=True)
        record(
            "refresh",
            status,
            {"httpOk": status == 200, **checks},
            expiry_seconds(refreshed, True),
        )
        require(
            status == 200
            and all(
                value for key, value in checks.items() if key != "expiryMatchesOneHour"
            )
        )
        status, _ = state(refreshed["id_token"])
        record("refreshed-lookup", status, {"ownedIdentity": True})
        owned(lookup({"localId": [uid]}), email, marker, uid)
        status, value = client("delete", {"idToken": refreshed["id_token"]})
        record(
            "delete", status, {"httpOk": status == 200, "noError": "error" not in value}
        )
        absent = lookup({"localId": [uid]}) == [] and lookup({"email": [email]}) == []
        record("deleted-account-absent", 200, {"bothSelectorsAbsent": absent})
        if production:
            current = config_projection(
                *request(
                    f"{identity}/admin/v2/projects/{PROJECT}/config",
                    token=admin_token,
                    quota=True,
                )
            )
            require(current == report["configReadback"])
            report["configurationUnchanged"] = True
        require(before == inputs())
        report["status"] = (
            "passed" if all(row["passed"] for row in report["cases"]) else "failed"
        )
    except Exception as error:
        report["failure"] = type(error).__name__
    finally:
        if attempted:
            try:
                report["cleanup"] = cleanup_account(admin, email, marker, uid)
            except Exception as error:
                report["cleanupFailure"] = type(error).__name__
        save(output / "observation.json", report)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--recover", type=Path)
    parser.add_argument("--production", action="store_true", required=True)
    args = parser.parse_args()
    if args.recover:
        try:
            print(json.dumps(reconcile(args.recover)))
        except Exception:
            raise SystemExit(
                "Recovery unresolved; retain the private journal"
            ) from None
        raise SystemExit(0)
    if not args.output:
        parser.error("--output or --recover is required")
    result = observe(args.output)
    print(
        json.dumps(
            {
                "status": result["status"],
                "complete": complete(result),
                "caseCount": len(result["cases"]),
                "cleanup": result.get("cleanup"),
                "failure": result.get("failure"),
                "cleanupFailure": result.get("cleanupFailure"),
            }
        )
    )
    raise SystemExit(0 if complete(result) else 2)
