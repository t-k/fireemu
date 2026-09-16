"""Record a narrowly scoped Auth lifecycle as sanitized, unapproved observations."""

# ruff: noqa: BLE001 -- Boundaries retain only exception classes, never credentials.

import argparse
import hashlib
import json
import os
import re
import secrets
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType

from session_contract import (
    CORPUS,
    LANES,
    OFFSETS,
    cleanup_confirmed,
    complete,
    kind_for,
    may_start,
    owned,
    require,
    response,
    sample_quality,
    unavailable,
    users,
)

PROJECT = "fireemu-35fe6"
NUMBER = "592603257417"
ROOT = Path(__file__).resolve().parents[2]
PASSWORD_POLICY = {
    "customStrengthOptions": {"minPasswordLength": 6, "maxPasswordLength": 4096},
    "schemaVersion": 1,
    "enforcementState": "ENFORCE",
}


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


def password_policy(status, value, passwords):
    """Support only this explicit policy; missing admin config never means OFF."""
    require(status == 200 and digest(value) == digest(PASSWORD_POLICY))
    require(len(passwords) == 2 and passwords[0] != passwords[1])
    require(
        all(
            isinstance(p, str) and re.fullmatch(r"Aa9![A-Za-z0-9_-]{43}", p)
            for p in passwords
        )
    )
    return PASSWORD_POLICY.copy()


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


def request(
    url, body=None, token=None, quota=False, form=False, timeout=20
) -> tuple[int, dict]:
    started = time.monotonic()
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
        ).open(req, timeout=timeout)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        chunks = []
        size = 0
        while True:
            if time.monotonic() - started >= timeout:
                raise TimeoutError("Auth request budget exceeded")
            chunk = response.read1(min(65536, 1024 * 1024 + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            require(size <= 1024 * 1024)
        if time.monotonic() - started > timeout:
            raise TimeoutError("Auth request budget exceeded")
        raw = b"".join(chunks)
        value = json.loads(raw)
        require(isinstance(value, dict))
        status = response.status
        if type(status) is not int or not 100 <= status <= 599:
            raise ValueError("Auth observation contract failed")
        return status, value


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
        "adminPasswordPolicyAbsent": "passwordPolicyConfig" not in config,
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


def cleanup_account(admin, email, marker, uid=None, journal=None):
    def lookup(selector):
        return users(*admin("lookup", selector))

    records = lookup({"email": [email]})
    if records:
        recovered = owned(records, email, marker, uid)
        owned(lookup({"localId": [recovered]}), email, marker, recovered)
        uid = recovered
        require(journal is not None)
        persist_cleanup_identity(journal, email, marker, uid)
        try:
            admin("delete", {"localId": uid})
        except Exception:  # noqa: S110 -- Never log a credential-bearing transport error.
            pass  # Absence readback, not a DELETE response, is authoritative.
    email_absent = lookup({"email": [email]}) == []
    uid_absent = uid is not None and lookup({"localId": [uid]}) == []
    require(cleanup_confirmed(uid, uid_absent, email_absent))
    return {"uidAbsent": True, "emailAbsent": True}


def recovery_identity(journal):
    require(
        journal.is_file()
        and not journal.is_symlink()
        and journal.stat().st_mode & 0o077 == 0
    )
    value = json.loads(journal.read_bytes())
    validate_journal(value)
    verified = journal.parent / "verified-account.json"
    if not verified.exists():
        require(not verified.is_symlink())
        return value, None
    require(
        verified.is_file()
        and not verified.is_symlink()
        and verified.stat().st_mode & 0o077 == 0
    )
    identity = json.loads(verified.read_bytes())
    require(isinstance(identity, dict) and set(identity) == set(value) | {"uid"})
    require(all(identity[key] == item for key, item in value.items()))
    uid = identity["uid"]
    require(isinstance(uid, str) and bool(uid) and len(uid) <= 128)
    return value, uid


def persist_cleanup_identity(journal, email, marker, uid):
    value, saved_uid = recovery_identity(journal)
    require(value["email"] == email and value["marker"] == marker)
    require(isinstance(uid, str) and bool(uid) and len(uid) <= 128)
    if saved_uid is None:
        save(journal.parent / "verified-account.json", {**value, "uid": uid})
    _, saved_uid = recovery_identity(journal)
    require(saved_uid == uid)


def reconcile(journal):
    value, uid = recovery_identity(journal)
    token, _, _ = production_preflight()

    def admin(action, body):
        return request(
            f"https://identitytoolkit.googleapis.com/v1/projects/{PROJECT}/accounts:{action}",
            body,
            token,
            quota=True,
        )

    # Persist a recovered identity before deletion, including interrupted signups.
    if uid is None:
        records = users(*admin("lookup", {"email": [value["email"]]}))
        uid = owned(records, value["email"], value["marker"])
        owned(
            users(*admin("lookup", {"localId": [uid]})),
            value["email"],
            value["marker"],
            uid,
        )
        save(journal.parent / "verified-account.json", {**value, "uid": uid})
    # An absent account with unknown UID remains unresolved; never close the journal.
    return cleanup_account(admin, value["email"], value["marker"], uid, journal)


def observe(output, origin=None):
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    identity, secure = origins(origin)
    production = origin is None
    before = inputs()
    begun = time.monotonic()
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
        "corpus": CORPUS,
        "corpusSha256": digest(CORPUS),
        "cases": [],
    }
    email = "fireemu-basic-" + secrets.token_hex(16) + "@example.test"
    marker = "fireemu-owned-" + secrets.token_hex(24)
    password, replacement = ("Aa9!" + secrets.token_urlsafe(32) for _ in range(2))
    uid = None
    attempted = False
    admin_token, key = "owner", "local-test-key"

    def elapsed(origin):
        return max(0, int((time.monotonic() - origin) * 1000))

    def admin(action, body):
        return request(
            f"{identity}/v1/projects/{PROJECT}/accounts:{action}",
            body,
            admin_token,
            quota=production,
        )

    def lookup(selector):
        return users(*admin("lookup", selector))

    def client(action, body) -> tuple[int, dict]:
        return request(
            f"{identity}/v1/accounts:{action}?key={urllib.parse.quote(key, safe='')}",
            body,
            timeout=5,
        )

    def exchange(token):
        return request(
            f"{secure}/v1/token?key={urllib.parse.quote(key, safe='')}",
            {"grant_type": "refresh_token", "refresh_token": token},
            form=True,
            timeout=5,
        )

    def inspect_call(
        name, operation, origin_time, frozen_refresh=None, scheduled=False
    ):
        kind = kind_for(name)
        start = elapsed(origin_time)
        raw = {}
        if operation is None or (scheduled and not may_start(start)):
            projected = unavailable(kind, "not-sampled")
        else:
            try:
                status, raw = operation()
                projected = response(status, raw, kind, uid, email)
            except Exception:
                projected = unavailable(kind, "transport-failure")
                raw = {}
        primary_end = elapsed(origin_time)
        row = {
            "id": name,
            "response": projected,
            "followup": None,
            "rotated": None,
            "startMs": start,
            "primaryEndMs": primary_end,
            "endMs": primary_end,
            "followupStartMs": None,
            "followupEndMs": None,
            "credentialUnchanged": True,
            "quality": "inconclusive",
        }
        if kind == "refresh" and projected["outcome"] == "accepted":
            require(isinstance(frozen_refresh, str))
            row["rotated"] = raw["refresh_token"] != frozen_refresh
            follow_start = elapsed(origin_time)
            if scheduled and not may_start(follow_start):
                follow = unavailable("lookup", "not-sampled")
            else:
                try:
                    follow = response(
                        *client("lookup", {"idToken": raw["id_token"]}),
                        "lookup",
                        uid,
                        email,
                    )
                except Exception:
                    follow = unavailable("lookup", "transport-failure")
            follow_end = elapsed(origin_time)
            row.update(
                followup=follow,
                followupStartMs=follow_start,
                followupEndMs=follow_end,
                endMs=follow_end,
            )
        if scheduled:
            lane, target = name.split("@")
            row["quality"] = sample_quality(
                projected,
                row["followup"],
                row["startMs"],
                row["endMs"],
                int(target),
                lane,
            )
        else:
            row["quality"] = (
                "observed"
                if projected["outcome"] == "accepted"
                and (
                    kind != "refresh"
                    or (
                        row["followup"] is not None
                        and row["followup"]["outcome"] == "accepted"
                    )
                )
                else "inconclusive"
            )
        return row, raw

    def baseline(name, operation, frozen_refresh=None):
        row, raw = inspect_call(name, operation, begun, frozen_refresh)
        report["cases"].append(row)
        require(row["quality"] == "observed")
        return raw

    try:
        if production:
            admin_token, key, report["configReadback"] = production_preflight()
            require(report["configReadback"]["adminPasswordPolicyAbsent"] is True)
            report["configReadback"]["passwordPolicy"] = password_policy(
                *request(
                    f"{identity}/v2/passwordPolicy?key={urllib.parse.quote(key, safe='')}"
                ),
                (password, replacement),
            )
        else:
            password_policy(200, PASSWORD_POLICY, (password, replacement))
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
        # Signup is the only operation before an independently known UID.
        signup_start = elapsed(begun)
        status, signup = client(
            "signUp",
            {
                "email": email,
                "password": password,
                "displayName": marker,
                "returnSecureToken": True,
            },
        )
        signup_end = elapsed(begun)
        uid = owned(lookup({"email": [email]}), email, marker)
        owned(lookup({"localId": [uid]}), email, marker, uid)
        persist_cleanup_identity(output / "recovery.json", email, marker, uid)
        signup_row = {
            "id": "signup",
            "response": response(status, signup, "token", uid, email),
            "followup": None,
            "rotated": None,
            "startMs": signup_start,
            "primaryEndMs": signup_end,
            "endMs": signup_end,
            "followupStartMs": None,
            "followupEndMs": None,
            "credentialUnchanged": True,
            "quality": "observed",
        }
        require(signup_row["response"]["outcome"] == "accepted")
        report["cases"].append(signup_row)
        a = baseline(
            "signin-a",
            lambda: client(
                "signInWithPassword",
                {"email": email, "password": password, "returnSecureToken": True},
            ),
        )
        time.sleep(2.05)
        b = baseline(
            "signin-b",
            lambda: client(
                "signInWithPassword",
                {"email": email, "password": password, "returnSecureToken": True},
            ),
        )
        require(a["refreshToken"] != b["refreshToken"])
        frozen = MappingProxyType(
            {
                "a-id": a["idToken"],
                "a-refresh": a["refreshToken"],
                "b-id": b["idToken"],
                "b-refresh": b["refreshToken"],
            }
        )
        snapshot = tuple(frozen.items())
        for session in ("a", "b"):
            baseline(
                session + "-id-baseline",
                lambda session=session: client(
                    "lookup", {"idToken": frozen[session + "-id"]}
                ),
            )
            for repeat in (1, 2):
                token = frozen[session + "-refresh"]
                baseline(
                    f"{session}-refresh-baseline-{repeat}",
                    lambda token=token: exchange(token),
                    token,
                )
        latest = max(
            row["response"]["tokenTime"]["iat"]
            for row in report["cases"]
            if row["response"].get("tokenTime") is not None
        )
        time.sleep(3.05)
        changed = baseline(
            "change-password",
            lambda: client(
                "update",
                {
                    "idToken": frozen["a-id"],
                    "password": replacement,
                    "returnSecureToken": True,
                },
            ),
        )
        # Origin is receipt completion; mutation start/end are retained separately.
        sampling_origin = time.monotonic()
        mutation_end = elapsed(begun)
        mutation_start = report["cases"][-1]["startMs"]
        changed_time = report["cases"][-1]["response"]["tokenTime"]
        report["timing"] = {
            "sessionsSeparated": True,
            "issueGapMs": report["cases"][2]["startMs"]
            - report["cases"][1]["primaryEndMs"],
            "preChangeWaitMs": mutation_start - report["cases"][8]["endMs"],
            "mutationStartMs": mutation_start,
            "mutationEndMs": mutation_end,
            "latestPreIssuedAt": latest,
            "changedIssuedAt": changed_time["iat"],
            "orderEstablished": changed_time["iat"] > latest,
        }
        require(report["timing"]["orderEstablished"])
        credentials = MappingProxyType(
            {
                **frozen,
                "changed-id": changed["idToken"],
                "changed-refresh": changed["refreshToken"],
            }
        )
        credential_snapshot = tuple(credentials.items())

        def sample(lane, target):
            token = credentials[lane]
            operation = (
                (lambda: exchange(token))
                if lane.endswith("refresh")
                else (lambda: client("lookup", {"idToken": token}))
            )
            row, _ = inspect_call(
                f"{lane}@{target}",
                operation,
                sampling_origin,
                token if lane.endswith("refresh") else None,
                scheduled=True,
            )
            row["credentialUnchanged"] = (
                tuple(credentials.items()) == credential_snapshot
                and tuple(frozen.items()) == snapshot
                and credentials[lane] == token
            )
            return row

        # Each worker reads immutable credentials; all workers drain before destructive cleanup.
        with ThreadPoolExecutor(max_workers=len(LANES)) as pool:
            for target in OFFSETS:
                remaining = target / 1000 - (time.monotonic() - sampling_origin)
                if remaining > 0:
                    time.sleep(remaining)
                futures = [pool.submit(sample, lane, target) for lane in LANES]
                report["cases"].extend(future.result() for future in futures)
        # Fresh-password signin is outside the observation window to avoid changing its controls.
        row, signin = inspect_call(
            "new-password-signin",
            lambda: client(
                "signInWithPassword",
                {"email": email, "password": replacement, "returnSecureToken": True},
            ),
            begun,
        )
        report["cases"].append(row)
        end_token = (
            signin.get("idToken")
            if row["response"]["outcome"] == "accepted"
            else changed["idToken"]
        )
        row, _ = inspect_call(
            "new-password-lookup",
            (lambda: client("lookup", {"idToken": signin["idToken"]}))
            if row["response"]["outcome"] == "accepted"
            else None,
            begun,
        )
        report["cases"].append(row)
        owned(lookup({"localId": [uid]}), email, marker, uid)
        row, _ = inspect_call(
            "delete", lambda: client("delete", {"idToken": end_token}), begun
        )
        report["cases"].append(row)
        # Check both selectors even if the first reports an account.
        uid_absent = lookup({"localId": [uid]}) == []
        email_absent = lookup({"email": [email]}) == []
        row, _ = inspect_call(
            "deleted-account-absent",
            lambda: (200, {"uidAbsent": uid_absent, "emailAbsent": email_absent}),
            begun,
        )
        report["cases"].append(row)
        if production:
            current = config_projection(
                *request(
                    f"{identity}/admin/v2/projects/{PROJECT}/config",
                    token=admin_token,
                    quota=True,
                )
            )
            require(current["adminPasswordPolicyAbsent"] is True)
            current["passwordPolicy"] = password_policy(
                *request(
                    f"{identity}/v2/passwordPolicy?key={urllib.parse.quote(key, safe='')}"
                ),
                (password, replacement),
            )
            require(current == report["configReadback"])
            report["configurationUnchanged"] = True
        require(before == inputs())
        report["status"] = (
            "observed"
            if all(row["quality"] == "observed" for row in report["cases"])
            else "inconclusive"
        )
    except Exception as error:
        report["failure"] = type(error).__name__
    finally:
        if attempted:
            try:
                report["cleanup"] = cleanup_account(
                    admin, email, marker, uid, output / "recovery.json"
                )
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
