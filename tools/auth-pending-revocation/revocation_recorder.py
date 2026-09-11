"""Hold an MFA pending credential across an explicit revocation, observe, and clean up.

Production needs phone MFA and test phone numbers, which the oracle project does not
have. The recorder enables them for the run and restores the recorded configuration in
`finally`; the restore readback is part of the report. Tokens, codes and passwords stay
in memory and are never written.
"""

# ruff: noqa: BLE001 -- Never expose raw exceptions or credentials.
import argparse
import base64
import hashlib
import json
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

from revocation_contract import (
    CORPUS,
    DIAGNOSTIC,
    TEST_CODE,
    TEST_PHONES,
    complete,
    error_code,
    require,
    validate_row,
)

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/auth-password-maximum"))
import maximum_recorder as core
from maximum_contract import owned, tokens, users

PROJECT, NUMBER = core.PROJECT, core.NUMBER
digest, save = core.digest, core.save
CONFIG_URL = (
    f"https://identitytoolkit.googleapis.com/admin/v2/projects/{PROJECT}/config"
)
MFA_ON = {"state": "ENABLED", "enabledProviders": ["PHONE_SMS"]}
MFA_OFF = {"state": "DISABLED"}
# The oracle blocks SMS in every region; test numbers still pass the region check. The run
# switches to the allow-by-default policy (every region allowed, none disallowed; an
# allowlist of only "US" was tried first and refused, possibly for propagation lag) and
# restores whatever was read. Narrowing to the needed region is a candidate improvement.
SMS_REGIONS_ON = {"allowByDefault": {"disallowedRegions": []}}
CONFIG_MASK = "mfa,signIn.phoneNumber,smsRegionConfig"
# Diagnostic codes for an aborted run: raw error text is never retained.
ERROR_DETAILS = {
    "SMS unable to be sent until this region enabled": "SMS_REGION_NOT_ENABLED",
}


def note(report, step, status, response):
    """Sanitized diagnostics for an aborted run: step, status and classified error."""
    report["lastStep"] = step
    report["lastStatus"] = status
    report["lastError"] = None if status == 200 else error_code(response)
    message = (
        (response.get("error") or {}).get("message")
        if status != 200 and isinstance(response, dict)
        else None
    )
    report["lastErrorDetail"] = next(
        (
            code
            for text, code in ERROR_DETAILS.items()
            if isinstance(message, str) and text in message
        ),
        None,
    )


def restore_body(original):
    """The configuration to write back: exactly what was read, in PATCH shape."""
    phone = original["phoneNumber"] or {"enabled": False, "testPhoneNumbers": {}}
    return {
        "mfa": original["mfa"],
        "signIn": {"phoneNumber": phone},
        "smsRegionConfig": original["smsRegionConfig"],
    }


def restored(raw, original):
    """The readback after the restore: phone sign-in off with no test numbers (a null
    original reads back as an empty object), and the other two fields exactly as read."""
    phone = raw.get("signIn", {}).get("phoneNumber") or {}
    return (
        raw.get("mfa") == original["mfa"]
        and not phone.get("enabled")
        and not phone.get("testPhoneNumbers")
        and raw.get("smsRegionConfig") == original["smsRegionConfig"]
    )


def restore_configuration(access, original):
    status, response = patch(
        f"{CONFIG_URL}?updateMask={CONFIG_MASK}", restore_body(original), access
    )
    require(status == 200 and "error" not in response)
    status, raw = core.request(CONFIG_URL, token=access, quota=True)
    require(status == 200 and restored(raw, original))
    return status, raw


def patch(url, body, token):
    """A quota-attributed PATCH; the shared request helper only speaks GET and POST."""
    require(url.startswith(CONFIG_URL))
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
            "X-Goog-User-Project": PROJECT,
        },
        method="PATCH",
    )
    try:
        response = urllib.request.build_opener(
            core.NoRedirect(), urllib.request.ProxyHandler({})
        ).open(req, timeout=20)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read(1024 * 1024 + 1)
        require(len(raw) <= 1024 * 1024)
        value = json.loads(raw)
        require(isinstance(value, dict) and type(response.status) is int)
        return response.status, value


def inputs():
    return {
        **core.inputs(),
        **{
            str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(Path(__file__).parent.glob("*.py"))
            if not p.name.startswith("test_")
        },
    }


def claims(id_token):
    """Unverified payload of a JWT: only used to compare its own timestamps."""
    require(isinstance(id_token, str) and id_token.count(".") == 2)
    payload = id_token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    value = json.loads(base64.urlsafe_b64decode(payload))
    require(isinstance(value, dict))
    return value


def phone_config(enabled):
    return {
        "enabled": enabled,
        "testPhoneNumbers": {n: TEST_CODE for n in TEST_PHONES.values()}
        if enabled
        else {},
    }


def observe(output):
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    identity = "https://identitytoolkit.googleapis.com"
    secure = "https://securetoken.googleapis.com"
    before = inputs()
    report: dict = {
        "schemaVersion": 1,
        "acceptance": "candidate",
        "status": "incomplete",
        "target": "production",
        "recordedAt": datetime.now(UTC).isoformat(),
        "project": PROJECT,
        "projectNumber": NUMBER,
        "probeInputs": before,
        "probeSourceCommit": core.command(["git", "rev-parse", "HEAD"]),
        "corpus": CORPUS,
        "cases": [],
        "setup": {},
        "revocation": {},
        "cleanup": {},
    }
    accounts = {}
    admin = None
    access = None
    original = None
    change_attempted = False
    try:
        access, key, report["configReadback"] = core.production_preflight()
        query = f"?key={urllib.parse.quote(key, safe='')}"

        def config(patch_body=None, mask=None):
            if patch_body is None:
                return core.request(CONFIG_URL, token=access, quota=True)
            return patch(
                f"{CONFIG_URL}?updateMask={urllib.parse.quote(mask, safe=',')}",
                patch_body,
                access,
            )

        status, raw = config()
        require(status == 200 and "error" not in raw)
        read = {
            "mfa": raw.get("mfa"),
            "phoneNumber": raw.get("signIn", {}).get("phoneNumber"),
            "smsRegionConfig": raw.get("smsRegionConfig"),
        }
        # Preconditions come first: an unexpected configuration aborts the run before
        # anything is written, and nothing is restored either.
        require(read["mfa"] == MFA_OFF and not read["phoneNumber"])
        require(read["smsRegionConfig"] == {"allowlistOnly": {}})
        original = read
        # The recovery record and the flag precede the attempt, so a change that reached
        # the server without a readable response is still restored.
        save(
            output / "config-recovery.json",
            {"project": PROJECT, "original": original, "changeAttempted": True},
        )
        change_attempted = True
        status, patched = config(
            {
                "mfa": MFA_ON,
                "signIn": {"phoneNumber": phone_config(True)},
                "smsRegionConfig": SMS_REGIONS_ON,
            },
            CONFIG_MASK,
        )
        require(status == 200 and "error" not in patched)
        status, raw = config()
        require(status == 200 and raw.get("mfa") == MFA_ON)
        require(raw.get("signIn", {}).get("phoneNumber") == phone_config(True))
        require("allowByDefault" in raw.get("smsRegionConfig", {}))
        report["configEnabled"] = True
        # Configuration enforcement may lag the readback.
        time.sleep(30)

        def admin(action, body):
            require(action in {"lookup", "update", "delete"})
            return core.request(
                f"{identity}/v1/projects/{PROJECT}/accounts:{action}",
                body,
                access,
                quota=True,
            )

        def client(action, body):
            require(action in {"signUp", "signInWithPassword", "lookup"})
            return core.request(f"{identity}/v1/accounts:{action}{query}", body)

        def mfa(action, body):
            require(action in {"mfaSignIn:start", "mfaSignIn:finalize"})
            status, response = core.request(
                f"{identity}/v2/accounts/{action}{query}", body
            )
            note(report, action, status, response)
            return status, response

        def refresh(token):
            return core.request(
                f"{secure}/v1/token{query}",
                {"grant_type": "refresh_token", "refresh_token": token},
                form=True,
            )

        def lookup(account):
            records = users(*admin("lookup", {"localId": [account["uid"]]}))
            owned(records, account["email"], account["marker"], account["uid"])
            return records[0]

        def derived_lookup(account, id_token):
            records = users(*client("lookup", {"idToken": id_token}))
            owned(records, account["email"], account["marker"], account["uid"])
            return True

        def pending(account):
            status, response = client(
                "signInWithPassword",
                {
                    "email": account["email"],
                    "password": account["password"],
                    "returnSecureToken": True,
                },
            )
            note(report, "signInWithPassword", status, response)
            require(status == 200 and "error" not in response)
            report["lastPendingShape"] = sorted(
                k for k in response if k not in {"idToken", "refreshToken"}
            )
            require("idToken" not in response and "refreshToken" not in response)
            credential = response.get("mfaPendingCredential")
            info = response.get("mfaInfo")
            require(isinstance(credential, str) and bool(credential))
            require(isinstance(info, list) and len(info) == 1)
            require(info[0].get("mfaEnrollmentId") == account["enrollmentId"])
            return credential

        def start(account, credential):
            return mfa(
                "mfaSignIn:start",
                {
                    "mfaPendingCredential": credential,
                    "mfaEnrollmentId": account["enrollmentId"],
                    "phoneSignInInfo": {
                        "phoneNumber": account["phone"],
                        "recaptchaToken": "fireemu-test-phone-number",
                    },
                },
            )

        def finalize(credential, session_info):
            return mfa(
                "mfaSignIn:finalize",
                {
                    "mfaPendingCredential": credential,
                    "phoneVerificationInfo": {
                        "sessionInfo": session_info,
                        "code": TEST_CODE,
                    },
                },
            )

        rows_started = time.monotonic()

        def row(name, status, response, checks=None):
            elapsed = int((time.monotonic() - rows_started) * 1000)
            result = {
                "id": name,
                "httpStatus": status,
                "outcome": "accepted" if status == 200 else "refused",
                "observedError": None if status == 200 else error_code(response),
                "checks": checks if status == 200 else {},
                "elapsedMs": elapsed,
                "skipped": False,
            }
            validate_row(result, name)
            report["cases"].append(result)
            return result

        def skipped(name):
            result = {
                "id": name,
                "httpStatus": None,
                "outcome": "skipped",
                "observedError": None,
                "checks": {},
                "elapsedMs": int((time.monotonic() - rows_started) * 1000),
                "skipped": True,
            }
            validate_row(result, name)
            report["cases"].append(result)

        def token_checks(account, response, diagnostic=None):
            checks = {
                "noError": "error" not in response,
                "idTokenPresent": isinstance(response.get("idToken"), str)
                and bool(response["idToken"]),
                "refreshTokenPresent": isinstance(response.get("refreshToken"), str)
                and bool(response["refreshToken"]),
            }
            require(all(v is True for v in checks.values()))
            payload = claims(response["idToken"])
            checks["claimSubMatches"] = payload.get("sub") == account["uid"]
            checks["claimEmailMatches"] = payload.get("email") == account["email"]
            checks["secondFactorClaim"] = (
                payload.get("firebase", {}).get("sign_in_second_factor") == "phone"
            )
            checks["derivedLookup"] = derived_lookup(account, response["idToken"])
            if diagnostic is not None:
                checks["authTimeAtOrAfterValidSince"] = (
                    type(payload.get("auth_time")) is int
                    and payload["auth_time"] >= diagnostic
                )
                report["heldFinalizeTimes"] = {
                    "authTime": payload.get("auth_time"),
                    "iat": payload.get("iat"),
                    "validSince": diagnostic,
                }
            return checks

        def fresh_finalize(name, account):
            credential = pending(account)
            status, started = start(account, credential)
            require(status == 200 and "error" not in started)
            session = started.get("phoneResponseInfo", {}).get("sessionInfo")
            require(isinstance(session, str) and bool(session))
            status, signed = finalize(credential, session)
            require(status == 200)
            row(name, status, signed, token_checks(account, signed))

        for label in ("a", "b"):
            directory = output / label
            directory.mkdir(mode=0o700)
            account = {
                "email": "fireemu-basic-" + secrets.token_hex(16) + "@example.test",
                "marker": "fireemu-owned-" + secrets.token_hex(24),
                "password": "Aa9!" + secrets.token_urlsafe(32),
                "phone": TEST_PHONES[label],
                "uid": None,
                "journal": directory / "recovery.json",
            }
            require(users(*admin("lookup", {"email": [account["email"]]})) == [])
            require(users(*admin("lookup", {"phoneNumber": [account["phone"]]})) == [])
            save(
                account["journal"],
                {
                    "project": PROJECT,
                    "email": account["email"],
                    "marker": account["marker"],
                    "creationAttempted": True,
                },
            )
            accounts[label] = account
            status, signed = client(
                "signUp",
                {
                    "email": account["email"],
                    "password": account["password"],
                    "displayName": account["marker"],
                    "returnSecureToken": True,
                },
            )
            require(status == 200)
            account["uid"] = owned(
                users(*admin("lookup", {"email": [account["email"]]})),
                account["email"],
                account["marker"],
            )
            save(
                directory / "verified-account.json",
                {**json.loads(account["journal"].read_bytes()), "uid": account["uid"]},
            )
            require(core.recovery_identity(account["journal"])[1] == account["uid"])
            status, updated = admin(
                "update",
                {
                    "localId": account["uid"],
                    "emailVerified": True,
                    "mfa": {"enrollments": [{"phoneInfo": account["phone"]}]},
                },
            )
            require(status == 200 and "error" not in updated)
            record = lookup(account)
            enrollments = record.get("mfaInfo")
            require(isinstance(enrollments, list) and len(enrollments) == 1)
            require(enrollments[0].get("phoneInfo") == account["phone"])
            account["enrollmentId"] = enrollments[0]["mfaEnrollmentId"]
            require(record.get("emailVerified") is True)
            account["validSince"] = record.get("validSince")
            report["setup"][label] = True

        fresh_finalize("baseline-a-fresh-finalize", accounts["a"])
        fresh_finalize("baseline-b-fresh-finalize", accounts["b"])

        target, control = accounts["a"], accounts["b"]
        # The credential under observation is issued now and never completed before the
        # revocation.
        held = pending(target)
        issued_at = int(time.time())
        # Whole-second validSince must be strictly after the issuance second.
        time.sleep(2)
        require(core.recovery_identity(target["journal"])[1] == target["uid"])
        lookup(target)
        revoke_at = int(time.time())
        status, response = admin(
            "update", {"localId": target["uid"], "validSince": str(revoke_at)}
        )
        require(status == 200 and "error" not in response)
        current, other = lookup(target), lookup(control)
        require(current.get("validSince") == str(revoke_at))
        require(other.get("validSince") == control["validSince"])
        report["revocation"] = {"validSinceReadback": True, "controlUnchanged": True}
        report["heldCredentialIssuedBeforeRevocation"] = issued_at < revoke_at
        require(report["heldCredentialIssuedBeforeRevocation"])
        held_start_at = int(time.time())
        report["timeline"] = {
            "heldIssuedAt": issued_at,
            "validSince": revoke_at,
            "validSinceReadbackAt": held_start_at,
            "heldStartAt": held_start_at,
        }

        status, started = start(target, held)
        session = started.get("phoneResponseInfo", {}).get("sessionInfo")
        held_start = row(
            "revoked-a-held-start",
            status,
            started,
            {"sessionInfoPresent": isinstance(session, str) and bool(session)},
        )
        if held_start["outcome"] != "accepted":
            for name in DIAGNOSTIC[1:]:
                skipped(name)
        else:
            status, signed = finalize(held, session)
            held_finalize = row(
                "revoked-a-held-finalize",
                status,
                signed,
                token_checks(target, signed, revoke_at) if status == 200 else None,
            )
            if held_finalize["outcome"] != "accepted":
                skipped("revoked-a-held-lookup")
                skipped("revoked-a-held-refresh")
            else:
                status, seen = client("lookup", {"idToken": signed["idToken"]})
                checks = None
                if status == 200:
                    checks = {
                        "ownerMatches": owned(
                            users(status, seen),
                            target["email"],
                            target["marker"],
                            target["uid"],
                        )
                        == target["uid"]
                    }
                row("revoked-a-held-lookup", status, seen, checks)
                status, renewed = refresh(signed["refreshToken"])
                checks = None
                if status == 200:
                    checks = tokens(renewed, target["uid"], target["email"], True)
                    require(all(v is True for v in checks.values()))
                    checks["derivedLookup"] = derived_lookup(
                        target, renewed["id_token"]
                    )
                row("revoked-a-held-refresh", status, renewed, checks)

        fresh_finalize("revoked-a-fresh-finalize", target)
        fresh_finalize("revoked-b-fresh-finalize", control)
        require(inputs() == before)
        report["status"] = "observed"
    except Exception as error:
        report["failure"] = type(error).__name__
    finally:
        clean = []
        for account in accounts.values():
            try:
                clean.append(
                    core.cleanup_account(
                        admin,
                        account["email"],
                        account["marker"],
                        account["uid"],
                        account["journal"],
                    )
                )
            except Exception as error:
                report["cleanupFailure"] = type(error).__name__
        if len(clean) == 2 and all(
            c == {"uidAbsent": True, "emailAbsent": True} for c in clean
        ):
            report["cleanup"] = {"uidAbsent": True, "emailAbsent": True}
        if change_attempted:
            try:
                status, raw = restore_configuration(access, original)
                report["configRestored"] = True
                report["configRestoredReadback"] = {
                    "mfa": raw.get("mfa"),
                    "phoneNumber": raw.get("signIn", {}).get("phoneNumber") or {},
                    "smsRegionConfig": raw.get("smsRegionConfig"),
                }
                projection = core.config_projection(status, raw)
                report["configDigestMatches"] = (
                    projection["sha256"] == report["configReadback"]["sha256"]
                )
            except Exception as error:
                report["configRestoreFailure"] = type(error).__name__
        save(output / "observation.json", report)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--production", action="store_true", required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--recover", type=Path)
    parser.add_argument("--restore-config", type=Path)
    args = parser.parse_args()
    if args.restore_config:
        # Restore the project configuration recorded before an interrupted change.
        value = json.loads(args.restore_config.read_bytes())
        require(
            value.get("project") == PROJECT and value.get("changeAttempted") is True
        )
        access, _, _ = core.production_preflight()
        restore_configuration(access, value["original"])
        print(json.dumps({"configRestored": True}))
    elif args.recover:
        try:
            print(json.dumps(core.reconcile(args.recover)))
        except Exception:
            raise SystemExit("Recovery unresolved; retain private journal") from None
    else:
        require(args.output is not None)
        result = observe(args.output)
        print(json.dumps({"status": result["status"], "complete": complete(result)}))
        raise SystemExit(0 if complete(result) else 2)
