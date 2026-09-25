"""Own two accounts, observe distinct credential routes, and always clean up."""

# ruff: noqa: BLE001 -- Never expose raw exceptions or credentials.
import argparse
import hashlib
import json
import secrets
import sys
import time
import urllib.parse
from datetime import UTC, datetime
from pathlib import Path

from disabled_contract import (
    CORPUS,
    PHASES,
    complete,
    error_code,
    require,
    validate_row,
)

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/auth-password-maximum"))
import maximum_recorder as core
from maximum_contract import (
    expiry_seconds,
    owned,
    selected_state,
    tokens,
    users,
)

PROJECT, NUMBER, PASSWORD_POLICY = core.PROJECT, core.NUMBER, core.PASSWORD_POLICY
digest, save, origins = core.digest, core.save, core.origins


def inputs():
    return {
        **core.inputs(),
        **{
            str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(Path(__file__).parent.glob("*.py"))
            if not p.name.startswith("test_")
        },
    }


def state_without_disabled(user):
    return selected_state({k: v for k, v in user.items() if k != "disabled"})


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
        "probeSourceCommit": core.command(["git", "rev-parse", "HEAD"]),
        "corpus": CORPUS,
        "cases": [],
        "setup": {},
        "transitions": [],
        "cleanup": {},
    }
    accounts = {}
    admin = None
    try:
        access, key = "owner", "local-test-key"
        if production:
            access, key, report["configReadback"] = core.production_preflight()
        policy_url = (
            f"{identity}/v2/passwordPolicy?key={urllib.parse.quote(key, safe='')}"
        )
        if production:
            status, policy = core.request(policy_url)
            require(status == 200 and digest(policy) == digest(PASSWORD_POLICY))
            report["configReadback"]["passwordPolicy"] = policy

        def admin(action, body):
            require(action in {"lookup", "update", "delete"})
            return core.request(
                f"{identity}/v1/projects/{PROJECT}/accounts:{action}",
                body,
                access,
                quota=production,
            )

        def client(action, body):
            require(action in {"signUp", "signInWithPassword", "lookup"})
            return core.request(
                f"{identity}/v1/accounts:{action}?key={urllib.parse.quote(key, safe='')}",
                body,
            )

        def refresh(token):
            return core.request(
                f"{secure}/v1/token?key={urllib.parse.quote(key, safe='')}",
                {"grant_type": "refresh_token", "refresh_token": token},
                form=True,
            )

        def lookup(account):
            records = users(*admin("lookup", {"localId": [account["uid"]]}))
            owned(records, account["email"], account["marker"], account["uid"])
            return records[0]

        def client_state(account, token):
            records = users(*client("lookup", {"idToken": token}))
            owned(records, account["email"], account["marker"], account["uid"])
            return state_without_disabled(records[0]) == account["initial"]

        for label in ("a", "b"):
            directory = output / label
            directory.mkdir(mode=0o700)
            account = {
                "email": "fireemu-basic-" + secrets.token_hex(16) + "@example.test",
                "marker": "fireemu-owned-" + secrets.token_hex(24),
                "password": "Aa9!" + secrets.token_urlsafe(32),
                "uid": None,
                "journal": directory / "recovery.json",
            }
            require(users(*admin("lookup", {"email": [account["email"]]})) == [])
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
            account["uid"] = owned(
                users(*admin("lookup", {"email": [account["email"]]})),
                account["email"],
                account["marker"],
            )
            lookup(account)
            save(
                directory / "verified-account.json",
                {**json.loads(account["journal"].read_bytes()), "uid": account["uid"]},
            )
            require(core.recovery_identity(account["journal"])[1] == account["uid"])
            require(
                status == 200
                and all(
                    v is True
                    for v in tokens(signed, account["uid"], account["email"]).values()
                )
            )
            status, fixed = client(
                "signInWithPassword",
                {
                    "email": account["email"],
                    "password": account["password"],
                    "returnSecureToken": True,
                },
            )
            require(
                status == 200
                and all(
                    v is True
                    for v in tokens(fixed, account["uid"], account["email"]).values()
                )
            )
            account["fixed"] = fixed
            initial = lookup(account)
            require(initial.get("disabled", False) is False)
            account["initial"] = state_without_disabled(initial)
            require(client_state(account, fixed["idToken"]))
            report["setup"][label] = True

        for phase in PHASES:
            if phase != "baseline":
                target, control = accounts["a"], accounts["b"]
                # Re-establish ownership from the persisted identity before every mutation.
                require(core.recovery_identity(target["journal"])[1] == target["uid"])
                lookup(target)
                disabled = phase == "disabled"
                status, response = admin(
                    "update", {"localId": target["uid"], "disableUser": disabled}
                )
                require(
                    status == 200
                    and isinstance(response, dict)
                    and "error" not in response
                )
                current, other = lookup(target), lookup(control)
                require(
                    current.get("disabled", False) is disabled
                    and state_without_disabled(current) == target["initial"]
                )
                require(
                    other.get("disabled", False) is False
                    and state_without_disabled(other) == control["initial"]
                )
                report["transitions"].append(
                    {
                        "disabled": disabled,
                        "targetReadback": True,
                        "controlUnchanged": True,
                    }
                )
            started = time.monotonic()
            for label, account in accounts.items():
                for route in ("signin", "id", "refresh"):
                    name = f"{phase}-{label}-{route}"
                    elapsed = int((time.monotonic() - started) * 1000)
                    if route == "signin":
                        status, response = client(
                            "signInWithPassword",
                            {
                                "email": account["email"],
                                "password": account["password"],
                                "returnSecureToken": True,
                            },
                        )
                    elif route == "id":
                        status, response = client(
                            "lookup", {"idToken": account["fixed"]["idToken"]}
                        )
                    else:
                        status, response = refresh(account["fixed"]["refreshToken"])
                    row = {
                        "id": name,
                        "httpStatus": status,
                        "outcome": "accepted" if status == 200 else "refused",
                        "observedError": None
                        if status == 200
                        else error_code(response),
                        "checks": {},
                        "expirySeconds": None,
                        "elapsedMs": elapsed,
                    }
                    if status == 200:
                        if route == "id":
                            records = users(status, response)
                            owned(
                                records,
                                account["email"],
                                account["marker"],
                                account["uid"],
                            )
                            row["checks"] = {
                                "stateMatches": state_without_disabled(records[0])
                                == account["initial"]
                            }
                        else:
                            row["checks"] = tokens(
                                response,
                                account["uid"],
                                account["email"],
                                route == "refresh",
                            )
                            require(all(v is True for v in row["checks"].values()))
                            row["checks"]["derivedLookup"] = client_state(
                                account,
                                response[
                                    "id_token" if route == "refresh" else "idToken"
                                ],
                            )
                            row["expirySeconds"] = expiry_seconds(
                                response, route == "refresh"
                            )
                    report["cases"].append(row)
                    validate_row(row, name)
        if production:
            current = core.config_projection(
                *core.request(
                    f"{identity}/admin/v2/projects/{PROJECT}/config",
                    token=access,
                    quota=True,
                )
            )
            status, policy = core.request(policy_url)
            require(status == 200 and digest(policy) == digest(PASSWORD_POLICY))
            current["passwordPolicy"] = policy
            require(current == report["configReadback"])
            report["configurationUnchanged"] = True
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
        save(output / "observation.json", report)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--production", action="store_true", required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--recover", type=Path)
    args = parser.parse_args()
    if args.recover:
        try:
            print(json.dumps(core.reconcile(args.recover)))
        except Exception:
            raise SystemExit("Recovery unresolved; retain private journal") from None
    else:
        require(args.output is not None)
        result = observe(args.output)
        print(json.dumps({"status": result["status"], "complete": complete(result)}))
        raise SystemExit(0 if complete(result) else 2)
