"""Typed shared-Gate projection for the 26+6 AUTH-ACTION matrix."""

from __future__ import annotations

import hashlib
import os
import re
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(HERE))

import action_codes_plan as plan_module
import shared_gate

JOB = "auth-action"
CONTRACT = "shared-local-v1"
_BINDING = re.compile(r"\$binding:([A-Za-z][A-Za-z0-9_.]*)")


def _account_for(stage_id: str) -> str | None:
    if stage_id.startswith("account-a") or "accountA" in stage_id:
        return "accountA"
    if stage_id.startswith("account-b") or "accountB" in stage_id:
        return "accountB"
    if "account-a" in stage_id or stage_id.endswith("accountA"):
        return "accountA"
    if "account-b" in stage_id or stage_id.endswith("accountB"):
        return "accountB"
    return None


def _find_account(value):
    if isinstance(value, str):
        if "accountA" in value:
            return "accountA"
        if "accountB" in value:
            return "accountB"
    if isinstance(value, dict):
        for item in value.values():
            found = _find_account(item)
            if found:
                return found
    if isinstance(value, list):
        for item in value:
            found = _find_account(item)
            if found:
                return found
    return None


def _replace_bindings(value, account):
    if isinstance(value, str) and value.startswith("$binding:"):
        name = value.removeprefix("$binding:")
        if name.endswith(".localId"):
            return "$binding:" + account + "Uid"
        return value
    if isinstance(value, dict):
        return {key: _replace_bindings(item, account) for key, item in value.items()}
    if isinstance(value, list):
        return [_replace_bindings(item, account) for item in value]
    return value


def _resource(project: str, nonce: str, account: str) -> str:
    suffix = "a" if account == "accountA" else "b"
    return f"projects/{project}/auth/accounts/o1-oob-{nonce}-{suffix}"


def _operation(row: dict, project: str, nonce: str, *, recovery: bool) -> dict:
    account = _account_for(row["id"]) or _find_account(row.get("body"))
    if account is None and row["id"].startswith("recover-"):
        account = "accountA" if "accountA" in row["id"] else "accountB"
    body = _replace_bindings(row["body"], account) if account else row["body"]
    kind = "action-stage"
    if recovery:
        if "delete" in row["id"]:
            kind = "delete"
        elif "uid-absence" in row["id"]:
            kind = "uid-absence"
        else:
            kind = "address-reconcile"
    operation = {
        "id": row["id"],
        "service": "auth",
        "project": project,
        "method": "POST",
        "path": row["path"].format(project=project).lstrip("/"),
        "body": body,
        "owner": row.get("routeClass") == "admin",
        "kind": kind,
        "account": account,
        "uidBinding": account + "Uid" if account else None,
    }
    if account:
        operation["resource"] = _resource(project, nonce, account)
    if row["id"] in {
        "account-a-create",
        "account-b-create",
    }:
        operation["kind"] = "sign-up"
        operation["binds"] = {account + "Uid": "localId"}
    code_bindings = {
        "reset-link-generate": "resetCode",
        "reset-link-generate-second": "resetCodeSecond",
        "verify-link-generate": "verifyCode",
        "email-link-generate": "emailLinkCode",
        "email-link-generate-second": "emailLinkCodeSecond",
        "deleted-user-link-generate": "deletedUserCode",
    }
    if row["id"] in code_bindings:
        operation["binds"] = {code_bindings[row["id"]]: "oobCode"}
    if recovery and kind == "address-reconcile":
        operation["body"] = {"email": [f"$binding:{account}.email"]}
    elif recovery and kind == "uid-absence":
        operation["body"] = {"localId": [f"$binding:{account}Uid"]}
    return operation


def gate_plan(project: str, nonce: str) -> dict:
    if project != "fireemu-35fe6" or not re.fullmatch(r"[0-9a-f]{32}", nonce):
        raise ValueError("authorized Action project and nonce required")
    manifest = plan_module.campaign_manifest(nonce, project=project)
    observation = [_operation(row, project, nonce, recovery=False) for row in manifest["stages"]]
    recovery = [_operation(row, project, nonce, recovery=True) for row in manifest["recovery"]]
    resources = [_resource(project, nonce, account) for account in ("accountA", "accountB")]
    account_bindings = {
        account: {"resource": _resource(project, nonce, account), "uidBinding": account + "Uid"}
        for account in ("accountA", "accountB")
    }
    schedule = [
        {
            "phase": "observation",
            "index": index,
            "seconds": 1,
            "creates": index in (0, 1),
        }
        for index in range(len(observation))
    ] + [
        {"phase": "recovery", "index": index, "seconds": 1}
        for index in range(len(recovery))
    ]
    return {
        "contract": CONTRACT,
        "campaignId": plan_module.CAMPAIGN_ID,
        "nonce": nonce,
        "project": project,
        "jobSlots": 1,
        "requestSeconds": 1,
        "wallSeconds": 300,
        "recoverySeconds": 180,
        "intervalSeconds": 0.25,
        "observationRequests": len(observation) + 2,
        "dataRequests": len(observation) + len(recovery),
        "managementRequests": 2,
        "requestCostMicrousd": 1,
        "costMicrousd": len(observation) + len(recovery) + 2,
        "management": {
            "dispatchKind": "closed-v1",
            "observation": [
                {"id": "oauth-tokeninfo", "timeout": 12},
                {"id": "auth-project-readback", "timeout": 12},
            ],
            "recovery": [],
        },
        "receiptKind": "auth-action-codes-production-receipt-v1",
        "ownershipMarker": {"field": "resource", "binding": "resource-name"},
        "observationDeletePolicy": "auth-action-account-b-delete-v1",
        "publishedAllocation": {"wallSeconds": 300, "recoverySeconds": 180},
        "permissionExpiresAt": time.time() + 600,
        "jobs": {
            JOB: {
                "resources": resources,
                "accountBindings": account_bindings,
                "observation": observation,
                "recovery": recovery,
                "schedule": schedule,
            }
        },
    }


def plan_digest(plan: dict) -> str:
    from broad_contract import digest

    return digest(plan)


def create(path: Path, plan: dict) -> None:
    shared_gate.create(path, plan)


class ActionGate(shared_gate.Gate):
    """Gate handle; runtime binding/creation evidence is supplied by the adapter."""

    def _skip_unowned_recovery_delete(self, operation, index):
        with self.locked() as state:
            job = state["jobs"][self.job]
            schedule = shared_gate.job_schedule(state["plan"]["jobs"][self.job])
            if (
                not schedule
                or job["pid"] != os.getpid()
                or job["inflight"]
                or job["recovery"] != index
                or schedule[job["scheduleDone"]]["phase"] != "recovery"
                or schedule[job["scheduleDone"]]["index"] != index
                or operation != state["plan"]["jobs"][self.job]["recovery"][index]
            ):
                raise ValueError("Action recovery skip outside frozen schedule")
            resource = operation.get("resource")
            account = operation.get("account")
            record = job.get("authAccounts", {}).get(account)
            if not isinstance(record, dict) or not shared_gate._auth_creation_ownership(
                state, job, operation
            ):
                job["recovery"] += 1
                job["scheduleDone"] += 1
                state["reservedRecovery"] -= 1
                state.setdefault("skips", []).append(
                    {"job": self.job, "index": index, "reason": "auth-ownership-unproven"}
                )
                shared_gate._save(self.path, state)
                return (None, {"skipped": "auth-ownership-unproven", "resource": resource})
        raise ValueError("Action recovery ownership unexpectedly changed")

    def dispatch(self, operation, recovery, send):
        if recovery and operation.get("kind") == "delete":
            state = self.snapshot()
            record = state["jobs"][self.job].get("authAccounts", {}).get(operation.get("account"))
            if not isinstance(record, dict) or not shared_gate._auth_creation_ownership(
                state, state["jobs"][self.job], operation
            ):
                return self._skip_unowned_recovery_delete(operation, state["jobs"][self.job]["recovery"])
        return super().dispatch(operation, recovery, send)

    def _allow_observation_auth_delete(self, state, job, operation, index):
        plan = state["plan"]
        declared = plan.get("jobs", {}).get(self.job, {}).get("accountBindings", {}).get("accountB", {})
        if (
            not shared_gate._action_observation_delete_plan_allowed(plan, job, operation)
            or operation.get("id") != "account-b-delete"
            or index != 23
            or not isinstance(declared, dict)
            or operation.get("resource") != declared.get("resource")
            or operation.get("uidBinding") != declared.get("uidBinding")
        ):
            return False
        record = job.get("authAccounts", {}).get("accountB")
        if not isinstance(record, dict) or "createEvent" not in record:
            return False
        event_index = record["createEvent"]
        if type(event_index) is not int or not 0 <= event_index < len(state["events"]):
            return False
        event = state["events"][event_index]
        observation = plan.get("jobs", {}).get(self.job, {}).get("observation", [])
        expected_signup = observation[event_index] if 0 <= event_index < len(observation) else None
        return (
            record.get("resource") == operation.get("resource")
            and isinstance(record.get("uid"), str)
            and event.get("phase") == "observation"
            and event.get("completed") is True
            and event.get("creationOutcome") == "created"
            and event.get("authEvidence", {}).get("account") == "accountB"
            and event.get("authEvidence", {}).get("uid") == record["uid"]
            and event.get("authEvidence", {}).get("creationOutcome") == "created"
            and isinstance(expected_signup, dict)
            and expected_signup.get("kind") == "sign-up"
            and event.get("requestDigest") == shared_gate.digest(expected_signup)
            and record.get("requestDigest") == event.get("requestDigest")
            and operation.get("body") == {"localId": "$binding:accountBUid"}
        )

    def _record_response(self, state, operation, recovery, event, status, body):
        if (
            not recovery
            and operation.get("service") == "auth"
            and operation.get("kind") == "sign-up"
            and operation.get("account") in {"accountA", "accountB"}
        ):
            uid = body.get("localId") if isinstance(body, dict) else None
            valid = (
                status == 200
                and isinstance(uid, str)
                and uid
                and isinstance(body.get("idToken"), str)
                and isinstance(body.get("refreshToken"), str)
            )
            if not valid:
                event["creationOutcome"] = "unknown"
                event["authEvidence"] = {
                    "account": operation["account"],
                    "creationOutcome": "unknown",
                    "status": status,
                }
                state.setdefault("jobs", {}).setdefault(self.job, {}).setdefault("authAccounts", {})[
                    operation["account"]
                ] = {
                    "resource": operation["resource"],
                    "createEvent": len(state["events"]) - 1,
                    "requestDigest": event["requestDigest"],
                    "creationOutcome": "unknown",
                }
                return
            records = job = state["jobs"][self.job]
            accounts = job.setdefault("authAccounts", {})
            if any(item.get("uid") == uid for item in accounts.values() if isinstance(item, dict)):
                raise ValueError("duplicate Auth creation UID")
            accounts[operation["account"]] = {
                "resource": operation["resource"],
                "uid": uid,
                "createEvent": len(state["events"]) - 1,
                "requestDigest": event["requestDigest"],
            }
            event["creationOutcome"] = "created"
            event["authEvidence"] = {
                "account": operation["account"],
                "uid": uid,
                "resource": operation["resource"],
                "creationOutcome": "created",
                "status": status,
            }
            return
        if (
            not recovery
            and operation.get("id") == "account-b-delete"
            and operation.get("service") == "auth"
        ):
            if not (
                (status == 200 and isinstance(body, dict) and "error" not in body)
                or (400 <= status <= 499 and isinstance(body, dict) and isinstance(body.get("error"), dict))
            ):
                raise ValueError("terminal Action delete response required")
            if status == 200:
                state["jobs"][self.job].setdefault("authAccounts", {}).setdefault("accountB", {})[
                    "deletedEvent"
                ] = len(state["events"]) - 1
            event["authEvidence"] = {"account": "accountB", "status": status, "transition": status == 200}
