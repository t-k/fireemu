"""Campaign-owned typed facade over the frozen shared Gate."""

from __future__ import annotations

import copy
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from broad_contract import digest
from shared_gate import Gate as FrozenGate
from shared_gate import create as frozen_create
from shared_gate import validate_absence_proofs


def validate(operation):
    kind = operation.get("operationType")
    if kind is None:
        raise ValueError("typed operation required")
    if not isinstance(operation.get("principal"), str) or not operation["principal"]:
        raise ValueError("typed principal required")
    if not isinstance(operation.get("resource"), str) or not operation["resource"]:
        raise ValueError("typed resource required")
    provenance = operation.get("provenance")
    if not isinstance(provenance, dict) or not provenance.get("source"):
        raise ValueError("typed provenance required")
    if kind == "auth-refresh" and (
        provenance.get("token") != "owned-refresh-token"
        or not isinstance(operation.get("body"), dict)
        or operation["body"].get("grant_type") != "refresh_token"
        or not operation["body"].get("refresh_token")
    ):
        raise ValueError("owned refresh token required")
    if kind == "auth-delete" and (
        operation.get("method") != "POST"
        or ":delete" not in operation.get("path", "")
        or not isinstance(operation.get("body"), dict)
        or not operation["body"].get("localId")
    ):
        raise ValueError("typed Auth delete required")
    if kind == "firestore-list-collection-ids":
        body = operation.get("body")
        resource = operation.get("resource")
        if (
            operation.get("method") != "POST"
            or not isinstance(resource, str)
            or operation.get("path") != "/v1/" + resource + ":listCollectionIds"
        ):
            raise ValueError("ListCollectionIds wire shape required")
        if not isinstance(body, dict) or "parent" in body:
            raise ValueError("ListCollectionIds parent must be in URL")
        if body.get("pageToken") is not None and (
            provenance.get("pageToken") != "observed-continuation"
            or provenance.get("tokenValue") != body["pageToken"]
            or provenance.get("consumed") is not False
        ):
            raise ValueError("page token provenance or single-use binding required")


def _local_plan(plan):
    """This facade can only service the exact, non-authorizing local recipe."""
    from campaign_auth_list import campaign_manifest

    if not isinstance(plan, dict):
        raise ValueError("closed local campaign plan required")
    nonce = plan.get("nonce")
    if not isinstance(nonce, str) or re.fullmatch(r"[0-9a-f]{32}", nonce) is None:
        raise ValueError("fresh local campaign nonce required")
    origins = plan.get("localOrigins")
    if not isinstance(origins, dict) or set(origins) != {"auth", "firestore"}:
        raise ValueError("two explicit local campaign origins required")
    for value in origins.values():
        try:
            parsed = urlsplit(value)
            valid = (
                isinstance(value, str)
                and parsed.scheme == "http"
                and parsed.hostname == "127.0.0.1"
                and parsed.port is not None
                and 0 < parsed.port < 65536
                and value == f"http://127.0.0.1:{parsed.port}"
            )
        except (TypeError, ValueError, AttributeError):
            valid = False
        if not valid:
            raise ValueError("numeric loopback origin required")
    expected = campaign_manifest(nonce)
    expected["localOrigins"] = origins
    if "observerSha256" in plan:
        value = plan["observerSha256"]
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise ValueError("local observer digest required")
        expected["observerSha256"] = value
    expected_legacy = expected
    expected_canonical = _project_auth_plan(expected_legacy)
    if digest(plan) == digest(expected_legacy):
        projected = expected_canonical
    elif digest(plan) == digest(expected_canonical):
        projected = copy.deepcopy(plan)
    else:
        # Compare before projection so an untrusted resource or binding cannot
        # be silently normalized into an owned account.
        raise ValueError("closed local Auth-list contract drift")
    # In particular: no production permission, Ledger binding, extra operations,
    # changed project, omitted account, relaxed schedule or enlarged budget.
    return projected


def _canonical_auth_resource(project, account):
    return f"projects/{project}/auth/accounts/{account}"


def _project_auth_operation(operation, project, expected=None):
    if operation.get("service") != "auth":
        return copy.deepcopy(operation)
    projected = copy.deepcopy(operation)
    account = projected.get("account", projected.get("resource"))
    if not isinstance(account, str) or not account:
        raise ValueError("Auth account binding required")
    if expected is not None:
        expected_account = expected.get("account", expected.get("resource"))
        if account != expected_account:
            raise ValueError("Auth account binding differs from frozen slot")
        if projected.get("resource") not in {
            account,
            _canonical_auth_resource(project, account),
        }:
            raise ValueError("Auth resource differs from frozen slot")
        supplied_provenance = projected.get("provenance")
        supplied_uid = (
            supplied_provenance.get("uid")
            if isinstance(supplied_provenance, dict)
            else None
        )
        if (
            isinstance(supplied_uid, str)
            and supplied_uid.startswith("$binding:")
            and supplied_uid != "$binding:" + account + "Uid"
        ):
            raise ValueError("Auth UID binding differs from frozen account")
    projected["account"] = account
    projected["resource"] = _canonical_auth_resource(project, account)
    provenance = projected.get("provenance")
    if not isinstance(provenance, dict):
        raise ValueError("Auth provenance required")
    if (
        projected.get("operationType") != "auth-sign-up"
        and isinstance(provenance.get("uid"), str)
        and provenance["uid"].startswith("$binding:")
    ):
        provenance["uid"] = "$binding:" + account + "Uid"
    if projected.get("operationType") == "auth-lookup" and projected.get("method") == "POST":
        projected["kind"] = "uid-absence"
        if isinstance(projected.get("body"), dict) and "localId" in projected["body"]:
            local_id = projected["body"]["localId"]
            projected["body"]["localId"] = (
                local_id if isinstance(local_id, list) else [local_id]
            )
    return projected


def _project_auth_plan(plan):
    projected = copy.deepcopy(plan)
    from campaign_auth_list import PROJECT

    project = projected.setdefault("project", PROJECT)
    for job in projected.get("jobs", {}).values():
        accounts = []
        for phase in ("observation", "recovery"):
            for operation in job.get(phase, []):
                if operation.get("service") != "auth":
                    continue
                account = operation.get("account", operation.get("resource"))
                if account not in accounts:
                    accounts.append(account)
                original = copy.deepcopy(operation)
                operation.clear()
                operation.update(_project_auth_operation(original, project))
        resources = job.get("resources", [])
        auth_resources = [
            _canonical_auth_resource(project, account) for account in accounts
        ]
        resources = [
            resource
            for resource in resources
            if not (isinstance(resource, str) and "/accounts:" in resource)
        ]
        job["resources"] = resources + [
            resource for resource in sorted(auth_resources) if resource not in resources
        ]
    return projected


def create(path, plan):
    return frozen_create(path, _local_plan(plan))


def _text(value):
    return isinstance(value, str) and bool(value) and not value.startswith("$binding:")


def _deleted_response(status, body):
    return type(status) is int and status == 200 and (
        body == {} or body == {"kind": "identitytoolkit#DeleteAccountResponse"}
    )


def _absent_response(status, body):
    """An empty arbitrary success body is not an account absence response."""
    if type(status) is not int or not isinstance(body, dict):
        return False
    if status == 200:
        if body == {"kind": "identitytoolkit#GetAccountInfoResponse"}:
            return True
        return (
            set(body) <= {"users", "kind"}
            and type(body.get("users")) is list
            and body["users"] == []
            and ("kind" not in body or body["kind"] == "identitytoolkit#GetAccountInfoResponse")
        )
    error = body.get("error")
    return (
        status == 404
        and set(body) == {"error"}
        and isinstance(error, dict)
        and error.get("status") == "USER_NOT_FOUND"
        and ("code" not in error or type(error["code"]) is int and error["code"] == 404)
    )


class CampaignGate(FrozenGate):
    def __init__(self, path, job):
        super().__init__(path, job)
        if job != "auth-list":
            raise ValueError("closed local Auth-list job required")
        _local_plan(self.snapshot()["plan"])
        self.bindings = {}
        # Raw credentials never enter the persistent Gate journal. Only a value
        # actually returned by this instance may be installed as a binding.
        self._observed_bindings = {}

    def bind(self, name, value):
        if not _text(name) or not _text(value) or self._observed_bindings.get(name) != value:
            raise ValueError("binding must come from this run's validated response")
        if name.endswith(("Uid", "Principal")) and name in self.bindings and self.bindings[name] != value:
            raise ValueError("account identity binding is immutable")
        self.bindings[name] = value

    def _template(self, value, declared):
        # Resolve by the declared binding NAME at each position, not by reverse
        # lookup of an equal value. UID reuse or equal tokens cannot switch the
        # requested account to the first matching entry in a dictionary.
        if isinstance(declared, str) and declared.startswith("$binding:"):
            name = declared.removeprefix("$binding:")
            if name not in self.bindings or type(value) is not str or value != self.bindings[name]:
                raise ValueError("runtime binding differs from the frozen slot")
            return declared
        if isinstance(value, dict) and isinstance(declared, dict):
            return {key: self._template(item, declared.get(key)) for key, item in value.items()}
        if isinstance(value, list) and isinstance(declared, list) and len(value) == len(declared):
            return [self._template(item, expected) for item, expected in zip(value, declared, strict=True)]
        return copy.deepcopy(value)

    def dispatch(self, operation, recovery, send):
        state = self.snapshot()
        plan = _local_plan(state["plan"])
        phase = "recovery" if recovery else "observation"
        index = state["jobs"][self.job][phase]
        operations = plan["jobs"][self.job][phase]
        if index >= len(operations):
            raise ValueError("scenario request capacity")
        declared = operations[index]
        operation = _project_auth_operation(operation, plan["project"], declared)
        validate(operation)
        normalized = self._template(operation, declared)
        if operation.get("service") == "auth" and operation.get("operationType") != "auth-sign-up":
            account = state["jobs"][self.job].get("authAccounts", {}).get(operation["account"])
            if not account or operation["provenance"].get("uid") != account["uid"]:
                raise ValueError("Auth operation requires this run's created account")
            expected_local_id = (
                [account["uid"]]
                if operation.get("operationType") == "auth-lookup"
                else account["uid"]
            )
            if recovery and operation["body"].get("localId") != expected_local_id:
                raise ValueError("Auth cleanup identity differs")
        # The base class rechecks the slot, PID, stop state and budgets under its
        # lock. Recording below runs inside that SAME lock, not after dispatch.
        return super().dispatch(normalized, recovery, send)

    def _record_response(self, state, operation, recovery, event, status, body):
        job = state["jobs"][self.job]
        try:
            self._record_local_response(state, operation, recovery, event, status, body)
        except ValueError:
            job["stopped"] = True
            event["failure"] = "InvalidLocalCampaignResponse"
            raise

    def _record_local_response(self, state, operation, recovery, event, status, body):
        kind = operation.get("operationType")
        if kind == "firestore-list-collection-ids":
            if status == 200 and isinstance(body, dict) and "nextPageToken" in body:
                if not _text(body["nextPageToken"]):
                    raise ValueError("invalid continuation binding")
                self._observed_bindings["pagedToken"] = body["nextPageToken"]
            return
        if operation.get("service") != "auth":
            return
        job = state["jobs"][self.job]
        accounts = job.setdefault("authAccounts", {})
        key = operation.get("account", operation["resource"])
        position = len(state["events"]) - 1
        if kind == "auth-sign-up":
            uid = body.get("localId") if isinstance(body, dict) else None
            if (
                recovery or status != 200 or not _text(uid) or len(uid) > 128
                or key in accounts or any(value["uid"] == uid for value in accounts.values())
                or not _text(body.get("idToken")) or not _text(body.get("refreshToken"))
                or "error" in body
            ):
                raise ValueError("same-run account creation acknowledgement required")
            accounts[key] = {
                "uid": uid,
                "resource": operation["resource"],
                "createEvent": position,
            }
            self._observed_bindings[key + "Uid"] = uid
            self._observed_bindings[key + "Principal"] = "owned-account:" + uid
            event["creationOutcome"] = "created"
        else:
            account = accounts.get(key)
            if not account:
                raise ValueError("same-run account creation proof missing")
            uid = account["uid"]
            if kind == "auth-sign-in":
                if (
                    recovery or status != 200 or not isinstance(body, dict)
                    or body.get("localId") != uid or "error" in body
                    or not _text(body.get("idToken")) or not _text(body.get("refreshToken"))
                ):
                    raise ValueError("sign-in returned an invalid account or credentials")
                self._observed_bindings[key + "Refresh"] = body["refreshToken"]
                self._observed_bindings[key + "IdToken"] = body["idToken"]
            elif kind == "auth-refresh":
                if (
                    recovery or status != 200 or not isinstance(body, dict)
                    or body.get("user_id") != uid or "error" in body or not _text(body.get("id_token"))
                ):
                    raise ValueError("refresh returned an invalid account or credential")
                self._observed_bindings[key + "IdToken"] = body["id_token"]
            elif kind == "auth-delete":
                if not recovery or not _deleted_response(status, body):
                    raise ValueError("typed account deletion acknowledgement required")
                account["deleteEvent"] = position
            elif kind == "auth-lookup" and recovery:
                if "deleteEvent" not in account or not _absent_response(status, body):
                    raise ValueError("typed post-delete account absence required")
                account["absenceEvent"] = position
            elif kind == "auth-lookup":
                users = body.get("users") if isinstance(body, dict) else None
                if (
                    status != 200 or not isinstance(body, dict) or "error" in body
                    or type(users) is not list or len(users) != 1
                    or not isinstance(users[0], dict) or users[0].get("localId") != uid
                ):
                    raise ValueError("lookup did not return the bound account")
            else:
                raise ValueError("unsupported local Auth response")
        evidence = {
            "kind": kind, "account": key, "uid": uid,
            "responseDigest": event["responseDigest"],
        }
        if kind == "auth-sign-up":
            evidence["creationOutcome"] = "created"
        if recovery:
            # Delete and absence bodies contain no credentials and can be
            # independently checked against their original response digest.
            evidence["body"] = copy.deepcopy(body)
        event["authEvidence"] = evidence
        # Route sentinels do NOT represent an individual account. Both accounts
        # must have a delete AND a final lookup; one success cannot hide another.
        expected_accounts = {
            op.get("account", op["resource"])
            for op in state["plan"]["jobs"][self.job]["observation"]
            if op.get("operationType") == "auth-sign-up"
        }
        if set(accounts) == expected_accounts and all(
            "deleteEvent" in account and "absenceEvent" in account
            for account in accounts.values()
        ):
            owned_auth_resources = {
                account["resource"] for account in accounts.values()
            }
            for resource in job["resources"]:
                if (
                    resource.startswith("identitytoolkit.googleapis.com/")
                    or resource in owned_auth_resources
                ) and resource not in job["absent"]:
                    job["absent"].append(resource)

    def _validate_finish_evidence(self, state):
        _local_plan(state["plan"])
        job = state["jobs"][self.job]
        recipe = state["plan"]["jobs"][self.job]
        if job["observation"] != len(recipe["observation"]):
            raise ValueError("local campaign observations incomplete")
        accounts = job.get("authAccounts", {})
        expected_accounts = {
            op.get("account", op["resource"]) for op in recipe["observation"]
            if op.get("operationType") == "auth-sign-up"
        }
        if (
            not isinstance(accounts, dict) or set(accounts) != expected_accounts
            or any(
                not isinstance(item, dict)
                or set(item) != {"uid", "resource", "createEvent", "deleteEvent", "absenceEvent"}
                or not _text(item["uid"])
                or any(type(item[field]) is not int for field in ("createEvent", "deleteEvent", "absenceEvent"))
                for item in accounts.values()
            )
            or len({item["uid"] for item in accounts.values()}) != len(accounts)
        ):
            raise ValueError("account creation proof coverage differs")
        for phase in ("observation", "recovery"):
            for index, operation in enumerate(recipe[phase]):
                if operation["service"] != "auth":
                    continue
                matches = [
                    (position, event) for position, event in enumerate(state["events"])
                    if event.get("job") == self.job and event.get("phase") == phase and event.get("index") == index
                ]
                if len(matches) != 1:
                    raise ValueError("account response event missing or duplicated")
                position, event = matches[0]
                kind = operation["operationType"]
                key = operation.get("account", operation["resource"])
                account = accounts[key]
                evidence = event.get("authEvidence", {})
                fields = {"kind", "account", "uid", "responseDigest"}
                if kind == "auth-sign-up":
                    fields.add("creationOutcome")
                if phase == "recovery":
                    fields.add("body")
                if (
                    not isinstance(evidence, dict) or set(evidence) != fields
                    or not isinstance(event.get("responseDigest"), str)
                    or re.fullmatch(r"[0-9a-f]{64}", event["responseDigest"]) is None
                    or type(event.get("index")) is not int or type(event.get("status")) is not int
                    or event.get("completed") is not True or event.get("failure") is not None
                    or event.get("requestDigest") != digest(operation)
                    or evidence.get("kind") != kind or evidence.get("account") != key
                    or evidence.get("uid") != account.get("uid")
                    or evidence.get("responseDigest") != event.get("responseDigest")
                    or self.bindings.get(key + "Uid") != account.get("uid")
                ):
                    raise ValueError("account response identity/binding differs")
                if phase == "observation":
                    if event["status"] != 200:
                        raise ValueError("account observation failed")
                    if kind == "auth-sign-up" and (
                        event.get("creationOutcome") != "created" or account.get("createEvent") != position
                    ):
                        raise ValueError("account creation event differs")
                else:
                    body = evidence.get("body")
                    valid = _deleted_response(event["status"], body) if kind == "auth-delete" else _absent_response(event["status"], body)
                    field = "deleteEvent" if kind == "auth-delete" else "absenceEvent"
                    if not valid or event["responseDigest"] != digest(body) or account.get(field) != position:
                        raise ValueError("account cleanup response differs")
                    if not account["createEvent"] < account["deleteEvent"] < account["absenceEvent"]:
                        raise ValueError("account cleanup event order differs")
        # Keep Firestore's typed, request-bound final readbacks too. The Auth
        # route sentinels are validated above, not passed off as document names.
        projected = {**state, "jobs": {**state["jobs"], self.job: {
            **job, "resources": [name for name in job["resources"] if name.startswith("projects/")]
        }}}
        validate_absence_proofs(projected, self.job)
        super()._validate_finish_evidence(state)

    def adapter_request(self, adapter, operation, send):
        extra = getattr(adapter, "campaign_operation", {})
        merged = {**operation, **extra}
        plan = _local_plan(self.snapshot()["plan"])
        recovery = bool(getattr(getattr(adapter, "budget", None), "recovery", False))
        phase = "recovery" if recovery else "observation"
        index = self.snapshot()["jobs"][self.job][phase]
        declared = plan["jobs"][self.job][phase][index]
        merged = _project_auth_operation(merged, plan["project"], declared)
        validate(merged)
        return super().adapter_request(adapter, merged, send)


__all__ = ["CampaignGate", "create", "validate"]
