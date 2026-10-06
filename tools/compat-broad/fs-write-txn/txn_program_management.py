"""The metadata session of the program runner: the shared project's session unchanged, and the one FS-TRANSACTION owns alone.

`fireemu-oracle-txn` has no Firestore Rules release (admin bearer calls bypass Rules), so its session has no Rules source to hash: before a run it reads
tokeninfo, the project and the database, and proves that no Rules release exists (a clean 404), so the baseline's "no Rules release" is checked and not
assumed; after a run it reads the project and the database again. That is six management slots. The prior families keep txn_sandbox_management.py unchanged.
"""

from __future__ import annotations

import copy
import re
import time

import txn_sandbox_management as management
from broad_contract import digest as body_digest   # on sys.path once txn_sandbox_management (through txn_expiry_preflight) is imported
from txn_program_program import PROJECT

TXN_PROJECT = "fireemu-oracle-txn"
QUERY_PROJECT = "fireemu-oracle-query"
TXN_PRE_SLOTS = ("oauth-tokeninfo", "project", "database", "rules-absent")
preflight = management.preflight
database_evidence = management.database_evidence
EXPECTED_DATABASE = {
    **management.EXPECTED_DATABASE,
    "name": f"projects/{TXN_PROJECT}/databases/(default)",
}


class MetadataSession(management.MetadataSession):
    def __init__(self, token, baseline, budget, *, request_fn=None, project=PROJECT):
        self.project = project
        if project == PROJECT:
            super().__init__(token, baseline, budget, request_fn=request_fn)
            return
        if project not in (TXN_PROJECT, QUERY_PROJECT):
            raise ValueError("management session project differs")
        if not isinstance(token, str) or not 0 < len(token) <= 8192:
            raise ValueError("bounded OAuth credential required")
        if not isinstance(baseline, dict) or set(baseline) != {"projectNumber", "databaseExpected", "credentialPrincipal"}:
            raise ValueError("frozen sandbox database identity and settings required")
        expected = baseline["databaseExpected"]
        if project == TXN_PROJECT and expected != EXPECTED_DATABASE or project == QUERY_PROJECT and (
            not isinstance(expected, dict) or set(expected) != set(EXPECTED_DATABASE)
            or expected.get("name") != f"projects/{project}/databases/(default)"
            or any(not isinstance(value, str) or not value for value in expected.values())
        ):
            raise ValueError("frozen sandbox database identity and settings required")
        preflight.validate_principal(baseline.get("credentialPrincipal"))
        preflight.validate_project_number(baseline.get("projectNumber"))
        self._token = token
        self.baseline = baseline
        self.budget = budget
        self.request = request_fn
        self._ready = False
        self._database_projection = None
        self._database_settings = None
        self.project = project

    def _read(self, slot, resource=None):
        if self.project == PROJECT:
            return super()._read(slot, resource)
        self.budget.charge("management")
        sent = time.monotonic()
        if slot == "rules-absent":
            result = self.request("rules-release", self._token, None)
            if not isinstance(result, dict) or result.get("workerReaped") is not True or result.get("status") != 404 or result.get("body") is not None:
                raise ValueError("a Rules release exists or its answer is unreadable, but the baseline of this project has none")
            return "absent"
        if slot not in ("oauth-tokeninfo", "project", "database"):
            raise ValueError("management slot outside the fixed set")
        result = self.request(slot, self._token, resource)
        if (
            not isinstance(result, dict)
            or result.get("complete") is not True
            or result.get("workerReaped") is not True
            or result.get("status") != 200
            or not isinstance(result.get("body"), dict)
        ):
            raise ValueError(f"{slot} management readback is incomplete or refused")
        body = result["body"]
        if slot == "oauth-tokeninfo":
            preflight.verify_token(self._token, result, self.baseline["credentialPrincipal"], sent=sent, now=time.monotonic(), required_seconds=1600)
            return {"verified": True, "requiredSeconds": 1600}
        if slot == "database":
            if any(body.get(key) != value for key, value in self.baseline["databaseExpected"].items()):
                raise ValueError("sandbox database must match PESSIMISTIC expected settings")
            projection = database_evidence(body)["projectionDigest"]
            # The two non-secret values the boundary of a read at a time ago depends on (read-time retention compares "configuration"): kept in the receipt, as reported or None.
            settings = {key: body.get(key) for key in ("pointInTimeRecoveryEnablement", "versionRetentionPeriod")}
            if any(value is not None and not isinstance(value, str) for value in settings.values()):
                raise ValueError("sandbox database settings must be strings")
            if self._database_projection is None:
                self._database_projection, self._database_settings = projection, settings
            elif projection != self._database_projection:   # the projection retains both settings, so a change in either is refused here
                raise ValueError("sandbox database changed after observation")
            return projection
        if body.get("projectId") != self.project or body.get("projectNumber") != preflight.validate_project_number(self.baseline.get("projectNumber")):
            raise ValueError("project identity differs")
        return body_digest(body)

    def preflight(self):
        if self.project == PROJECT:
            return super().preflight()
        observed = {slot: self._read(slot) for slot in (TXN_PRE_SLOTS if self.project == TXN_PROJECT else TXN_PRE_SLOTS[:-1])}
        observed["databaseSettings"] = dict(self._database_settings)
        self._ready = True
        return observed

    def postflight(self):
        observed = super().postflight()
        if self.project != PROJECT:
            observed["databaseSettings"] = dict(self._database_settings)
        return observed


    def _named_request(self, slot, resource, save):
        self.budget.charge("management")
        self.named_database["lastRequestEpoch"] = time.time()
        save(copy.deepcopy(self.named_database))
        result = self.request(slot, self._token, resource)
        if not isinstance(result, dict) or result.get("workerReaped") is not True:
            raise ValueError("named database worker is not reaped")
        return result

    def _wait_database_operation(self, result, save):
        resource = self.named_database["database"]
        body = result.get("body")
        if result.get("complete") is not True or result.get("status") != 200 or not isinstance(body, dict):
            raise ValueError("named database mutation outcome is unknown")
        operation = body.get("name")
        if not isinstance(operation, str) or not re.fullmatch(re.escape(resource) + r"/operations/[A-Za-z0-9_-]+", operation):
            raise ValueError("named database operation differs")
        for attempt in range(11):
            if body.get("done") is True:
                if "error" in body or not isinstance(body.get("response"), dict):
                    raise ValueError("named database operation did not succeed")
                return body["response"]
            if attempt == 10:
                break
            time.sleep(1)
            result = self._named_request("database-operation", operation, save)
            body = result.get("body")
            if result.get("complete") is not True or result.get("status") != 200 or not isinstance(body, dict) or body.get("name") != operation:
                break
        raise ValueError("named database operation is unknown or unfinished")

    def create_named_database(self, resource, save):
        if self.project != QUERY_PROJECT or not self._ready or hasattr(self, "named_database") or not isinstance(resource, str) or not re.fullmatch(r"projects/fireemu-oracle-query/databases/txn-[a-f0-9]{32}", resource):
            raise ValueError("one resolved run-prefixed query database required")
        # Firestore holds deleted database IDs for five minutes before reuse: https://firebase.google.com/docs/firestore/manage-databases#delete_a_database
        # This run never reuses an ID, including after an unknown create or delete.
        self.named_database = {"database": resource, "closureReady": False, "unknownCreate": False, "createRefused": False, "unknownDelete": False, "createConfirmed": False, "deleteAttempted": False, "deleteConfirmed": False, "deleteAccepted": False, "lastRequestEpoch": None, "a2": False}
        probe = self._named_request("named-database", resource, save)
        if probe.get("complete") is not True or probe.get("status") != 404 or (probe.get("body") or {}).get("error", {}).get("status") != "NOT_FOUND":
            raise ValueError("run database name was not proven absent")
        self.named_database["unknownCreate"] = True
        result = self._named_request("create-database", resource, save)
        body = result.get("body")
        if result.get("complete") is True and type(result.get("status")) is int and 400 <= result["status"] < 500 and result["status"] not in (408, 429, 499) and isinstance(body, dict) and isinstance(body.get("error"), dict) and type(body["error"].get("code")) is int and body["error"]["code"] == result["status"] and isinstance(body["error"].get("status"), str) and body["error"]["status"] and body["error"]["status"] not in ("CANCELLED", "UNKNOWN", "DEADLINE_EXCEEDED", "INTERNAL", "UNAVAILABLE", "DATA_LOSS"):
            self.named_database["createRefused"] = True
            self.readback_named_database(None, save)
            raise ValueError("named database create was refused; no resend")
        response = self._wait_database_operation(result, save)
        if response.get("name") != resource:
            raise ValueError("created database identity differs")
        self.named_database.update(unknownCreate=False, createConfirmed=True)
        read = self._named_request("named-database", resource, save)
        if read.get("complete") is not True or read.get("status") != 200 or (read.get("body") or {}).get("name") != resource:
            raise ValueError("confirmed create lacks its database readback; A2 required")
        save(copy.deepcopy(self.named_database))
        return copy.deepcopy(self.named_database)

    def delete_named_database(self, save):
        state = self.named_database
        if not state["createConfirmed"] or state["unknownCreate"] or state["deleteAttempted"]:
            raise ValueError("unknown mutations are sticky; deletion cannot be sent or repeated")
        state.update(deleteAttempted=True, unknownDelete=True, a2=False)
        result = self._named_request("delete-database", state["database"], save)
        body = result.get("body")
        response = body.get("response") if isinstance(body, dict) else None
        if result.get("complete") is not True or result.get("status") != 200 or not isinstance(body, dict) or "error" in body or not isinstance(body.get("metadata"), dict) or body["metadata"].get("@type") != "type.googleapis.com/google.firestore.admin.v1.DeleteDatabaseMetadata" or not isinstance(body.get("name"), str) or not re.fullmatch(re.escape(state["database"]) + r"/operations/[A-Za-z0-9_-]+", body["name"]) or not isinstance(response, dict) or response.get("previousId") != state["database"].rsplit("/", 1)[1] or not isinstance(response.get("deleteTime"), str) or not response["deleteTime"]:
            raise ValueError("named database delete outcome is unknown")
        state["deleteAccepted"] = True
        return self.readback_named_database(None, save)

    def readback_named_database(self, a2_epoch, save):
        state = self.named_database
        if a2_epoch is not None:
            if type(a2_epoch) not in (int, float) or a2_epoch > time.time() or not 600 <= a2_epoch - state["lastRequestEpoch"] < float("inf"):
                raise ValueError("A2 readback requires at least ten minutes after the last request")
            state["a2"] = True
        state["a2"] = a2_epoch is not None
        result = self._named_request("named-database", state["database"], save)
        if state["a2"] and result.get("complete") is True and result.get("status") == 200 and (result.get("body") or {}).get("name") == state["database"]:
            state.update(createConfirmed=True, unknownCreate=False, createRefused=False)
        absent = result.get("complete") is True and result.get("status") == 404 and (result.get("body") or {}).get("error", {}).get("status") == "NOT_FOUND"
        if absent and state.get("createRefused") and not state["createConfirmed"]:
            state.update(unknownCreate=False, closureReady=True)
        elif absent and state["deleteAttempted"] and state["createConfirmed"] and not state["unknownCreate"] and (state.get("deleteAccepted") or state["a2"]):
            state.update(unknownDelete=False, deleteConfirmed=True, closureReady=True)
        else:
            state["closureReady"] = False
        save(copy.deepcopy(state))
        return copy.deepcopy(state)
