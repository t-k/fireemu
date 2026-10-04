"""The metadata session of the program runner: the shared project's session unchanged, and the one FS-TRANSACTION owns alone.

`fireemu-oracle-txn` has no Firestore Rules release (admin bearer calls bypass Rules), so its session has no Rules source to hash: before a run it reads
tokeninfo, the project and the database, and proves that no Rules release exists (a clean 404), so the baseline's "no Rules release" is checked and not
assumed; after a run it reads the project and the database again. That is six management slots. The prior families keep txn_sandbox_management.py unchanged.
"""

from __future__ import annotations

import time

import txn_sandbox_management as management
from broad_contract import digest as body_digest   # on sys.path once txn_sandbox_management (through txn_expiry_preflight) is imported
from txn_program_program import PROJECT

TXN_PROJECT = "fireemu-oracle-txn"
TXN_PRE_SLOTS = ("oauth-tokeninfo", "project", "database", "rules-absent")
preflight = management.preflight
database_evidence = management.database_evidence
EXPECTED_DATABASE = {
    **management.EXPECTED_DATABASE,
    "name": f"projects/{TXN_PROJECT}/databases/(default)",
}


class MetadataSession(management.MetadataSession):
    def __init__(self, token, baseline, budget, *, request_fn=None, project=PROJECT):
        if project == PROJECT:
            super().__init__(token, baseline, budget, request_fn=request_fn)
            return
        if project != TXN_PROJECT:
            raise ValueError("management session project differs")
        if not isinstance(token, str) or not 0 < len(token) <= 8192:
            raise ValueError("bounded OAuth credential required")
        if not isinstance(baseline, dict) or set(baseline) != {"projectNumber", "databaseExpected", "credentialPrincipal"} or baseline["databaseExpected"] != EXPECTED_DATABASE:
            raise ValueError("frozen sandbox database identity and settings required")
        preflight.validate_principal(baseline.get("credentialPrincipal"))
        preflight.validate_project_number(baseline.get("projectNumber"))
        self._token = token
        self.baseline = baseline
        self.budget = budget
        self.request = request_fn
        self._ready = False
        self._database_projection = None
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
            if any(body.get(key) != value for key, value in EXPECTED_DATABASE.items()):
                raise ValueError("sandbox database must match PESSIMISTIC expected settings")
            projection = database_evidence(body)["projectionDigest"]
            if self._database_projection is None:
                self._database_projection = projection
            elif projection != self._database_projection:
                raise ValueError("sandbox database changed after observation")
            return projection
        if body.get("projectId") != self.project or body.get("projectNumber") != preflight.validate_project_number(self.baseline.get("projectNumber")):
            raise ValueError("project identity differs")
        return body_digest(body)

    def preflight(self):
        if self.project == PROJECT:
            return super().preflight()
        observed = {slot: self._read(slot) for slot in TXN_PRE_SLOTS}
        self._ready = True
        return observed
