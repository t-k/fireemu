"""Bounded local executor for one persisted request-byte recovery child."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "production-admission"))
sys.path.insert(0, str(HERE.parent))

import request_bytes_recovery_campaign as recovery_campaign
import reservations
import shared_gate
from broad_contract import digest

RECOVERY_JOB = recovery_campaign.RECOVERY_JOB


class _RecoveryGate(shared_gate.Gate):
    """Gate facade binding owned readbacks to the canonical parent fields."""

    def __init__(self, path, job, expected_fields):
        super().__init__(path, job)
        self.expected_fields = expected_fields

    def _recovery_capture(self, operation, status, body):
        capture = super()._recovery_capture(operation, status, body)
        capture["responseDigest"] = digest(body)
        return capture

    def _validate_cleanup_ownership(self, operation, recovery, resource, source, job):
        capture = job.get("captures", {}).get(str(source), {})
        if (
            not recovery
            or capture.get("name") != resource
            or capture.get("fieldsDigest") != self.expected_fields.get(resource)
            or not isinstance(capture.get("updateTime"), str)
            or not capture["updateTime"]
        ):
            raise ValueError("canonical recovery ownership proof required")


def _response(base_url: str, operation: dict, versions: dict[str, str]):
    path = operation["path"]
    source = operation.get("versionFrom")
    if source is not None and "currentDocument.updateTime=" not in path:
        version = versions.get(operation["resource"])
        if version is None:
            raise ValueError("version-bound recovery delete without inspection")
        path += "?currentDocument.updateTime=" + quote(version, safe="")
    request = Request(base_url.rstrip("/") + path, method=operation["method"])
    try:
        response = urlopen(request, timeout=3.0)
    except HTTPError as error:
        response = error
    with response:
        raw = response.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError("loopback response exceeds bounded receipt")
        body = json.loads(raw) if raw else {}
        return response.status, body


def execute_recovery(
    *,
    ledger: reservations.Ledger,
    child_ticket: dict,
    canonical_parent_plan: dict,
    child_gate_plan: dict,
    gate_path: Path,
    base_url: str,
) -> dict:
    """Run the exact persisted 85-slot child against a bounded loopback server."""
    if not str(base_url).startswith("http://127.0.0.1:"):
        raise ValueError("loopback transport endpoint required")
    bound = ledger.bound_recovery_claim(child_ticket)
    if bound["state"] != "allocated":
        raise ValueError("allocated child required")
    if digest(child_gate_plan) != bound["childClaim"]["gatePlanDigest"]:
        raise ValueError("persisted child Gate plan differs")
    expected_fields = {
        write["update"]["name"]: digest(write["update"]["fields"])
        for operation in canonical_parent_plan.get("observation", [])
        if isinstance(operation.get("body"), dict)
        for write in operation["body"].get("writes", [])
        if isinstance(write.get("update"), dict)
        and isinstance(write["update"].get("fields"), dict)
    }
    shared_gate.create(gate_path, child_gate_plan)
    gate = _RecoveryGate(gate_path, RECOVERY_JOB, expected_fields)
    gate.claim()
    versions: dict[str, str] = {}
    for operation in child_gate_plan["jobs"][RECOVERY_JOB]["recovery"]:
        admitted_operation = copy.deepcopy(operation)
        if operation.get("versionFrom") is not None and operation["resource"] in versions:
            admitted_operation["path"] += "?currentDocument.updateTime=" + quote(
                versions[operation["resource"]], safe=""
            )
        admitted_operation.pop("versionFrom", None)

        def send(operation=admitted_operation):
            status, body = _response(base_url, operation, versions)
            if operation["kind"] == "recovery-inspection-read" and status == 200:
                if body.get("name") != operation["resource"]:
                    raise ValueError("inspection resource identity differs")
                versions[operation["resource"]] = body.get("updateTime")
            return status, body

        gate.dispatch(admitted_operation, True, send)
    gate.finish()
    final_gate = gate.snapshot()
    receipt_digest = hashlib.sha256(
        json.dumps(
            {"gateDigest": digest(final_gate), "child": child_ticket["claimDigest"]},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    settled = ledger.settle_recovery_child(
        child_ticket,
        receipt_digest=receipt_digest,
        canonical_parent_plan=canonical_parent_plan,
        now=time.time(),
    )
    return {"ticket": settled, "gateDigest": digest(final_gate), "receiptDigest": receipt_digest}
