"""Typed collector for the FS-CONFIG-LIFECYCLE campaign.

The collector drives the twelve cases through an injected `transmit(request, *,
deadline)` callable behind the configuration gate. It never chooses a transport: a
local rehearsal injects a loopback transport, and the production launcher binds the
one-shot capability transport. Every request is charged by the gate before it is
sent; every response body is written to the private run directory and enters the
result only as a digest and a type shape, which is the raw-retention boundary.

Each configuration change is a locked step: baseline read (pre digest and body
reference), patch, bounded operation poll, readback (post digest), revert, and a
verifying readback whose digest must equal the pre digest. On every stop path the
recovery phase reverts what was applied and verifies it again, then reconciles the
owned field listings and the database enumeration. A step whose revert was refused or
whose verification differs is reported unrecovered; the run then exits non-zero and
the shared Ledger reservation is never released.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[0]))

from batch_contract import database_evidence

from .cases import DEFAULT_DATABASE, PROJECT, compile_cases, locked_steps
from .lifecycle_gate import (
    APPLIED,
    APPLY_REFUSED,
    APPLY_UNCERTAIN,
    FINISHED_STATES,
    NOT_APPLIED,
    RESTORED,
    REVERT_NOT_ATTEMPTED,
    REVERT_REFUSED,
    REVERT_UNCERTAIN,
    UNVERIFIED,
    ConfigurationGate,
)
from .surface_matrix import CASE_ID, digest

RESULT_KIND = "fs-config-lifecycle-collection-v1"
PREFLIGHT_CASE = "PRE-01"
# Refusal codes that prove a second attempt cannot succeed with this credential or
# this resource; every other refused revert gets one attempt under the reserve.
PERMANENT_REFUSALS = frozenset({401, 403, 404})
RECONCILIATION_FILTERS = (
    ("indexConfig", "indexConfig.usesAncestorConfig:false"),
    ("ttlConfig", "ttlConfig:*"),
)
UNRECOVERED_KIND = "fs-config-lifecycle-unrecovered-v1"
_M = "firestore.projects."
# Fields whose value is never compared: they advance on their own or identify one
# provisioning instance. Their presence and JSON type are still part of the shape.
VALUE_NORMALIZED = frozenset(
    {
        "earliestVersionTime",
        "etag",
        "createTime",
        "updateTime",
        "deleteTime",
        "uid",
        "snapshotTime",
        "startTime",
        "endTime",
        "name",
    }
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def http_request(case: dict[str, Any], *, operation_name: str | None = None) -> dict:
    """The REST request one case issues; the method is taken from the Discovery locator."""
    method = case["method"].removeprefix(_M)
    request = case["request"]
    query: dict[str, Any] = {}
    body = None
    if method == "databases.get":
        path = f"/v1/{request['name']}"
        verb = "GET"
    elif method == "databases.list":
        path = f"/v1/{request['parent']}/databases"
        query = {"showDeleted": "false" if request["showDeleted"] is False else "true"}
        verb = "GET"
    elif method == "databases.collectionGroups.fields.get":
        path = f"/v1/{request['name']}"
        verb = "GET"
    elif method == "databases.collectionGroups.fields.list":
        path = f"/v1/{request['parent']}/fields"
        query = {"filter": request["filter"], "pageSize": str(request["pageSize"])}
        verb = "GET"
    elif method == "databases.collectionGroups.fields.patch":
        path = f"/v1/{request['name']}"
        query = {"updateMask": request["updateMask"]}
        body = request["field"]
        verb = "PATCH"
    elif method == "databases.operations.get":
        if operation_name is None:
            raise ValueError(
                "operation poll requires the operation an owned patch returned"
            )
        path = f"/v1/{operation_name}"
        verb = "GET"
    else:
        raise ValueError(f"no REST mapping for {case['method']}")
    return {
        "case": case["id"],
        "role": "case",
        "method": verb,
        "path": path,
        "query": query,
        "body": body,
    }


def request_url_path(request: dict) -> str:
    query = request.get("query") or {}
    return request["path"] + ("?" + urlencode(query, quote_via=quote) if query else "")


def shape(value: Any) -> Any:
    """The type skeleton of a response: keys and JSON types, values only for enums.

    A string is kept when it is short, upper-case and underscored, which is how the
    Admin API spells an enum; every other value collapses to its JSON type. Fields in
    VALUE_NORMALIZED collapse to their type unconditionally.
    """
    if isinstance(value, dict):
        return {
            key: "string"
            if key in VALUE_NORMALIZED and isinstance(item, str)
            else shape(item)
            for key, item in sorted(value.items())
        }
    if isinstance(value, list):
        return [shape(item) for item in value]
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        if len(value) <= 64 and value.replace("_", "").isalnum() and value.isupper():
            return {"enum": value}
        return "string"
    if value is None:
        return "null"
    raise TypeError("JSON value required")


def _proves_not_applied(status: Any, typed_error: dict | None) -> bool:
    """Whether a typed answer proves the patch was not applied.

    Every typed 4xx does: the request was refused before it changed anything. Of the
    5xx answers only a typed UNIMPLEMENTED does, because it says the method is not
    served at all; INTERNAL, UNAVAILABLE and DEADLINE_EXCEEDED can all follow a
    server-side apply whose acknowledgement was lost, so they leave the step owned.
    """
    if typed_error is None or type(status) is not int:
        return False
    if 400 <= status < 500:
        return True
    return status == 501 and typed_error.get("status") == "UNIMPLEMENTED"


def _typed_error(body: Any) -> dict | None:
    if not isinstance(body, dict) or set(body) != {"error"}:
        return None
    error = body["error"]
    if not isinstance(error, dict) or type(error.get("code")) is not int:
        return None
    return {"code": error["code"], "status": error.get("status")}


def _write_private(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


class _Run:
    def __init__(
        self, nonce, transmit, output, gate, sleeper, credential_preflight=None
    ) -> None:
        self.nonce = nonce
        self.credential_preflight = credential_preflight
        self.transmit = transmit
        self.output = Path(output)
        self.gate = gate
        self.sleep = sleeper
        self.cases = {case["id"]: case for case in compile_cases(nonce)}
        self.steps = locked_steps(nonce)
        self.rows: list[dict] = []
        self.deviations: list[dict] = []
        self.refused_applies: list[str] = []
        self.recovery_failures: list[dict] = []
        self.enumeration: list[str] | None = None
        self.stop_point: str | None = None

    # -- one charged request -------------------------------------------------

    def send(self, phase, request, *, step=None, via=None) -> dict:
        """One charged request; `via` replaces the campaign transport for one call."""
        transmit = self.transmit if via is None else via
        index = len(self.rows)
        row = {
            "index": index,
            "phase": phase,
            "case": request["case"],
            "role": request["role"],
            "step": step,
            "method": request["method"],
            "path": request_url_path(request),
            "requestDigest": digest(request),
            "status": None,
            "bodyDigest": None,
            "shape": None,
            "typedError": None,
            "complete": False,
            "failure": None,
            "responseBodyFile": None,
        }
        self.rows.append(row)
        try:
            receipt = self.gate.charge(
                phase, request, lambda deadline: transmit(request, deadline=deadline)
            )
        except Exception as error:
            row["failure"] = type(error).__name__
            self._persist_row(row, None)
            raise
        body = receipt["body"]
        raw = receipt.get("raw")
        if raw is None:
            raw = json.dumps(body, sort_keys=True, allow_nan=False).encode()
        row.update(
            status=receipt["status"],
            bodyDigest=digest(body),
            shape=shape(body) if body is not None else None,
            typedError=_typed_error(body),
            complete=bool(receipt["complete"]),
            failure=receipt["failure"],
            responseBodyFile=f"response-{index:03d}.body",
        )
        self._persist_row(row, raw)
        return {**receipt, "row": row}

    def _persist_row(self, row, raw) -> None:
        collection = self.output
        if raw is not None:
            _write_private(collection / row["responseBodyFile"], raw)
            row["responseBytes"] = len(raw)
            row["responseSha256"] = _sha256(raw)
        _write_private(
            collection / f"row-{row['index']:03d}.json",
            json.dumps(row, sort_keys=True, indent=1).encode(),
        )

    def journaled(self, request) -> bool:
        """Whether the gate journaled a wire attempt for this request.

        A bound refusal raises before the event is appended; a transport failure
        raises after. The difference decides whether a patch may have reached the
        server, so it is read from the journal rather than inferred from the error.
        """
        wanted = digest(request)
        return any(
            event["requestDigest"] == wanted for event in self.gate.snapshot()["events"]
        )

    @staticmethod
    def _ok(receipt) -> bool:
        status = receipt["status"]
        return receipt["complete"] and type(status) is int and 200 <= status < 300

    # -- observation ----------------------------------------------------------

    def case_request(self, case_id, role="case", **extra) -> dict:
        request = http_request(self.cases[case_id], **extra)
        request["role"] = role
        return request

    def observe(self) -> None:
        plan = self.gate.plan
        if self.credential_preflight is not None:
            request = {
                "case": PREFLIGHT_CASE,
                "role": "preflight",
                "method": "GET",
                "path": "/oauth2/v1/tokeninfo",
                "query": {},
                "body": None,
            }
            attested = self.send(
                "observation",
                request,
                via=lambda _request, *, deadline: self.credential_preflight(deadline),
            )
            if not self._ok(attested) or not (
                isinstance(attested["body"], dict)
                and attested["body"].get("verified") is True
            ):
                return self.stop("credential-preflight-refused")
        projection = self.send("observation", self.case_request("OC-01"))
        if not self._ok(projection):
            return self.stop("projection-unavailable")
        try:
            evidence = database_evidence(projection["body"])
        except ValueError:
            return self.stop("projection-identity-incomplete")
        if evidence["projectionDigest"] != plan["baselineProjectionDigest"]:
            return self.stop("projection-drift")
        enumeration = self.send("observation", self.case_request("OC-02"))
        if not self._ok(enumeration):
            return self.stop("enumeration-unavailable")
        self.enumeration = _database_names(enumeration["body"])
        for step in self.steps:
            if not self.locked_step(step):
                return None
        listing = self.send("observation", self.case_request("OC-21"))
        if not self._ok(listing):
            return self.stop("listing-unavailable")
        return None

    def stop(self, reason) -> None:
        """Record the first stop; a stop the gate already typed keeps the gate's name."""
        if self.stop_point is None:
            journaled = self.gate.snapshot()
            if journaled["stopped"]:
                self.stop_point = journaled["stopReason"]
            else:
                self.stop_point = reason
                self.gate.stop(reason)

    def locked_step(self, step) -> bool:
        """Baseline, patch, poll, readback, revert, verify. False stops the run."""
        sid = step["id"]
        baseline = self.send(
            "observation", self.case_request(step["baseline"]), step=sid
        )
        if not self._ok(baseline):
            self.stop(f"{sid}-baseline-unavailable")
            return False
        self.gate.record_step(
            sid,
            preDigest=digest(baseline["body"]),
            preBodyRef={
                "file": baseline["row"]["responseBodyFile"],
                "sha256": baseline["row"]["responseSha256"],
                "bytes": baseline["row"]["responseBytes"],
            },
        )
        # Ownership is journaled before the patch leaves: from here until a complete
        # answer proves otherwise the field is owned and recovery will revert it.
        self.gate.record_step(sid, restore=APPLY_UNCERTAIN)
        apply_request = self.case_request(step["apply"])
        try:
            applied = self.send("observation", apply_request, step=sid)
        except Exception:
            if not self.journaled(apply_request):
                # The gate refused before the wire; nothing can have reached the server.
                self.gate.record_step(sid, restore=NOT_APPLIED)
            raise
        operation = None
        if self._ok(applied):
            try:
                operation = _operation_name(applied["body"])
            except ValueError:
                # Accepted, but the answer names no owned operation: the patch is
                # applied for all this run knows, and stays owned until reverted.
                self.stop(f"{sid}-apply-unparsed")
                return False
            self.gate.record_step(sid, restore=APPLIED, appliedOperation=operation)
        elif applied["complete"] and _proves_not_applied(
            applied["status"], applied["row"]["typedError"]
        ):
            # A typed refusal that proves nothing changed: the step needs no revert.
            # Locally this is the expected UNIMPLEMENTED answer for the indexConfig
            # patch.
            refusal = applied["row"]["typedError"]
            self.gate.record_step(sid, restore=APPLY_REFUSED, refusal=refusal)
            self.refused_applies.append(step["apply"])
            self.deviations.append(
                {"case": step["apply"], "kind": "apply-refused", "error": refusal}
            )
            return True
        else:
            # A 5xx, an untyped or an incomplete answer does not prove the patch was
            # not applied. It stays owned until a revert proves otherwise.
            self.stop(f"{sid}-apply-uncertain")
            return False
        if operation is not None and not self.poll(
            step, operation, "observation", declared=step["poll"] is not None
        ):
            self.stop(f"{sid}-operation-deadline")
            return False
        readback = self.send(
            "observation", self.case_request(step["readback"]), step=sid
        )
        if not self._ok(readback):
            self.stop(f"{sid}-readback-unavailable")
            return False
        self.gate.record_step(sid, postDigest=digest(readback["body"]))
        return self.revert(step, "observation")

    def poll(self, step, operation, phase, *, declared=False) -> bool:
        """Poll one operation until done, bounded by attempts and the poll deadline.

        Only the first poll of the step's declared poll case is a case row; every
        other poll, including the polls of a revert's operation, is a `poll` row.
        """
        plan = self.gate.plan
        self.gate.count_operation()
        poll_case = step["poll"] or "OC-22"
        deadline = time.monotonic() + plan["pollDeadlineSeconds"]
        backoff, ceiling = plan["pollBackoffSeconds"]
        for attempt in range(plan["pollAttempts"]):
            request = self.case_request(
                poll_case,
                role="case" if declared and attempt == 0 else "poll",
                operation_name=operation,
            )
            polled = self.send(phase, request, step=step["id"])
            if not self._ok(polled):
                return False
            if polled["body"].get("done") is True:
                return "error" not in polled["body"]
            if time.monotonic() + backoff > deadline:
                return False
            self.sleep(backoff)
            backoff = min(backoff * 2, ceiling)
        return False

    def revert(self, step, phase) -> bool:
        """Revert one owned step and verify the readback equals the baseline."""
        sid = step["id"]
        state = self.gate.snapshot()["steps"][sid]
        revert_request = self.case_request(step["revert"])
        self.gate.record_step(sid, revertAttempts=state["revertAttempts"] + 1)
        try:
            reverted = self.send(phase, revert_request, step=sid)
        except Exception:
            self.gate.record_step(
                sid,
                restore=REVERT_NOT_ATTEMPTED
                if not self.journaled(revert_request)
                else REVERT_UNCERTAIN,
            )
            raise
        if not self._ok(reverted):
            self.gate.record_step(
                sid, restore=REVERT_REFUSED, refusal=reverted["row"]["typedError"]
            )
            self.stop(f"{sid}-revert-refused")
            return False
        try:
            operation = _operation_name(reverted["body"])
        except ValueError:
            self.gate.record_step(sid, restore=UNVERIFIED)
            self.stop(f"{sid}-revert-unparsed")
            return False
        self.gate.record_step(sid, revertOperation=operation)
        if operation is not None and not self.poll(step, operation, phase):
            self.gate.record_step(sid, restore=UNVERIFIED)
            self.stop(f"{sid}-revert-operation-deadline")
            return False
        request = self.case_request(step["baseline"], role="verify")
        verify = self.send(phase, request, step=sid)
        if not self._ok(verify):
            self.gate.record_step(sid, restore=UNVERIFIED)
            self.stop(f"{sid}-verify-unavailable")
            return False
        verify_digest = digest(verify["body"])
        if verify_digest != state["preDigest"]:
            self.gate.record_step(sid, restore=UNVERIFIED, verifyDigest=verify_digest)
            self.stop(f"{sid}-verify-differs")
            return False
        self.gate.record_step(sid, restore=RESTORED, verifyDigest=verify_digest)
        return True

    # -- recovery -------------------------------------------------------------

    def recover(self) -> None:
        """Revert every step still owned, in reverse order, under the recovery reserve.

        Owned means applied, uncertain, unverified, or refused by an answer that does
        not prove the refusal is permanent: a 401, 403 or 404 is not retried, any
        other refusal gets exactly one recovery attempt.
        """
        self.gate.begin_recovery()
        if self.enumeration is None and all(
            state["restore"] == NOT_APPLIED
            for state in self.gate.snapshot()["steps"].values()
        ):
            # Stopped before OC-02 captured anything and before any patch left: no
            # field is owned and there is no enumeration to compare, so no request
            # is spent on a reconciliation that could prove nothing.
            self.gate.record_reconciliation(
                {"ok": False, "skipped": "no-mutation-before-enumeration"}
            )
            return
        for step in reversed(self.steps):
            state = self.gate.snapshot()["steps"][step["id"]]
            if state["restore"] in FINISHED_STATES:
                continue
            if state["restore"] == REVERT_REFUSED and (
                state["revertAttempts"] >= 2
                or (state["refusal"] or {}).get("code") in PERMANENT_REFUSALS
            ):
                continue
            try:
                self.revert(step, "recovery")
            except Exception as error:  # noqa: BLE001 -- the gate journaled the stop
                self.recovery_failures.append(
                    {"step": step["id"], "failure": type(error).__name__}
                )
        self.reconcile()

    def reconcile(self) -> None:
        record: dict[str, Any] = {"ok": False, "fieldListings": {}, "enumeration": None}
        try:
            # Production lists a field under the index filter only when its index
            # configuration is overridden; a field whose only override is a TTL
            # policy keeps usesAncestorConfig and is listed under `ttlConfig:*`.
            # Both listings run for every owned group, so a stray policy or
            # exemption in either is visible.
            for step in self.steps:
                parent = step["resource"].rsplit("/fields/", 1)[0]
                for label, filter_ in RECONCILIATION_FILTERS:
                    request = {
                        "case": "OC-21",
                        "role": "reconcile",
                        "method": "GET",
                        "path": f"/v1/{parent}/fields",
                        "query": {"filter": filter_, "pageSize": "20"},
                        "body": None,
                    }
                    listing = self.send("recovery", request, step=step["id"])
                    entries = (
                        listing["body"].get("fields", []) if self._ok(listing) else None
                    )
                    record["fieldListings"][f"{step['id']}:{label}"] = {
                        "status": listing["status"],
                        "nonDefaultFields": None if entries is None else len(entries),
                    }
            request = self.case_request("OC-02", role="reconcile")
            after = self.send("recovery", request)
            names = _database_names(after["body"]) if self._ok(after) else None
            record["enumeration"] = {
                "before": self.enumeration,
                "after": names,
                "equal": names is not None and names == self.enumeration,
            }
        except Exception as error:  # noqa: BLE001 -- recorded, never hidden
            record["failure"] = type(error).__name__
        record["ok"] = (
            record.get("failure") is None
            and all(
                item["nonDefaultFields"] == 0
                for item in record["fieldListings"].values()
            )
            and record["enumeration"] is not None
            and record["enumeration"]["equal"] is True
        )
        self.gate.record_reconciliation(record)


def _database_names(body) -> list[str] | None:
    if not isinstance(body, dict) or not isinstance(body.get("databases"), list):
        return None
    return sorted(
        item.get("name") for item in body["databases"] if isinstance(item, dict)
    )


def _operation_name(body) -> str | None:
    """The operation a patch returned, refused unless it is under the owned database.

    A returned name is polled at least once even when the answer already says done,
    so the operation projection (OC-22) is observed on every side that names one.
    """
    if not isinstance(body, dict):
        return None
    name = body.get("name")
    prefix = f"projects/{PROJECT}/databases/{DEFAULT_DATABASE}/operations/"
    if (
        isinstance(name, str)
        and name.startswith(prefix)
        and "/" not in name[len(prefix) :]
    ):
        return name
    if body.get("done") is True:
        return None
    raise ValueError("owned patch answered without an owned operation name")


def collect(
    nonce: str,
    transmit: Callable[..., dict],
    output,
    *,
    gate: ConfigurationGate,
    sleeper: Callable[[float], None] = time.sleep,
    credential_preflight: Callable[[float], dict] | None = None,
) -> dict:
    """Run the twelve cases behind the gate; always run recovery; never release.

    `credential_preflight(deadline)` is the production token attestation: it is
    charged as the first request and must answer a complete receipt whose body says
    `verified: true`, or the run stops before OC-01 with nothing patched.
    """
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise ValueError("fresh collection output required")
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    run = _Run(nonce, transmit, output, gate, sleeper, credential_preflight)
    failure = None
    try:
        run.observe()
    except Exception as error:  # noqa: BLE001 -- the gate journaled the stop
        failure = type(error).__name__
        run.stop_point = run.stop_point or run.gate.snapshot()["stopReason"]
    try:
        run.recover()
    except Exception as error:  # noqa: BLE001 -- recovery failures are typed below
        failure = failure or type(error).__name__
    snapshot = run.gate.snapshot()
    steps = snapshot["steps"]
    unrecovered = [
        {
            "step": name,
            "resource": step["resource"],
            "restore": step["restore"],
            "preDigest": step["preDigest"],
            "verifyDigest": step["verifyDigest"],
            "refusal": step["refusal"],
        }
        for name, step in steps.items()
        if step["restore"] not in FINISHED_STATES
    ]
    restore_verified = not unrecovered and all(
        step["restore"] in FINISHED_STATES for step in steps.values()
    )
    preflight_rows = [row for row in run.rows if row["role"] == "preflight"]
    mutation_attempted = any(
        row["role"] == "case" and row["method"] == "PATCH" for row in run.rows
    )
    reconciliation = snapshot["reconciliation"] or {"ok": False}
    cleanup_complete = restore_verified and reconciliation.get("ok") is True
    if cleanup_complete:
        run.gate.finish()
    observed = {
        row["case"] for row in run.rows if row["role"] == "case" and row["complete"]
    }
    completed = (
        run.stop_point is None and failure is None and observed >= set(run.cases)
    )
    result = {
        "kind": RESULT_KIND,
        "campaignId": CASE_ID,
        "nonceDigest": digest(nonce),
        "completed": completed,
        "cleanupComplete": cleanup_complete,
        "mutationAttempted": mutation_attempted,
        "credentialPreflight": None
        if not preflight_rows
        else {
            "status": preflight_rows[0]["status"],
            "complete": preflight_rows[0]["complete"],
            "attestationDigest": preflight_rows[0]["bodyDigest"],
        },
        "restoreVerified": restore_verified,
        "stopPoint": run.stop_point,
        "failure": failure,
        "rowCount": len(run.rows),
        "chargedRequests": snapshot["total"],
        "chargedMicrousd": snapshot["costMicrousd"],
        "observedCases": sorted(observed),
        "refusedApplies": run.refused_applies,
        "recoveryFailures": run.recovery_failures,
        "deviations": run.deviations,
        "steps": {
            name: {key: value for key, value in step.items() if key != "preBodyRef"}
            | {"preBodyRef": step["preBodyRef"]}
            for name, step in steps.items()
        },
        "reconciliation": reconciliation,
        "unrecovered": unrecovered,
        "rows": [
            {
                key: row[key]
                for key in (
                    "index",
                    "phase",
                    "case",
                    "role",
                    "step",
                    "method",
                    "path",
                    "requestDigest",
                    "status",
                    "bodyDigest",
                    "shape",
                    "typedError",
                    "complete",
                    "failure",
                )
            }
            for row in run.rows
        ],
    }
    if unrecovered:
        result["unrecoveredRecord"] = {
            "kind": UNRECOVERED_KIND,
            "campaignId": CASE_ID,
            "nonceDigest": digest(nonce),
            "resources": unrecovered,
            "reservation": "held",
            "ownerAction": (
                "restore each listed field configuration to the body referenced by "
                "preBodyRef in the private run directory, read it back, then close the "
                "shared Ledger reservation through the owner escalation path"
            ),
        }
    _write_private(
        output / "result.json",
        json.dumps(result, sort_keys=True, indent=1).encode(),
    )
    return result
