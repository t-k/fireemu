"""Bounded collector for the transaction expiry / finished-token / retry campaign.

The collector executes the compiled plan against one Firestore REST endpoint
through an injected transport. It owns every document it creates, it stops at an
absolute deadline, and it always attempts the cleanup contract: an owned read, a
delete conditional on the observed update time, and a typed absence check. It
never deletes or restores anything without an ownership proof, and it never
converts a transport failure into a semantic result.

Timing is explicit. Production reaches the idle limit by waiting real seconds;
the local emulator runs a virtual clock and reaches it by advancing that clock.
Each row records which mechanism produced the elapsed time, so a comparison can
refuse to treat the two as interchangeable by accident.
"""

from __future__ import annotations

import base64
import sys
import time
from pathlib import Path
from typing import ClassVar

sys.path.insert(0, str(Path(__file__).parents[1]))

import txn_expiry_cases as cases
import txn_expiry_plan as plan_module

CONTRACT = "txn-expiry-collector-v1"

WALL_CLOCK = "wall-clock"
CONTROL_CLOCK = "control-clock"
TIMING_MODES = (WALL_CLOCK, CONTROL_CLOCK)

LOOPBACK_HOSTS = ("127.0.0.1", "::1", "localhost")
PRODUCTION_HOST = "firestore.googleapis.com"

NOT_FOUND = 5
ABORTED = 10
INVALID_ARGUMENT = 3
OK = 0

#: Recovery gets its own deadline so an exhausted observation budget still
#: leaves room to give owned documents back.
RECOVERY_SECONDS = 120


def owner_marker(owner_id):
    return f"o3-txn-expiry:{owner_id}"


def validate_collector_options(options):
    if not isinstance(options, dict):
        raise TypeError("collector options must be a mapping")
    host = options.get("host")
    timing = options.get("timing")
    target = options.get("target", "local")
    if target not in ("local", "production"):
        raise ValueError("target must be local or production")
    if target == "local":
        if host not in LOOPBACK_HOSTS:
            raise ValueError("a local collection must stay on the loopback host")
    elif host != PRODUCTION_HOST:
        raise ValueError("a production collection must use the fixed Firestore host")
    if timing not in TIMING_MODES:
        raise ValueError("timing must be wall-clock or control-clock")
    if target == "production" and timing != WALL_CLOCK:
        raise ValueError("production elapsed time cannot be simulated")
    nonce = options.get("nonce")
    owner_id = options.get("ownerId")
    plan_module._validate_identity(nonce, owner_id)
    deadline = options.get("deadlineSeconds", plan_module.WALL_SECONDS)
    if not isinstance(deadline, int) or not 1 <= deadline <= plan_module.WALL_SECONDS:
        raise ValueError("deadline must be a positive integer within the envelope")
    return {
        "target": target,
        "host": host,
        "port": options.get("port"),
        "projectId": options.get("projectId"),
        "database": options.get("database", plan_module.DATABASE),
        "nonce": nonce,
        "ownerId": owner_id,
        "timing": timing,
        "deadlineSeconds": deadline,
    }


def _b64(raw):
    return base64.b64encode(raw).decode()


def document_name(project, database, path):
    return f"projects/{project}/databases/{database}/documents/{path}"


def is_owned(document, owner_id, role, nonce):
    if not isinstance(document, dict):
        return False
    fields = document.get("fields")
    if not isinstance(fields, dict):
        return False
    if not document.get("updateTime"):
        return False
    expected = {
        "owner": owner_marker(owner_id),
        "role": role,
        "nonce": nonce,
    }
    for key, value in expected.items():
        entry = fields.get(key)
        if not isinstance(entry, dict) or entry.get("stringValue") != value:
            return False
    return True


def _marker_fields(owner_id, role, nonce, state):
    return {
        "owner": {"stringValue": owner_marker(owner_id)},
        "role": {"stringValue": role},
        "nonce": {"stringValue": nonce},
        "state": {"stringValue": state},
    }


class _Deadline:
    def __init__(self, seconds, monotonic):
        self._monotonic = monotonic
        self.limit = monotonic() + seconds

    def remaining(self):
        return self.limit - self._monotonic()

    def expired(self):
        return self.remaining() <= 0


class Collection:
    """One bounded execution of the compiled plan."""

    def __init__(
        self,
        options,
        plan,
        transport,
        *,
        sleeper=None,
        advance=None,
        monotonic=time.monotonic,
    ):
        self.options = validate_collector_options(options)
        self.plan = plan
        self.transport = transport
        self.sleeper = sleeper or time.sleep
        self.advance = advance
        self.monotonic = monotonic
        self.rows = []
        self.tokens = {}
        self.created = {}
        self.failure = None
        if self.options["timing"] == CONTROL_CLOCK and advance is None:
            raise ValueError("control-clock timing needs a clock advance callable")

    # -- request helpers ----------------------------------------------------

    def _path(self, role):
        return f"{self.plan['documentPrefix']}/{role}"

    def _name(self, role):
        return document_name(
            self.options["projectId"], self.options["database"], self._path(role)
        )

    def _send(self, rpc, body=None, *, role=None, query=None):
        request = {
            "rpc": rpc,
            "database": self.options["database"],
            "projectId": self.options["projectId"],
            "name": self._name(role) if role else None,
            "body": body,
            "query": query,
            "maxResponseBytes": plan_module.MAX_RESPONSE_BYTES,
        }
        return self.transport(request)

    def _begin(self, options_body):
        return self._send("BeginTransaction", {"options": options_body})

    def _commit(self, writes, token=None):
        body = {"writes": writes}
        if token is not None:
            body["transaction"] = _b64(token)
        return self._send("Commit", body)

    def _rollback(self, token):
        return self._send("Rollback", {"transaction": _b64(token)})

    def _get(self, role, token=None):
        query = {"transaction": _b64(token)} if token is not None else None
        return self._send("GetDocument", None, role=role, query=query)

    def _write_marker(self, role, state, *, create=False):
        write = {
            "update": {
                "name": self._name(role),
                "fields": _marker_fields(
                    self.options["ownerId"], role, self.options["nonce"], state
                ),
            }
        }
        if create:
            write["currentDocument"] = {"exists": False}
        return write

    # -- row recording ------------------------------------------------------

    def _record(self, step, response, *, waited=None, detail=None):
        row = {
            "slot": step["slot"],
            "phase": step["phase"],
            "caseId": step["caseId"],
            "rpc": step["rpc"],
            "role": step["role"],
            "observed": {
                "code": response.get("code"),
                "status": response.get("status"),
                "message": response.get("message"),
            },
            "complete": bool(response.get("complete", True)),
            "waited": waited,
            "detail": detail,
        }
        if step["caseId"]:
            case = CASE_BY_ID[step["caseId"]]
            row["expectedLocal"] = dict(case["expectedLocal"])
        self.rows.append(row)
        return row

    def _elapse(self, seconds):
        if seconds <= 0:
            return None
        if self.options["timing"] == WALL_CLOCK:
            self.sleeper(seconds)
            return {"mode": WALL_CLOCK, "seconds": seconds}
        self.advance(seconds)
        return {"mode": CONTROL_CLOCK, "seconds": seconds}

    # -- execution ----------------------------------------------------------

    def run(self):
        deadline = _Deadline(self.options["deadlineSeconds"], self.monotonic)
        try:
            self._observe(deadline)
        except _Stopped as stop:
            self.failure = stop.reason
        except Exception as error:  # noqa: BLE001 - retained, never reinterpreted
            self.failure = type(error).__name__
        cleanup = self._cleanup()
        return self._receipt(cleanup)

    def _guard(self, deadline, needed):
        if deadline.remaining() <= needed:
            raise _Stopped("deadline-reached")

    def _observe(self, deadline):
        for step in self.plan["operations"]:
            if step["phase"] == "cleanup":
                continue
            wait = step["waitSeconds"]
            self._guard(deadline, wait)
            waited = self._elapse(wait)
            response = self._dispatch(step)
            row = self._record(step, response, waited=waited)
            if not row["complete"]:
                raise _Stopped("incomplete-response")

    def _dispatch(self, step):
        slot = step["slot"]
        handler = self._HANDLERS.get(slot)
        if handler is not None:
            return handler(self, step)
        prefix, _, _ = slot.partition("/")
        if slot.startswith("preflight/absence/"):
            return self._get(step["role"])
        if slot.startswith("setup/create/"):
            response = self._commit(
                [self._write_marker(step["role"], "created", create=True)]
            )
            if response.get("code") == OK:
                self.created[step["role"]] = True
            return response
        if slot.startswith("readback/"):
            return self._get(step["role"])
        if slot.startswith("idle/begin/"):
            return self._open(step, {"readWrite": {}})
        if slot.startswith("idle/read/"):
            tag = slot.rsplit("/", 1)[1]
            return self._get(step["role"], self.tokens.get(tag))
        if slot.startswith(("finished/begin/", "retry/begin/")):
            tag = slot.rsplit("/", 1)[1]
            body = {"readOnly": {}} if tag == "j" else {"readWrite": {}}
            return self._open(step, body)
        if slot.startswith(("retry/rollback/", "finished/rollback/")):
            tag = slot.rsplit("/", 1)[1]
            return self._rollback(self.tokens[tag])
        if slot.startswith(("finished/commit/", "retry/commit/")):
            tag = slot.rsplit("/", 1)[1]
            return self._commit(
                [self._write_marker(step["role"], f"finished-{tag}")], self.tokens[tag]
            )
        raise ValueError(f"unhandled slot {prefix}: {slot}")

    def _open(self, step, options_body):
        response = self._begin(options_body)
        tag = step["opensTransaction"]
        token = (response.get("body") or {}).get("transaction")
        if response.get("code") == OK and token and tag:
            self.tokens[tag] = base64.b64decode(token)
        return response

    # -- individual case handlers ------------------------------------------

    def _lock_held(self, step):
        return self._commit([self._write_marker("locked-c", "out-of-band-blocked")])

    def _commit_before(self, step):
        return self._commit(
            [self._write_marker("locked-d", "committed-before-idle")], self.tokens["d"]
        )

    def _commit_after(self, step):
        return self._commit(
            [self._write_marker("locked-a", "committed-after-idle")], self.tokens["a"]
        )

    def _rollback_after(self, step):
        return self._rollback(self.tokens["b"])

    def _lock_released(self, step):
        return self._commit([self._write_marker("locked-a", "written-after-expiry")])

    def _release_c(self, step):
        return self._rollback(self.tokens["c"])

    def _rollback_after_begin(self, step):
        return self._rollback(self.tokens["e"])

    def _rollback_after_rollback(self, step):
        return self._rollback(self.tokens["e"])

    def _rollback_after_commit(self, step):
        return self._rollback(self.tokens["f"])

    def _retry_rolled_back(self, step):
        return self._open(
            step, {"readWrite": {"retryTransaction": _b64(self.tokens["g"])}}
        )

    def _retry_committed(self, step):
        return self._begin({"readWrite": {"retryTransaction": _b64(self.tokens["i"])}})

    def _retry_read_only(self, step):
        return self._begin({"readWrite": {"retryTransaction": _b64(self.tokens["j"])}})

    def _retry_unissued(self, step):
        token = plan_module.unissued_retry_token(self.options["nonce"])
        return self._begin({"readWrite": {"retryTransaction": _b64(token)}})

    def _retry_malformed(self, step):
        return self._begin({"readWrite": {"retryTransaction": "not base64!"}})

    _HANDLERS: ClassVar[dict] = {
        "idle/lock-held": _lock_held,
        "idle/commit-before": _commit_before,
        "idle/commit-after": _commit_after,
        "idle/rollback-after": _rollback_after,
        "idle/lock-released": _lock_released,
        "idle/release/c": _release_c,
        "finished/rollback-after-begin": _rollback_after_begin,
        "finished/rollback-after-rollback": _rollback_after_rollback,
        "finished/rollback-after-commit": _rollback_after_commit,
        "retry/rolled-back-previous": _retry_rolled_back,
        "retry/committed-previous": _retry_committed,
        "retry/read-only-previous": _retry_read_only,
        "retry/unissued-previous": _retry_unissued,
        "retry/malformed-previous": _retry_malformed,
    }

    # -- cleanup ------------------------------------------------------------

    def _cleanup(self):
        recovery = _Deadline(RECOVERY_SECONDS, self.monotonic)
        results = []
        for resource in self.plan["resources"]:
            role = resource["role"]
            results.append(self._recover_one(role, recovery))
        return results

    def _recover_one(self, role, recovery):
        entry = {
            "role": role,
            "path": self._path(role),
            "skipped": False,
            "complete": False,
            "absent": False,
            "failure": None,
        }
        if recovery.expired():
            entry.update(skipped=True, failure="recovery-deadline-reached")
            return entry
        read = self._get(role)
        entry["ownedRead"] = {
            "code": read.get("code"),
            "status": read.get("status"),
        }
        if read.get("code") == NOT_FOUND:
            entry.update(skipped=True, complete=True, absent=True)
            return entry
        if read.get("code") != OK:
            entry.update(skipped=True, failure="owned-read-incomplete")
            return entry
        document = read.get("body") or {}
        if not is_owned(document, self.options["ownerId"], role, self.options["nonce"]):
            entry.update(skipped=True, failure="ownership-not-proven")
            return entry
        delete = self._commit(
            [
                {
                    "delete": self._name(role),
                    "currentDocument": {"updateTime": document["updateTime"]},
                }
            ]
        )
        entry["delete"] = {"code": delete.get("code"), "status": delete.get("status")}
        if delete.get("code") != OK:
            entry["failure"] = "conditional-delete-refused"
            return entry
        absence = self._get(role)
        entry["absence"] = {"code": absence.get("code")}
        entry["absent"] = absence.get("code") == NOT_FOUND
        entry["complete"] = entry["absent"]
        if not entry["absent"]:
            entry["failure"] = "final-absence-not-proven"
        return entry

    # -- receipt ------------------------------------------------------------

    def _receipt(self, cleanup):
        observed = {row["caseId"]: row for row in self.rows if row["caseId"]}
        missing = [case["id"] for case in cases.CASES if case["id"] not in observed]
        unrecovered = [entry["role"] for entry in cleanup if not entry["complete"]]
        return {
            "kind": CONTRACT,
            "campaign": cases.CAMPAIGN,
            "casesDigest": cases.cases_digest(),
            "sourceDigest": plan_module.source_digest(),
            "target": self.options["target"],
            "timing": self.options["timing"],
            "projectId": self.options["projectId"],
            "database": self.options["database"],
            "documentPrefix": self.plan["documentPrefix"],
            "nonce": self.options["nonce"],
            "rows": self.rows,
            "cleanup": cleanup,
            "unrecovered": unrecovered,
            "missingCases": missing,
            "failure": self.failure,
            "complete": not missing and not unrecovered and self.failure is None,
            "requestCount": len(self.rows)
            + sum(
                1 + (1 if "delete" in e else 0) + (1 if "absence" in e else 0)
                for e in cleanup
                if "ownedRead" in e
            ),
        }


class _Stopped(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


CASE_BY_ID = {case["id"]: case for case in cases.CASES}


def collect(options, transport, **kwargs):
    """Run one bounded collection and return its receipt."""
    prepared = validate_collector_options(options)
    plan = plan_module.compile_plan(
        prepared["nonce"],
        prepared["ownerId"],
        project=prepared["projectId"],
        database=prepared["database"],
    )
    return Collection(options, plan, transport, **kwargs).run()
