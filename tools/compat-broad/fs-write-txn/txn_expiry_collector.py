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
import datetime
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

#: Fixed stand-ins for the identities that differ between any two runs. The
#: recorded body keeps its values and types; only the run-bound resource names
#: and the instants are replaced, so two receipts stay comparable.
RESOURCE_SLOT = "<fireemu:o3-txn-expiry:resource>"
TOKEN_SLOT = "<fireemu:o3-txn-expiry:token>"
OWNER_SLOT = "<fireemu:o3-txn-expiry:owner>"

#: Document keys that carry an instant rather than a value.
INSTANT_KEYS = ("updateTime", "createTime", "readTime")

LOOPBACK_HOSTS = ("127.0.0.1", "::1", "localhost")
PRODUCTION_HOST = "firestore.googleapis.com"

NOT_FOUND = 5
ABORTED = 10
INVALID_ARGUMENT = 3
ALREADY_EXISTS = 6
PERMISSION_DENIED = 7
UNAUTHENTICATED = 16
OK = 0

#: A refusal that says the caller may not act at all. Sending more requests
#: after one of these cannot help and may make things worse, so recovery stops
#: sending, but it still records what it was responsible for.
AUTHORITY_REFUSALS = (PERMISSION_DENIED, UNAUTHENTICATED)

#: Steps whose refusal is not a precondition failure. The contention holder is
#: released on a best-effort basis; the campaign has already observed what it
#: needed from it by then.
BEST_EFFORT_SLOTS = ("idle/release/c",)

#: Recovery gets its own deadline so an exhausted observation budget still
#: leaves room to give owned documents back.
RECOVERY_SECONDS = 180

#: A wall-clock wait is served in bounded steps rather than one long sleep, so
#: the run records progress and can be interrupted between steps. This records
#: progress; it does not make a killed process resume.
CHECKPOINT_SECONDS = 5


def _instant(seconds):
    return (
        datetime.datetime.fromtimestamp(seconds, tz=datetime.timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


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


def _decode_token(token):
    """Decode a transaction token, or None when it cannot be used as one."""
    if not isinstance(token, str) or not token:
        return None
    try:
        decoded = base64.b64decode(token, validate=True)
    except (ValueError, TypeError):
        return None
    return decoded or None


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
        wall=time.time,
        checkpoint=None,
    ):
        self.options = validate_collector_options(options)
        self.plan = plan
        self.transport = transport
        self.sleeper = sleeper or time.sleep
        self.advance = advance
        self.monotonic = monotonic
        self.wall = wall
        self.checkpoint = checkpoint
        self.rows = []
        self.tokens = {}
        self.open_tokens = {}
        self.locked_at = {}
        self.virtual_elapsed = 0.0
        self.checkpoints = []
        self.created = {}
        self.established = {}
        self.update_times = {}
        self.preconditions = []
        self.failure_sites = []
        self.authority_refusal = None
        self.request_count = 0
        self.failure = None
        self.started_at = None
        self.finished_at = None
        self.current_timeout = plan_module.DEFAULT_REQUEST_TIMEOUT_SECONDS
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
            "maxRequestBytes": plan_module.MAX_REQUEST_BYTES,
            "timeoutSeconds": self.current_timeout,
        }
        self.request_count += 1
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
        response = self._send("GetDocument", None, role=role, query=query)
        if response.get("code") != OK:
            return response
        body = response.get("body")
        if not isinstance(body, dict) or not body.get("name"):
            # A successful read has to return the document. Without one the
            # reply proves neither presence nor absence, so it is an incomplete
            # response rather than evidence that the document exists.
            return {**response, "complete": False, "incomplete": "get-without-document"}
        return response

    def _blocked(self, reason):
        """A request the collector refuses to send, recorded as incomplete."""
        return {
            "code": None,
            "status": None,
            "message": None,
            "complete": False,
            "blocked": reason,
        }

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

    # -- observed document bodies -------------------------------------------

    def _scrub(self, value):
        """Replace this run's identities inside a recorded value."""
        if isinstance(value, dict):
            return {key: self._scrub(entry) for key, entry in value.items()}
        if isinstance(value, list):
            return [self._scrub(entry) for entry in value]
        if not isinstance(value, str):
            return value
        for needle, slot in (
            (owner_marker(self.options["ownerId"]), OWNER_SLOT),
            (self.plan["documentPrefix"], RESOURCE_SLOT),
            (self.options["nonce"], TOKEN_SLOT),
            (self.options["ownerId"], OWNER_SLOT),
            (self.options["projectId"], RESOURCE_SLOT),
        ):
            if needle:
                value = value.replace(needle, slot)
        return value

    def _version_ordinal(self, role, instant):
        """Where this instant sits in the versions observed for one document.

        The instant itself is volatile, but whether it changed between two
        readings is exactly the relation a post-state comparison needs, and an
        ordinal carries that across two runs.
        """
        seen = self.update_times.setdefault(role, [])
        if instant is None:
            return None
        if instant not in seen:
            seen.append(instant)
        return seen.index(instant)

    def _observed_document(self, role, response):
        code = response.get("code")
        if code == NOT_FOUND:
            return {"exists": False, "code": code}
        if code != OK:
            return {"exists": None, "code": code}
        body = response.get("body") or {}
        return {
            "exists": True,
            "code": code,
            "name": RESOURCE_SLOT,
            "updateTime": TOKEN_SLOT,
            "updateTimeOrdinal": self._version_ordinal(role, body.get("updateTime")),
            "fields": self._scrub(body.get("fields") or {}),
        }

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
        for key in ("blocked", "incomplete"):
            if response.get(key):
                row[key] = response[key]
        if response.get("acquisition"):
            row["acquisition"] = response["acquisition"]
        if step.get("verifiesCase"):
            row["verifiesCase"] = step["verifiesCase"]
        if step["rpc"] == "GetDocument" and step["role"]:
            row["document"] = self._observed_document(step["role"], response)
        tag = step.get("idleOfTransaction")
        if tag is not None and tag in self.locked_at:
            row["idleSeconds"] = self._campaign_now() - self.locked_at[tag]
            row["idleOfTransaction"] = tag
        elif tag is not None:
            row["idleSeconds"] = None
            row["idleOfTransaction"] = tag
        if step["caseId"]:
            case = CASE_BY_ID[step["caseId"]]
            row["expectedLocal"] = dict(case["expectedLocal"])
        self.rows.append(row)
        return row

    def _campaign_now(self):
        """The coordinate the campaign measures idle time in.

        Wall-clock runs measure real monotonic seconds. Control-clock runs
        measure the virtual seconds the emulator actually reported advancing.
        Neither is the plan's requested number.
        """
        if self.options["timing"] == WALL_CLOCK:
            return self.monotonic()
        return self.virtual_elapsed

    def _elapse(self, seconds, slot):
        if seconds <= 0:
            return None
        started_monotonic = self.monotonic()
        started_wall = self.wall()
        if self.options["timing"] == WALL_CLOCK:
            steps = self._wall_wait(seconds, slot, started_monotonic)
            measured = self.monotonic() - started_monotonic
        else:
            steps = 1
            reported = self.advance(seconds)
            measured = None if reported is None else float(reported)
            if measured is not None:
                self.virtual_elapsed += measured
        return {
            "mode": self.options["timing"],
            "requestedSeconds": seconds,
            "measuredSeconds": measured,
            "startedAt": _instant(started_wall),
            "endedAt": _instant(self.wall()),
            "wallSeconds": self.wall() - started_wall,
            "checkpoints": steps,
        }

    def _wall_wait(self, seconds, slot, started):
        """Wait in bounded steps, recording a checkpoint after each one."""
        steps = 0
        while True:
            remaining = seconds - (self.monotonic() - started)
            if remaining <= 0:
                return steps
            step = min(CHECKPOINT_SECONDS, remaining)
            self.sleeper(step)
            steps += 1
            record = {
                "slot": slot,
                "step": steps,
                "elapsedSeconds": self.monotonic() - started,
                "requestedSeconds": seconds,
                "at": _instant(self.wall()),
            }
            self.checkpoints.append(record)
            if self.checkpoint is not None:
                self.checkpoint(record)
            if steps > 2 * (seconds / CHECKPOINT_SECONDS) + 10:
                # The injected clock is not advancing; stop rather than spin.
                return steps

    # -- execution ----------------------------------------------------------

    def run(self):
        deadline = _Deadline(self.options["deadlineSeconds"], self.monotonic)
        try:
            self._observe(deadline)
        except _Stopped as stop:
            self.failure = stop.reason
        except Exception as error:  # noqa: BLE001 - retained, never reinterpreted
            self.failure = type(error).__name__
        try:
            cleanup, releases = self._cleanup()
        except Exception as error:  # noqa: BLE001 - a receipt is owed regardless
            self._note_failure("cleanup", type(error).__name__)
            cleanup, releases = self._unattempted_cleanup(type(error).__name__), []
        return self._receipt(cleanup, releases)

    def _unattempted_cleanup(self, reason):
        """Entries for a recovery that could not run at all.

        The receipt still has to say which documents this run is answerable
        for, so a caller reading only the receipt sees the same residue a
        successful pass would have cleared.
        """
        return [
            {
                "role": resource["role"],
                "path": self._path(resource["role"]),
                "skipped": True,
                "complete": False,
                "absent": False,
                "createdByThisRun": resource["role"] in self.established,
                "creationEvidence": self.established.get(resource["role"]),
                "failure": reason,
            }
            for resource in self.plan["resources"]
        ]

    def _guard(self, deadline, needed):
        if deadline.remaining() <= needed:
            raise _Stopped("deadline-reached")

    def _observe(self, deadline):
        self.started_at = _instant(self.wall())
        for step in self.plan["operations"]:
            if step["phase"] == "cleanup":
                continue
            wait = step["waitSeconds"]
            self._guard(deadline, wait + step["timeoutSeconds"])
            waited = self._elapse(wait, step["slot"])
            self.current_timeout = step["timeoutSeconds"]
            response = self._dispatch(step)
            row = self._record(step, response, waited=waited)
            closes = step["closesTransaction"]
            if closes and response.get("code") == OK:
                self.open_tokens.pop(closes, None)
            if step["slot"].startswith("idle/read/"):
                self.locked_at[step["slot"].rsplit("/", 1)[1]] = self._campaign_now()
            if not row["complete"]:
                self._note_failure(step["slot"], "incomplete-response", row)
                raise _Stopped("incomplete-response")
            failure = self._precondition(step, response)
            if failure is not None:
                row["precondition"] = failure
                self._note_failure(step["slot"], failure, row)
                raise _Stopped("precondition-not-established")

    def _note_failure(self, site, reason, detail=None):
        """Record where the run stopped being able to do what it promised."""
        entry = {"site": site, "reason": reason}
        if isinstance(detail, dict):
            for key in ("blocked", "incomplete", "role", "caseId"):
                if detail.get(key):
                    entry[key] = detail[key]
        self.failure_sites.append(entry)

    def _precondition(self, step, response):
        """Judge a setup step's own success, separately from any semantics.

        Only steps without a case id are preconditions. A case's observed code
        is the thing the campaign is here to record and is never read as a
        failure of the run. A precondition that did not hold means the workspace
        this run promised to own was never established, so nothing after it may
        mutate anything.
        """
        if step["caseId"] is not None or step["slot"] in BEST_EFFORT_SLOTS:
            return None
        slot = step["slot"]
        code = response.get("code")
        if slot.startswith("preflight/absence/"):
            # A preflight finding never stops the run by itself. The only write
            # still ahead of it is the create-only commit, which cannot damage
            # whatever is there, and whose refusal is the authoritative proof.
            role = step["role"]
            if code == NOT_FOUND:
                self._record_precondition(role, absence=True)
            elif code == OK:
                self._record_precondition(
                    role, absence=False, finding="document-exists"
                )
            else:
                self._record_precondition(
                    role, absence=None, finding="absence-not-proven"
                )
            return None
        if slot.startswith("setup/create/"):
            role = step["role"]
            observed = self._record_precondition(role)
            if code == OK:
                if observed.get("absence") is False:
                    # The preflight saw a document and the create-only commit
                    # was accepted anyway. One of the two is wrong, so this run
                    # cannot claim it owns anything here.
                    self._record_precondition(role, created=False)
                    return "absence-contradicted-by-accepted-create"
                body = response.get("body") or {}
                results = body.get("writeResults") or [{}]
                self.established[role] = {
                    "role": role,
                    "createdAt": _instant(self.wall()),
                    "updateTime": (results[0] or {}).get("updateTime"),
                }
                self.created[role] = True
                self._version_ordinal(role, self.established[role]["updateTime"])
                self._record_precondition(role, created=True)
                return None
            self._record_precondition(role, created=False)
            if code == ALREADY_EXISTS:
                return "conditional-create-refused-already-exists"
            return "conditional-create-refused"
        if slot.startswith(("readback/", "verify/")):
            # A readback records what it saw. An absent or unreadable document
            # is an observation about the case before it, not a setup failure.
            return None
        if code == OK:
            return None
        return f"setup-step-refused:{slot}"

    def _record_precondition(self, role, **fields):
        for entry in self.preconditions:
            if entry["role"] == role:
                entry.update(fields)
                return entry
        entry = {"role": role, "absence": None, "created": False}
        entry.update(fields)
        self.preconditions.append(entry)
        return entry

    def _dispatch(self, step):
        slot = step["slot"]
        if (
            step["rpc"] == "Commit"
            and step["role"]
            and not slot.startswith("setup/create/")
            and step["role"] not in self.established
        ):
            # This run never proved it created this document, so it has no
            # standing to write to it. The request is not sent at all.
            return self._blocked("precondition-not-established")
        handler = self._HANDLERS.get(slot)
        if handler is not None:
            return handler(self, step)
        prefix, _, _ = slot.partition("/")
        if slot.startswith("preflight/absence/"):
            return self._get(step["role"])
        if slot.startswith("setup/create/"):
            return self._commit(
                [self._write_marker(step["role"], "created", create=True)]
            )
        if slot.startswith(("readback/", "verify/")):
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
        """Begin a transaction and take responsibility for whatever it issued.

        A case may expect the request to be refused. Whether it was is a result
        to record, not a reason to look away: a transaction the backend really
        did start is live, holds whatever it holds, and has to be released
        during recovery. So every fully successful begin is registered, and the
        expectation only classifies the row afterwards.
        """
        response = self._begin(options_body)
        if response.get("code") != OK:
            return response
        tag = step["opensTransaction"] or f"unplanned/{step['slot']}"
        decoded = _decode_token((response.get("body") or {}).get("transaction"))
        if decoded is None:
            # A success-shaped reply without a usable token has not acquired
            # anything, and it may still have started a transaction this run can
            # never name. That is an incomplete response, not an acquisition.
            return {
                **response,
                "complete": False,
                "incomplete": "begin-without-usable-token",
            }
        self.tokens[tag] = decoded
        self.open_tokens[tag] = decoded
        expected = self._expected_code(step) == OK
        return {
            **response,
            "acquisition": {
                "transaction": tag,
                "tokenRegistered": True,
                "expected": expected,
                "planned": bool(step["opensTransaction"]),
            },
        }

    def _expected_code(self, step):
        case = CASE_BY_ID.get(step["caseId"]) if step["caseId"] else None
        return case["expectedLocal"]["code"] if case else OK

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
        return self._open(
            step, {"readWrite": {"retryTransaction": _b64(self.tokens["i"])}}
        )

    def _retry_read_only(self, step):
        return self._open(
            step, {"readWrite": {"retryTransaction": _b64(self.tokens["j"])}}
        )

    def _retry_unissued(self, step):
        token = plan_module.unissued_retry_token(self.options["nonce"])
        return self._open(step, {"readWrite": {"retryTransaction": _b64(token)}})

    def _retry_malformed(self, step):
        return self._open(step, {"readWrite": {"retryTransaction": "not base64!"}})

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
        self.current_timeout = plan_module.DEFAULT_REQUEST_TIMEOUT_SECONDS
        recovery = _Deadline(RECOVERY_SECONDS, self.monotonic)
        releases = self._release_transactions(recovery)
        results = []
        for resource in self.plan["resources"]:
            role = resource["role"]
            try:
                results.append(self._recover_one(role, recovery))
            except Exception as error:  # noqa: BLE001 - one document, not the run
                # One document failing to come back says nothing about the
                # others, and the run still owes every one of them an attempt.
                reason = type(error).__name__
                self._note_failure(f"cleanup/{role}", reason)
                results.append(
                    {
                        "role": role,
                        "path": self._path(role),
                        "skipped": False,
                        "complete": False,
                        "absent": False,
                        "createdByThisRun": role in self.established,
                        "creationEvidence": self.established.get(role),
                        "failure": reason,
                    }
                )
        self.finished_at = _instant(self.wall())
        return results, releases

    def _release_transactions(self, recovery):
        """Roll back every transaction still open before touching a document.

        A conditional delete is an out-of-band write. Against a document a live
        transaction still locks it is refused, so releasing first is what makes
        recovery possible at all. A refusal here is recorded and does not stop
        the remaining releases.
        """
        releases = []
        for tag in sorted(self.open_tokens):
            entry = {"transaction": tag, "released": False, "skipped": False}
            if self.authority_refusal is not None:
                entry["skipped"] = True
                entry["failure"] = "authority-refused-earlier"
                releases.append(entry)
                continue
            if recovery.expired():
                entry["skipped"] = True
                entry["failure"] = "recovery-deadline-reached"
                releases.append(entry)
                continue
            try:
                response = self._rollback(self.open_tokens[tag])
            except Exception as error:  # noqa: BLE001 - retained, never reinterpreted
                entry["failure"] = type(error).__name__
                self._note_failure(f"release/{tag}", entry["failure"])
                releases.append(entry)
                continue
            code = response.get("code")
            if code in AUTHORITY_REFUSALS:
                self.authority_refusal = response.get("status") or code
                self._note_failure(f"release/{tag}", "authority-refused")
                entry["code"] = code
                entry["status"] = response.get("status")
                entry["message"] = response.get("message")
                entry["failure"] = "rollback-refused-authority"
                releases.append(entry)
                continue
            entry["code"] = code
            entry["status"] = response.get("status")
            entry["message"] = response.get("message")
            idle = None
            if tag in self.locked_at:
                idle = self._campaign_now() - self.locked_at[tag]
            entry["idleSeconds"] = idle
            if code == OK:
                entry["released"] = True
            elif code == ABORTED:
                # ABORTED is only proof of release when the transaction really
                # did run out of time. The same code also means contention,
                # which says nothing about whether this transaction still holds
                # its locks, so it must not be read as a successful release.
                expired = idle is not None and idle >= cases.DECLARED_IDLE_LIMIT_SECONDS
                entry["released"] = expired
                entry["expiryProven"] = expired
                if not expired:
                    entry["failure"] = "rollback-aborted-without-proven-expiry"
            else:
                entry["released"] = False
                entry["failure"] = "rollback-refused"
            releases.append(entry)
        for entry in releases:
            if entry["released"]:
                self.open_tokens.pop(entry["transaction"], None)
        return releases

    def _recover_one(self, role, recovery):
        evidence = self.established.get(role)
        entry = {
            "role": role,
            "path": self._path(role),
            "skipped": False,
            "complete": False,
            "absent": False,
            "createdByThisRun": evidence is not None,
            "creationEvidence": evidence,
            "failure": None,
        }
        if evidence is None:
            # Recovery is bound to what this run created, not to what the
            # document currently says. A marker can be written by a mutation
            # this run should never have made; a creation record cannot.
            entry.update(skipped=True, failure="not-created-by-this-run")
            return entry
        if self.authority_refusal is not None:
            # The caller has already been told it may not act here. Sending
            # more requests cannot help, but this run still created the
            # document, so it stays on the unrecovered list.
            entry.update(skipped=True, failure="authority-refused-earlier")
            return entry
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
        if read.get("code") in AUTHORITY_REFUSALS:
            self.authority_refusal = read.get("status") or read.get("code")
            self._note_failure(f"cleanup/{role}", "authority-refused")
            entry.update(skipped=True, failure="owned-read-refused-authority")
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
        if delete.get("code") in AUTHORITY_REFUSALS:
            self.authority_refusal = delete.get("status") or delete.get("code")
            self._note_failure(f"cleanup/{role}", "authority-refused")
            entry["failure"] = "conditional-delete-refused-authority"
            return entry
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

    def _receipt(self, cleanup, releases):
        observed = {row["caseId"]: row for row in self.rows if row["caseId"]}
        missing = [case["id"] for case in cases.CASES if case["id"] not in observed]
        unrecovered = [
            entry["role"]
            for entry in cleanup
            if entry.get("createdByThisRun") and not entry["complete"]
        ]
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
            "preconditions": self.preconditions,
            "cleanup": cleanup,
            "transactionReleases": releases,
            "openTransactions": sorted(self.open_tokens),
            "checkpoints": self.checkpoints,
            "startedAt": self.started_at,
            "finishedAt": self.finished_at,
            "unrecovered": unrecovered,
            "missingCases": missing,
            "failureSites": self.failure_sites,
            "authorityRefusal": self.authority_refusal,
            "failure": self.failure,
            "complete": (
                not missing
                and not unrecovered
                and not self.open_tokens
                and self.failure is None
            ),
            # Counted where the requests are actually sent, so releases and
            # any request that failed are included and a request the collector
            # refused to send is not.
            "requestCount": self.request_count,
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
