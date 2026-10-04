"""Closed shared-Gate facade for the transaction expiry campaign.

The shared Gate admits a request only when it digests to the frozen slot it is
dispatched into. This campaign's requests carry two values no plan can freeze:
the transaction tokens the backend issues at run time, and the update time a
recovery read observes before the conditional delete that binds it. The frozen
plan therefore carries `$binding:<name>` placeholders in those positions, and
this facade resolves them the way the Auth-list Gate does: a value observed by
this Gate in one of its own journaled responses may be installed as a binding,
and a later request is normalized back to the placeholder only where it carries
exactly that value. A request that names a token this run never received, or a
version this run never read, is refused as outside the closed scenario.

The facade also settles the creation outcome of requests the shared Gate cannot
classify on its own. The Gate treats every body-carrying request as able to
create a document, which is the safe default; a `BeginTransaction`, a
`Rollback` and a transactional update of a document this run already created
cannot bring a new document into existence, and leaving them "unknown" would
make every run unfinishable. Each is settled here only against a typed answer
and only for the exact request shapes the plan freezes. A lost answer stays
unknown and keeps the reservation held, which is the conservative outcome.

Nothing here grants authority. The Gate's own admission, budget, deadline and
ownership rules run unchanged in the base class.
"""

from __future__ import annotations

import base64
import copy
import os
import re
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[0]))
sys.path.insert(0, str(HERE))

import shared_gate
import txn_expiry_cases as cases
import txn_expiry_collector as collector
import txn_expiry_plan as plan_module
from broad_contract import digest
from shared_gate import ZERO_WIRE_REASON, _save, job_schedule, unconfirmed_creates

JOB = "txn-expiry-04"
PLACEHOLDER = "$binding:"
_BINDING_NAME = re.compile(r"^(txn|version):[A-Za-z0-9/_.-]{1,96}$")

#: Observation request kinds and the recovery kinds, by what they may do.
OBSERVATION_KINDS = (
    "preflight-read",
    "create",
    "begin",
    "read-in-transaction",
    "readback",
    "commit-update",
    "rollback",
)
RECOVERY_KINDS = ("release", "owned-read", "conditional-delete", "typed-absence")
#: Recovery kinds the shared dispatch cannot admit because their path is not
#: an owned document; the facade admits them itself.
RPC_RECOVERY_KINDS = ("release", "conditional-delete")
#: Every recovery kind may be consumed without a wire call when the run has
#: nothing to send for it: a transaction that is not open, a document that is
#: already gone, or a document whose cleanup the collector abandoned. A skip
#: records that nothing was sent; it never records a proof, so a skipped
#: absence read leaves its document unproven and the run unreleasable.
SKIPPABLE_RECOVERY_KINDS = RECOVERY_KINDS
#: HTTP statuses whose typed Firestore error envelope proves the request was
#: refused as a whole. A commit is atomic, so a refusal applied nothing. 5xx
#: answers are deliberately absent: they can follow an applied write.
REFUSAL_STATUSES = (400, 401, 403, 404, 409, 429)


def canonical_token(value):
    """The canonical base64 form of an issued transaction token, or None."""
    decoded = collector._decode_token(value)
    if decoded is None:
        return None
    return base64.b64encode(decoded).decode("ascii")


def _text(value):
    return isinstance(value, str) and bool(value) and not value.startswith(PLACEHOLDER)


def _error_envelope(status, body):
    """Whether a body is exactly one typed Firestore error for this status."""
    if type(status) is not int or status not in REFUSAL_STATUSES:
        return False
    if not isinstance(body, dict) or set(body) != {"error"}:
        return False
    error = body["error"]
    return (
        isinstance(error, dict)
        and type(error.get("code")) is int
        and error["code"] == status
        and error.get("status") in collector.CANONICAL_STATUS
        and error["status"] != "OK"
    )


def validate_plan(plan):
    """The closed shape this facade hosts, checked before any dispatch."""
    if (
        not isinstance(plan, dict)
        or plan.get("contract") != "shared-local-v2"
        or plan.get("campaignId") != cases.CAMPAIGN
        or not isinstance(plan.get("nonce"), str)
        or not isinstance(plan.get("ownerId"), str)
        or plan_module.OWNER_PATTERN.match(plan["ownerId"]) is None
        or set(plan.get("jobs", {})) != {JOB}
        or plan.get("ownershipMarker") != {"field": "nonce", "binding": "nonce"}
    ):
        raise ValueError("closed transaction expiry Gate plan required")
    job = plan["jobs"][JOB]
    if job_schedule(job) is None:
        raise ValueError("a declared schedule is required")
    for phase, kinds in (
        ("observation", OBSERVATION_KINDS),
        ("recovery", RECOVERY_KINDS),
    ):
        for operation in job[phase]:
            if (
                not isinstance(operation, dict)
                or operation.get("kind") not in kinds
                or not isinstance(operation.get("site"), str)
                or operation.get("service") != "firestore"
                or operation.get("method") not in ("GET", "POST")
            ):
                raise ValueError("closed transaction expiry Gate plan required")
            binds = operation.get("binds")
            if binds is not None and _BINDING_NAME.match(binds) is None:
                raise ValueError("closed transaction expiry Gate plan required")
    for operation in job["recovery"]:
        _validate_recovery_shape(operation, job["resources"])
    return plan


def _delete_body(resource, version):
    return {
        "writes": [{"delete": resource, "currentDocument": {"updateTime": version}}]
    }


def _validate_recovery_shape(operation, resources):
    """A recovery slot names an assigned document in its request, not only in
    its annotation: a delete body must delete exactly its resource, and a
    document read must read exactly its resource."""
    kind = operation["kind"]
    resource = operation.get("resource")
    if kind == "release":
        if operation.get("method") != "POST" or set(operation.get("body", {})) != {
            "transaction"
        }:
            raise ValueError("closed transaction expiry Gate plan required")
        return
    if resource not in resources:
        raise ValueError("recovery slot names an unassigned resource")
    if kind == "conditional-delete":
        binds_from = operation.get("bindsFrom")
        if (
            operation.get("method") != "POST"
            or not isinstance(binds_from, str)
            or _BINDING_NAME.match(binds_from) is None
            or operation.get("body") != _delete_body(resource, PLACEHOLDER + binds_from)
        ):
            raise ValueError("conditional delete must delete exactly its resource")
    elif operation.get("method") != "GET" or operation.get("path") != "/v1/" + resource:
        raise ValueError("recovery read must read exactly its resource")


def owned_document(body, plan, resource):
    """Whether a read answer is this run's own document at the requested name."""
    if not isinstance(body, dict) or body.get("name") != resource:
        return False
    role = resource.rsplit("/", 1)[-1]
    return collector.is_owned(body, plan["ownerId"], role, plan["nonce"])


class TxnGate(shared_gate.Gate):
    """The shared Gate with this campaign's bindings and settled outcomes."""

    def __init__(self, path, job):
        super().__init__(path, job)
        if job != JOB:
            raise ValueError("closed transaction expiry job required")
        self.plan = validate_plan(self.snapshot()["plan"])
        self.bindings = {}
        # Only a value this Gate observed in one of its own journaled responses
        # may become a binding; the coordinator can install, never invent.
        self._observed_bindings = {}

    # -- bindings ------------------------------------------------------------

    def observed(self, name):
        """The value this Gate observed for one binding, if any."""
        return self._observed_bindings.get(name)

    def bind(self, name, value):
        if (
            not _text(name)
            or _BINDING_NAME.match(name) is None
            or not _text(value)
            or self._observed_bindings.get(name) != value
        ):
            raise ValueError("binding must come from this run's validated response")
        if name in self.bindings and self.bindings[name] != value:
            raise ValueError("a binding is immutable once installed")
        self.bindings[name] = value

    def _template(self, value, declared):
        """Normalize a runtime request onto its frozen slot, placeholder by placeholder.

        Resolution is by the declared binding name at each position, never by
        reverse lookup of an equal value, so a token that happens to equal
        another transaction's cannot move the request to that slot.
        """
        if isinstance(declared, str) and declared.startswith(PLACEHOLDER):
            name = declared.removeprefix(PLACEHOLDER)
            if (
                name not in self.bindings
                or type(value) is not str
                or value != self.bindings[name]
            ):
                raise ValueError("runtime binding differs from the frozen slot")
            return declared
        if isinstance(value, dict) and isinstance(declared, dict):
            return {
                key: self._template(item, declared.get(key))
                for key, item in value.items()
            }
        if (
            isinstance(value, list)
            and isinstance(declared, list)
            and len(value) == len(declared)
        ):
            return [
                self._template(item, expected)
                for item, expected in zip(value, declared, strict=True)
            ]
        return copy.deepcopy(value)

    # -- admission -----------------------------------------------------------

    def declared_slot(self, recovery):
        """The frozen operation the next dispatch of this job must match."""
        state = self.snapshot()
        phase = "recovery" if recovery else "observation"
        index = state["jobs"][self.job][phase]
        operations = self.plan["jobs"][self.job][phase]
        if index >= len(operations):
            raise ValueError("scenario request capacity")
        return index, operations[index]

    def dispatch(self, operation, recovery, send):
        if not isinstance(operation, dict):
            raise ValueError("closed request operation required")  # noqa: TRY004 -- admission boundary collapses malformed input to one refusal class
        _index, declared = self.declared_slot(recovery)
        normalized = self._template(operation, declared)
        if recovery and declared["kind"] in RPC_RECOVERY_KINDS:
            if declared["kind"] == "conditional-delete":
                self._admit_delete(declared, normalized)
            return self._dispatch_rpc_recovery(normalized, send)
        # The base class rechecks the slot, PID, stop state and budgets under
        # its lock. Recording below runs inside that same lock.
        return super().dispatch(normalized, recovery, send)

    def _dispatch_rpc_recovery(self, operation, send):
        """Admit one recovery rollback or delete-carrying Commit.

        The shared Gate's recovery phase admits only operations whose path is
        an owned document: a read, or a `DELETE` whose version it resolved
        itself and whose document is byte-identical to its creation. This
        campaign's recovery has to roll back transactions, which is an RPC on
        the database, and delete documents it deliberately modified, which it
        does with a Commit bound to the version its own ownership read
        observed. Neither fits that shape, so the two are admitted here under
        the same rules the shared dispatch applies to a recovery slot: the
        claimed job, no in-flight or refused-credential state, the frozen
        schedule order, the exact frozen request, the recovery deadline, the
        rate interval, the request and cost budgets, and a journal entry
        written before the wire and settled after it. Neither shape can
        create a document, so no creation outcome is tracked.
        """
        with self.locked() as state:
            job, plan = state["jobs"][self.job], state["plan"]
            if (
                job["pid"] != os.getpid()
                or job["complete"]
                or state["coordinatorInflight"]
                or state.get("credentialRejected")
                or state["coordinatorDone"] != plan.get("coordinatorRequests", 0)
                or any(other["inflight"] for other in state["jobs"].values())
                or state.get("noDataAbort") is not None
            ):
                raise ValueError("job or environment stopped/uncertain")
            management = plan.get("management", {})
            if management.get("dispatchKind") == "closed-v1":
                expected_management = [
                    "observation:" + entry["id"]
                    for entry in management.get("observation", [])
                ]
                events = state["managementEvents"][: len(expected_management)]
                if (
                    state["managementUsed"][: len(expected_management)]
                    != expected_management
                    or len(events) != len(expected_management)
                    or any(
                        event.get("completed") is not True
                        or type(event.get("status")) is not int
                        or not 200 <= event["status"] < 300
                        for event in events
                    )
                    or any(
                        identity.startswith("recovery:")
                        for identity in state["managementUsed"]
                    )
                ):
                    raise ValueError(
                        "closed management preflight incomplete or postflight begun"
                    )
            operations = plan["jobs"][self.job]["recovery"]
            index = job["recovery"]
            if index >= len(operations):
                raise ValueError("scenario request capacity")
            schedule = job_schedule(plan["jobs"][self.job])
            cursor = job["scheduleDone"]
            if job.get("stopReason") is not None:
                while (
                    cursor < len(schedule)
                    and schedule[cursor]["phase"] == "observation"
                ):
                    cursor += 1
                    job["skippedByStop"] += 1
                job["scheduleDone"] = cursor
            slot = schedule[cursor] if cursor < len(schedule) else None
            if slot is None or slot["phase"] != "recovery" or slot["index"] != index:
                raise ValueError("dispatch outside the frozen execution schedule")
            expected = operations[index]
            if expected.get("kind") not in RPC_RECOVERY_KINDS or digest(
                operation
            ) != digest(expected):
                raise ValueError("request outside closed scenario")
            seconds = shared_gate.slot_seconds(slot, shared_gate.request_seconds(plan))
            now = time.monotonic()
            delay = max(0, state["lastSent"] + plan["intervalSeconds"] - now)
            deadline = state["started"] + plan["wallSeconds"]
            cost = plan["requestCostMicrousd"]
            remaining = state["reservedRecovery"] - 1
            if (
                now + delay + seconds > deadline
                or remaining < 0
                or state["costMicrousd"] + cost * (1 + remaining) > plan["costMicrousd"]
            ):
                raise ValueError("global phase/time/cost capacity")
            time.sleep(delay)
            if time.monotonic() + seconds > deadline:
                raise ValueError("deadline after rate wait")
            state["lastSent"] = time.monotonic()
            state["total"] += 1
            state["recovery"] += 1
            state["reservedRecovery"] = remaining
            state["costMicrousd"] += cost
            job["recovery"] += 1
            job["scheduleDone"] += 1
            job["inflight"] = True
            event = {
                "job": self.job,
                "phase": "recovery",
                "index": index,
                "started": state["lastSent"],
                "requestDigest": digest(operation),
                "service": operation["service"],
                "method": operation["method"],
                "completed": False,
            }
            state["events"].append(event)
            _save(
                self.path, state
            )  # crash spends capacity and retains uncertain ownership
            try:
                result = send()
            except Exception as error:
                job["stopped"] = True
                event["failure"] = type(error).__name__
                raise
            else:
                status, body = result
                event.update(status=status, responseDigest=digest(body), completed=True)
                if type(status) is not int:
                    job["stopped"] = True
                    raise ValueError("typed HTTP status required")
                # The shared path clears `absent`/`absenceProofs` for the
                # resource before a recovery request; a delete here can only
                # follow an owned 200 read, which already cleared them, and the
                # final typed-absence read re-records the proof afterwards.
                self._record_response(state, operation, True, event, status, body)
                job["captures"][str(index)] = self._recovery_capture(
                    operation, status, body
                )
                return result
            finally:
                interruption = sys.exc_info()[0]
                job["inflight"] = interruption is not None and not issubclass(
                    interruption, Exception
                )
                event["ended"] = time.monotonic()
                state["lastSent"] = event["ended"]
                _save(self.path, state)

    def _admit_delete(self, declared, normalized):
        """A conditional delete binds the version an owned read of this run observed.

        The template has already required the request to carry the bound
        version. What remains is that the request itself deletes exactly the
        assigned document, that the document was created by this run, and
        that the binding was installed from an owned readback, which is the
        only path that records it.
        """
        state = self.snapshot()
        job = state["jobs"][self.job]
        resource = declared.get("resource")
        binding = declared.get("bindsFrom") or ""
        if resource not in job["resources"] or normalized.get("body") != _delete_body(
            resource, PLACEHOLDER + binding
        ):
            raise ValueError("conditional delete must delete exactly its resource")
        if (
            resource not in job.get("creationProofs", {})
            or not binding
            or binding not in self.bindings
            or self.bindings[binding] != self._observed_bindings.get(binding)
        ):
            raise ValueError("cleanup requires journaled creation ownership/version")

    def skip_recovery_slot(self, operation, reason):
        """Consume one recovery slot the run has nothing to send for.

        The shared Gate refuses to skip a slot whose request could create a
        document, and it classifies every body-carrying request that way. A
        rollback and a delete-only commit cannot create anything, and the
        typed-absence read is bodyless. Skipping one of them records that this
        run sent nothing for the slot; it never records a proof. A skipped
        absence read therefore leaves its document without a proof, and the
        Gate and the Ledger refuse to release on that, which is the point.

        Admitted only when no creating request is still unconfirmed and when
        the slot is the next one in the frozen order, the same facts the
        shared skip checks.
        """
        if (
            not isinstance(reason, str)
            or not 0 < len(reason) <= shared_gate.MAX_STOP_REASON
        ):
            raise ValueError("bounded skip reason required")
        with self.locked() as state:
            job, plan = state["jobs"][self.job], state["plan"]
            schedule = job_schedule(plan["jobs"][self.job])
            if (
                job["pid"] != os.getpid()
                or job["complete"]
                or job["inflight"]
                or state.get("noDataAbort") is not None
            ):
                raise ValueError("job or environment stopped/uncertain")
            index = job["recovery"]
            operations = plan["jobs"][self.job]["recovery"]
            next_kind = (
                operations[index].get("kind") if index < len(operations) else None
            )
            # Skipping a rollback passes over no document, so an unconfirmed
            # write elsewhere does not block it; skipping a cleanup slot while
            # a write is unconfirmed would hide a document, and is refused.
            if next_kind != "release" and unconfirmed_creates(state, self.job):
                raise ValueError("an unconfirmed write is outstanding")
            cursor = job["scheduleDone"]
            if job.get("stopReason") is not None:
                while (
                    cursor < len(schedule)
                    and schedule[cursor]["phase"] == "observation"
                ):
                    cursor += 1
                    job["skippedByStop"] += 1
                job["scheduleDone"] = cursor
            slot = schedule[cursor] if cursor < len(schedule) else None
            if (
                slot is None
                or slot["phase"] != "recovery"
                or slot["index"] != index
                or index >= len(operations)
            ):
                raise ValueError("dispatch outside the frozen execution schedule")
            expected = operations[index]
            if expected.get("kind") not in SKIPPABLE_RECOVERY_KINDS:
                raise ValueError("this recovery slot cannot be skipped")
            if digest(operation) != digest(expected):
                raise ValueError("request outside closed scenario")
            job["scheduleDone"] += 1
            job["recovery"] += 1
            state["reservedRecovery"] -= 1
            state.setdefault("skips", []).append(
                {
                    "job": self.job,
                    "index": index,
                    "reason": ZERO_WIRE_REASON,
                    "note": reason,
                }
            )
            _save(self.path, state)
            return (None, {"skipped": ZERO_WIRE_REASON})

    # -- journal extension points -------------------------------------------

    def _recovery_capture(self, operation, status, body):
        capture = super()._recovery_capture(operation, status, body)
        if operation.get("kind") == "owned-read":
            capture["owned"] = owned_document(
                body, self.plan, operation.get("resource")
            )
        return capture

    def _record_response(self, state, operation, recovery, event, status, body):
        kind = operation.get("kind")
        job = state["jobs"][self.job]
        if kind == "begin" and status == 200 and isinstance(body, dict):
            token = canonical_token(body.get("transaction"))
            binds = operation.get("binds")
            if token is not None and binds:
                self._observed_bindings[binds] = token
        if recovery and kind == "owned-read" and status == 200:
            resource = operation.get("resource")
            binds = operation.get("binds")
            if binds and owned_document(body, self.plan, resource):
                self._observed_bindings[binds] = body["updateTime"]
        if not recovery and event.get("creationOutcome") == "unknown":
            settled = self._settle(kind, operation, status, body, job)
            if settled is not None:
                event["creationOutcome"] = settled

    def _settle(self, kind, operation, status, body, job):
        """A settled outcome for a request the shared rule left unknown.

        `refused` here means "no document was created by this request", which
        is the shared vocabulary's only settled value for a request that does
        not create. A begin that issued a token, a rollback that answered
        `{}`, and any typed refusal are all in that class. A transactional
        update of a document this run created is `created`: a write was
        applied to a document the run already owns and will delete.
        """
        if kind in ("begin", "rollback"):
            # Neither RPC can bring a document into existence under any answer,
            # so any completed typed answer, a 5xx envelope included, settles
            # the slot; only a lost answer stays unknown. The collector tracks
            # the transaction that such an answer may have started separately.
            return "refused" if type(status) is int and isinstance(body, dict) else None
        if _error_envelope(status, body):
            return "refused" if kind in ("commit-update", "create") else None
        if status != 200 or not isinstance(body, dict) or "error" in body:
            return None
        if kind == "commit-update":
            request = operation.get("body")
            writes = request.get("writes") if isinstance(request, dict) else None
            results = body.get("writeResults")
            if (
                not isinstance(writes, list)
                or not writes
                or not isinstance(results, list)
                or len(results) != len(writes)
            ):
                return None
            for write, result in zip(writes, results, strict=True):
                update = write.get("update") if isinstance(write, dict) else None
                if (
                    not isinstance(write, dict)
                    or set(write) != {"update"}
                    or not isinstance(update, dict)
                    or update.get("name") not in job.get("creationProofs", {})
                    or not isinstance(result, dict)
                    or "error" in result
                    or not collector.valid_instant(result.get("updateTime"))
                ):
                    return None
            return "created"
        return None
