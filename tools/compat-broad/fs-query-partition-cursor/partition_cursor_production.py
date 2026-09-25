"""One admitted partition/cursor acquisition, with immutable offline-review evidence.

The credential callback runs only after the shared Ledger reservation and the
Gate claim. The compiled plan is driven by the lane's own collector through the
Gate facade, then the Gate-native recovery ladder proves every seeded document
absent, the two residual scans run, the postflight management slots run, and
only a run whose collection completed and whose every resource is proven absent
releases its reservation. Anything else keeps the reservation held with a
receipt that names its disposition.
"""

# ruff: noqa: BLE001 -- Preserve a secret-free failure class and keep publishing evidence after any error.

from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/production-admission"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/o8-core"))
sys.path.insert(0, str(HERE))

import o4_partition_cursor_descriptor as campaign
import partition_cursor_admission as admission
import partition_cursor_gate as gate_projection
import partition_cursor_preflight as preflight
import partition_cursor_wire as wire
import reservations
import shared_gate
from broad_contract import digest
from partition_cursor_collector import _documents, _row, _verify_raw, publish_row
from partition_cursor_gate import JOB, PartitionCursorGate
from partition_cursor_wire import validate_production_origin

LADDER_READ = "ladder-ownership-read"
LADDER_DELETE = "ladder-version-bound-delete"
LADDER_ABSENCE = "ladder-typed-absence"
RESIDUAL_KINDS = ("residual-group-scan", "residual-cursor-scan")
ABSENT_AT_READ = "absent-at-ladder-read"


class GateRefusal(ValueError):
    """The shared Gate refused a slot; nothing was sent for it."""


class ObservationAbandoned(GateRefusal):
    """An observation-phase slot was requested after the observation ended."""


class GateScheduleStalled(GateRefusal):
    """A skipped creating slot cannot be consumed zero-wire; the schedule cannot advance."""


class CredentialUnavailable(GateRefusal):
    """The verified credential cannot cover the slot; refused before the Gate charged it."""


def validate_collector_options(options: dict) -> dict:
    """Refuse loopback as a production target and non-loopback as a local one.

    The two collector entry points already refuse the wrong origin each; this
    is the same rule stated once for a caller that holds a target name and an
    origin together, before anything is created or sent.
    """
    if not isinstance(options, dict) or set(options) != {"target", "origin"}:
        raise ValueError("closed collector options required")
    target, origin = options["target"], options["origin"]
    if target == "production":
        validate_production_origin(origin)
    elif target == "local":
        wire.validate_origin(origin)
    else:
        raise ValueError("closed collector target required")
    return {"target": target, "origin": origin}


def _envelope(permission: dict, claim: dict) -> dict:
    return {
        "permissionDigest": digest(permission),
        "issuedAt": permission["issuedAt"],
        "expiresAt": permission["expiresAt"],
        "limits": copy.deepcopy(claim["budget"]),
        "concurrency": 1,
        "scopes": copy.deepcopy(claim["locks"]),
    }


def _write_receipt(path: Path, receipt: dict) -> None:
    encoded = json.dumps(
        receipt, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    if len(encoded) > reservations.MAX_BYTES:
        raise ValueError("bounded immutable production evidence required")
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path, follow_symlinks=False)
    finally:
        os.unlink(temporary)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


class _Journal:
    """A retained directory of rows outside the compiled plan, same boundary."""

    def __init__(self, directory: Path) -> None:
        directory.mkdir(mode=0o700, parents=False, exist_ok=False)
        (directory / "raw").mkdir(mode=0o700)
        self.directory_fd = os.open(directory, os.O_RDONLY)
        self.raw_fd = os.open(directory / "raw", os.O_RDONLY)
        self.bindings: list[dict] = []
        self.publication: dict = {"complete": True, "failures": []}
        self.rows: list[dict] = []
        self._evidence_complete: bool | None = None

    def record(self, row: dict, receipt) -> None:
        self.rows.append(row)
        publish_row(
            self.directory_fd,
            self.raw_fd,
            row,
            receipt,
            self.bindings,
            self.publication,
        )

    def summary(self) -> dict:
        """Report the retained rows, one raw-evidence verdict, and publication detail.

        `raw.complete` must be the same verified verdict `evidence_complete()`
        returns, never the bare `publication["complete"]` flag: a raw sidecar
        write can fail without ever touching `publication`, and a receipt must
        not be able to carry `raw.complete: true` next to
        `<journal>EvidenceComplete: false`. `evidence_complete()` must be
        called first (it re-reads the retained sidecars, which needs the file
        descriptors this journal still holds open).
        """
        if self._evidence_complete is None:
            raise RuntimeError("evidence_complete() must be called before summary()")
        return {
            "rows": copy.deepcopy(self.rows),
            "raw": {
                "bindings": len(self.bindings),
                "complete": self._evidence_complete,
            },
            "publication": copy.deepcopy(self.publication),
        }

    def evidence_complete(self) -> bool:
        """Mirror the collector's `_result()` raw/publication evidence checks.

        A dispatched row (one the Gate actually sent, not one it consumed
        without a send) must have retained its raw sidecar, that sidecar must
        re-read and hash to what was recorded, and every row/manifest write
        must have durably published. Must be called once, before the
        journal's file descriptors close: it re-reads the retained sidecars.
        The result is cached so `summary()` can report the same verdict after
        the descriptors close, instead of recomputing it from a weaker signal.
        """
        dispatched = [row for row in self.rows if row["status"] != "skipped"]
        try:
            verified = bool(dispatched) and _verify_raw(self.raw_fd, self.bindings)
        except Exception as error:
            verified = False
            self.publication["complete"] = False
            self.publication["failures"].append(
                {"file": "raw", "error": type(error).__name__}
            )
        self._evidence_complete = (
            verified
            and len(self.bindings) == len(dispatched)
            and all(row["raw"]["present"] for row in dispatched)
            and self.publication["complete"]
        )
        return self._evidence_complete

    def close(self) -> None:
        os.close(self.raw_fd)
        os.close(self.directory_fd)


def _stop_point(snapshot, ready):
    """Name where a run stopped, from the Gate journal rather than from memory."""
    if ready:
        return None
    if snapshot is None or not snapshot.get("events"):
        return "schedule-not-started"
    job = snapshot["jobs"][JOB]
    for event in snapshot["events"]:
        if (
            event.get("phase") == "observation"
            and event.get("index") in (1, 2)
            and event.get("creationOutcome") not in ("refused", "created")
        ):
            return "create-uncertain" if event["index"] == 1 else "seed-uncertain"
    observed = [
        event for event in snapshot["events"] if event.get("phase") == "observation"
    ]
    if all(event.get("index") == 0 for event in observed) and not job.get(
        "creationProofs"
    ):
        return "preflight-absence"
    if (
        job.get("stopReason") is not None
        or job.get("scheduleDone", 0) < gate_projection.OBSERVATION_COUNT
    ):
        return "observation-incomplete"
    return "recovery-incomplete"


def ladder_absence_complete(snapshot) -> bool:
    """Whether every assigned resource ends with a validated typed absence."""
    if snapshot is None:
        return False
    job = snapshot["jobs"][JOB]
    if set(job.get("absent", [])) != set(job["resources"]):
        return False
    try:
        shared_gate.validate_absence_proofs(snapshot, JOB)
    except Exception:
        return False
    return True


def _native_request(gate, gate_index: int) -> dict:
    """The runtime request for one Gate recovery slot, from the Gate's own journal.

    A read is the frozen request. A delete carries the version the slot's own
    recovery read captured, when that read found the document; when it found a
    typed absence the request carries no version and the Gate consumes the slot
    without a send.
    """
    frozen = gate.frozen_operation("recovery", gate_index)
    request = {
        "phase": "ladder",
        "index": gate_index,
        "kind": frozen["kind"],
        "method": frozen["method"],
        "path": frozen["path"],
        "body": None,
    }
    if frozen["method"] == "DELETE":
        capture = (
            gate.snapshot()["jobs"][JOB]
            .get("captures", {})
            .get(str(frozen["versionFrom"]))
        )
        if (
            isinstance(capture, dict)
            and capture.get("status") == 200
            and isinstance(capture.get("updateTime"), str)
        ):
            request["path"] += "?currentDocument.updateTime=" + capture["updateTime"]
    return request


def execute(*, capability, inputs, permission, credential_reader, ledger_root, output):
    """Execute only the consumed capability's fixed transport; never accept one."""
    if not admission.issued_capability(capability):
        raise ValueError("unissued O7 production capability")
    inputs, permission = copy.deepcopy(inputs), copy.deepcopy(permission)
    admission.validate_frozen_inputs(inputs)
    if digest(permission) != inputs["permissionDigest"]:
        raise ValueError("independent permission differs from frozen inputs")
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise ValueError("fresh production output required")
    ledger = reservations.Ledger(ledger_root)
    plan = campaign.execution_plan(inputs["plan"])
    gate_plan = admission.gate_plan_for(inputs, permission)
    slot_seconds = admission.gate_reservations(permission)["slot"]
    generation = admission.abort_generation(inputs)
    gate_plan.update(
        permissionDigest=digest(permission),
        collectorSourceDigest=generation["collectorSourceDigest"],
    )
    claim = admission.reservation_claim(
        inputs, gate_path=output / "gate", gate_plan=gate_plan
    )
    capability._consume(
        campaign_id=claim["campaignId"],
        inputs_digest=inputs["inputsDigest"],
        ledger_root=ledger_root,
    )
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    output = output.resolve()
    _write_receipt(output / "inputs.json", inputs)
    ticket = ledger.reserve(
        _envelope(permission, claim), claim, gate_plan, generation=generation
    )
    gate = None
    routes: list[dict] = []
    result = None
    failure = None
    ready = False
    snapshot = None
    management = None
    ladder = None
    residual = None
    abandoned = {"done": False}
    stall_record: dict = {"first": None}
    ladder_summary = {
        "slots": 0,
        "reads": 0,
        "absentAtRead": 0,
        "deleted": 0,
        "provenAbsent": 0,
        "failed": 0,
    }
    residual_summary = {"complete": False, "documents": None}
    ladder_evidence_complete = False
    residual_evidence_complete = False
    try:
        gate_projection.create(output / "gate", gate_plan)
        gate = PartitionCursorGate(output / "gate")
        gate.claim()
        token = credential_reader()
        management = preflight.ManagementSession(
            gate=gate,
            ledger=ledger,
            ticket=ticket,
            capability=capability,
            permission=permission,
            token=token,
        )
        management.run("observation")
        token = None
        ladder = _Journal(output / "ladder")
        slot_map = gate_projection.slot_map(plan)
        schedule = gate_plan["jobs"][JOB]["schedule"]
        positions = {
            (entry["phase"], entry["index"]): index
            for index, entry in enumerate(schedule)
        }
        projection = gate_projection.gate_operations(plan)

        def abandon(job):
            if not abandoned["done"] and job.get("stopReason") is None:
                gate.abandon_observation("observation-incomplete")
            abandoned["done"] = True

        stuck: dict[int, str] = {}

        def stall(position, reason):
            """Record the first stall so the receipt names the slot and its cause."""
            entry = schedule[position]
            if stall_record["first"] is None:
                stall_record["first"] = {
                    "phase": entry["phase"],
                    "index": entry["index"],
                    "kind": projection[entry["phase"]][entry["index"]]["kind"],
                    "reason": reason,
                }
            raise GateScheduleStalled(reason)

        def advance_to(gate_phase, gate_index):
            """Consume the frozen slots the collector passed over without a send.

            An observation slot the Gate accepts as non-creating is skipped
            zero-wire. One it treats as creating cannot be: when the
            observation is over the abandon transition opens the cleanup
            behind it, otherwise the schedule is stalled and the request is
            refused. A recovery slot the collector did not send is dispatched
            natively, once; a recovery slot the Gate refused stays refused, and
            every later slot behind it is refused without another attempt.
            """
            state = gate.snapshot()
            job = state["jobs"][JOB]
            target = positions[(gate_phase, gate_index)]
            cursor = job["scheduleDone"]
            stopped = (
                job["stopped"] or state["stopped"] or job.get("stopReason") is not None
            )
            for position in range(cursor, target):
                if position in stuck:
                    stall(position, stuck[position])
                entry = schedule[position]
                if entry["phase"] == "recovery":
                    dispatch_native(entry["index"], advance=False)
                    if gate.snapshot()["jobs"][JOB]["scheduleDone"] <= position:
                        stuck[position] = "refused-recovery-slot"
                        stall(position, stuck[position])
                    continue
                if stopped or abandoned["done"]:
                    abandon(job)
                    continue
                if entry.get("creates") is False:
                    frozen = gate.frozen_operation(entry["phase"], entry["index"])
                    gate.skip_scheduled_slot(frozen, False, "collector-skipped-slot")
                    continue
                if gate_phase == "observation":
                    stall(position, "creating-declaration-gap")
                abandon(job)
            if gate_phase == "observation" and (stopped or abandoned["done"]):
                raise ObservationAbandoned(
                    "observation slot after the observation ended"
                )

        def charge(
            gate_phase,
            gate_index,
            request,
            *,
            collector_phase,
            collector_index,
            advance=True,
        ):
            """Charge one frozen slot with one runtime request through the Gate."""
            if advance:
                advance_to(gate_phase, gate_index)
            entry = {
                "phase": collector_phase,
                "index": collector_index,
                "gatePhase": gate_phase,
                "gateIndex": gate_index,
                "kind": request.get("kind"),
                "route": request["path"],
                "requestDigest": digest(request),
                "gateRequestDigest": None,
                "status": None,
                "responseDigest": digest(None),
                "skipped": None,
            }
            routes.append(entry)
            box = {}
            # A credential that cannot cover the slot refuses here, before the
            # Gate charges it, rather than as a lost answer inside `send`.
            try:
                token = management.data_token(time.monotonic() + slot_seconds)
            except ValueError as error:
                entry["skipped"] = "refused:CredentialUnavailable"
                raise CredentialUnavailable(type(error).__name__) from error

            def send():
                deadline = time.monotonic() + slot_seconds
                receipt = capability._transmit(
                    admission.transport_call(request, token, deadline=deadline)
                )
                box["receipt"] = receipt
                decoded = wire.validate_receipt(receipt)
                preflight.observe_status(management.credential, receipt["status"])
                return receipt["status"], decoded

            try:
                entry["gateRequestDigest"] = digest(
                    gate.normalize(gate_phase, gate_index, request)
                )
                outcome = gate.dispatch_slot(gate_phase, gate_index, request, send)
            except ValueError as error:
                if "receipt" in box:
                    entry.update(
                        status=box["receipt"].get("status"),
                        responseDigest=digest({"failure": type(error).__name__}),
                    )
                    raise
                entry["skipped"] = "refused:" + type(error).__name__
                raise GateRefusal(type(error).__name__) from error
            if "receipt" not in box:
                entry["skipped"] = (
                    outcome[1].get("skipped")
                    if isinstance(outcome, tuple)
                    else "skipped"
                )
                return None
            receipt = box["receipt"]
            entry.update(
                status=receipt["status"], responseDigest=digest(receipt["body"])
            )
            return receipt

        def dispatch_native(gate_index, *, advance=True):
            """Dispatch one Gate recovery slot from the Gate's own journal."""
            request = _native_request(gate, gate_index)
            row = _row("ladder", gate_index, {"kind": request["kind"]})
            row["request"] = copy.deepcopy(request)
            ladder_summary["slots"] += 1
            receipt = None
            try:
                receipt = charge(
                    "recovery",
                    gate_index,
                    request,
                    collector_phase="ladder",
                    collector_index=gate_index,
                    advance=advance,
                )
                if receipt is None:
                    # The Gate consumed the slot without a send; its own
                    # reason is the row's, and only an absent read counts as
                    # the ladder's expected outcome.
                    reason = routes[-1]["skipped"]
                    row["skipReason"] = (
                        ABSENT_AT_READ
                        if reason == "absent-or-unavailable-cleanup-read"
                        else reason
                    )
                    ladder_summary["absentAtRead"] += int(
                        row["skipReason"] == ABSENT_AT_READ
                    )
                else:
                    row["receipt"] = {
                        "status": receipt["status"],
                        "body": receipt["body"],
                        "complete": True,
                    }
                    if request["method"] == "DELETE":
                        row["status"] = (
                            "pass" if receipt["status"] == 200 else "mismatch"
                        )
                        ladder_summary["deleted"] += int(receipt["status"] == 200)
                    elif (
                        request["kind"].endswith("typed-absence")
                        or request["kind"] == "cleanup-verify-root-absence"
                    ):
                        row["status"] = (
                            "pass" if receipt["status"] == 404 else "mismatch"
                        )
                        ladder_summary["provenAbsent"] += int(receipt["status"] == 404)
                    else:
                        row["status"] = (
                            "pass" if receipt["status"] in (200, 404) else "mismatch"
                        )
                        ladder_summary["reads"] += 1
            except Exception as error:
                row["status"] = "failed"
                row["failure"] = type(error).__name__
                ladder_summary["failed"] += 1
            ladder.record(row, receipt)

        def execute_wire(request):
            key = (request["phase"], request["index"])
            if key not in slot_map:
                raise GateRefusal("request outside the frozen slot map")
            gate_phase, gate_index = slot_map[key]
            receipt = charge(
                gate_phase,
                gate_index,
                request,
                collector_phase=request["phase"],
                collector_index=request["index"],
            )
            if receipt is None:
                raise GateRefusal("frozen slot consumed without a send")
            return receipt

        result = campaign.collector(plan, execute_wire, output / "collection")
        seeded_ladder = gate_projection.SEEDED_DOCUMENTS * gate_projection.LADDER_STEPS
        ladder_start = slot_map[("ladder", 0)][1]
        for offset in range(seeded_ladder):
            dispatch_native(ladder_start + offset)
        residual = _Journal(output / "residual")
        counts = []
        for index in range(gate_projection.RESIDUAL_SLOTS):
            gate_phase, gate_index = slot_map[("residual", index)]
            frozen = projection[gate_phase][gate_index]
            request = {
                "phase": "residual",
                "index": index,
                "kind": frozen["kind"],
                "method": frozen["method"],
                "path": frozen["path"],
                "body": copy.deepcopy(frozen["body"]),
            }
            row = _row("residual", index, frozen)
            row["request"] = copy.deepcopy(request)
            receipt = None
            try:
                receipt = charge(
                    gate_phase,
                    gate_index,
                    request,
                    collector_phase="residual",
                    collector_index=index,
                )
                documents = (
                    _documents(receipt["body"]) if receipt["status"] == 200 else None
                )
                row["receipt"] = {
                    "status": receipt["status"],
                    "body": receipt["body"],
                    "complete": True,
                }
                row["status"] = "pass" if documents is not None else "mismatch"
                counts.append(len(documents) if documents is not None else None)
            except Exception as error:
                row["status"] = "failed"
                row["failure"] = type(error).__name__
                counts.append(None)
            residual.record(row, receipt)
        if all(count is not None for count in counts):
            residual_summary = {"complete": True, "documents": sum(counts)}
        for offset in range(
            seeded_ladder,
            gate_projection.LADDER_DOCUMENTS * gate_projection.LADDER_STEPS,
        ):
            dispatch_native(ladder_start + offset)
        snapshot = gate.snapshot()
        # Each predicate is load-bearing on its own. The collector's `pass`
        # status already means every row passed or was a benign skip, cleanup
        # and raw retention and publication completed, and the partition
        # ranges rebuilt the baseline; the ladder is judged by the Gate's own
        # typed-absence journal and by its own publication; the residual scans
        # must have run and found nothing.
        # Computed once, here, while the journals' file descriptors are still
        # open -- `evidence_complete()` re-reads the retained raw sidecars.
        ladder_evidence_complete = ladder.evidence_complete()
        residual_evidence_complete = residual.evidence_complete()
        collection_clean = result.get("status") == "pass"
        ladder_clean = (
            ladder_summary["failed"] == 0
            and ladder_evidence_complete
            and ladder_absence_complete(snapshot)
        )
        residual_clean = (
            residual_summary["complete"]
            and residual_summary["documents"] == 0
            and residual_evidence_complete
        )
        if collection_clean and ladder_clean and residual_clean:
            management.run("recovery")
            gate.finish()
            ready = True
        else:
            failure = "collection-incomplete"
    except Exception as error:
        failure = type(error).__name__
    finally:
        admission.revoke_production_capability(capability)
        # Common teardown for both the normal and the abnormal exit: an
        # exception between a journal's creation and its verification above
        # (collector-start failure, residual-directory creation failure, ...)
        # must not leave that journal unverified. `evidence_complete()` never
        # raises -- verification failures are folded into its own False
        # verdict -- so it is safe to call here for whichever journal the
        # normal path above did not already verify; an unverifiable journal
        # counts as incomplete, never as ready. The guard keeps the "called
        # once" contract: a journal the normal path already verified is left
        # alone rather than re-verified from closed-adjacent state.
        if ladder is not None and ladder._evidence_complete is None:
            ladder_evidence_complete = ladder.evidence_complete()
        if residual is not None and residual._evidence_complete is None:
            residual_evidence_complete = residual.evidence_complete()
        for journal in (ladder, residual):
            if journal is not None:
                journal.close()
    if gate is not None:
        snapshot = gate.snapshot()
    _write_receipt(output / "routes.json", {"rows": routes})
    if snapshot is not None:
        _write_receipt(output / "gate-snapshot.json", snapshot)
    evidence = {}
    for path in sorted(output.rglob("*")):
        relative = path.relative_to(output)
        if path.is_file() and relative.parts[0] != "gate":
            evidence[str(relative)] = hashlib.sha256(path.read_bytes()).hexdigest()
    receipt = admission.build_receipt(
        inputs,
        result,
        capability=None,
        routes=routes,
        generation=generation,
        management=management,
        failure=failure,
        stop_point=_stop_point(snapshot, ready),
    )
    receipt.update(
        ticket=ticket,
        claimDigest=digest(claim),
        campaignPlanDigest=inputs["planDigest"],
        planDigest=digest(gate_plan),
        gateDigest=digest(snapshot) if snapshot is not None else None,
        evidenceFiles=evidence,
        chargedCalls=snapshot["total"] if snapshot else 0,
        dataDispatches=len([row for row in routes if row["skipped"] is None]),
        credentialEvidence=management.credential_evidence if management else [],
        managementEvidence=management.evidence if management else [],
        preflightComplete=bool(management and management.preflight_complete),
        postflightComplete=bool(management and management.postflight_complete),
        ladder=ladder.summary() if ladder is not None else None,
        ladderSummary=ladder_summary,
        ladderAbsenceComplete=ladder_absence_complete(snapshot),
        ladderEvidenceComplete=ladder_evidence_complete,
        creationProofCount=len(snapshot["jobs"][JOB].get("creationProofs", {}))
        if snapshot
        else 0,
        resourceCount=len(snapshot["jobs"][JOB]["resources"]) if snapshot else 0,
        scheduleStall=stall_record["first"],
        residual=residual.summary() if residual is not None else None,
        residualSummary=residual_summary,
        residualEvidenceComplete=residual_evidence_complete,
        reconstruction=result["reconstruction"] if result is not None else None,
        reservationStateAtPublication="held",
        releaseEligible=ready,
        releaseRecord="release.json" if ready else None,
        executionKind="fixed-production-wire",
        productionExecuted=bool([row for row in routes if row["skipped"] is None]),
        workerSha256=inputs["sourceInputs"][campaign.WORKER_ENTRY],
        mayHaveCreated=bool(
            snapshot and shared_gate.creating_outcome(snapshot, JOB) != "none"
        ),
    )
    _write_receipt(output / "receipt.json", receipt)
    released = False
    release = None
    if ready:
        try:
            ledger.finish(ticket)
            released = True
        except Exception as error:
            failure = type(error).__name__
        release = {
            "receiptDigest": digest(receipt),
            "ticket": ticket,
            "failure": failure,
            "reservationFinal": ledger.snapshot()["reservations"][
                ticket["reservation"]
            ],
        }
        _write_receipt(output / "release.json", release)
    return {
        **receipt,
        "failure": failure,
        "reservationReleased": released,
        "release": release,
    }


def _read_saved(path):
    if (
        path.is_symlink()
        or not path.is_file()
        or path.stat().st_size > reservations.MAX_BYTES
    ):
        raise ValueError("bounded regular saved evidence required")
    return json.loads(path.read_bytes())


def _verify_saved(output, *, expected_inputs_digest, ledger_root, release=None):
    """Verify completed evidence against independently retained inputs and Ledger.

    This is read-only and uses no current credentials, capability or transport.
    The Ledger anchors the final Gate snapshot; the release record links that
    snapshot to the immutable receipt and its per-file evidence digests.
    """
    if not isinstance(expected_inputs_digest, str) or len(expected_inputs_digest) != 64:
        raise ValueError("independently retained frozen inputs digest required")
    if Path(output).is_symlink():
        raise ValueError("regular evidence directory required")
    output = Path(output).resolve()
    inputs = _read_saved(output / "inputs.json")
    receipt = _read_saved(output / "receipt.json")
    if release is None:
        release = _read_saved(output / "release.json")
    snapshot = _read_saved(output / "gate-snapshot.json")
    if (
        inputs.get("inputsDigest") != expected_inputs_digest
        or digest(
            {key: value for key, value in inputs.items() if key != "inputsDigest"}
        )
        != expected_inputs_digest
        or receipt.get("inputsDigest") != expected_inputs_digest
        or receipt.get("permissionDigest") != digest(inputs["permission"])
        or receipt.get("campaignPlanDigest") != inputs["planDigest"]
        or receipt.get("productionExecuted") is not True
        or receipt.get("executionKind") != "fixed-production-wire"
        or receipt.get("releaseEligible") is not True
        or receipt.get("releaseRecord") != "release.json"
        or receipt.get("failure") is not None
        or set(release) != {"receiptDigest", "ticket", "failure", "reservationFinal"}
        or release.get("failure") is not None
        or release.get("receiptDigest") != digest(receipt)
        or release.get("ticket") != receipt.get("ticket")
    ):
        raise ValueError("saved acquisition binding differs")
    preflight.validate_saved_management(receipt, snapshot, inputs["permission"])
    ledger = reservations.Ledger(ledger_root)
    ledger.bound_claim(receipt["ticket"])
    final = ledger.snapshot()["reservations"].get(receipt["ticket"]["reservation"])
    if (
        final is None
        or final != release["reservationFinal"]
        or final.get("state") != "released"
        or final.get("finalGateDigest") != digest(snapshot)
        or receipt.get("gateDigest") != digest(snapshot)
        or receipt.get("claimDigest") != final.get("claimDigest")
        or digest(final["claim"]) != final.get("claimDigest")
        or final["claim"]["manifestDigest"] != inputs["planDigest"]
        or final["claim"]["gatePlanDigest"] != digest(snapshot["plan"])
        or receipt.get("planDigest") != digest(snapshot["plan"])
        or final.get("generation") != receipt.get("generation")
        or receipt.get("workerSha256") != inputs["sourceInputs"][campaign.WORKER_ENTRY]
    ):
        raise ValueError("saved Ledger release binding differs")
    evidence = receipt.get("evidenceFiles")
    required = {
        "inputs.json",
        "routes.json",
        "collection/collection.json",
        "collection/raw/manifest.json",
    }
    if not isinstance(evidence, dict) or not required <= evidence.keys():
        raise ValueError("saved evidence inventory incomplete")
    for name, expected in evidence.items():
        relative = Path(name)
        path = output / relative
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or path.is_symlink()
            or any(parent.is_symlink() for parent in path.parents if parent != output)
            or not path.is_file()
            or path.stat().st_size > reservations.MAX_BYTES
            or hashlib.sha256(path.read_bytes()).hexdigest() != expected
        ):
            raise ValueError("saved evidence file differs")
    collection = _read_saved(output / "collection/collection.json")
    routes = _read_saved(output / "routes.json")["rows"]
    sent = [row for row in routes if row.get("skipped") is None]
    if (
        collection != receipt.get("collection")
        or collection.get("status") != "pass"
        or collection.get("productionExecuted") is not True
        or collection.get("target") != "fixed-production-wire"
        or collection["cleanup"].get("complete") is not True
        or collection["reconstruction"].get("matches") is not True
        or len(sent) + len(snapshot.get("managementEvents", [])) != snapshot["total"]
        or receipt.get("chargedCalls") != snapshot["total"]
        or receipt.get("routes") != routes
        or receipt.get("routeDigest") != digest(routes)
        or receipt.get("ladderAbsenceComplete") is not True
        or receipt.get("ladderEvidenceComplete") is not True
        or receipt.get("residualSummary") != {"complete": True, "documents": 0}
        or receipt.get("residualEvidenceComplete") is not True
    ):
        raise ValueError("saved route journal differs")
    for route, event in zip(sent, snapshot["events"], strict=True):
        if (
            route["gatePhase"] != event["phase"]
            or route["gateIndex"] != event["index"]
            or route["gateRequestDigest"] != event["requestDigest"]
            or route["responseDigest"] != event["responseDigest"]
            or route["status"] != event["status"]
            or event.get("completed") is not True
        ):
            raise ValueError("saved routes differ from charged Gate events")
    job = snapshot["jobs"][JOB]
    if not job["complete"] or shared_gate.unconfirmed_creates(snapshot, JOB):
        raise ValueError("saved Gate cleanup incomplete")
    shared_gate.validate_absence_proofs(snapshot, JOB)
    return receipt


def verify_saved(output, *, expected_inputs_digest, ledger_root):
    """Require a persisted release record and verify its complete evidence chain."""
    return _verify_saved(
        output, expected_inputs_digest=expected_inputs_digest, ledger_root=ledger_root
    )


def recover_release(output, *, expected_inputs_digest, ledger_root):
    """Publish missing release evidence after the Ledger already released the run.

    This operation reads no credential, sends no request, and never reserves
    or finishes a Ledger row a second time. Existing files are never replaced.
    """
    if Path(output).is_symlink():
        raise ValueError("regular evidence directory required")
    output = Path(output).resolve()
    release_path = output / "release.json"
    if release_path.exists() or release_path.is_symlink():
        raise ValueError("immutable release record already exists")
    receipt = _read_saved(output / "receipt.json")
    ledger = reservations.Ledger(ledger_root)
    ledger.bound_claim(receipt["ticket"])
    final = ledger.snapshot()["reservations"][receipt["ticket"]["reservation"]]
    release = {
        "receiptDigest": digest(receipt),
        "ticket": receipt["ticket"],
        "failure": None,
        "reservationFinal": final,
    }
    _verify_saved(
        output,
        expected_inputs_digest=expected_inputs_digest,
        ledger_root=ledger_root,
        release=release,
    )
    _write_receipt(release_path, release)
    return release
