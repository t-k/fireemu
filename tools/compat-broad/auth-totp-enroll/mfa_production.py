"""One admitted MFA campaign run, resumable, with the configuration lock on every path.

Order of operations, fresh run: consume the capability, reserve the shared Ledger,
read the private credential handoff, verify the bearer against the frozen principal,
read the Auth configuration and refuse unless its digest is the frozen baseline, save
the pre-value, apply the campaign configuration, verify it by readback, walk the
thirty-three cases with real waits, delete every owned account and prove absence,
restore the configuration and verify it, write the receipt, release the reservation.

A resumed run holds the same reservation and the same run directory: it re-verifies
the credential, re-reads the configuration against the same frozen baseline (the
previous stop restored it), re-applies, and continues from the checkpoint. A stop
that is not an abandonment keeps the owned accounts, because the aged credentials
they hold are the campaign; the configuration is restored regardless.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
import time
from pathlib import Path

import reservations
from broad_contract import digest

import mfa_admission as admission
import mfa_descriptor as campaign
import mfa_gate
import mfa_production_transport as transport
from mfa_config_lock import VERIFIED_RESTORE_STATUSES, ConfigLock, ConfigLockError
from mfa_provenance import compute_provenance, describe_worktree
from mfa_timing import timing_mode
from mfa_walk import BudgetError, Refused, StopRequested

RUN_STATE_FILE = "run-state.json"
INJECTED_EXECUTION = "injected-transport"
PRODUCTION_EXECUTION = "fixed-production-wire"


def _envelope(permission: dict, claim: dict) -> dict:
    return {
        "permissionDigest": digest(permission),
        "issuedAt": permission["issuedAt"],
        "expiresAt": permission["expiresAt"],
        "limits": copy.deepcopy(claim["budget"]),
        "concurrency": 1,
        "scopes": copy.deepcopy(claim["locks"]),
    }


def _write_immutable(path: Path, value: dict) -> None:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
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


def _write_private(path: Path, value: dict) -> None:
    encoded = json.dumps(value, sort_keys=True, indent=2).encode() + b"\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())


def _read_private(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise ValueError("private run record missing")
    info = path.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("private run record required")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("private run record malformed")  # noqa: TRY004 -- refusal class
    return value


class GateSession:
    """The walk's session over the shared Gate facade and an inner transport.

    Every data request is admitted against its frozen slot before the inner session
    sends it, every management call is charged as its closed slot, and a planned
    finalize the walk cannot send is consumed as a journaled zero-wire skip.
    """

    def __init__(self, inner, gate: mfa_gate.MfaGate) -> None:
        self.inner = inner
        self.gate = gate
        self.phase = "observation"
        self._management_slots = [
            ("observation", name) for name in mfa_gate.MANAGEMENT_OBSERVATION_IDS
        ] + [("recovery", name) for name in mfa_gate.MANAGEMENT_RECOVERY_IDS]
        self.management_receipts: list[dict] = []

    @property
    def requests(self) -> int:
        return self.inner.requests

    def _dispatch(self, path, body, *, owner):
        recovery = self.phase == "recovery"

        def send():
            deadline = time.monotonic() + mfa_gate.DATA_SLOT_SECONDS
            if owner:
                return self.inner.admin(path, body, deadline=deadline)
            return self.inner.public(path, body, deadline=deadline)

        return self.gate.dispatch_runtime(
            path, body, owner=owner, recovery=recovery, send=send
        )

    def public(self, path, body):
        return self._dispatch(path, body, owner=False)

    def admin(self, path, body):
        return self._dispatch(path, body, owner=True)

    def skip_planned(self, reason: str):
        return self.gate.skip_planned(reason, recovery=self.phase == "recovery")

    def sms_code(self) -> str:
        return self.inner.sms_code()

    def _management(self, expected_kind: str, call):
        """Charge the next closed management slot and run `call` inside it."""
        if not self._management_pending():
            raise ValueError("management slot out of order: none remain")
        phase, slot_id = self._management_pending()[0]
        if expected_kind not in slot_id:
            raise ValueError(f"management slot out of order: next is {slot_id}")
        outcome: dict = {}

        def send(deadline):
            try:
                status, body = call(deadline)
            except Exception as error:  # noqa: BLE001 -- the slot is charged either way; the class is the evidence
                outcome["failure"] = type(error).__name__
                return {
                    "status": None,
                    "complete": False,
                    "workerReaped": True,
                    "bodyKind": None,
                    "body": None,
                }
            outcome["status"], outcome["body"] = status, body
            return {
                "status": status,
                "complete": True,
                "workerReaped": True,
                "bodyKind": "json",
                "body": body,
            }

        self._consumed = getattr(self, "_consumed", 0) + 1
        self.gate.management_dispatch(phase, slot_id, send)
        self.management_receipts.append(
            {
                "id": f"{phase}:{slot_id}",
                **{k: v for k, v in outcome.items() if k != "body"},
            }
        )
        if "failure" in outcome:
            raise ValueError(f"management slot {slot_id} failed: {outcome['failure']}")
        return outcome["status"], outcome["body"]

    def _management_pending(self):
        return self._management_slots[getattr(self, "_consumed", 0) :]

    def tokeninfo(self, attest):
        """The tokeninfo slot; `attest(body)` turns the raw body into the attestation."""
        phase, slot_id = self._management_pending()[0]
        if slot_id != "oauth-tokeninfo":
            raise ValueError("management slot out of order")
        result: dict = {}

        def send(deadline):
            status, body = self.inner.tokeninfo(deadline=deadline)
            result["status"] = status
            if status != 200:
                return {
                    "status": status,
                    "complete": True,
                    "workerReaped": True,
                    "bodyKind": "json",
                    "body": None,
                }
            result["attestation"] = attest(body)
            return {
                "status": status,
                "complete": True,
                "workerReaped": True,
                "bodyKind": "json",
                "body": result["attestation"],
            }

        self._consumed = getattr(self, "_consumed", 0) + 1
        self.gate.management_dispatch(phase, slot_id, send)
        self.management_receipts.append(
            {"id": f"{phase}:{slot_id}", "status": result.get("status")}
        )
        if result.get("status") != 200:
            raise ValueError(f"tokeninfo answered {result.get('status')}")
        return result["attestation"]

    def read_config(self):
        return self._management(
            "readback", lambda deadline: self.inner.read_config(deadline=deadline)
        )

    def patch_config(self, body, mask):
        kind = "restore" if self.phase == "recovery" else "apply"
        return self._management(
            kind,
            lambda deadline: self.inner.patch_config(body, mask, deadline=deadline),
        )


def _validate_credentials(value) -> dict:
    if (
        not isinstance(value, dict)
        or set(value) != {"token", "apiKey"}
        or not transport.private_string(value["token"], 8192)
        or not transport.private_string(value["apiKey"], 512)
    ):
        raise ValueError("bounded bearer token and Web API key required")
    return value


def execute(
    *,
    capability,
    inputs,
    permission,
    credential_reader,
    ledger_root,
    output,
    sleeper,
    descriptor_,
    source_root,
    resume=False,
    abandon=False,
    stop_requested=None,
    session_factory=None,
):
    """Run, resume or abandon one admitted campaign. Returns the receipt plus status.

    `session_factory` is None in production, which binds the fixed transport through
    the capability. A rehearsal injects a session over a virtual clock; its receipt
    says `injected-transport` and can never be production evidence. A rehearsal is
    also the only execution that may continue after the shared Ledger refuses the
    reservation: the refusal is recorded by name, and the run then proves the Gate
    side; production raises instead.
    """
    if not admission.issued_capability(capability):
        raise ValueError("unissued O7 production capability")
    mode = timing_mode(sleeper)
    rehearsal = bool(descriptor_.frozen_bounds.get("rehearsal"))
    if session_factory is None and (mode != "wall-clock" or rehearsal):
        raise ValueError("production execution requires wall-clock timing")
    inputs, permission = copy.deepcopy(inputs), copy.deepcopy(permission)
    admission.validate_frozen_inputs(inputs, descriptor_)
    if digest(permission) != inputs["permissionDigest"]:
        raise ValueError("independent permission differs from frozen inputs")
    output = Path(output)
    if resume or abandon:
        if not output.is_dir() or output.is_symlink():
            raise ValueError("existing private run directory required to resume")
    elif output.exists() or output.is_symlink():
        raise ValueError("fresh production output required")
    ledger = reservations.Ledger(ledger_root)
    manifest = campaign.execution_plan(inputs["plan"])
    gate_plan = admission.gate_plan_for(inputs, permission, descriptor_)
    generation = admission.abort_generation(inputs, descriptor_)
    gate_plan.update(
        permissionDigest=digest(permission),
        collectorSourceDigest=generation["collectorSourceDigest"],
    )
    claim = admission.reservation_claim(
        inputs, gate_path=output / "gate", gate_plan=gate_plan, descriptor_=descriptor_
    )
    hosting = admission.hosting_check(claim, gate_plan)
    capability._consume(
        campaign_id=claim["campaignId"],
        inputs_digest=inputs["inputsDigest"],
        ledger_root=ledger_root,
    )
    execution_kind = (
        PRODUCTION_EXECUTION if session_factory is None else INJECTED_EXECUTION
    )
    if resume or abandon:
        run_state = _read_private(output / RUN_STATE_FILE)
        if run_state.get("inputsDigest") != inputs["inputsDigest"]:
            raise ValueError("run directory belongs to other frozen inputs")
        ticket = run_state["ticket"]
        if ticket is not None:
            ledger.validate(ticket, duration=13)
        run_state["resumeCount"] += 1
        if run_state["resumeCount"] > campaign.RESUME_ALLOWANCE:
            raise ValueError("resume allowance exhausted")
    else:
        output.mkdir(mode=0o700, parents=True, exist_ok=False)
        _write_immutable(output / "inputs.json", inputs)
        reservation_refusal = None
        try:
            ticket = ledger.reserve(
                _envelope(permission, claim), claim, gate_plan, generation=generation
            )
        except ValueError as error:
            if execution_kind != INJECTED_EXECUTION or not rehearsal:
                raise
            # A rehearsal records the shared Ledger's own refusal and goes on to
            # prove the Gate side without a reservation; production never does.
            ticket = None
            reservation_refusal = str(error)
        run_state = {
            "inputsDigest": inputs["inputsDigest"],
            "ticket": ticket,
            "reservationRefusal": reservation_refusal,
            "claimDigest": digest(claim),
            "gatePlanDigest": digest(gate_plan),
            "resumeCount": 0,
            "receipts": [],
        }
        mfa_gate.create(output / "gate", gate_plan)
    output = output.resolve()
    _write_private(output / RUN_STATE_FILE, run_state)
    gate = mfa_gate.MfaGate(output / "gate")
    if not (resume or abandon):
        gate.claim()
    started_wall = sleeper.now()
    wall_seconds = manifest["limits"]["maxWallSeconds"]

    def deadline_for():
        return time.monotonic() + mfa_gate.DATA_SLOT_SECONDS

    stop_point = "schedule-not-started"
    failure = None
    stopped = False
    walk = None
    lock = None
    credential_evidence = None
    session = None
    try:
        credentials = _validate_credentials(credential_reader())
        if session_factory is None:
            inner = transport.ProductionSession(
                capability=capability,
                token=credentials["token"],
                api_key=credentials["apiKey"],
                deadline_for=deadline_for,
            )
        else:
            inner = session_factory(capability, credentials, deadline_for)
        credentials = None
        session = GateSession(inner, gate)
        lock_arguments = {
            "read": session.read_config,
            "patch": session.patch_config,
            "frozen_baseline_digest": permission["authConfigBaselineDigest"],
        }
        if resume or abandon:
            # The Gate's observation preflight was spent by the first process; the
            # configuration stays applied under the held lock across a pause, so a
            # resumed run continues from the lock record rather than re-reading.
            lock = ConfigLock.resume(output, **lock_arguments)
            session._consumed = len(mfa_gate.MANAGEMENT_OBSERVATION_IDS)
            walk = descriptor_.collector(
                session,
                manifest,
                output,
                sleeper=sleeper,
                resume=True,
                stop_requested=stop_requested,
            )
            walk.reconcile_intents()
            if abandon:
                stop_point = "cleanup"
                raise StopRequested("abandon requested")
            stop_point = "cases"
            walk.run()
        else:
            stop_point = "preflight-tokeninfo"
            credential_evidence = session.tokeninfo(
                lambda body: transport.verify_tokeninfo(
                    body,
                    permission["credentialPrincipal"],
                    required_seconds=descriptor_.window_seconds,
                )
            )
            stop_point = "preflight-config-readback"
            lock = ConfigLock(output, **lock_arguments)
            lock.preflight()
            stop_point = "config-apply"
            lock.apply()
            sleeper.sleep_until(sleeper.now() + campaign.CONFIG_ENFORCEMENT_LAG_SECONDS)
            stop_point = "acquisition"
            walk = descriptor_.collector(
                session,
                manifest,
                output,
                sleeper=sleeper,
                resume=False,
                stop_requested=stop_requested,
            )
            stop_point = "cases"
            walk.run()
    except StopRequested as error:
        stopped = True
        failure = type(error).__name__
    except (
        Refused,
        BudgetError,
        ConfigLockError,
        ValueError,
        KeyError,
        TypeError,
    ) as error:
        failure = type(error).__name__
    finally:
        if stop_point == "cases" and walk is not None and failure is not None:
            stop_point = (
                "acquisition" if walk.material.value["origin"] is None else "cases"
            )
        resumable = stopped and not abandon and walk is not None
        cleanup = {
            "ownedAccounts": 0,
            "deleted": 0,
            "absent": 0,
            "complete": not resumable,
            "attempted": not resumable,
        }
        gate_complete = False
        gate_refusal = None
        if session is not None and not resumable:
            # Open the Gate's recovery phase: consume what observation left, clean
            # up whatever was created, and skip the slots of accounts that never
            # were, so the configuration restore behind them is reachable.
            snapshot = gate.snapshot()
            job = snapshot["jobs"][mfa_gate.JOB]
            planned = len(snapshot["plan"]["jobs"][mfa_gate.JOB]["observation"])
            if job["observation"] < planned and job.get("stopReason") is None:
                try:
                    gate.abandon_observation(failure or "observation-incomplete")
                except ValueError as error:
                    gate_refusal = type(error).__name__
            session.phase = "recovery"
            if walk is not None:
                walk.cleanup()
            try:
                gate.drain_recovery()
            except ValueError as error:
                gate_refusal = gate_refusal or type(error).__name__
        if walk is not None:
            owned = [r for r in walk.state["ownedResources"] if r["kind"] == "account"]
            all_absent = all(r["deleted"] and r["absenceVerified"] for r in owned)
            cleanup = {
                "ownedAccounts": len(owned),
                "deleted": sum(r["deleted"] for r in owned),
                "absent": sum(r["absenceVerified"] for r in owned),
                "complete": (not resumable) and all_absent,
                "attempted": not resumable,
            }
            if cleanup["attempted"] and not cleanup["complete"]:
                stop_point = "cleanup"
                failure = failure or "CleanupIncomplete"
        if lock is not None and not resumable:
            if session is not None:
                session.phase = "recovery"
            try:
                lock.restore()
            except ConfigLockError as error:
                failure = failure or type(error).__name__
                if stop_point != "cleanup":
                    stop_point = "restore"
        if session is not None and not resumable and cleanup["complete"]:
            try:
                gate.finish()
                gate_complete = True
            except ValueError as error:
                gate_refusal = type(error).__name__
        admission.revoke_production_capability(capability)
    walk_state = copy.deepcopy(walk.state) if walk is not None else None
    rows = walk.ordered_rows() if walk is not None else []
    complete = bool(
        walk is not None
        and failure is None
        and walk.complete()
        and cleanup["complete"]
        and lock is not None
        and lock.record["restoreStatus"] in VERIFIED_RESTORE_STATUSES
        and gate_complete
    )
    if stop_point == "cases" and failure is None and complete:
        stop_point = None
    snapshot = gate.snapshot()
    _write_immutable(
        output / f"gate-snapshot-{len(run_state['receipts']):02d}.json", snapshot
    )
    receipt = admission.build_receipt(
        inputs,
        walk_state=walk_state,
        rows=rows,
        configuration=lock.evidence() if lock is not None else None,
        credential=credential_evidence,
        cleanup=cleanup,
        generation=generation,
        execution_kind=execution_kind,
        timing_mode=mode,
        stop_point=stop_point,
        failure=failure,
        resumable=resumable,
    )
    receipt.update(
        ticket=ticket,
        reservationRefusal=run_state.get("reservationRefusal"),
        claimDigest=digest(claim),
        planDigest=digest(gate_plan),
        gateDigest=digest(snapshot),
        gateComplete=gate_complete,
        gateRefusal=gate_refusal,
        accountEvidence=mfa_gate.account_evidence(snapshot),
        managementEvidence=session.management_receipts if session is not None else [],
        chargedCalls=snapshot["total"],
        hostingRefusals=hosting,
        resumeCount=run_state["resumeCount"],
        wallElapsedSeconds=sleeper.now() - started_wall,
        wallBudgetSeconds=wall_seconds,
        reservationStateAtPublication="held" if ticket is not None else "unreserved",
        releaseEligible=complete and ticket is not None,
        releaseRecord="release.json" if complete else None,
        requestsCharged=session.requests if session is not None else 0,
    )
    admission.screen_receipt(receipt)
    sequence = len(run_state["receipts"])
    receipt_path = output / (
        "receipt.json" if not resumable else f"receipt-{sequence:02d}.json"
    )
    if receipt_path.exists():
        receipt_path = output / f"receipt-{sequence:02d}.json"
    _write_immutable(receipt_path, receipt)
    run_state["receipts"].append(
        {
            "path": receipt_path.name,
            "sha256": hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
        }
    )
    _write_private(output / RUN_STATE_FILE, run_state)
    record = comparison_record(
        manifest,
        walk,
        lock,
        permission,
        source_root=source_root,
        execution_kind=execution_kind,
        requests=session.requests if session else 0,
    )
    _write_immutable(output / f"production-record-{sequence:02d}.json", record)
    released = False
    release = None
    release_refusal = None
    if complete and ticket is None:
        release_refusal = "Unreserved"
    elif complete and hosting:
        # The shared Ledger releases a row only through the shared Gate's Firestore
        # cleanup proof, which this campaign's Gate cannot supply; the row stays
        # held and the release record names why rather than turning a known
        # refusal into a missing-proof error.
        release_refusal = "HostingRefused"
    elif complete:
        try:
            ledger.finish(ticket)
            released = True
        except Exception as error:  # noqa: BLE001 -- never report an unverified release
            release_refusal = type(error).__name__
    if complete:
        release = {
            "receiptDigest": digest(receipt),
            "ticket": ticket,
            "failure": release_refusal,
            "hostingRefusals": hosting,
            "reservationRefusal": run_state.get("reservationRefusal"),
            "gateComplete": gate_complete,
            "reservationFinal": (
                ledger.snapshot()["reservations"][ticket["reservation"]]
                if ticket is not None
                else None
            ),
        }
        _write_immutable(output / "release.json", release)
    return {
        **receipt,
        "failure": failure,
        "reservationReleased": released,
        "releaseRefusal": release_refusal,
        "release": release,
        "comparisonRecord": record,
        "executionStarted": True,
    }


def comparison_record(
    manifest, walk, lock, permission, *, source_root, execution_kind, requests
):
    """The receipt in the comparator's shape, so the shadow can be compared against it."""
    state = walk.state if walk is not None else None
    restored = (
        lock is not None and lock.record["restoreStatus"] in VERIFIED_RESTORE_STATUSES
    )
    owned = (
        [r for r in state["ownedResources"] if r["kind"] == "account"] if state else []
    )
    complete = walk is not None and walk.complete()
    return {
        "schema": "o2-mfa-production-record-v1",
        "campaignId": campaign.CAMPAIGN,
        "campaign": copy.deepcopy(manifest),
        "side": "production" if execution_kind == PRODUCTION_EXECUTION else "rehearsal",
        "productionExecuted": execution_kind == PRODUCTION_EXECUTION,
        "recordingComplete": complete,
        "requestsCharged": requests,
        "maxRequests": manifest["limits"]["maxRequests"],
        "provenance": compute_provenance(Path(source_root)),
        "worktree": describe_worktree(Path(source_root)),
        "rows": walk.ordered_rows() if walk is not None else [],
        "recovery": {
            "cleanupVerified": bool(owned)
            and all(r["deleted"] and r["absenceVerified"] for r in owned),
            "remainingOwnedResources": sum(
                not (r["deleted"] and r["absenceVerified"]) for r in owned
            ),
            "configurationMutated": bool(
                lock is not None and lock.record["changeAttempted"]
            ),
            "configurationRestored": restored,
            "ownedAccounts": len(owned),
        },
        "ownerApproval": {
            "approvedBy": permission.get("ownerIdentity"),
            "manifestDigest": digest(manifest),
            "nonceDigest": manifest["owner"]["nonceDigest"],
            "grant": "one-run",
        },
    }
