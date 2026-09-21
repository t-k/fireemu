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
import mfa_production_transport as transport
from mfa_config_lock import ConfigLock, ConfigLockError
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
    says `injected-transport` and can never be production evidence.
    """
    if not admission.issued_capability(capability):
        raise ValueError("unissued O7 production capability")
    mode = timing_mode(sleeper)
    if session_factory is None and mode != "wall-clock":
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
        ledger.validate(ticket, duration=13)
        run_state["resumeCount"] += 1
        if run_state["resumeCount"] > campaign.RESUME_ALLOWANCE:
            raise ValueError("resume allowance exhausted")
    else:
        output.mkdir(mode=0o700, parents=True, exist_ok=False)
        _write_immutable(output / "inputs.json", inputs)
        ticket = ledger.reserve(
            _envelope(permission, claim), claim, gate_plan, generation=generation
        )
        run_state = {
            "inputsDigest": inputs["inputsDigest"],
            "ticket": ticket,
            "claimDigest": digest(claim),
            "gatePlanDigest": digest(gate_plan),
            "resumeCount": 0,
            "receipts": [],
        }
    output = output.resolve()
    _write_private(output / RUN_STATE_FILE, run_state)
    started_wall = sleeper.now()
    wall_seconds = manifest["limits"]["maxWallSeconds"]

    def deadline_for():
        return time.monotonic() + transport.REQUEST_SECONDS

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
            session = transport.ProductionSession(
                capability=capability,
                token=credentials["token"],
                api_key=credentials["apiKey"],
                deadline_for=deadline_for,
            )
        else:
            session = session_factory(capability, credentials, deadline_for)
        credentials = None
        stop_point = "preflight-tokeninfo"
        status, body = session.tokeninfo()
        if status != 200:
            raise ValueError(f"tokeninfo answered {status}")
        credential_evidence = transport.verify_tokeninfo(
            body,
            permission["credentialPrincipal"],
            required_seconds=descriptor_.window_seconds,
        )
        stop_point = "preflight-config-readback"
        lock_arguments = {
            "read": session.read_config,
            "patch": session.patch_config,
            "frozen_baseline_digest": permission["authConfigBaselineDigest"],
        }
        lock = (
            ConfigLock.resume(output, **lock_arguments)
            if resume or abandon
            else ConfigLock(output, **lock_arguments)
        )
        if abandon:
            walk = descriptor_.collector(
                session, manifest, output, sleeper=sleeper, resume=True
            )
            walk.reconcile_intents()
            stop_point = "cleanup"
            raise StopRequested("abandon requested")
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
            resume=resume,
            stop_requested=stop_requested,
        )
        if resume:
            walk.reconcile_intents()
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
        cleanup = {
            "ownedAccounts": 0,
            "deleted": 0,
            "absent": 0,
            "complete": False,
            "attempted": False,
        }
        resumable = stopped and not abandon and walk is not None
        if walk is not None and not resumable:
            if stop_point == "cases":
                stop_point = "cleanup" if failure else stop_point
            walk.cleanup()
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
        if lock is not None:
            try:
                lock.restore()
            except ConfigLockError as error:
                failure = failure or type(error).__name__
                if stop_point != "cleanup":
                    stop_point = "restore"
        admission.revoke_production_capability(capability)
    walk_state = copy.deepcopy(walk.state) if walk is not None else None
    rows = walk.ordered_rows() if walk is not None else []
    complete = bool(
        walk is not None
        and failure is None
        and walk.complete()
        and cleanup["complete"]
        and lock is not None
        and lock.record["restoreStatus"] == "restored-verified"
    )
    if stop_point == "cases" and failure is None and complete:
        stop_point = None
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
        claimDigest=digest(claim),
        planDigest=digest(gate_plan),
        hostingRefusals=hosting,
        resumeCount=run_state["resumeCount"],
        wallElapsedSeconds=sleeper.now() - started_wall,
        wallBudgetSeconds=wall_seconds,
        reservationStateAtPublication="held",
        releaseEligible=complete,
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
    if complete:
        try:
            ledger.finish(ticket)
            released = True
        except Exception as error:  # noqa: BLE001 -- never report an unverified release
            release_refusal = type(error).__name__
        release = {
            "receiptDigest": digest(receipt),
            "ticket": ticket,
            "failure": release_refusal,
            "reservationFinal": ledger.snapshot()["reservations"][
                ticket["reservation"]
            ],
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
    restored = lock is not None and lock.record["restoreStatus"] == "restored-verified"
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
