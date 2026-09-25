"""One admitted FS-WRITE-LIMITS-03 acquisition, with immutable offline evidence.

The credential callback runs only after the shared Ledger reservation and the
Gate claim. Failed or uncertain cleanup retains the reservation. A run that
stopped before any creating slot is retirable as no data; one that stopped
after a confirmed create is not, and stays held until its Gate journal proves
every created document absent.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
import time
from pathlib import Path
from urllib.parse import quote

import limits_03_admission as admission
import limits_03_descriptor as campaign
import limits_03_preflight as preflight
import limits_03_remote_transport as remote
import reservations
import shared_gate
from broad_contract import digest
from collector_03 import collect

EVIDENCE_SUMMARY_KEYS = (
    "recordingComplete",
    "cleanupComplete",
    "collectionComplete",
    "expectationMismatches",
    "pendingDifferences",
    "infrastructureFailures",
    "resourceAbsence",
)


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


def _index_exemption_verified(management, identifier: str) -> bool:
    """Require a successful transport and a verified exemption projection."""
    for row in management.evidence if management is not None else ():
        if not isinstance(row, dict) or row.get("id") != identifier:
            continue
        response = row.get("response")
        body = response.get("body") if isinstance(response, dict) else None
        if (
            isinstance(response, dict)
            and response.get("complete") is True
            and isinstance(body, dict)
            and body.get("baselineVerified") is True
        ):
            return True
    return False


def first_creating_index(plan: dict) -> int:
    schedule = plan["localGatePlan"]["jobs"]["limits"]["schedule"]
    return next(
        index
        for index, entry in enumerate(schedule)
        if entry["phase"] == "observation" and entry["creates"]
    )


def _stop_point(snapshot, plan, ready):
    """Where a stopped run stopped, read from the Gate journal.

    A run whose journal holds no creating dispatch at all stopped inside the
    typed-absence preflight of the owned names and is a no-data stop. One
    with an unconfirmed create may have written and is uncertain. One that
    created and then abandoned its observation, or completed observation and
    did not reach the normal close, has documents to account for.
    """
    if ready:
        return None
    if snapshot is None or not snapshot.get("events"):
        return "schedule-not-started"
    job = snapshot["jobs"][campaign.GATE_JOB]
    if shared_gate.unconfirmed_creates(snapshot, campaign.GATE_JOB):
        return "create-deadline"
    if (
        not job.get("creationProofs")
        and shared_gate.creating_outcome(snapshot, campaign.GATE_JOB) == "none"
    ):
        return "namespace-preflight"
    if job.get("stopReason") is not None or job["observation"] < len(
        plan["localGatePlan"]["jobs"]["limits"]["observation"]
    ):
        return "observation-incomplete"
    return "recovery-incomplete"


def _summary(result):
    """The collection with its journals replaced by digests.

    The rows carry every response body, which for this campaign includes a
    dozen documents near the megabyte limit; the receipt binds them by the
    digest of the collection record on disk rather than embedding them.
    """
    if result is None:
        return None
    summary = {key: copy.deepcopy(result.get(key)) for key in EVIDENCE_SUMMARY_KEYS}
    summary["rowsDigest"] = digest(result.get("rows"))
    summary["cleanupDigest"] = digest(result.get("cleanup"))
    summary["rowCount"] = len(result.get("rows") or [])
    summary["cleanupCount"] = len(result.get("cleanup") or [])
    return summary


def semantic_classification(receipt: dict) -> str:
    """Classify saved semantics without changing the independent safety verdict."""
    collection = receipt.get("collection")
    mismatches = (
        collection.get("expectationMismatches")
        if isinstance(collection, dict)
        else None
    )
    if not isinstance(mismatches, list):
        raise ValueError("saved semantic comparison is not a bound mismatch list")
    return "SEMANTIC_MISMATCH" if mismatches else "MATCH"


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
    rows = []
    result = None
    failure = None
    ready = False
    recovery_attempted = False
    recovery_failure = None
    snapshot = None
    management = None
    # The collector's Gate binding compares the created Gate's jobs with the
    # plan's own, so the plan handed to it carries the production projection.
    collector_plan = {**plan, "localGatePlan": gate_plan}
    try:
        shared_gate.create(output / "gate", gate_plan)
        gate = shared_gate.Gate(output / "gate", campaign.GATE_JOB)
        gate.claim()
        token = credential_reader()
        management = preflight.ManagementSession(
            gate=gate,
            ledger=ledger,
            ticket=ticket,
            capability=capability,
            inputs=inputs,
            permission=permission,
            token=token,
        )
        try:
            management.run("observation")
        except Exception as error:
            event = gate.snapshot()["managementEvents"][-1]
            lifecycle_events = gate.snapshot()["managementEvents"]
            lifecycle_ids = {
                "observation:index-lifecycle-apply",
                "observation:index-lifecycle-poll",
                "observation:index-lifecycle-after",
            }
            if event.get("id") not in lifecycle_ids or event.get("workerReaped") is not True:
                raise
            cancel = event.get("completed") is True
            failure = type(error).__name__
            try:
                if cancel:
                    if not any(
                        row.get("id") == "observation:index-lifecycle-apply"
                        and row.get("completed") is True
                        and row.get("workerReaped") is True
                        for row in lifecycle_events
                    ):
                        raise ValueError("completed lifecycle apply evidence required")
                    gate.cancel_management_observation()
                else:
                    gate.abort_management_observation()
                recovery_attempted = True
                try:
                    management.run("recovery")
                except Exception as recovery_error:
                    recovery_failure = type(recovery_error).__name__
                    raise
            except Exception as recovery_error:  # noqa: BLE001 -- retain the reservation.
                failure = type(recovery_error).__name__
            else:
                failure = "management-observation-aborted"
            token = None
        else:
            token = None

        def execute_wire(operation, recovery, index, request_index):
            phase = "recovery" if recovery else "observation"
            entry = {
                "phase": phase,
                "index": index,
                "route": operation["path"],
                "requestDigest": digest(operation),
                "status": None,
                "responseDigest": digest(None),
            }
            rows.append(entry)
            ceiling = plan["requests"][request_index]["responseByteLimit"]
            # The slot's own reservation is its wire deadline; the Gate has
            # already admitted the slot inside the phase window.
            deadline = time.monotonic() + remote.slot_timeout(operation, ceiling)
            receipt = capability._transmit(
                admission.transport_call(
                    plan,
                    phase,
                    index,
                    operation,
                    management.data_token(deadline),
                    deadline=deadline,
                )
            )
            if not isinstance(receipt, dict):
                raise TypeError("bounded transport receipt required")
            preflight.observe_status(management.credential, receipt.get("status"))
            complete = (
                receipt.get("complete") is True and receipt.get("failure") is None
            )
            entry.update(
                status=receipt.get("status"),
                responseDigest=digest(receipt.get("body"))
                if complete
                else digest({"failure": receipt.get("failure")}),
            )
            return receipt

        if failure is None:
            result = collect(gate, collector_plan, output / "collection", execute_wire)
            if result.get("collectionComplete") and result.get("cleanupComplete"):
                recovery_attempted = True
                try:
                    management.run("recovery")
                except Exception as recovery_error:
                    recovery_failure = type(recovery_error).__name__
                    raise
                ready = not management.lifecycle_failed
            else:
                failure = "collection-incomplete"
                raise ValueError("collection incomplete")
    except Exception as error:  # noqa: BLE001 -- preserve only a secret-free failure class.
        failure = type(error).__name__
        if (
            management is not None
            and not recovery_attempted
            and not management.postflight_complete
            and (
                management.preflight_complete
                or "after" in getattr(management, "_lifecycle", {})
            )
        ):
            recovery_attempted = True
            try:
                if not gate.snapshot().get("events"):
                    gate.cancel_management_observation()
                management.run("recovery")
            except Exception as recovery_error:  # noqa: BLE001 -- retain held responsibility.
                recovery_failure = type(recovery_error).__name__
                failure = type(recovery_error).__name__
    finally:
        admission.revoke_production_capability(capability)
    if gate is not None:
        snapshot = gate.snapshot()
    _write_receipt(output / "routes.json", {"rows": rows})
    if snapshot is not None:
        _write_receipt(output / "gate-snapshot.json", snapshot)
    evidence = {}
    for path in [
        output / "inputs.json",
        output / "routes.json",
        output / "gate-snapshot.json",
        *sorted((output / "collection").glob("*")),
    ]:
        if path.is_file():
            evidence[str(path.relative_to(output))] = hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
    created = (
        sorted(snapshot["jobs"][campaign.GATE_JOB].get("creationProofs", {}))
        if snapshot is not None
        else []
    )
    receipt = admission.build_receipt(
        inputs,
        _summary(result),
        capability=None,
        rows=rows,
        generation=generation,
        failure=failure,
        stop_point=_stop_point(snapshot, plan, ready),
    )
    receipt.update(
        ticket=ticket,
        claimDigest=digest(claim),
        campaignPlanDigest=inputs["planDigest"],
        planReference=copy.deepcopy(inputs["plan"]),
        planDigest=digest(gate_plan),
        gateDigest=digest(snapshot) if snapshot is not None else None,
        evidenceFiles=evidence,
        chargedCalls=snapshot["total"] if snapshot else 0,
        credentialEvidence=management.credential_evidence if management else [],
        managementEvidence=management.evidence if management else [],
        recoveryAttempted=recovery_attempted,
        recoveryFailure=recovery_failure,
        preflightComplete=bool(management and management.preflight_complete),
        postflightComplete=bool(management and management.postflight_complete),
        createdResources=created,
        abandonedCleanupComplete=bool(
            snapshot is not None
            and shared_gate.abandoned_cleanup_complete(snapshot) is not None
        ),
        indexExemption={
            "precondition": permission["indexExemptionPrecondition"],
            "verifiedAtPreflight": _index_exemption_verified(
                management, "observation:index-exemption"
            ),
            "verifiedAtPostflight": _index_exemption_verified(
                management, "recovery:index-exemption"
            ),
            "restoreRequired": True,
            "restoreTo": permission["indexExemptionPrecondition"][
                "conformanceIndexesSha256Before"
            ],
        },
        reservationStateAtPublication="held",
        releaseEligible=ready,
        releaseRecord="release.json" if ready else None,
        executionKind="fixed-production-wire",
        productionExecuted=bool(rows),
        workerSha256=inputs["sourceInputs"][campaign.WORKER_ENTRY],
        mayHaveCreated=bool(
            snapshot
            and shared_gate.creating_outcome(snapshot, campaign.GATE_JOB) != "none"
        ),
    )
    _write_receipt(output / "receipt.json", receipt)
    released = False
    release = None
    if ready:
        try:
            ledger.finish(ticket)
            released = True
        except Exception as error:  # noqa: BLE001 -- never report an unverified release.
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


# The collection record carries every response body, a dozen of them near the
# megabyte document limit, so it is bounded above the Ledger's receipt cap.
EVIDENCE_FILE_MAX_BYTES = 256 * 1024 * 1024


def _read_saved(path, *, limit=reservations.MAX_BYTES):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise ValueError("bounded regular saved evidence required")
    return json.loads(path.read_bytes())


def _verify_saved(output, *, expected_inputs_digest, ledger_root, release=None):
    """Verify completed evidence against independently retained inputs and Ledger.

    Read-only: no credential, capability or transport. The Ledger anchors the
    final Gate snapshot; the release record links that snapshot to the
    immutable receipt and its per-file evidence digests; every charged Gate
    event is matched to its route row and to the wire receipt on disk.
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
        or receipt.get("planReference") != inputs["plan"]
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
    exemption = receipt.get("indexExemption")
    if (
        not isinstance(exemption, dict)
        or exemption.get("verifiedAtPreflight") is not True
        or exemption.get("verifiedAtPostflight") is not True
        or exemption.get("restoreRequired") is not True
        or exemption.get("precondition")
        != inputs["permission"].get("indexExemptionPrecondition")
    ):
        raise ValueError("saved index exemption attestation differs")
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
    if (
        not isinstance(evidence, dict)
        or not {
            "inputs.json",
            "routes.json",
            "gate-snapshot.json",
            "collection/collection.json",
        }
        <= evidence.keys()
    ):
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
            or path.stat().st_size > EVIDENCE_FILE_MAX_BYTES
            or hashlib.sha256(path.read_bytes()).hexdigest() != expected
        ):
            raise ValueError("saved evidence file differs")
    collection = _read_saved(
        output / "collection/collection.json", limit=EVIDENCE_FILE_MAX_BYTES
    )
    routes = _read_saved(output / "routes.json")["rows"]
    if (
        _summary(collection) != receipt.get("collection")
        or collection.get("collectionComplete") is not True
        or collection.get("cleanupComplete") is not True
        or not isinstance(collection.get("expectationMismatches"), list)
        or len(routes) + len(snapshot.get("managementEvents", [])) != snapshot["total"]
        or receipt.get("chargedCalls") != snapshot["total"]
        or receipt.get("metadata")
        != [
            {
                "id": f"{row['phase']}:{row['index']:03d}",
                "route": row["route"],
                "status": row["status"],
                "responseDigest": row["responseDigest"],
            }
            for row in routes
        ]
        or receipt.get("routeDigest") != digest(receipt.get("metadata"))
    ):
        raise ValueError("saved route journal differs")
    plan = snapshot["plan"]["jobs"][campaign.GATE_JOB]
    for route, event in zip(routes, snapshot["events"], strict=True):
        if event["job"] != campaign.GATE_JOB:
            raise ValueError("saved Gate event belongs to another job")
        operation = plan[event["phase"]][event["index"]]
        phase_name = "cleanup" if event["phase"] == "recovery" else "observation"
        wire_name = f"collection/{phase_name}-{event['index']:02d}-wire.json"
        if wire_name not in evidence:
            raise ValueError("saved per-request evidence missing")
        wire = _read_saved(output / wire_name, limit=EVIDENCE_FILE_MAX_BYTES)
        expected_path = operation["path"]
        if operation["method"] == "DELETE":
            version = snapshot["jobs"][campaign.GATE_JOB]["creationProofs"][
                operation["path"].removeprefix("/v1/")
            ]["updateTime"]
            expected_path += "?currentDocument.updateTime=" + quote(version, safe="")
        if (
            wire.get("index") != event["index"]
            or wire.get("request", {}).get("path") != expected_path
            or wire.get("request", {}).get("method") != operation["method"]
            or wire.get("complete") is not True
            or wire.get("failure") is not None
            or wire.get("status") != event["status"]
            or digest(wire.get("body")) != event["responseDigest"]
            or route["phase"] != event["phase"]
            or route["index"] != event["index"]
            or route["requestDigest"] != event["requestDigest"]
            or route["responseDigest"] != event["responseDigest"]
            or route["status"] != event["status"]
            or event.get("completed") is not True
            or route["route"] != expected_path
        ):
            raise ValueError("saved response differs from Ledger-bound Gate event")
    job = snapshot["jobs"][campaign.GATE_JOB]
    if not job["complete"] or shared_gate.unconfirmed_creates(
        snapshot, campaign.GATE_JOB
    ):
        raise ValueError("saved Gate cleanup incomplete")
    shared_gate.validate_absence_proofs(snapshot, campaign.GATE_JOB)
    return receipt


def verify_saved(output, *, expected_inputs_digest, ledger_root):
    """Require a persisted release record and verify its complete evidence chain."""
    return _verify_saved(
        output, expected_inputs_digest=expected_inputs_digest, ledger_root=ledger_root
    )


def recover_release(output, *, expected_inputs_digest, ledger_root):
    """Publish missing release evidence after the Ledger already released the run.

    This reads no credential, sends no request, and never reserves or finishes
    a Ledger row a second time. Existing files are never replaced.
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
