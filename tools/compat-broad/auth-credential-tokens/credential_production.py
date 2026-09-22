"""One admitted AUTH-CREDENTIAL acquisition, with immutable offline-review evidence.

The credential callback runs only after the shared Ledger reservation and the Gate
claim. The management preflight verifies the bearer and reads the Auth config back
before any data request; the case runner and the collector's cleanup are then driven
through the Gate facade, one frozen slot per request. Failed or uncertain cleanup
retains the reservation.

The bootstrap continuation reuses the original reservation, Gate, budget and
deadline after a separately issued observation capability approves its proof.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import secrets
import tempfile
import time
from pathlib import Path

import credential_admission as admission
import credential_descriptor as campaign
import credential_gate as gate_module
import credential_preflight as preflight
import credential_responsibility as responsibility
import credential_shadow as shadow
import reservations
from broad_contract import digest
from credential_cases import observation_cases
from credential_collector import (
    assert_no_secret,
    build_receipt,
    cleanup_report,
    enter_recovery,
    new_budget,
    new_tracker,
)
from credential_gate import (
    CredentialGate,
    account_evidence,
    gate_environment,
    gate_poster,
)
from credential_plan import BUDGET

PROJECT = campaign.PROJECT
RECOVERY_KINDS = ("delete", "uid-absence", "address-absence")


def _envelope(permission: dict, claim: dict) -> dict:
    return {
        "permissionDigest": digest(permission),
        "issuedAt": permission["issuedAt"],
        "expiresAt": permission["expiresAt"],
        "limits": copy.deepcopy(claim["budget"]),
        "concurrency": 1,
        "scopes": copy.deepcopy(claim["locks"]),
    }


def _write_record(
    path: Path, value: dict, secrets_held: list[str] | None = None
) -> None:
    """Persist one immutable record, refusing it if it carries a secret this run held."""
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    if len(encoded) > reservations.MAX_BYTES:
        raise ValueError("bounded immutable production evidence required")
    if secrets_held:
        # A secret-shaped value in evidence is a refusal, never a redaction: the
        # record is not written, and the run reports the leak class.
        assert_no_secret(encoded.decode("utf-8"), secrets_held)
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


def _mint_password() -> str:
    return "Aa9!" + secrets.token_urlsafe(24)


def production_environment(
    management: preflight.ManagementSession, *, signing: bool
) -> dict:
    """The runner environment of a production run: Gate paths and minted secrets."""
    return {
        **shadow.local_environment(),
        **gate_environment(PROJECT, signing=signing),
        "password": _mint_password(),
        "resetPassword": _mint_password(),
        "customTokenIssuer": campaign.SERVICE_ACCOUNT,
        "signer": management.signer,
        "trustRoot": "signed",
    }


def collect_hosted(
    gate,
    gate_plan,
    output,
    *,
    transmit,
    environment,
    nonce,
    binding,
    before=None,
    after=None,
    started_monotonic=None,
    existing_budget=None,
):
    """Run every case and the cleanup through the facade, journaling each route.

    `transmit(declared, body, timeout)` performs the bound wire call; `before` and
    `after` are the poster's hooks (the credential latch). The budget is the lane's
    published one; its cost ceiling is the runaway guard, not a forecast. The
    observation is abandoned on the Gate as soon as the runner stops, so the cleanup
    slots behind the unreached observation slots become admissible.
    """
    routes: list[dict] = []

    def journaled(declared, body, timeout):
        entry = {
            "phase": "recovery"
            if declared["kind"] in RECOVERY_KINDS
            else "observation",
            "route": declared["path"],
            "kind": declared["kind"],
            "requestDigest": digest(declared),
            "status": None,
            "responseDigest": digest(None),
        }
        routes.append(entry)
        status, response = transmit(declared, body, timeout)
        entry.update(status=status, responseDigest=digest(response))
        return status, response

    poster = gate_poster(gate, journaled, before=before, after=after)
    budget = (
        existing_budget
        if existing_budget is not None
        else new_budget(
            BUDGET["maxRequests"],
            BUDGET["maxWallSeconds"],
            BUDGET["maxCostUsd"],
            started_monotonic=time.monotonic()
            if started_monotonic is None
            else started_monotonic,
            recovery_requests=BUDGET["recoveryRequests"],
            recovery_wall_seconds=BUDGET["recoveryWallSeconds"],
        )
    )
    tracker = new_tracker(nonce)
    responsibility.attach(tracker, Path(output) / "responsibility", binding)
    rows, failure = shadow.collect(
        "",
        budget,
        tracker,
        runner=lambda base, b, t, r: shadow.run_cases(
            base, b, t, r, poster=poster, environment=environment
        ),
    )
    if failure is not None:
        try:
            gate.abandon_observation(failure[:120])
        except ValueError:
            pass
    enter_recovery(budget, time.monotonic())
    if existing_budget is not None and budget["recoveryDeadlineMonotonic"] is not None:
        budget["recoveryDeadlineMonotonic"] = min(
            budget["recoveryDeadlineMonotonic"], budget["totalDeadlineMonotonic"]
        )
    try:
        problems = shadow.cleanup(
            "", budget, tracker, poster=poster, environment=environment
        )
    except Exception as error:  # noqa: BLE001 -- the failure class is recorded, never its text.
        problems = ["cleanup: " + type(error).__name__]
    finally:
        responsibility.close(tracker)
    for index, entry in enumerate(routes):
        entry["index"] = index
    return {
        "rows": rows,
        "failure": failure,
        # The exception class that stopped the observation, for the stop point.
        "stopCause": failure.split(":", 1)[0] if failure else None,
        "problems": problems,
        "tracker": tracker,
        "budget": budget,
        "routes": routes,
    }


STOP_CAUSES = {
    "CredentialRefused": "credential-refused",
    "ApiKeyRefused": "api-key-refused",
}


def _stop_point(snapshot, ready, cause=None):
    """Name where a stopped run stopped; a no-data stop is one with no data event.

    A sign-up or custom sign-in whose answer never settled is the one uncertain
    stop: an account may exist that the run does not know. Any other unsettled
    slot cannot have created an account, so it is not reported as that.
    """
    if ready:
        return None
    if snapshot is None:
        return "schedule-not-started"
    if not snapshot.get("events"):
        return "preflight"
    observation = snapshot["plan"]["jobs"][gate_module.JOB]["observation"]
    if any(
        event.get("creationOutcome") not in ("refused", "created")
        and event.get("phase") == "observation"
        and observation[event["index"]]["kind"] in gate_module.CREATING_KINDS
        for event in snapshot["events"]
        if "creationOutcome" in event
    ):
        return "sign-up-unsettled"
    if cause in STOP_CAUSES:
        return STOP_CAUSES[cause]
    job = snapshot["jobs"][gate_module.JOB]
    return (
        "cleanup-incomplete"
        if job["observation"] == len(observation)
        else "observation-incomplete"
    )


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
    plan = inputs["plan"]
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
    # The reservation is taken before the Gate exists and before the handoff is
    # read, so a refused claim leaves only frozen inputs and a refusal record.
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    output = output.resolve()
    _write_record(output / "inputs.json", inputs)
    try:
        ticket = ledger.reserve(
            _envelope(permission, claim), claim, gate_plan, generation=generation
        )
    except Exception as error:
        admission.revoke_production_capability(capability)
        _write_record(
            output / "refusal.json",
            {
                "kind": "auth-credential-admission-refusal-v1",
                "stage": "ledger-reserve",
                "failure": type(error).__name__,
                "message": str(error)[:200],
            },
        )
        raise
    return _execute_after_reservation(
        capability=capability,
        inputs=inputs,
        permission=permission,
        credential_reader=credential_reader,
        ledger=ledger,
        output=output,
        plan=plan,
        gate_plan=gate_plan,
        generation=generation,
        claim=claim,
        ticket=ticket,
    )


def execute_reserved(
    *,
    capability,
    inputs,
    permission,
    preparation,
    preparation_inputs,
    source_root,
    ledger_root,
    output,
):
    """Continue only with an independent observation capability on the same Gate."""
    import credential_bootstrap as bootstrap

    if (
        not admission.issued_capability(capability)
        or not isinstance(inputs, dict)
        or not isinstance(permission, dict)
    ):
        raise ValueError("independent observation O7 required")
    admission.validate_frozen_inputs(inputs)
    admission._approve(
        permission,
        inputs["plan"],
        inputs["sourceCommit"],
        inputs["artifactSha256"],
        inputs["sourceInputs"],
    )
    admission._provenance(source_root, inputs["sourceCommit"], inputs["sourceInputs"])
    if (
        inputs["sourceInputs"] != preparation_inputs["sourceInputs"]
        or inputs["sourceCommit"] != preparation_inputs["sourceCommit"]
        or inputs["plan"] != preparation_inputs["plan"]
    ):
        raise ValueError("observation source or plan differs from preparation")
    ledger = reservations.Ledger(ledger_root)
    ticket, gate = preparation.ticket, preparation.gate
    claim = ledger.bound_claim(ticket)
    row = ledger.snapshot()["reservations"][ticket["reservation"]]
    snapshot = gate.snapshot()
    output = Path(output).resolve()
    if (
        str(output / "gate") != claim["gatePath"]
        or snapshot["total"] != 4
        or snapshot["events"]
    ):
        raise ValueError("fresh continuation on original Gate required")
    if digest(permission) != inputs["permissionDigest"]:
        raise ValueError("observation permission differs")
    if (
        preparation.proof.get("ticket") != ticket
        or _read_saved(output / "preparation-proof.json") != preparation.proof
        or _read_saved(output / "preparation-inputs.json") != preparation_inputs
    ):
        raise ValueError("retained preparation proof differs")
    task_budget = preparation.budget
    if (
        not isinstance(task_budget, dict)
        or task_budget["requests"] != 4
        or task_budget["maxRequests"] != 60
        or task_budget["maxWallSeconds"] != 600
        or task_budget["totalDeadlineMonotonic"]
        != preparation.proof["reservationMonotonicDeadline"]
    ):
        raise ValueError("original preparation budget required")
    handoff = bootstrap.finalize_handoff(
        preparation.prepared,
        permission,
        preparation.proof,
        snapshot=snapshot,
        reservation=row,
        inputs=preparation_inputs,
    )
    ledger.validate(ticket, duration=61)
    if time.monotonic() + 61 >= preparation.proof["reservationMonotonicDeadline"]:
        raise ValueError("original monotonic reservation deadline expired")
    capability._consume(
        campaign_id=campaign.CAMPAIGN,
        inputs_digest=inputs["inputsDigest"],
        ledger_root=ledger_root,
    )
    _write_record(output / "inputs.json", inputs)
    _write_record(
        output / "observation-admission.json",
        {
            "inputsDigest": inputs["inputsDigest"],
            "approvalDigest": capability.approval_digest,
            "bootstrap": permission["bootstrap"],
        },
    )
    return _execute_after_reservation(
        capability=capability,
        inputs=inputs,
        permission=permission,
        credential_reader=lambda: admission.validate_handoff(
            handoff, permission, inputs["plan"]
        ),
        ledger=ledger,
        output=output,
        plan=inputs["plan"],
        gate_plan=snapshot["plan"],
        generation=row["generation"],
        claim=claim,
        ticket=ticket,
        gate=gate,
        preparation_proof=preparation.proof,
        source_root=source_root,
        existing_budget=task_budget,
    )


def _execute_after_reservation(
    *,
    capability,
    inputs,
    permission,
    credential_reader,
    ledger,
    output,
    plan,
    gate_plan,
    generation,
    claim,
    ticket,
    gate=None,
    preparation_proof=None,
    source_root=None,
    existing_budget=None,
):
    management = None
    collected = None
    failure = None
    ready = False
    snapshot = None
    environment = None
    secrets_held: list[str] = []
    binding, binding_digest = capability._binding, capability.binding_digest
    try:
        if gate is None:
            gate_module.create(output / "gate", gate_plan)
            gate = CredentialGate(output / "gate")
            gate.claim()
        handoff = credential_reader()
        secrets_held = [handoff["token"], handoff["apiKey"]]
        management = preflight.ManagementSession(
            gate=gate,
            ledger=ledger,
            ticket=ticket,
            capability=capability,
            inputs=inputs,
            permission=permission,
            handoff=handoff,
            binding=binding,
            binding_digest=binding_digest,
            reservation_deadline=preparation_proof["reservationDeadline"]
            if preparation_proof
            else None,
            monotonic_deadline=preparation_proof["reservationMonotonicDeadline"]
            if preparation_proof
            else None,
            source_check=(
                lambda: admission._provenance(
                    source_root, inputs["sourceCommit"], inputs["sourceInputs"]
                )
            )
            if preparation_proof
            else None,
        )
        handoff = None
        management.run("observation")
        if existing_budget is not None:
            existing_budget["requests"] = gate.snapshot()["total"]

        def transmit(declared, body, timeout):
            deadline = time.monotonic() + timeout
            if preparation_proof is not None:
                admission._provenance(
                    source_root, inputs["sourceCommit"], inputs["sourceInputs"]
                )
                ledger.validate(ticket, duration=max(1, math.ceil(timeout)))
                remaining = min(
                    preparation_proof["reservationDeadline"] - time.time(),
                    preparation_proof["reservationMonotonicDeadline"]
                    - time.monotonic(),
                    permission["expiresAt"] - time.time(),
                    capability.window_expires_at - time.time(),
                )
                if declared["kind"] not in RECOVERY_KINDS:
                    remaining -= campaign.recovery_seconds()
                deadline = min(deadline, time.monotonic() + remaining)
                if deadline <= time.monotonic():
                    raise ValueError("original reservation deadline expired")
            return capability._transmit(
                {
                    "kind": "data",
                    "declared": declared,
                    "body": body,
                    # An API-key slot still presents no bearer; the token is read
                    # here only so a latched bearer refuses the slot before the wire.
                    "token": management.data_token(deadline),
                    "apiKey": management.api_key(),
                    "deadline": deadline,
                }
            )

        # A 401 or 403 on an owner slot latches the bearer: no further owner call,
        # not even a cleanup delete, is attempted with it, and the receipt records
        # the accounts that remain (the lane's privileged-call-refused rehearsal).
        # A refusal on an API-key slot stops the observation only; cleanup still
        # runs with the bearer under the recovery reserve.
        def after(declared, status, _body):
            management.observe_status(declared, status)

        environment = production_environment(management, signing=plan["signing"])
        secrets_held += [environment["password"], environment["resetPassword"]]
        collected = collect_hosted(
            gate,
            gate_plan,
            output,
            transmit=transmit,
            environment=environment,
            nonce=plan["nonce"],
            binding={
                "inputsDigest": inputs["inputsDigest"],
                "sourceCommit": inputs["sourceCommit"],
            },
            before=management.require_bearer,
            after=after,
            started_monotonic=preparation_proof["reservationMonotonicDeadline"]
            - campaign.campaign_seconds()
            if preparation_proof is not None
            else None,
            existing_budget=existing_budget,
        )
        if (
            collected["failure"] is None
            and collected["problems"] == []
            and cleanup_report(collected["tracker"])["cleanupComplete"]
        ):
            management.run("recovery")
            if existing_budget is not None:
                existing_budget["requests"] = gate.snapshot()["total"]
            gate.finish()
            ready = True
        else:
            failure = "collection-incomplete"
    except Exception as error:  # noqa: BLE001 -- preserve only a secret-free failure class.
        failure = type(error).__name__
    finally:
        admission.revoke_production_capability(capability)
        if management is not None:
            secrets_held += management.forget()
    if gate is not None:
        snapshot = gate.snapshot()
    rows = collected["routes"] if collected else []
    _write_record(output / "routes.json", {"rows": rows}, secrets_held)
    if snapshot is not None:
        _write_record(output / "gate-snapshot.json", snapshot, secrets_held)
    result = None
    if collected is not None:
        ordered = [
            collected["rows"].get(
                case["id"],
                shadow.not_run_row(
                    case,
                    shadow.SIGNING_ABSENT_REASON
                    if not plan["signing"] and case["requiresSigning"]
                    else None,
                ),
            )
            for case in observation_cases()
        ]
        result = build_receipt(
            side="production",
            rows=ordered,
            tracker=collected["tracker"],
            budget=collected["budget"],
            source_binding={
                "commit": inputs["sourceCommit"],
                "artifactSha256": inputs["artifactSha256"],
            },
            production_executed=True,
        )
        (output / "collection").mkdir(mode=0o700)
        _write_record(output / "collection" / "receipt.json", result, secrets_held)
    evidence = {}
    for path in [
        output / "inputs.json",
        output / "routes.json",
        output / "gate-snapshot.json",
        output / "collection" / "receipt.json",
        output / "preparation-inputs.json",
        output / "preparation-proof.json",
        output / "observation-admission.json",
    ]:
        if path.is_file():
            evidence[str(path.relative_to(output))] = hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
    receipt = admission.build_receipt(
        inputs,
        result,
        rows=rows,
        generation=generation,
        failure=failure,
        stop_point=_stop_point(
            snapshot, ready, collected["stopCause"] if collected else None
        ),
    )
    receipt.update(
        ticket=ticket,
        claimDigest=digest(claim),
        campaignPlanDigest=inputs["planDigest"],
        planDigest=digest(gate_plan),
        gateDigest=digest(snapshot) if snapshot is not None else None,
        evidenceFiles=evidence,
        chargedCalls=snapshot["total"] if snapshot else 0,
        accountEvidence=account_evidence(snapshot) if snapshot else None,
        credentialEvidence=management.credential_evidence if management else [],
        managementEvidence=management.evidence if management else [],
        signatureEvidence=management.signature_evidence if management else [],
        preflightComplete=bool(management and management.preflight_complete),
        postflightComplete=bool(management and management.postflight_complete),
        reservationStateAtPublication="held",
        releaseEligible=ready,
        releaseRecord="release.json" if ready else None,
        executionKind="fixed-production-wire",
        productionExecuted=bool(rows),
        workerSha256=inputs["sourceInputs"][campaign.WORKER_ENTRY],
        mayHaveCreated=bool(snapshot and account_evidence(snapshot)["createdAccounts"]),
        comparison=campaign.comparator(result)
        if ready and result is not None
        else None,
    )
    if preparation_proof is not None:
        receipt["preparationProof"] = preparation_proof
        if snapshot is not None and snapshot["events"] == []:
            # No-data retirement must bind the entire actual management prefix.
            receipt["managementEvidence"] = [
                *preparation_proof["managementEvidence"],
                *receipt["managementEvidence"],
            ]
        receipt["observationApprovalDigest"] = digest(
            _read_saved(output / "observation-admission.json")
        )
    _write_record(output / "receipt.json", receipt, secrets_held)
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
        _write_record(output / "release.json", release, secrets_held)
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


def verify_saved(output, *, expected_inputs_digest, ledger_root):
    """Verify completed evidence against independently retained inputs and Ledger.

    Read-only: no credential, capability or transport. The Ledger anchors the final
    Gate snapshot; the release record links that snapshot to the immutable receipt.
    """
    if not isinstance(expected_inputs_digest, str) or len(expected_inputs_digest) != 64:
        raise ValueError("independently retained frozen inputs digest required")
    if Path(output).is_symlink():
        raise ValueError("regular evidence directory required")
    output = Path(output).resolve()
    inputs = _read_saved(output / "inputs.json")
    receipt = _read_saved(output / "receipt.json")
    release = _read_saved(output / "release.json")
    snapshot = _read_saved(output / "gate-snapshot.json")
    collection = _read_saved(output / "collection" / "receipt.json")
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
        or receipt.get("collection") != collection
        or collection.get("recordingComplete") is not True
        or collection.get("cleanup", {}).get("cleanupComplete") is not True
    ):
        raise ValueError("saved acquisition binding differs")
    preflight.validate_saved_management(
        receipt, snapshot, inputs["permission"], signing=inputs["plan"]["signing"]
    )
    ledger = reservations.Ledger(ledger_root)
    ledger.bound_claim(receipt["ticket"])
    final = ledger.snapshot()["reservations"].get(receipt["ticket"]["reservation"])
    if receipt.get("preparationProof") is not None:
        import credential_bootstrap as bootstrap

        prep_inputs = _read_saved(output / "preparation-inputs.json")
        proof = _read_saved(output / "preparation-proof.json")
        observation = _read_saved(output / "observation-admission.json")
        bootstrap.validate_proof(
            proof, snapshot=snapshot, reservation=final, inputs=prep_inputs
        )
        if (
            receipt["preparationProof"] != proof
            or inputs["permission"].get("bootstrap")
            != bootstrap.observation_binding(proof)
            or inputs["permission"].get("authConfigDigest") != proof["authConfigDigest"]
            or observation.get("inputsDigest") != expected_inputs_digest
            or observation.get("bootstrap") != inputs["permission"]["bootstrap"]
            or digest(observation) != receipt.get("observationApprovalDigest")
        ):
            raise ValueError("saved independent observation authority differs")
    if (
        final is None
        or final != release["reservationFinal"]
        or final.get("state") != "released"
        or final.get("finalGateDigest") != digest(snapshot)
        or receipt.get("gateDigest") != digest(snapshot)
        or receipt.get("claimDigest") != final.get("claimDigest")
        or final["claim"]["gatePlanDigest"] != digest(snapshot["plan"])
        or final.get("generation") != receipt.get("generation")
        or receipt.get("workerSha256") != inputs["sourceInputs"][campaign.WORKER_ENTRY]
    ):
        raise ValueError("saved Ledger release binding differs")
    for name, expected in receipt.get("evidenceFiles", {}).items():
        path = output / name
        if (
            ".." in Path(name).parts
            or path.is_symlink()
            or not path.is_file()
            or hashlib.sha256(path.read_bytes()).hexdigest() != expected
        ):
            raise ValueError("saved evidence file differs")
    accounts = account_evidence(snapshot)
    if (
        not accounts["complete"]
        or accounts["deletedAccounts"] != accounts["createdAccounts"]
        or accounts["uidAbsenceReadbacks"] != accounts["createdAccounts"]
        or receipt.get("accountEvidence") != accounts
        or len(receipt.get("metadata", [])) + len(snapshot.get("managementEvents", []))
        != snapshot["total"]
    ):
        raise ValueError("saved account evidence differs")
    return receipt
