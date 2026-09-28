"""One admitted request-byte acquisition, with immutable offline-review evidence.

The credential callback runs only after the shared Ledger reservation and all
three Gate claims. Failed or uncertain cleanup retains the reservation. A
zero-dispatch failure remains held until an external owner proves worker exit.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import tempfile
from pathlib import Path
from urllib.parse import quote

import request_bytes_admission as admission
import request_bytes_descriptor as campaign
import request_bytes_preflight as preflight
import request_bytes_remote_transport as remote
import reservations
import shared_gate
from broad_contract import digest
from request_bytes_collector import (
    SEMANTIC_OUTCOMES,
    _validated_response,
    cleanup_safety_complete,
    collect_local,
    commit_versions,
    complete,
    typed_firestore_refusal,
    typed_over_refusal,
)
from request_bytes_compiler import RAW_16MIB_OVER_BYTES, RAW_16MIB_OVER_CASE_ID


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


def _stop_point(snapshot, plan, ready):
    if ready:
        return None
    if snapshot is None or not snapshot.get("events"):
        return "schedule-not-started"
    for probe in plan["probes"]:
        scope = campaign.gate_scope_for_probe(plan, probe)
        name = campaign.gate_job_name(scope)
        if shared_gate.unconfirmed_creates(snapshot, name):
            return f"{scope}-commit-deadline"
    last = snapshot["events"][-1]
    operation = snapshot["plan"]["jobs"][last["job"]][last["phase"]][last["index"]]
    probe = next(item for item in plan["probes"] if item["label"] == operation["probe"])
    scope = probe["scope"].rsplit("/", 1)[-1]
    return (
        f"{scope}-preflight"
        if operation["kind"] == "preflight-typed-absence"
        else f"{scope}-incomplete"
    )


RESERVATION_MARKER_KIND = "request-bytes-reservation-marker-v1"


def execute(
    *,
    capability,
    inputs,
    permission,
    credential_reader,
    ledger_root,
    output,
    reserved=None,
):
    """Execute only the consumed capability's fixed transport; never accept one.

    `reserved`, when given, is called with the ticket the moment the shared
    Ledger row exists, before any Gate, handoff or wire activity, so a caller
    can tell a refusal that charged nothing from a stop that left a row held.
    The same fact is persisted as `<output>/reservation.json`.
    """
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
    if reserved is not None:
        reserved(ticket)
    # A row now exists whatever happens next. The marker names it durably so
    # that an operator retiring this directory never has to infer from an exit
    # code whether a reservation was taken.
    _write_receipt(
        output / "reservation.json",
        {
            "kind": RESERVATION_MARKER_KIND,
            "ticket": ticket,
            "claimDigest": digest(claim),
            "gatePath": claim["gatePath"],
        },
    )
    gates, rows = {}, []
    result = None
    failure = None
    ready = False
    snapshot = None
    management = None
    try:
        shared_gate.create(output / "gate", gate_plan)
        for probe in plan["probes"]:
            scope = campaign.gate_scope_for_probe(plan, probe)
            gate = shared_gate.Gate(output / "gate", campaign.gate_job_name(scope))
            gate.claim()
            gates[probe["label"]] = gate
        token = credential_reader()
        management = preflight.ManagementSession(
            gate=next(iter(gates.values())),
            ledger=ledger,
            ticket=ticket,
            capability=capability,
            inputs=inputs,
            permission=permission,
            token=token,
        )
        management.run("observation")
        token = None
        # Coordinates come from the frozen operations, not a count of sends:
        # refused creates skip deletes without consuming transport positions.
        coordinates = {
            (operation["probe"], operation["kind"], operation.get("resource")): (
                phase,
                index,
            )
            for phase in ("observation", "recovery")
            for index, operation in enumerate(plan[phase])
        }

        def execute_wire(operation, *, deadline):
            phase, index = coordinates[
                (operation["probe"], operation["kind"], operation.get("resource"))
            ]
            entry = {
                "phase": phase,
                "index": index,
                "route": operation["path"],
                "requestDigest": digest(operation),
                "status": None,
                "responseDigest": digest(None),
            }
            rows.append(entry)
            receipt = _validated_response(
                capability._transmit(
                    admission.transport_call(
                        plan,
                        phase,
                        index,
                        operation,
                        management.data_token(deadline),
                        deadline=deadline,
                    )
                )
            )
            preflight.observe_status(management.credential, receipt.get("status"))
            entry.update(
                status=receipt.get("status"),
                responseDigest=digest(receipt.get("body"))
                if complete(receipt)
                else digest({"failure": receipt.get("failure")}),
            )
            return receipt

        result = collect_local(plan, execute_wire, output / "collection", gate=gates)
        if (
            result.get("cleanupSafetyComplete") is True
            and cleanup_safety_complete(result)
        ):
            management.run("recovery")
            for gate in gates.values():
                gate.finish()
            ready = True
        else:
            failure = "collection-incomplete"
    except Exception as error:  # noqa: BLE001 -- preserve only a secret-free failure class.
        failure = type(error).__name__
    finally:
        admission.revoke_production_capability(capability)
    if gates:
        snapshot = next(iter(gates.values())).snapshot()
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
    receipt = admission.build_receipt(
        inputs,
        result,
        capability=None,
        rows=rows,
        generation=generation,
        failure=failure,
        stop_point=_stop_point(snapshot, plan, ready),
    )
    receipt.update(
        ticket=ticket,
        claimDigest=digest(claim),
        # The shared retirement protocol binds the Gate plan here; retain the
        # campaign's independently frozen plan under its own explicit name.
        campaignPlanDigest=inputs["planDigest"],
        planDigest=digest(gate_plan),
        gateDigest=digest(snapshot) if snapshot is not None else None,
        evidenceFiles=evidence,
        chargedCalls=snapshot["total"] if snapshot else 0,
        credentialEvidence=management.credential_evidence if management else [],
        managementEvidence=management.evidence if management else [],
        preflightComplete=bool(management and management.preflight_complete),
        postflightComplete=bool(management and management.postflight_complete),
        reservationStateAtPublication="held",
        releaseEligible=ready,
        releaseRecord="release.json" if ready else None,
        executionKind="fixed-production-wire",
        productionExecuted=bool(rows),
        workerSha256=inputs["sourceInputs"][campaign.WORKER_ENTRY],
        mayHaveCreated=bool(
            snapshot
            and any(
                shared_gate.creating_outcome(snapshot, name) != "none"
                for name in snapshot["jobs"]
            )
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


def _read_saved(path):
    if (
        path.is_symlink()
        or not path.is_file()
        or path.stat().st_size > reservations.MAX_BYTES
    ):
        raise ValueError("bounded regular saved evidence required")
    return json.loads(path.read_bytes())


def _saved_sentinel_body_refs(inputs, snapshot):
    """Return only compiled sentinel body files bound by the saved Gate plan."""
    reference = inputs.get("plan")
    if (
        not isinstance(reference, dict)
        or reference.get("caseId") != RAW_16MIB_OVER_CASE_ID
        or reference.get("caseMode") != "single-exploratory-sentinel"
    ):
        return {}
    plan = campaign.execution_plan(reference)
    if plan.get("caseMode") != "single-exploratory-sentinel":
        return {}
    gate_operations = [
        operation
        for job in snapshot.get("plan", {}).get("jobs", {}).values()
        for operation in job.get("observation", [])
    ]
    allowed = {}
    for operation in plan["observation"]:
        body = operation.get("body")
        if body is None or operation.get("kind") != "conditional-create-commit":
            continue
        body_ref = shared_gate.body_reference(body)
        if (
            body_ref["bytes"] != RAW_16MIB_OVER_BYTES
            or body_ref["bytes"] != remote.MAX_SENTINEL_REQUEST_BYTES
        ):
            continue
        matches = [
            gate_operation
            for gate_operation in gate_operations
            if gate_operation.get("probe") == operation.get("probe")
            and gate_operation.get("kind") == operation["kind"]
            and gate_operation.get("bodyRef") == body_ref
        ]
        if len(matches) == 1:
            name = f"collection/request-{operation['probe']}.body"
            allowed[name] = body_ref
    return allowed


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
    campaign.validate_generation(receipt.get("generation"), inputs)
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
    if (
        not isinstance(evidence, dict)
        or not {
            "inputs.json",
            "routes.json",
            "gate-snapshot.json",
            "collection/result.json",
        }
        <= evidence.keys()
    ):
        raise ValueError("saved evidence inventory incomplete")
    sentinel_body_refs = _saved_sentinel_body_refs(inputs, snapshot)
    for name, expected in evidence.items():
        relative = Path(name)
        path = output / relative
        body_ref = sentinel_body_refs.get(name)
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or path.is_symlink()
            or any(parent.is_symlink() for parent in path.parents if parent != output)
            or not path.is_file()
        ):
            raise ValueError("saved evidence file differs")
        size = path.stat().st_size
        if size > reservations.MAX_BYTES and (
            body_ref is None
            or size != body_ref["bytes"]
            or expected != body_ref["sha256"]
        ):
            raise ValueError("saved evidence file differs")
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError("saved evidence file differs")
    collection = _read_saved(output / "collection/result.json")
    routes = _read_saved(output / "routes.json")["rows"]
    if (
        collection != receipt.get("collection")
        or collection.get("cleanupSafetyComplete") is not True
        or not cleanup_safety_complete(collection)
        or collection.get("formalCompatibilityClaim") is not False
        or collection.get("semanticOutcome") not in SEMANTIC_OUTCOMES
        # The Gate total counts the seven charged management slots as well as
        # the data routes; the route journal carries only the data routes.
        or len(routes) + len(snapshot.get("managementEvents", []))
        != snapshot["total"]
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
    actual_semantic_outcome = None
    plan = campaign.execution_plan(inputs["plan"])
    job_names = [
        campaign.gate_job_name(campaign.gate_scope_for_probe(plan, probe))
        for probe in plan["probes"]
    ]
    sequence_offset = 0
    for route, event in zip(routes, snapshot["events"], strict=True):
        # Job order in canonical JSON is alphabetical, so recover the compiler
        # order from the frozen probe list rather than serialized object order.
        probe_index = job_names.index(event["job"])
        probe = plan["probes"][probe_index]
        gate_job = snapshot["plan"]["jobs"][event["job"]]
        operation = gate_job[event["phase"]][event["index"]]
        probe_operations = [
            item
            for item in plan[event["phase"]]
            if item.get("probe") == probe["label"]
        ]
        global_index = next(
            index
            for index, item in enumerate(plan[event["phase"]])
            if item.get("probe") == probe["label"]
            and sum(
                1
                for prior in plan[event["phase"]][:index]
                if prior.get("probe") == probe["label"]
            )
            == event["index"]
        )
        phase_lengths = {
            phase: len(
                [
                    item
                    for item in plan[phase]
                    if item.get("probe") == probe["label"]
                ]
            )
            for phase in ("observation", "recovery")
        }
        sequence = sequence_offset + event["index"]
        if event["phase"] == "recovery":
            sequence += phase_lengths["observation"]
        if event["index"] == phase_lengths[event["phase"]] - 1 and event["phase"] == "recovery":
            sequence_offset += phase_lengths["observation"] + phase_lengths["recovery"]
        row_name, response_name = (
            f"collection/row-{sequence:03d}.json",
            f"collection/response-{sequence:03d}.body",
        )
        if row_name not in evidence or response_name not in evidence:
            raise ValueError("saved per-request evidence missing")
        row = _read_saved(output / row_name)
        reference = operation.get("bodyRef")
        if reference is not None:
            request_name = f"collection/request-{operation['probe']}.body"
            if request_name not in evidence:
                raise ValueError("saved request body missing")
            request_bytes = (output / request_name).read_bytes()
            if (
                len(request_bytes) != reference["bytes"]
                or hashlib.sha256(request_bytes).hexdigest() != reference["sha256"]
                or row.get("requestBytes") != reference["bytes"]
                or row.get("requestSha256") != reference["sha256"]
            ):
                raise ValueError(
                    "saved request differs from Ledger-bound body reference"
                )
        raw = (output / response_name).read_bytes()
        if (
            row.get("phase") != route["phase"]
            or row.get("index") != route["index"]
            or row.get("path") != route["route"]
            or row.get("method") != operation["method"]
            or row.get("responseBodyFile") != Path(response_name).name
            or row.get("responseSha256") != hashlib.sha256(raw).hexdigest()
            or row.get("responseBytes") != len(raw)
            or row.get("receipt", {}).get("status") != event["status"]
            or digest(json.loads(raw)) != event["responseDigest"]
        ):
            raise ValueError("saved response differs from Ledger-bound Gate event")
        expected_path = operation["path"]
        if operation["method"] == "DELETE":
            version = snapshot["jobs"][event["job"]]["creationProofs"][
                operation["resource"]
            ]["updateTime"]
            expected_path += "?currentDocument.updateTime=" + quote(version, safe="")
        if (
            route["phase"] != event["phase"]
            or route["index"] != global_index
            or route["requestDigest"] != event["requestDigest"]
            or route["responseDigest"] != event["responseDigest"]
            or route["status"] != event["status"]
            or event.get("completed") is not True
            or route["route"] != expected_path
        ):
            raise ValueError("saved routes differ from charged Gate events")
        if operation.get("kind") == "conditional-create-commit":
            response = {
                "complete": event.get("completed") is True,
                "failure": None,
                "status": event.get("status"),
                "body": json.loads(raw),
                "rawBodyBase64": base64.b64encode(raw).decode("ascii"),
                "bodyBytes": len(raw),
            }
            resources = snapshot["jobs"][event["job"]]["resources"]
            if plan.get("caseMode") == "single-exploratory-sentinel":
                if commit_versions(response, probe["resources"]) is not None:
                    actual_semantic_outcome = "sentinel-accepted"
                elif typed_firestore_refusal(response):
                    actual_semantic_outcome = "sentinel-typed-refusal"
                else:
                    actual_semantic_outcome = "sentinel-inconclusive"
            elif operation.get("probe") == "over" and typed_over_refusal(response):
                actual_semantic_outcome = "typed-over-refusal"
            elif operation.get("probe") == "over" and commit_versions(
                response, probe["resources"]
            ) is not None:
                actual_semantic_outcome = "unexpected-over-success"
            elif operation.get("probe") == "over":
                actual_semantic_outcome = "unknown-over-outcome"
    if actual_semantic_outcome is None:
        raise ValueError("saved over-boundary semantic event missing")
    if collection["semanticOutcome"] != actual_semantic_outcome:
        raise ValueError("saved semantic outcome differs from Gate event")
    if collection["formalCompatibilityClaim"] is not False:
        raise ValueError("saved compatibility claim differs")
    if actual_semantic_outcome.startswith("sentinel-"):
        if actual_semantic_outcome in {
            "sentinel-accepted",
            "sentinel-typed-refusal",
        } and (
            collection.get("failures") != []
            or collection.get("completed") is not True
            or collection.get("cleanupComplete") is not True
        ):
            raise ValueError("saved sentinel observation and cleanup evidence differs")
    elif actual_semantic_outcome == "unexpected-over-success":
        if (
            collection.get("failures") != ["over:unexpected-success"]
            or collection.get("completed") is not False
            or collection.get("cleanupComplete") is not False
        ):
            raise ValueError("saved semantic mismatch evidence differs")
    elif actual_semantic_outcome == "typed-over-refusal":
        if (
            collection.get("failures") != []
            or collection.get("completed") is not True
            or collection.get("cleanupComplete") is not True
        ):
            raise ValueError("saved typed refusal evidence differs")
    else:
        raise ValueError("saved over-boundary semantic outcome is unknown")
    for name, job in snapshot["jobs"].items():
        if not job["complete"] or shared_gate.unconfirmed_creates(snapshot, name):
            raise ValueError("saved Gate cleanup incomplete")
        shared_gate.validate_absence_proofs(snapshot, name)
    return receipt


def verify_saved(output, *, expected_inputs_digest, ledger_root):
    """Require a persisted release record and verify its complete evidence chain."""
    return _verify_saved(
        output, expected_inputs_digest=expected_inputs_digest, ledger_root=ledger_root
    )


def recover_release(output, *, expected_inputs_digest, ledger_root):
    """Publish missing release evidence after the Ledger already released the run.

    The immutable held receipt is the durable release intent. A missing release
    record remains inadmissible until every saved byte and the canonical Ledger
    ticket/claim/Gate binding verify. This operation reads no credential, sends
    no request, and never reserves or finishes a Ledger row a second time.
    Existing files, including partial files and symlinks, are never replaced.
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
