"""One admitted FS-CONFIG-LIFECYCLE acquisition, with immutable offline evidence.

`execute` is the production path: it consumes the capability, reserves the shared
Ledger under the EXCLUSIVE field-configuration locks, creates the configuration gate,
reads the private credential handoff only after the reservation, and drives the
collector through the capability-bound wire. `execute_reserved` is the same
reservation-to-receipt path with an injected transport; it exists for the integration
proof against a temporary Ledger and refuses any Ledger that is not marked as one.

A completed configuration-management run attaches its receipt and registered Gate
proof to the Ledger before the typed finalizer releases the reservation.

`verify_saved` is the verified-input boundary for the comparator: it re-reads a saved
receipt directory, checks every binding the receipt names (frozen inputs, gate
snapshot, evidence digests, reviewed worker, credential preflight, the shared Ledger
row the ticket points at and the gate path that row claims) and only then returns
the production record with the `VerifiedAcquisition` the comparator requires. A
collection that merely carries the production label never gets one.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
import tempfile
import weakref
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/production-admission"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/o8-core"))
sys.path.insert(0, str(HERE))

import _lane

_lane.ensure_package()

import o8_admission
import reservations
from broad_contract import digest
from fs_config_lifecycle import lifecycle_admission as admission
from fs_config_lifecycle import lifecycle_descriptor as campaign
from fs_config_lifecycle import lifecycle_preflight as preflight
from fs_config_lifecycle import lifecycle_remote_transport
from fs_config_lifecycle.comparator import PRODUCTION_KIND, VerifiedAcquisition
from fs_config_lifecycle.lifecycle_collector import RESULT_KIND, collect
from fs_config_lifecycle.lifecycle_gate import ConfigurationGate, create
from fs_config_lifecycle.surface_matrix import digest as canonical_digest

PROOF_MARKER = "PROOF-LEDGER"
REQUIRED_EVIDENCE = ("inputs.json", "gate-snapshot.json", "collection/result.json")
# Identity registry of the acquisition objects verify_saved built, the way o8-core
# keeps its live capabilities: membership, never shape, is what the comparator asks.
_VERIFIED: weakref.WeakSet = weakref.WeakSet()


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


def _is_proof_ledger(ledger_root) -> bool:
    root = Path(ledger_root)
    marker = root / PROOF_MARKER
    return not root.is_symlink() and not marker.is_symlink() and marker.is_file()


def _proof_ledger(ledger_root) -> None:
    """An injected transport may reserve only in a Ledger created for a proof."""
    if not _is_proof_ledger(ledger_root):
        raise ValueError(
            "injected transport requires a proof Ledger, never the canonical one"
        )


def verified(acquisition) -> bool:
    """Whether this exact object is one verify_saved built and registered."""
    return type(acquisition) is VerifiedAcquisition and acquisition in _VERIFIED


def _register(acquisition: VerifiedAcquisition) -> VerifiedAcquisition:
    _VERIFIED.add(acquisition)
    return acquisition


def execute_reserved(
    *,
    inputs,
    permission,
    ledger_root,
    output,
    transmit,
    capability=None,
    credential_reader=None,
    sleeper=None,
    tokeninfo=None,
):
    """Reserve, gate, collect, receipt, and the typed release disposition.

    `tokeninfo` is the credential preflight's exchange. The production launcher
    passes nothing and gets the real one; an injected exchange is admitted only
    against a proof Ledger, like an injected transport.
    """
    inputs, permission = copy.deepcopy(inputs), copy.deepcopy(permission)
    admission.validate_frozen_inputs(inputs)
    if digest(permission) != inputs["permissionDigest"]:
        raise ValueError("independent permission differs from frozen inputs")
    if capability is None or tokeninfo is not None:
        _proof_ledger(ledger_root)
    if capability is None:
        o8_admission.reject_production_transport(admission.descriptor(), transmit)
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise ValueError("fresh production output required")
    ledger = reservations.Ledger(ledger_root)
    plan = campaign.execution_plan(inputs["plan"])
    gate_plan = admission.gate_plan_for(inputs, permission)
    generation = admission.abort_generation(inputs)
    claim = admission.reservation_claim(
        inputs, gate_path=output / "gate", gate_plan=gate_plan
    )
    worker_sha256 = capability.binding_digest if capability is not None else None
    if capability is not None:
        capability._consume(
            campaign_id=claim["campaignId"],
            inputs_digest=inputs["inputsDigest"],
            ledger_root=ledger_root,
        )
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    output = output.resolve()
    _write_receipt(output / "inputs.json", inputs)
    ticket = ledger.reserve(
        admission.envelope(permission, claim), claim, gate_plan, generation=generation
    )
    result = None
    failure = None
    gate = None
    token = None
    try:
        create(output / "gate", gate_plan)
        gate = ConfigurationGate(output / "gate")
        extra = {} if sleeper is None else {"sleeper": sleeper}
        if capability is not None:
            token = credential_reader()

            def execute_wire(request, *, deadline):
                return capability._transmit(
                    {"request": request, "token": token, "deadline": deadline}
                )

            wire = execute_wire
            # The token is attested before OC-01: principal, scope and a lifetime
            # covering the wall plus the recovery reserve, or nothing is patched.
            extra["credential_preflight"] = preflight.credential_preflight(
                token,
                permission["credentialPrincipal"],
                tokeninfo=tokeninfo or preflight.tokeninfo_receipt,
            )
        else:
            wire = transmit
        result = collect(plan["nonce"], wire, output / "collection", gate=gate, **extra)
        token = None
        if not result.get("cleanupComplete"):
            failure = "restore-incomplete"
    except Exception as error:  # noqa: BLE001 -- preserve only a secret-free failure class.
        failure = type(error).__name__
    finally:
        if capability is not None:
            o8_admission.revoke_production_capability(capability)
    snapshot = gate.snapshot() if gate is not None else None
    if snapshot is not None:
        _write_receipt(output / "gate-snapshot.json", snapshot)
    evidence = {}
    for path in [
        output / "inputs.json",
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
        production=capability is not None,
        worker_sha256=worker_sha256,
        generation=generation,
        failure=failure,
    )
    disposition = admission.classify_stop(receipt)
    supported, blocker = admission.release_supported()
    receipt.update(
        ticket=ticket,
        claimDigest=digest(claim),
        campaignPlanDigest=inputs["planDigest"],
        gatePlanDigest=digest(gate_plan),
        gateDigest=digest(snapshot) if snapshot is not None else None,
        evidenceFiles=evidence,
        chargedCalls=snapshot["total"] if snapshot else 0,
        chargedMicrousd=snapshot["costMicrousd"] if snapshot else 0,
        disposition=disposition,
        reservationStateAtPublication="held",
        releaseEligible=bool(disposition["releaseEligible"]),
        releaseRecord=None,
        releaseBlocked=None
        if supported
        else {"kind": admission.RELEASE_BLOCKED_KIND, **blocker},
        productionExecuted=capability is not None
        and bool((result or {}).get("rowCount")),
    )
    receipt_path = output / "receipt.json"
    _write_receipt(receipt_path, receipt)
    release_record = None
    release_failure = None
    if supported and receipt["releaseEligible"]:
        try:
            receipt_digest = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
            collection_digest = canonical_digest(receipt["collection"])
            ledger.attach_evidence(
                ticket,
                receipt_digest,
                receipt["gateDigest"],
                collection_digest,
            )
            release_record = {
                "kind": "fs-config-lifecycle-release-v1",
                "ticket": ticket,
                "receiptPath": str(receipt_path.resolve()),
                "receiptDigest": receipt_digest,
                "gateDigest": receipt["gateDigest"],
                "collectionDigest": collection_digest,
                "generation": copy.deepcopy(generation),
            }
            ledger.finish_management_only(ticket, release_record)
        except Exception as error:  # noqa: BLE001 -- hold on any release uncertainty.
            release_failure = type(error).__name__
            failure = failure or "release-" + release_failure
    final_row = ledger.snapshot()["reservations"][ticket["reservation"]]
    return {
        **receipt,
        "failure": failure,
        "releaseRecord": release_record,
        "releaseFailure": release_failure,
        "reservationReleased": final_row["state"] == "released",
        "reservationFinal": final_row,
    }


def execute(*, capability, inputs, permission, credential_reader, ledger_root, output):
    """Execute only the consumed capability's fixed transport; never accept one."""
    if not admission.issued_capability(capability):
        raise ValueError("unissued O7 production capability")
    return execute_reserved(
        inputs=inputs,
        permission=permission,
        ledger_root=ledger_root,
        output=output,
        transmit=None,
        capability=capability,
        credential_reader=credential_reader,
    )


def _read_evidence(root: Path, name: str) -> tuple[dict, bytes]:
    """One bounded, regular, non-symlinked evidence file inside the receipt directory."""
    if not name or name.startswith("/") or ".." in Path(name).parts:
        raise ValueError("evidence path inside the receipt directory required")
    path = root / name
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"regular evidence file required: {name}")
    if path.stat().st_size > reservations.MAX_BYTES:
        raise ValueError("bounded immutable production evidence required")
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"evidence object required: {name}")  # noqa: TRY004 -- refusal class, not a type report
    return value, raw


def verify_saved(
    output, *, ledger_root, synthetic: bool = False
) -> tuple[dict, VerifiedAcquisition]:
    """Verify one saved O8 acquisition and return the comparator's production input.

    Returns `(record, acquisition)`: the `{executionKind, collection}` record the
    comparator takes and the `VerifiedAcquisition` bound to that collection,
    registered so `verified()` answers for it. Raises `ValueError` naming the first
    binding that does not hold. Nothing is sent and nothing in the directory or the
    Ledger is changed.

    A proof Ledger (the temporary one the integration tests create) is refused as
    the anchor unless `synthetic=True` is passed explicitly, and the object then
    carries `synthetic=True` so the comparison can never read as production;
    `synthetic=True` against a Ledger without the proof marker is refused too.

    The Ledger row anchors the reservation (claim digest, gate plan digest,
    generation, nonce digest, gate path), not the bytes observed after it: the
    receipt, gate snapshot and collection digests are checked against each other
    inside the directory. A shared `attach_evidence` Ledger transition is the
    missing piece for anchoring those.
    """
    if type(synthetic) is not bool:
        raise ValueError("synthetic must be an explicit boolean")
    if _is_proof_ledger(ledger_root) != synthetic:
        raise ValueError(
            "proof Ledger anchors require synthetic=True and a canonical Ledger "
            "refuses it"
        )
    output = Path(output)
    if output.is_symlink() or not output.is_dir():
        raise ValueError("saved receipt directory required")
    output = output.resolve()
    receipt, receipt_bytes = _read_evidence(output, "receipt.json")
    if (
        receipt.get("kind") != campaign.RECEIPT_KIND
        or receipt.get("campaignId") != campaign.CAMPAIGN
    ):
        raise ValueError("acquisition receipt of this campaign required")
    if (
        receipt.get("executionKind") != PRODUCTION_KIND
        or receipt.get("productionExecuted") is not True
    ):
        raise ValueError("not a production acquisition")
    if receipt.get("workerSha256") != lifecycle_remote_transport._WORKER_SHA256:
        raise ValueError("receipt names no reviewed worker")
    evidence = receipt.get("evidenceFiles")
    if not isinstance(evidence, dict) or any(
        name not in evidence for name in REQUIRED_EVIDENCE
    ):
        raise ValueError("required evidence files missing from the receipt")
    files = {}
    for name, expected in evidence.items():
        value, raw = _read_evidence(output, name)
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError(f"evidence digest differs: {name}")
        files[name] = value
    inputs = files["inputs.json"]
    admission.validate_frozen_inputs(inputs)
    if (
        inputs["inputsDigest"] != receipt.get("inputsDigest")
        or inputs["planDigest"] != receipt.get("planDigest")
        or inputs["planDigest"] != receipt.get("campaignPlanDigest")
        or inputs["permissionDigest"] != receipt.get("permissionDigest")
    ):
        raise ValueError("receipt does not bind its frozen inputs")
    snapshot = files["gate-snapshot.json"]
    if (
        digest(snapshot) != receipt.get("gateDigest")
        or snapshot.get("total") != receipt.get("chargedCalls")
        or snapshot.get("costMicrousd") != receipt.get("chargedMicrousd")
    ):
        raise ValueError("receipt does not bind its gate digest")
    collection = files["collection/result.json"]
    if json.loads(json.dumps(receipt.get("collection"))) != collection:
        raise ValueError("receipt collection differs from the saved result")
    preflight_row = collection.get("credentialPreflight")
    if (
        collection.get("kind") != RESULT_KIND
        or collection.get("campaignId") != campaign.CAMPAIGN
        or collection.get("nonceDigest") != digest(inputs["plan"]["nonce"])
        or type(collection.get("rowCount")) is not int
        or collection["rowCount"] < 1
        or not isinstance(preflight_row, dict)
        or preflight_row.get("complete") is not True
    ):
        raise ValueError("saved result carries no attested credential preflight")
    ticket = receipt.get("ticket")
    if not isinstance(ticket, dict):
        raise ValueError("shared reservation ticket required")  # noqa: TRY004 -- refusal class, not a type report
    ledger = reservations.Ledger(ledger_root)
    try:
        claim = ledger.bound_claim(ticket)
    except (KeyError, ValueError) as error:
        raise ValueError("receipt ticket names no held reservation") from error
    row = ledger.snapshot()["reservations"][ticket["reservation"]]
    if (
        digest(claim) != receipt.get("claimDigest")
        or claim.get("campaignId") != campaign.CAMPAIGN
        or claim.get("gatePlanDigest") != receipt.get("gatePlanDigest")
        or claim.get("nonceDigest") != collection["nonceDigest"]
        or row.get("generation") != receipt.get("generation")
    ):
        raise ValueError("receipt does not bind its reservation claim")
    if claim.get("gatePath") != str(output / "gate"):
        raise ValueError("receipt directory is not at the claimed gate path")
    record = {"executionKind": PRODUCTION_KIND, "collection": collection}
    acquisition = VerifiedAcquisition(
        campaign_id=campaign.CAMPAIGN,
        execution_kind=PRODUCTION_KIND,
        endpoint=lifecycle_remote_transport.ORIGIN,
        reservation=ticket["reservation"],
        ledger_identity=ticket["ledgerIdentity"],
        receipt_digest=hashlib.sha256(receipt_bytes).hexdigest(),
        gate_digest=receipt["gateDigest"],
        artifact_sha256=inputs["artifactSha256"],
        worker_sha256=receipt["workerSha256"],
        collection_digest=canonical_digest(collection),
        synthetic=synthetic,
    )
    return record, _register(acquisition)
