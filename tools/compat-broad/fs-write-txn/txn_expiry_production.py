"""One admitted transaction expiry acquisition, with immutable offline evidence.

The pipeline is: shared Ledger reservation, Gate creation and claim, private
credential handoff, the four preflight management slots, the collector driven
slot by slot through the campaign's Gate facade with real wall-clock waits,
recovery through the same Gate, the three postflight management slots, an
immutable receipt, `Ledger.finish` and a release record.

Two entry points share that pipeline and differ only in where the wire comes
from:

- `execute` is production. It runs the consumed O7 capability's fixed
  transport and nothing else, sleeps real seconds, and reads the credential
  only after the reservation exists and the Gate is claimed.
- `rehearse` is the credential-free integration proof. It takes an injected
  data transport and an injected management transport, refuses either if it
  can reach the production wire, and admits `Rehearsal(sleep_scale)`, the one
  documented switch that shortens the real sleeper. Its receipt is marked
  `injected-transport`, its waits are measured short, the comparator refuses
  it, and the saved-evidence verifier refuses it; it can never be mistaken
  for production evidence. The launcher has no flag for it.

The clock advance callable the rehearsal shadow uses to reach the idle limit is
accepted by neither path: production elapsed time cannot be simulated.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/production-admission"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/o8-core"))
sys.path.insert(0, str(HERE))

import reservations
import shared_gate
import txn_expiry_admission as admission
import txn_expiry_collector as collector
import txn_expiry_descriptor as campaign
import txn_expiry_gate as gate_module
import txn_expiry_preflight as preflight
from broad_contract import digest
from o8_admission import reject_production_transport

PRODUCTION_EXECUTION = "fixed-production-wire"
INJECTED_EXECUTION = "injected-transport"
MAX_STOP_REASON = shared_gate.MAX_STOP_REASON


@dataclass(frozen=True)
class Rehearsal:
    """The documented local-mode switch: shorten the real sleeper by a factor.

    The sleeper still sleeps, so the collector's checkpoints and measured waits
    are real, only shorter than requested. That is exactly what the comparator
    refuses (`wait-shorter-than-requested`), so a rehearsal receipt cannot pass
    as evidence. Admitted by `rehearse` only, never by `execute`.
    """

    sleep_scale: float

    def __post_init__(self):
        scale = self.sleep_scale
        if (
            type(scale) not in (int, float)
            or isinstance(scale, bool)
            or not math.isfinite(scale)
        ):
            raise ValueError("finite rehearsal sleep scale required")
        if not 0 < scale <= 1:
            raise ValueError("rehearsal sleep scale must be in (0, 1]")

    def sleeper(self):
        scale = float(self.sleep_scale)

        def sleep(seconds):
            time.sleep(seconds * scale)

        return sleep


# -- evidence files ---------------------------------------------------------


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


# -- the Gate adapter ---------------------------------------------------------


def _bounded_reason(text: str) -> str:
    return text[:MAX_STOP_REASON] or "stopped"


class GateAdapter:
    """The collector's transport, admitting every request through the Gate.

    The collector names the plan slot each request serves. The adapter finds
    that slot in the frozen Gate schedule, consumes the recovery slots the run
    has nothing to send for as zero-wire skips, builds the operation the Gate
    verifies from the request's actual content, dispatches through the Gate
    facade, installs the bindings the facade observed, and hands the
    collector back the normalized response. A Gate refusal is returned to the
    collector as an incomplete answer that was never sent; the collector
    records it and keeps to its own contract.
    """

    def __init__(self, gate, gate_plan, wire, *, rows, clock=time.monotonic):
        self.gate = gate
        self.job = gate_plan["jobs"][gate_module.JOB]
        self.schedule = gate_plan["jobs"][gate_module.JOB]["schedule"]
        self.slot_seconds = {
            (entry["phase"], entry["index"]): entry["seconds"]
            for entry in self.schedule
        }
        self.sites = {
            phase: {
                operation["site"]: index
                for index, operation in enumerate(self.job[phase])
            }
            for phase in ("observation", "recovery")
        }
        self.wire = wire
        self.rows = rows
        self.clock = clock
        self.collection = None
        self.recovery_begun = False
        self.stopped = None

    def _incomplete(self, reason):
        return {
            "complete": False,
            "code": None,
            "status": None,
            "message": None,
            "blocked": reason,
        }

    def _locate(self, site):
        if isinstance(site, str) and site.startswith(("release/", "cleanup/")):
            phase = "recovery"
        else:
            phase = "observation"
        index = self.sites[phase].get(site)
        if index is None:
            raise ValueError("request outside the frozen execution schedule")
        return phase, index

    def _operation(self, declared, request):
        """The operation the Gate verifies, built from what is really sent."""
        operation = copy.deepcopy(declared)
        if request["rpc"] == "GetDocument":
            operation["path"] = "/v1/" + request["name"]
            query = request.get("query")
            if query is not None:
                operation["query"] = copy.deepcopy(query)
            else:
                operation.pop("query", None)
        else:
            operation["body"] = copy.deepcopy(request["body"])
        return operation

    def _begin_recovery(self):
        self.recovery_begun = True
        state = self.gate.snapshot()["jobs"][gate_module.JOB]
        if state["observation"] < len(self.job["observation"]):
            failure = (
                getattr(self.collection, "failure", None) or "observation-incomplete"
            )
            self.gate.abandon_observation(
                _bounded_reason(f"collector-stopped:{failure}")
            )

    def _skip_until(self, target):
        """Consume the recovery slots before `target` without a wire call."""
        while True:
            state = self.gate.snapshot()["jobs"][gate_module.JOB]
            cursor = state["recovery"]
            if cursor >= target:
                if cursor != target:
                    raise ValueError("request behind the frozen execution schedule")
                return
            declared = self.job["recovery"][cursor]
            note = {
                "release": "transaction-not-open-at-cleanup",
                "owned-read": "cleanup-not-attempted",
                "conditional-delete": "document-absent-or-not-deleted",
                "typed-absence": "cleanup-abandoned-before-absence-read",
            }[declared["kind"]]
            self.gate.skip_recovery_slot(declared, note)

    def __call__(self, request):
        if self.stopped is not None:
            return self._incomplete(self.stopped)
        try:
            phase, index = self._locate(request.get("site"))
            recovery = phase == "recovery"
            if recovery and not self.recovery_begun:
                self._begin_recovery()
            if recovery:
                self._skip_until(index)
            declared = self.job[phase][index]
            operation = self._operation(declared, request)
        except Exception as error:  # noqa: BLE001 -- a refusal before the wire is an incomplete answer
            return self._incomplete(f"gate-refused:{type(error).__name__}")
        seconds = self.slot_seconds[(phase, index)]
        entry = {
            "phase": phase,
            "index": index,
            "site": declared["site"],
            "route": declared["path"],
            "requestDigest": None,
            "status": None,
            "responseDigest": digest(None),
            "elapsedSeconds": None,
        }
        self.rows.append(entry)
        answer = {}

        def send():
            deadline = self.clock() + seconds
            response = self.wire(request, deadline)
            answer["response"] = response
            status = response.get("httpStatus")
            body = response.get("body") if response.get("complete") is True else None
            return (status if type(status) is int else None, body)

        try:
            status, body = self.gate.dispatch(operation, recovery, send)
            if "response" not in answer:
                # The shared dispatch consumed the slot without calling the
                # wire (its own zero-wire skip). Nothing was sent, so the
                # collector gets an incomplete answer, not a fabricated one.
                self.rows.pop()
                return self._incomplete("gate-skipped")
        except Exception as error:  # noqa: BLE001 -- retained as an incomplete answer, never reinterpreted
            response = answer.get("response")
            if response is None:
                self.rows.pop()
                return self._incomplete(f"gate-refused:{type(error).__name__}")
            entry.update(
                status=response.get("httpStatus"),
                responseDigest=digest({"failure": response.get("message")}),
                gateFailure=type(error).__name__,
            )
            self._record_wire(entry, response)
            return {
                **response,
                "complete": False,
                "incomplete": response.get("message") or "gate-refused",
            }
        response = answer["response"]
        entry.update(status=status, responseDigest=digest(body))
        self._record_wire(entry, response)
        entry["requestDigest"] = self.gate.snapshot()["events"][-1]["requestDigest"]
        self._install_bindings(declared, status, body)
        return response

    def _record_wire(self, entry, response):
        wire = response.get("wire") if isinstance(response, dict) else None
        if isinstance(wire, dict):
            entry["elapsedSeconds"] = wire.get("elapsedSeconds")
            entry["rawBodySha256"] = wire.get("rawBodySha256")
            entry["rawBodyBytes"] = wire.get("rawBodyBytes")

    def _install_bindings(self, declared, status, body):
        binds = declared.get("binds")
        if not binds or status != 200:
            return
        observed = self.gate.observed(binds)
        if observed is not None:
            self.gate.bind(binds, observed)


def run_collection(
    gate, plan, output, *, transmit, rehearsal=None, clock=time.monotonic, rows=None
):
    """Drive the reviewed collector through the Gate facade, wall-clock only.

    `transmit(request, deadline)` is the wire. A `rehearsal` is admitted only
    when the wire cannot reach the production transport; the production wire
    always sleeps real seconds. No clock advance callable is ever accepted.
    """
    if rehearsal is not None:
        if not isinstance(rehearsal, Rehearsal):
            raise ValueError("rehearsal must be a Rehearsal")
        reject_production_transport(campaign.descriptor(), transmit)
        sleeper = rehearsal.sleeper()
    else:
        sleeper = time.sleep
    options = campaign.collector_options(plan)
    gate_plan = gate.snapshot()["plan"]
    rows = [] if rows is None else rows
    adapter = GateAdapter(gate, gate_plan, transmit, rows=rows, clock=clock)
    collection = collector.Collection(
        options,
        plan,
        adapter,
        sleeper=sleeper,
        advance=None,
        monotonic=clock,
        wall=time.time,
    )
    adapter.collection = collection
    receipt = collection.run()
    output = Path(output)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    _write_receipt(output / "result.json", receipt)
    return receipt


# -- the pipeline ------------------------------------------------------------


def _run(
    *,
    execution_kind,
    inputs,
    permission,
    credential_reader,
    ledger_root,
    output,
    data_wire,
    management_wire,
    rehearsal,
    after_reservation=None,
):
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
    snapshot = None
    management = None
    try:
        shared_gate.create(output / "gate", gate_plan)
        gate = gate_module.TxnGate(output / "gate", gate_module.JOB)
        gate.claim()
        if after_reservation is not None:
            after_reservation()
        token = credential_reader()
        management = preflight.ManagementSession(
            gate=gate,
            ledger=ledger,
            ticket=ticket,
            transmit=management_wire,
            permission=permission,
            token=token,
        )
        management.run("observation")
        token = None

        def transmit(request, deadline):
            response = data_wire(request, management.data_token(deadline), deadline)
            preflight.preflight.observe_status(
                management.credential, response.get("httpStatus")
            )
            return response

        result = run_collection(
            gate,
            plan,
            output / "collection",
            transmit=transmit,
            rehearsal=rehearsal,
            rows=rows,
        )
        if result.get("complete"):
            management.run("recovery")
            gate.finish()
            ready = True
        else:
            failure = "collection-incomplete"
    except Exception as error:  # noqa: BLE001 -- preserve only a secret-free failure class.
        failure = type(error).__name__
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
    stop = admission.stop_point(snapshot, ready)
    creating = bool(
        snapshot and shared_gate.creating_outcome(snapshot, gate_module.JOB) != "none"
    )
    receipt = admission.build_receipt(
        inputs,
        result if creating else None,
        rows=rows,
        management=management,
        generation=generation,
        failure=failure,
        stop=stop,
    )
    receipt.update(
        ticket=ticket,
        claimDigest=digest(claim),
        planDigest=digest(gate_plan),
        gateDigest=digest(snapshot) if snapshot is not None else None,
        evidenceFiles=evidence,
        chargedCalls=snapshot["total"] if snapshot else 0,
        reservationStateAtPublication="held",
        releaseEligible=ready,
        releaseRecord="release.json" if ready else None,
        executionKind=execution_kind,
        productionExecuted=creating,
        collectorReceiptFile="collection/result.json" if result is not None else None,
        mayHaveCreated=creating,
    )
    # The retirement path, named in the receipt so an operator reads it there
    # rather than recomputing it: classified on the receipt and the Gate
    # snapshot, which the Ledger's abandoned close consults as well.
    receipt["retirement"] = admission.classify_stop({**receipt, "gate": snapshot})
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


def execute(
    *,
    capability,
    inputs,
    permission,
    credential_reader,
    ledger_root,
    output,
    after_reservation=None,
):
    """Execute only the consumed capability's fixed transport; never accept one."""
    if not admission.issued_capability(capability):
        raise ValueError("unissued O7 production capability")
    inputs = copy.deepcopy(inputs)
    admission.validate_frozen_inputs(inputs)

    def consume():
        capability._consume(
            campaign_id=admission.descriptor().campaign_id,
            inputs_digest=inputs["inputsDigest"],
            ledger_root=ledger_root,
        )

    def data_wire(request, token, deadline):
        return capability._transmit(
            admission.transport_call(request, token, deadline=deadline)
        )

    def management_wire(value):
        return capability._transmit(value)

    consume()
    try:
        return _run(
            execution_kind=PRODUCTION_EXECUTION,
            inputs=inputs,
            permission=permission,
            credential_reader=credential_reader,
            ledger_root=ledger_root,
            output=output,
            data_wire=data_wire,
            management_wire=management_wire,
            rehearsal=None,
            after_reservation=after_reservation,
        )
    finally:
        admission.revoke_production_capability(capability)


def rehearse(
    *,
    inputs,
    permission,
    ledger_root,
    output,
    transport,
    management_transport,
    token,
    rehearsal=None,
    after_reservation=None,
):
    """The credential-free integration proof over an injected transport.

    Both callables are refused if they can reach the production wire. The
    receipt is `injected-transport` and the run's waits are shortened only
    through `rehearsal`; without it the real sleeper sleeps the plan's real
    seconds.
    """
    descriptor = admission.descriptor()
    reject_production_transport(descriptor, transport)
    reject_production_transport(descriptor, management_transport)
    if not isinstance(token, str) or not token:
        raise ValueError("rehearsal token required")

    def data_wire(request, secret, deadline):
        return transport(request, secret, deadline)

    return _run(
        execution_kind=INJECTED_EXECUTION,
        inputs=inputs,
        permission=permission,
        credential_reader=lambda: token,
        ledger_root=ledger_root,
        output=output,
        data_wire=data_wire,
        management_wire=management_transport,
        rehearsal=rehearsal,
        after_reservation=after_reservation,
    )


# -- saved evidence ----------------------------------------------------------


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

    Read-only; no credential, capability or transport. Only a
    `fixed-production-wire` receipt is admissible: a rehearsal directory fails
    closed here.
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
        or receipt.get("executionKind") != PRODUCTION_EXECUTION
        or receipt.get("timing") != "wall-clock"
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
    collection = _read_saved(output / "collection/result.json")
    routes = _read_saved(output / "routes.json")["rows"]
    if (
        collection != receipt.get("collection")
        or collection.get("complete") is not True
        or collection.get("target") != "production"
        or collection.get("timing") != collector.WALL_CLOCK
        or len(routes) + len(snapshot.get("managementEvents", [])) != snapshot["total"]
        or receipt.get("chargedCalls") != snapshot["total"]
        or receipt.get("dataRoutes")
        != [
            {
                "id": f"{row['phase']}:{row['index']:03d}",
                "site": row["site"],
                "route": row["route"],
                "status": row["status"],
                "requestDigest": row["requestDigest"],
                "responseDigest": row["responseDigest"],
            }
            for row in routes
        ]
        or receipt.get("dataRouteDigest") != digest(receipt.get("dataRoutes"))
    ):
        raise ValueError("saved route journal differs")
    events = [event for event in snapshot["events"]]
    if len(events) != len(routes):
        raise ValueError("saved routes differ from charged Gate events")
    for route, event in zip(routes, events, strict=True):
        if (
            route["phase"] != event["phase"]
            or route["index"] != event["index"]
            or route["requestDigest"] != event["requestDigest"]
            or route["responseDigest"] != event["responseDigest"]
            or route["status"] != event["status"]
            or event.get("completed") is not True
        ):
            raise ValueError("saved routes differ from charged Gate events")
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
    """Publish a missing release record after the Ledger already released the run."""
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
