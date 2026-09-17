"""Prepared stream management; O8 supplies credentials, never this module."""

from __future__ import annotations

import copy
import json
import time
from pathlib import Path
from urllib.parse import urlencode

import stream_bridge
from batch_adapter import request_headers, wire
from batch_contract import PROJECT, Credential, database_evidence
from broad_contract import digest, local_origin
from shared_gate import _save, create
from shared_production import Coordinator, ProductionGate

PROFILE = "stream-prepared-metadata-v1"
ACTIONS = ("project", "database", "auth", "key")


def with_management(plan):
    plan = copy.deepcopy(plan)
    entries = [{"id": action, "duration": 12, "timeout": 13} for action in ACTIONS]
    plan.update(
        managementProfile=PROFILE,
        management={"observation": entries, "recovery": copy.deepcopy(entries)},
        coordinatorRequests=0,
        observationRequests=19,
        recoverySeconds=366,
        costMicrousd=3300,
    )
    return plan


def prepared_plan(nonce, owner, permission_digest):
    plan = with_management(stream_bridge.compile_plan(PROJECT, nonce, owner))
    plan.update(
        permissionDigest=permission_digest, observerSha256=stream_bridge.source_digest()
    )
    return plan


def metadata_valid(state):
    proof = state.get("streamMetadata", {})
    events = state["managementEvents"]
    if (
        proof.get("permissionDigest") != state["plan"]["permissionDigest"]
        or set(proof) != {"permissionDigest", "preflight", "postflight"}
        or len(events) != 8
    ):
        raise ValueError("stream preflight/postflight proof incomplete")
    projected = []
    for phase, label, indexes in [
        ("observation", "preflight", list(range(4))),
        ("recovery", "postflight", list(range(4, 8))),
    ]:
        evidence = proof[label]
        selected = [events[index] for index in indexes]
        if (
            evidence.get("eventIndexes") != indexes
            or evidence.get("eventsDigest") != digest(selected)
            or [item["id"] for item in selected]
            != [f"{phase}:{action}" for action in ACTIONS]
            or any(
                item.get("completed") is not True
                or item.get("status") != 200
                or item.get("responseDigest") != digest(item.get("body"))
                for item in selected
            )
        ):
            raise ValueError("stream metadata journal differs")
        projected.append(
            [
                database_evidence(item["body"])["projectionDigest"]
                if item["id"].endswith(":database")
                else digest(item["body"])
                for item in selected
            ]
        )
    if projected[0] != projected[1]:
        raise ValueError("stream metadata changed")


class StreamProductionGate(ProductionGate):
    """The shared stream Gate with the existing management lock implementation."""

    def __init__(self, path):
        super().__init__(path, "stream")


class StreamCoordinator(Coordinator):
    def __init__(
        self,
        permission,
        output,
        gate,
        api_key,
        *,
        ledger,
        ticket,
        credential,
        shadow_origin=None,
    ):
        if not isinstance(gate, StreamProductionGate) or not isinstance(
            credential, Credential
        ):
            raise TypeError("stream Gate and verified Credential required")
        plan = gate.snapshot()["plan"]
        source = stream_bridge.source_digest()
        if (
            plan.get("observerSha256") != source
            or permission.get("collectorSourceDigest") != source
        ):
            raise ValueError("prepared stream source binding differs")
        claim = ledger.bound_claim(ticket)
        if (
            plan.get("managementProfile") != PROFILE
            or digest(permission) != plan["permissionDigest"]
            or claim["gatePlanDigest"] != digest(plan)
            or claim["gatePath"] != str(gate.path.resolve())
        ):
            raise ValueError("prepared stream reservation differs")
        if shadow_origin is not None:
            local_origin(shadow_origin)
        self._ledger, self._ticket = ledger, copy.deepcopy(ticket)
        self._bound_ledger = ledger
        self._ledger_path = str(ledger.path)
        self._ledger_identity = ledger.identity
        self._ticket_digest = digest(ticket)
        self._key_digest = digest(api_key)
        self._claim_digest = digest(claim)
        self._source = source
        self._permission_digest = digest(permission)
        self._gate = gate
        self._plan_digest = digest(plan)
        self._credential = credential
        self._shadow_origin = shadow_origin
        self._runtime = plan["nodeRuntime"]
        super().__init__(permission, plan["nonce"], Path(output), gate, api_key)
        self.credential = credential
        self.failures = []

    def acquire(self, recovery=False):
        raise ValueError("O8 credential injection required; acquisition disabled")

    def recover_credentials(self):
        raise ValueError("O8 credential injection required; acquisition disabled")

    def validate_current(self, duration=13):
        if (
            self.gate is not self._gate
            or self.gate.plan_digest != self._plan_digest
            or self.credential is not self._credential
            or digest(self.permission) != self._permission_digest
            or digest(self.api_key) != self._key_digest
            or self.key_digest != self._key_digest
            or self._ledger is not self._bound_ledger
            or str(self._ledger.path) != self._ledger_path
            or self._ledger.identity != self._ledger_identity
            or digest(self._ticket) != self._ticket_digest
            or not self.credential.usable(time.monotonic(), duration)
            or time.time() + duration > self.permission["expiresAt"]
        ):
            raise ValueError("prepared stream identity/lease changed")
        stream_bridge.verify_execution_bindings(self._source, self._runtime)
        if self._ledger.validate(self._ticket, duration=duration) != self._claim_digest:
            raise ValueError("prepared stream reservation changed")

    def reserve(self, service, duration=12):
        super().reserve(service, duration)
        # This runs after the shared rate wait/debit, with Gate already locked.
        self.validate_current(duration + 1)
        if self.management_context is None:
            raise ValueError("management context changed")
        state, _ = self.management_context
        deadline = (
            state["started"]
            + state["plan"]["wallSeconds"]
            - (0 if self.budget.recovery else state["plan"]["recoverySeconds"])
        )
        if time.monotonic() + duration + 1 > deadline:
            raise ValueError("management phase deadline after all waits")

    def request(
        self, service, path, body=None, *, method="POST", privileged=False, form=False
    ):
        routes = dict(
            zip(
                [
                    f"cloudresourcemanager.googleapis.com/v1/projects/{PROJECT}",
                    f"firestore.googleapis.com/v1/projects/{PROJECT}/databases/(default)",
                    f"identitytoolkit.googleapis.com/admin/v2/projects/{PROJECT}/config",
                    "apikeys.googleapis.com/v2/keys:lookupKey?"
                    + urlencode({"keyString": self.api_key}),
                ],
                ACTIONS,
                strict=True,
            )
        )
        if (
            service != "metadata"
            or path not in routes
            or [body, method, privileged, form] != [None, "GET", True, False]
        ):
            raise ValueError("closed read-only metadata operation required")
        action = routes[path]

        def send():
            self.reserve("metadata")
            headers = request_headers(
                self.access(), local=self._shadow_origin is not None, form=False
            )
            url = (
                self._shadow_origin + "/" + action
                if self._shadow_origin
                else "https://" + path
            )
            status, response, media_type = wire(
                url, "GET", None, headers, local=self._shadow_origin is not None
            )
            if (
                not isinstance(response, dict)
                or len(json.dumps(response).encode()) > 1048576
                or media_type.split(";")[0] != "application/json"
            ):
                raise ValueError("bounded JSON metadata required")
            state, _ = self.management_context
            state["managementEvents"][-1].update(
                completed=True,
                status=status,
                responseDigest=digest(response),
                body=response,
            )
            if status in {401, 403}:
                self.credential.fail()
            return status, response

        result = self.gate.manage(self, action, send)
        self.metadata_evidence.append(
            {
                "id": ("recovery" if self.budget.recovery else "observation")
                + ":"
                + action,
                "status": result[0],
                "responseDigest": digest(result[1]),
            }
        )
        return result

    def checked_preflight(self, *, recovery):
        self.budget.recovery = recovery
        if recovery:
            self.gate.stop()  # A one-way transition before any metadata wait.
        super().preflight()
        self.validate_current()
        with self.gate.locked() as state:
            indexes = list(range(4, 8)) if recovery else list(range(4))
            selected = [state["managementEvents"][index] for index in indexes]
            state.setdefault(
                "streamMetadata", {"permissionDigest": self._permission_digest}
            )["postflight" if recovery else "preflight"] = {
                "eventIndexes": indexes,
                "eventsDigest": digest(selected),
            }
            _save(self.gate.path, state)
        if recovery:
            self.configuration_unchanged = True


def execution_facts(state, *, production):
    metadata = len(state["managementEvents"])
    data = len(state["events"])
    observed = [event for event in state["events"] if event["phase"] == "observation"]
    complete = len(observed) == 15 and all(
        event.get("completed") is True and event.get("failure") is None
        for event in observed
    )
    return {
        "productionExecuted": production and bool(metadata + data),
        "productionRequests": metadata + data if production else 0,
        "metadataRequests": metadata,
        "dataRequests": data,
        "productionDataExecuted": production and bool(data),
        "completedDataObservation": complete,
    }


def execute_session(
    plan, permission, output, ledger, ticket, api_key, credential, *, shadow=None
):
    """Execute an already reserved, frozen plan with an injected O8 credential."""
    output = Path(output)
    create(output / "gate", plan)
    gate = StreamProductionGate(output / "gate")
    gate.claim()
    coordinator = StreamCoordinator(
        permission,
        output / "coordinator",
        gate,
        api_key,
        ledger=ledger,
        ticket=ticket,
        credential=credential,
        shadow_origin=None if shadow is None else shadow["metadataOrigin"],
    )
    result = None
    failures = []
    released = False

    def postflight():
        try:
            coordinator.checked_preflight(recovery=True)
        except Exception as error:  # noqa: BLE001 -- Persist failure kinds without credential-bearing text.
            # Acquisition drift never suppresses already authorized owned cleanup.
            failures.append({"phase": "postflight", "kind": type(error).__name__})

    try:
        coordinator.checked_preflight(recovery=False)
        if shadow is None:
            result = stream_bridge.run_reserved(
                plan,
                gate,
                ledger,
                ticket,
                coordinator,
                before_recovery=postflight,
                finalize=False,
            )
        else:

            def authorize(recovery):
                coordinator.validate_current(31)
                if coordinator.budget.recovery is not recovery:
                    raise ValueError("stream metadata phase differs")
                return (
                    {"authorization": "Bearer owner"},
                    time.time() + credential.expiry - time.monotonic(),
                    permission["expiresAt"],
                )

            result = stream_bridge._run_worker(
                plan,
                gate,
                ledger,
                ticket,
                mode="local",
                port=shadow["port"],
                authorize=authorize,
                before_recovery=postflight,
                finalize=False,
            )
        coordinator.validate_current()
        metadata_valid(gate.snapshot())
        if failures:
            raise ValueError("stream acquisition incomplete")
        gate.finish()
        coordinator.validate_current()
        ledger.finish(ticket)
        released = True
    except Exception as error:  # noqa: BLE001 -- Persist failure kinds without credential-bearing text.
        failures.append({"phase": "execution", "kind": type(error).__name__})
    final_state = gate.snapshot()
    receipt = {
        "kind": "stream-prepared-execution-v1",
        "collection": result,
        "failures": failures,
        "reservationReleased": released,
        "configurationUnchanged": coordinator.configuration_unchanged,
        "acquisitionValidated": not failures and released,
        **execution_facts(final_state, production=shadow is None),
        "gate": final_state,
        "metadataEvidence": coordinator.metadata_evidence,
    }
    stream_bridge.write_private_json(output / "receipt.json", receipt)
    return receipt
