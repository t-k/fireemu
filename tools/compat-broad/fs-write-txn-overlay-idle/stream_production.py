"""Prepared stream management; O8 supplies credentials, never this module."""

from __future__ import annotations

import copy
import json
import time
import sys
from pathlib import Path
from urllib.parse import urlencode

# ruff: noqa: I001 -- Bootstrap sibling admission and owned evidence modules.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "production-admission"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "compat-inventory"))

import stream_bridge
import credential_prep
from batch_adapter import request_headers, wire
from batch_contract import PROJECT, NUMBER, Credential, database_evidence
from broad_contract import digest, local_origin
from shared_gate import _save, create
from shared_production import Coordinator, ProductionGate

PROFILE = "stream-prepared-metadata-v1"
ACTIONS = ("project", "database", "auth", "key")
REQUEST_SLOTS = 33
REQUEST_COST_MICROUSD = 100
FIXED_NETWORK_MICROUSD = 1_300_000
TOTAL_COST_MICROUSD = FIXED_NETWORK_MICROUSD + REQUEST_SLOTS * REQUEST_COST_MICROUSD
SDK_CLIENT_SHA256 = "ab6947259f63e324aaa87ab6934fd538b5defce75a19f40a8896728223c23dc7"


def pricing_basis():
    """Conservative planning charge; accepted JSON bytes are not received wire bytes."""
    network_mib = (290 + 25) * 17 + 8 * 8 + 64
    rate = 230_000
    return {
        "kind": "stream-conservative-pricing-v1",
        "checkedAt": "2026-09-17",
        "primarySource": "https://cloud.google.com/firestore/pricing",
        "rateMicrousdPerGiB": rate,
        "rateBasis": "highest listed destination (China), no destination discount",
        "freeQuotaCreditBytes": 0,
        "acceptedEventSlots": 290,
        "rejectedMessageSlots": 25,
        "encodedReceiveCeilingMiB": 17,
        "sdkVersion": "@google-cloud/firestore@8.7.1",
        "sdkSource": "tools/sdk-smoke/node_modules/@google-cloud/firestore/build/src/v1/firestore_client.js:initialize",
        "sdkLockSha256": sha_file(ROOT / "tools/sdk-smoke/package-lock.json"),
        "metadataCalls": 8,
        "metadataAllowanceMiBPerCall": 8,
        "metadataBodyReadBytes": 65537,
        "httpHeaderCount": 100,
        "httpHeaderLineBytes": 65536,
        "metadataBasis": "body plus one overflow header: 65537 + 101*65537, status line and buffering within8MiB",
        "framingAndBufferingReserveMiB": 64,
        "networkPlanningMiB": network_mib,
        "calculatedNetworkMicrousd": (network_mib * rate + 1023) // 1024,
        "fixedNetworkMicrousd": FIXED_NETWORK_MICROUSD,
        "operationSlots": REQUEST_SLOTS,
        "operationAllowanceMicrousdPerSlot": REQUEST_COST_MICROUSD,
        "documentWritesUpperBound": 9,
        "totalPlanningMicrousd": TOTAL_COST_MICROUSD,
        "isExpectedInvoice": False,
    }


def pricing_sdk_binding(directory=None):
    """Attest only the inspected SDK initialization cap, not the whole dependency tree."""
    directory = (
        Path(directory)
        if directory is not None
        else ROOT / "tools/sdk-smoke/node_modules/@google-cloud/firestore"
    )
    version = load_json(directory / "package.json").get("version")
    source = sha_file(directory / "build/src/v1/firestore_client.js")
    if version != "8.7.1" or source != SDK_CLIENT_SHA256:
        raise ValueError("installed pricing SDK cap source differs")
    lock = load_json(ROOT / "tools/sdk-smoke/package-lock.json")
    if lock["packages"]["node_modules/@google-cloud/firestore"]["version"] != version:
        raise ValueError("pricing SDK lock version differs")
    return {
        "version": version,
        "clientSha256": source,
        "lockSha256": sha_file(ROOT / "tools/sdk-smoke/package-lock.json"),
        "encodedReceiveCeilingMiB": 17,
    }


def with_management(plan):
    plan = copy.deepcopy(plan)
    entries = [{"id": action, "duration": 12, "timeout": 13} for action in ACTIONS]
    plan.update(
        managementProfile=PROFILE,
        management={"observation": entries, "recovery": copy.deepcopy(entries)},
        coordinatorRequests=0,
        observationRequests=19,
        recoverySeconds=366,
        fixedCostMicrousd=FIXED_NETWORK_MICROUSD,
        requestCostMicrousd=REQUEST_COST_MICROUSD,
        costMicrousd=TOTAL_COST_MICROUSD,
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
        self._pricing_sdk = pricing_sdk_binding() if shadow_origin is None else None
        if self._pricing_sdk is not None and permission.get(
            "pricingSdkDigest"
        ) != digest(self._pricing_sdk):
            raise ValueError("owner pricing SDK binding differs")
        super().__init__(permission, plan["nonce"], Path(output), gate, api_key)
        self.credential = credential
        self.failures = []

    def acquire(self, recovery=False):
        raise ValueError("O8 credential injection required; acquisition disabled")

    def recover_credentials(self):
        raise ValueError("O8 credential injection required; acquisition disabled")

    def validate_current(self, duration=13):
        if self._pricing_sdk is not None and pricing_sdk_binding() != self._pricing_sdk:
            raise ValueError("installed pricing SDK binding changed")
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


def write_atomic_receipt(path, value):
    """Publish a private immutable receipt only after its complete bytes are durable."""
    import uuid

    path = Path(path)
    pending = path.with_name("." + path.name + "." + uuid.uuid4().hex + ".pending")
    try:
        stream_bridge.write_private_json(pending, value)
        os.link(pending, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        pending.unlink(missing_ok=True)


def retained_failure(output, ledger, ticket, error, *, production=True):
    try:
        reservation = ledger.snapshot()["reservations"][ticket["reservation"]]
        released = reservation["state"] == "released"
    except (OSError, ValueError, KeyError):
        released = False
    facts = execution_facts(
        {"managementEvents": [], "events": []}, production=production
    )
    try:
        facts = execution_facts(
            StreamProductionGate(Path(output) / "gate").snapshot(),
            production=production,
        )
    except FileNotFoundError:
        pass
    except (OSError, ValueError, KeyError):
        facts = {key: None for key in facts}
    preparation_attempts = sum(
        (Path(output) / "credential-preparation" / f"{slot}-charge.json").exists()
        for slot in ("refresh", "tokeninfo")
    )
    if preparation_attempts and production:
        facts["productionExecuted"] = True
        if facts["productionRequests"] is not None:
            facts["productionRequests"] += preparation_attempts
    receipt = {
        "credentialPreparationAttempts": preparation_attempts,
        "kind": "stream-prepared-setup-failure-v1",
        "acquisitionValidated": False,
        "reservationReleased": released,
        **facts,
        "failures": [{"phase": "reserved-execution", "kind": type(error).__name__}],
        "recoveryResponsibility": {
            "state": "released" if released else "retained",
            "ticket": ticket,
            "gatePath": str(Path(output) / "gate"),
        },
    }
    try:
        write_atomic_receipt(Path(output) / "failure-receipt.json", receipt)
    except OSError:
        # If storage itself fails, retain the lease and expose only its non-secret recovery ID.
        receipt["terminalReceiptPersisted"] = False
        print(
            json.dumps(
                {
                    "kind": "stream-recovery-required",
                    "reservation": ticket["reservation"],
                    "terminalReceiptPersisted": False,
                }
            ),
            file=sys.stderr,
            flush=True,
        )
        os.fsync(sys.stderr.fileno())
    return receipt


def execute_session(
    plan,
    permission,
    output,
    ledger,
    ticket,
    api_key,
    credential,
    *,
    shadow=None,
    final_binding=None,
    preparation_proof=None,
):
    try:
        return _execute_session(
            plan,
            permission,
            output,
            ledger,
            ticket,
            api_key,
            credential,
            shadow=shadow,
            final_binding=final_binding,
            preparation_proof=preparation_proof,
        )
    except Exception as error:  # noqa: BLE001 -- Keep responsibility visible even before Gate setup succeeds.
        return retained_failure(
            output, ledger, ticket, error, production=shadow is None
        )


def _execute_session(
    plan,
    permission,
    output,
    ledger,
    ticket,
    api_key,
    credential,
    *,
    shadow=None,
    final_binding=None,
    preparation_proof=None,
):
    """Execute an already reserved, frozen plan with an injected O8 credential."""
    output = Path(output)
    if permission.get("credentialMode") == credential_prep.MODE:
        if preparation_proof is None:
            raise ValueError("verified two-slot preparation proof required")
        credential_prep.validate_preparation(
            output,
            ledger,
            ticket,
            permission,
            preparation_proof,
            {"total": 0, "costMicrousd": FIXED_NETWORK_MICROUSD},
        )
    elif preparation_proof is not None:
        raise ValueError("unbound preparation proof refused")
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
    comparison = None

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
        comparison = final_binding(result) if final_binding is not None else None
        coordinator.validate_current()
        if preparation_proof is not None:
            credential_prep.validate_preparation(
                output, ledger, ticket, permission, preparation_proof, gate.snapshot()
            )
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
        "comparison": comparison,
        "failures": failures,
        "reservationReleased": released,
        "configurationUnchanged": coordinator.configuration_unchanged,
        "acquisitionValidated": not failures and released,
        **execution_facts(final_state, production=shadow is None),
        "gate": final_state,
        "metadataEvidence": coordinator.metadata_evidence,
    }
    if preparation_proof is not None:
        receipt["credentialPreparation"] = preparation_proof
        receipt["outerAccounting"] = {
            "requests": final_state["total"] + 2,
            "costMicrousd": final_state["costMicrousd"] + 200,
            "reservationStartedAt": preparation_proof["reservationStartedAt"],
            "finishedAt": time.time(),
        }
        if shadow is None:
            receipt["productionExecuted"] = True
            receipt["productionRequests"] += 2
    write_atomic_receipt(output / "receipt.json", receipt)
    return receipt


# The CLI is a frozen-input consumer. It never acquires or refreshes credentials.
import argparse
import hashlib
import math
import os
import re
import select
import stat
import subprocess

from batch_contract import DATABASE_PROJECTION, validate_owner_baseline

SHARED_ROOT = Path.home() / ".local/state/fireemu-broad/production-admission-v1"
ROOT = Path(__file__).resolve().parents[3]
MAX_INPUT_BYTES = 16 * 1024 * 1024


def sha_file(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("regular bound artifact required")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def load_json(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError("bounded regular prepared input required")
    value = json.loads(
        path.read_bytes(),
        parse_constant=lambda _: (_ for _ in ()).throw(
            ValueError("finite JSON required")
        ),
    )
    if not isinstance(value, dict):
        raise TypeError("prepared input object required")
    return value


def checkout_binding():
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT).strip():
        raise ValueError("clean frozen checkout required")
    return commit


def comparison_contract(plan):
    return {
        "version": 1,
        "projectId": plan["projectId"],
        "documentPrefix": plan["documentPrefix"],
        "resources": [
            {"role": "control", "suffix": "control"},
            {"role": "locked", "suffix": "locked"},
            {"role": "suffix", "suffix": "contended-tail"},
        ],
        "maxRpc": 25,
        "maxFramesPerRpc": 32,
    }


def compare_bound(collection, local, plan):
    # Fixed checked-in comparator, fixed Node runtime, bounded stdin/output.
    expected = comparison_contract(plan)
    local_plan = local["gate"]["plan"]
    expected["local"] = {
        "projectId": local_plan["projectId"],
        "documentPrefix": local_plan["documentPrefix"],
    }
    source = 'import {compareStreamReceipts} from "./stream_comparison.mjs"; let raw=""; for await (const chunk of process.stdin) { raw+=chunk; if(raw.length>16777216) process.exit(2); } process.stdout.write(JSON.stringify(compareStreamReceipts(JSON.parse(raw))));'
    result = subprocess.run(
        [plan["nodeRuntime"]["path"], "--input-type=module", "-e", source],
        input=json.dumps(
            {
                "production": collection,
                "local": local["collection"],
                "expected": expected,
            }
        ),
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
        cwd=Path(__file__).parent,
        env={},
    )
    if result.returncode != 0 or len(result.stdout) > MAX_INPUT_BYTES:
        raise ValueError("bounded comparison failed")
    value = json.loads(result.stdout)
    if value.get("classification") == "INDETERMINATE":
        raise ValueError("stream comparison proof incomplete")
    return value


def resource_locks(plan):
    """Keep shared configuration stable without serializing unrelated documents."""
    project = f"project/{PROJECT}"
    firestore = f"{project}/firestore/(default)"
    return [
        {"key": f"{firestore}/documents/{plan['documentPrefix']}", "mode": "EXCLUSIVE"},
        {"key": f"{firestore}/indexes", "mode": "READ"},
        {"key": f"{firestore}/ruleset", "mode": "READ"},
        {"key": f"{firestore}/database", "mode": "READ"},
        {"key": f"{project}/auth/config", "mode": "READ"},
        {"key": f"{project}/api-key-binding", "mode": "READ"},
    ]


def credential_mode_contract(mode):
    if mode == credential_prep.VERIFIED_MODE:
        return {
            "mode": mode,
            "outer": {
                "requests": 33,
                "seconds": 1100,
                "costMicrousd": TOTAL_COST_MICROUSD,
            },
            "preparation": None,
        }
    if mode == credential_prep.MODE:
        return {
            "mode": mode,
            "outer": credential_prep.contract()["outer"],
            "preparation": credential_prep.contract(),
        }
    raise ValueError("closed frozen credential mode required")


def legacy_verified_permission(permission):
    return (
        permission.get("kind") == "stream-prepared-owner-permission-v1"
        and "credentialMode" not in permission
    )


def bound_credential_contract(value):
    permission = value["permission"]
    if legacy_verified_permission(permission):
        if "credential" in value["manifest"]:
            raise ValueError("legacy permission requires legacy manifest")
        return credential_mode_contract(credential_prep.VERIFIED_MODE)
    mode = permission.get("credentialMode")
    contract = credential_mode_contract(mode)
    expected_kind = (
        "stream-prepared-refresh-owner-permission-v1"
        if mode == credential_prep.MODE
        else "stream-prepared-owner-permission-v1"
    )
    if (
        permission.get("kind") != expected_kind
        or value["manifest"].get("credential") != contract
    ):
        raise ValueError("frozen credential mode differs")
    return contract


def manifest(nonce, owner, credential_mode=credential_prep.VERIFIED_MODE):
    allocation = with_management(stream_bridge.compile_plan(PROJECT, nonce, owner))
    return {
        "kind": "stream-prepared-manifest-v1",
        "credential": credential_mode_contract(credential_mode),
        "allocation": allocation,
        "resourceLocks": resource_locks(allocation),
        "sourceDigest": stream_bridge.source_digest(),
        "pricingBasis": pricing_basis(),
        "pricingSdk": pricing_sdk_binding(),
        "comparatorSha256": sha_file(Path(__file__).with_name("stream_comparison.mjs")),
    }


def _prepared_inputs(permission_path, local_path, artifact_path, credential_mode=None):
    from reservations import Ledger

    import uuid

    permission = load_json(permission_path) if permission_path is not None else None
    local = load_json(local_path)
    artifact_path, local_path = (
        Path(artifact_path).resolve(),
        Path(local_path).resolve(),
    )
    nonce = permission.get("nonce") if permission else uuid.uuid4().hex
    owner = permission.get("ownerId") if permission else "stream-owner-" + nonce
    if (
        not isinstance(nonce, str)
        or not re.fullmatch(r"[a-f0-9]{32}", nonce)
        or not isinstance(owner, str)
    ):
        raise ValueError("fresh stream owner namespace required")
    mode = credential_mode or (permission or {}).get(
        "credentialMode", credential_prep.VERIFIED_MODE
    )
    mode_contract = credential_mode_contract(mode)
    outer = mode_contract["outer"]
    frozen = manifest(nonce, owner, mode)
    legacy = permission is not None and legacy_verified_permission(permission)
    if legacy:
        if mode != credential_prep.VERIFIED_MODE:
            raise ValueError("legacy permission only authorizes verified tokens")
        del frozen["credential"]
    ledger = Ledger(SHARED_ROOT)
    binding = {
        "sourceDigest": stream_bridge.source_digest(),
        "comparatorSha256": frozen["comparatorSha256"],
        "artifactPath": str(artifact_path),
        "artifactSha256": sha_file(artifact_path),
        "localReceiptPath": str(local_path),
        "localReceiptSha256": sha_file(local_path),
        "frozenCommit": checkout_binding(),
        "ledgerPath": str(ledger.path),
        "ledgerIdentity": ledger.identity,
    }
    required = {
        "kind": (
            "stream-prepared-refresh-owner-permission-v1"
            if mode == credential_prep.MODE
            else "stream-prepared-owner-permission-v1"
        ),
        "credentialMode": mode,
        "nonce": nonce,
        "ownerId": owner,
        "project": PROJECT,
        "projectNumber": NUMBER,
        "quotaProject": PROJECT,
        "database": "(default)",
        "manifestSha256": digest(frozen),
        "resourceLocks": frozen["resourceLocks"],
        "collectorSourceDigest": binding["sourceDigest"],
        "comparisonContractDigest": digest(comparison_contract(frozen["allocation"])),
        "comparatorSha256": binding["comparatorSha256"],
        "artifactSha256": binding["artifactSha256"],
        "localReceiptSha256": binding["localReceiptSha256"],
        "frozenCommit": binding["frozenCommit"],
        "ledgerIdentity": ledger.identity,
        "databaseProjectionContractDigest": digest(DATABASE_PROJECTION),
        "tariffsConfirmedBelowPlanningCeilings": True,
        "requestUpperBound": outer["requests"],
        "accountUpperBound": 0,
        "resourceUpperBound": 3,
        "concurrencyUpperBound": 1,
        "timeUpperBound": outer["seconds"],
        "costUpperMicrousd": outer["costMicrousd"],
        "pricingBasisDigest": digest(frozen["pricingBasis"]),
        "pricingSdkDigest": digest(frozen["pricingSdk"]),
        "allowedReobservations": 0,
        "recoveryDiagnostics": {
            "path": str(SHARED_ROOT / ("stream-recovery-" + nonce + ".jsonl")),
            "ownerRetainsUntilReservationResolved": True,
        },
    }
    if legacy:
        del required["credentialMode"]
    if mode == credential_prep.MODE:
        required["credentialPreparationDigest"] = digest(mode_contract["preparation"])
    if (
        local.get("kind") != "stream-prepared-execution-v1"
        or local.get("productionExecuted") is not False
        or local.get("acquisitionValidated") is not True
        or local.get("reservationReleased") is not True
        or local.get("failures") != []
        or local["gate"]["plan"].get("observerSha256") != binding["sourceDigest"]
    ):
        raise ValueError("current complete local outer receipt required")
    stream_bridge.validate_plan(local["gate"]["plan"])
    stream_bridge.validate_absence(local["gate"], "stream")
    compare_bound(local["collection"], local, local["gate"]["plan"])
    from stream_shadow import validate_owned_receipt

    validate_owned_receipt(local, binding["artifactSha256"])
    if permission is None:
        return {
            "kind": "stream-owner-proposal-v1",
            "status": "BLOCKED_OWNER",
            "bindings": binding,
            "manifest": frozen,
            "requiredPermission": required,
            "ownerFieldsRequired": (
                ["authorizedUserDigest", "credentialPrincipal"]
                if mode == credential_prep.MODE
                else []
            )
            + [
                "issuedAt",
                "expiresAt",
                "apiKeyDigest",
                "recoveryOwner",
                "authConfigDigest",
                "databaseProjectionDigest",
                "pricingLocation",
                "pricingCheckedAt",
                "databaseProjection",
                "ownerIdentity",
                "permissionReference",
            ],
            "permissionGranted": False,
        }
    validate_owner_baseline(permission, required, time.time())
    if (
        not isinstance(permission.get("apiKeyDigest"), str)
        or not re.fullmatch(r"[a-f0-9]{64}", permission["apiKeyDigest"])
        or not isinstance(permission.get("recoveryOwner"), str)
        or not permission["recoveryOwner"].strip()
    ):
        raise ValueError("API-key binding and recovery owner required")
    if mode == credential_prep.MODE:
        credential_prep.validate_principal(permission.get("credentialPrincipal"))
        if not re.fullmatch(
            r"[a-f0-9]{64}", str(permission.get("authorizedUserDigest", ""))
        ):
            raise ValueError("private authorized-user digest required")
    plan = prepared_plan(nonce, owner, digest(permission))
    return {
        "kind": "stream-prepared-inputs-v1",
        "permissionPath": str(Path(permission_path).resolve()),
        "permission": permission,
        "permissionDigest": digest(permission),
        "bindings": binding,
        "manifest": frozen,
        "plan": plan,
        "comparisonContract": comparison_contract(plan),
    }


def prepare_inputs(
    permission_path, local_path, artifact_path, output, *, credential_mode=None
):
    value = _prepared_inputs(
        permission_path, local_path, artifact_path, credential_mode
    )
    stream_bridge.write_private_json(output, value)
    return value


def validate_prepared(value):
    if not isinstance(value, dict) or value.get("kind") != "stream-prepared-inputs-v1":
        raise ValueError("closed prepared input required")
    binding = value["bindings"]
    current = _prepared_inputs(
        value["permissionPath"], binding["localReceiptPath"], binding["artifactPath"]
    )
    if digest(current) != digest(value):
        raise ValueError("prepared execution binding changed")
    return current


def _read_private_handoff(fd):
    if type(fd) is not int or fd < 3:
        raise ValueError("private O8 descriptor required")
    info = os.fstat(fd)
    if (
        info.st_uid != os.getuid()
        or info.st_mode & 0o077
        or not (
            stat.S_ISREG(info.st_mode)
            or stat.S_ISFIFO(info.st_mode)
            or stat.S_ISSOCK(info.st_mode)
        )
    ):
        raise ValueError("private O8 descriptor required")
    # A private regular file is also supported; secrets never become CLI arguments.
    raw = bytearray()
    deadline = time.monotonic() + 5
    while len(raw) <= 16384:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
            raise ValueError("O8 handoff deadline")
        chunk = os.read(fd, 16385 - len(raw))
        if not chunk:
            break
        raw.extend(chunk)
    if len(raw) > 16384:
        raise ValueError("bounded O8 handoff required")
    return credential_prep.decode_json(raw)


def read_refresh_handoff(fd, permission):
    return credential_prep.validate_handoff(_read_private_handoff(fd), permission)


def read_o8_handoff(fd, permission_digest):
    value = _read_private_handoff(fd)
    if (
        not isinstance(value, dict)
        or set(value)
        != {"kind", "permissionDigest", "token", "apiKey", "verifiedAt", "expiresAt"}
        or value["kind"] != "stream-o8-credential-v1"
        or value["permissionDigest"] != permission_digest
    ):
        raise ValueError("bound O8 handoff required")
    now = time.time()
    if (
        any(
            type(value[key]) not in (int, float) or not math.isfinite(value[key])
            for key in ("verifiedAt", "expiresAt")
        )
        or not 0 <= now - value["verifiedAt"] <= 300
        or not now + 1102 <= value["expiresAt"] <= now + 3600
    ):
        raise ValueError("verified O8 credential lifetime required")
    if any(
        not isinstance(value[key], str)
        or not value[key]
        or not value[key].isascii()
        or any(char.isspace() for char in value[key])
        or len(value[key]) > maximum
        for key, maximum in [("token", 8192), ("apiKey", 256)]
    ):
        raise ValueError("bounded O8 credential values required")
    credential = Credential()
    credential.accept(
        value["token"], {"expires_in": int(value["expiresAt"] - now)}, time.monotonic()
    )
    return credential, value["apiKey"]


def validate_recovery_capture(permission, *, fd=2):
    """The owner retains an exact private append file for last-resort recovery IDs."""
    import fcntl

    contract = permission["recoveryDiagnostics"]
    path = Path(contract["path"])
    info = os.fstat(fd)
    if (
        contract.get("ownerRetainsUntilReservationResolved") is not True
        or not path.is_absolute()
        or path.is_symlink()
        or not path.is_file()
        or info.st_uid != os.getuid()
        or info.st_mode & 0o077
        or not stat.S_ISREG(info.st_mode)
        or (info.st_dev, info.st_ino) != (path.stat().st_dev, path.stat().st_ino)
        or not fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_APPEND
    ):
        raise ValueError("exact private owner recovery stderr capture required")


def execute_prepared(config_path, output, credential_fd):
    from reservations import Ledger

    value = validate_prepared(load_json(config_path))
    validate_recovery_capture(value["permission"])
    permission = value["permission"]
    mode_contract = bound_credential_contract(value)
    mode = mode_contract["mode"]
    handoff = None
    if mode == credential_prep.MODE:
        handoff = read_refresh_handoff(credential_fd, permission)
        credential, api_key = None, handoff["apiKey"]
    else:
        credential, api_key = read_o8_handoff(credential_fd, value["permissionDigest"])
    if digest(api_key) != permission["apiKeyDigest"]:
        raise ValueError("O8 API-key binding differs")
    output = Path(output).absolute()
    ledger = Ledger(SHARED_ROOT)
    ticket, reservation_inputs = reserve_execution(value, output, ledger)
    return execute_reserved_inputs(
        value,
        output,
        ledger,
        ticket,
        api_key,
        credential,
        reservation_inputs=reservation_inputs,
        preparation_handoff=handoff,
    )


def reserve_execution(value, output, ledger):
    """Reserve the frozen mode without altering immutable owner permission."""
    permission, plan = value["permission"], value["plan"]
    outer = bound_credential_contract(value)["outer"]
    if digest(permission) != value["permissionDigest"]:
        raise ValueError("owner permission digest differs")
    output = Path(output).absolute()
    if output != output.resolve() or output.exists():
        raise ValueError("fresh canonical execution output required")
    locks = resource_locks(plan)
    if value["manifest"]["resourceLocks"] != locks:
        raise ValueError("frozen resource locks differ")
    budget = {
        "requests": outer["requests"],
        "accounts": 0,
        "resources": 3,
        "costMicrousd": outer["costMicrousd"],
    }
    envelope = {
        "permissionDigest": value["permissionDigest"],
        "issuedAt": permission["issuedAt"],
        "expiresAt": permission["expiresAt"],
        "limits": budget,
        "concurrency": 1,
        "scopes": locks,
    }
    claim = {
        "campaignId": "FS-WRITE-TXN-PRECEDENCE-01",
        "manifestDigest": digest(value["manifest"]),
        "nonceDigest": digest(plan["nonce"]),
        "gatePath": str(output / "gate"),
        "gatePlanDigest": digest(plan),
        "locks": locks,
        "budget": budget,
        "durationSeconds": outer["seconds"],
    }
    output.mkdir(mode=0o700)
    ticket = ledger.reserve(envelope, claim, plan)
    return ticket, {"claim": claim, "ticket": ticket, "envelope": envelope}


def execute_reserved_inputs(
    value,
    output,
    ledger,
    ticket,
    api_key,
    credential,
    *,
    reservation_inputs=None,
    preparation_handoff=None,
):
    """Own every operation after the one successful central reservation."""
    try:
        plan = value["plan"]
        stream_bridge.write_private_json(
            output / "inputs.json",
            {**value, **(reservation_inputs or {})},
        )

        preparation_proof = None
        if value.get("permission", {}).get("credentialMode") == credential_prep.MODE:
            if preparation_handoff is None:
                raise ValueError("frozen refresh mode requires private preparation")
            credential, preparation_proof = credential_prep.prepare_credentials(
                output,
                ledger,
                ticket,
                value["permission"],
                plan,
                preparation_handoff,
                binding_check=lambda: validate_prepared(value),
            )
        elif preparation_handoff is not None:
            raise ValueError("unbound credential preparation refused")

        def final_binding(collection):
            validate_prepared(value)
            if preparation_proof is not None:
                credential_prep.validate_preparation(
                    output,
                    ledger,
                    ticket,
                    value["permission"],
                    preparation_proof,
                    StreamProductionGate(output / "gate").snapshot(),
                )
            return compare_bound(
                collection, load_json(value["bindings"]["localReceiptPath"]), plan
            )

        return execute_session(
            plan,
            value["permission"],
            output,
            ledger,
            ticket,
            api_key,
            credential,
            final_binding=final_binding,
            preparation_proof=preparation_proof,
        )
    except Exception as error:  # noqa: BLE001 -- Reservation ownership persists across every setup failure.
        return retained_failure(output, ledger, ticket, error)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Prepare or execute one frozen stream campaign; credentials are supplied only by O8 private FD."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--permission", type=Path)
    prepare.add_argument(
        "--credential-mode",
        choices=[credential_prep.VERIFIED_MODE, credential_prep.MODE],
    )
    prepare.add_argument("--local-receipt", type=Path, required=True)
    prepare.add_argument("--artifact", type=Path, required=True)
    prepare.add_argument("--output", type=Path, required=True)
    execute = commands.add_parser("execute")
    execute.add_argument("--prepared", type=Path, required=True)
    execute.add_argument("--output", type=Path, required=True)
    execute.add_argument("--credential-fd", type=int, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            prepare_inputs(
                args.permission,
                args.local_receipt,
                args.artifact,
                args.output,
                credential_mode=args.credential_mode,
            )
            return 0
        result = execute_prepared(args.prepared, args.output, args.credential_fd)
        return 0 if result["acquisitionValidated"] else 1
    except Exception as error:  # noqa: BLE001 -- Never echo credential-bearing messages or tracebacks.
        print(
            f"Prepared stream refused ({type(error).__name__}); no permission is inferred.",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
