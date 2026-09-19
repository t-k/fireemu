"""File-bound outer Commit acquisition; no production command-line entrypoint.

The caller supplies an independent owner permission, retained artifact, clean
source snapshot and existing shared Ledger. Injectable communication is only a
transport boundary; it cannot replace permission, reservations or Gate charging.

The O7 admission checks, the frozen-input record and the one-shot production
wire capability are not Commit-specific and live in the campaign-generic core
under `tools/compat-broad/o8-core`. This module is that core's first client: it
declares the Commit campaign descriptor at the bottom of the file and keeps only
the Commit file, git, Ledger, baseline, collector and comparator handling.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/production-admission"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/o8-core"))

import commit_baseline
import commit_remote_transport
import o8_admission
from batch_contract import DATABASE_PROJECTION, NUMBER, PROJECT, validate_owner_baseline
from broad_contract import digest
from commit_production import _save, collect_commit
from commit_remote_transport import request as remote_request
from commit_remote_transport import request_bound as remote_request_bound
from commit_reserved_adapter import (
    CommitReservedCoordinator,
    credential_preparation,
    source_digest,
    source_inputs,
    validate_handoff,
)
from gate_adapter import (
    compiler_plan,
    create_production_commit_gate,
    production_cost_model,
    production_gate_plan,
)
from o8_admission import (
    MAX_CAPABILITY_SCAN,
    PLACEHOLDER_OWNER_IDENTITIES,
    ProductionWireCapability,
    execution_host,
    issued_capability,
    revoke_production_capability,
    validate_owner_identity,
)
from o8_campaign import BASE_APPROVAL_FIELDS, CampaignDescriptor
from owned_transform_runner import validate_retained_artifact
from reservations import Ledger

__all__ = [
    "ABORT_CLOSURE_SOURCES",
    "APPROVAL_FIELDS",
    "APPROVAL_KIND",
    "BUDGET",
    "CAMPAIGN_SECONDS",
    "COMMIT",
    "MANIFEST_KIND",
    "MAX_CAPABILITY_SCAN",
    "PLACEHOLDER_OWNER_IDENTITIES",
    "RECOVERY_SECONDS",
    "REVIEWED_ARTIFACT_PROFILE",
    "WINDOW_SECONDS",
    "ProductionWireCapability",
    "abort_generation",
    "compare_saved",
    "execution_host",
    "freeze_inputs",
    "issue_production_capability",
    "permission_bindings",
    "revoke_production_capability",
    "run_acquisition",
    "validate_frozen_inputs",
    "validate_o7_admission",
    "validate_owner_identity",
]

# The live registry of issued capabilities, shared with the generic core.
_ISSUED = o8_admission._ISSUED

DATA_REQUESTS = 17
METADATA_ACTIONS = ("project", "database", "auth", "key")
BUDGET = {
    "requests": 27,
    "accounts": 0,
    "resources": 2,
    "costMicrousd": production_cost_model()["totalCostMicrousd"],
}
FROZEN_BOUNDS = {
    "dataRequests": 17,
    "metadataRequests": 8,
    "credentialRequests": 2,
    "totalRequests": 27,
}

CAMPAIGN_ID = "FS-DATA-WRITE-COMMIT-TRANSFORMS-03"
FROZEN_INPUTS_KIND = "commit-frozen-inputs-v2"
PERMISSION_KIND = "commit-owner-execution-permission-v1"
APPROVAL_KIND = "commit-o8-approval-v1"
MANIFEST_KIND = "commit-o8-manifest-v1"
REVIEWED_ARTIFACT_PROFILE = "repaired-567565bdd"
CAMPAIGN_SECONDS = 1200
RECOVERY_SECONDS = 180
# An approved window has to hold the whole campaign and its recovery allocation.
# A window sized to the wall budget alone admits a run that cannot finish its
# recovery inside the time the owner approved. The core derives the same value
# from the descriptor; this name is kept for callers that read it.
WINDOW_SECONDS = CAMPAIGN_SECONDS + RECOVERY_SECONDS
# The Commit approval keeps the original 16-key schema: its campaign identity is
# bound through the frozen plan, which the admission core checks against the
# descriptor. A campaign-generic approval carries `campaignId` as a 17th key.
APPROVAL_FIELDS = BASE_APPROVAL_FIELDS
# The source files whose digests a reservation records, so that a later abort
# proves it runs the same closure the acquisition ran.
ABORT_CLOSURE_SOURCES = (
    "tools/compat-broad/shared_gate.py",
    "tools/compat-broad/production-admission/reservations.py",
    "tools/compat-broad/fs-commit-transform-limits/commit_reserved_adapter.py",
    "tools/compat-broad/fs-commit-transform-limits/gate_adapter.py",
    "tools/compat-broad/fs-commit-transform-limits/commit_acquisition.py",
    "tools/compat-broad/o8-core/o8_admission.py",
    "tools/compat-broad/o8-core/o8_campaign.py",
)
COLLECTOR_ENTRY = "tools/compat-broad/fs-commit-transform-limits/commit_production.py"
COMPARATOR_ENTRY = (
    "tools/compat-broad/fs-commit-transform-limits/transform_comparator.py"
)


def _load_bundle():
    """Load the archive builder from its exact sibling path, not from sys.path."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "_commit_o8_bundle", HERE / "o8_bundle.py"
    )
    if spec is None or spec.loader is None:
        raise ValueError("reviewed archive builder unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _verify_worker_archive(binding, binding_digest, frozen):
    """Verify the live archive descriptor against the frozen worker closure."""
    _load_bundle().verify_worker_archive_fd(binding, binding_digest, frozen)


def _transmit_bound(value, *, binding, binding_digest, capability):
    """Run one bounded request in a worker loaded only from the bound archive."""
    return remote_request_bound(
        value,
        archive_fd=binding,
        archive_sha256=binding_digest,
        capability=capability,
    )


def _retained_artifact(artifact_path, manifest_path, profile):
    """Validate the retained artifact through this module's bound validator."""
    return validate_retained_artifact(artifact_path, manifest_path, profile=profile)


def _forbidden_transports():
    """Objects an injected preparation transport must not be able to reach."""
    return (
        remote_request,
        remote_request_bound,
        commit_remote_transport,
        commit_remote_transport._request_bound_unchecked,
    )


def _plan_compiler(nonce):
    return compiler_plan(PROJECT, "(default)", nonce)


def _collect(gate, plan, output, *, transmit):
    return collect_commit(gate, plan, output, transmit=transmit)


def _descriptor(descriptor):
    """The campaign this call runs under; the Commit descriptor unless overridden.

    An explicit descriptor exists so tests and a second campaign can drive the
    same code path. It is not a weakening of the Commit boundary: `commit_o8`
    never passes one, and any in-process caller able to pass a descriptor here
    could equally call the generic core directly.
    """
    return COMMIT if descriptor is None else descriptor


def abort_generation(inputs, *, descriptor=None):
    """The source closure this acquisition records on its reservation."""
    return o8_admission.abort_generation(_descriptor(descriptor), inputs)


def validate_frozen_inputs(inputs, *, descriptor=None) -> None:
    """The frozen O7 input self-consistency check used by every admission path."""
    o8_admission.validate_frozen_inputs(_descriptor(descriptor), inputs)


def validate_o7_admission(*, descriptor=None, **bindings):
    """The complete O7 admission check set, shared by the O8 CLI and by issuance."""
    return o8_admission.validate_o7_admission(_descriptor(descriptor), **bindings)


def issue_production_capability(*, descriptor=None, **bindings):
    """Issue the production wire capability for one fully admitted O7 campaign."""
    return o8_admission.issue_production_capability(_descriptor(descriptor), **bindings)


def _reject_production_transport(transmit, *, descriptor=None):
    """Refuse any injected callable that reaches the fixed production wire."""
    return o8_admission.reject_production_transport(_descriptor(descriptor), transmit)


def _read(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 8 * 1024 * 1024:
        raise ValueError("bounded regular input file required")
    return json.loads(path.read_bytes())


def _artifact(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
        raise ValueError("retained regular artifact required")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _provenance(source_root, expected_commit, expected_inputs, descriptor=None):
    source_root = Path(source_root).resolve()
    campaign = _descriptor(descriptor)

    def git(*args):
        return subprocess.check_output(["git", "-C", str(source_root), *args])

    if (
        git("rev-parse", "HEAD").decode().strip() != expected_commit
        or git("status", "--porcelain", "--untracked-files=all").strip()
        or expected_inputs != campaign.source_map()
    ):
        raise ValueError("clean frozen source snapshot required")
    for name, sha in expected_inputs.items():
        path = source_root / name
        if path.is_symlink() or not path.is_file() or _artifact(path) != sha:
            raise ValueError("source input differs")
        if hashlib.sha256(git("show", f"{expected_commit}:{name}")).hexdigest() != sha:
            raise ValueError("source input not in frozen commit")


def permission_bindings(plan, source_commit, artifact_digest, inputs, baseline=None):
    """Required non-authorizing fields for an independently supplied permission.

    When a derived production baseline is supplied, the three values that cannot
    be recomputed from the repository, the auth configuration digest, the
    database projection and its digest, and the pricing location, are required to
    equal what a named production observation actually produced. A literal that
    no recorded observation produces is refused here, offline, instead of
    spending a campaign's preflight budget to discover it.
    """
    if digest(plan) != digest(compiler_plan(PROJECT, "(default)", plan["nonce"])):
        raise ValueError("fixed production project/database required")
    required = {
        "kind": "commit-owner-execution-permission-v1",
        "project": PROJECT,
        "projectNumber": NUMBER,
        "quotaProject": PROJECT,
        "database": "(default)",
        "nonce": plan["nonce"],
        "planDigest": digest(plan),
        "sourceCommit": source_commit,
        "sourceInputs": inputs,
        "collectorSourceDigest": digest(inputs),
        "artifactSha256": artifact_digest,
        "comparatorSha256": inputs[
            "tools/compat-broad/fs-commit-transform-limits/transform_comparator.py"
        ],
        "budget": BUDGET,
        "wallSeconds": 1200,
        "recoverySeconds": 180,
        "concurrency": 1,
        "retentionHours": 24,
        "tariffsConfirmedBelowPlanningCeilings": True,
        "costModel": production_cost_model(),
        "credentialMode": "commit-bounded-authorized-user-v1",
        "credentialPreparationSha256": inputs[
            "tools/compat-broad/fs-write-txn/credential_prep.py"
        ],
        "databaseProjectionContractDigest": digest(DATABASE_PROJECTION),
    }
    if baseline is not None:
        required.update(commit_baseline.permission_baseline(baseline))
        required["baselineProvenance"] = baseline["provenance"]
    return required


def _approve(permission, plan, source_commit, artifact_digest, inputs, baseline=None):
    required = permission_bindings(
        plan, source_commit, artifact_digest, inputs, baseline
    )
    validate_owner_baseline(permission, required, time.time())
    # A permission always names where its production baseline came from, even
    # where the observation journals themselves are not available to re-read.
    commit_baseline.validate_provenance(permission.get("baselineProvenance"))
    if baseline is not None:
        commit_baseline.validate_permission_baseline(permission, baseline)
    validate_owner_identity(permission.get("ownerIdentity"), field="ownerIdentity")
    credential_preparation.validate_principal(permission.get("credentialPrincipal"))
    if digest({key: permission.get(key) for key in required}) != digest(required):
        raise ValueError("typed owner permission binding differs")
    # The recovery owner carries the same provenance weight as the execution
    # identity: it names who answers for a campaign that stops mid-flight.
    validate_owner_identity(permission.get("recoveryOwner"), field="recoveryOwner")


def freeze_inputs(
    permission_path, plan, *, source_root, artifact_path, baseline=None, descriptor=None
):
    """Freeze independently read permission and verified on-disk source/artifact.

    `baseline` is the production baseline recomputed from named observation
    records. It is supplied when a campaign is frozen, where those journals are
    available, and omitted when a frozen record is revalidated later; the
    permission's own provenance block is required either way.
    """
    campaign = _descriptor(descriptor)
    permission = _read(permission_path)
    inputs = campaign.source_map()
    commit = subprocess.check_output(
        ["git", "-C", str(source_root), "rev-parse", "HEAD"], text=True
    ).strip()
    artifact = _artifact(artifact_path)
    _provenance(source_root, commit, inputs, campaign)
    _approve(permission, plan, commit, artifact, inputs, baseline)
    return o8_admission.freeze_inputs(
        campaign, permission, plan, source_commit=commit, artifact_sha256=artifact
    )


def _validate(inputs, permission_path, source_root, artifact_path, descriptor=None):
    if inputs.get("inputsDigest") != digest(
        {k: v for k, v in inputs.items() if k != "inputsDigest"}
    ):
        raise ValueError("frozen inputs differ")
    permission = _read(permission_path)
    if digest(permission) != inputs["permissionDigest"] or digest(permission) != digest(
        inputs["permission"]
    ):
        raise ValueError("independent permission differs")
    expected = freeze_inputs(
        permission_path,
        inputs["plan"],
        source_root=source_root,
        artifact_path=artifact_path,
        descriptor=descriptor,
    )
    if digest(inputs) != digest(expected):
        raise ValueError("frozen binding differs")


def _validate_live(inputs, permission_path, source_root, artifact_path):
    if (
        digest(_read(permission_path)) != inputs["permissionDigest"]
        or _artifact(artifact_path) != inputs["artifactSha256"]
    ):
        raise ValueError("live permission or artifact differs")
    for name, expected in inputs["sourceInputs"].items():
        if _artifact(Path(source_root) / name) != expected:
            raise ValueError("live source input differs")
    head = subprocess.check_output(
        ["git", "-C", str(source_root), "rev-parse", "HEAD"], text=True
    ).strip()
    dirty = subprocess.check_output(
        [
            "git",
            "-C",
            str(source_root),
            "status",
            "--porcelain",
            "--untracked-files=all",
        ]
    )
    if head != inputs["sourceCommit"] or dirty.strip():
        raise ValueError("live source snapshot differs")


def _locks(plan):
    scope = f"project/{PROJECT}"
    firestore = f"{scope}/firestore/(default)"
    return [
        {
            "key": f"{firestore}/documents/oracle/{plan['nonce']}/commit-limits-03/*",
            "mode": "WRITE",
        },
        *[
            {"key": f"{firestore}/{kind}", "mode": "READ"}
            for kind in ("indexes", "ruleset", "database")
        ],
        {"key": f"{scope}/auth/config", "mode": "READ"},
        {"key": f"{scope}/api-key-binding", "mode": "READ"},
    ]


EVIDENCE_SOURCES = ("transform_comparator.py", "transform_compiler.py")


def _copy_frozen_sources(output, source_root, frozen):
    """Copy comparator evidence from the verified checkout, never from this file's tree.

    `_provenance()` and `_validate_live()` verify digests under `source_root`, so
    the retained evidence must come from there too; reading the sibling checkout
    of this module would save bytes that nothing in the receipt ever verified.
    """
    o8_bundle = _load_bundle()
    output = Path(output)
    for name in EVIDENCE_SOURCES:
        relative = f"tools/compat-broad/fs-commit-transform-limits/{name}"
        expected = frozen.get(relative)
        if type(expected) is not str:
            raise ValueError("frozen comparator source binding required")
        data = o8_bundle.read_source_bytes(Path(source_root), relative)
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError("frozen comparator source differs")
        with (output / name).open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())


def _run_acquisition(
    output,
    inputs,
    *,
    permission_path,
    source_root,
    artifact_path,
    ledger_root,
    api_key,
    credential_handoff,
    capability=None,
    injected_transport=None,
    descriptor=None,
):
    """Run an admitted acquisition. There is deliberately no implicit wire/ADC call.

    Production requires an O7-issued `ProductionWireCapability`, which only
    `commit_o8.execute()` can obtain and which pins the worker to an archive
    descriptor. `injected_transport` is the explicit local/preparation mode: it
    is never production evidence and can never set `productionExecuted`.
    """
    if (capability is None) == (injected_transport is None):
        raise ValueError(
            "exactly one of an O7 production capability or a local "
            "injected transport is required"
        )
    campaign = _descriptor(descriptor)
    if capability is None:
        _reject_production_transport(injected_transport, descriptor=campaign)
    elif not issued_capability(capability):
        raise ValueError("unissued O7 production capability")
    inputs = copy.deepcopy(inputs)
    if capability is None:
        transmit = injected_transport
    else:
        # Spend the O7 admission first: campaign, frozen inputs, shared Ledger
        # root and approval window are checked before any file, Ledger or wire.
        if not isinstance(inputs, dict) or not isinstance(inputs.get("plan"), dict):
            raise ValueError("frozen O7 inputs differ")
        capability._consume(
            campaign_id=inputs["plan"].get("campaignId"),
            inputs_digest=inputs.get("inputsDigest"),
            ledger_root=ledger_root,
        )
        transmit = capability._transmit
    _validate(inputs, permission_path, source_root, artifact_path, campaign)
    validate_handoff(credential_handoff, inputs["permission"], api_key)
    ledger = Ledger(ledger_root)
    permission, plan = (
        copy.deepcopy(inputs["permission"]),
        copy.deepcopy(inputs["plan"]),
    )
    output = Path(output)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    _save(output / "inputs.json", inputs)
    _copy_frozen_sources(output, source_root, inputs["sourceInputs"])
    binding = {
        "permissionDigest": inputs["permissionDigest"],
        "collectorSourceDigest": source_digest(),
    }
    projected = production_gate_plan(plan, binding)
    locks = campaign.lock_scopes(plan)
    envelope = {
        "permissionDigest": inputs["permissionDigest"],
        "issuedAt": permission["issuedAt"],
        "expiresAt": permission["expiresAt"],
        "limits": copy.deepcopy(campaign.budget),
        "concurrency": 1,
        "scopes": locks,
    }
    claim = {
        "campaignId": plan["campaignId"],
        "manifestDigest": inputs["planDigest"],
        "nonceDigest": digest(plan["nonce"]),
        "gatePath": str((output / "gate").resolve()),
        "gatePlanDigest": digest(projected),
        "locks": locks,
        "budget": copy.deepcopy(campaign.budget),
        "durationSeconds": campaign.campaign_seconds,
    }
    generation = abort_generation(inputs, descriptor=campaign)
    ticket = ledger.reserve(envelope, claim, projected, generation=generation)
    gate = coordinator = collection = None
    failure = None
    postflight = False
    wire_ran = False
    try:
        gate = create_production_commit_gate(output / "gate", plan, binding)
        gate.claim()
        coordinator = CommitReservedCoordinator(
            permission,
            plan["nonce"],
            output / "coordinator",
            gate,
            api_key,
            ledger=ledger,
            ticket=ticket,
            credential_handoff=credential_handoff,
            binding_check=lambda: _validate_live(
                inputs, permission_path, source_root, artifact_path
            ),
        )
        coordinator.acquire()
        coordinator.preflight()

        def wire(value):
            nonlocal wire_ran
            wire_ran = True
            return transmit(value)

        collection = campaign.collector(
            gate, plan, output / "collection", transmit=coordinator.bind_wire(wire)
        )
        coordinator.budget.recovery = True
        coordinator.recover_credentials()
        coordinator.preflight()
        postflight = True
        _validate(inputs, permission_path, source_root, artifact_path, campaign)
    except Exception as error:  # noqa: BLE001 -- sanitized receipt; retain ownership
        failure = type(error).__name__
    snapshot = gate.snapshot() if gate is not None else None
    ready = (
        failure is None
        and postflight
        and collection is not None
        and collection["collectionComplete"]
    )
    receipt = {
        "kind": "commit-acquisition-receipt-v2",
        "inputsDigest": inputs["inputsDigest"],
        "permissionDigest": inputs["permissionDigest"],
        "planDigest": digest(projected),
        "claimDigest": digest(claim),
        "collection": collection,
        "credentialEvidence": coordinator.credential_evidence if coordinator else [],
        "metadata": coordinator.metadata_evidence if coordinator else [],
        "ticket": ticket,
        # The closure this run executed under, so a receipt names the generation
        # an abort of its reservation has to prove.
        "generation": copy.deepcopy(generation),
        "reservationStateAtPublication": "held",
        "releaseRecord": "release.json" if ready else None,
        "chargedCalls": snapshot["total"] if snapshot else 0,
        "gate": snapshot,
        "executionKind": "fixed-production-wire"
        if capability is not None
        else "injected-transport",
        "productionExecuted": bool(wire_ran and capability is not None),
        "workerArchiveSha256": capability.binding_digest if capability else None,
        "acquisitionValidated": False,
        "promotionReady": False,
        "failure": failure,
        "postflightComplete": postflight,
        "releaseEligible": ready,
    }
    try:
        _save(output / "receipt.json", receipt)
    except OSError as error:
        failure_receipt = {
            **receipt,
            "failure": f"receipt-persistence:{type(error).__name__}",
            "releaseEligible": False,
            "releaseRecord": None,
        }
        _save(output / "failure.json", failure_receipt)
        return {**failure_receipt, "reservationReleased": False}
    released = False
    release = None
    if ready:
        try:
            ledger.finish(ticket)
            released = True
        except Exception as error:  # noqa: BLE001 -- actual ledger state retained
            failure = type(error).__name__
        release = {
            "receiptDigest": digest(receipt),
            "ticket": ticket,
            "failure": failure,
            "reservationFinal": ledger.snapshot()["reservations"][
                ticket["reservation"]
            ],
        }
        _save(output / "release.json", release)
    return {
        **receipt,
        "failure": failure,
        "reservationReleased": released,
        "release": release,
    }


def run_acquisition(
    output,
    inputs,
    *,
    permission_path,
    source_root,
    artifact_path,
    ledger_root,
    api_key,
    credential_handoff,
    capability=None,
    injected_transport=None,
    descriptor=None,
):
    """Run acquisition and revoke any consumed production capability on exit."""
    try:
        return _run_acquisition(
            output,
            inputs,
            permission_path=permission_path,
            source_root=source_root,
            artifact_path=artifact_path,
            ledger_root=ledger_root,
            api_key=api_key,
            credential_handoff=credential_handoff,
            capability=capability,
            injected_transport=injected_transport,
            descriptor=descriptor,
        )
    finally:
        if capability is not None:
            revoke_production_capability(capability)


def compare_saved(
    output,
    reference_path,
    *,
    expected_inputs_digest,
    expected_execution_kind="fixed-production-wire",
):
    """Validate linked saved records and run only their source-frozen comparator.

    The caller supplies the independently retained frozen-input digest and the
    execution kind it expects. The default is production, so a directory produced
    by an injected local transport fails closed here and cannot be mistaken for
    production evidence; local comparison must ask for it explicitly. This does
    not establish owner identity. No current permission, checkout, artifact,
    credential or wire is consulted.
    """
    if expected_execution_kind not in ("fixed-production-wire", "injected-transport"):
        raise ValueError("unknown saved execution kind")
    output = Path(output)
    inputs, receipt = _read(output / "inputs.json"), _read(output / "receipt.json")
    produced = expected_execution_kind == "fixed-production-wire"
    archive_sha256 = receipt.get("workerArchiveSha256")
    if (
        receipt.get("executionKind") != expected_execution_kind
        or receipt.get("productionExecuted") is not produced
        or (
            produced
            and (
                not isinstance(archive_sha256, str)
                or re.fullmatch(r"[0-9a-f]{64}", archive_sha256) is None
            )
        )
        or (not produced and archive_sha256 is not None)
    ):
        raise ValueError("saved execution kind is not the expected evidence")
    unsigned = {key: value for key, value in inputs.items() if key != "inputsDigest"}
    if (
        digest(unsigned) != expected_inputs_digest
        or inputs["inputsDigest"] != expected_inputs_digest
        or receipt["inputsDigest"] != expected_inputs_digest
        or receipt["permissionDigest"] != digest(inputs["permission"])
        or inputs["permissionDigest"] != digest(inputs["permission"])
        or receipt.get("releaseEligible") is not True
        or receipt.get("releaseRecord") != "release.json"
        or receipt.get("failure") is not None
        or receipt.get("chargedCalls") != 27
        or receipt.get("postflightComplete") is not True
        or [entry["id"] for entry in receipt["metadata"]]
        != [
            phase + ":" + action
            for phase in ("observation", "recovery")
            for action in METADATA_ACTIONS
        ]
        or any(entry["status"] != 200 for entry in receipt["metadata"])
    ):
        raise ValueError("saved acquisition binding incomplete")
    release = _read(output / "release.json")
    final = release["reservationFinal"]
    gate = receipt["gate"]
    if (
        release["receiptDigest"] != digest(receipt)
        or release["ticket"] != receipt["ticket"]
        or release.get("failure") is not None
        or final["state"] != "released"
        or final["finalGateDigest"] != digest(gate)
        or final["claimDigest"] != receipt["claimDigest"]
        or final["claim"]["gatePlanDigest"] != receipt["planDigest"]
        or digest(gate["plan"]) != receipt["planDigest"]
    ):
        raise ValueError("saved release binding incomplete")
    credential_evidence = receipt.get("credentialEvidence")
    if not isinstance(credential_evidence, list) or len(credential_evidence) != 2:
        raise ValueError("saved bounded credential evidence incomplete")
    for ordinal, slot in enumerate(("refresh", "tokeninfo"), 1):
        charge = _read(output / "coordinator" / f"oauth-{slot}-charge.json")
        evidence = _read(output / "coordinator" / f"oauth-{slot}-receipt.json")
        if (
            digest(evidence) != digest(credential_evidence[ordinal - 1])
            or evidence.get("chargeDigest") != digest(charge)
            or evidence.get("verified") is not True
            or evidence.get("workerReaped") is not True
            or evidence.get("complete") is not True
            or type(evidence.get("status")) is not int
            or evidence["status"] != 200
            or charge.get("ticketDigest") != digest(receipt["ticket"])
            or charge.get("permissionDigest") != inputs["permissionDigest"]
            or charge.get("ordinal") != ordinal
            or charge.get("slot") != slot
        ):
            raise ValueError("saved bounded credential journal differs")
    collection = _read(output / "collection/collection.json")
    if (
        digest(collection) != digest(receipt["collection"])
        or collection["collectionComplete"] is not True
    ):
        raise ValueError("saved collection differs")
    for phase, entries in (
        ("observation", collection["rows"]),
        ("recovery", collection["cleanup"]),
    ):
        for index, entry in enumerate(entries):
            if digest(
                _read(output / "collection" / f"{phase}-{index:02d}.json")
            ) != digest(entry):
                raise ValueError("saved row journal differs")
    for name in ("transform_compiler.py", "transform_comparator.py"):
        expected = inputs["sourceInputs"][
            f"tools/compat-broad/fs-commit-transform-limits/{name}"
        ]
        if _artifact(output / name) != expected:
            raise ValueError("saved comparator source differs")
    reference = _read(reference_path)
    script = (
        "import json,sys;sys.path.insert(0,sys.argv[1]);"
        "from transform_comparator import compare_rows;v=json.load(sys.stdin);"
        "print(json.dumps(compare_rows(v['plan'],v['rows'],v['reference']['plan'],v['reference']['rows'],"
        "left_recovery=v['cleanup'],right_recovery=v['reference']['cleanup'])))"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", script, str(output.resolve())],
        input=json.dumps(
            {
                "plan": inputs["plan"],
                "rows": collection["rows"],
                "cleanup": collection["cleanup"],
                "reference": reference,
            }
        ),
        text=True,
        capture_output=True,
        timeout=15,
        check=True,
        env={},
    )
    return {
        **json.loads(result.stdout),
        "executionKind": expected_execution_kind,
        "productionExecuted": produced,
    }


# The Commit campaign, the generic O8 core's first client. Every binding the
# admission checks depend on is declared here, in one hard-coded place; the core
# refuses a descriptor that is missing any of them.
COMMIT = CampaignDescriptor(
    campaign_id=CAMPAIGN_ID,
    frozen_inputs_kind=FROZEN_INPUTS_KIND,
    permission_kind=PERMISSION_KIND,
    approval_kind=APPROVAL_KIND,
    manifest_kind=MANIFEST_KIND,
    approval_fields=APPROVAL_FIELDS,
    artifact_profile=REVIEWED_ARTIFACT_PROFILE,
    campaign_seconds=CAMPAIGN_SECONDS,
    recovery_seconds=RECOVERY_SECONDS,
    source_map=source_inputs,
    abort_closure_sources=ABORT_CLOSURE_SOURCES,
    required_source_entries=(COLLECTOR_ENTRY, COMPARATOR_ENTRY),
    frozen_bounds=FROZEN_BOUNDS,
    budget=BUDGET,
    plan_compiler=_plan_compiler,
    lock_scopes=_locks,
    collector=_collect,
    comparator=compare_saved,
    cost_model=production_cost_model,
    permission_bindings=permission_bindings,
    transport_bound=_transmit_bound,
    binding_verifier=_verify_worker_archive,
    retained_artifact_validator=_retained_artifact,
    forbidden_transports=_forbidden_transports,
)
