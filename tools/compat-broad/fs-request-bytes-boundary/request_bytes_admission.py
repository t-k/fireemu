"""File-bound O8 admission for the request-byte boundary campaign.

This module freezes the campaign's inputs, runs the shared O7 admission check
set through the campaign-generic core, and adapts the reviewed remote transport
to a capability-bound wire call. It has no command line; the launcher is
`request_bytes_o8.py`.

What it deliberately does not do is start a production run. The shared
reservation contract requires a Gate that hosts the campaign's schedule, and
the shared Gate cannot host this one: `shared_gate.create` admits one or two
jobs while the schedule spans three probes, `Gate.dispatch` makes recovery a
one-way transition per job while the schedule interleaves observation and
recovery within each probe, and `Ledger.finish` addresses the Gate by the fixed
job name `limits`. `reservation_claim` therefore builds every part of the claim
that is settled and refuses to invent the Gate binding that is not. Admission,
which is what an O7 freeze binds, is complete and testable today.
"""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/production-admission"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/o8-core"))
sys.path.insert(0, str(HERE))

import o8_admission
import request_bytes_descriptor as campaign
from broad_contract import digest
from o8_admission import (
    ProductionWireCapability,
    execution_host,
    issued_capability,
    revoke_production_capability,
    validate_owner_identity,
)

MAX_INPUT_BYTES = 8 * 1024 * 1024
UNRESOLVED_GATE = (
    "the shared Gate cannot host the request-byte schedule: three probes exceed "
    "the two-job limit, and recovery is a one-way transition per job while the "
    "schedule interleaves observation and recovery within each probe"
)

__all__ = [
    "UNRESOLVED_GATE",
    "ProductionWireCapability",
    "abort_generation",
    "bind_execute",
    "build_receipt",
    "descriptor",
    "execution_host",
    "freeze_inputs",
    "issue_production_capability",
    "permission_bindings",
    "reservation_claim",
    "revoke_production_capability",
    "validate_fresh_admission",
    "validate_frozen_inputs",
    "validate_o7_admission",
]


def descriptor():
    return campaign.descriptor()


def permission_bindings(plan, source_commit, artifact_digest, inputs):
    return campaign.permission_bindings(plan, source_commit, artifact_digest, inputs)


def validate_frozen_inputs(inputs) -> None:
    o8_admission.validate_frozen_inputs(descriptor(), inputs)


def abort_generation(inputs):
    return o8_admission.abort_generation(descriptor(), inputs)


def validate_o7_admission(**bindings):
    return o8_admission.validate_o7_admission(descriptor(), **bindings)


def issue_production_capability(**bindings):
    return o8_admission.issue_production_capability(descriptor(), **bindings)


def _read(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError("bounded regular input file required")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("bounded JSON object required")  # noqa: TRY004 -- refusal class, not a type report
    return value


def _artifact(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
        raise ValueError("retained regular artifact required")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _provenance(source_root, expected_commit, expected_inputs) -> None:
    """Every frozen source must be clean, current and present in the named commit."""
    source_root = Path(source_root).resolve()

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


def _approve(permission, plan, source_commit, artifact_digest, inputs) -> None:
    required = permission_bindings(plan, source_commit, artifact_digest, inputs)
    if digest({key: permission.get(key) for key in required}) != digest(required):
        raise ValueError("typed owner permission binding differs")
    validate_owner_identity(permission.get("ownerIdentity"), field="ownerIdentity")
    # The recovery owner carries the same provenance weight as the execution
    # identity: it names who answers for a campaign that stops mid-flight, and
    # this campaign can leave up to 17 documents behind when a request times out.
    validate_owner_identity(permission.get("recoveryOwner"), field="recoveryOwner")
    if (
        not isinstance(permission.get("permissionReference"), str)
        or not permission["permissionReference"].strip()
    ):
        raise ValueError("owner supplied permissionReference required")


def freeze_inputs(permission_path, plan, *, source_root, artifact_path):
    """Freeze an independently read permission over a verified source snapshot.

    `plan` is the reference, not the 63 MB compiled plan. Recompiling it here
    proves the reference names exactly one plan the reviewed compiler produces.
    """
    campaign.execution_plan(plan)
    permission = _read(permission_path)
    inputs = campaign.source_map()
    commit = subprocess.check_output(
        ["git", "-C", str(source_root), "rev-parse", "HEAD"], text=True
    ).strip()
    artifact = _artifact(artifact_path)
    _provenance(source_root, commit, inputs)
    _approve(permission, plan, commit, artifact, inputs)
    return o8_admission.freeze_inputs(
        descriptor(),
        permission,
        plan,
        source_commit=commit,
        artifact_sha256=artifact,
    )


def validate_fresh_admission(ledger_root, plan, permission) -> dict:
    """Refuse a reused nonce or a reused owner permission, reading only.

    A campaign that re-entered an owned namespace, or that spent a permission a
    previous reservation already spent, would make its own absence proofs
    meaningless. The shared Ledger is the record of both, and this check reads
    it without taking a reservation.
    """
    root = Path(ledger_root)
    state_path = root / "state.json"
    if root.is_symlink() or not state_path.is_file():
        raise ValueError("existing shared Ledger required")
    state = json.loads(state_path.read_bytes())
    nonce_digest = digest(plan["nonce"])
    permission_digest = digest(permission)
    for row in state.get("reservations", {}).values():
        claim = row.get("claim", {})
        if claim.get("nonceDigest") == nonce_digest:
            raise ValueError("campaign nonce already reserved")
        for lock in claim.get("locks", []):
            if plan["nonce"] in str(lock.get("key", "")):
                raise ValueError("campaign nonce already reserved")
    for entry in state.get("envelopes", {}).values():
        envelope = entry.get("envelope", entry)
        if envelope.get("permissionDigest") == permission_digest:
            raise ValueError("owner permission already spent")
    return {
        "ledgerRoot": str(root.resolve(strict=False)),
        "nonceDigest": nonce_digest,
        "permissionDigest": permission_digest,
    }


def reservation_claim(inputs, *, gate_path=None):
    """The shared Ledger claim for this campaign, minus the unresolved Gate.

    Every settled part is here: the campaign identity, the frozen plan digest,
    the nonce digest, the owned document lock scopes and the budget. The Gate
    binding is not, and this refuses rather than inventing one.
    """
    descriptor_ = descriptor()
    plan = inputs["plan"]
    claim = {
        "campaignId": descriptor_.campaign_id,
        "manifestDigest": inputs["planDigest"],
        "nonceDigest": digest(plan["nonce"]),
        "locks": descriptor_.lock_scopes(plan),
        "budget": copy.deepcopy(descriptor_.budget),
        "durationSeconds": descriptor_.campaign_seconds,
    }
    if gate_path is None:
        raise ValueError(f"request-byte reservation is unavailable: {UNRESOLVED_GATE}")
    claim["gatePath"] = str(Path(gate_path).resolve())
    return claim


def transport_call(plan, phase, index, operation, token) -> dict:
    """The closed value one bound wire call carries."""
    return {
        "plan": plan,
        "phase": phase,
        "index": index,
        "operation": operation,
        "token": token,
    }


def bind_execute(capability, plan, token, *, schedule=None):
    """Adapt the collector's one-argument callable onto an admitted capability.

    The collector drives the frozen schedule and hands each operation here. The
    slot coordinates come from the schedule, never from the operation, so a
    caller cannot move a request to another slot by reshaping it.
    """
    if not issued_capability(capability) and not capability._consumed:
        raise ValueError("unissued O7 production capability")
    if schedule is None and "executionSchedule" not in plan:
        raise ValueError("bind_execute requires the compiled plan, not its reference")
    order = list(schedule if schedule is not None else plan["executionSchedule"])
    position = {"index": 0}

    def execute(operation):
        if position["index"] >= len(order):
            raise ValueError("request-byte schedule exhausted")
        slot = order[position["index"]]
        position["index"] += 1
        return capability._transmit(
            transport_call(plan, slot["phase"], slot["index"], operation, token)
        )

    return execute


def build_receipt(inputs, result, *, capability, rows, generation, failure=None):
    """The campaign receipt, binding every route it observed by response digest."""
    metadata = [
        {
            "id": f"{row['phase']}:{row['index']:03d}",
            "route": row["route"],
            "status": row.get("status"),
            "responseDigest": row["responseDigest"],
        }
        for row in rows
    ]
    return {
        "kind": "request-bytes-acquisition-receipt-v1",
        "campaignId": descriptor().campaign_id,
        "inputsDigest": inputs["inputsDigest"],
        "permissionDigest": inputs["permissionDigest"],
        "planDigest": inputs["planDigest"],
        "collection": result,
        "metadata": metadata,
        "routeDigest": digest(metadata),
        "generation": copy.deepcopy(generation),
        "executionKind": "fixed-production-wire"
        if capability is not None
        else "injected-transport",
        "productionExecuted": capability is not None,
        "workerSha256": capability.binding_digest if capability is not None else None,
        "transportDeadlineSeconds": campaign.transport_deadline_seconds(),
        "failure": failure,
    }
