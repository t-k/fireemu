"""Preparation-only campaign descriptor for the O4 partition/cursor lane.

This module is a proof that the generic O8 core carries a second campaign. It is
NOT a production entry point and wires nothing to the wire:

- it has no command line, no credential handling and no Ledger access;
- the members that would let a campaign reach production (retained artifact
  profile, bound transport, worker archive closure, collector and comparator)
  have no default that works. Each one refuses when called, so a descriptor
  built here can freeze inputs and pass the O7 admission check set against a
  synthetic approval, and can do nothing else;
- the O4 lane's own modules are read, never modified, and its admission stays
  closed: `partition_cursor_manifest.admission_status()` still refuses.

Before O4 can execute, an owner has to supply the refusing members above, the
lane needs an O7-approved artifact profile, and the whole seam needs the same
independent security review the Commit lane received. The declared kinds,
window and budget below are proposals, not approved values.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/fs-query-partition-cursor"))
sys.path.insert(0, str(HERE))

from batch_contract import PROJECT
from o8_campaign import CAMPAIGN_APPROVAL_FIELDS, CampaignDescriptor
from partition_cursor_case import (
    CAMPAIGN,
    CURSOR_DOCUMENTS,
    OBSERVATION_COUNT,
    PARTITION_DOCUMENTS,
    RECOVERY_COUNT,
    compile_plan,
)
from partition_cursor_manifest import source_inputs as lane_source_inputs

DATABASE = "(default)"
OWNED_DOCUMENTS = PARTITION_DOCUMENTS + CURSOR_DOCUMENTS + 1
DATA_REQUESTS = OBSERVATION_COUNT + RECOVERY_COUNT
METADATA_REQUESTS = 8
CREDENTIAL_REQUESTS = 2
TOTAL_REQUESTS = DATA_REQUESTS + METADATA_REQUESTS + CREDENTIAL_REQUESTS
# Proposed, not approved: the lane's own planning ceiling is US$0.01.
COST_CEILING_MICROUSD = 10_000
CAMPAIGN_SECONDS = 1200
RECOVERY_SECONDS = 180
FROZEN_INPUTS_KIND = "o4-partition-cursor-frozen-inputs-v1"
PERMISSION_KIND = "o4-partition-cursor-owner-execution-permission-v1"
APPROVAL_KIND = "o4-partition-cursor-o8-approval-v1"
MANIFEST_KIND = "o4-partition-cursor-o8-manifest-v1"
ARTIFACT_PROFILE = "unreviewed-o4-partition-cursor"
COLLECTOR_ENTRY = (
    "tools/compat-broad/fs-query-partition-cursor/partition_cursor_collector.py"
)
COMPARATOR_ENTRY = (
    "tools/compat-broad/fs-query-partition-cursor/partition_cursor_comparator.py"
)
ABORT_CLOSURE_SOURCES = (
    "tools/compat-broad/shared_gate.py",
    "tools/compat-broad/production-admission/reservations.py",
    COLLECTOR_ENTRY,
    COMPARATOR_ENTRY,
)
BUDGET = {
    "requests": TOTAL_REQUESTS,
    "accounts": 0,
    "resources": OWNED_DOCUMENTS,
    "costMicrousd": COST_CEILING_MICROUSD,
}
FROZEN_BOUNDS = {
    "dataRequests": DATA_REQUESTS,
    "metadataRequests": METADATA_REQUESTS,
    "credentialRequests": CREDENTIAL_REQUESTS,
    "totalRequests": TOTAL_REQUESTS,
}


SHARED_CLOSURE = (
    "tools/compat-broad/shared_gate.py",
    "tools/compat-broad/production-admission/reservations.py",
)


def source_map() -> dict[str, str]:
    """The lane's own modules plus the shared Gate and Ledger closure.

    The lane manifest binds only its own directory, which is enough for a
    preparation record but not for a reservation: an abort has to prove the
    shared closure it was acquired under, so those two files are frozen here.
    """
    values = dict(lane_source_inputs())
    for name in SHARED_CLOSURE:
        values[name] = hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
    return values


def unwired(member: str):
    """A descriptor member the O4 lane has not earned yet."""

    def refuse(*args, **kwargs):
        raise PermissionError(f"O4 partition/cursor {member} is not wired")

    return refuse


def plan_compiler(nonce: str) -> dict:
    """The lane's own compiled observation plan, bound to one fresh nonce."""
    return compile_plan(PROJECT, DATABASE, nonce)


def lock_scopes(plan: dict) -> list[dict]:
    """Firestore document lock scopes for the nonce-unique owned namespace."""
    scope = f"project/{PROJECT}"
    firestore = f"{scope}/firestore/{DATABASE}"
    nonce = plan["nonce"]
    return [
        {
            "key": (
                f"{firestore}/documents/oracle/{nonce}/o4-query-partition-cursor/root/*"
            ),
            "mode": "WRITE",
        },
        *[
            {"key": f"{firestore}/{kind}", "mode": "READ"}
            for kind in ("indexes", "ruleset", "database")
        ],
        {"key": f"{scope}/auth/config", "mode": "READ"},
        {"key": f"{scope}/api-key-binding", "mode": "READ"},
    ]


def cost_model() -> dict:
    """The lane's planning ceiling, not a quoted tariff."""
    return {
        "campaignId": CAMPAIGN,
        "totalCostMicrousd": COST_CEILING_MICROUSD,
        "basis": "planning ceiling from the lane manifest; no tariff is confirmed",
    }


def permission_bindings(plan, source_commit, artifact_digest, inputs) -> dict:
    """Required non-authorizing fields an O4 owner permission would carry."""
    return {
        "kind": PERMISSION_KIND,
        "project": PROJECT,
        "database": DATABASE,
        "nonce": plan["nonce"],
        "sourceCommit": source_commit,
        "sourceInputs": inputs,
        "artifactSha256": artifact_digest,
        "comparatorSha256": inputs[COMPARATOR_ENTRY],
        "collectorSha256": inputs[COLLECTOR_ENTRY],
        "budget": BUDGET,
        "wallSeconds": CAMPAIGN_SECONDS,
        "recoverySeconds": RECOVERY_SECONDS,
        "concurrency": 1,
        "costModel": cost_model(),
    }


def descriptor(
    *,
    retained_artifact_validator=None,
    transport_bound=None,
    binding_verifier=None,
    collector=None,
    comparator=None,
    forbidden_transports=None,
) -> CampaignDescriptor:
    """Build the O4 descriptor; every production member must be supplied here.

    Leaving a member out yields one that refuses when called, which is what an
    offline dry run wants: the frozen inputs and the O7 admission check set can
    be exercised, and nothing can reach a collector, a comparator or a wire.
    """
    return CampaignDescriptor(
        campaign_id=CAMPAIGN,
        frozen_inputs_kind=FROZEN_INPUTS_KIND,
        permission_kind=PERMISSION_KIND,
        approval_kind=APPROVAL_KIND,
        manifest_kind=MANIFEST_KIND,
        approval_fields=CAMPAIGN_APPROVAL_FIELDS,
        artifact_profile=ARTIFACT_PROFILE,
        campaign_seconds=CAMPAIGN_SECONDS,
        recovery_seconds=RECOVERY_SECONDS,
        source_map=source_map,
        abort_closure_sources=ABORT_CLOSURE_SOURCES,
        required_source_entries=(COLLECTOR_ENTRY, COMPARATOR_ENTRY),
        frozen_bounds=FROZEN_BOUNDS,
        budget=BUDGET,
        plan_compiler=plan_compiler,
        lock_scopes=lock_scopes,
        collector=collector or unwired("production collector"),
        comparator=comparator or unwired("production comparator"),
        cost_model=cost_model,
        permission_bindings=permission_bindings,
        transport_bound=transport_bound or unwired("production transport"),
        binding_verifier=binding_verifier or unwired("worker archive closure"),
        retained_artifact_validator=(
            retained_artifact_validator or unwired("retained artifact profile")
        ),
        forbidden_transports=forbidden_transports or tuple,
    )
