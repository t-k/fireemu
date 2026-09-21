"""Shared-O8 descriptor for the prepared FS-LISTEN-SDK campaign.

This descriptor only supplies the generic admission bindings. Its transport is
deliberately disabled until the shared Ledger registry and owner approval exist.
"""

from __future__ import annotations

import hashlib
import sys
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/o8-core"))

from broad_contract import digest
from o8_campaign import CAMPAIGN_APPROVAL_FIELDS, CampaignDescriptor

_PACKAGE = "o6_listen_o8"
if _PACKAGE not in sys.modules:
    package = types.ModuleType(_PACKAGE)
    package.__path__ = [str(HERE)]
    sys.modules[_PACKAGE] = package
from o6_listen_o8 import campaign, observation

CAMPAIGN = "FS-LISTEN-SDK"
FROZEN_INPUTS_KIND = "fs-listen-sdk-o8-frozen-inputs-v1"
PERMISSION_KIND = "fs-listen-sdk-o8-owner-execution-permission-v1"
APPROVAL_KIND = "fs-listen-sdk-o8-approval-v1"
MANIFEST_KIND = "fs-listen-sdk-o8-manifest-v1"
ARTIFACT_PROFILE = "fs-listen-sdk-local-shadow"

COLLECTOR_ENTRY = "tools/compat-broad/fs-listen-resume/listen_collector.mjs"
COMPARATOR_ENTRY = "tools/compat-broad/fs-listen-resume/observation.py"
ADAPTER_ENTRY = "tools/compat-broad/fs-listen-resume/listen_sdk_adapter.mjs"
BROWSER_ENTRY = "tools/compat-broad/fs-listen-resume/listen_browser_adapter.mjs"
LANE_SOURCES = (
    COLLECTOR_ENTRY,
    COMPARATOR_ENTRY,
    ADAPTER_ENTRY,
    BROWSER_ENTRY,
    "tools/compat-broad/fs-listen-resume/cases.py",
    "tools/compat-broad/fs-listen-resume/campaign.py",
    "tools/sdk-smoke/package-lock.json",
)
SHARED_SOURCES = (
    "tools/compat-broad/o8-core/o8_admission.py",
    "tools/compat-broad/o8-core/o8_campaign.py",
    "tools/compat-broad/production-admission/reservations.py",
    "tools/compat-broad/shared_gate.py",
)
ABORT_CLOSURE_SOURCES = (*LANE_SOURCES, *SHARED_SOURCES)


def _file_digest(relative: str) -> str:
    path = ROOT / relative
    if path.is_symlink() or not path.is_file():
        raise ValueError("frozen campaign source missing")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_map() -> dict[str, str]:
    return {name: _file_digest(name) for name in ABORT_CLOSURE_SOURCES}


def plan_compiler(nonce: str) -> dict:
    if not isinstance(nonce, str) or len(nonce) != 32:
        raise ValueError("fresh 128-bit nonce required")
    plan = campaign.compile_campaign(nonce, permission="o6-listen-sdk-0000000000000000")
    plan["campaignId"] = CAMPAIGN
    plan["nonce"] = nonce
    plan["planDigest"] = digest(plan)
    return plan


def lock_scopes(plan: dict) -> list[dict]:
    nonce = plan.get("nonce")
    return [
        {"key": "project/fireemu-35fe6/firestore/(default)/documents/o6_listen/*", "mode": "EXCLUSIVE"},
        {"key": "project/fireemu-35fe6/firestore/(default)/documents/o6_listen_private/*", "mode": "EXCLUSIVE"},
        {"key": f"project/fireemu-35fe6/listen/{nonce}", "mode": "EXCLUSIVE"},
    ]


def frozen_bounds() -> dict:
    return {"observationSeconds": 600, "recoverySeconds": 180, "maxCases": 18}


def budget() -> dict:
    counts = campaign.count_operations()
    return {
        "requests": counts["reads"] + counts["writes"] + counts["deletes"],
        "accounts": 2,
        "resources": len(campaign.campaign_paths("0" * 32)),
        "costMicrousd": int(campaign.estimate_cost_usd(counts) * 1_000_000),
    }


def cost_model() -> dict:
    return {"estimatedCostUsd": campaign.estimate_cost_usd(), "hardCostCeilingUsd": 0.5}


def collector(*_args, **_kwargs):
    return {"entry": "tools/compat-broad/fs-listen-resume/listen_collector.mjs"}


def comparator(result, shadow=None):
    if not isinstance(result, dict):
        raise ValueError("Listen comparison result required")
    local = result.get("local")
    production = result.get("production", shadow)
    return observation.compare_observations(
        result.get("campaign", {}), local, production, base_dir=ROOT
    )


def permission_bindings(plan, source_commit, artifact_digest, inputs):
    return {
        "kind": PERMISSION_KIND,
        "campaignId": CAMPAIGN,
        "project": campaign.PROJECT,
        "database": campaign.DATABASE,
        "nonce": plan["nonce"],
        "planDigest": digest(plan),
        "sourceCommit": source_commit,
        "sourceInputs": inputs,
        "artifactSha256": artifact_digest,
        "sdk": dict(campaign.SDK_PIN),
        "budget": budget(),
        "ownerPreconditions": [dict(item) for item in campaign.OWNER_PRECONDITIONS],
    }


def transport_bound(value, *, binding, binding_digest, capability=None):
    if capability is not None:
        raise ValueError("FS-LISTEN-SDK production transport is not enabled")
    return {
        "kind": "fs-listen-sdk-transport-binding-v1",
        "adapter": ADAPTER_ENTRY,
        "valueKind": type(value).__name__,
        "bindingDigest": binding_digest,
        "productionEnabled": False,
    }


def binding_verifier(binding, binding_digest, frozen):
    if not isinstance(binding, bytes) or not binding:
        raise ValueError("reviewed Listen adapter source required")
    observed = hashlib.sha256(binding).hexdigest()
    if observed != binding_digest:
        raise ValueError("Listen adapter source digest differs")
    if frozen is not None and frozen.get(ADAPTER_ENTRY) != observed:
        raise ValueError("Listen adapter source differs from frozen inputs")


def retained_artifact_validator(artifact_path, manifest_path, profile):
    if profile != ARTIFACT_PROFILE:
        raise ValueError("retained artifact profile differs")
    values = {}
    for key, path in (("artifactSha256", artifact_path), ("retainedManifestSha256", manifest_path)):
        path = Path(path)
        if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
            raise ValueError("retained regular artifact required")
        values[key] = hashlib.sha256(path.read_bytes()).hexdigest()
    return values


def forbidden_transports():
    return (transport_bound,)


def descriptor() -> CampaignDescriptor:
    return CampaignDescriptor(
        campaign_id=CAMPAIGN,
        frozen_inputs_kind=FROZEN_INPUTS_KIND,
        permission_kind=PERMISSION_KIND,
        approval_kind=APPROVAL_KIND,
        manifest_kind=MANIFEST_KIND,
        approval_fields=CAMPAIGN_APPROVAL_FIELDS,
        artifact_profile=ARTIFACT_PROFILE,
        campaign_seconds=600,
        recovery_seconds=180,
        source_map=source_map,
        abort_closure_sources=ABORT_CLOSURE_SOURCES,
        required_source_entries=(COLLECTOR_ENTRY, ADAPTER_ENTRY, COMPARATOR_ENTRY),
        frozen_bounds=frozen_bounds(),
        budget=budget(),
        plan_compiler=plan_compiler,
        lock_scopes=lock_scopes,
        collector=collector,
        comparator=comparator,
        cost_model=cost_model,
        permission_bindings=permission_bindings,
        transport_bound=transport_bound,
        binding_verifier=binding_verifier,
        retained_artifact_validator=retained_artifact_validator,
        forbidden_transports=forbidden_transports,
    )
