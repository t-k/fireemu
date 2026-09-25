"""Campaign-generic O8 admission: frozen inputs, O7 check set and capability.

This module is the single definition of "the O7 checks passed" for every
campaign. A lane supplies a `CampaignDescriptor` and keeps its own file, git,
Ledger and collector handling; the checks below, the one-shot production wire
capability and the frozen-input record are shared.

Nothing here grants authority. The wire authority remains the private credential
handoff and the shared Ledger reservation; an admitted capability only records
which campaign, frozen inputs, shared Ledger root and approval window one
execution is confined to, and which reviewed bytes its worker must load.
"""

from __future__ import annotations

import copy
import hashlib
import math
import platform
import sys
import time
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(HERE))

from broad_contract import digest
from o8_campaign import CampaignDescriptor

# Owner provenance must be a value the owner supplied. These are the shapes an
# agent or an unfilled template leaves behind, and admission refuses them.
PLACEHOLDER_OWNER_IDENTITIES = frozenset(
    {
        "agent",
        "ai",
        "assistant",
        "claude",
        "codex",
        "none",
        "owner",
        "owner-current-conversation",
        "owner-current-session",
        "placeholder",
        "tbd",
        "todo",
        "unknown",
    }
)
MAX_CAPABILITY_SCAN = 64
_CAPABILITY_TOKEN = object()
# Identity registry of live, unconsumed capabilities. Membership, never shape,
# is the admission test: a look-alike object with the same attributes fails.
_ISSUED: set = set()
_ACTIVE: set = set()
_CAPABILITY_STATE: dict = {}


def execution_host():
    """The host an approval is bound to; the campaign runs on this host only.

    The worker's process supervision and `/proc` assumptions are verified on one
    platform only, so an approval issued there must not authorize a run
    elsewhere. Prose in the package cannot enforce that; this binding can.
    """
    return {"platform": platform.system().lower(), "machine": platform.machine()}


def validate_owner_identity(value, *, field):
    """Refuse an absent or placeholder-shaped owner supplied identity."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"owner supplied {field} required")
    text = value.strip()
    if (
        text.startswith("<<")
        or text.endswith(">>")
        or text.casefold() in PLACEHOLDER_OWNER_IDENTITIES
    ):
        raise ValueError(f"owner supplied {field} required")


def regular_file_digest(path):
    """Digest a regular file without following a replaceable symlink."""
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("bound regular file required")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _require_descriptor(descriptor):
    if type(descriptor) is not CampaignDescriptor:
        raise ValueError("campaign descriptor required")
    return descriptor


def abort_generation(descriptor, inputs):
    """The source closure this acquisition records on its reservation.

    A reservation is retired after a preflight stop by proving the closure it
    was acquired under, so the binding is derived from the frozen inputs of this
    campaign rather than from a constant of an earlier generation. Proving it
    establishes that the aborting caller runs identical sources to the
    acquisition, not that those sources were reviewed.
    """
    _require_descriptor(descriptor)
    sources = inputs["sourceInputs"]
    if not isinstance(sources, dict) or any(
        name not in sources for name in descriptor.abort_closure_sources
    ):
        raise ValueError("frozen acquisition source closure required")
    return {
        "sourceCommit": inputs["sourceCommit"],
        "collectorSourceDigest": digest(sources),
        "sourceDigests": {
            Path(name).name: sources[name] for name in descriptor.abort_closure_sources
        },
    }


def freeze_inputs(descriptor, permission, plan, *, source_commit, artifact_sha256):
    """Build one campaign's frozen-input record over its declared source map.

    The source map is the descriptor's, not a hard-coded closure of one lane, so
    a second campaign freezes its own sources through this same record shape.
    """
    _require_descriptor(descriptor)
    inputs = descriptor.source_map()
    if not isinstance(inputs, dict) or not inputs:
        raise ValueError("campaign source map required")
    value = {
        "kind": descriptor.frozen_inputs_kind,
        "permission": permission,
        "permissionDigest": digest(permission),
        "plan": copy.deepcopy(plan),
        "planDigest": digest(plan),
        "sourceCommit": source_commit,
        "sourceInputs": inputs,
        "artifactSha256": artifact_sha256,
        "bounds": copy.deepcopy(descriptor.frozen_bounds),
    }
    value["inputsDigest"] = digest(value)
    return value


def validate_frozen_inputs(descriptor, inputs) -> None:
    """The frozen O7 input self-consistency check used by every admission path."""
    _require_descriptor(descriptor)
    if (
        not isinstance(inputs, dict)
        or inputs.get("kind") != descriptor.frozen_inputs_kind
    ):
        raise ValueError("O7 frozen approval binding required")
    required = {
        "permission",
        "permissionDigest",
        "plan",
        "planDigest",
        "sourceCommit",
        "sourceInputs",
        "artifactSha256",
        "inputsDigest",
    }
    if (
        not required.issubset(inputs)
        or inputs["permission"].get("kind") != descriptor.permission_kind
    ):
        raise ValueError("O7 frozen approval binding required")
    unsigned = {key: value for key, value in inputs.items() if key != "inputsDigest"}
    if (
        inputs["inputsDigest"] != digest(unsigned)
        or inputs["permissionDigest"] != digest(inputs["permission"])
        or inputs["planDigest"] != digest(inputs["plan"])
        or not isinstance(inputs["sourceInputs"], dict)
        or not isinstance(inputs["sourceCommit"], str)
        or not isinstance(inputs["artifactSha256"], str)
    ):
        raise ValueError("O7 frozen approval binding differs")
    # The collector and comparator this campaign executes must be named by the
    # frozen inputs, so the bytes the worker loads and the sources the receipt
    # is compared against are the ones the approval is bound to.
    if any(
        not isinstance(inputs["sourceInputs"].get(name), str)
        for name in descriptor.required_source_entries
    ):
        raise ValueError("frozen campaign entry source required")


def campaign_identity(descriptor, inputs):
    """The campaign this frozen plan declares, refused unless it is the descriptor's."""
    _require_descriptor(descriptor)
    plan = inputs.get("plan") if isinstance(inputs, dict) else None
    campaign_id = plan.get("campaignId") if isinstance(plan, dict) else None
    if not isinstance(campaign_id, str) or not campaign_id:
        raise ValueError("frozen campaign identity required")
    if campaign_id != descriptor.campaign_id:
        raise ValueError("frozen inputs belong to another campaign")
    return campaign_id


def validate_o7_admission(
    descriptor,
    *,
    inputs,
    approval,
    manifest,
    manifest_bytes,
    manifest_path,
    permission,
    ledger_root,
    artifact_path,
    launcher_path,
):
    """The complete O7 admission check set, shared by a lane's CLI and issuance.

    This is the single definition of "the O7 checks passed". A lane's CLI and
    `issue_production_capability` call exactly this function, so a capability can
    never be issued on a weaker check set than the CLI enforces.
    """
    _require_descriptor(descriptor)
    validate_frozen_inputs(descriptor, inputs)
    campaign_id = campaign_identity(descriptor, inputs)
    if not isinstance(approval, dict) or not isinstance(manifest, dict):
        raise ValueError("O7 approval artifact required")  # noqa: TRY004 -- admission boundary collapses malformed input to one refusal class
    if (
        set(approval) != set(descriptor.approval_fields)
        or approval["kind"] != descriptor.approval_kind
    ):
        raise ValueError("O7 approval artifact required")
    if descriptor.binds_campaign_id and approval["campaignId"] != campaign_id:
        raise ValueError("O7 approval belongs to another campaign")
    if manifest.get("kind") != descriptor.manifest_kind:
        raise ValueError("O7 manifest artifact required")
    if approval["status"] != "approved":
        raise ValueError("O7 approval is not approved")
    if approval["artifactProfile"] != descriptor.artifact_profile:
        raise ValueError("O7 artifact profile differs")
    if not isinstance(manifest_bytes, bytes):
        raise ValueError("retained O7 manifest bytes required")  # noqa: TRY004 -- admission boundary collapses malformed input to one refusal class
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    if manifest_sha256 != approval["manifestSha256"]:
        raise ValueError("O7 manifest digest differs")
    resolved_ledger = str(Path(ledger_root).resolve(strict=False))
    bindings = {
        "inputsDigest": inputs["inputsDigest"],
        "permissionDigest": inputs["permissionDigest"],
        "sourceCommit": inputs["sourceCommit"],
        "sourceInputsDigest": digest(inputs["sourceInputs"]),
        "artifactSha256": inputs["artifactSha256"],
        "planDigest": inputs["planDigest"],
        "nonceDigest": digest(inputs["plan"]["nonce"]),
        "ledgerRoot": resolved_ledger,
        # The launcher digest must bind the launcher that is actually running,
        # not whichever copy happens to sit next to the lane module.
        "launcherSha256": regular_file_digest(launcher_path),
    }
    if any(approval[key] != value for key, value in bindings.items()):
        raise ValueError("O7 approval binding differs")
    if approval["executionHost"] != execution_host():
        raise ValueError("O7 execution host differs")
    if (
        permission.get("wallSeconds") != descriptor.campaign_seconds
        or permission.get("recoverySeconds") != descriptor.recovery_seconds
    ):
        raise ValueError("O7 campaign window binding differs")
    if digest(permission) != inputs["permissionDigest"]:
        raise ValueError("stale O7 permission binding")
    if manifest.get("inputsDigest") != inputs["inputsDigest"]:
        raise ValueError("O7 manifest binding differs")
    for key in ("windowStartsAt", "windowExpiresAt"):
        if (
            type(approval[key]) not in (int, float)
            or isinstance(approval[key], bool)
            or not math.isfinite(approval[key])
        ):
            raise ValueError("O7 execution window invalid")
    seconds = descriptor.window_seconds
    if (
        not approval["windowStartsAt"] <= time.time()
        or time.time() + seconds > approval["windowExpiresAt"]
        or approval["windowStartsAt"] + seconds > approval["windowExpiresAt"]
    ):
        raise ValueError("O7 execution window expired")
    retained = descriptor.retained_artifact_validator(
        artifact_path, manifest_path, descriptor.artifact_profile
    )
    if (
        retained.get("artifactSha256") != inputs["artifactSha256"]
        or retained.get("retainedManifestSha256") != manifest_sha256
    ):
        raise ValueError("retained v7 artifact binding differs")
    return {
        "campaignId": campaign_id,
        "ledgerRoot": resolved_ledger,
        "windowStartsAt": approval["windowStartsAt"],
        "windowExpiresAt": approval["windowExpiresAt"],
        "retained": retained,
    }


class ProductionWireCapability:
    """One-shot record confining a production campaign to its O7 admission.

    The object is not the wire authority and neither is its integrity binding:
    the bytes a binding pins are plain repository sources that anyone may
    rebuild, so a binding pins which bytes the worker executes and is neither a
    secret nor a permission. The actual authority remains the private credential
    handoff and the shared Ledger reservation. What this object adds is that one
    fully admitted O7 approval can be spent exactly once, on its own campaign,
    frozen inputs, shared Ledger root and approval window.
    """

    __slots__ = (
        "_identity",
    )

    def __init__(
        self,
        token,
        *,
        binding,
        binding_digest,
        campaign_id,
        window_seconds,
        inputs_digest,
        ledger_root,
        window_starts_at,
        window_expires_at,
        approval_digest,
        transport_bound,
    ):
        if token is not _CAPABILITY_TOKEN:
            raise TypeError("the O8 production capability is not constructible")
        object.__setattr__(self, "_identity", object())
        _CAPABILITY_STATE[self] = {
            "binding": binding,
            "consumed": False,
            "transport": transport_bound,
            "binding_digest": binding_digest,
            "campaign_id": campaign_id,
            "inputs_digest": inputs_digest,
            "ledger_root": ledger_root,
            "window_starts_at": window_starts_at,
            "window_expires_at": window_expires_at,
            "window_seconds": window_seconds,
            "approval_digest": approval_digest,
        }

    def _state(self):
        try:
            return _CAPABILITY_STATE[self]
        except KeyError as exc:
            raise ValueError("unknown or revoked O8 production capability") from exc

    def __getattr__(self, name):
        if name in {
            "consumed",
            "binding_digest", "campaign_id", "inputs_digest", "ledger_root",
            "window_starts_at", "window_expires_at", "window_seconds",
            "approval_digest",
        }:
            if name == "consumed":
                return self._state()["consumed"]
            return self._state()[name]
        raise AttributeError(name)

    @property
    def _binding(self):
        return self._state()["binding"]

    def __copy__(self):
        raise TypeError("the O8 production capability is not copyable")

    def __deepcopy__(self, memo):
        raise TypeError("the O8 production capability is not copyable")

    def __reduce__(self):
        raise TypeError("the O8 production capability is not serializable")

    def __repr__(self):
        return f"<ProductionWireCapability campaign={self.campaign_id!r}>"

    def _consume(self, *, campaign_id, inputs_digest, ledger_root):
        """Spend this admission on exactly one campaign execution."""
        state = self._state()
        if state["consumed"]:
            raise ValueError("the O8 production capability is one-shot")
        if state["campaign_id"] != campaign_id:
            raise ValueError("production capability belongs to another campaign")
        if state["inputs_digest"] != inputs_digest:
            raise ValueError("production capability belongs to other frozen inputs")
        if state["ledger_root"] != str(Path(ledger_root).resolve(strict=False)):
            raise ValueError("production capability belongs to another shared Ledger")
        now = time.time()
        if (
            not state["window_starts_at"] <= now
            or now + state["window_seconds"] > state["window_expires_at"]
        ):
            raise ValueError("O7 execution window expired")
        state["consumed"] = True
        _ISSUED.discard(self)
        _ACTIVE.add(self)

    def _transmit(self, value):
        """Run one bounded request through the campaign's own integrity binding.

        The binding is whatever the campaign's reviewed transport pins its
        worker bytes with: an unlinked read-only archive descriptor for the
        Commit lane, the digest-pinned worker source for a lane that spawns its
        worker from source. Either way it is an integrity binding, not a secret
        and not an authority.
        """
        state = self._state()
        if not state["consumed"]:
            raise ValueError("unconsumed O8 production capability")
        if self not in _ACTIVE:
            raise ValueError("revoked or inactive O7 production capability")
        now = time.time()
        if not state["window_starts_at"] <= now <= state["window_expires_at"]:
            raise ValueError("O7 execution window expired")
        return state["transport"](
            value,
            binding=state["binding"],
            binding_digest=state["binding_digest"],
            capability=self,
        )


def issue_production_capability(
    descriptor,
    *,
    inputs,
    approval,
    manifest,
    manifest_bytes,
    manifest_path,
    permission,
    ledger_root,
    artifact_path,
    launcher_path,
    binding,
    binding_digest,
):
    """Issue the production wire capability for one fully admitted O7 campaign.

    Issuance runs the complete `validate_o7_admission` check set, so it is never
    a weaker gate than a lane's O8 CLI. The returned object is not itself the
    authority: it records which campaign, frozen inputs, shared Ledger root and
    approval window this execution is confined to, and which reviewed bytes the
    worker must load. The wire authority remains the private credential handoff
    and the shared Ledger reservation.
    """
    _require_descriptor(descriptor)
    admitted = validate_o7_admission(
        descriptor,
        inputs=inputs,
        approval=approval,
        manifest=manifest,
        manifest_bytes=manifest_bytes,
        manifest_path=manifest_path,
        permission=permission,
        ledger_root=ledger_root,
        artifact_path=artifact_path,
        launcher_path=launcher_path,
    )
    descriptor.binding_verifier(binding, binding_digest, inputs["sourceInputs"])
    capability = ProductionWireCapability(
        _CAPABILITY_TOKEN,
        binding=binding,
        binding_digest=binding_digest,
        campaign_id=admitted["campaignId"],
        window_seconds=descriptor.window_seconds,
        inputs_digest=inputs["inputsDigest"],
        ledger_root=admitted["ledgerRoot"],
        window_starts_at=admitted["windowStartsAt"],
        window_expires_at=admitted["windowExpiresAt"],
        approval_digest=digest(approval),
        transport_bound=descriptor.transport_bound,
    )
    _ISSUED.add(capability)
    return capability


def revoke_production_capability(capability) -> None:
    """Withdraw an issued capability that will not be executed."""
    _ISSUED.discard(capability)
    _ACTIVE.discard(capability)
    _CAPABILITY_STATE.pop(capability, None)


def authorize_transport(capability, *, binding, binding_digest) -> None:
    """Authorize one transport call from an admitted, consumed capability."""
    if type(capability) is not ProductionWireCapability or capability not in _ACTIVE:
        raise ValueError("unadmitted O7 production capability")
    now = time.time()
    if not capability.window_starts_at <= now <= capability.window_expires_at:
        raise ValueError("O7 execution window expired")
    if capability._binding != binding or capability.binding_digest != binding_digest:
        raise ValueError("production capability binding differs")


def reject_production_transport(descriptor, transmit):
    """Refuse any injected callable that reaches the fixed production wire.

    The production wire is unreachable without an admitted binding, so this is
    defense in depth: a preparation callback must not even name that path.
    """
    _require_descriptor(descriptor)
    if not callable(transmit):
        raise ValueError("injected local transport must be callable")  # noqa: TRY004 -- admission boundary collapses malformed input to one refusal class
    fixed = (*descriptor.forbidden_transports(), ProductionWireCapability._transmit)
    seen: set = set()
    pending = [transmit]
    while pending and len(seen) < MAX_CAPABILITY_SCAN:
        item = pending.pop()
        if id(item) in seen:
            continue
        seen.add(id(item))
        if any(item is entry for entry in fixed):
            raise ValueError("injected transport must not reach the production wire")
        if isinstance(item, ProductionWireCapability):
            raise ValueError(  # noqa: TRY004 -- refusal class, not a type report
                "injected transport must not reach the production wire"
            )
        for attribute in ("func", "__wrapped__", "__func__", "__self__"):
            nested = getattr(item, attribute, None)
            if nested is not None:
                pending.append(nested)
        for cell in getattr(item, "__closure__", None) or ():
            try:
                pending.append(cell.cell_contents)
            except ValueError:
                continue
        pending.extend(getattr(item, "__defaults__", None) or ())
        pending.extend((getattr(item, "__kwdefaults__", None) or {}).values())
        code = getattr(item, "__code__", None)
        if code is None:
            continue
        namespace = getattr(item, "__globals__", None) or {}
        for name in code.co_names:
            if name in namespace:
                pending.append(namespace[name])
        for value in list(pending):
            if isinstance(value, types.ModuleType):
                pending.extend(
                    getattr(value, name)
                    for name in code.co_names
                    if hasattr(value, name)
                )
    return transmit


def issued_capability(capability) -> bool:
    """Whether this exact object is a live, unconsumed capability."""
    return type(capability) is ProductionWireCapability and capability in _ISSUED
