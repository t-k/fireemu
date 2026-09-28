"""Externally approved launcher for the O5 Rules user-token campaign.

This module never creates approval material or credentials. A commander-owned
packet carries the independently reviewed O7 artifacts, response-bound Auth
proofs, and already-reserved Gate/Ledger objects. The launcher validates the
packet shape, consumes the one-shot capability, and delegates all wire and
cleanup behavior to the existing bridge and collector.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "production-admission"))
sys.path.insert(0, str(HERE.parent / "o8-core"))

from o5_user_token_campaign import validate_production_packet
from o5_user_token_descriptor import descriptor
from o5_user_token_production_bridge import run_bound_collection
from o8_admission import issue_production_capability, revoke_production_capability
from reservations import Ledger
from shared_gate import Gate

REQUIRED_PACKET_KEYS = frozenset(
    {
        "plan",
        "approval",
        "manifest",
        "manifestBytes",
        "manifestPath",
        "permission",
        "capabilityInputs",
        "artifactPath",
        "launcherPath",
        "ledgerRoot",
        "binding",
        "bindingDigest",
        "credentials",
        "setupSecrets",
        "frozenInputs",
        "accountBindings",
        "identityProofs",
        "fixtureOrigin",
        "gate",
        "ledger",
        "ticket",
        "acquisition",
        "runId",
    }
)


def _require_packet(packet: Any) -> dict[str, Any]:
    if not isinstance(packet, dict) or set(packet) != REQUIRED_PACKET_KEYS:
        raise ValueError("approved O5 packet required")
    if (
        not isinstance(packet["plan"], dict)
        or not isinstance(packet["approval"], dict)
        or not isinstance(packet["manifest"], dict)
        or not isinstance(packet["manifestBytes"], bytes)
        or not isinstance(packet["permission"], dict)
        or not isinstance(packet["capabilityInputs"], dict)
        or not isinstance(packet["credentials"], dict)
        or not isinstance(packet["setupSecrets"], dict)
        or not isinstance(packet["frozenInputs"], dict)
        or not isinstance(packet["accountBindings"], dict)
        or not isinstance(packet["identityProofs"], dict)
        or packet["fixtureOrigin"] is not None
        and not isinstance(packet["fixtureOrigin"], str)
        or not isinstance(packet["ticket"], dict)
        or not isinstance(packet["acquisition"], dict)
        or not isinstance(packet["runId"], str)
        or not packet["runId"]
        or not isinstance(packet["binding"], bytes)
        or not isinstance(packet["bindingDigest"], str)
        or not isinstance(packet["ledgerRoot"], (str, Path))
        or not isinstance(packet["manifestPath"], (str, Path))
        or not isinstance(packet["artifactPath"], (str, Path))
        or not isinstance(packet["launcherPath"], (str, Path))
        or not isinstance(packet["gate"], Gate)
        or not isinstance(packet["ledger"], Ledger)
    ):
        raise ValueError("approved O5 packet required")
    if packet["capabilityInputs"].get("plan") != packet["plan"]:
        raise ValueError("approved O5 packet plan binding differs")
    if packet["frozenInputs"].get("plan") != packet["plan"]:
        raise ValueError("approved O5 packet frozen plan differs")
    return packet


def run_approved(packet: dict[str, Any]) -> dict[str, Any]:
    """Consume one commander-approved packet and run the bound campaign."""
    values = _require_packet(packet)
    validate_production_packet(
        values["plan"],
        approval=values["approval"],
        permission=values["permission"],
        capability_inputs=values["capabilityInputs"],
        credentials=values["credentials"],
        account_bindings=values["accountBindings"],
        identity_proofs=values["identityProofs"],
        gate=values["gate"],
        ledger=values["ledger"],
        ticket=values["ticket"],
    )
    campaign = descriptor()
    capability = issue_production_capability(
        campaign,
        inputs=values["capabilityInputs"],
        approval=values["approval"],
        manifest=values["manifest"],
        manifest_bytes=values["manifestBytes"],
        manifest_path=values["manifestPath"],
        permission=values["permission"],
        ledger_root=values["ledgerRoot"],
        artifact_path=values["artifactPath"],
        launcher_path=values["launcherPath"],
        binding=values["binding"],
        binding_digest=values["bindingDigest"],
    )
    try:
        inputs = values["capabilityInputs"]
        capability._consume(
            campaign_id=inputs["plan"]["campaignId"],
            inputs_digest=inputs["inputsDigest"],
            ledger_root=values["ledgerRoot"],
        )
        return run_bound_collection(
            plan=values["plan"],
            gate=values["gate"],
            ledger=values["ledger"],
            ticket=values["ticket"],
            frozen_inputs=values["frozenInputs"],
            acquisition=values["acquisition"],
            run_id=values["runId"],
            permission_expires_at=values["approval"].get("windowExpiresAt"),
            setup_secrets=values["setupSecrets"],
            capability=capability,
            account_bindings=values["accountBindings"],
            credentials=values["credentials"],
            fixture_origin=values["fixtureOrigin"],
            binding=values["binding"],
            binding_digest=values["bindingDigest"],
            compare_after_collect=True,
        )
    finally:
        revoke_production_capability(capability)


__all__ = ["REQUIRED_PACKET_KEYS", "run_approved"]
