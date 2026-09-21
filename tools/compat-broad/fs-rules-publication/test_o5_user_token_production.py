"""Tests for the externally approved O5 production launcher boundary."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "o8-core"))
sys.path.insert(0, str(HERE))

import o5_user_token_production as production


def test_launcher_requires_an_externally_materialized_approved_packet() -> None:
    with pytest.raises(ValueError, match="approved O5 packet"):
        production.run_approved({})


@pytest.mark.parametrize("field", ["approval", "manifest", "permission", "capabilityInputs"])
def test_launcher_refuses_missing_authority_material_before_any_wire(field: str) -> None:
    packet = {key: object() for key in production.REQUIRED_PACKET_KEYS}
    packet.pop(field)
    with pytest.raises(ValueError, match="approved O5 packet"):
        production.run_approved(packet)


def test_launcher_requires_canonical_ledger_and_gate_objects() -> None:
    packet = {key: object() for key in production.REQUIRED_PACKET_KEYS}
    packet["ledger"] = object()
    packet["gate"] = object()
    with pytest.raises(ValueError, match="approved O5 packet"):
        production.run_approved(packet)
