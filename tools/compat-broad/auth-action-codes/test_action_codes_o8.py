"""Bounded tests for the Action-specific private-FD O8 entrypoint."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(HERE))

import action_codes_o8 as o8
import action_codes_plan as plan_module


NONCE = "a" * 32


def test_bindings_for_canonical_plan_cover_only_private_placeholders():
    plan = plan_module.campaign_manifest(NONCE, project="fireemu-35fe6")
    bindings = o8.bindings_for(plan)
    assert set(bindings) == {row["id"] for row in (*plan["stages"], *plan["recovery"])}
    assert all(value and value.isascii() and not any(char.isspace() for char in value) for row in bindings.values() for value in row.values())


def test_cli_bindings_are_stable_and_share_recovery_uids():
    plan = plan_module.campaign_manifest(NONCE, project="fireemu-35fe6")
    first = o8.bindings_for(plan)
    second = o8.bindings_for(plan)
    assert first == second
    assert first["link-generate-unknown-email"]["unknownEmail"] == (
        f"o1-oob-{NONCE}-absent@example.invalid"
    )
    assert first["reset-weak-password"]["weakPassword"].startswith("Aa9!")
    assert first["recover-delete-accountA"]["accountA.localId"] == (
        first["recover-uid-absence-accountA"]["accountA.localId"]
    )


def test_private_fd_rejects_an_oversized_handoff():
    with tempfile.TemporaryFile(mode="w+b") as stream:
        stream.write(b"x" * (o8.MAX_HANDOFF_BYTES + 1))
        stream.flush()
        stream.seek(0)
        with pytest.raises(ValueError, match="bounded private credential handoff"):
            o8.read_private_fd(stream.fileno())


def test_production_mode_has_no_loopback_escape():
    parser = o8.build_parser()
    args = parser.parse_args(
        [
            "--inputs", "inputs.json", "--approval", "approval.json",
            "--manifest", "manifest.json", "--permission", "permission.json",
            "--source", "source", "--artifact", "artifact", "--ledger", "ledger",
            "--output", "output", "--credential-fd", "3",
        ]
    )
    assert args.credential_fd == 3
