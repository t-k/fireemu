import hashlib
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/o8-core"))
sys.path.insert(0, str(HERE))

import action_codes_descriptor as campaign


NONCE = "a" * 32


def test_descriptor_binds_explicit_project_and_complete_campaign():
    descriptor = campaign.descriptor()
    plan = descriptor.plan_compiler(NONCE)
    assert plan["localProject"] == campaign.AUTHORIZED_PROJECT
    assert len(plan["stages"]) == 26
    assert len(plan["recovery"]) == 6
    assert descriptor.frozen_bounds["ownedAccountsMax"] == 2
    assert descriptor.window_seconds == 480


def test_lock_scopes_are_exactly_the_two_nonce_accounts():
    plan = campaign.descriptor().plan_compiler(NONCE)
    locks = campaign.descriptor().lock_scopes(plan)
    owned = [row for row in locks if row["mode"] == "WRITE"]
    assert len(owned) == 2
    assert all(campaign.AUTHORIZED_PROJECT in row["key"] for row in owned)
    assert all(NONCE in row["key"] for row in owned)


def test_source_map_contains_actual_transport_and_shared_abort_closure():
    sources = campaign.source_map()
    assert sources[campaign.WORKER_ENTRY] == hashlib.sha256(
        (ROOT / campaign.WORKER_ENTRY).read_bytes()
    ).hexdigest()
    for name in campaign.ABORT_CLOSURE_SOURCES:
        assert name in sources


def test_production_transport_is_closed():
    with pytest.raises(ValueError, match="transport remains closed"):
        campaign.descriptor().transport_bound({}, binding=b"x", binding_digest="x")
