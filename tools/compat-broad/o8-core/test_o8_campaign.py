"""Construction negatives for the campaign descriptor.

No credential, network or production artifact is used.
"""

import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from o8_campaign import (
    BASE_APPROVAL_FIELDS,
    CAMPAIGN_APPROVAL_FIELDS,
    REQUIRED_MEMBERS,
    CampaignDescriptor,
)


def members(**overrides):
    base = {
        "campaign_id": "TEST-CAMPAIGN-01",
        "frozen_inputs_kind": "test-frozen-inputs-v1",
        "permission_kind": "test-owner-execution-permission-v1",
        "approval_kind": "test-o8-approval-v1",
        "manifest_kind": "test-o8-manifest-v1",
        "approval_fields": CAMPAIGN_APPROVAL_FIELDS,
        "artifact_profile": "test-profile",
        "campaign_seconds": 600,
        "recovery_seconds": 120,
        "source_map": dict,
        "abort_closure_sources": ("tools/compat-broad/o8-core/o8_admission.py",),
        "required_source_entries": ("tools/compat-broad/o8-core/o8_campaign.py",),
        "frozen_bounds": {"totalRequests": 1},
        "budget": {"requests": 1},
        "plan_compiler": lambda nonce: {"nonce": nonce},
        "lock_scopes": lambda plan: [],
        "collector": lambda *args, **kwargs: None,
        "comparator": lambda *args, **kwargs: None,
        "cost_model": dict,
        "permission_bindings": lambda *args: {},
        "transport_bound": lambda value, **kwargs: value,
        "binding_verifier": lambda *args: None,
        "retained_artifact_validator": lambda *args: {},
        "forbidden_transports": tuple,
    }
    base.update(overrides)
    return base


def test_the_window_is_the_wall_budget_plus_recovery():
    descriptor = CampaignDescriptor(**members())
    assert descriptor.window_seconds == 720
    assert descriptor.window_seconds == (
        descriptor.campaign_seconds + descriptor.recovery_seconds
    )


def test_a_complete_descriptor_declares_every_required_member():
    descriptor = CampaignDescriptor(**members())
    assert set(descriptor.members()) == set(REQUIRED_MEMBERS)
    assert descriptor.campaign_id == "TEST-CAMPAIGN-01"
    assert descriptor.binds_campaign_id is True


@pytest.mark.parametrize("member", REQUIRED_MEMBERS)
def test_a_descriptor_missing_any_required_member_is_refused(member):
    """An incomplete campaign can never reach an admission check."""
    incomplete = members()
    incomplete.pop(member)
    with pytest.raises(ValueError, match="every member"):
        CampaignDescriptor(**incomplete)
    with pytest.raises(ValueError, match="every member"):
        CampaignDescriptor(**members(**{member: None}))


def test_an_unknown_member_is_refused():
    with pytest.raises(ValueError, match="unknown"):
        CampaignDescriptor(**members(), collector_entry="extra")


@pytest.mark.parametrize(
    ("member", "value"),
    [
        ("campaign_id", "   "),
        ("campaign_id", 7),
        ("approval_kind", ""),
        ("campaign_seconds", 0),
        ("campaign_seconds", -1),
        ("campaign_seconds", 600.0),
        ("recovery_seconds", True),
        ("source_map", "not-callable"),
        ("collector", 3),
        ("budget", {}),
        ("frozen_bounds", []),
        ("abort_closure_sources", ()),
        ("abort_closure_sources", "a-single-string"),
        ("required_source_entries", ("",)),
        ("required_source_entries", (None,)),
    ],
)
def test_a_malformed_member_is_refused(member, value):
    with pytest.raises(ValueError):
        CampaignDescriptor(**members(**{member: value}))


@pytest.mark.parametrize(
    "fields",
    [
        frozenset(BASE_APPROVAL_FIELDS - {"executionHost"}),
        frozenset(CAMPAIGN_APPROVAL_FIELDS | {"invented"}),
        frozenset(),
        ("kind",),
    ],
)
def test_an_approval_schema_outside_the_declared_range_is_refused(fields):
    with pytest.raises(ValueError, match="approval_fields"):
        CampaignDescriptor(**members(approval_fields=fields))


def test_the_base_schema_does_not_bind_a_campaign_id_field():
    descriptor = CampaignDescriptor(**members(approval_fields=BASE_APPROVAL_FIELDS))
    assert descriptor.binds_campaign_id is False
    assert len(BASE_APPROVAL_FIELDS) == 16
    assert CAMPAIGN_APPROVAL_FIELDS - BASE_APPROVAL_FIELDS == {"campaignId"}


def test_a_descriptor_is_immutable():
    descriptor = CampaignDescriptor(**members())
    with pytest.raises(AttributeError):
        descriptor.campaign_id = "other"
    with pytest.raises(AttributeError):
        del descriptor.campaign_id
    with pytest.raises(AttributeError):
        descriptor.invented = 1


def test_members_returns_a_detached_mapping_for_an_explicit_variant():
    descriptor = CampaignDescriptor(**members())
    variant = CampaignDescriptor(
        **{**descriptor.members(), "campaign_id": "TEST-CAMPAIGN-02"}
    )
    assert variant.campaign_id == "TEST-CAMPAIGN-02"
    assert descriptor.campaign_id == "TEST-CAMPAIGN-01"
    descriptor.members()["campaign_id"] = "mutated"
    assert descriptor.campaign_id == "TEST-CAMPAIGN-01"
