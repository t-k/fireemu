"""Immutable account identity is independent of the display name under test."""

import importlib.util
from pathlib import Path

import pytest


def contract():
    path = Path(__file__).with_name("display_name_contract.py")
    assert path.exists(), "Display-name contract is required"
    spec = importlib.util.spec_from_file_location("display_name_contract", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_bootstrap_needs_marker_but_verified_uid_survives_name_changes():
    c = contract()
    original = {"localId": "owned", "email": "email", "displayName": "marker"}
    assert c.owned([original], "email", "marker") == "owned"
    for name in [c.FIRST, c.SECOND, "", None]:
        changed = {**original, "displayName": name}
        assert c.owned([changed], "email", "marker", "owned") == "owned"
        with pytest.raises(ValueError):
            c.owned([changed], "email", "marker")
    assert (
        c.owned([{"localId": "owned", "email": "email"}], "email", "marker", "owned")
        == "owned"
    )


def test_reused_email_and_wrong_identity_never_become_owned():
    c = contract()
    for row in [
        {"localId": "replacement", "email": "email", "displayName": "marker"},
        {"localId": "owned", "email": "other", "displayName": "marker"},
    ]:
        with pytest.raises(ValueError):
            c.owned([row], "email", "marker", "owned")
    for uid in ["", True, 1]:
        with pytest.raises(ValueError):
            c.owned([{"localId": uid, "email": "email"}], "email", "marker", uid)


def test_display_name_partition_does_not_publish_arbitrary_names():
    c = contract()
    for value, expected in [
        ({}, "absent"),
        ({"displayName": None}, "null"),
        ({"displayName": ""}, "empty"),
        ({"displayName": "marker"}, "initial"),
        ({"displayName": c.FIRST}, "first"),
        ({"displayName": c.SECOND}, "second"),
        ({"displayName": "SECRET"}, "other"),
        ({"displayName": True}, "invalid-type"),
    ]:
        state = c.display_name(value, "marker")
        assert state == expected
        assert "SECRET" not in state


def test_name_mismatch_stays_visible_and_cannot_be_forged_as_pass():
    c = contract()
    for state in c.NAME_STATES:
        row = c.name_row("set-name-lookup", 200, state, True)
        c.validate_case(row, "set-name-lookup")
        assert row["passed"] is (state == "first")
        with pytest.raises(ValueError):
            c.validate_case({**row, "passed": not row["passed"]}, "set-name-lookup")
        with pytest.raises(ValueError):
            c.validate_case({**row, "displayName": "SECRET"}, "set-name-lookup")
    assert not c.name_row("deleted-name-lookup", 200, "empty", True)["passed"]
