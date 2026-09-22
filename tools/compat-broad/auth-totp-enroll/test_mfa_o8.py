"""The launcher refuses before it reads a credential, and names why."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
for entry in (
    ROOT / "tools/compat-broad",
    ROOT / "tools/compat-broad/production-admission",
    ROOT / "tools/compat-broad/o8-core",
    HERE,
):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

import mfa_o8
from conftest_rehearsal import (
    NONCE,
    RehearsalAdmission,
    owner_permission,
)


def _argv(built, tmp_path, *extra):
    inputs_path = tmp_path / "inputs.json"
    inputs_path.write_text(json.dumps(built.inputs))
    handoff = tmp_path / "handoff.json"
    handoff.write_text(
        json.dumps(
            {
                "kind": mfa_o8.HANDOFF_KIND,
                "permissionDigest": "0" * 64,
                "token": "offline-fixture-token",
                "apiKey": "offline-fixture-key",
            }
        )
    )
    handoff.chmod(0o600)
    return [
        "--inputs",
        str(inputs_path),
        "--approval",
        str(built.approval_path),
        "--manifest",
        str(built.manifest_path),
        "--permission",
        str(built.permission_path),
        "--source",
        str(built.source),
        "--artifact",
        str(built.artifact_path),
        "--ledger",
        str(built.ledger),
        "--output",
        str(tmp_path / "output"),
        "--credential-file",
        str(handoff),
        *extra,
    ]


def _selected_production(built):
    import hashlib
    import mfa_admission as admission
    import mfa_descriptor as campaign
    from mfa_timing import WallClockSleeper

    plan = campaign.plan_compiler(NONCE, selector="pending-age-300-v1")
    descriptor = campaign.descriptor_for_plan(plan, WallClockSleeper())
    permission = owner_permission(
        descriptor,
        plan,
        built.commit,
        hashlib.sha256(built.artifact_path.read_bytes()).hexdigest(),
        campaign.source_map(),
        built.baseline_digest,
    )
    built.descriptor = descriptor
    built.plan = plan
    built.permission = permission
    built.permission_path.write_text(json.dumps(permission))
    built.inputs = admission.freeze_inputs(
        built.permission_path,
        plan,
        source_root=built.source,
        artifact_path=built.artifact_path,
        descriptor_=descriptor,
    )
    built.manifest = {
        "kind": campaign.MANIFEST_KIND,
        "inputsDigest": built.inputs["inputsDigest"],
    }
    built.manifest_bytes = json.dumps(built.manifest).encode()
    built.manifest_path.write_bytes(built.manifest_bytes)
    built.approval = built._approval()
    built.approval_path.write_text(json.dumps(built.approval))
    return built


def test_selected_fixture_passes_hosting_then_stops_at_guarded_credential_handoff(
    tmp_path, monkeypatch, capsys
):
    import mfa_descriptor as campaign
    from mfa_timing import WallClockSleeper

    built = _selected_production(RehearsalAdmission(tmp_path))
    assert campaign.descriptor(WallClockSleeper()).campaign_seconds == 2700
    assert built.descriptor.campaign_seconds == 1200
    assert built.descriptor.recovery_seconds == 300

    reached_handoff = []

    def stop_at_handoff(_args):
        reached_handoff.append(True)
        raise RuntimeError("offline fixture stops at credential handoff")

    monkeypatch.setattr(mfa_o8, "_read_handoff", stop_at_handoff)
    assert mfa_o8.main(_argv(built, tmp_path)) == 1
    assert reached_handoff == [True]
    assert "stop point schedule-not-started" in capsys.readouterr().err
    assert json.loads((built.ledger / "state.json").read_bytes())["reservations"]


def test_rehearsal_inputs_are_refused_for_production_before_any_credential(
    tmp_path, monkeypatch, capsys
):
    built = RehearsalAdmission(tmp_path)

    def never(_args):
        raise AssertionError("the credential handoff must not be read")

    monkeypatch.setattr(mfa_o8, "_read_handoff", never)
    assert mfa_o8.main(_argv(built, tmp_path)) == 2
    assert "refused (ValueError)" in capsys.readouterr().err
    assert not (tmp_path / "output").exists()
    assert json.loads((built.ledger / "state.json").read_bytes())["reservations"] == {}


def test_a_production_plan_is_refused_by_the_hosting_check_before_any_credential(
    tmp_path, monkeypatch, capsys
):
    import mfa_descriptor as campaign
    from mfa_timing import WallClockSleeper

    built = RehearsalAdmission(tmp_path)
    production = campaign.descriptor(WallClockSleeper())
    # Rebuild the frozen record around the production descriptor so every check
    # before the hosting check passes; the launcher then stops at hosting.
    import hashlib

    import mfa_admission as admission
    from conftest_rehearsal import NONCE, owner_permission

    plan = production.plan_compiler(NONCE)
    permission = owner_permission(
        production,
        plan,
        built.commit,
        hashlib.sha256(built.artifact_path.read_bytes()).hexdigest(),
        campaign.source_map(),
        built.baseline_digest,
    )
    permission["expiresAt"] = permission["issuedAt"] + 7200
    built.permission = permission
    built.permission_path.write_text(json.dumps(permission))
    built.inputs = admission.freeze_inputs(
        built.permission_path,
        plan,
        source_root=built.source,
        artifact_path=built.artifact_path,
        descriptor_=production,
    )
    built.plan = plan
    built.descriptor = production
    built.manifest = {
        "kind": campaign.MANIFEST_KIND,
        "inputsDigest": built.inputs["inputsDigest"],
    }
    built.manifest_bytes = json.dumps(built.manifest).encode()
    built.manifest_path.write_bytes(built.manifest_bytes)
    built.approval = built._approval()
    built.approval_path.write_text(json.dumps(built.approval))

    def never(_args):
        raise AssertionError("the credential handoff must not be read")

    monkeypatch.setattr(mfa_o8, "_read_handoff", never)
    assert mfa_o8.main(_argv(built, tmp_path)) == 2
    assert "refused (HostingRefused)" in capsys.readouterr().err
    assert not (tmp_path / "output").exists()
    assert json.loads((built.ledger / "state.json").read_bytes())["reservations"] == {}


@pytest.mark.parametrize(
    "field", ["status", "campaignId", "launcherSha256", "manifestSha256"]
)
def test_an_incomplete_approval_is_refused_before_anything_else(
    tmp_path, monkeypatch, field
):
    built = RehearsalAdmission(tmp_path)
    approval = dict(built.approval)
    approval[field] = "damaged"
    built.approval_path.write_text(json.dumps(approval))

    def never(_args):
        raise AssertionError("the credential handoff must not be read")

    monkeypatch.setattr(mfa_o8, "_read_handoff", never)
    assert mfa_o8.main(_argv(built, tmp_path)) == 2


def test_the_handoff_must_carry_both_secrets_bound_to_the_permission():
    permission = {"kind": "x"}
    from broad_contract import digest

    good = {
        "kind": mfa_o8.HANDOFF_KIND,
        "permissionDigest": digest(permission),
        "token": "t" * 8,
        "apiKey": "k" * 8,
    }
    assert mfa_o8.validate_handoff(good, permission) == {
        "token": "t" * 8,
        "apiKey": "k" * 8,
    }
    for damage in (
        lambda h: h.pop("apiKey"),
        lambda h: h.update(permissionDigest="0" * 64),
        lambda h: h.update(token=""),
        lambda h: h.update(kind="request-bytes-bearer-token-v1"),
    ):
        value = dict(good)
        damage(value)
        with pytest.raises(ValueError, match="credential handoff"):
            mfa_o8.validate_handoff(value, permission)
