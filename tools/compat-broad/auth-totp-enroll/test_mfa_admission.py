"""O8 admission tests for the MFA campaign: synthetic freeze, validate, refuse.

Every artifact is built locally against a temporary Ledger. No production request,
no credential, no origin outside the process, and the canonical Ledger is untouched.
"""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import time
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

import mfa_admission as admission
import mfa_descriptor as campaign
import reservations
from broad_contract import digest
from conftest_rehearsal import (
    NONCE,
    RehearsalAdmission,
    frozen_checkout,
    owner_permission,
)
from mfa_timing import VirtualClockSleeper, WallClockSleeper


def test_frozen_inputs_bind_the_plan_permission_and_source_snapshot(tmp_path):
    built = RehearsalAdmission(tmp_path)
    inputs = built.inputs
    assert inputs["kind"] == campaign.FROZEN_INPUTS_KIND
    assert inputs["plan"] == built.plan
    assert inputs["sourceCommit"] == built.commit
    assert inputs["sourceInputs"] == campaign.source_map()
    assert inputs["permission"]["kind"] == campaign.PERMISSION_KIND
    assert inputs["permission"]["authConfigBaselineDigest"] == built.baseline_digest
    assert inputs["bounds"]["timingMode"] == "virtual-clock"
    admission.validate_frozen_inputs(inputs, built.descriptor)


def test_selected_plan_permission_passes_the_o8_frozen_input_path(tmp_path):
    plan = campaign.plan_compiler(NONCE, selector="pending-age-300-v1")
    descriptor = campaign.descriptor_for_plan(plan, WallClockSleeper())
    source = frozen_checkout(tmp_path)
    commit = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
    ).strip()
    artifact = tmp_path / "selected-artifact"
    artifact.write_bytes(b"retained selected MFA artifact")
    baseline = digest({"config": "offline selected fixture"})
    permission = owner_permission(
        descriptor,
        plan,
        commit,
        hashlib.sha256(artifact.read_bytes()).hexdigest(),
        campaign.source_map(),
        baseline,
    )
    permission_path = tmp_path / "selected-permission.json"
    permission_path.write_text(json.dumps(permission))

    inputs = admission.freeze_inputs(
        permission_path,
        plan,
        source_root=source,
        artifact_path=artifact,
        descriptor_=descriptor,
    )
    admission.validate_frozen_inputs(inputs, descriptor)
    assert inputs["plan"] == plan
    assert inputs["permission"]["planDigest"] == digest(plan)
    assert inputs["permission"]["selector"] == "pending-age-300-v1"
    assert inputs["permission"]["caseCount"] == 3
    assert inputs["permission"]["ownedAccounts"] == 1
    assert inputs["permission"]["campaignSeconds"] == 1200

    mismatch = copy.deepcopy(inputs)
    mismatch["plan"] = campaign.plan_compiler(NONCE)
    mismatch["planDigest"] = digest(mismatch["plan"])
    mismatch["bounds"] = campaign.descriptor(WallClockSleeper()).frozen_bounds
    mismatch["inputsDigest"] = digest(
        {key: value for key, value in mismatch.items() if key != "inputsDigest"}
    )
    with pytest.raises(ValueError, match="typed owner permission binding differs"):
        admission.validate_frozen_inputs(mismatch)

    unknown = copy.deepcopy(inputs)
    unknown["plan"]["selector"]["name"] = "unknown"
    unknown["planDigest"] = digest(unknown["plan"])
    unknown["inputsDigest"] = digest(
        {key: value for key, value in unknown.items() if key != "inputsDigest"}
    )
    with pytest.raises(ValueError, match="unsupported MFA selector"):
        admission.validate_frozen_inputs(unknown)


def test_a_complete_o7_binding_is_admitted(tmp_path):
    built = RehearsalAdmission(tmp_path)
    admitted = admission.validate_o7_admission(built.descriptor, **built.bindings())
    assert admitted["campaignId"] == campaign.CAMPAIGN
    assert admitted["ledgerRoot"] == str(built.ledger.resolve())


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("status", "pending", "not approved"),
        ("campaignId", "FS-LIMIT-API-REQUEST-BYTES", "another campaign"),
        ("artifactProfile", "auth-totp-enroll-000000000", "artifact profile differs"),
        ("launcherSha256", "0" * 64, "approval binding differs"),
        ("ledgerRoot", "/nonexistent/ledger", "approval binding differs"),
    ],
)
def test_an_approval_that_does_not_bind_this_run_is_refused(
    tmp_path, field, value, message
):
    built = RehearsalAdmission(tmp_path)
    approval = dict(built.approval, **{field: value})
    with pytest.raises(ValueError, match=message):
        admission.validate_o7_admission(
            built.descriptor, **built.bindings(approval=approval)
        )


def test_another_campaigns_descriptor_cannot_admit_this_approval(tmp_path):
    built = RehearsalAdmission(tmp_path)
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "_other_request_bytes_descriptor",
        campaign.ROOT
        / "tools/compat-broad/fs-request-bytes-boundary/request_bytes_descriptor.py",
    )
    other = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(other)
    with pytest.raises(ValueError, match="O7 frozen approval binding required"):
        admission.validate_o7_admission(other.descriptor(), **built.bindings())


def test_the_window_must_hold_the_campaign_and_its_recovery(tmp_path):
    built = RehearsalAdmission(tmp_path)
    approval = dict(
        built.approval,
        windowExpiresAt=time.time() + built.descriptor.window_seconds - 1,
    )
    with pytest.raises(ValueError, match="window expired"):
        admission.validate_o7_admission(
            built.descriptor, **built.bindings(approval=approval)
        )


@pytest.mark.parametrize(
    ("damage", "message"),
    [
        (lambda p: p.pop("authConfigBaselineDigest"), "baseline digest required"),
        (
            lambda p: p.update(authConfigBaselineDigest="not-a-digest"),
            "baseline digest required",
        ),
        (lambda p: p.pop("baselineProvenance"), "baseline provenance required"),
        (lambda p: p.update(ownerIdentity="claude"), "ownerIdentity required"),
        (lambda p: p.update(recoveryOwner="<<fill in>>"), "recoveryOwner required"),
        (lambda p: p.pop("configurationChangeAcknowledged"), "acknowledgement"),
        (lambda p: p.update(wallSeconds=2700), "permission binding differs"),
        (lambda p: p.update(timingMode="wall-clock"), "permission binding differs"),
        (
            lambda p: p.update(credentialPrincipal={"clientId": "c"}),
            "credential principal",
        ),
        (lambda p: p.update(expiresAt=time.time() + 60), "too short"),
    ],
)
def test_a_permission_that_does_not_bind_the_campaign_is_refused(
    tmp_path, damage, message
):
    sleeper = VirtualClockSleeper()
    descriptor = campaign.rehearsal_descriptor(sleeper)
    source = frozen_checkout(tmp_path)
    commit = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
    ).strip()
    artifact = tmp_path / "artifact"
    artifact.write_bytes(b"retained")
    plan = descriptor.plan_compiler(NONCE)
    permission = owner_permission(
        descriptor,
        plan,
        commit,
        hashlib.sha256(artifact.read_bytes()).hexdigest(),
        campaign.source_map(),
        "a" * 64,
    )
    damage(permission)
    path = tmp_path / "permission.json"
    path.write_text(json.dumps(permission))
    with pytest.raises(ValueError, match=message):
        admission.freeze_inputs(
            path,
            plan,
            source_root=source,
            artifact_path=artifact,
            descriptor_=descriptor,
        )


def test_binding_drift_in_the_frozen_checkout_is_refused(tmp_path):
    built = RehearsalAdmission(tmp_path)
    admission._provenance(built.source, built.commit, built.inputs["sourceInputs"])
    target = built.source / campaign.COLLECTOR_ENTRY
    target.write_text(target.read_text() + "\n# drift\n")
    with pytest.raises(ValueError, match="clean frozen source snapshot"):
        admission._provenance(built.source, built.commit, built.inputs["sourceInputs"])
    subprocess.run(
        ["git", "-C", str(built.source), "checkout", "--", campaign.COLLECTOR_ENTRY],
        check=True,
    )
    stale = dict(built.inputs["sourceInputs"], **{campaign.COLLECTOR_ENTRY: "0" * 64})
    with pytest.raises(ValueError, match="clean frozen source snapshot"):
        admission._provenance(built.source, built.commit, stale)


def test_a_reused_nonce_a_spent_permission_or_a_held_config_lock_is_refused(tmp_path):
    built = RehearsalAdmission(tmp_path)
    admission.validate_fresh_admission(built.ledger, built.plan, built.permission)
    state_path = built.ledger / "state.json"
    state = json.loads(state_path.read_bytes())
    state["reservations"]["r1"] = {
        "state": "held",
        "claim": {"nonceDigest": digest(built.plan["nonce"]), "locks": []},
    }
    state_path.write_text(json.dumps(state))
    with pytest.raises(ValueError, match="nonce already reserved"):
        admission.validate_fresh_admission(built.ledger, built.plan, built.permission)
    state["reservations"]["r1"] = {
        "state": "held",
        "claim": {
            "nonceDigest": "0" * 64,
            "locks": [{"key": "project/fireemu-35fe6/auth/config", "mode": "READ"}],
        },
    }
    state_path.write_text(json.dumps(state))
    with pytest.raises(ValueError, match="configuration lock is held"):
        admission.validate_fresh_admission(built.ledger, built.plan, built.permission)
    state["reservations"]["r1"]["state"] = "released"
    state["envelopes"]["e1"] = {
        "envelope": {"permissionDigest": digest(built.permission)}
    }
    state_path.write_text(json.dumps(state))
    with pytest.raises(ValueError, match="permission already spent"):
        admission.validate_fresh_admission(built.ledger, built.plan, built.permission)


def test_the_hosting_check_names_every_shared_module_refusal(tmp_path):
    built = RehearsalAdmission(tmp_path)
    production = campaign.descriptor(WallClockSleeper())
    inputs = copy.deepcopy(built.inputs)
    inputs["plan"] = production.plan_compiler(NONCE)
    gate_plan = admission.gate_plan_for(inputs, built.permission, production)
    claim = admission.reservation_claim(
        inputs, gate_path=tmp_path / "gate", gate_plan=gate_plan, descriptor_=production
    )
    assert claim["durationSeconds"] == 2700
    assert claim["budget"] == campaign.ledger_budget()
    assert claim["locks"][1]["mode"] == "EXCLUSIVE"
    refusals = admission.hosting_check(claim, gate_plan)
    assert [item["refusal"] for item in refusals] == [
        "ledger-claim-refused",
        "gate-wall-cap",
        "ledger-resource-refused",
    ]
    assert refusals[0]["value"] == {"durationSeconds": 2700, "cap": 1200}
    assert refusals[1]["value"] == {"wallSeconds": 2700, "cap": 1200}
    assert refusals[2]["value"]["refusedResources"] == 11 + 11 + 1
    with pytest.raises(admission.HostingRefused, match="ledger-claim-refused"):
        admission.require_hosted(claim, gate_plan)
    # The shared Ledger itself refuses the same claim, in its own words.
    ledger = reservations.Ledger(built.ledger)
    envelope = {
        "permissionDigest": digest(built.permission),
        "issuedAt": built.permission["issuedAt"],
        "expiresAt": built.permission["expiresAt"],
        "limits": claim["budget"],
        "concurrency": 1,
        "scopes": claim["locks"],
    }
    with pytest.raises(ValueError, match="bounded duration required"):
        ledger.reserve(envelope, claim, gate_plan)
    # The rehearsal's window is the Gate's cap, so its plan is created by the shared
    # Gate itself; what remains is the Ledger's resource scope.
    rehearsal_plan = admission.gate_plan_for(
        built.inputs, built.permission, built.descriptor
    )
    rehearsal_claim = admission.reservation_claim(
        built.inputs,
        gate_path=tmp_path / "gate2",
        gate_plan=rehearsal_plan,
        descriptor_=built.descriptor,
    )
    assert [
        item["refusal"]
        for item in admission.hosting_check(rehearsal_claim, rehearsal_plan)
    ] == ["ledger-resource-refused"]
    with pytest.raises(
        ValueError,
        match="canonical Firestore resource required|Gate resource lock is not covered",
    ):
        ledger.reserve(
            {
                **envelope,
                "limits": rehearsal_claim["budget"],
                "scopes": rehearsal_claim["locks"],
            },
            rehearsal_claim,
            rehearsal_plan,
        )


def test_selected_age_300_plan_uses_supported_auth_account_scope_and_bounded_claim(
    tmp_path,
):
    import mfa_gate

    built = RehearsalAdmission(tmp_path)
    production = campaign.descriptor(WallClockSleeper())
    inputs = copy.deepcopy(built.inputs)
    inputs["plan"] = production.plan_compiler(NONCE, selector="pending-age-300-v1")
    gate_plan = admission.gate_plan_for(inputs, built.permission, production)
    claim = admission.reservation_claim(
        inputs, gate_path=tmp_path / "gate", gate_plan=gate_plan, descriptor_=production
    )

    assert gate_plan["wallSeconds"] == 1200
    assert claim["durationSeconds"] == 1200
    account_resource = gate_plan["accountResources"][0]
    assert claim["locks"][0] == {
        "key": "project/fireemu-35fe6/auth/accounts/o2-mfa-pending-age-300-" + NONCE,
        "mode": "WRITE",
    }
    assert reservations._resource_scope(account_resource) == tuple(
        claim["locks"][0]["key"].split("/")
    )
    refusals = admission.hosting_check(claim, gate_plan)
    assert refusals == []

    envelope = {
        "permissionDigest": digest(built.permission),
        "issuedAt": built.permission["issuedAt"],
        "expiresAt": built.permission["expiresAt"],
        "limits": claim["budget"],
        "concurrency": 1,
        "scopes": claim["locks"],
    }
    ledger = reservations.Ledger(built.ledger)
    ticket = ledger.reserve(envelope, claim, gate_plan)
    mfa_gate.create(Path(claim["gatePath"]), gate_plan)
    row = ledger.snapshot()["reservations"][ticket["reservation"]]
    assert row["state"] == "held"
    assert row["claim"]["locks"] == claim["locks"]


@pytest.mark.parametrize(
    "value",
    [
        "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhYmMifQ.c2lnbmF0dXJlLXNpZ25hdHVyZQ",
        "ya29.a0AfH6SMBexample",
        "AIza" + "x" * 35,
        "1//0gexampleexampleexampleexample",
        "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
        "Aa9!exampleexampleexample",
    ],
)
def test_a_receipt_with_a_secret_shaped_value_is_refused(value):
    with pytest.raises(admission.ReceiptScreenError, match="shaped like a credential"):
        admission.screen_receipt({"rows": [{"id": "x", "note": value}]})
    admission.screen_receipt({"rows": [{"id": "x", "note": "plain"}]})


def test_a_receipt_with_a_sensitive_field_name_is_refused():
    from mfa_collector import SensitiveMaterialError

    with pytest.raises(SensitiveMaterialError):
        admission.screen_receipt({"idToken": "redacted"})
    with pytest.raises(SensitiveMaterialError):
        admission.screen_receipt({"nested": {"sharedSecretKey": None}})


def _configuration(status, *, attempted=True):
    """A complete lock evidence record in one restore status."""
    verified = status in ("restored-verified", "restored-verified-normalized")
    return {
        "frozenBaselineDigest": "a" * 64,
        "preflightReadbackDigest": "a" * 64,
        "baselineReference": {
            "sha256": "a" * 64,
            "bytes": 1,
            "topLevelFields": [],
            "valuesRetained": False,
        },
        "changeAttempted": attempted,
        "appliedReadbackDigest": "b" * 64 if attempted else None,
        "applied": attempted,
        "restoreAttempts": 1 if attempted else 0,
        "restoreReadbackDigest": (
            "a" * 64 if status == "restored-verified" else "c" * 64
        )
        if verified
        else None,
        "restoreStatus": status,
        "restoreDifferingFields": []
        if status == "restored-verified"
        else (["signIn"] if verified else None),
    }


@pytest.mark.parametrize(
    ("receipt", "disposition"),
    [
        (
            {
                "stopPoint": "preflight-tokeninfo",
                "configuration": None,
                "cleanup": None,
            },
            "aborted-no-data",
        ),
        (
            {
                "stopPoint": "preflight-key-project",
                "configuration": None,
                "cleanup": None,
            },
            "aborted-no-data",
        ),
        (
            {
                "stopPoint": "preflight-key-project",
                "configuration": None,
                "cleanup": {"ownedAccounts": 8, "complete": False},
                "resumeCount": 1,
            },
            "owner-escalation",
        ),
        (
            {
                "stopPoint": "preflight-config-readback",
                "configuration": _configuration("not-attempted", attempted=False),
                "cleanup": {"ownedAccounts": 0},
            },
            "aborted-no-data",
        ),
        (
            {
                "stopPoint": "preflight-config-readback",
                "configuration": _configuration("restored-verified"),
                "cleanup": {},
            },
            "owner-escalation",
        ),
        # A resumed run can never be no-data: an earlier process owned accounts.
        (
            {
                "stopPoint": "preflight-tokeninfo",
                "configuration": None,
                "cleanup": {"ownedAccounts": 8, "complete": False},
                "resumeCount": 1,
            },
            "owner-escalation",
        ),
        (
            {
                "stopPoint": "cases",
                "configuration": _configuration("restored-verified"),
                "cleanup": {"complete": True},
                "gateComplete": True,
            },
            "abandoned-cleanup-complete",
        ),
        (
            {
                "stopPoint": "cases",
                "configuration": _configuration("restored-verified-normalized"),
                "cleanup": {"complete": True},
                "gateComplete": True,
            },
            "abandoned-cleanup-complete",
        ),
        # The walk's cleanup alone is not proof: the Gate's finish must agree.
        (
            {
                "stopPoint": "cases",
                "configuration": _configuration("restored-verified"),
                "cleanup": {"complete": True},
                "gateComplete": False,
            },
            "owner-escalation",
        ),
        # A verified status alone is not enough: the evidence has to validate.
        (
            {
                "stopPoint": "cases",
                "configuration": {
                    **_configuration("restored-verified"),
                    "restoreReadbackDigest": "d" * 64,
                },
                "cleanup": {"complete": True},
            },
            "owner-escalation",
        ),
        (
            {
                "stopPoint": "cleanup",
                "configuration": _configuration("restored-verified"),
                "cleanup": {"complete": False},
            },
            "owner-escalation",
        ),
        (
            {
                "stopPoint": "restore",
                "configuration": _configuration("restore-failed"),
                "cleanup": {"complete": True},
            },
            "owner-escalation",
        ),
    ],
)
def test_every_stop_point_has_a_named_disposition(receipt, disposition):
    assert admission.classify_stop(receipt)["disposition"] == disposition


def test_an_unknown_stop_point_is_refused():
    with pytest.raises(ValueError, match="unknown MFA stop point"):
        admission.classify_stop({"stopPoint": "somewhere"})
