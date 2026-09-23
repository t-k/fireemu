"""Integration proof of the MFA run driver against an injected transport.

Every run here is a rehearsal: an in-memory Identity Toolkit, a virtual clock, a
temporary Ledger created for the test and removed with it. Nothing reaches a network
origin, no credential exists, and no receipt produced here can be production
evidence; the driver labels them `injected-transport` and the comparator refuses them.
"""

from __future__ import annotations

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
from conftest_rehearsal import (
    ENROLLMENT_TTL_SECONDS,
    NONCE,
    RehearsalAdmission,
    owner_permission,
)
from mfa_cases import CASE_IDS, owned_accounts
from mfa_config_lock import LOCK_FILE, applied
from mfa_walk import CHECKPOINT_FILE, MATERIAL_FILE

EXPECTED_SKIPS = {"age-1800s-finalize"}


def _rows(result):
    return {row["id"]: row for row in result["rows"]}


def _selected_rehearsal(built):
    manifest = campaign.compile_campaign(NONCE, selector="pending-age-300-v1")
    bounds = campaign.frozen_bounds(
        case_count=3, account_count=1, limits=manifest["limits"]
    )
    bounds.update(timingMode="virtual-clock", rehearsal=True)
    built.descriptor = campaign._descriptor(
        built.sleeper,
        seconds=1200,
        recovery=300,
        bounds=bounds,
        timing=campaign.VIRTUAL_CLOCK,
    )
    built.plan = built.descriptor.plan_compiler(NONCE, selector="pending-age-300-v1")
    built.permission = owner_permission(
        built.descriptor,
        built.plan,
        built.commit,
        hashlib.sha256(built.artifact_path.read_bytes()).hexdigest(),
        campaign.source_map(),
        built.baseline_digest,
    )
    built.permission_path.write_text(json.dumps(built.permission))
    built.inputs = admission.freeze_inputs(
        built.permission_path,
        built.plan,
        source_root=built.source,
        artifact_path=built.artifact_path,
        descriptor_=built.descriptor,
    )
    built.manifest = {
        "kind": campaign.MANIFEST_KIND,
        "inputsDigest": built.inputs["inputsDigest"],
    }
    built.manifest_bytes = json.dumps(built.manifest).encode()
    built.manifest_path.write_bytes(built.manifest_bytes)
    built.manifest_path.chmod(0o600)
    built.approval = built._approval()
    built.approval_path.write_text(json.dumps(built.approval))
    built.approval_path.chmod(0o600)
    return built


def test_the_durable_request_budget_rejects_exhaustion_before_transport(tmp_path):
    import mfa_production

    spec = {
        "schema": "mfa-request-budget-v1",
        "inputsDigest": "a" * 64,
        "planDigest": "b" * 64,
        "permissionDigest": "c" * 64,
        "allowances": {"resume-tokeninfo": 1},
    }
    budget = mfa_production.MfaRequestBudget(tmp_path, spec, create=True)
    sent = []
    assert budget.call("resume-tokeninfo", lambda: sent.append("first")) is None
    assert sent == ["first"]

    resumed = mfa_production.MfaRequestBudget(tmp_path, spec)
    with pytest.raises(mfa_production.RequestBudgetRefused, match="exhausted"):
        resumed.call("resume-tokeninfo", lambda: sent.append("second"))
    assert sent == ["first"]


def test_a_failed_dispatch_stays_spent_after_budget_reload(tmp_path):
    import mfa_production

    spec = {
        "schema": "mfa-request-budget-v1",
        "inputsDigest": "a" * 64,
        "planDigest": "b" * 64,
        "permissionDigest": "c" * 64,
        "allowances": {"restore-fallback": 1},
    }
    budget = mfa_production.MfaRequestBudget(tmp_path, spec, create=True)
    sent = []

    def interrupted():
        sent.append("dispatch-started")
        raise TimeoutError("fixture response was lost")

    with pytest.raises(TimeoutError, match="response was lost"):
        budget.call("restore-fallback", interrupted)

    resumed = mfa_production.MfaRequestBudget(tmp_path, spec)
    with pytest.raises(mfa_production.RequestBudgetRefused, match="exhausted"):
        resumed.call("restore-fallback", lambda: sent.append("retried"))
    assert sent == ["dispatch-started"]


@pytest.mark.parametrize(
    ("boundary", "expected_charges"),
    [("before", 1), ("after", 2)],
)
def test_request_budget_recovers_from_sigkill_at_hard_link_boundaries(
    tmp_path, boundary, expected_charges
):
    """A killed immutable writer leaves only a validated, unpublished temp event."""
    import mfa_production

    spec = {
        "schema": "mfa-request-budget-v1",
        "inputsDigest": "a" * 64,
        "planDigest": "b" * 64,
        "permissionDigest": "c" * 64,
        "allowances": {"resume-tokeninfo": 3},
    }
    budget = mfa_production.MfaRequestBudget(tmp_path, spec, create=True)
    budget.call("resume-tokeninfo", lambda: None)
    marker = tmp_path / f"link-{boundary}.ready"
    module_paths = [str(path) for path in sys.path if path]
    script = "\n".join(
        [
            "import os, sys, time",
            f"sys.path[:0] = {module_paths!r}",
            "import mfa_production",
            f"output = {str(tmp_path)!r}",
            f"marker = {str(marker)!r}",
            f"boundary = {boundary!r}",
            "spec = {",
            "    'schema': 'mfa-request-budget-v1',",
            "    'inputsDigest': 'a' * 64,",
            "    'planDigest': 'b' * 64,",
            "    'permissionDigest': 'c' * 64,",
            "    'allowances': {'resume-tokeninfo': 3},",
            "}",
            "real_link = os.link",
            "def interrupted_link(source, destination, **kwargs):",
            "    if boundary == 'before':",
            "        open(marker, 'xb').close()",
            "        while True: time.sleep(1)",
            "    real_link(source, destination, **kwargs)",
            "    open(marker, 'xb').close()",
            "    while True: time.sleep(1)",
            "os.link = interrupted_link",
            "budget = mfa_production.MfaRequestBudget(__import__('pathlib').Path(output), spec)",
            "budget.call('resume-tokeninfo', lambda: None)",
            "raise AssertionError('charge unexpectedly returned before dispatch')",
        ]
    )
    child = subprocess.Popen([sys.executable, "-c", script])
    deadline = time.monotonic() + 10
    try:
        while not marker.exists() and time.monotonic() < deadline:
            if child.poll() is not None:
                pytest.fail(f"writer exited before crash boundary: {child.returncode}")
            time.sleep(0.01)
        assert marker.exists(), "writer did not reach the requested hard-link boundary"
        child.kill()
        assert child.wait(timeout=5) == -9
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)

    resumed = mfa_production.MfaRequestBudget(tmp_path, spec)
    assert resumed.used == expected_charges
    committed = sorted(
        (tmp_path / mfa_production.CALL_BUDGET_EVENTS).glob("[0-9]*.json")
    )
    assert len(committed) == expected_charges
    event_bytes = [path.read_bytes() for path in committed]
    assert [json.loads(content)["index"] for content in event_bytes] == list(
        range(expected_charges)
    )
    resumed.call("resume-tokeninfo", lambda: None)
    assert resumed.used == expected_charges + 1
    assert [path.read_bytes() for path in committed] == event_bytes
    reloaded = mfa_production.MfaRequestBudget(tmp_path, spec)
    assert reloaded.used == expected_charges + 1


def test_request_budget_discards_only_an_exact_prefix_of_next_temp_event(tmp_path):
    import mfa_production

    spec = {
        "schema": "mfa-request-budget-v1",
        "inputsDigest": "a" * 64,
        "planDigest": "b" * 64,
        "permissionDigest": "c" * 64,
        "allowances": {"resume-tokeninfo": 2},
    }
    budget = mfa_production.MfaRequestBudget(tmp_path, spec, create=True)
    budget.call("resume-tokeninfo", lambda: None)
    body = {
        "schema": "mfa-request-charge-v1",
        "index": 1,
        "specDigest": mfa_production.digest(spec),
        "category": "resume-tokeninfo",
        "previousDigest": json.loads(
            (tmp_path / mfa_production.CALL_BUDGET_EVENTS / "000000.json").read_bytes()
        )["eventDigest"],
    }
    event = {**body, "eventDigest": mfa_production.digest(body)}
    encoded = json.dumps(event, sort_keys=True, separators=(",", ":")).encode()
    assert encoded.startswith(b'{"category"')
    events = tmp_path / mfa_production.CALL_BUDGET_EVENTS
    residue = events / ".000001.json.ABCdef12"
    residue.write_bytes(encoded[:13])
    residue.chmod(0o600)

    resumed = mfa_production.MfaRequestBudget(tmp_path, spec)
    assert resumed.used == 1
    assert not residue.exists()
    resumed.call("resume-tokeninfo", lambda: None)
    assert resumed.used == 2
    assert mfa_production.MfaRequestBudget(tmp_path, spec).used == 2


def test_request_budget_refuses_malformed_temp_bytes_that_are_not_a_valid_prefix(
    tmp_path,
):
    import mfa_production

    spec = {
        "schema": "mfa-request-budget-v1",
        "inputsDigest": "a" * 64,
        "planDigest": "b" * 64,
        "permissionDigest": "c" * 64,
        "allowances": {"resume-tokeninfo": 1},
    }
    mfa_production.MfaRequestBudget(tmp_path, spec, create=True)
    events = tmp_path / mfa_production.CALL_BUDGET_EVENTS
    residue = events / ".000000.json.ABCdef12"
    residue.write_bytes(b'{"not-a-charge":')
    residue.chmod(0o600)

    with pytest.raises(mfa_production.RequestBudgetRefused):
        mfa_production.MfaRequestBudget(tmp_path, spec)
    assert residue.exists()


@pytest.mark.parametrize("name", ["unrelated", ".000001.json.bad-name"])
def test_request_budget_refuses_unknown_files_even_when_recovering_temp_events(
    tmp_path, name
):
    import mfa_production

    spec = {
        "schema": "mfa-request-budget-v1",
        "inputsDigest": "a" * 64,
        "planDigest": "b" * 64,
        "permissionDigest": "c" * 64,
        "allowances": {"resume-tokeninfo": 1},
    }
    mfa_production.MfaRequestBudget(tmp_path, spec, create=True)
    unknown = tmp_path / mfa_production.CALL_BUDGET_EVENTS / name
    unknown.write_text("{}")
    unknown.chmod(0o600)

    with pytest.raises(mfa_production.RequestBudgetRefused):
        mfa_production.MfaRequestBudget(tmp_path, spec)


@pytest.mark.parametrize("corruption", ["gap", "tamper"])
def test_request_budget_refuses_gaps_and_tampered_committed_events(
    tmp_path, corruption
):
    import mfa_production

    spec = {
        "schema": "mfa-request-budget-v1",
        "inputsDigest": "a" * 64,
        "planDigest": "b" * 64,
        "permissionDigest": "c" * 64,
        "allowances": {"resume-tokeninfo": 2},
    }
    budget = mfa_production.MfaRequestBudget(tmp_path, spec, create=True)
    budget.call("resume-tokeninfo", lambda: None)
    budget.call("resume-tokeninfo", lambda: None)
    first = tmp_path / mfa_production.CALL_BUDGET_EVENTS / "000000.json"
    if corruption == "gap":
        first.unlink()
    else:
        event = json.loads(first.read_bytes())
        event["category"] = "tampered"
        first.write_text(json.dumps(event, separators=(",", ":")))
        first.chmod(0o600)

    with pytest.raises(mfa_production.RequestBudgetRefused):
        mfa_production.MfaRequestBudget(tmp_path, spec)


def test_a_rehashed_request_budget_cannot_expand_the_manifest_allowance(tmp_path):
    import mfa_production

    spec = {
        "schema": "mfa-request-budget-v1",
        "inputsDigest": "a" * 64,
        "planDigest": "b" * 64,
        "permissionDigest": "c" * 64,
        "allowances": {"resume-tokeninfo": 1},
    }
    mfa_production.MfaRequestBudget(tmp_path, spec, create=True)
    contract_path = tmp_path / mfa_production.CALL_BUDGET_CONTRACT
    contract = json.loads(contract_path.read_bytes())
    contract["spec"]["allowances"]["resume-tokeninfo"] = 100
    contract["specDigest"] = mfa_production.digest(contract["spec"])
    mfa_production._write_private(contract_path, contract)

    with pytest.raises(ValueError, match="manifest-bound request budget"):
        mfa_production.MfaRequestBudget(tmp_path, spec)


def test_selected_run_resume_cumulatively_charges_calls_under_its_22_position_base(
    tmp_path,
):
    built = _selected_rehearsal(RehearsalAdmission(tmp_path))
    first = built.run(stop_requested=_stop_after(built, 1))
    assert first["failure"] == "StopRequested"
    assert first["resumable"] is True
    first_used = first["requestBudget"]["used"]
    assert first["requestBudget"]["baseRequests"] == 22

    second = built.run(resume=True)

    assert second["failure"] is None
    assert len(second["rows"]) == 3
    assert 22 <= second["requestBudget"]["used"] <= 23
    assert second["requestBudget"]["used"] > first_used
    assert second["requestBudget"]["allowance"] == 30
    assert second["chargedCalls"] <= 21
    assert any(
        item["id"] == "resume:oauth-tokeninfo"
        and item["budgetCategory"] == "resume-tokeninfo"
        for item in second["managementEvidence"]
    )


def test_the_selected_manifest_binds_a_22_position_base_and_finite_contingency(
    tmp_path,
):
    import mfa_gate
    import mfa_production

    manifest = campaign.compile_campaign("d" * 32, selector="pending-age-300-v1")
    built = RehearsalAdmission(tmp_path)
    plan = campaign.plan_compiler(
        "d" * 32, selector="pending-age-300-v1", timing=campaign.VIRTUAL_CLOCK
    )
    gate_plan = mfa_gate.gate_plan(
        "d" * 32,
        wall_seconds=1200,
        recovery_seconds=300,
        cost_microusd=campaign.ledger_budget()["costMicrousd"],
        selector="pending-age-300-v1",
    )
    inputs = {
        "inputsDigest": "a" * 64,
        "planDigest": campaign.digest(plan),
    }
    permission = {"selector": "pending-age-300-v1"}
    spec = mfa_production.request_budget_spec(inputs, permission, manifest, gate_plan)

    assert spec["baseRequests"] == manifest["selector"]["declaredRequests"] == 22
    assert manifest["selector"]["requestContingency"] == {
        "resumeTokeninfoRequests": 3,
        "abandonTokeninfoRequests": 1,
        "restoreFallbackRequests": 4,
    }
    assert spec["allowances"] == {
        "gate": 21,
        "project-preflight": 1,
        "resume-tokeninfo": campaign.RESUME_ALLOWANCE,
        "abandon-tokeninfo": mfa_production.ABANDON_ALLOWANCE,
        "restore-fallback": mfa_production.UNGATED_RESTORE_ATTEMPTS * 2,
    }
    assert built.descriptor.frozen_bounds["caseCount"] == len(CASE_IDS) == 33


def test_a_second_abandon_is_refused_before_credentials_or_transport(tmp_path):
    built = RehearsalAdmission(tmp_path)
    first = built.run(stop_requested=_stop_after(built, 1))
    assert first["resumable"] is True

    abandoned = built.run(abandon=True)
    assert abandoned["abandonCount"] == 1
    before = list(built.fake.log)
    with pytest.raises(ValueError, match="abandon allowance exhausted"):
        built.run(
            abandon=True, credential_reader=lambda: pytest.fail("credential read")
        )
    assert built.fake.log == before
    assert built.fake.accounts == {}
    assert not applied(built.fake.config)


@pytest.fixture(scope="module")
def completed(tmp_path_factory):
    """One full rehearsal, shared by the tests that only read its evidence.

    The shared Gate paces every slot by a quarter second in real time, so a full
    walk costs about half a minute; the read-only assertions share one.
    """
    built = RehearsalAdmission(tmp_path_factory.mktemp("completed"))
    return built, built.run()


def test_the_full_walk_completes_cleans_up_and_restores(completed):
    built, result = completed
    assert result["failure"] is None
    assert result["stopPoint"] is None
    assert [row["id"] for row in result["rows"]] == list(CASE_IDS)
    rows = _rows(result)
    assert {
        rid for rid, row in rows.items() if row["outcome"] == "skipped"
    } == EXPECTED_SKIPS
    # The refusal-direction control is refused by the fake as production did, and
    # the three sampled ages are accepted, so the age rows say what they should.
    assert rows["age-1800s-start"]["errorCode"] == "INVALID_MFA_PENDING_CREDENTIAL"
    for age in (300, 450, 600):
        assert rows[f"age-{age}s-start"]["status"] == 200
        assert rows[f"age-{age}s-same-account-fresh-control"]["status"] == 200
    assert rows["totp-enroll-session-age-300s"]["errorCode"] == "SESSION_EXPIRED"
    assert rows["totp-enroll-session-age-600s"]["errorCode"] == "INVALID_SESSION_INFO"
    assert rows["totp-signin-replay-same-code"]["errorCode"] == "INVALID_CODE"
    assert rows["totp-withdraw-unknown"]["errorCode"] == "MFA_ENROLLMENT_NOT_FOUND"
    assert rows["second-factor-limit"]["errorCode"] == "SECOND_FACTOR_EXISTS"
    # Every owned account is deleted and proven absent by UID and by email.
    cleanup = result["cleanup"]
    assert cleanup["ownedAccounts"] == len(owned_accounts()) == 11
    assert cleanup["deleted"] == cleanup["absent"] == 11
    assert cleanup["complete"] is True
    assert built.fake.accounts == {}
    # The configuration was changed inside the run and is back to the baseline.
    configuration = result["configuration"]
    assert configuration["changeAttempted"] is True and configuration["applied"] is True
    assert configuration["restoreStatus"] in (
        "restored-verified",
        "restored-verified-normalized",
    )
    assert configuration["preflightReadbackDigest"] == built.baseline_digest
    assert configuration["baselineReference"]["valuesRetained"] is False
    assert not applied(built.fake.config)
    assert result["collection"]["requests"] <= campaign.request_budget()["maxRequests"]
    assert result["requestBudget"]["used"] == result["requestsCharged"]
    assert result["requestBudget"]["baseRequests"] == 400
    assert result["executionKind"] == "injected-transport"
    assert result["productionExecuted"] is False
    assert result["timingMode"] == "virtual-clock"
    # The Gate side passes end to end: every slot admitted in order, one journaled
    # zero-wire skip (the finalize behind the refused 1800 s start), every account
    # created, deleted and read back absent, and the facade's finish accepted.
    assert result["gateComplete"] is True and result["gateRefusal"] is None
    evidence = result["accountEvidence"]
    assert evidence["createdAccounts"] == evidence["deletedAccounts"] == 11
    assert evidence["uidAbsenceReadbacks"] == 11
    assert evidence["addressAbsenceReadbacks"] == 10
    assert evidence["skips"] == 11 and evidence["complete"] is True
    assert [item["id"] for item in result["managementEvidence"]] == [
        "observation:oauth-tokeninfo",
        "preflight:auth-key-project",
        "observation:auth-config-readback",
        "observation:auth-config-apply",
        "observation:auth-config-apply-readback",
        "recovery:auth-config-restore",
        "recovery:auth-config-restore-readback",
    ]
    assert result["chargedCalls"] == 93 + 42 - 11 + 6
    # Canonical Auth account resources are deliberately not covered by the
    # rehearsal's Firestore/configuration lock scopes, so Ledger.reserve refuses
    # the claim before its Firestore-resource parser. The Gate side still runs
    # unreserved in rehearsal; production raises at the same hosting boundary.
    assert result["reservationRefusal"] == "Gate resource lock is not covered"
    assert result["ticket"] is None
    assert result["releaseEligible"] is False
    assert result["reservationReleased"] is False
    assert result["releaseRefusal"] == "Unreserved"
    assert built.ledger_row() is None
    assert [item["refusal"] for item in result["hostingRefusals"]] == [
        "ledger-resource-refused"
    ]
    assert (built.output / "receipt.json").is_file()
    assert (built.output / "release.json").is_file()
    assert (built.output / "gate-snapshot-00.json").is_file()
    receipt = json.loads((built.output / "receipt.json").read_bytes())
    admission.screen_receipt(receipt)
    assert receipt["cleanup"]["complete"] is True


def test_the_comparator_refuses_a_rehearsal_record_as_production(completed):
    built, result = completed
    record = result["comparisonRecord"]
    assert record["side"] == "rehearsal" and record["productionExecuted"] is False
    assert record["recovery"]["configurationRestored"] is True
    verdict = campaign.comparator(record, root=built.source)
    assert verdict["comparison"]["classification"] == "INDETERMINATE"
    assert "side is not production" in verdict["comparison"]["productionProblems"]
    assert verdict["formalCompatibilityClaim"] is False


def test_a_stop_mid_run_restores_the_configuration_and_a_resume_completes(tmp_path):
    built = RehearsalAdmission(tmp_path)
    stops = {"after": 0}

    def stop_requested():
        # Stop once the walk has passed the first aged rows.
        checkpoint = built.output / CHECKPOINT_FILE
        if not checkpoint.exists():
            return False
        state = json.loads(checkpoint.read_bytes())["state"]
        done = sum(step["status"] != "pending" for step in state["steps"])
        return done >= 8

    first = built.run(stop_requested=stop_requested)
    assert first["failure"] == "StopRequested"
    assert first["resumable"] is True
    assert first["stopPoint"] == "cases"
    # The accounts stay owned across the pause and so does the configuration: the
    # Gate's management phases admit the restore only after the recovery slots,
    # and the exclusive lock is what keeps the configuration safe meanwhile.
    assert first["cleanup"]["attempted"] is False
    assert len(built.fake.accounts) == first["cleanup"]["ownedAccounts"] > 0
    assert first["configuration"]["restoreStatus"] == "not-attempted"
    assert applied(built.fake.config)
    assert first["gateComplete"] is False
    assert (built.output / "receipt-00.json").is_file()
    assert (built.output / MATERIAL_FILE).stat().st_mode & 0o077 == 0
    del stops
    second = built.run(resume=True)
    assert second["failure"] is None
    assert second["resumeCount"] == 1
    assert [row["id"] for row in second["rows"]] == list(CASE_IDS)
    assert second["configuration"]["restoreAttempts"] == 1
    assert second["requestBudget"]["used"] > first["requestBudget"]["used"]
    assert any(
        item["id"] == "resume:oauth-tokeninfo"
        and item["chargedByBudget"] is True
        and item["budgetCategory"] == "resume-tokeninfo"
        for item in second["managementEvidence"]
    )
    assert second["gateComplete"] is True
    assert second["cleanup"]["complete"] is True
    assert built.fake.accounts == {}
    assert not applied(built.fake.config)
    assert (built.output / "receipt.json").is_file()
    lock = json.loads((built.output / LOCK_FILE).read_bytes())
    assert lock["restoreStatus"] in (
        "restored-verified",
        "restored-verified-normalized",
    )


def test_an_abandon_after_a_stop_deletes_every_account_and_restores(tmp_path):
    built = RehearsalAdmission(tmp_path)
    checkpoint = built.output / CHECKPOINT_FILE

    def stop_requested():
        if not checkpoint.exists():
            return False
        state = json.loads(checkpoint.read_bytes())["state"]
        return any(step["status"] != "pending" for step in state["steps"])

    first = built.run(stop_requested=stop_requested)
    assert first["resumable"] is True and built.fake.accounts
    abandoned = built.run(abandon=True)
    assert abandoned["failure"] == "StopRequested"
    assert any(
        item["id"] == "abandon:oauth-tokeninfo"
        and item["chargedByBudget"] is True
        and item["budgetCategory"] == "abandon-tokeninfo"
        for item in abandoned["managementEvidence"]
    )
    assert abandoned["resumable"] is False
    assert abandoned["stopPoint"] == "cleanup"
    assert abandoned["cleanup"]["complete"] is True
    assert abandoned["gateComplete"] is True
    assert built.fake.accounts == {}
    assert not applied(built.fake.config)
    verdict = admission.classify_stop(abandoned)
    assert verdict["disposition"] == "abandoned-cleanup-complete"


def test_recover_unsettled_is_a_classifiable_cleanup_stop():
    receipt = {
        "stopPoint": "recover-unsettled",
        "configuration": {
            "frozenBaselineDigest": "a" * 64,
            "changeAttempted": True,
            "applied": True,
            "appliedReadbackDigest": "b" * 64,
            "baselineReference": {"valuesRetained": False},
            "restoreStatus": "restored-verified",
            "preflightReadbackDigest": "a" * 64,
            "restoreReadbackDigest": "a" * 64,
            "restoreDifferingFields": [],
        },
        "cleanup": {"complete": True, "ownedAccounts": 0},
        "accountEvidence": {"createdAccounts": 0, "unsettledSignups": 0},
        "gateComplete": True,
        "untrackedIntents": [],
    }
    assert (
        admission.classify_stop(receipt)["disposition"] == "abandoned-cleanup-complete"
    )


def test_a_key_of_another_project_refuses_before_any_patch_or_signup(tmp_path):
    # Owner review a2d2db49c item 1: the public routes (signUp first of all) are
    # selected by the Web API key alone, with nothing binding it to the approved
    # project the way the admin routes are pinned by their literal path. A key
    # minted for another project must be refused by the read-only preflight
    # before it ever reaches a config PATCH or a signUp.
    built = RehearsalAdmission(tmp_path)
    built.fake.project_id = "some-other-project"
    result = built.run()
    assert result["failure"] == "ValueError"
    assert result["stopPoint"] == "preflight-key-project"
    assert result["configuration"] is None
    assert built.fake.accounts == {}
    assert not any(kind == "auth-config-patch" for kind, _ in built.fake.log)
    assert not any(path.endswith("accounts:signUp") for _, path in built.fake.log)
    assert not (built.output / LOCK_FILE).exists()
    verdict = admission.classify_stop(result)
    assert verdict["disposition"] == "aborted-no-data"
    assert verdict["retirableAsNoData"] is True


def test_configuration_drift_at_preflight_refuses_before_any_change(tmp_path):
    built = RehearsalAdmission(tmp_path)
    built.fake.config["emailPrivacyConfig"] = {"enableImprovedEmailPrivacy": False}
    result = built.run()
    assert result["failure"] == "ConfigLockError"
    assert result["stopPoint"] == "preflight-config-readback"
    assert result["configuration"]["changeAttempted"] is False
    assert result["configuration"]["preflightReadbackDigest"] != built.baseline_digest
    assert built.fake.accounts == {}
    assert (
        "auth-config-patch",
        "/admin/v2/projects/fireemu-35fe6/config",
    ) not in built.fake.log
    verdict = admission.classify_stop(result)
    assert verdict["disposition"] == "aborted-no-data"
    assert verdict["retirableAsNoData"] is True


@pytest.mark.parametrize(
    ("stage", "stop_point"),
    [
        ("apply-readback", "config-apply"),
        ("acquisition", "acquisition"),
        ("cases", "cases"),
        ("cleanup", "cleanup"),
    ],
)
def test_every_failure_path_restores_the_configuration(tmp_path, stage, stop_point):
    built = RehearsalAdmission(tmp_path)
    counters = {"signups": 0, "cases": 0, "deletes": 0}

    def fault(kind, path, count, fake):
        # The readback after the change reports an unrelated configuration.
        if (
            stage == "apply-readback"
            and kind == "auth-admin"
            and path.endswith("/config")
            and fake.log.count(("auth-config-patch", path)) == 1
            and applied(fake.config)
        ):
            fake.config["mfa"] = {"state": "DISABLED"}
        if stage == "acquisition" and path.endswith("accounts:signUp"):
            counters["signups"] += 1
            if counters["signups"] == 3:
                raise ValueError("injected signup transport failure")
        if stage == "cases" and path.endswith("mfaSignIn:finalize"):
            counters["cases"] += 1
            if counters["cases"] == 4:
                raise ValueError("injected transport failure")
        if stage == "cleanup" and path.endswith("accounts:delete"):
            counters["deletes"] += 1
            if counters["deletes"] == 2:
                raise ValueError("injected delete failure")

    result = built.run(fault=fault)
    assert result["failure"] in ("ConfigLockError", "ValueError", "CleanupIncomplete")
    assert result["stopPoint"] == stop_point
    assert result["resumable"] is False
    configuration = result["configuration"]
    assert configuration["changeAttempted"] is True
    assert configuration["restoreStatus"] in (
        "restored-verified",
        "restored-verified-normalized",
    )
    assert not applied(built.fake.config)
    if stage == "cleanup":
        assert result["cleanup"]["complete"] is False
        assert admission.classify_stop(result)["disposition"] == "owner-escalation"
    else:
        assert result["cleanup"]["complete"] is True
        assert built.fake.accounts == {}


def test_a_failed_restore_is_reported_and_never_verified(tmp_path):
    built = RehearsalAdmission(tmp_path)

    def fault(kind, path, count, fake):
        if kind == "auth-config-patch" and not applied(fake.config):
            return
        if kind == "auth-config-patch":
            raise ValueError("injected restore refusal")

    result = built.run(fault=fault)
    assert result["failure"] == "ConfigLockError"
    assert result["stopPoint"] == "restore"
    assert result["configuration"]["restoreStatus"] == "restore-failed"
    # One gated attempt and two un-gated retries, all refused by the fault.
    assert result["configuration"]["restoreAttempts"] == 3
    assert result["configurationStillApplied"] is True
    assert result["releaseEligible"] is False
    assert applied(built.fake.config)
    verdict = admission.classify_stop(result)
    assert verdict["disposition"] == "owner-escalation"
    # The abandon restores through the un-gated retry: the Gate's restore slot is
    # spent, so the retry is journaled as not charged by the Gate.
    abandoned = built.run(abandon=True)
    assert abandoned["configuration"]["restoreStatus"] in (
        "restored-verified",
        "restored-verified-normalized",
    )
    assert not applied(built.fake.config)
    assert abandoned["configurationStillApplied"] is False
    assert any(
        item["id"] == "recover:auth-config-restore" and item["chargedByGate"] is False
        for item in abandoned["managementEvidence"]
    )


def test_a_restore_that_reads_back_an_exact_baseline_is_exact(tmp_path):
    from conftest_rehearsal import BASELINE_CONFIG

    config = json.loads(json.dumps(BASELINE_CONFIG))
    config["signIn"]["phoneNumber"] = {"enabled": False, "testPhoneNumbers": {}}
    built = RehearsalAdmission(tmp_path, config=config)
    result = built.run()
    assert result["failure"] is None
    assert result["configuration"]["restoreStatus"] == "restored-verified"
    assert result["configuration"]["restoreReadbackDigest"] == built.baseline_digest


def test_the_enrollment_session_ages_are_taken_from_the_shared_clock(completed):
    _built, result = completed
    rows = _rows(result)
    assert rows["totp-enroll-session-age-450s"]["sessionAgeSeconds"] == 450.0
    assert ENROLLMENT_TTL_SECONDS < 450 < 2 * ENROLLMENT_TTL_SECONDS
    assert rows["totp-enroll-session-age-450s"]["errorCode"] == "SESSION_EXPIRED"


def test_the_receipt_and_the_run_directory_carry_no_secret_shaped_value(completed):
    built, result = completed
    receipt = json.loads((built.output / "receipt.json").read_bytes())
    admission.screen_receipt(receipt)
    record = json.loads(max(built.output.glob("production-record-*.json")).read_bytes())
    admission.screen_receipt({"rows": record["rows"], "recovery": record["recovery"]})
    # The private material file does hold secrets, by design, and is mode 0600.
    assert (built.output / MATERIAL_FILE).stat().st_mode & 0o077 == 0
    del result


# --- review follow-ups: honest receipts on every resume and abandon path -----------


def _stop_after(built, done_cases):
    checkpoint = built.output / CHECKPOINT_FILE

    def stop_requested():
        if not checkpoint.exists():
            return False
        state = json.loads(checkpoint.read_bytes())["state"]
        return sum(step["status"] != "pending" for step in state["steps"]) >= done_cases

    return stop_requested


@pytest.mark.parametrize("outage", ["oauth-tokeninfo", "lock-record", "api-key-swap"])
def test_a_resume_that_fails_before_acting_still_owns_the_earlier_accounts(
    tmp_path, outage
):
    built = RehearsalAdmission(tmp_path)
    first = built.run(stop_requested=_stop_after(built, 4))
    assert first["resumable"] is True
    live = len(built.fake.accounts)
    assert live == first["cleanup"]["ownedAccounts"] > 0
    if outage == "lock-record":
        # The lock record an earlier process wrote is unreadable: no request may
        # be made on its behalf, and the receipt still says what is owned.
        (built.output / LOCK_FILE).write_text("{}")

    def fault(kind, path, count, fake):
        if outage == "oauth-tokeninfo" and kind == "oauth-tokeninfo":
            raise ValueError("injected tokeninfo outage")

    credential_reader = None
    if outage == "api-key-swap":
        # A resume handed a different physical key than the one the fresh run
        # bound (owner review a2d2db49c item 1): refused by digest before any
        # network call, let alone a signUp or a configuration patch.
        def credential_reader():
            return {"token": "offline-fixture-token", "apiKey": "swapped-key"}

    before_log = len(built.fake.log)
    second = built.run(resume=True, fault=fault, credential_reader=credential_reader)
    assert second["failure"] in ("ValueError", "ConfigLockError")
    assert second["resumable"] is False
    cleanup = second["cleanup"]
    assert cleanup["ownedAccounts"] == live
    assert cleanup["attempted"] is False and cleanup["complete"] is False
    assert len(built.fake.accounts) == live
    verdict = admission.classify_stop(second)
    assert verdict["disposition"] == "owner-escalation"
    assert verdict["retirableAsNoData"] is False
    assert second["resumeCount"] == 1
    if outage == "api-key-swap":
        assert second["stopPoint"] == "preflight-key-project"
        # The digest check is purely local: not one extra wire call was made.
        assert len(built.fake.log) == before_log


def test_an_abandon_does_not_consult_the_reservation_deadline_but_a_resume_does(
    tmp_path,
):
    built = RehearsalAdmission(tmp_path)
    first = built.run(stop_requested=_stop_after(built, 4))
    assert first["resumable"] is True
    # A ticket the temporary Ledger does not know stands in for a reservation whose
    # deadline has passed: `Ledger.validate` refuses it, so a resume is refused
    # before anything is read, while an abandon never asks.
    run_state = json.loads((built.output / "run-state.json").read_bytes())
    run_state["ticket"] = {
        "ledgerPath": str(built.ledger.resolve()),
        "ledgerIdentity": "0" * 64,
        "reservation": "0" * 64,
        "claimDigest": "0" * 64,
        "envelopeDigest": "0" * 64,
    }
    (built.output / "run-state.json").write_text(json.dumps(run_state))
    with pytest.raises(ValueError, match="exact shared reservation ticket required"):
        built.run(resume=True)
    assert built.fake.accounts
    abandoned = built.run(abandon=True)
    assert abandoned["failure"] == "StopRequested"
    assert abandoned["cleanup"]["complete"] is True
    assert built.fake.accounts == {}
    assert abandoned["configuration"]["restoreStatus"] in (
        "restored-verified",
        "restored-verified-normalized",
    )
    assert not applied(built.fake.config)
    assert abandoned["abandonCount"] == 1
    assert (
        admission.classify_stop(abandoned)["disposition"]
        == "abandoned-cleanup-complete"
    )


def test_remaining_seconds_covers_the_critical_path_left_and_the_recovery_reserve():
    from mfa_production import remaining_seconds

    manifest = {"limits": {"criticalPathSeconds": 1830}}
    fresh = {"pendingDueAt": []}
    assert (
        remaining_seconds(fresh, 0.0, manifest=manifest, recovery=300) == 1830 + 300 + 1
    )
    paused = {"pendingDueAt": [1000.0, 1500.0]}
    assert (
        remaining_seconds(paused, 1000.0, manifest=manifest, recovery=300)
        == 500 + 30 + 300 + 1
    )
    late = {"pendingDueAt": [1000.0]}
    assert (
        remaining_seconds(late, 5000.0, manifest=manifest, recovery=300) == 30 + 300 + 1
    )


def _dead_during_apply(tmp_path, *, after_readback):
    """The on-disk state of a process that died during the configuration change."""
    import mfa_gate
    import mfa_production
    from conftest_rehearsal import FakeSession
    from mfa_config_lock import ConfigLock

    built = RehearsalAdmission(tmp_path)
    inputs, permission = built.inputs, built.permission
    gate_plan = admission.gate_plan_for(inputs, permission, built.descriptor)
    generation = admission.abort_generation(inputs, built.descriptor)
    gate_plan.update(
        permissionDigest=admission.digest(permission),
        collectorSourceDigest=generation["collectorSourceDigest"],
    )
    output = built.output
    output.mkdir(mode=0o700)
    budget_spec = mfa_production.request_budget_spec(
        inputs, permission, campaign.execution_plan(inputs["plan"]), gate_plan
    )
    budget = mfa_production.MfaRequestBudget(output, budget_spec, create=True)
    mfa_production._write_immutable(output / "inputs.json", inputs)
    mfa_production._write_private(
        output / "run-state.json",
        {
            "inputsDigest": inputs["inputsDigest"],
            "ticket": None,
            "reservationRefusal": "canonical Firestore resource required",
            "claimDigest": "0" * 64,
            "gatePlanDigest": admission.digest(gate_plan),
            "resumeCount": 0,
            "receipts": [],
            # A real process binds this at its key-project preflight, before it
            # can ever reach the configuration apply this fixture starts from.
            "apiKeyDigest": hashlib.sha256(
                built.credentials()["apiKey"].encode()
            ).hexdigest(),
        },
    )
    mfa_gate.create(output / "gate", gate_plan)
    gate = mfa_gate.MfaGate(output / "gate")
    gate.claim()
    session = mfa_production.GateSession(FakeSession(built.fake), gate, budget)
    session.tokeninfo(
        lambda body: {
            "kind": "request-byte-token-attestation-v1",
            "principalDigest": "a" * 64,
            "requiredScopeVerified": True,
            "identityMode": "subject",
            "identityVerified": True,
            "oauthClientVerified": True,
            "expiresInSeconds": 3599,
            "remainingSecondsAtVerification": 3599.0,
            "requiredSeconds": 240.0,
            "complete": True,
            "workerReaped": True,
        }
    )
    lock = ConfigLock(
        output,
        read=session.read_config,
        patch=session.patch_config,
        frozen_baseline_digest=permission["authConfigBaselineDigest"],
    )
    lock.preflight()
    if after_readback:
        lock.apply()
    else:
        lock.record["changeAttempted"] = True
        lock.save()
        session.patch_config(
            __import__("mfa_config_lock").campaign_patch(),
            "mfa,signIn.phoneNumber,smsRegionConfig",
        )
    assert applied(built.fake.config)
    assert not (output / CHECKPOINT_FILE).exists()
    return built


def test_an_abandon_after_a_death_between_apply_and_readback_restores_and_receipts(
    tmp_path,
):
    built = _dead_during_apply(tmp_path, after_readback=True)
    result = built.run(abandon=True)
    assert result["failure"] == "StopRequested"
    assert result["stopPoint"] == "cleanup"
    assert result["cleanup"] == {
        "ownedAccounts": 0,
        "deleted": 0,
        "absent": 0,
        "complete": True,
        "attempted": True,
    }
    assert result["configuration"]["restoreStatus"] in (
        "restored-verified",
        "restored-verified-normalized",
    )
    assert not applied(built.fake.config)
    assert (built.output / "receipt.json").is_file()


def test_an_abandon_after_a_death_before_the_apply_readback_restores_ungated(tmp_path):
    built = _dead_during_apply(tmp_path, after_readback=False)
    result = built.run(abandon=True)
    # The Gate admits its management slots once and in order: the apply readback
    # was never taken, so the restore slot behind it cannot be charged. The
    # un-gated retry restores anyway, journaled as such, and the receipt says so.
    assert result["failure"] == "StopRequested"
    assert result["configuration"]["restoreStatus"] in (
        "restored-verified",
        "restored-verified-normalized",
    )
    assert not applied(built.fake.config)
    assert (built.output / "receipt.json").is_file()
    assert any(
        item["id"] == "recover:auth-config-restore" and item["chargedByGate"] is False
        for item in result["managementEvidence"]
    )
    assert (
        admission.classify_stop(result)["disposition"] == "abandoned-cleanup-complete"
    )


def test_production_execution_refuses_a_virtual_clock_directly(tmp_path):
    from mfa_production import execute

    built = RehearsalAdmission(tmp_path)
    with pytest.raises(ValueError, match="wall-clock timing"):
        execute(
            capability=built.capability(),
            inputs=built.inputs,
            permission=built.permission,
            credential_reader=built.credentials,
            ledger_root=built.ledger,
            output=built.output,
            sleeper=built.sleeper,
            descriptor_=built.descriptor,
            source_root=built.source,
            session_factory=None,
        )


def test_a_stop_requested_during_a_wait_is_honoured_before_the_next_case(tmp_path):
    built = RehearsalAdmission(tmp_path)
    # Ask to stop as soon as the baseline row is recorded: the next step is a wait
    # for the 300 s rows, and the wait's tick is where the stop is honoured.
    first = built.run(stop_requested=_stop_after(built, 1))
    assert first["resumable"] is True
    state = json.loads((built.output / CHECKPOINT_FILE).read_bytes())["state"]
    steps = {step["id"]: step for step in state["steps"]}
    assert steps["baseline-fresh-finalize"]["status"] == "done"
    assert steps["age-300s-start"]["status"] == "pending"
    assert steps["age-300s-start"]["dueAt"] is not None
    second = built.run(resume=True)
    assert second["failure"] is None and second["gateComplete"] is True


def test_rows_carry_the_observed_age_anchored_to_each_resource(completed):
    _built, result = completed
    rows = _rows(result)
    for age in (300, 450, 600, 1800):
        row = rows[f"age-{age}s-start"]
        assert row["pendingAgeSeconds"] == float(age)
        # Under the virtual clock nothing elapses between acquisitions, so the
        # observed age is exactly the target plus the sampling margin.
        assert row["observedAgeSeconds"] == float(age) + 1.0
        assert (
            rows[f"age-{age}s-same-account-fresh-control"]["observedAgeSeconds"] == 0.0
        )
    for age in (300, 450, 600):
        row = rows[f"totp-enroll-session-age-{age}s"]
        assert row["sessionAgeSeconds"] == float(age)
        assert row["observedAgeSeconds"] == float(age) + 1.0


def _process_dies_when(monkeypatch, dead):
    """After `dead["now"]` is set, the process sends nothing more: no slot is
    consumed, no management slot is charged, exactly as a killed process leaves
    the Gate. The inner session is failed too so the un-gated retries do nothing."""
    import mfa_production

    original_dispatch = mfa_production.GateSession._dispatch
    original_management = mfa_production.GateSession._management

    def dispatch(self, path, body, *, owner):
        if dead["now"]:
            raise ValueError("the process is dead: nothing more is sent")
        return original_dispatch(self, path, body, owner=owner)

    def management(self, expected, call):
        if dead["now"]:
            raise ValueError("the process is dead: nothing more is sent")
        return original_management(self, expected, call)

    monkeypatch.setattr(mfa_production.GateSession, "_dispatch", dispatch)
    monkeypatch.setattr(mfa_production.GateSession, "_management", management)

    def fault(kind, path, count, fake):
        if dead["now"]:
            raise ValueError("the process is dead: nothing more is sent")

    return fault


# --- re-review: cross-process adoption, un-gated restore, lost signups ------------


def _elsewhere(monkeypatch):
    """Make every Gate check see another process, whose predecessor is gone."""
    import os

    import mfa_gate

    real = os.getpid()
    monkeypatch.setattr(os, "getpid", lambda: real + 100_000)
    monkeypatch.setattr(mfa_gate, "_process_alive", lambda pid: pid != real)


@pytest.mark.parametrize("mode", ["resume", "abandon"])
def test_a_new_process_adopts_the_gate_and_finishes_or_abandons(
    tmp_path, monkeypatch, mode
):
    built = RehearsalAdmission(tmp_path)
    first = built.run(stop_requested=_stop_after(built, 4))
    assert first["resumable"] is True and built.fake.accounts
    _elsewhere(monkeypatch)
    result = built.run(resume=mode == "resume", abandon=mode == "abandon")
    assert (
        result["adoptions"]
        and result["adoptions"][0]["to"] != result["adoptions"][0]["from"][0]
    )
    assert result["cleanup"]["complete"] is True
    assert built.fake.accounts == {}
    assert result["configuration"]["restoreStatus"] in (
        "restored-verified",
        "restored-verified-normalized",
    )
    assert not applied(built.fake.config)
    assert result["gateComplete"] is True
    if mode == "resume":
        assert result["failure"] is None
        assert [row["id"] for row in result["rows"]] == list(CASE_IDS)


def test_adoption_is_refused_before_any_credential_while_the_owner_is_alive(
    tmp_path, monkeypatch
):
    import os

    from mfa_production import GateAdoptionRefused

    built = RehearsalAdmission(tmp_path)
    first = built.run(stop_requested=_stop_after(built, 4))
    assert first["resumable"] is True
    real = os.getpid()
    monkeypatch.setattr(os, "getpid", lambda: real + 100_000)
    # The recorded process is this one and it is alive.

    def never():
        raise AssertionError("the credential must not be read")

    with pytest.raises(GateAdoptionRefused, match="still alive"):
        built.run(resume=True, credential_reader=never)
    assert built.fake.accounts


def test_a_lost_signup_answer_is_held_when_email_only_readback_finds_presence(tmp_path):
    built = RehearsalAdmission(tmp_path)
    counters = {"signups": 0}

    def after(kind, path, count, fake, status, body):
        if path.endswith("accounts:signUp"):
            counters["signups"] += 1
            if counters["signups"] == 3:
                raise ValueError("answer lost after the service applied it")

    result = built.run(after=after)
    assert result["failure"] == "ValueError"
    assert result["stopPoint"] == "acquisition"
    # The third signup created an account this process never saw. Email-only
    # readback identifies presence but cannot prove ownership, so it remains held.
    assert result["cleanup"]["ownedAccounts"] == 2
    assert result["cleanup"]["complete"] is True
    assert len(built.fake.accounts) == 1
    assert result["accountEvidence"]["createdAccounts"] == 2
    assert result["accountEvidence"]["unsettledSignups"] == 1
    assert result["accountEvidence"]["complete"] is False
    assert result["unprovenIntents"] == ["pending-age-450"]
    assert result["gateComplete"] is False
    assert result["untrackedIntents"] == []


def test_a_lost_signup_in_a_dead_process_stays_held_on_abandon(tmp_path, monkeypatch):
    built = RehearsalAdmission(tmp_path)
    counters = {"signups": 0}
    dead = {"now": False}

    def after(kind, path, count, fake, status, body):
        if path.endswith("accounts:signUp"):
            counters["signups"] += 1
            if counters["signups"] == 3:
                dead["now"] = True
                raise ValueError("answer lost, then the process dies")

    fault = _process_dies_when(monkeypatch, dead)
    first = built.run(fault=fault, after=after)
    assert first["cleanup"]["complete"] is False
    assert first["configuration"]["restoreStatus"] == "restore-failed"
    assert len(built.fake.accounts) == 3
    dead["now"] = False
    recovered = built.run(abandon=True)
    assert recovered["cleanup"]["ownedAccounts"] == 2
    assert recovered["cleanup"]["complete"] is True
    assert len(built.fake.accounts) == 1
    assert recovered["accountEvidence"]["unsettledSignups"] == 1
    assert recovered["accountEvidence"]["complete"] is False
    assert recovered["unprovenIntents"] == ["pending-age-450"]
    assert recovered["configuration"]["restoreStatus"] in (
        "restored-verified",
        "restored-verified-normalized",
    )
    assert not applied(built.fake.config)
    assert admission.classify_stop(recovered)["disposition"] == "owner-escalation"


def test_an_anonymous_signup_whose_answer_was_lost_is_reported_untracked(tmp_path):
    built = RehearsalAdmission(tmp_path)

    def after(kind, path, count, fake, status, body):
        if (
            path.endswith("accounts:signUp")
            and body.get("localId")
            and "email" not in body
        ):
            raise ValueError("anonymous answer lost")

    result = built.run(after=after)
    assert result["untrackedIntents"] == ["interaction-anonymous"]
    assert result["failure"] in ("ValueError", "UntrackedAccount")
    assert result["gateComplete"] is False
    # The anonymous account is the one residue the cleanup contract cannot find.
    assert len(built.fake.accounts) == 1
    assert admission.classify_stop(result)["disposition"] == "owner-escalation"


def test_email_only_unknown_signup_is_reported_unproven_and_not_adopted():
    import mfa_production

    class Walk:
        def _email(self, role):
            return f"o2-mfa-{role}-nonce@example.com"

        def adopt_account(self, role, uid):
            raise AssertionError("email-only presence must not be adopted")

        def settle_intent(self, role):
            raise AssertionError("email-only presence must not be settled absent")

    class Gate:
        def unsettled_accounts(self):
            return ["pending-control"]

        def settle_reconciled_creation(self, role):
            return {
                "role": role,
                "uid": "foreign-uid",
                "adopted": False,
                "held": True,
            }

    class Session:
        def admin(self, path, body):
            assert path.endswith("accounts:lookup")
            return 200, {"users": [{"email": "same", "localId": "foreign-uid"}]}

    result = mfa_production.discover_unsettled(Walk(), Gate(), Session(), [])
    assert result == {"untracked": [], "unproven": ["pending-control"]}


def test_a_death_between_the_gate_journal_and_the_walk_ack_is_reconciled(
    tmp_path, monkeypatch
):
    """The Gate journals a creation the instant the answer arrives; the walk a moment later."""
    import mfa_walk

    built = RehearsalAdmission(tmp_path)
    counters = {"signups": 0}
    original = mfa_walk.register_owned

    def dying_register(state, kind, identifier, now):
        counters["signups"] += 1
        if counters["signups"] == 3:
            raise RuntimeError("process dies before the walk owns the account")
        return original(state, kind, identifier, now)

    monkeypatch.setattr(mfa_walk, "register_owned", dying_register)
    first = built.run()
    monkeypatch.setattr(mfa_walk, "register_owned", original)
    # In-process the terminal path already reconciles: three accounts, all gone.
    assert first["accountEvidence"]["createdAccounts"] == 3
    assert (
        first["cleanup"]["ownedAccounts"] == 3 and first["cleanup"]["complete"] is True
    )
    assert first["gateComplete"] is True
    assert built.fake.accounts == {}


def test_a_dead_process_with_the_gate_ahead_of_the_walk_is_recovered_by_abandon(
    tmp_path, monkeypatch
):
    import mfa_walk

    built = RehearsalAdmission(tmp_path)
    counters = {"signups": 0}
    original = mfa_walk.register_owned
    dead = {"now": False}

    def dying_register(state, kind, identifier, now):
        counters["signups"] += 1
        if counters["signups"] == 3:
            dead["now"] = True
            raise RuntimeError("process dies before the walk owns the account")
        return original(state, kind, identifier, now)

    fault = _process_dies_when(monkeypatch, dead)
    monkeypatch.setattr(mfa_walk, "register_owned", dying_register)
    first = built.run(fault=fault)
    monkeypatch.setattr(mfa_walk, "register_owned", original)
    assert first["cleanup"]["complete"] is False and len(built.fake.accounts) == 3
    dead["now"] = False
    recovered = built.run(abandon=True)
    assert recovered["accountEvidence"]["createdAccounts"] == 3
    assert recovered["cleanup"]["ownedAccounts"] == 3
    assert recovered["cleanup"]["complete"] is True
    assert recovered["gateComplete"] is True
    assert built.fake.accounts == {}
    assert (
        admission.classify_stop(recovered)["disposition"]
        == "abandoned-cleanup-complete"
    )


def test_a_dead_process_with_a_request_in_flight_is_adopted_and_settled(
    tmp_path, monkeypatch
):
    """SIGKILL during a send leaves the Gate's in-flight marker; the answer is unknowable."""
    import os

    import mfa_gate

    built = RehearsalAdmission(tmp_path)
    first = built.run(stop_requested=_stop_after(built, 4))
    assert first["resumable"] is True
    # Leave the next observation slot in flight, as a killed process would.
    gate = mfa_gate.MfaGate(built.output / "gate")
    with gate.locked() as state:
        job = state["jobs"][mfa_gate.JOB]
        index = job["observation"]
        state["events"].append(
            {
                "job": mfa_gate.JOB,
                "phase": "observation",
                "index": index,
                "started": state["lastSent"],
                "requestDigest": "0" * 64,
                "service": "auth",
                "method": "POST",
                "completed": False,
            }
        )
        job["observation"] += 1
        job["scheduleDone"] += 1
        job["inflight"] = True
        mfa_gate._save(gate.path, state)
    # While the recorded process lives, adoption is refused.
    with pytest.raises(ValueError, match="in flight"):
        mfa_gate.MfaGate(built.output / "gate").adopt()
    real = os.getpid()
    monkeypatch.setattr(os, "getpid", lambda: real + 100_000)
    monkeypatch.setattr(mfa_gate, "_process_alive", lambda pid: pid != real)
    recovered = built.run(abandon=True)
    assert recovered["adoptions"][-1]["settledInflight"]
    assert recovered["cleanup"]["complete"] is True
    assert built.fake.accounts == {}
    assert not applied(built.fake.config)
