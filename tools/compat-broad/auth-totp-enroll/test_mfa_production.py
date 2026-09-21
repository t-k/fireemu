"""Integration proof of the MFA run driver against an injected transport.

Every run here is a rehearsal: an in-memory Identity Toolkit, a virtual clock, a
temporary Ledger created for the test and removed with it. Nothing reaches a network
origin, no credential exists, and no receipt produced here can be production
evidence; the driver labels them `injected-transport` and the comparator refuses them.
"""

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

import mfa_admission as admission
import mfa_descriptor as campaign
from conftest_rehearsal import ENROLLMENT_TTL_SECONDS, RehearsalAdmission
from mfa_cases import CASE_IDS, owned_accounts
from mfa_config_lock import LOCK_FILE, applied
from mfa_walk import CHECKPOINT_FILE, MATERIAL_FILE

EXPECTED_SKIPS = {"age-1800s-finalize"}


def _rows(result):
    return {row["id"]: row for row in result["rows"]}


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
    assert evidence["skips"] == 1 and evidence["complete"] is True
    assert [item["id"] for item in result["managementEvidence"]] == [
        "observation:oauth-tokeninfo",
        "observation:auth-config-readback",
        "observation:auth-config-apply",
        "observation:auth-config-apply-readback",
        "recovery:auth-config-restore",
        "recovery:auth-config-restore-readback",
    ]
    assert result["chargedCalls"] == 93 + 32 - 1 + 6
    # The shared Ledger refused the reservation by name: its reserve admits only
    # Firestore document resources. The rehearsal recorded that and went on to
    # prove the Gate side unreserved; production raises at the same point.
    assert result["reservationRefusal"] == "canonical Firestore resource required"
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
    assert abandoned["resumable"] is False
    assert abandoned["stopPoint"] == "cleanup"
    assert abandoned["cleanup"]["complete"] is True
    assert abandoned["gateComplete"] is True
    assert built.fake.accounts == {}
    assert not applied(built.fake.config)
    verdict = admission.classify_stop(abandoned)
    assert verdict["disposition"] == "abandoned-cleanup-complete"


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
    assert result["configuration"]["restoreAttempts"] == 1
    assert result["releaseEligible"] is False
    assert applied(built.fake.config)
    verdict = admission.classify_stop(result)
    assert verdict["disposition"] == "owner-escalation"
    # A second attempt through the abandon path is refused by the shared Gate: its
    # management slots are one-shot, so a failed restore cannot be retried inside
    # the envelope. The receipt keeps saying so; the owner restores by hand.
    abandoned = built.run(abandon=True)
    assert abandoned["configuration"]["restoreStatus"] == "restore-failed"
    assert abandoned["configuration"]["restoreAttempts"] == 2
    assert applied(built.fake.config)
    assert admission.classify_stop(abandoned)["disposition"] == "owner-escalation"


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


@pytest.mark.parametrize("outage", ["oauth-tokeninfo", "lock-record"])
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

    second = built.run(resume=True, fault=fault)
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
        },
    )
    mfa_gate.create(output / "gate", gate_plan)
    gate = mfa_gate.MfaGate(output / "gate")
    gate.claim()
    session = mfa_production.GateSession(FakeSession(built.fake), gate)
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


def test_an_abandon_after_a_death_before_the_apply_readback_is_receipted_not_raised(
    tmp_path,
):
    built = _dead_during_apply(tmp_path, after_readback=False)
    result = built.run(abandon=True)
    # The Gate admits its management slots once and in order: the apply readback
    # was never taken, so the restore slot behind it cannot be charged. The run
    # says so instead of raising, and the owner restores by hand.
    assert result["failure"] == "StopRequested"
    assert result["configuration"]["restoreStatus"] == "restore-failed"
    assert applied(built.fake.config)
    assert (built.output / "receipt.json").is_file()
    assert admission.classify_stop(result)["disposition"] == "owner-escalation"


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
