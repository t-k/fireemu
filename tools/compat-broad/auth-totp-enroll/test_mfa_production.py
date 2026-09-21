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
