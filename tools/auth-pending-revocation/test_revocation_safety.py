"""The recorder must not write configuration before its preconditions hold, must restore
what it read, must not retain raw error text, and complete() must reject a run that never
observed the held credential or did not restore the configuration."""

import json
import revocation_contract as contract
import revocation_recorder as recorder
from revocation_contract import CASES, FINALIZE_CHECKS, complete


def accepted(name, checks):
    return {
        "id": name,
        "httpStatus": 200,
        "outcome": "accepted",
        "observedError": None,
        "checks": checks,
        "elapsedMs": 1,
        "skipped": False,
    }


def skipped(name):
    return {
        "id": name,
        "httpStatus": None,
        "outcome": "skipped",
        "observedError": None,
        "checks": {},
        "elapsedMs": 1,
        "skipped": True,
    }


def refused(name):
    return {
        "id": name,
        "httpStatus": 400,
        "outcome": "refused",
        "observedError": "INVALID_MFA_PENDING_CREDENTIAL",
        "checks": {},
        "elapsedMs": 1,
        "skipped": False,
    }


def complete_report():
    finalize = dict.fromkeys(FINALIZE_CHECKS, True)
    rows = {
        "baseline-a-fresh-finalize": accepted("baseline-a-fresh-finalize", finalize),
        "baseline-b-fresh-finalize": accepted("baseline-b-fresh-finalize", finalize),
        "revoked-a-held-start": accepted(
            "revoked-a-held-start", {"sessionInfoPresent": True}
        ),
        "revoked-a-held-finalize": accepted(
            "revoked-a-held-finalize", {**finalize, "authTimeAtOrAfterValidSince": True}
        ),
        "revoked-a-held-lookup": accepted(
            "revoked-a-held-lookup", {"ownerMatches": True}
        ),
        "revoked-a-held-refresh": accepted(
            "revoked-a-held-refresh",
            {
                "noError": True,
                "idTokenPresent": True,
                "refreshTokenPresent": True,
                "uidMatches": True,
                "expiryIsPositiveInteger": True,
                "expiryMatchesOneHour": True,
                "bearerType": True,
                "derivedLookup": True,
            },
        ),
        "revoked-a-fresh-finalize": accepted("revoked-a-fresh-finalize", finalize),
        "revoked-b-fresh-finalize": accepted("revoked-b-fresh-finalize", finalize),
    }
    return {
        "status": "observed",
        "cases": [rows[name] for name in CASES],
        "setup": {"a": True, "b": True},
        "revocation": {"validSinceReadback": True, "controlUnchanged": True},
        "heldCredentialIssuedBeforeRevocation": True,
        "cleanup": {"uidAbsent": True, "emailAbsent": True},
        "configRestored": True,
        "configDigestMatches": True,
    }


def with_rows(report, **replacements):
    report["cases"] = [replacements.get(r["id"], r) for r in report["cases"]]
    return report


def test_complete_report_is_complete():
    assert complete(complete_report())


def test_complete_rejects_a_configuration_digest_mismatch():
    assert complete({**complete_report(), "configDigestMatches": False}) is False


def test_complete_rejects_a_run_that_never_observed_the_held_credential():
    report = with_rows(
        complete_report(),
        **{name: skipped(name) for name in contract.DIAGNOSTIC},
    )
    assert complete(report) is False


def test_complete_requires_the_held_chain_to_be_consistent():
    # A refused start must be followed by skipped rows, not executed ones.
    report = with_rows(
        complete_report(), **{"revoked-a-held-start": refused("revoked-a-held-start")}
    )
    assert complete(report) is False
    report = with_rows(
        report,
        **{name: skipped(name) for name in contract.DIAGNOSTIC[1:]},
    )
    assert complete(report)
    # A successful finalize must not skip lookup and refresh.
    report = with_rows(
        complete_report(), **{"revoked-a-held-lookup": skipped("revoked-a-held-lookup")}
    )
    assert complete(report) is False
    # A refused finalize must skip both.
    report = with_rows(
        complete_report(),
        **{
            "revoked-a-held-finalize": refused("revoked-a-held-finalize"),
            "revoked-a-held-lookup": skipped("revoked-a-held-lookup"),
            "revoked-a-held-refresh": skipped("revoked-a-held-refresh"),
        },
    )
    assert complete(report)


def test_note_keeps_only_classified_diagnostics():
    report = {}
    recorder.note(
        report,
        "mfaSignIn:start",
        400,
        {"error": {"message": "OPERATION_NOT_ALLOWED : secret-token-value-123"}},
    )
    assert report["lastError"] == "OPERATION_NOT_ALLOWED"
    assert "secret-token-value-123" not in json.dumps(report)
    recorder.note(
        report,
        "mfaSignIn:start",
        400,
        {
            "error": {
                "message": "OPERATION_NOT_ALLOWED : SMS unable to be sent until this region enabled by the app developer."
            }
        },
    )
    assert report["lastErrorDetail"] == "SMS_REGION_NOT_ENABLED"


class FakeTransport:
    """Stands in for the network: records every configuration PATCH."""

    def __init__(self, config):
        self.config = config
        self.patches = []

    def preflight(self):
        return "token", "key", {"sha256": "x"}

    def request(self, url, body=None, token=None, quota=False, form=False):
        assert url == recorder.CONFIG_URL and body is None
        return 200, json.loads(json.dumps(self.config))

    def patch(self, url, body, token):
        self.patches.append(body)
        return 200, {}


def test_no_configuration_write_when_preconditions_fail(tmp_path, monkeypatch):
    transport = FakeTransport(
        {
            "mfa": {"state": "ENABLED"},
            "signIn": {},
            "smsRegionConfig": {"allowlistOnly": {}},
        }
    )
    monkeypatch.setattr(recorder.core, "production_preflight", transport.preflight)
    monkeypatch.setattr(recorder.core, "request", transport.request)
    monkeypatch.setattr(recorder, "patch", transport.patch)
    monkeypatch.setattr(recorder.core, "command", lambda argv: "deadbeef")
    report = recorder.observe(tmp_path / "run")
    assert report["status"] == "incomplete" and report["cases"] == []
    assert transport.patches == [], "no PATCH may be sent before the preconditions hold"
    assert "configRestored" not in report
    assert not (tmp_path / "run" / "config-recovery.json").exists()


def test_restore_uses_the_values_that_were_read(tmp_path, monkeypatch):
    original = {
        "mfa": {"state": "DISABLED"},
        "signIn": {"phoneNumber": None},
        "smsRegionConfig": {"allowlistOnly": {}},
    }
    transport = FakeTransport(original)
    monkeypatch.setattr(recorder.core, "production_preflight", transport.preflight)
    monkeypatch.setattr(recorder.core, "request", transport.request)
    monkeypatch.setattr(recorder, "patch", transport.patch)
    monkeypatch.setattr(recorder.core, "command", lambda argv: "deadbeef")
    monkeypatch.setattr(recorder.time, "sleep", lambda s: None)
    # The readback after the enabling PATCH does not match, so the run aborts after the
    # change was attempted: the restore must still be sent, with the values read before.
    report = recorder.observe(tmp_path / "run")
    assert report["status"] == "incomplete"
    assert len(transport.patches) == 2
    assert transport.patches[1] == {
        "mfa": {"state": "DISABLED"},
        "signIn": {"phoneNumber": {"enabled": False, "testPhoneNumbers": {}}},
        "smsRegionConfig": {"allowlistOnly": {}},
    }
    recovery = json.loads((tmp_path / "run" / "config-recovery.json").read_bytes())
    assert recovery["original"]["smsRegionConfig"] == {"allowlistOnly": {}}
    assert recovery["changeAttempted"] is True
