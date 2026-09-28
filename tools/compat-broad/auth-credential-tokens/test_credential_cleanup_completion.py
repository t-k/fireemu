"""Typed resource cleanup and CLI completion, without a real Firebase artifact."""
from __future__ import annotations

import copy
import json
import sys
import time
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import credential_shadow as shadow
from credential_cases import control_members, observation_cases
from credential_collector import new_tracker, track_account, owned_email, mark_deleted, cleanup_report


def tracker(email=True):
    value = new_tracker("c" * 32)
    track_account(value, "owned-uid", owned_email(value, 0) if email else None)
    return value


def rows():
    return {c["id"]: {"caseId":c["id"], "status":c["expectedLocal"]["status"],
                      "errorCode":c["expectedLocal"]["errorCode"],
                      "assertions":{k:True for k in c["expectedLocal"]["assertions"]},
                      "trustRoot":"unsigned-emulator", **control_members(c)}
            for c in observation_cases()}


def stopped():
    return dict(exitCode=-15, processStopped=True, remainingChildren=0,
                outputDrainerStopped=True, failures=[])


BAD_ABSENCE = [{}, {"users": None}, {"users": False}, {"users": 0}, {"users": ""},
               {"users": [] ,"error": {"message":"DENIED"}}, {"users": [], "nextPageToken": "next"},
               {"kind": "wrong"}, {"users":[], "kind":"wrong"}, {"users":[{"localId":"other"}]}, []]


@pytest.mark.parametrize("bad", BAD_ABSENCE)
@pytest.mark.parametrize("which", ["uid", "email"])
def test_ambiguous_absence_cannot_complete_cleanup(bad, which):
    owned = tracker()
    calls = []
    def send(budget, base, path, body, **kwargs):
        calls.append(path)
        if path.endswith(":delete"):
            return 200, {}
        if ("localId" in body) == (which == "uid"):
            return 200, bad
        return 200, {"users": []}
    problems = shadow.cleanup("http://127.0.0.1:1", shadow.shadow_budget(), owned, poster=send)
    assert problems and cleanup_report(owned)["cleanupComplete"] is False
    assert len(calls) == 3


@pytest.mark.parametrize("bad", [None, [], {"error":{}}, {"kind":"wrong"}, {"localId":"owned-uid"}])
def test_http_200_alone_does_not_prove_delete_success(bad):
    owned = tracker()
    calls = []
    def send(*args, **kwargs):
        calls.append(args)
        return 200, bad
    assert shadow.cleanup("http://127.0.0.1:1", shadow.shadow_budget(), owned, poster=send)
    assert len(calls) == 1 and cleanup_report(owned)["cleanupComplete"] is False


@pytest.mark.parametrize("absent", [{"users":[]}, {"kind":"identitytoolkit#GetAccountInfoResponse"},
    {"kind":"identitytoolkit#GetAccountInfoResponse","users":[]}])
@pytest.mark.parametrize("email", [False, True])
def test_typed_success_retains_addressless_cleanup(absent, email):
    owned = tracker(email)
    calls = []
    def send(budget, base, path, body, **kwargs):
        calls.append(path)
        return (200, {"kind":"identitytoolkit#DeleteAccountResponse"}) if path.endswith(":delete") else (200, absent)
    assert shadow.cleanup("http://127.0.0.1:1", shadow.shadow_budget(), owned, poster=send) == []
    assert cleanup_report(owned)["cleanupComplete"] is True
    assert len(calls) == (3 if email else 2)


@pytest.mark.parametrize("error", [OSError("secret-io"), ValueError("secret-value"), RuntimeError("secret-runtime")])
def test_one_uid_failure_keeps_other_account_recovery_and_hides_exception_body(error):
    owned = tracker(False)
    track_account(owned, "second-uid", None)
    calls = []
    def send(budget, base, path, body, **kwargs):
        calls.append((path,body))
        if body.get("localId") == "owned-uid":
            raise error
        return (200,{}) if path.endswith(":delete") else (200,{"users":[]})
    issues = shadow.cleanup("http://127.0.0.1:1", shadow.shadow_budget(), owned, poster=send)
    assert len(calls) == 3 and cleanup_report(owned)["remainingAccounts"] == 1
    assert owned["accounts"]["second-uid"]["uidAbsent"] is True
    assert "secret" not in repr(issues)


def finish(owned=None, shutdown=None, budget=None):
    owned = owned or tracker(False)
    return shadow.finish_record(rows=rows(), tracker=owned, budget=budget or shadow.shadow_budget(), failure=None,
                                shutdown=stopped() if shutdown is None else shutdown,
                                source_binding={"commit":None, "artifactSha256":"a"*64})


def cleaned():
    value = tracker(False)
    mark_deleted(value, "owned-uid", uid_absent=True, email_absent=True)
    return value


def test_agreeing_rows_do_not_override_failed_resource_cleanup():
    record, code = finish()
    assert record["expectedLocalAgreement"]["unexpected"] == []
    assert code == 1 and "incomplete-resource-cleanup" in record["completionIssues"]


@pytest.mark.parametrize("change", [
    {"processStopped":False}, {"processStopped":1}, {"remainingChildren":1}, {"remainingChildren":False},
    {"remainingChildren":None}, {"exitCode":1}, {"exitCode":False}, {"exitCode":None},
    {"outputDrainerStopped":False}, {"outputDrainerStopped":1}, {"failures":["census-unavailable"]},
])
def test_shutdown_failure_is_independent_of_expected_case_agreement(change):
    result = stopped(); result.update(change)
    record, code = finish(cleaned(), result)
    assert code == 1 and "process-cleanup-unconfirmed" in record["completionIssues"]


@pytest.mark.parametrize("field", list(stopped()))
def test_missing_shutdown_evidence_is_not_an_implicit_success(field):
    result = stopped(); result.pop(field)
    record, code = finish(cleaned(), result)
    assert code == 1 and "process-cleanup-unconfirmed" in record["completionIssues"]


def test_complete_control_remains_successful():
    record, code = finish(cleaned())
    assert code == 0 and record["completionIssues"] == []


def test_budget_fault_is_not_overridden_by_agreement_and_cleanup():
    budget = shadow.shadow_budget(); budget["integrityFailure"] = "invalid-clock"
    record, code = finish(cleaned(), budget=budget)
    assert code == 1 and "budget-integrity-failure" in record["completionIssues"]


@pytest.mark.parametrize("error", [RuntimeError("private"), TypeError("private"), KeyboardInterrupt()])
def test_cli_stops_owned_daemon_even_when_cleanup_raises(tmp_path, monkeypatch, error):
    process = object()
    calls = []
    monkeypatch.setattr(shadow,"start_daemon",lambda *a:(process,"http://127.0.0.1:1"))
    def collect(base, budget, owned):
        track_account(owned,"owned-uid",None)
        return rows(), None
    monkeypatch.setattr(shadow,"collect",collect)
    def cleanup(*args):
        raise error
    monkeypatch.setattr(shadow,"cleanup",cleanup)
    monkeypatch.setattr(shadow,"stop_daemon",lambda p:(calls.append(p) or stopped()))
    argv=["--binary",sys.executable,"--output",str(tmp_path/"result.json")]
    if isinstance(error, KeyboardInterrupt):
        with pytest.raises(KeyboardInterrupt):
            shadow.main(argv)
    else:
        assert shadow.main(argv) == 1
        record=json.loads((tmp_path/"result.json").read_text())
        assert "private" not in json.dumps(record)
    assert calls == [process]


def test_existing_result_rejected_before_startup(tmp_path, monkeypatch):
    output=tmp_path/"result.json"; output.write_text("keep")
    def forbidden(*args):
        pytest.fail("must not spawn")
    monkeypatch.setattr(shadow,"start_daemon",forbidden)
    assert shadow.main(["--binary",sys.executable,"--output",str(output)]) == 2
    assert output.read_text() == "keep"


def test_result_publication_occurs_after_cleanup_and_shutdown(tmp_path, monkeypatch):
    output=tmp_path/"result.json"
    calls=[]
    monkeypatch.setattr(shadow,"start_daemon",lambda *args:(object(),"http://127.0.0.1:1"))
    def collect(base,budget,owned):
        track_account(owned,"owned-uid",None)
        return rows(),None
    def cleanup(base,budget,owned):
        calls.append("cleanup"); mark_deleted(owned,"owned-uid",uid_absent=True,email_absent=True)
        return []
    def stop(process):
        calls.append("stop")
        output.write_text("concurrent output")
        return stopped()
    monkeypatch.setattr(shadow,"collect",collect)
    monkeypatch.setattr(shadow,"cleanup",cleanup)
    monkeypatch.setattr(shadow,"stop_daemon",stop)
    assert shadow.main(["--binary",sys.executable,"--output",str(output)]) == 2
    assert calls == ["cleanup","stop"] and output.read_text() == "concurrent output"
