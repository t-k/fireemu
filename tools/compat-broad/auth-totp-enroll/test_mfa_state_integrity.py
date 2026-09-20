"""MFA state/checkpoint integrity, atomic transitions and per-account recovery."""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mfa_collector as m
import mfa_local_shadow as shadow
from mfa_cases import CASE_IDS
from mfa_manifest import compile_campaign

START = 1000.0


def plan():
    return compile_campaign("a" * 32)


def fresh():
    return m.initial_state(plan(), START)


def raw_checkpoint(state):
    # Deliberately bypass the writer to test untrusted serialized inputs, including
    # self-consistent but structurally invalid checkpoints.
    return json.dumps({"state": state, "checkpointDigest": m.digest(state)}, separators=(",", ":")).encode()


def finished():
    state = fresh()
    for identifier in CASE_IDS:
        m.record_step(state, identifier, {"status": 200}, START)
    assert m.run_complete(state)
    return state


@pytest.mark.parametrize("charge", [-1, -400, 1.5, True, False, "1", None])
def test_bad_charges_are_rejected_without_partially_resolving_step(charge):
    state = fresh()
    before = copy.deepcopy(state)
    with pytest.raises(ValueError):
        m.record_step(state, CASE_IDS[0], {"status": 200}, START, requests=charge)
    assert state == before


@pytest.mark.parametrize("invalid", ["unknown", "negative", "nan", "string", "self", "done", "reschedule", "non-object"])
def test_bad_schedule_is_atomic_even_after_an_earlier_valid_dependent(invalid):
    state = fresh()
    bad_name, bad_time = CASE_IDS[2], START + 2
    if invalid == "unknown":
        bad_name = "no-such-case"
    if invalid == "negative":
        bad_time = -1
    if invalid == "nan":
        bad_time = float("nan")
    if invalid == "string":
        bad_time = "1002"
    if invalid == "self":
        bad_name = CASE_IDS[0]
    if invalid == "done":
        m.record_step(state, CASE_IDS[2], {"status": 200}, START)
    if invalid == "reschedule":
        state["steps"][2]["dueAt"] = START + 30
    schedule = {CASE_IDS[1]: START + 1, bad_name: bad_time}
    if invalid == "non-object":
        schedule = []
    before = copy.deepcopy(state)
    with pytest.raises((ValueError, KeyError)):
        m.record_step(state, CASE_IDS[0], {"status": 200}, START, schedule=schedule)
    assert state == before


def test_recorded_observation_is_detached_from_the_caller():
    state = fresh()
    observation = {"status": 200, "body": {"ok": [True]}}
    m.record_step(state, CASE_IDS[0], observation, START)
    observation["body"]["idToken"] = "PRIVATE"
    observation["body"]["ok"].clear()
    assert state["steps"][0]["observation"] == {"status": 200, "body": {"ok": [True]}}
    assert b"PRIVATE" not in m.checkpoint_bytes(state)


@pytest.mark.parametrize("value", [True, "1000", None, -1, float("nan"), float("inf"), 10**1000])
def test_invalid_clock_cannot_schedule_work_or_create_a_checkpoint(value):
    with pytest.raises(ValueError):
        m.initial_state(plan(), value)
    state = fresh()
    with pytest.raises(m.BudgetError):
        m.next_action(state, value)
    assert state["aborted"] is True
    assert m.next_action(state, START).get("aborted") is True
    assert not m.run_complete(state)


def test_late_response_is_recorded_and_charged_but_not_a_success():
    state = fresh()
    m.record_step(state, CASE_IDS[0], {"status": 200}, state["deadline"] + 1, requests=3)
    assert state["requests"] == 3
    assert state["steps"][0]["status"] == "done"
    assert state["aborted"] and state["abortReason"] == "wall-budget-exhausted"
    assert not m.run_complete(state)


def test_exact_request_limit_allows_a_finished_run_but_no_more_observation():
    state = fresh()
    m.record_step(state, CASE_IDS[0], {"status": 200}, START, requests=state["maxRequests"])
    assert m.next_action(state, START)["action"] != "RUN"
    assert state["aborted"]
    completed = finished()
    completed["requests"] = completed["maxRequests"]
    assert m.next_action(completed, START)["action"] == "DONE"
    assert m.run_complete(completed)


@pytest.mark.parametrize("flag", ["false", "true", 0, 1, None, [], {}])
def test_absence_flags_are_not_truthy_coercions(flag):
    state = fresh()
    m.register_owned(state, "account", "owned", START)
    before = copy.deepcopy(state)
    with pytest.raises(ValueError):
        m.mark_deleted(state, "owned", flag)
    assert state == before
    assert not m.cleanup_complete(state)


@pytest.mark.parametrize("mutation", [
    "no-cases", "duplicate-case", "reordered", "wrong-case", "wrong-campaign", "missing-field",
    "negative-requests", "float-requests", "bool-limit", "abort-number", "abort-reason",
    "unknown-status", "pending-with-data", "resolved-without-time", "skipped-empty-reason",
    "duplicate-resource", "truthy-cleanup", "absence-without-delete", "created-before-start",
    "secret-observation", "due-before-start", "empty-resource-id",
])
def test_self_consistent_invalid_checkpoint_is_rejected(mutation):
    state = finished()
    m.register_owned(state, "account", "owned", START)
    m.mark_deleted(state, "owned", True)
    if mutation == "no-cases":
        state["steps"] = []
    elif mutation == "duplicate-case":
        state["steps"][1] = copy.deepcopy(state["steps"][0])
    elif mutation == "reordered":
        state["steps"].reverse()
    elif mutation == "wrong-case":
        state["steps"][0]["id"] = "unknown"
    elif mutation == "wrong-campaign":
        state["campaignId"] = "other"
    elif mutation == "missing-field":
        del state["deadline"]
    elif mutation == "negative-requests":
        state["requests"] = -1
    elif mutation == "float-requests":
        state["requests"] = 1.0
    elif mutation == "bool-limit":
        state["maxRequests"] = True
    elif mutation == "abort-number":
        state["aborted"] = 0
    elif mutation == "abort-reason":
        state["abortReason"] = "ignored"
    elif mutation == "unknown-status":
        state["steps"][0]["status"] = "anything"
    elif mutation == "pending-with-data":
        state["steps"][0]["status"] = "pending"
        del state["steps"][0]["recordedAt"]
    elif mutation == "resolved-without-time":
        del state["steps"][0]["recordedAt"]
    elif mutation == "skipped-empty-reason":
        state["steps"][0].update(status="skipped", observation={"skippedReason":""})
    elif mutation == "duplicate-resource":
        state["ownedResources"].append(copy.deepcopy(state["ownedResources"][0]))
    elif mutation == "truthy-cleanup":
        state["ownedResources"][0]["absenceVerified"] = "false"
    elif mutation == "absence-without-delete":
        state["ownedResources"][0]["deleted"] = False
    elif mutation == "created-before-start":
        state["ownedResources"][0]["createdAt"] = 1
    elif mutation == "secret-observation":
        state["steps"][0]["observation"]["idToken"] = "PRIVATE"
    elif mutation == "due-before-start":
        state["steps"][0]["dueAt"] = START - 1
    elif mutation == "empty-resource-id":
        state["ownedResources"][0]["id"] = ""
    with pytest.raises(m.CheckpointError):
        m.load_checkpoint(raw_checkpoint(state))
    with pytest.raises(m.CheckpointError):
        m.checkpoint_bytes(state)
    assert m.run_complete(state) is False


@pytest.mark.parametrize("variant", ["duplicate", "escaped-duplicate", "utf16", "nonfinite"])
def test_checkpoint_decoder_rejects_ambiguous_or_non_utf8_bytes(variant):
    raw = raw_checkpoint(fresh())
    if variant == "duplicate":
        raw = raw.replace(b'"requests":0', b'"requests":9,"requests":0')
    elif variant == "escaped-duplicate":
        raw = raw.replace(b'"requests":0', b'"\\u0072equests":9,"requests":0')
    elif variant == "utf16":
        raw = raw.decode().encode("utf-16")
    else:
        raw = raw.replace(b'"startedAt":1000.0', b'"startedAt":NaN')
    with pytest.raises(m.CheckpointError):
        m.load_checkpoint(raw)


@pytest.mark.parametrize("field,value", [("maxRequests", 999), ("deadline", 9999), ("nonce", "b"*64), ("planDigest", "b"*64)])
def test_resume_can_be_bound_to_an_independently_held_plan(field, value):
    state = fresh()
    state[field] = value
    # A self-hash authenticates nothing. Without an independent plan the compatible
    # structural state may be read, but an explicitly supplied plan must reject drift.
    encoded = raw_checkpoint(state)
    assert m.load_checkpoint(encoded) == state
    with pytest.raises(m.CheckpointError):
        m.load_checkpoint(encoded, plan=plan())


def test_bound_resume_retains_waiting_cases_and_outstanding_resources():
    p = plan()
    state = m.initial_state(p, START)
    m.register_owned(state, "account", "owned", START)
    m.record_step(state, CASE_IDS[0], {"status":400, "errorCode":"REFUSED"}, START,
                  schedule={CASE_IDS[1]: START + 300})
    resumed = m.load_checkpoint(m.checkpoint_bytes(state), plan=p)
    assert resumed == state
    assert m.next_action(resumed, START + 100)["action"] == "WAIT"
    assert m.next_action(resumed, resumed["deadline"] + 1)["action"] == "CLEANUP"
    assert m.outstanding_cleanup(resumed)[0]["id"] == "owned"


class Instance(shadow.Instance):
    def __init__(self, failure=None):
        super().__init__("http://127.0.0.1:9099", "http://127.0.0.1:9100", "CONTROL")
        self.calls = []
        self.failure = failure
    def admin(self, path, body):
        uid = body["localId"]
        uid = uid[0] if isinstance(uid, list) else uid
        deletion = path.endswith(":delete")
        with self._request_budget.attempt(operation="delete" if deletion else "lookup", uid=uid):
            pass
        self.calls.append((uid, "delete" if deletion else "lookup"))
        if uid == "one" and self.failure:
            stage, reply = self.failure
            if stage == ("delete" if deletion else "lookup"):
                if isinstance(reply, Exception):
                    raise reply
                return reply
        return (200, {"kind":"identitytoolkit#DeleteAccountResponse"}) if deletion else (200, {"kind":"identitytoolkit#GetAccountInfoResponse"})


def cleanup(failure=None):
    state = fresh()
    accounts = {key:{"localId":key} for key in ("one", "two")}
    for uid in accounts:
        m.register_owned(state, "account", uid, START)
    instance = Instance(failure)
    shadow._delete_owned(instance, state, accounts)
    return state, instance


@pytest.mark.parametrize("reply", [
    (200, {}), (200, {"users":None}), (200, {"users":False}),
    (200, {"users":[], "error":{"message":"REFUSED"}}),
    (200, {"kind":"wrong"}), (200, {"users":[], "nextPageToken":"next"}),
    (404, {"error":{"status":"USER_NOT_FOUND"}}),
    (200, {"users":[{"localId":"one"}]}),
])
def test_ambiguous_lookup_cannot_clear_one_account_or_prevent_other_cleanup(reply):
    state, instance = cleanup(("lookup", reply))
    assert [row["id"] for row in m.outstanding_cleanup(state)] == ["one"]
    assert ("two", "lookup") in instance.calls


@pytest.mark.parametrize("reply", [(403, {"error":{}}), (200, {"error":{}}), (200, []), (200, None), (200.0,{})])
def test_failed_delete_is_not_made_successful_by_a_later_empty_lookup(reply):
    state, instance = cleanup(("delete", reply))
    assert [row["id"] for row in m.outstanding_cleanup(state)] == ["one"]
    assert ("one", "lookup") not in instance.calls
    assert ("two", "lookup") in instance.calls


@pytest.mark.parametrize("stage", ["delete", "lookup"])
def test_transport_failure_retains_first_account_and_continues_to_second(stage):
    state, instance = cleanup((stage, OSError("PRIVATE-EXCEPTION")))
    assert [row["id"] for row in m.outstanding_cleanup(state)] == ["one"]
    assert ("two", "lookup") in instance.calls
    assert b"PRIVATE-EXCEPTION" not in m.checkpoint_bytes(state)


def test_only_state_registered_accounts_are_sent_and_duplicates_are_not_retried():
    state = fresh()
    m.register_owned(state, "account", "one", START)
    instance = Instance()
    shadow._delete_owned(instance, state, {"a":{"localId":"one"}, "dup":{"localId":"one"}, "foreign":{"localId":"unowned"}})
    assert instance.calls == [("one", "delete"), ("one", "lookup")]
    assert m.cleanup_complete(state)


def test_successful_cleanup_is_preserved_as_success_but_abort_stays_aborted():
    state, _ = cleanup()
    assert m.cleanup_complete(state)
    assert not m.run_complete(state)  # no observation cases ran
    for identifier in CASE_IDS:
        m.record_step(state, identifier, {"status":200}, START)
    assert m.run_complete(state)
    state["aborted"] = True
    state["abortReason"] = "injected-stop"
    assert m.cleanup_complete(state) and not m.run_complete(state)


def test_age_dependent_case_cannot_be_recorded_before_its_due_time():
    state = fresh()
    m.record_step(state, CASE_IDS[0], {"status":200}, START,
                  schedule={CASE_IDS[1]: START + 300})
    before = copy.deepcopy(state)
    with pytest.raises(ValueError):
        m.record_step(state, CASE_IDS[1], {"status":200}, START + 299)
    assert state == before
    m.record_step(state, CASE_IDS[1], {"status":200}, START + 300)
    assert state["steps"][1]["status"] == "done"


def test_retained_checkpoint_cannot_claim_an_aged_observation_too_early():
    state = finished()
    state["steps"][1]["dueAt"] = START + 300
    with pytest.raises(m.CheckpointError):
        m.load_checkpoint(raw_checkpoint(state))
    assert not m.run_complete(state)


def test_real_sequence_finally_saves_failed_observation_and_per_account_cleanup(tmp_path, monkeypatch):
    class Counted(Instance):
        def __init__(self):
            super().__init__(("delete", OSError("SECRET")))
    instance = Counted()
    def fail_after_signup(_instance, state, _checkpoint, _rows, accounts, *, journal):
        # The two simulated setup attempts occur inside this run's binding.
        for _ in range(2):
            with _instance._request_budget.attempt():
                pass
        for uid in ("one", "two"):
            m.register_owned(state, "account", uid, state["startedAt"])
            accounts[uid] = {"localId":uid}
        raise ValueError("observation-failed")
    monkeypatch.setattr(shadow, "_walk", fail_after_signup)
    with pytest.raises(ValueError, match="observation-failed"):
        shadow.run_sequence(instance, tmp_path)
    state = m.load_checkpoint((tmp_path / "checkpoint.json").read_bytes())
    assert [item["id"] for item in m.outstanding_cleanup(state)] == ["one"]
    assert state["requests"] == instance.requests == 5
    assert not m.run_complete(state)
    assert ("two", "lookup") in instance.calls
