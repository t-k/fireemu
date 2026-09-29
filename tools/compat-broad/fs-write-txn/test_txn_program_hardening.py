"""Tests added after the independent review and the mutation run: each names the behaviour it pins."""

import base64
import copy
import importlib

import pytest

from test_txn_program_collector import Clock, NONCE, OWNER, Service, collector_module, fixture, program, support, without

GONE = "The referenced transaction has expired or is no longer valid."


def tamper(service, matches, change):
    """Wrap the service so the answer to the first request `matches` is changed."""
    original = service.send
    seen = {"done": False}
    def send(transport, method, request, **kwargs):
        result = original(transport, method, request, **kwargs)
        if not seen["done"] and matches(len(service.calls), transport, method, request):
            seen["done"] = True
            return change(copy.deepcopy(result))
        return result
    service.send = send
    return service


def at(site_number):
    return lambda number, _transport, _method, _request: number == site_number


def timing(start=1.0, end=1.5):
    return {"dispatchMonotonic": start, "responseMonotonic": end, "dispatchUtc": collector_module.utc_now() if False else f"2026-09-30T00:00:{int(start):02d}.000Z", "responseUtc": f"2026-09-30T00:00:{int(start):02d}.500Z"}


def receipt(transport="grpc", code=0, details="", response=None, http="auto", **changes):
    http = (None if transport == "grpc" else 200 if code == 0 else 409) if http == "auto" else http
    value = {"kind": "txn-program-receipt-v1", "transport": transport, "complete": True, "code": code, "details": details, "response": {} if code == 0 and response is None else response, "http": http, "dispatchedRequests": 1, "childReaped": True}
    return {**value, **changes}


def ledger(table=None):
    return collector_module.Ledger(program.compile_plan(table or support.TABLE, NONCE, OWNER))


def step_of(table, step_id):
    return next(step for step in program.compile_plan(table, NONCE, OWNER)["steps"] if step["id"] == step_id)


# --- responsibility survives a bad answer (review M2) ---

def test_a_malformed_minted_token_keeps_the_unknown_start():
    big = base64.b64encode(b"x" * 1100).decode()
    collector, service, *_ = fixture()
    tamper(service, at(4), lambda result: {**result, "response": {"transaction": big}})
    receipt_ = collector.run()
    assert receipt_["failureType"] == "ValueError" and receipt_["unknownStarts"] == ["r/begin"] and receipt_["unrecovered"] is True and receipt_["complete"] is False


def test_a_duplicate_minted_token_keeps_the_unknown_start():
    collector, service, *_ = fixture(duplicate_tokens=True)
    receipt_ = collector.run()
    assert receipt_["unknownStarts"] == ["g/begin"] and receipt_["unrecovered"] is True and receipt_["complete"] is False


@pytest.mark.parametrize("bad", [{"writeResults": []}, {"writeResults": [{}]}, {"writeResults": [{"updateTime": "not a time"}]}, {"writeResults": [{"updateTime": {"seconds": "1", "nanos": 10 ** 9}}]}, {"writeResults": "x"}])
def test_a_malformed_commit_acknowledgement_keeps_the_unknown_commit(bad):
    collector, service, *_ = fixture()
    tamper(service, at(3), lambda result: {**result, "response": bad})
    receipt_ = collector.run()
    assert receipt_["unknownCommits"] == ["setup/create-a"] and receipt_["unrecovered"] is True and receipt_["complete"] is False
    assert service.documents == {}, "the possibly-owned document is still cleaned up"


# --- recovery never repeats a refused release (review M3) and refusals prove nothing unless they say the token is gone ---

def test_a_refused_recovery_release_is_sent_once():
    table = without(support.TABLE, "r/rollback", "r/rollback-again", "g/rollback", "g/rollback-again")
    collector, service, *_ = fixture(table, rollback_code=5)
    receipt_ = collector.run()
    rollbacks = [call for call in service.calls if call[1] == "Rollback"]
    assert len(rollbacks) == 1, "one release per token, never repeated in final recovery"
    assert receipt_["complete"] is False and receipt_["unrecovered"] is True and receipt_["openTokens"] == ["rest-r"]
    assert receipt_["phaseRequests"]["tokenCleanup"] == 1


@pytest.mark.parametrize("code,details,finishes", [(10, GONE, True), (10, "another refusal", False), (5, GONE, False), (9, GONE, False), (3, "Invalid transaction.", False)])
def test_only_the_gone_answer_finishes_a_token_a_declared_rollback_refused(code, details, finishes):
    collector, service, *_ = fixture(rollback_code=10)
    original = service.send
    def send(transport, method, request, **kwargs):
        result = original(transport, method, request, **kwargs)
        if method == "Rollback" and result["code"] != 0 and transport == "rest":
            return {**result, "code": code, "details": details, "http": 409}
        return result
    service.send = send
    receipt_ = collector.run()
    states = {role: entry["state"] for role, entry in receipt_["tokens"].items()}
    if finishes:
        assert receipt_["complete"] is True and set(states.values()) == {"released-refused"}
    else:
        assert receipt_["complete"] is False
        assert not any(call[0] == "grpc" and call[1] == "BeginTransaction" for call in service.calls), "no later chain begins while a token is unresolved"
        assert receipt_["unrecovered"] is True


# --- Ledger rules, exercised directly ---

@pytest.mark.parametrize("state,blocked", [("open", True), ("unconfirmed-release", True), ("released-refused", False), ("committed", False), ("rolled-back", False)])
def test_a_begin_needs_every_earlier_token_resolved(state, blocked):
    value = ledger()
    value.tokens["rest-r"] = {"value": "dG9rZW4=", "state": state, "transport": "rest", "start": timing(), "lastUse": timing()}
    begin = step_of(support.TABLE, "g/begin")
    if blocked:
        with pytest.raises(ValueError, match="unresolved"):
            value.guard("BeginTransaction", {"database": value.plan["database"], "options": {"readWrite": {}}}, begin)
    else:
        value.guard("BeginTransaction", {"database": value.plan["database"], "options": {"readWrite": {}}}, begin)


def test_a_guard_failure_charges_no_request():
    collector, _service, budget, *_ = fixture()
    collector.ledger.tokens["rest-r"] = {"value": "dG9rZW4=", "state": "open", "transport": "rest", "start": timing(), "lastUse": timing()}
    begin = step_of(support.TABLE, "g/begin")
    with pytest.raises(ValueError, match="unresolved"):
        collector._rpc("g/begin", "grpc", "BeginTransaction", {"database": collector.plan["database"], "options": {"readWrite": {}}}, "observation", step=begin)
    assert budget.total == 0 and collector.pending is None


def test_an_unwritten_document_that_answers_a_read_stops():
    value = ledger()
    value.docs["m"]["status"] = "confirmed-absent"
    read = step_of(support.TABLE, "g/post-read")
    name = value.plan["documents"]["m"]
    document = {"name": name, "fields": {"owner": {"stringValue": OWNER}, "nonce": {"stringValue": NONCE}, "role": {"stringValue": "m"}, "state": {"stringValue": "created"}}, "updateTime": {"seconds": "1", "nanos": 1}}
    with pytest.raises(ValueError, match="never wrote"):
        value.after("x", "grpc", "GetDocument", {"name": name}, {**read, "allow": [0]}, receipt(response=document), timing())


@pytest.mark.parametrize("code", [1, 2, 4, 13, 14])
def test_an_unknown_code_claimed_complete_is_indeterminate(code):
    value = ledger()
    with pytest.raises(ValueError, match="indeterminate"):
        value.after("r/begin", "rest", "BeginTransaction", {}, step_of(support.TABLE, "r/begin"), receipt("rest", code, http=503), timing())


@pytest.mark.parametrize("transport,code,http,fine", [
    ("grpc", 0, None, True), ("grpc", 5, None, True), ("grpc", 0, 200, False), ("grpc", 5, 404, False),
    ("rest", 0, 200, True), ("rest", 5, 404, True), ("rest", 10, 409, True),
    ("rest", 9, 200, False), ("rest", 0, 409, False), ("rest", 0, None, False), ("rest", 5, None, False), ("rest", 0, 99, False), ("rest", 0, 600, False), ("rest", 5, "404", False),
])
def test_the_http_status_agrees_with_the_transport_and_the_code(transport, code, http, fine):
    value = ledger()
    step = {**step_of(support.TABLE, "r/plain-read"), "allow": [0, 5, 9, 10], "transport": transport}
    read = {"name": value.plan["documents"]["a"]}
    value.docs["a"].update(status="created", state="created")
    document = {"name": read["name"], "fields": {"owner": {"stringValue": OWNER}, "nonce": {"stringValue": NONCE}, "role": {"stringValue": "a"}, "state": {"stringValue": "created"}}, "updateTime": {"seconds": "1", "nanos": 1} if transport == "grpc" else "2026-09-30T00:00:00.000000001Z"}
    result = receipt(transport, code, response=document if code == 0 else None, http=http)
    if fine:
        value.after("x", transport, "GetDocument", read, step, result, timing())
    else:
        with pytest.raises(ValueError, match="HTTP|indeterminate|malformed"):
            value.after("x", transport, "GetDocument", read, step, result, timing())


# --- the marker and cleanup rules ---

@pytest.mark.parametrize("label,change", [
    ("nonce", lambda fields: fields["nonce"].update(stringValue="c" * 32)),
    ("role", lambda fields: fields["role"].update(stringValue="m")),
    ("owner", lambda fields: fields["owner"].update(stringValue="c" * 32)),
    ("state", lambda fields: fields["state"].update(stringValue="held")),
    ("extra field", lambda fields: fields.update(extra={"stringValue": "x"})),
    ("missing field", lambda fields: fields.pop("state")),
    ("not a string", lambda fields: fields.update(state={"integerValue": "1"})),
    ("string with another type", lambda fields: fields["state"].update(valueType="integerValue")),
])
def test_a_document_whose_marker_differs_stops_the_recording(label, change):
    collector, service, *_ = fixture()
    def alter(result):
        change(result["response"]["fields"])
        return result
    tamper(service, lambda number, _t, method, _r: method == "GetDocument" and number >= 5, alter)
    receipt_ = collector.run()
    assert receipt_["failureType"] == "ValueError" and receipt_["complete"] is False, label
    assert not any(call[1] == "Commit" and "transaction" in call[2] for call in service.calls), "nothing is committed after a foreign marker"


def cleanup_number(service_calls_before_cleanup=22, offset=0):
    # The clean recording sends 41 steps... plus setup; cleanup starts after the 19 observation requests.
    return 19 + 1 + offset


@pytest.mark.parametrize("label,matches,change", [
    ("delete refused", lambda n, t, m, r: m == "DeleteDocument", lambda r: {**r, "code": 9, "details": "no", "response": None}),
    ("deleted document still answers", lambda n, t, m, r: m == "GetDocument" and n == 22, lambda r: {**r, "code": 0, "response": {"name": "x", "fields": {}, "updateTime": {"seconds": "1", "nanos": 1}}}),
    ("owned document unreadable for deletion", lambda n, t, m, r: m == "GetDocument" and n == 20, lambda r: {**r, "code": 5, "response": None}),
])
def test_a_cleanup_that_cannot_prove_deletion_reports_the_recording_unrecovered(label, matches, change):
    collector, service, *_ = fixture()
    tamper(service, matches, change)
    receipt_ = collector.run()
    assert receipt_["graphComplete"] is True, "the graph itself ran to its end"
    assert receipt_["complete"] is False and receipt_["unrecovered"] is True and receipt_["cleanup"] == {"absent": False}, label


# --- clocks, timestamps and order ---

def test_a_recording_whose_utc_and_monotonic_elapsed_disagree_is_refused():
    good = {"dispatchMonotonic": 1.0, "responseMonotonic": 2.0, "dispatchUtc": "2026-09-30T00:00:01.000Z", "responseUtc": "2026-09-30T00:00:02.000Z"}
    collector_module.check_timing(good)
    for bad in [{**good, "responseUtc": "2026-09-30T00:00:02.300Z"}, {**good, "responseUtc": "2026-09-30T00:00:01.700Z"}, {**good, "responseMonotonic": 0.5}, {**good, "dispatchMonotonic": -1.0}, {**good, "responseUtc": "2026-09-30T00:00:00.000Z"}, {**good, "responseUtc": "2026-09-30 00:00:02"}, {**good, "extra": 1}]:
        with pytest.raises(ValueError):
            collector_module.check_timing(bad)
    collector_module.check_timing({**good, "responseUtc": "2026-09-30T00:00:02.200Z"})


@pytest.mark.parametrize("transport,value,fine", [
    ("rest", "2026-09-30T00:00:00.123456789Z", True), ("rest", "2026-09-30T00:00:00Z", True), ("rest", "2026-09-30T00:00:00+09:00", False), ("rest", "2026-09-30", False), ("rest", {"seconds": "1", "nanos": 1}, False),
    ("grpc", {"seconds": "1788004860", "nanos": 999999999}, True), ("grpc", {"seconds": "1788004860"}, True), ("grpc", {"seconds": "1", "nanos": 10 ** 9}, False), ("grpc", {"seconds": "1", "nanos": -1}, False), ("grpc", {"seconds": 1, "nanos": 1}, False), ("grpc", {"seconds": "1", "nanos": 1, "x": 1}, False), ("grpc", "2026-09-30T00:00:00Z", False),
])
def test_document_version_stamps_are_checked_in_their_transports_form(transport, value, fine):
    if fine:
        collector_module.check_timestamp(value, transport)
    else:
        with pytest.raises(ValueError):
            collector_module.check_timestamp(value, transport)


def test_a_request_is_sent_only_after_the_answer_to_the_one_before():
    first = {"dispatchMonotonic": 1.0, "responseMonotonic": 2.0, "dispatchUtc": "2026-09-30T00:00:01.000Z", "responseUtc": "2026-09-30T00:00:02.000Z"}
    collector_module.check_order(first, {"dispatchMonotonic": 2.0, "responseMonotonic": 3.0, "dispatchUtc": "2026-09-30T00:00:02.000Z", "responseUtc": "2026-09-30T00:00:03.000Z"})
    for bad in [{"dispatchMonotonic": 1.9, "responseMonotonic": 3.0, "dispatchUtc": "2026-09-30T00:00:02.000Z", "responseUtc": "2026-09-30T00:00:03.000Z"},
                {"dispatchMonotonic": 2.0, "responseMonotonic": 3.0, "dispatchUtc": "2026-09-30T00:00:01.500Z", "responseUtc": "2026-09-30T00:00:02.500Z"}]:
        with pytest.raises(ValueError, match="overlap|order"):
            collector_module.check_order(first, bad)


# --- projection only freezes what the rows derive ---

def clean():
    receipt_ = fixture()[0].run()
    assert receipt_["complete"] is True
    return receipt_


def cleanup_variant():
    table = without(support.TABLE, "r/rollback", "r/rollback-again", "g/rollback", "g/rollback-again")
    collector, *_ = fixture(table)
    receipt_ = collector.run()
    assert receipt_["complete"] is True and receipt_["phaseRequests"]["tokenCleanup"] == 2
    return table, receipt_


@pytest.mark.parametrize("key,value", [("complete", False), ("graphComplete", False), ("journalFailure", True), ("unrecovered", True), ("failureType", "ValueError"), ("openTokens", ["x"]), ("unknownStarts", ["x"]), ("unknownRollbacks", ["x"]), ("unknownCommits", ["x"]), ("cleanup", {"absent": False}), ("kind", "other"), ("timingMode", "control-clock"), ("timingSource", "local-control-clock")])
def test_every_completion_flag_is_required_by_the_projection(key, value):
    changed = clean()
    changed[key] = value
    with pytest.raises(ValueError):
        collector_module.projection(changed, support.TABLE)


@pytest.mark.parametrize("mutation", ["sandbox-count", "phase-count", "cleanup-count", "unknown-phase-key", "negative", "over-cap"])
def test_request_accounting_must_add_up(mutation):
    changed = clean()
    if mutation == "sandbox-count": changed["sandboxRequests"] += 1
    elif mutation == "phase-count": changed["phaseRequests"]["management"] += 1
    elif mutation == "cleanup-count": changed["phaseRequests"]["documentCleanup"] += 1; changed["sandboxRequests"] += 1
    elif mutation == "unknown-phase-key": changed["phaseRequests"]["extra"] = 0
    elif mutation == "negative": changed["phaseRequests"]["credential"] = -1; changed["sandboxRequests"] -= 1
    else: changed["phaseRequests"]["observation"] = 999; changed["sandboxRequests"] = 999 + 3
    with pytest.raises(ValueError):
        collector_module.projection(changed, support.TABLE)


def test_rows_must_arrive_in_their_declared_order_and_numbering():
    changed = clean()
    changed["steps"][3], changed["steps"][4] = changed["steps"][4], changed["steps"][3]
    with pytest.raises(ValueError, match="sequence"):
        collector_module.projection(changed, support.TABLE)
    changed = clean()
    a, b = changed["steps"][3], changed["steps"][4]
    a["sequence"], b["sequence"] = b["sequence"], a["sequence"]
    with pytest.raises(ValueError):
        collector_module.projection(changed, support.TABLE)
    changed = clean()
    changed["steps"][2]["sequence"] = changed["steps"][3]["sequence"]
    with pytest.raises(ValueError, match="sequence"):
        collector_module.projection(changed, support.TABLE)


def test_a_rows_transport_must_be_the_declared_one_on_both_sides_of_the_receipt():
    changed = clean()
    row = changed["steps"][3]
    row["transport"] = "grpc"; row["result"]["transport"] = "grpc"; row["result"]["http"] = None
    with pytest.raises(ValueError, match="closed request graph"):
        collector_module.projection(changed, support.TABLE)


def test_an_outcome_class_that_the_code_does_not_give_is_refused():
    changed = clean()
    assert changed["steps"][3]["caseId"] is None
    changed["steps"][3]["outcomeClass"] = "REFUSED"
    with pytest.raises(ValueError, match="class"):
        collector_module.projection(changed, support.TABLE)


def test_a_rows_declared_request_and_case_are_rechecked():
    changed = clean()
    changed["steps"][4]["request"]["name"] = changed["steps"][4]["request"]["name"].replace("/a", "/m")
    with pytest.raises(ValueError):
        collector_module.projection(changed, support.TABLE)
    changed = clean()
    changed["steps"][5]["caseId"] = "renamed"
    with pytest.raises(ValueError):
        collector_module.projection(changed, support.TABLE)


def test_projection_replays_the_chain_release_and_final_recovery_order():
    table, receipt_ = cleanup_variant()
    collector_module.projection(receipt_, table)
    releases = [row for row in receipt_["cleanupSteps"] if row["phase"] == "tokenCleanup"]
    documents = [row for row in receipt_["cleanupSteps"] if row["phase"] == "documentCleanup"]
    assert len(releases) == 2 and len(documents) == 3
    changed = copy.deepcopy(receipt_)
    first = next(row for row in changed["cleanupSteps"] if row["phase"] == "tokenCleanup")
    first["request"] = {**first["request"], "transaction": "AAAA"}
    with pytest.raises(ValueError, match="release"):
        collector_module.projection(changed, table)
    changed = copy.deepcopy(receipt_)
    first = next(row for row in changed["cleanupSteps"] if row["phase"] == "tokenCleanup")
    first["site"] = "cleanup/token/grpc-g"
    with pytest.raises(ValueError, match="release"):
        collector_module.projection(changed, table)
    changed = copy.deepcopy(receipt_)
    release = next(row for row in changed["cleanupSteps"] if row["phase"] == "tokenCleanup")
    document = next(row for row in changed["cleanupSteps"] if row["phase"] == "documentCleanup")
    release["sequence"], document["sequence"] = document["sequence"], release["sequence"]
    with pytest.raises(ValueError):
        collector_module.projection(changed, table)
    changed = copy.deepcopy(receipt_)
    changed["cleanupSteps"] = [row for row in changed["cleanupSteps"] if row["phase"] != "tokenCleanup"]
    changed["phaseRequests"]["tokenCleanup"] = 0; changed["sandboxRequests"] -= 2
    with pytest.raises(ValueError):
        collector_module.projection(changed, table)


def test_projection_replays_the_cleanup_requests():
    changed = clean()
    delete = next(row for row in changed["cleanupSteps"] if row["rpc"] == "DeleteDocument")
    delete["request"] = {**delete["request"], "currentDocument": {"updateTime": {"seconds": "1", "nanos": 1}}}
    with pytest.raises(ValueError, match="cleanup"):
        collector_module.projection(changed, support.TABLE)
    changed = clean()
    next(row for row in changed["cleanupSteps"] if row["rpc"] == "DeleteDocument")["transport"] = "rest"
    with pytest.raises(ValueError, match="cleanup"):
        collector_module.projection(changed, support.TABLE)
    changed = clean()
    changed["cleanupSteps"][0]["site"] = "cleanup/verify/a"
    with pytest.raises(ValueError, match="cleanup"):
        collector_module.projection(changed, support.TABLE)


def test_projection_refuses_rows_that_overlap_or_ran_out_of_order():
    changed = clean()
    changed["steps"][2]["timing"], changed["steps"][0]["timing"] = changed["steps"][0]["timing"], changed["steps"][2]["timing"]
    with pytest.raises(ValueError):
        collector_module.projection(changed, support.TABLE)
    changed = clean()
    later = changed["steps"][1]["timing"]
    changed["steps"][1]["timing"] = {**later, "dispatchMonotonic": changed["steps"][0]["timing"]["responseMonotonic"] - 0.001, "responseMonotonic": later["responseMonotonic"]}
    with pytest.raises(ValueError):
        collector_module.projection(changed, support.TABLE)


def test_details_are_masked_of_tokens_the_run_and_the_owner():
    collector, service, *_ = fixture()
    def leak(result):
        return {**result, "details": f"token {service_tokens(service)} run {NONCE} owner {OWNER}"}
    def service_tokens(_service):
        return next(iter(_service.tokens))
    tamper(service, lambda n, t, m, r: m == "Commit" and "transaction" in r and n > 5, leak)
    receipt_ = collector.run()
    projected = collector_module.projection(receipt_, support.TABLE)
    detail = next(case["details"] for case in projected["cases"] if case["caseId"] == "rest/fail-commit")
    assert detail == "token <token:rest-r> run <nonce> owner <owner>"


def test_a_backwards_monotonic_clock_is_refused_directly():
    collector, *_ = fixture()
    readings = iter([100.0, 99.0])
    collector.monotonic = lambda: next(readings)
    collector._last_monotonic = 100.0
    assert collector._now() == 100.0
    with pytest.raises(ValueError, match="clock"):
        collector._now()
    collector.monotonic = lambda: float("nan")
    with pytest.raises(ValueError, match="clock"):
        collector._now()
