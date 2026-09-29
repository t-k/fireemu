"""Recordings follow the closed graph, stop on uncertain ownership and clean up what they own."""

import base64
import copy
import datetime as dt
import importlib

import pytest

NONCE, OWNER = "a" * 32, "b" * 32
support = importlib.import_module("txn_program_support_for_tests")
program = importlib.import_module("txn_program_program")
collector_module = importlib.import_module("txn_program_collector")


class Clock:
    def __init__(self): self.seconds = 100.0
    def now(self): return self.seconds
    def utc(self): return (dt.datetime(2026, 9, 30, tzinfo=dt.timezone.utc) + dt.timedelta(seconds=self.seconds)).isoformat().replace("+00:00", "Z")
    def sleep(self, seconds): self.seconds += seconds


class Service:
    """A stand-in for Firestore over both transports; each knob is one production answer a table may allow."""

    def __init__(self, clock, *, fail_code=9, writer_code=0, writer_applies=None, rollback_code=0, repeat_rollback_code=0, after_commit_rollback_code=10, fail_at=None, foreign_marker=False, duplicate_tokens=False, corrupt=None, existing=None, dead_on_failure=False, dead_rollback_code=10):
        self.clock, self.fail_code, self.writer_code, self.rollback_code = clock, fail_code, writer_code, rollback_code
        self.writer_applies = writer_applies if writer_applies is not None else writer_code == 0
        self.repeat_rollback_code, self.after_commit_rollback_code = repeat_rollback_code, after_commit_rollback_code
        self.fail_at, self.foreign_marker, self.duplicate_tokens, self.corrupt = fail_at, foreign_marker, duplicate_tokens, corrupt
        self.dead_on_failure, self.dead_rollback_code = dead_on_failure, dead_rollback_code
        self.calls, self.documents, self.tokens, self.version = [], {}, {}, 0
        if existing:
            self.documents[existing] = {"name": existing, "fields": {}, "version": self._bump()}

    def _bump(self):
        self.version += 1
        return self.version

    def _stamp(self, transport, version=None):
        version = version or self.version
        return {"seconds": "1788004860", "nanos": version} if transport == "grpc" else f"2026-09-30T00:00:00.{version:09d}Z"

    def _receipt(self, transport, code, *, details="", response=None, complete=True):
        return {"kind": "txn-program-receipt-v1", "transport": transport, "complete": complete, "code": code, "details": details, "response": response, "http": None if transport == "grpc" else (200 if code == 0 else 409), "dispatchedRequests": 1, "childReaped": True}

    def send(self, transport, method, request, **_kwargs):
        self.calls.append((transport, method, copy.deepcopy(request)))
        self.clock.sleep(1 / 64)
        if len(self.calls) == self.fail_at:
            return self._receipt(transport, 14, details="lost", complete=False)
        token = request.get("transaction")
        if method == "BeginTransaction":
            value = base64.b64encode(f"issued-{0 if self.duplicate_tokens else len(self.tokens)}".encode()).decode()
            self.tokens[value] = "open"
            return self._receipt(transport, 0, response={"transaction": value})
        if method == "GetDocument":
            if token and self.tokens.get(token) == "dead":
                return self._receipt(transport, 10, details="The referenced transaction has expired or is no longer valid.")
            document = self.documents.get(request["name"])
            if document is None:
                return self._receipt(transport, 5, details="not found")
            response = {**copy.deepcopy(document), "updateTime": self._stamp(transport, document["version"])}
            del response["version"]
            if self.foreign_marker and token: response["fields"]["owner"]["stringValue"] = "foreign"
            return self._receipt(transport, 0, response=response)
        if method == "BatchGetDocuments":
            if token and self.tokens.get(token) == "dead":
                return self._receipt(transport, 10, details="The referenced transaction has expired or is no longer valid.")
            if token and self.tokens.get(token) in ("committed", "rolled-back"):
                return self._receipt(transport, 10, details="The referenced transaction has expired or is no longer valid.")
            frames = []
            for name in request["documents"]:
                document = self.documents.get(name)
                if document is None:
                    frames.append({"missing": name, "readTime": self._stamp(transport)})
                else:
                    found = {**copy.deepcopy(document), "updateTime": self._stamp(transport, document["version"])}
                    del found["version"]
                    frames.append({"found": found, "readTime": self._stamp(transport)})
            return self._receipt(transport, 0, response={"responses": frames})
        if method == "Commit":
            return self._commit(transport, request, token)
        if method == "Rollback":
            state = self.tokens.get(token)
            if state is None: return self._receipt(transport, 3, details="unknown transaction")
            def answer(code):
                gone = "The referenced transaction has expired or is no longer valid."
                return self._receipt(transport, code, details="" if code == 0 else gone if code == 10 else "refused", response={} if code == 0 else None)
            if state == "dead": return answer(self.dead_rollback_code)
            if state == "open":
                if self.rollback_code == 0: self.tokens[token] = "rolled-back"
                return answer(self.rollback_code)
            if state == "committed": return answer(self.after_commit_rollback_code)
            return answer(self.repeat_rollback_code)
        if method == "DeleteDocument":
            document = self.documents[request["name"]]
            assert request["currentDocument"]["updateTime"] == self._stamp(transport, document["version"])
            del self.documents[request["name"]]
            return self._receipt(transport, 0, response={})
        raise AssertionError(method)

    def _commit(self, transport, request, token):
        writes = request["writes"]
        if token and self.tokens.get(token) in ("committed", "rolled-back"):
            return self._receipt(transport, 10, details="The referenced transaction has expired or is no longer valid.")
        if not writes:
            if self.tokens.get(token) != "open":
                return self._receipt(transport, 10, details="The referenced transaction has expired or is no longer valid.")
            self.tokens[token] = "committed"
            return self._receipt(transport, 0, response={"writeResults": []})
        writer = token is None and request["writes"][0]["currentDocument"]["exists"] is True
        failing = [w for w in writes if w["currentDocument"]["exists"] != (w["update"]["name"] in self.documents)]
        if writer:
            self.clock.sleep(25 if self.writer_code == 10 else 0)
            if self.writer_code == 4:
                if self.writer_applies: self._apply(writes, transport)
                return self._receipt(transport, 4, details="deadline", complete=False)
            if self.writer_code != 0 or failing:
                return self._receipt(transport, self.writer_code or 9, details="contended")
        elif token and self.tokens.get(token) == "dead":
            return self._receipt(transport, 10, details="The referenced transaction has expired or is no longer valid.")
        elif failing and self.fail_code != 0:
            if self.dead_on_failure: self.tokens[token] = "dead"
            return self._receipt(transport, self.fail_code, details="precondition")
        elif self.fail_code == 0 and token and any(w["currentDocument"]["exists"] and w["update"]["name"] not in self.documents for w in writes):
            for w in writes: w["currentDocument"]["exists"] = False
        results = self._apply(writes, transport)
        if token: self.tokens[token] = "committed"
        return self._receipt(transport, 0, response={"writeResults": results})

    def _apply(self, writes, transport):
        results = []
        for write in writes:
            version = self._bump()
            self.documents[write["update"]["name"]] = {"name": write["update"]["name"], "fields": copy.deepcopy(write["update"]["fields"]), "version": version}
            results.append({"updateTime": self._stamp(transport, version)})
        return results


def fixture(table=None, **knobs):
    table = table or support.TABLE
    clock = Clock()
    plan = program.compile_plan(table, NONCE, OWNER)
    service = Service(clock, **knobs)
    budget, journal = program.RequestBudget(plan, table), []
    collector = collector_module.Collector(plan, table, budget, service, "owner", save=lambda value: journal.append(copy.deepcopy(value)), monotonic=clock.now, utc=clock.utc)
    return collector, service, budget, journal, clock, plan


def without(table, *ids):
    changed = copy.deepcopy(table)
    changed["steps"] = tuple(step for step in table["steps"] if step["id"] not in ids)
    changed["caps"] = {**table["caps"], "observation": len(changed["steps"])}
    return changed


def test_a_clean_recording_uses_both_transports_and_cleans_up():
    collector, service, budget, journal, _clock, plan = fixture()
    receipt = collector.run()
    assert receipt["complete"] is True and receipt["graphComplete"] is True and receipt["unrecovered"] is False
    assert {call[0] for call in service.calls} == {"rest", "grpc"}
    assert receipt["phaseRequests"] == {"observation": 19, "tokenCleanup": 0, "documentCleanup": 3, "management": 0, "credential": 0}
    assert service.documents == {}
    assert receipt["cleanup"] == {"absent": True}
    assert {role: entry["state"] for role, entry in receipt["tokens"].items()} == {"rest-r": "rolled-back", "grpc-g": "rolled-back"}
    assert receipt["documents"]["a"]["status"] == "confirmed-absent" and receipt["documents"]["m"]["status"] == "confirmed-absent"
    projected = collector_module.projection(receipt, support.TABLE)
    assert [case["caseId"] for case in projected["cases"]] == plan["cases"]
    assert projected["expectedStates"] == {"a": "moved"}
    assert all(row["outcomeClass"] in ("OK", "REFUSED") for row in receipt["steps"])
    assert journal and journal[-1]["pending"] is None


def test_two_recordings_of_one_service_project_identically():
    first = collector_module.projection(fixture()[0].run(), support.TABLE)
    second = collector_module.projection(fixture()[0].run(), support.TABLE)
    assert first == second


def test_the_failed_commit_is_recorded_as_a_refusal_and_leaves_the_state_unpublished():
    receipt = fixture()[0].run()
    cases = {case["caseId"]: case for case in collector_module.projection(receipt, support.TABLE)["cases"]}
    assert cases["rest/fail-commit"]["outcomeClass"] == "REFUSED" and cases["rest/fail-commit"]["code"] == 9
    reads = {read["site"]: read for read in collector_module.projection(receipt, support.TABLE)["reads"]}
    assert reads["r/plain-read"]["state"] == "created"


@pytest.mark.parametrize("writer_code", [0, 10])
def test_the_outside_writer_may_proceed_or_be_refused_by_contention(writer_code):
    receipt = fixture(writer_code=writer_code)[0].run()
    assert receipt["complete"] is True
    projected = collector_module.projection(receipt, support.TABLE)
    assert projected["expectedStates"] == {"a": "moved" if writer_code == 0 else "created"}


@pytest.mark.parametrize("applies", [True, False])
def test_a_writer_timeout_is_unknown_and_never_resent(applies):
    collector, service, budget, journal, _clock, _plan = fixture(writer_code=4, writer_applies=applies)
    receipt = collector.run()
    assert receipt["complete"] is False and receipt["unrecovered"] is True
    assert receipt["unknownCommits"] == ["r/writer"]
    assert sum(1 for call in service.calls if call[1] == "Commit" and "transaction" not in call[2] and call[2]["writes"][0]["update"]["fields"]["state"]["stringValue"] == "moved") == 1
    assert service.documents == {}, "the owned document is still cleaned up, whether or not the write landed"
    assert receipt["cleanup"] == {"absent": True}
    assert receipt["phaseRequests"]["tokenCleanup"] == 1, "the token the stop left open is released once"


def test_an_unknown_start_or_rollback_keeps_its_responsibility():
    for fail_at, key in [(4, "unknownStarts"), (9, "unknownRollbacks")]:
        collector, service, _budget, _journal, _clock, _plan = fixture(fail_at=fail_at)
        receipt = collector.run()
        assert receipt["complete"] is False and receipt[key], key
        began = [call for call in service.calls if call[1] == "BeginTransaction"]
        rolled = [call for call in service.calls if call[1] == "Rollback"]
        assert len(began) == 1, "the graph stops before the next chain"
        assert len(rolled) == (0 if key == "unknownStarts" else 1), "an unknown outcome is never resent"


def test_a_commit_the_service_accepts_against_the_declared_refusal_still_cleans_up_what_it_created():
    collector, service, _budget, _journal, _clock, _plan = fixture(fail_code=0)
    receipt = collector.run()
    assert receipt["complete"] is False and receipt["failureType"] == "ValueError"
    assert service.documents == {}
    assert receipt["cleanup"] == {"absent": True}
    assert receipt["phaseRequests"]["documentCleanup"] == 6, "both a and m were created, so both are read, deleted and verified"


def test_a_refused_rollback_the_table_allows_finishes_the_token_as_refused():
    receipt = fixture(rollback_code=10)[0].run()
    assert receipt["complete"] is True
    assert {entry["state"] for entry in receipt["tokens"].values()} == {"released-refused"}


def test_an_undeclared_rollback_refusal_leaves_the_token_open_for_one_recovery_release():
    collector, service, _budget, _journal, _clock, _plan = fixture(rollback_code=7)
    receipt = collector.run()
    assert receipt["complete"] is False
    assert receipt["phaseRequests"]["tokenCleanup"] == 1
    assert receipt["openTokens"] == ["rest-r"] and receipt["unrecovered"] is True


def test_a_chain_that_ends_with_its_token_open_releases_it_before_the_next_chain():
    table = without(support.TABLE, "r/rollback", "r/rollback-again", "g/rollback", "g/rollback-again")
    collector, service, _budget, _journal, _clock, _plan = fixture(table)
    receipt = collector.run()
    assert receipt["complete"] is True
    assert receipt["phaseRequests"]["tokenCleanup"] == 2
    order = [(call[0], call[1]) for call in service.calls]
    assert order.index(("rest", "Rollback")) < order.index(("grpc", "BeginTransaction"))
    projected = collector_module.projection(receipt, table)
    assert {entry["state"] for entry in projected["tokens"].values()} == {"rolled-back"}


def test_a_chain_release_that_is_refused_forbids_the_next_chain():
    table = without(support.TABLE, "r/rollback", "r/rollback-again", "g/rollback", "g/rollback-again")
    collector, service, _budget, _journal, _clock, _plan = fixture(table, rollback_code=5)
    receipt = collector.run()
    assert receipt["complete"] is False
    assert not any(call[0] == "grpc" and call[1] == "BeginTransaction" for call in service.calls)


def test_a_chain_release_answered_with_the_gone_text_finishes_the_token_and_the_chain_goes_on():
    table = without(support.TABLE, "r/rollback", "r/rollback-again", "g/rollback", "g/rollback-again")
    collector, service, _budget, _journal, _clock, _plan = fixture(table, rollback_code=10)
    receipt = collector.run()
    assert receipt["complete"] is True and receipt["unrecovered"] is False
    assert {entry["state"] for entry in receipt["tokens"].values()} == {"released-refused"}
    assert any(call[0] == "grpc" and call[1] == "BeginTransaction" for call in service.calls)
    collector_module.projection(receipt, table)


def test_a_finished_token_probe_never_changes_the_token():
    receipt = fixture(repeat_rollback_code=10)[0].run()
    assert receipt["complete"] is True
    assert {entry["state"] for entry in receipt["tokens"].values()} == {"rolled-back"}
    cases = {case["caseId"]: case for case in collector_module.projection(receipt, support.TABLE)["cases"]}
    assert cases["rest/rollback-again"]["code"] == 10


def test_a_document_that_already_exists_is_never_written_or_deleted():
    plan = program.compile_plan(support.TABLE, NONCE, OWNER)
    collector, service, _budget, _journal, _clock, _plan = fixture(existing=plan["documents"]["a"])
    receipt = collector.run()
    assert receipt["complete"] is False and receipt["documents"]["a"]["status"] == "pre-existing"
    assert [call[1] for call in service.calls] == ["GetDocument", "GetDocument"] or receipt["phaseRequests"]["observation"] == 1
    assert not any(call[1] in ("Commit", "DeleteDocument") for call in service.calls)


def test_a_foreign_owner_marker_stops_the_recording():
    receipt = fixture(foreign_marker=True)[0].run()
    assert receipt["complete"] is False and receipt["failureType"] == "ValueError"


def test_a_duplicate_minted_token_stops_the_recording():
    receipt = fixture(duplicate_tokens=True)[0].run()
    assert receipt["complete"] is False


def test_a_native_receipt_that_disagrees_with_its_dispatch_stops():
    for change in [{"transport": "grpc"}, {"dispatchedRequests": 2}, {"childReaped": False}, {"complete": False}, {"kind": "txn-p10b-grpc-receipt-v1"}]:
        collector, service, _budget, _journal, _clock, _plan = fixture()
        original = service.send
        def send(transport, method, request, _original=original, _change=change, **kwargs):
            result = _original(transport, method, request, **kwargs)
            return {**result, **_change} if len(service.calls) == 5 and transport == "rest" else result
        service.send = send
        receipt = collector.run()
        assert receipt["complete"] is False, change


def test_a_journal_failure_stops_all_dispatch():
    collector, service, _budget, journal, _clock, _plan = fixture()
    calls = []
    def save(value):
        calls.append(value)
        if len(calls) == 6: raise OSError("disk full")
    collector.save = save
    receipt = collector.run()
    assert receipt["journalFailure"] is True and receipt["complete"] is False
    dispatched = len(service.calls)
    assert dispatched <= 6


def test_a_pending_dispatch_is_journaled_before_the_send():
    collector, service, _budget, journal, _clock, _plan = fixture()
    seen = []
    original = service.send
    def send(transport, method, request, **kwargs):
        seen.append(copy.deepcopy(journal[-1]["pending"]))
        return original(transport, method, request, **kwargs)
    service.send = send
    collector.run()
    assert all(entry is not None for entry in seen)
    assert seen[0] == {"site": "setup/absence-a", "rpc": "GetDocument", "transport": "grpc"}


def test_the_writer_waits_for_its_own_deadline_and_the_phase_must_fit_it():
    collector, service, _budget, _journal, clock, _plan = fixture()
    collector.observation_deadline = collector.deadline = clock.now() + 20
    receipt = collector.run()
    assert receipt["complete"] is False and receipt["failureType"] == "TimeoutError"
    assert not any(call[1] == "Commit" and "transaction" not in call[2] and call[2]["writes"][0]["currentDocument"]["exists"] for call in service.calls)


def test_a_backwards_clock_stops_the_recording():
    collector, _service, _budget, _journal, clock, _plan = fixture()
    original = collector.monotonic
    ticks = iter(range(10000))
    def monotonic():
        value = original()
        return value - (5 if next(ticks) > 40 else 0)
    collector.monotonic = monotonic
    receipt = collector.run()
    assert receipt["complete"] is False


def test_the_wire_deadline_is_the_steps_own():
    collector, service, _budget, _journal, _clock, _plan = fixture()
    seen = []
    original = service.send
    def send(transport, method, request, **kwargs):
        seen.append((method, "transaction" in request, kwargs["deadline_ms"]))
        return original(transport, method, request, **kwargs)
    service.send = send
    collector.run()
    writer = [entry for entry in seen if entry[0] == "Commit" and not entry[1]][1:]
    assert {entry[2] for entry in writer} == {30000}
    assert {entry[2] for entry in seen if entry not in writer} <= {10000}


@pytest.mark.parametrize(
    "mutation",
    ["drop-row", "swap-request", "state-claim", "token-claim", "case-order", "phase", "class", "cleanup-drop", "sequence", "extra-cleanup", "document-claim", "transport"],
)
def test_projection_only_freezes_what_the_rows_derive(mutation):
    receipt = fixture()[0].run()
    changed = copy.deepcopy(receipt)
    if mutation == "drop-row": changed["steps"].pop(3); changed["phaseRequests"]["observation"] -= 1; changed["sandboxRequests"] -= 1
    elif mutation == "swap-request": changed["steps"][2]["request"]["writes"][0]["update"]["fields"]["state"]["stringValue"] = "moved"
    elif mutation == "state-claim": changed["documents"]["a"]["state"] = "held"
    elif mutation == "token-claim": changed["tokens"]["rest-r"]["state"] = "committed"
    elif mutation == "case-order": changed["observations"].reverse()
    elif mutation == "phase": changed["cleanupSteps"][0]["phase"] = "observation"
    elif mutation == "class": changed["steps"][5]["outcomeClass"] = "OK"
    elif mutation == "cleanup-drop": changed["cleanupSteps"].pop(); changed["phaseRequests"]["documentCleanup"] -= 1; changed["sandboxRequests"] -= 1
    elif mutation == "sequence": changed["steps"][0]["sequence"] = 99
    elif mutation == "extra-cleanup": changed["cleanupSteps"].append(copy.deepcopy(changed["cleanupSteps"][-1])); changed["cleanupSteps"][-1]["sequence"] = 99
    elif mutation == "document-claim": changed["documents"]["m"]["status"] = "created"
    else: changed["steps"][4]["transport"] = "grpc"
    with pytest.raises(ValueError):
        collector_module.projection(changed, support.TABLE)


def test_projection_refuses_an_incomplete_recording():
    receipt = fixture(writer_code=4)[0].run()
    with pytest.raises(ValueError, match="complete"):
        collector_module.projection(receipt, support.TABLE)


def test_projection_binds_the_receipt_to_its_table():
    receipt = fixture()[0].run()
    changed = copy.deepcopy(support.TABLE)
    changed["steps"] = tuple(dict(step, allow=(0, 5, 9, 10)) if step["id"] == "r/fail-commit" else step for step in changed["steps"])
    with pytest.raises(ValueError, match="source binding"):
        collector_module.projection(receipt, changed)
