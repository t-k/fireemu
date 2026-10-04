"""P14 against a stand-in Firestore: every outcome its allow sets admit finishes the recording, and the two the table does not admit stop it at its last steps.

The stand-in is the framework's own fake service with the P14 additions: queries over the run's collection (with the self-cancel), literal tokens refused as production
refuses an unknown token, and a read at a time ago answered by the one-hour retention (accepted within it, refused beyond it, a begin accepted or refused as told)."""

import base64
import copy
import datetime as dt

import pytest

import fs_txn_table_p14 as p14
import txn_program_collector as collector_module
from txn_program_program import LITERAL_TOKENS, RequestBudget, compile_plan
from test_txn_program_collector import Clock, Service, collector_module as _collector

NONCE, OWNER = "a" * 32, "b" * 32
TOO_OLD = "The requested 'read_time' is too old."
EPOCH = dt.datetime(2026, 9, 30, tzinfo=dt.timezone.utc).timestamp()


class P14Service(Service):
    def __init__(self, clock, plan, *, begin_59="accept", begin_61=9, refuse_writes_to=(), **knobs):
        super().__init__(clock, **knobs)
        self.plan, self.begin_59, self.begin_61, self.refuse_writes_to = plan, begin_59, begin_61, set(refuse_writes_to)
        self.roles = {name: role for role, name in plan["documents"].items()}

    def _refusal(self, transport, code, details):
        return self._receipt(transport, code, details=details)

    def send(self, transport, method, request, **kwargs):
        token = request.get("transaction")
        if token in LITERAL_TOKENS.values():
            text = "Invalid value at 'transaction' (TYPE_BYTES), Base64 decoding failed" if token == LITERAL_TOKENS["malformed"] else "Invalid transaction."
            self.calls.append((transport, method, copy.deepcopy(request)))
            return self._refusal(transport, 3, text)
        if method == "RunQuery":
            return self._query(transport, request, kwargs.get("cancel_after"))
        read_time = request.get("readTime") or request.get("options", {}).get("readOnly", {}).get("readTime")
        if read_time is not None:
            return self._read_ago(transport, method, request, read_time)
        setup = any(write["update"]["fields"]["state"]["stringValue"] == "created" for write in request.get("writes", []))   # the setup commit is never refused
        if method == "Commit" and token is None and not setup and any(self.roles.get(write["update"]["name"]) in self.refuse_writes_to for write in request["writes"]):
            self.calls.append((transport, method, copy.deepcopy(request)))
            return self._refusal(transport, 10, "Too much contention on these documents. Please try again.")
        return super().send(transport, method, request, **kwargs)

    def _query(self, transport, request, cancel_after):
        self.calls.append((transport, "RunQuery", copy.deepcopy(request)))
        self.clock.sleep(self.rpc_seconds)
        token = request.get("transaction")
        if token is not None and self.tokens.get(token) != "open":
            return self._refusal(transport, 10, "The referenced transaction has expired or is no longer valid.")
        where = request["structuredQuery"].get("where")
        wanted = where["fieldFilter"]["value"]["stringValue"] if where else None
        frames = []
        for name in sorted(self.documents):
            document = self.documents[name]
            if not name.startswith(request["parent"] + "/"):
                continue
            if wanted is not None and document["fields"]["state"]["stringValue"] != wanted:
                continue
            body = {key: value for key, value in copy.deepcopy(document).items() if key != "version"}
            body["createTime"] = body["updateTime"] = self._stamp(transport, document["version"])
            frames.append({"document": body, "readTime": self._stamp(transport), **({"transaction": "", "skippedResults": 0, "explainMetrics": None} if transport == "grpc" else {})})
            if token and self.locks:
                self.locked.setdefault(token, set()).add(name)
        frames.append({"readTime": self._stamp(transport), **({"transaction": "", "skippedResults": 0, "explainMetrics": None} if transport == "grpc" else {})})
        if cancel_after is not None:
            return self._receipt(transport, 1, details=f"cancelled by the client after {cancel_after} frame(s)", response={"responses": frames[:cancel_after]})
        return self._receipt(transport, 0, response={"responses": frames})

    def _read_ago(self, transport, method, request, read_time):
        self.calls.append((transport, method, copy.deepcopy(request)))
        self.clock.sleep(self.rpc_seconds)
        seconds = int(read_time["seconds"]) if isinstance(read_time, dict) else int(dt.datetime.fromisoformat(read_time.replace("Z", "+00:00")).timestamp())
        ago = round(EPOCH + self.clock.now() - seconds)
        old = ago > 3600
        if method == "BeginTransaction":
            outcome = self.begin_61 if old else self.begin_59
            if outcome == "accept" or outcome == 0:
                value = base64.b64encode(f"issued-{len(self.tokens)}".encode()).decode()
                self.tokens[value] = "open"
                self.readonly.add(value)
                self.tstart[value] = self.tlast[value] = self.clock.now()
                return self._receipt(transport, 0, response={"transaction": value})
            return self._refusal(transport, outcome, TOO_OLD)
        if old:
            return self._refusal(transport, 9, TOO_OLD)
        if method == "GetDocument":
            return self._refusal(transport, 5, "Document not found.")
        frames = [{"missing": name, "readTime": self._stamp(transport), **({"transaction": "", "result": "missing"} if transport == "grpc" else {})} for name in request["documents"]]
        return self._receipt(transport, 0, response={"responses": frames})


def run(**knobs):
    clock = Clock()
    plan = compile_plan(p14.TABLE, NONCE, OWNER)
    service = P14Service(clock, plan, locks=knobs.pop("locks", False), **knobs)
    collector = collector_module.Collector(plan, p14.TABLE, RequestBudget(plan, p14.TABLE), service, "owner", save=lambda _state: None, monotonic=clock.now, utc=clock.utc, sleep=clock.sleep)
    return collector.run(), service


def codes(receipt):
    return {row["site"]: row["result"]["code"] for row in receipt["steps"]}


def test_the_expected_answers_finish_the_recording_and_replay():
    receipt, service = run()
    assert receipt["complete"] is True and receipt["graphComplete"] is True and receipt["unrecovered"] is False
    answers = codes(receipt)
    assert answers["rest/ret/begin-59"] == 0 and answers["rest/ret/begin-61"] == 9 and answers["rest/ret/get-61"] == 9 and answers["rest/ret/get-59"] == 5
    assert answers["grpc/pg/query-cancelled"] == 1 and answers["rest/tv/get-malformed"] == 3 and answers["grpc/tv/rollback-unknown"] == 3
    projected = collector_module.projection(receipt, p14.TABLE)
    assert len(projected["cases"]) == 46 == len(compile_plan(p14.TABLE, NONCE, OWNER)["cases"])


@pytest.mark.parametrize("refused", [("o",), ("p",), ("p2",), ("h",), ("o", "p", "p2", "h"), ("c", "d")])
def test_a_range_or_paging_or_spare_writer_that_production_refuses_with_10_still_finishes_the_recording(refused):
    # the documents it would have created are then absent: the post reads answer 5 and the recording goes on to its retention rows
    receipt, _service = run(refuse_writes_to=refused)
    answers = codes(receipt)
    assert receipt["complete"] is True and receipt["unrecovered"] is False, receipt["failureType"]
    if "o" in refused:
        assert answers["rest/q1/writer"] == 10 and answers["rest/q/post-read-o"] == 5
    if "p" in refused:
        assert answers["rest/q2/writer"] == 10 and answers["rest/q/post-read-p"] == 5
    assert answers["rest/ret/begin-61"] == 9 and collector_module.projection(receipt, p14.TABLE)["cases"]
    # a document a refused writer never created is read once by the recovery and neither deleted nor verified
    for role in refused:
        if role in ("o", "p", "p2"):
            assert [row["site"] for row in receipt["cleanupSteps"] if row["site"].endswith(f"/{role}")] == [f"cleanup/read/{role}"], role
        if role in ("c", "d"):
            # a refused writer that was not sent beside a release has its document restored to absent at once: the recovery has nothing to read
            assert not [row for row in receipt["cleanupSteps"] if row["site"].endswith(f"/{role}")], role


@pytest.mark.parametrize("refusal", [3, 5, 9, 10])
def test_a_61_minute_begin_refused_with_any_allowed_code_finishes_the_recording(refusal):
    receipt, _service = run(begin_61=refusal)
    assert receipt["complete"] is True and codes(receipt)["rest/ret/begin-61"] == refusal
    assert collector_module.projection(receipt, p14.TABLE)["cases"]


def test_held_writers_beside_a_holders_locks_finish_the_recording_too():
    # a writer held until its holder's release (the P05 and P06 shape) answers after the release, in the same recording
    receipt, _service = run(locks=True, hold_writers=True, hold_timeout=5)
    assert receipt["complete"] is True, receipt["failureType"]
    assert collector_module.projection(receipt, p14.TABLE)["cases"]


def test_a_refused_59_minute_begin_is_an_honest_stop_at_the_end_and_loses_no_other_row():
    receipt, service = run(begin_59=9)
    assert receipt["complete"] is False and receipt["failureType"] == "ValueError"
    answers = codes(receipt)
    assert answers["rest/ret/begin-59"] == 9
    # every row before it was recorded; nothing after it was sent, and nothing is owed
    assert [step["id"] for step in compile_plan(p14.TABLE, NONCE, OWNER)["steps"]][-3:] == ["rest/ret/begin-59", "rest/ret/release-59", "rest/ret/begin-61"]
    assert len(answers) == 67 and "rest/ret/release-59" not in answers and "rest/ret/begin-61" not in answers
    assert receipt["unknownStarts"] == [] and receipt["unknownRollbacks"] == [] and receipt["openTokens"] == []


def test_an_accepted_61_minute_begin_is_an_honest_stop_and_the_recovery_releases_its_token():
    receipt, _service = run(begin_61=0)
    assert receipt["complete"] is False and receipt["failureType"] == "ValueError"
    assert codes(receipt)["rest/ret/begin-61"] == 0
    # the read-only token it minted is rolled back by the recovery: nothing is left in production
    assert receipt["tokens"]["ro-61"]["state"] == "rolled-back" and receipt["openTokens"] == [] and receipt["unknownRollbacks"] == []
