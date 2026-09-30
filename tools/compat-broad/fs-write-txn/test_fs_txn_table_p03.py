"""P03's table and the read-time rules it needs: the shape it declares, and the recordings it produces."""

import copy

import pytest

import fs_txn_table_p03 as p03
import txn_program_cli as cli
from txn_program_collector import Collector, Ledger, parse_time, projection
from txn_program_program import RequestBudget, compile_plan, corpus_digest, request_for_step
from test_txn_program_collector import Clock, Service
from test_txn_program_hardening import receipt, timing

TABLE = p03.TABLE
NONCE, OWNER = "a" * 32, "b" * 32


def plan():
    return compile_plan(TABLE, NONCE, OWNER)


def record(**knobs):
    clock = Clock()
    value = plan()
    service = Service(clock, **knobs)
    return Collector(value, TABLE, RequestBudget(value, TABLE), service, "owner", save=lambda _state: None, monotonic=clock.now, utc=clock.utc).run(), service


def test_the_table_is_registered_and_bound():
    assert cli.TABLES["p03-readtime"] == "fs_txn_table_p03" and cli.table_for("p03-readtime") is TABLE
    assert "tools/compat-broad/fs-write-txn/fs_txn_table_p03.py" in cli.source_manifest("p03-readtime")


def test_the_requests_stay_inside_the_corpus_cap():
    value = plan()
    assert len(value["steps"]) == 24 and len(value["cases"]) == 15
    assert value["caps"] == {"observation": 24, "tokenCleanup": 4, "documentCleanup": 14, "management": 7, "credential": 2}
    assert value["maxRequests"] == 51 <= 72 and value["maxTokens"] == 4
    assert TABLE["envelopeId"] == "FS-TRANSACTION-p03-readtime-001"


def test_a_has_three_acknowledged_versions_before_any_read_at_a_time():
    ids = [step["id"] for step in plan()["steps"]]
    assert ids[:5] == ["setup/absence-a", "setup/absence-m", "setup/create-a", "setup/update-a-1", "setup/update-a-2"]
    reads = [step for step in plan()["steps"] if "readAt" in step]
    v0, v1 = "setup/create-a", "setup/update-a-1"
    assert {step["id"]: step["readAt"]["commit"] for step in reads} == {"rest/get-at-v1": v1, "rest/get-at-v0": v0, "rest/batch-at-v1": v1, "rest/ro/begin": v1, "grpc/get-at-v1": v1, "grpc/batch-at-v1": v1, "grpc/ro/begin": v1}
    assert all(step["allow"] == [0] for step in plan()["steps"] if step["id"].startswith("setup/") and step["rpc"] == "Commit"), "a read time names only commits that must succeed"
    assert all(step["readAt"]["document"] == "a" for step in reads)


def test_the_embedded_transaction_is_begun_by_the_batch_and_the_read_only_one_by_its_begin():
    value = plan()
    begins = {step["id"]: step for step in value["steps"] if step["tokenOutput"]}
    assert set(begins) == {"rest/ro/begin", "rest/emb/batch-new", "grpc/ro/begin", "grpc/emb/batch-new"}
    assert begins["rest/emb/batch-new"]["newTransaction"] == "readWrite" and begins["rest/emb/batch-new"]["rpc"] == "BatchGetDocuments"
    assert begins["rest/ro/begin"]["mode"] == "readOnly" and begins["rest/ro/begin"]["rpc"] == "BeginTransaction"


def test_every_state_label_is_declared_and_used():
    assert len(set(TABLE["states"])) == len(TABLE["states"]) == 5
    assert {write["state"] for step in plan()["steps"] for write in step["writes"]} == set(TABLE["states"])


def test_the_digest_binds_the_table():
    assert corpus_digest(TABLE) == plan()["corpusDigest"]
    assert corpus_digest(TABLE) == "68f373dcbef6da967eba9cca9d34b2c1a7b5c420f9eafaded84453abe968f290"


def test_a_full_recording_completes_and_the_reads_show_the_versions_asked_for():
    receipt_, service = record()
    assert receipt_["complete"] is True, receipt_["failureType"]
    projected = projection(receipt_, TABLE)
    reads = {read["site"]: read for read in projected["reads"]}
    assert reads["rest/current-a"]["state"] == "v2"
    assert reads["rest/get-at-v1"]["state"] == "v1" and reads["rest/get-at-v0"]["state"] == "created"
    assert reads["rest/batch-at-v1"]["documents"] == {"a": "v1", "m": None}
    assert reads["rest/ro/read-a"]["state"] == "v1" and reads["rest/ro/batch"]["documents"]["a"] == "v1"
    assert reads["rest/emb/get-a"]["state"] == "v2" and reads["rest/emb/batch-new"]["documents"] == {"a": "v2", "m": None}
    assert reads["grpc/current-a"]["state"] == "rest-emb-commit" and reads["grpc/get-at-v1"]["state"] == "v1" and reads["grpc/ro/read-a"]["state"] == "v1"
    assert {entry["state"] for entry in projected["tokens"].values()} == {"committed", "rolled-back"}
    assert receipt_["phaseRequests"]["observation"] == 24


def test_the_read_times_are_the_acknowledged_times_and_each_transport_spells_them_its_way():
    receipt_, service = record()
    ledger_times = {}
    for call in service.calls:
        if call[1] == "GetDocument" and "readTime" in call[2]:
            ledger_times.setdefault(call[0], []).append(call[2]["readTime"])
    assert ledger_times["rest"][0] == {"seconds": "1788004860", "nanos": 2}, "version 1 was acknowledged at nanos 2 in the stand-in's clock"
    assert all(set(moment) == {"seconds", "nanos"} for moments in ledger_times.values() for moment in moments)


def test_a_read_at_a_time_that_shows_another_version_stops():
    receipt_, service = record()
    assert receipt_["complete"] is True
    clock = Clock()
    value = plan()
    service = Service(clock)
    original = service._at
    service._at = lambda name, moment: original(name, {"nanos": moment["nanos"] + 1})
    stopped = Collector(value, TABLE, RequestBudget(value, TABLE), service, "owner", save=lambda _state: None, monotonic=clock.now, utc=clock.utc).run()
    assert stopped["complete"] is False and stopped["failureType"] == "ValueError"
    assert stopped["cleanup"] == {"absent": True}


def test_a_read_only_transaction_at_a_time_shows_that_time_only():
    receipt_, _service = record()
    projected = projection(receipt_, TABLE)
    assert {read["site"]: read["state"] for read in projected["reads"] if "state" in read}["rest/ro/read-a"] == "v1"


def test_two_recordings_of_one_service_project_identically():
    assert projection(record()[0], TABLE) == projection(record()[0], TABLE)


def _ledger_with_versions():
    ledger = Ledger(plan())
    ledger.docs["a"].update(status="created", state="v2"); ledger.docs["m"].update(status="confirmed-absent")
    ledger.history["a"].extend(["created", "v1", "v2"])
    ledger.versions["a"] = [("created", (100, 1)), ("v1", (100, 2)), ("v2", (101, 0))]
    ledger.acked_at = {"a@setup/create-a": (100, 1), "a@setup/update-a-1": (100, 2), "a@setup/update-a-2": (101, 0)}
    return ledger


def test_the_state_at_a_time_is_the_latest_version_at_or_before_it():
    ledger = _ledger_with_versions()
    assert [ledger._state_at("a", moment) for moment in [(99, 0), (100, 1), (100, 2), (100, 999), (101, 0), (500, 0)]] == [None, "created", "v1", "v1", "v2", "v2"]
    assert ledger.times() == {"a@setup/create-a": {"seconds": "100", "nanos": 1}, "a@setup/update-a-1": {"seconds": "100", "nanos": 2}, "a@setup/update-a-2": {"seconds": "101", "nanos": 0}}


@pytest.mark.parametrize("value,transport,expected", [
    ({"seconds": "5", "nanos": 7}, "grpc", (5, 7)), ({"seconds": "5"}, "grpc", (5, 0)),
    ("1970-01-01T00:00:05.000000007Z", "rest", (5, 7)), ("1970-01-01T00:00:05Z", "rest", (5, 0)), ("1970-01-01T00:00:05.5Z", "rest", (5, 500000000)),
])
def test_stamps_of_both_forms_parse_to_seconds_and_nanos(value, transport, expected):
    assert parse_time(value, transport) == expected


def test_a_step_reads_only_at_a_version_that_has_been_acknowledged():
    value = plan()
    step = next(step for step in value["steps"] if step["id"] == "rest/get-at-v1")
    ledger = _ledger_with_versions()
    request = request_for_step(value, step, {}, TABLE, ledger.times())
    assert request["readTime"] == {"seconds": "100", "nanos": 2} and "transaction" not in request
    with pytest.raises(ValueError, match="acknowledged"):
        request_for_step(value, step, {}, TABLE, {})
    begin = next(step for step in value["steps"] if step["id"] == "rest/ro/begin")
    assert request_for_step(value, begin, {}, TABLE, ledger.times())["options"] == {"readOnly": {"readTime": {"seconds": "100", "nanos": 2}}}
    batch = next(step for step in value["steps"] if step["id"] == "rest/emb/batch-new")
    assert request_for_step(value, batch, {}, TABLE, ledger.times())["newTransaction"] == {"readWrite": {}}


def _frame_a(state="v2", **extra):
    return {"found": {"name": plan()["documents"]["a"], "fields": {"owner": {"stringValue": OWNER}, "nonce": {"stringValue": NONCE}, "role": {"stringValue": "a"}, "state": {"stringValue": state}}, "updateTime": {"seconds": "101", "nanos": 0}}, **extra}


@pytest.mark.parametrize("label,frames,ok,owned", [
    ("a bare head then the documents", [{"transaction": "dG9rZW4="}, _frame_a(), {"missing": "M"}], True, True),
    ("the transaction on the first document", [_frame_a(transaction="dG9rZW4="), {"missing": "M"}], True, True),
    ("a head an unset decoder member decorates", [{"transaction": "dG9rZW4=", "found": None, "result": ""}, _frame_a(), {"missing": "M"}], True, True),
    ("no transaction at all", [_frame_a(), {"missing": "M"}], False, False),
    ("the transaction on the second document", [_frame_a(), {"missing": "M", "transaction": "dG9rZW4="}], False, False),
    ("a head that also carries a discriminator", [{"transaction": "dG9rZW4=", "result": "found"}, _frame_a(), {"missing": "M"}], False, True),
    ("a head with another key", [{"transaction": "dG9rZW4=", "extra": 1}, _frame_a(), {"missing": "M"}], False, True),
    ("two bare heads", [{"transaction": "dG9rZW4="}, {"transaction": "dG9rZW4="}, _frame_a(), {"missing": "M"}], False, True),
    ("a head and too few documents", [{"transaction": "dG9rZW4="}, _frame_a()], False, True),
    ("a malformed transaction", [{"transaction": "not base64!"}, _frame_a(), {"missing": "M"}], False, False),
    ("a transaction that was already issued", [{"transaction": "QUxSRUFEWQ=="}, _frame_a(), {"missing": "M"}], False, False),
])
def test_the_batch_that_begins_a_transaction_hands_over_exactly_one_fresh_transaction(label, frames, ok, owned):
    value = plan()
    ledger = Ledger(value)
    ledger.docs["a"].update(status="created", state="v2"); ledger.docs["m"].update(status="confirmed-absent")
    ledger.history["a"].extend(["created", "v1", "v2"])
    ledger.versions["a"] = [("created", (100, 1)), ("v1", (100, 2)), ("v2", (101, 0))]
    ledger.acked_at = {"a@setup/update-a-1": (100, 2)}
    ledger.tokens["earlier"] = {"value": "QUxSRUFEWQ==", "state": "committed", "transport": "rest", "start": timing(), "lastUse": timing()}
    names = value["documents"]
    frames = [{**frame, "missing": names["m"]} if frame.get("missing") == "M" else frame for frame in copy.deepcopy(frames)]
    step = next(step for step in value["steps"] if step["id"] == "grpc/emb/batch-new")
    request = request_for_step(value, step, {}, TABLE, ledger.times())
    ledger.before("grpc/emb/batch-new", "grpc", "BatchGetDocuments", request, step)
    assert ledger.unknown_starts == {"grpc/emb/batch-new"}
    if ok:
        ledger.after("grpc/emb/batch-new", "grpc", "BatchGetDocuments", request, step, receipt(response={"responses": frames}), timing())
        assert ledger.tokens["grpc-emb"]["state"] == "open" and ledger.modes["grpc-emb"] == "readWrite" and ledger.unknown_starts == set()
    else:
        with pytest.raises(ValueError):
            ledger.after("grpc/emb/batch-new", "grpc", "BatchGetDocuments", request, step, receipt(response={"responses": frames}), timing())
        assert ledger.unknown_starts == {"grpc/emb/batch-new"}, "an unusable answer keeps the responsibility for a transaction that may exist"
        assert ("grpc-emb" in ledger.tokens) is owned, "a valid minted transaction is owned before the entries are judged, an invalid one cannot be"


def test_a_refused_batch_that_begins_a_transaction_releases_its_responsibility():
    value = plan()
    ledger = Ledger(value)
    ledger.docs["a"].update(status="created", state="v2"); ledger.docs["m"].update(status="confirmed-absent")
    step = next(step for step in value["steps"] if step["id"] == "grpc/emb/batch-new")
    request = {"database": value["database"], "documents": [value["documents"]["a"], value["documents"]["m"]], "newTransaction": {"readWrite": {}}}
    ledger.before("grpc/emb/batch-new", "grpc", "BatchGetDocuments", request, step)
    with pytest.raises(ValueError, match="outside the declared set"):
        ledger.after("grpc/emb/batch-new", "grpc", "BatchGetDocuments", request, step, receipt(code=10, details="refused"), timing())
    assert ledger.unknown_starts == set()


def test_a_batch_that_begins_a_transaction_waits_for_every_earlier_token():
    value = plan()
    ledger = Ledger(value)
    ledger.tokens["rest-ro"] = {"value": "dG9rZW4=", "state": "open", "transport": "rest", "start": timing(), "lastUse": timing()}
    step = next(step for step in value["steps"] if step["id"] == "grpc/emb/batch-new")
    with pytest.raises(ValueError, match="unresolved"):
        ledger.guard("BatchGetDocuments", {"database": value["database"], "documents": [], "newTransaction": {"readWrite": {}}}, step)
    ledger.guard("BatchGetDocuments", {"database": value["database"], "documents": []}, step)


def test_a_refused_optional_write_cannot_shift_which_version_a_read_names():
    """The version is named by the commit that acknowledged it, so a writer that was refused changes nothing."""
    receipt_, _service = record(writer_code=0)
    assert receipt_["complete"] is True
    ledger = Ledger(plan())
    ledger.acked_at = {"a@setup/create-a": (100, 1), "a@setup/update-a-2": (101, 0)}
    step = next(step for step in plan()["steps"] if step["id"] == "rest/get-at-v1")
    with pytest.raises(ValueError, match="acknowledged"):
        request_for_step(plan(), step, {}, TABLE, ledger.times())
