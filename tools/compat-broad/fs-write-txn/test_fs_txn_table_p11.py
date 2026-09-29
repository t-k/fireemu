"""P11's table and the wait support it needs: the shape it declares, and the recordings it produces."""

import copy

import pytest

import fs_txn_table_p11 as p11
import txn_program_cli as cli
import txn_program_collector as collector_module
from txn_program_collector import Collector, projection
from txn_program_program import RequestBudget, compile_plan, corpus_digest
from test_txn_program_collector import Clock, Service

TABLE = p11.TABLE
NONCE, OWNER = "a" * 32, "b" * 32


def plan():
    return compile_plan(TABLE, NONCE, OWNER)


def record(table=TABLE, **knobs):
    clock = Clock()
    value = compile_plan(table, NONCE, OWNER)
    service = Service(clock, **knobs)
    collector = Collector(value, table, RequestBudget(value, table), service, "owner", save=lambda _state: None, monotonic=clock.now, utc=clock.utc, sleep=clock.sleep)
    return collector.run(), service, clock


def test_the_table_is_registered_and_bound():
    assert cli.TABLES["p11-lifetime"] == "fs_txn_table_p11" and cli.table_for("p11-lifetime") is TABLE
    assert "tools/compat-broad/fs-write-txn/fs_txn_table_p11.py" in cli.source_manifest("p11-lifetime")


def test_the_requests_and_waits_stay_inside_their_clock():
    value = plan()
    assert len(value["steps"]) == 35 and len(value["cases"]) == 8
    assert value["caps"] == {"observation": 35, "tokenCleanup": 2, "documentCleanup": 14, "management": 7, "credential": 2}
    assert value["maxRequests"] == 60 and value["maxTokens"] == 2
    assert sum(value["waits"].values()) == 2 * (9 * 24 + 12 + 50) == 556
    assert value["observationSeconds"] == 840 and value["recoverySeconds"] == 180
    assert value["thresholds"] == {"totalAgeSeconds": 270}
    assert TABLE["envelopeId"] == "FS-TRANSACTION-p11-lifetime-001"


def test_every_wait_is_inside_the_idle_limit_and_the_chain_grows_old_by_keepalive():
    for transport in ["rest", "grpc"]:
        chain = [step for step in plan()["steps"] if step["id"].startswith(f"{transport}/")]
        assert [step["id"].split("/", 1)[1] for step in chain][:2] == ["begin", "read-a"] and [step["id"].split("/", 1)[1] for step in chain][-5:] == ["live-read", "expiry-read", "expiry-commit", "writer", "post-read-a"]
        waits = [step["waitSeconds"] for step in chain if "waitSeconds" in step]
        assert waits == [24] * 9 + [12, 50] and max(waits) < 60 and 9 * 24 + 12 + 50 > 270, "even with no per-request time the expiry read is older than the lifetime"
        assert all(step["tokenInput"] for step in chain if "waitSeconds" in step)


def test_only_the_expiry_reads_and_commit_may_be_refused_the_writer_and_setup_may_not_be_a_control():
    for step in plan()["steps"]:
        if step["id"].endswith(("keepalive-1", "live-read", "expiry-read", "expiry-commit")):
            assert step["allow"] == [0, 3, 5, 9, 10]
        if step["id"].endswith("/writer"):
            assert step["allow"] == [0, 10] and step["tokenInput"] is None and step["role"] == "outside-writer"
        if step["id"].endswith(("/begin", "/read-a")) and step["role"] == "control":
            assert step["allow"] == [0]
    assert [step["caseId"] for step in plan()["steps"] if step["caseId"] and "keepalive" in step["id"]] == []


def test_the_digest_binds_the_table():
    assert corpus_digest(TABLE) == plan()["corpusDigest"]
    assert corpus_digest(TABLE) == "d862cd04fe13954bba022dacd19f35cb8d0084feb3d6c9a4c244a11fa847333f"


def test_a_recording_with_the_documented_lifetime_expires_the_token_after_the_live_read():
    receipt, service, clock = record(expiry=True, lifetime=270, idle=120)
    assert receipt["complete"] is True, receipt["failureType"]
    projected = projection(receipt, TABLE)
    cases = {case["caseId"]: case["code"] for case in projected["cases"]}
    assert cases["rest/live-read"] == 0 and cases["rest/expiry-read"] == 10 and cases["rest/expiry-commit"] == 10 and cases["rest/writer"] == 0
    assert cases["grpc/live-read"] == 0 and cases["grpc/expiry-read"] == 10 and cases["grpc/writer"] == 0
    reads = {read["site"]: read["code"] for read in projected["reads"]}
    assert all(reads[f"rest/keepalive-{index}"] == 0 for index in range(1, 10))
    ages = {wait["site"]: wait["ageClass"] for wait in projected["waits"]}
    assert ages["rest/live-read"] == "BEFORE" and ages["rest/expiry-read"] == "AFTER" and ages["rest/keepalive-9"] == "BEFORE"
    assert ages["grpc/live-read"] == "BEFORE" and ages["grpc/expiry-read"] == "AFTER"
    assert all(set(wait) == {"site", "seconds", "ageClass"} for wait in projected["waits"])
    assert len(projected["waits"]) == 22


def test_a_service_whose_lifetime_is_longer_lets_the_expiry_read_through_and_the_commit_wins():
    receipt, _service, _clock = record(expiry=True, lifetime=400, idle=120)
    assert receipt["complete"] is True
    cases = {case["caseId"]: case["code"] for case in projection(receipt, TABLE)["cases"]}
    assert cases["rest/expiry-read"] == 0 and cases["rest/expiry-commit"] == 0
    assert cases["rest/writer"] == 0


def test_a_service_that_expires_the_token_early_is_measured_not_fatal():
    receipt, _service, _clock = record(expiry=True, lifetime=100, idle=120)
    assert receipt["complete"] is True, receipt["failureType"]
    reads = {read["site"]: read["code"] for read in projection(receipt, TABLE)["reads"]}
    assert reads["rest/keepalive-1"] == 0 and reads["rest/keepalive-9"] == 10


def test_each_wait_keeps_its_idle_and_age_bounds_and_lasted_at_least_its_seconds():
    receipt, _service, _clock = record(expiry=True)
    assert len(receipt["waits"]) == 22
    for entry in receipt["waits"]:
        assert entry["idleInterval"]["lowerSeconds"] >= entry["seconds"]
        assert entry["idleInterval"]["upperSeconds"] >= entry["idleInterval"]["lowerSeconds"]
        assert entry["totalAgeInterval"]["upperSeconds"] >= entry["totalAgeInterval"]["lowerSeconds"] >= entry["seconds"]
        assert entry["tokenRole"] in ("rest-k", "grpc-k")
    live = next(entry for entry in receipt["waits"] if entry["site"] == "rest/live-read")
    assert 9 * 24 + 12 <= live["totalAgeInterval"]["lowerSeconds"] < live["totalAgeInterval"]["upperSeconds"] < 270


def test_two_recordings_of_one_service_project_identically():
    assert projection(record(expiry=True)[0], TABLE) == projection(record(expiry=True)[0], TABLE)


def test_a_wait_that_does_not_fit_the_observation_phase_stops_before_it_starts():
    clock = Clock()
    value = plan()
    collector = Collector(value, TABLE, RequestBudget(value, TABLE), Service(clock, expiry=True), "owner", save=lambda _state: None, monotonic=clock.now, utc=clock.utc, sleep=clock.sleep)
    collector.observation_deadline = collector.deadline = clock.now() + 60
    receipt = collector.run()
    assert receipt["complete"] is False and receipt["failureType"] == "TimeoutError"
    assert not any(call[1] == "Commit" and "transaction" in call[2] and call[2]["writes"] for call in collector.wire.calls)


def test_a_wait_that_overshoots_its_slack_stops():
    table = copy.deepcopy(TABLE)
    table["steps"] = tuple(dict(step, waitSeconds=1) if "waitSeconds" in step else step for step in table["steps"])
    clock = Clock()
    value = compile_plan(table, NONCE, OWNER)
    original = clock.sleep
    collector = Collector(value, table, RequestBudget(value, table), Service(clock, expiry=True), "owner", save=lambda _state: None, monotonic=clock.now, utc=clock.utc, sleep=lambda seconds: original(seconds + 5))
    receipt = collector.run()
    assert receipt["complete"] is False and receipt["failureType"] == "TimeoutError"


def test_a_wait_whose_clock_stands_still_stops():
    clock = Clock()
    value = plan()
    collector = Collector(value, TABLE, RequestBudget(value, TABLE), Service(clock, expiry=True), "owner", save=lambda _state: None, monotonic=clock.now, utc=clock.utc, sleep=lambda _seconds: None)
    receipt = collector.run()
    assert receipt["complete"] is False and receipt["failureType"] == "ValueError"


def test_projection_refuses_a_wait_that_did_not_last_or_a_forged_entry():
    receipt, _service, _clock = record(expiry=True)
    changed = copy.deepcopy(receipt)
    changed["waits"][3]["seconds"] = 10
    with pytest.raises(ValueError, match="derived"):
        projection(changed, TABLE)
    changed = copy.deepcopy(receipt)
    changed["waits"].pop()
    with pytest.raises(ValueError, match="derived"):
        projection(changed, TABLE)
    changed = copy.deepcopy(receipt)
    changed.pop("waits")
    with pytest.raises(ValueError, match="derived"):
        projection(changed, TABLE)
    changed = copy.deepcopy(receipt)
    changed["waits"][0]["totalAgeInterval"]["upperSeconds"] += 1
    with pytest.raises(ValueError, match="derived"):
        projection(changed, TABLE)


def test_a_table_without_waits_records_and_projects_no_waits():
    import fs_txn_table_p08
    receipt, _service, _clock = record(fs_txn_table_p08.TABLE)
    assert "waits" not in receipt and "waits" not in projection(receipt, fs_txn_table_p08.TABLE)
    assert compile_plan(fs_txn_table_p08.TABLE, NONCE, OWNER)["waits"] == {} and "thresholds" not in compile_plan(fs_txn_table_p08.TABLE, NONCE, OWNER)
    assert corpus_digest(fs_txn_table_p08.TABLE) == "1dc1d44eca4b99a23d8f3b480eb9b8d71aec4ef0894509b149fa12354c9d92bc"


def test_a_wait_entry_refuses_an_interval_shorter_than_the_seconds_it_declares():
    step = next(step for step in plan()["steps"] if step["id"] == "rest/keepalive-1")
    def timing(start):
        return {"dispatchMonotonic": start, "responseMonotonic": start + 0.5, "dispatchUtc": f"2026-09-30T00:00:{int(start):02d}.000Z" if start < 60 else "2026-09-30T00:01:00.000Z", "responseUtc": f"2026-09-30T00:00:{int(start):02d}.500Z" if start < 60 else "2026-09-30T00:01:00.500Z"}
    previous = {"site": "rest/read-a", "timing": timing(1.0)}
    tokens = {"rest-k": {"start": timing(0.0)}}
    ok = collector_module.wait_entry(step, previous, timing(26.0), tokens)
    assert ok["idleInterval"]["lowerSeconds"] == 24.5 and ok["totalAgeInterval"]["upperSeconds"] == 26.5
    with pytest.raises(ValueError, match="did not last"):
        collector_module.wait_entry(step, previous, timing(20.0), tokens)
    with pytest.raises(ValueError, match="elapsed differ"):
        collector_module.wait_entry(step, previous, {**timing(26.0), "responseUtc": "2026-09-30T00:00:40.500Z"}, tokens)


def test_the_age_class_is_relative_to_the_tables_threshold_and_needs_a_token():
    entry = {"site": "s", "seconds": 5, "totalAgeInterval": {"lowerSeconds": 100.0, "upperSeconds": 269.9}}
    assert collector_module.wait_projection(entry, {"totalAgeSeconds": 270})["ageClass"] == "BEFORE"
    assert collector_module.wait_projection({**entry, "totalAgeInterval": {"lowerSeconds": 270.1, "upperSeconds": 300.0}}, {"totalAgeSeconds": 270})["ageClass"] == "AFTER"
    assert collector_module.wait_projection({**entry, "totalAgeInterval": {"lowerSeconds": 269.0, "upperSeconds": 271.0}}, {"totalAgeSeconds": 270})["ageClass"] == "INDETERMINATE"
    assert collector_module.wait_projection({**entry, "totalAgeInterval": {"lowerSeconds": 270.0, "upperSeconds": 270.0}}, {"totalAgeSeconds": 270})["ageClass"] == "INDETERMINATE", "exactly at the threshold is neither before nor after"
    assert "ageClass" not in collector_module.wait_projection(entry, None)
    assert "ageClass" not in collector_module.wait_projection({"site": "s", "seconds": 5}, {"totalAgeSeconds": 270})


def test_an_interval_needs_both_clocks_to_agree_and_time_to_move_forward():
    def timing(dispatch, response, utc_dispatch, utc_response):
        return {"dispatchMonotonic": dispatch, "responseMonotonic": response, "dispatchUtc": utc_dispatch, "responseUtc": utc_response}
    first = timing(1.0, 1.5, "2026-09-30T00:00:01.000Z", "2026-09-30T00:00:01.500Z")
    assert collector_module.interval(first, timing(26.0, 26.5, "2026-09-30T00:00:26.000Z", "2026-09-30T00:00:26.500Z")) == {"lowerSeconds": 24.5, "upperSeconds": 25.5}
    for bad in [timing(1.2, 1.7, "2026-09-30T00:00:01.200Z", "2026-09-30T00:00:01.700Z"),
                timing(26.0, 26.5, "2026-09-30T00:00:30.000Z", "2026-09-30T00:00:30.500Z"),
                timing(26.0, 26.5, "2026-09-30T00:00:01.000Z", "2026-09-30T00:00:01.500Z")]:
        with pytest.raises(ValueError):
            collector_module.interval(first, bad)
