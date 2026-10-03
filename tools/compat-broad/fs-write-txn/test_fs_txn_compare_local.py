"""The comparison tool's pure parts: commit-time relations and the row comparison."""

import fs_txn_compare_local as tool
import copy
import pytest
from hypothesis import given, settings, strategies as st
import datetime as dt
import re
import json


def step(site, transport, code=0, response=None, request=None, case=None):
    return {"site": site, "rpc": "Commit", "transport": transport, "caseId": case, "request": request or {}, "result": {"code": code, "response": response}}


def rest(stamp):
    return {"commitTime": stamp}


def test_an_empty_commit_before_the_outside_writer_is_related_to_it():
    steps = [
        step("s/writer", "rest", response=rest("2026-09-30T01:17:23.183416Z"), request={"writes": [{}]}, case="rest/s-writer"),
        step("s/ro-empty", "rest", response=rest("2026-09-30T01:17:19.219755Z"), request={"transaction": "t", "writes": []}),
    ]
    assert tool.commit_relations(steps)["s/ro-empty"] == {"commitTime": True, "relation": "before-writer"}
    steps[1]["result"]["response"] = rest("2026-09-30T01:17:29.000000Z")
    assert tool.commit_relations(steps)["s/ro-empty"]["relation"] == "after-writer"


def test_an_empty_commit_without_an_earlier_writer_or_a_time_has_no_relation():
    only = [step("s/ro-empty", "rest", response=rest("2026-09-30T01:17:19Z"), request={"transaction": "t", "writes": []})]
    assert tool.commit_relations(only)["s/ro-empty"] == {"commitTime": True, "relation": None}
    bare = [step("s/ro-empty", "grpc", response={}, request={"transaction": "t", "writes": []})]
    assert tool.commit_relations(bare)["s/ro-empty"] == {"commitTime": False, "relation": None}


def test_refused_commits_and_other_rpcs_are_not_related():
    refused = step("s/x", "rest", code=3, response=None)
    read = {**step("s/y", "rest", response=rest("2026-09-30T01:17:19Z")), "rpc": "GetDocument"}
    assert tool.commit_relations([refused, read]) == {}


def test_grpc_commit_times_compare_like_rest_ones():
    writer = step("g/writer", "grpc", response={"commitTime": {"seconds": "1790731101", "nanos": 314215000}}, request={"writes": [{}]}, case="grpc/s-writer")
    empty = step("g/ro-empty", "grpc", response={"commitTime": {"seconds": "1790731098", "nanos": 607751000}}, request={"transaction": "t", "writes": []})
    assert tool.commit_relations([writer, empty])["g/ro-empty"]["relation"] == "before-writer"


def projection(code=0, details="", state="v1", documents=None):
    return {"cases": [{"caseId": "c", "code": code, "details": details}], "reads": [{"site": "r", "code": 0, "state": state, "documents": documents}]}


def test_matching_rows_have_no_mismatch():
    cases, reads, times = tool.compare(projection(), projection(), {"s": {"commitTime": True, "relation": None}}, {"s": {"commitTime": True, "relation": None}})
    assert all(row["match"] for row in cases + reads + times)


def test_a_different_code_state_document_or_commit_time_is_a_mismatch():
    for local, relations in [
        (projection(code=3), {"s": {"commitTime": True, "relation": None}}),
        (projection(state="v2"), {"s": {"commitTime": True, "relation": None}}),
        (projection(documents={"a": "v1"}), {"s": {"commitTime": True, "relation": None}}),
        (projection(), {"s": {"commitTime": False, "relation": None}}),
        (projection(), {"s": {"commitTime": True, "relation": "after-writer"}}),
    ]:
        cases, reads, times = tool.compare(projection(), local, {"s": {"commitTime": True, "relation": None}}, relations)
        assert not all(row["match"] for row in cases + reads + times)


def test_only_the_declared_project_identifier_is_normalised():
    production = projection(code=5, details='Document "projects/fireemu-oracle-sbx/x" not found\nmore')
    local = projection(code=5, details='Document "projects/demo-program/x" not found\nother')
    cases, _reads, _times = tool.compare(production, local, None, {})
    assert cases[0]["match"] is False
    local["cases"][0]["details"] = local["cases"][0]["details"].replace("other", "more")
    assert tool.compare(production, local, None, {})[0][0]["match"] is True


@pytest.mark.parametrize("section,key", [("cases", "caseId"), ("reads", "site")])
def test_duplicate_or_extra_rows_cannot_disappear_in_a_dictionary(section, key):
    for duplicate in (True, False):
        local = projection()
        extra = copy.deepcopy(local[section][0])
        if not duplicate:
            extra[key] = "unexpected"
        local[section].append(extra)
        with pytest.raises(ValueError, match="row identity"):
            tool.compare(projection(), local, None, {})


def test_runtime_input_binding_rejects_missing_extra_or_changed_files():
    expected = {"a": "1" * 64, "b": "2" * 64}
    tool.validate_runtime_inputs(expected, expected)
    for actual in ({"a": expected["a"]}, {**expected, "c": "3" * 64}, {**expected, "b": "3" * 64}):
        with pytest.raises(ValueError, match="runtime inputs"):
            tool.validate_runtime_inputs(expected, actual)


def toy_recording():
    from test_fs_txn_table_p02 import record, TABLE
    receipt, _ = record(ro_snapshot="first-read")
    return receipt, TABLE


def test_all_step_semantics_include_control_http_versions_and_cleanup():
    receipt, table = toy_recording()
    semantic = tool.recording_semantics(receipt, table)
    assert len(semantic["steps"]) == len(table["steps"])
    assert semantic["cleanup"]["absent"] is True
    assert semantic["steps"]["rest/s1/ro-read"]["versions"]
    changed = copy.deepcopy(receipt)
    changed["steps"][4]["result"]["http"] = 201
    changed["observations"][0]["result"]["http"] = 201
    assert tool.recording_semantics(changed, table) != semantic


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "complete", "transport", "state", "version", "token", "commitTime", "cleanup"])
def test_forged_recording_cannot_be_published_as_an_agreeing_complete_record(mutation):
    receipt, table = toy_recording()
    original = tool.recording_semantics(receipt, table)
    changed = copy.deepcopy(receipt)
    if mutation == "missing": changed["steps"].pop()
    if mutation == "duplicate": changed["steps"][-1] = changed["steps"][-2]
    if mutation == "complete": changed["graphComplete"] = False
    if mutation == "transport": changed["steps"][4]["transport"] = "grpc"
    if mutation == "state": changed["steps"][5]["result"]["response"]["fields"]["state"]["stringValue"] = "held"
    if mutation == "version": changed["steps"][5]["result"]["response"]["updateTime"] = "2026-09-30T00:00:00.999999999Z"
    if mutation == "token": changed["steps"][5]["request"]["transaction"] = "AAAA"
    if mutation == "commitTime": changed["steps"][14]["result"]["response"].pop("commitTime")
    if mutation == "cleanup": changed["cleanupSteps"].pop()
    try:
        actual = tool.recording_semantics(changed, table)
    except ValueError:
        return
    assert actual != original


@given(st.dictionaries(st.text(alphabet="abc", min_size=1, max_size=5), st.integers(0, 16), min_size=1, max_size=12))
def test_generated_case_sets_preserve_every_code_and_reject_every_duplicate(values):
    source = {"cases": [{"caseId": key, "code": code, "details": ""} for key, code in values.items()], "reads": []}
    assert all(row["match"] for row in tool.compare(source, copy.deepcopy(source), None, {})[0])
    for index in range(len(source["cases"])):
        local = copy.deepcopy(source)
        local["cases"][index]["code"] = (local["cases"][index]["code"] + 1) % 17
        assert not tool.compare(source, local, None, {})[0][index]["match"]
        local["cases"].append(copy.deepcopy(local["cases"][index]))
        with pytest.raises(ValueError, match="row identity"):
            tool.compare(source, local, None, {})


@settings(max_examples=15)
@given(st.integers(1, 1000000))
def test_timestamp_translation_keeps_order_equality_precision_and_state(delta):
    receipt, table = toy_recording()
    def shift(value):
        if isinstance(value, dict):
            return {key: str(int(item) + delta) if key == "seconds" else shift(item) for key, item in value.items()}
        if isinstance(value, list): return [shift(item) for item in value]
        if isinstance(value, str) and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z", value):
            base, dot, fraction = value[:-1].partition(".")
            shifted = dt.datetime.fromisoformat(base) + dt.timedelta(seconds=delta)
            return shifted.isoformat() + (dot + fraction if dot else "") + "Z"
        return value
    assert tool.recording_semantics(shift(receipt), table) == tool.recording_semantics(receipt, table)


@pytest.mark.parametrize("status", [199, 302, 503])
def test_indeterminate_http_status_cannot_become_published_completion(status):
    receipt, table = toy_recording()
    receipt["steps"][7]["result"]["http"] = status
    receipt["observations"][3]["result"]["http"] = status
    with pytest.raises(ValueError):
        tool.recording_semantics(receipt, table)


def test_decoded_protobuf_member_insertion_order_does_not_change_timestamp_paths():
    receipt, table = toy_recording()
    changed = copy.deepcopy(receipt)
    def reorder(value):
        if isinstance(value, dict): return {key: reorder(item) for key, item in reversed(list(value.items()))}
        if isinstance(value, list): return [reorder(item) for item in value]
        return value
    assert tool.recording_semantics(reorder(changed), table) == tool.recording_semantics(receipt, table)


def test_changed_commit_chronology_cannot_be_normalised_away():
    receipt, table = toy_recording()
    changed = copy.deepcopy(receipt)
    changed["steps"][14]["result"]["response"]["commitTime"] = "2026-09-30T00:00:00.999999999Z"
    for row in changed["observations"]:
        if row["site"] == "rest/s2/ro-empty": row["result"] = copy.deepcopy(changed["steps"][14]["result"])
    assert tool.recording_semantics(changed, table) != tool.recording_semantics(receipt, table)


def test_a_profile_that_accepts_a_recorded_refused_commit_reports_the_extra_time():
    cases, reads, times = tool.compare(projection(code=3), projection(), {}, {"new-success": {"commitTime": True, "relation": None}})
    assert cases[0]["match"] is False
    assert times == [{"site": "new-success", "production": None, "local": {"commitTime": True, "relation": None}, "match": False}]


def test_cli_retains_the_verified_worker_runtime_in_the_saved_local_receipt(tmp_path, monkeypatch):
    import txn_program_wire as wire
    receipt, _table = toy_recording()
    production = tmp_path / "production.json"
    production.write_text(json.dumps(receipt))
    output = tmp_path / "compared.json"
    runtime = {"nodeSha256": "a" * 64, "workerSha256": "b" * 64}
    monkeypatch.setenv("SMOKE_TABLE", "fs_txn_table_p02")
    monkeypatch.setenv("FIRESTORE_EMULATOR_HOST", "127.0.0.1:12345")
    monkeypatch.delenv("COMPARE_RUNTIME_PROOF", raising=False)
    monkeypatch.setattr(wire, "discover_runtime", lambda _node: runtime)
    monkeypatch.setattr(wire, "NodeWire", lambda *_args, **_kwargs: object())
    class FixtureCollector:
        def __init__(self, *_args, **_kwargs): pass
        def run(self): return copy.deepcopy(receipt)
    monkeypatch.setattr(tool, "Collector", FixtureCollector)
    monkeypatch.setattr(tool.sys, "argv", ["compare", str(production), str(output)])
    tool.main()
    assert json.loads(output.with_suffix(".receipt.json").read_text())["runtime"] == runtime
    assert json.loads(output.read_text())["mismatches"] == 0


@pytest.mark.parametrize("profile", ["strict", "emulator"])
@pytest.mark.parametrize("with_time", [True, False])
def test_cli_saves_both_transports_extra_successful_commits_as_mismatches(tmp_path, monkeypatch, profile, with_time):
    import txn_program_wire as wire
    from test_fs_txn_table_p02b import record
    source, _ = record(ro_write_ends_token=True)
    local, _ = record()
    if with_time:
        for row in local["steps"] + local["observations"]:
            if row["transport"] == "grpc" and row["site"].endswith("/commit-empty"):
                row["result"]["response"]["commitTime"] = copy.deepcopy(local["steps"][1]["result"]["response"]["writeResults"][0]["updateTime"])
    if not with_time:
        for row in local["steps"] + local["observations"]:
            if row["site"].endswith("/commit-empty"):
                row["result"]["response"].pop("commitTime", None)
    production = tmp_path / "production.json"
    production.write_text(json.dumps(source))
    output = tmp_path / "compared.json"
    monkeypatch.setenv("SMOKE_TABLE", "fs_txn_table_p02b")
    monkeypatch.setenv("FIRESTORE_EMULATOR_HOST", "127.0.0.1:12345")
    monkeypatch.setenv("COMPARE_PROFILE", profile)
    monkeypatch.delenv("COMPARE_RUNTIME_PROOF", raising=False)
    monkeypatch.setattr(wire, "discover_runtime", lambda _node: {})
    monkeypatch.setattr(wire, "NodeWire", lambda *_args, **_kwargs: object())
    class FixtureCollector:
        def __init__(self, *_args, **_kwargs): pass
        def run(self): return copy.deepcopy(local)
    monkeypatch.setattr(tool, "Collector", FixtureCollector)
    monkeypatch.setattr(tool.sys, "argv", ["compare", str(production), str(output)])
    tool.main()
    saved = json.loads(output.read_text())
    assert saved["complete"] is True and saved["mismatches"] > 0
    expected_count = sum(not row["match"] for section in ("cases", "reads", "commitTimes", "allSteps") for row in saved[section]) + (0 if saved["cleanupMatch"] else 1)
    assert saved["mismatches"] == expected_count
    assert saved["metadata"]["profile"] == profile
    for transport in ("rest", "grpc"):
        for chain in ("x", "y"):
            site = f"{transport}/{chain}/commit-empty"
            case = next(row for row in saved["cases"] if row["caseId"] == f"{transport}/{chain}-commit-empty")
            assert case["production"]["code"] == 3 and case["local"]["code"] == 0 and not case["match"]
            assert next(row for row in saved["allSteps"] if row["site"] == site)["match"] is False
            stamp = next(row for row in saved["commitTimes"] if row["site"] == site)
            assert stamp == {"site": site, "production": None, "local": {"commitTime": with_time, "relation": None}, "match": False}


@pytest.mark.parametrize("mutation", ["steps", "sequence", "timing", "batch-frames", "timestamp-path", "timestamp-equality"])
def test_native_order_and_timestamp_paths_are_preserved(mutation):
    receipt, table = toy_recording()
    original = tool.recording_semantics(receipt, table)
    changed = copy.deepcopy(receipt)
    if mutation == "steps": changed["steps"][4], changed["steps"][5] = changed["steps"][5], changed["steps"][4]
    if mutation == "sequence": changed["steps"][4]["sequence"] = 999
    if mutation == "timing": changed["steps"][4]["timing"]["dispatchMonotonic"] = 0
    if mutation == "batch-frames": changed["steps"][6]["result"]["response"]["responses"].reverse()
    if mutation == "timestamp-path": changed["steps"][14]["result"]["response"]["readTime"] = changed["steps"][14]["result"]["response"]["commitTime"]
    if mutation == "timestamp-equality":
        previous = changed["steps"][14]["result"]["response"]["commitTime"]
        assert previous == changed["steps"][12]["result"]["response"]["writeResults"][0]["updateTime"]
        replacement = changed["steps"][4]["result"]["response"]["writeResults"][0]["updateTime"]
        assert previous != replacement
        changed["steps"][14]["result"]["response"]["commitTime"] = replacement
    for row in changed["observations"]:
        row["result"] = copy.deepcopy(next(step["result"] for step in changed["steps"] if step["site"] == row["site"]))
    try:
        actual = tool.recording_semantics(changed, table)
    except ValueError:
        assert mutation != "timestamp-equality", "the equality fixture must reach the semantic comparison"
        return
    assert actual != original
    if mutation == "timestamp-equality":
        assert actual["steps"]["rest/s2/ro-empty"]["versions"] != original["steps"]["rest/s2/ro-empty"]["versions"]
        before_target = original["steps"]["rest/s2/ro-empty"]["versions"]["/commitTime"]["rank"]
        before_writer = original["steps"]["rest/s2/writer"]["versions"]["/writeResults/0/updateTime"]["rank"]
        after_target = actual["steps"]["rest/s2/ro-empty"]["versions"]["/commitTime"]["rank"]
        after_writer = actual["steps"]["rest/s2/writer"]["versions"]["/writeResults/0/updateTime"]["rank"]
        assert before_target == before_writer and after_target < after_writer


def test_cli_refuses_a_non_loopback_target_before_any_dispatch(monkeypatch):
    monkeypatch.setenv("SMOKE_TABLE", "fs_txn_table_p02")
    monkeypatch.setenv("FIRESTORE_EMULATOR_HOST", "203.0.113.1:443")
    monkeypatch.setattr(tool.sys, "argv", ["compare", "not-opened.json", "not-written.json"])
    with pytest.raises(ValueError, match="loopback"):
        tool.main()


@pytest.mark.parametrize("binding", ["inputs", "binary", "commit", "production"])
def test_cli_binding_failures_leave_no_successful_comparison(tmp_path, monkeypatch, binding):
    import hashlib
    receipt, _ = toy_recording()
    production = tmp_path / "production.json"
    if binding == "production": receipt["graphComplete"] = False
    production.write_text(json.dumps(receipt))
    binary = tmp_path / "binary"
    binary.write_bytes(b"binary")
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    input_file = tmp_path / "input"
    input_file.write_bytes(b"source")
    input_digest = hashlib.sha256(input_file.read_bytes()).hexdigest()
    proof = {"root": str(tmp_path), "inputs": {"input": "0" * 64 if binding == "inputs" else input_digest}, "binary": str(binary), "binarySha256": digest, "sourceCommit": "c" * 40}
    proof_file = tmp_path / "proof.json"
    proof_file.write_text(json.dumps(proof))
    output = tmp_path / "compared.json"
    monkeypatch.setenv("SMOKE_TABLE", "fs_txn_table_p02")
    monkeypatch.setenv("FIRESTORE_EMULATOR_HOST", "127.0.0.1:12345")
    monkeypatch.setenv("COMPARE_RUNTIME_PROOF", str(proof_file))
    monkeypatch.setenv("COMPARE_BINARY_SHA256", "0" * 64 if binding == "binary" else digest)
    monkeypatch.setenv("COMPARE_COMMIT", "d" * 40 if binding == "commit" else "c" * 40)
    monkeypatch.setattr(tool.sys, "argv", ["compare", str(production), str(output)])
    with pytest.raises(ValueError): tool.main()
    assert not output.exists() and not output.with_suffix(".receipt.json").exists()


def test_semantic_diagnostic_suffix_is_retained_beyond_the_display_prefix():
    receipt, table = toy_recording()
    changed = copy.deepcopy(receipt)
    diagnostic = "x" * 120 + "\nmeaningful diagnostic suffix"
    changed["steps"][7]["result"]["details"] = diagnostic
    for row in changed["observations"]:
        if row["site"] == changed["steps"][7]["site"]: row["result"]["details"] = diagnostic
    semantic = tool.recording_semantics(changed, table)
    assert semantic["steps"][changed["steps"][7]["site"]]["details"] == diagnostic
    assert semantic != tool.recording_semantics(receipt, table)


def test_a_missing_local_row_is_a_mismatch():
    cases, reads, times = tool.compare(projection(), {"cases": [], "reads": []}, {"s": {"commitTime": True, "relation": None}}, {})
    assert not cases[0]["match"] and not reads[0]["match"] and not times[0]["match"]


def p08_recording():
    from fs_txn_table_p08 import TABLE
    from test_txn_program_collector import Clock, Service
    from txn_program_collector import Collector
    from txn_program_program import RequestBudget, compile_plan

    class RecordedRefusalService(Service):
        """A finite stand-in for P08's observed refusal family, without network access."""

        def _send(self, transport, method, request, **kwargs):
            result = super()._send(transport, method, request, **kwargs)
            token = request.get("transaction")
            if method in ("GetDocument", "Commit") and self.tokens.get(token) == "dead" and result["code"] == 10:
                result["code"] = 3
                result["details"] = "The referenced transaction has expired or is no longer valid."
            if method == "Commit" and result["code"] == 5:
                result["details"] = "No document to update: " + request["writes"][1]["update"]["name"]
            if transport == "rest":
                result["http"] = {0: 200, 3: 400, 5: 404, 10: 409}[result["code"]]
            if method == "Commit" and result["code"] == 0 and result["response"].get("writeResults"):
                result["response"]["commitTime"] = copy.deepcopy(result["response"]["writeResults"][-1]["updateTime"])
            return result

    clock = Clock()
    plan = compile_plan(TABLE, "a" * 32, "b" * 32)
    service = RecordedRefusalService(clock, dead_on_failure=True, fail_code=5, dead_rollback_code=0)
    receipt = Collector(plan, TABLE, RequestBudget(plan, TABLE), service, "owner", save=lambda _state: None, monotonic=clock.now, utc=clock.utc).run()
    assert receipt["complete"] is True and receipt["failureType"] is None
    return receipt, TABLE


def synchronize_p08_observations(receipt):
    for row in receipt["observations"]:
        row["result"] = copy.deepcopy(next(step["result"] for step in receipt["steps"] if step["site"] == row["site"]))


def test_p08_native_refusal_model_preserves_every_step_state_version_and_cleanup():
    receipt, table = p08_recording()
    semantic = tool.recording_semantics(receipt, table)
    assert len(semantic["steps"]) == 45
    assert len(semantic["cleanupSteps"]) == 3
    for transport in ("rest", "grpc"):
        steps = semantic["steps"]
        assert steps[f"{transport}/a/fail-commit"]["code"] == 5
        assert steps[f"{transport}/a/same-token-read-a"]["code"] == 3
        assert steps[f"{transport}/a/corrected-commit"]["code"] == 3
        for chain in ("a", "b"):
            assert steps[f"{transport}/{chain}/rollback"]["code"] == 0
            assert steps[f"{transport}/{chain}/rollback-again"]["code"] == 0
            assert steps[f"{transport}/{chain}/writer"]["code"] == 0
            assert steps[f"{transport}/{chain}/post-read-a"]["read"]["state"] == f"{transport}-{chain}-writer"
        assert steps[f"{transport}/a/plain-read-a"]["versions"] == steps[f"{transport}/a/read-a"]["versions"]
        assert steps[f"{transport}/c/rollback-after-commit"]["code"] == 10
    assert semantic["steps"]["rest/a/fail-commit"]["http"] == 404
    assert semantic["steps"]["rest/a/corrected-commit"]["http"] == 400
    assert semantic["cleanup"]["absent"] is True
    assert list(semantic["cleanupSteps"]) == ["cleanup/read/a", "cleanup/delete/a", "cleanup/verify/a"]
    assert "cleanup/verify/m" not in semantic["cleanupSteps"]
    assert len(semantic["commitTimes"]) == 7


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "complete", "source", "token", "cleanup", "unknown", "sequence"])
def test_p08_forged_native_completion_is_rejected(mutation):
    receipt, table = p08_recording()
    original = tool.recording_semantics(receipt, table)
    changed = copy.deepcopy(receipt)
    if mutation == "missing": changed["steps"].pop()
    if mutation == "duplicate": changed["steps"][-1] = copy.deepcopy(changed["steps"][-2])
    if mutation == "complete": changed["graphComplete"] = False
    if mutation == "source": changed["sourceDigest"] = "0" * 64
    if mutation == "token": changed["steps"][7]["request"]["transaction"] = "AAAA"
    if mutation == "cleanup": changed["cleanupSteps"].pop()
    if mutation == "unknown": changed["unknownCommits"] = ["rest/a/writer"]
    if mutation == "sequence": changed["steps"][7]["sequence"] = 999
    assert changed != receipt and original["cleanup"]["absent"] is True
    with pytest.raises(ValueError): tool.recording_semantics(changed, table)


@pytest.mark.parametrize("transport", ["rest", "grpc"])
def test_p08_a_changed_refusal_diagnostic_suffix_remains_visible(transport):
    receipt, table = p08_recording()
    original = tool.recording_semantics(receipt, table)
    changed = copy.deepcopy(receipt)
    row = next(row for row in changed["steps"] if row["site"] == f"{transport}/a/fail-commit")
    row["result"]["details"] += "\n" + "x" * 120 + " meaningful suffix"
    synchronize_p08_observations(changed)
    actual = tool.recording_semantics(changed, table)
    assert actual != original
    assert actual["steps"][row["site"]]["details"].endswith("meaningful suffix")


@pytest.mark.parametrize("transport", ["rest", "grpc"])
def test_p08_a_changed_plain_read_version_reaches_the_semantic_comparison(transport):
    receipt, table = p08_recording()
    original = tool.recording_semantics(receipt, table)
    changed = copy.deepcopy(receipt)
    plain = next(row for row in changed["steps"] if row["site"] == f"{transport}/a/plain-read-a")
    writer = next(row for row in changed["steps"] if row["site"] == f"{transport}/a/writer")
    previous = plain["result"]["response"]["updateTime"]
    replacement = writer["result"]["response"]["writeResults"][0]["updateTime"]
    assert previous != replacement
    plain["result"]["response"]["updateTime"] = copy.deepcopy(replacement)
    synchronize_p08_observations(changed)
    actual = tool.recording_semantics(changed, table)
    assert actual != original
    old_rank = original["steps"][plain["site"]]["versions"]["/updateTime"]["rank"]
    new_rank = actual["steps"][plain["site"]]["versions"]["/updateTime"]["rank"]
    assert old_rank != new_rank


@pytest.mark.parametrize("mutation", ["state", "http", "extra-commit-time"])
def test_p08_native_state_http_and_commit_times_cannot_be_lost(mutation):
    receipt, table = p08_recording()
    original = tool.recording_semantics(receipt, table)
    changed = copy.deepcopy(receipt)
    if mutation == "state": changed["steps"][6]["result"]["response"]["fields"]["state"]["stringValue"] = "held"
    if mutation == "http": changed["steps"][5]["result"]["http"] = 409
    if mutation == "extra-commit-time": changed["steps"][8]["result"]["response"].pop("commitTime")
    synchronize_p08_observations(changed)
    try:
        actual = tool.recording_semantics(changed, table)
    except ValueError:
        assert mutation == "state"
    else:
        assert actual != original


@settings(max_examples=20)
@given(st.sampled_from([f"{transport}/{chain}-{name}" for transport in ("rest", "grpc") for chain, name in [("a", "fail-commit"), ("a", "same-token-read"), ("a", "corrected-commit"), ("a", "rollback"), ("b", "writer"), ("c", "rollback-after-commit")]]), st.integers(0, 16))
def test_generated_p08_case_code_changes_are_rejected_or_visible(case_id, code):
    receipt, table = p08_recording()
    original = tool.recording_semantics(receipt, table)
    row = next(row for row in receipt["steps"] if row["caseId"] == case_id)
    if row["result"]["code"] == code:
        assert tool.recording_semantics(copy.deepcopy(receipt), table) == original
        return
    previous = row["result"]["code"]
    row["result"]["code"] = code
    assert previous != row["result"]["code"]
    synchronize_p08_observations(receipt)
    try:
        actual = tool.recording_semantics(receipt, table)
    except ValueError:
        return
    assert actual != original


@settings(max_examples=15)
@given(st.integers(1, 1000000))
def test_p08_uniform_time_translation_keeps_all_state_and_version_relations(delta):
    receipt, table = p08_recording()
    def shift(value):
        if isinstance(value, dict):
            return {key: str(int(item) + delta) if key == "seconds" else shift(item) for key, item in value.items()}
        if isinstance(value, list): return [shift(item) for item in value]
        if isinstance(value, str) and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z", value):
            base, dot, fraction = value[:-1].partition(".")
            return (dt.datetime.fromisoformat(base) + dt.timedelta(seconds=delta)).isoformat() + (dot + fraction if dot else "") + "Z"
        return value
    assert tool.recording_semantics(shift(receipt), table) == tool.recording_semantics(receipt, table)


def p13b_recording():
    """Replay the finite retry graph with a virtual clock and the observed acceptance model."""
    from test_fs_txn_table_p13b import TABLE, collector, RECORDED_PACE
    from test_txn_program_collector import Clock, Service
    class RecordedRetryService(Service):
        def _send(self, transport, method, request, **kwargs):
            result = super()._send(transport, method, request, **kwargs)
            if method == "Rollback" and request.get("transaction") in self.tokens and result["code"] == 10 and self.clock.now() - self.tstart[request["transaction"]] < 270:
                self.tokens[request["transaction"]] = "rolled-back"
                result = self._receipt(transport, 0, response={})
            if method == "Commit" and result["code"] == 0 and result["response"].get("writeResults"):
                result["response"]["commitTime"] = copy.deepcopy(result["response"]["writeResults"][-1]["updateTime"])
            return result
    clock = Clock()
    service = RecordedRetryService(clock, expiry=True, lifetime=270, idle=120, rpc_seconds=RECORDED_PACE)
    receipt = collector(service, clock).run()
    assert receipt["complete"] is True and receipt["failureType"] is None
    return receipt, TABLE


def synchronize_p13b_observations(receipt):
    for row in receipt["observations"]:
        row["result"] = copy.deepcopy(next(step["result"] for step in receipt["steps"] if step["site"] == row["site"]))


def test_p13b_retry_model_preserves_all_steps_named_tokens_versions_and_cleanup():
    receipt, table = p13b_recording()
    semantic = tool.recording_semantics(receipt, table)
    assert len(semantic["steps"]) == 30 and len(semantic["cleanupSteps"]) == 8
    assert len({row["caseId"] for row in receipt["observations"]}) == 8
    assert all(row["result"]["code"] == 0 and row["transport"] == "rest" for row in receipt["observations"])
    assert len({entry["value"] for entry in receipt["tokens"].values()}) == 8
    rows = {row["site"]: row for row in receipt["steps"]}
    for role, site in [("t1", "rest/rt1/retry-begin"), ("t2", "rest/rt2/retry-idle"), ("t3", "rest/rt3/retry-after-rollback"), ("t4", "rest/rt4/retry-lifetime")]:
        assert rows[site]["request"]["options"]["readWrite"]["retryTransaction"] == receipt["tokens"][role]["value"]
        assert rows[site]["result"]["response"]["transaction"] == receipt["tokens"][role + "r"]["value"]
        assert receipt["tokens"][role]["value"] != receipt["tokens"][role + "r"]["value"]
    first_read = semantic["steps"]["rest/rt1/first-read"]
    writer = semantic["steps"]["rest/rt1/writer"]
    assert first_read["read"]["state"] == "rest-rt1-writer"
    assert first_read["versions"]["/updateTime"]["rank"] == writer["versions"]["/writeResults/0/updateTime"]["rank"]
    assert rows["rest/rt1/retry-begin"]["sequence"] < rows["rest/rt1/writer"]["sequence"] < rows["rest/rt1/first-read"]["sequence"]
    assert semantic["tokens"]["t1r"]["state"] == "committed"
    assert semantic["tokens"]["t4"]["state"] == "released-refused"
    assert semantic["cleanupSteps"]["cleanup/token/t4"]["code"] == 10
    assert semantic["cleanupSteps"]["cleanup/token/t4r"]["code"] == 0
    assert semantic["cleanupSteps"]["cleanup/verify/a"]["code"] == 5
    assert semantic["cleanup"] == {"absent": True}
    commit_response = rows["rest/rt1/commit"]["result"]["response"]
    assert "commitTime" in commit_response
    assert commit_response["commitTime"] == commit_response["writeResults"][-1]["updateTime"]
    commit_versions = semantic["steps"]["rest/rt1/commit"]["versions"]
    assert commit_versions["/commitTime"] == commit_versions["/writeResults/0/updateTime"]
    assert len(commit_response["writeResults"]) == 1
    assert commit_versions["/commitTime"]["layout"] == {"precision": 9}
    assert semantic["steps"]["setup/create-a"]["versions"]["/commitTime"]["layout"] == {"members": ["nanos", "seconds"]}
    assert semantic["steps"]["final/post-read-a"]["read"]["state"] == "rest-rt1-commit"
    assert semantic["steps"]["final/post-read-a"]["versions"]["/updateTime"] == commit_versions["/commitTime"]
    cleanup = {row["site"]: row for row in receipt["cleanupSteps"]}
    readback = cleanup["cleanup/read/a"]
    delete = cleanup["cleanup/delete/a"]
    verify = cleanup["cleanup/verify/a"]
    response = readback["result"]["response"]
    assert readback["transport"] == "grpc" and readback["rpc"] == "GetDocument" and readback["result"]["code"] == 0
    assert response["fields"]["state"]["stringValue"] == "rest-rt1-commit"
    assert response["name"] == readback["request"]["name"] == delete["request"]["name"] == rows["final/post-read-a"]["request"]["name"]
    assert response["updateTime"] == receipt["documents"]["a"]["stamp"] == delete["request"]["currentDocument"]["updateTime"]
    assert semantic["cleanupSteps"]["cleanup/read/a"]["versions"]["/updateTime"]["layout"] == {"members": ["nanos", "seconds"]}
    assert delete["result"]["code"] == 0 and verify["result"]["code"] == 5
    assert semantic["cleanupSteps"]["cleanup/verify/a"]["versions"] == {}
    assert all(not receipt[key] for key in ["openTokens", "unknownStarts", "unknownRollbacks", "unknownCommits"])
    # Native REST precision is an independent saved-source contract, not the mock clock's epoch.
    from pathlib import Path
    native_path = Path(__file__).resolve().parents[3] / "spec/compatibility/broad-runs/fs-transaction-p13b-recorded-observations-v1.json"
    native_semantic = json.loads(native_path.read_text())["corpora"][0]["semantics"]
    native_commit = native_semantic["steps"]["rest/rt1/commit"]["versions"]
    assert native_commit["/commitTime"] == native_commit["/writeResults/0/updateTime"]
    assert native_commit["/commitTime"]["layout"] == {"precision": 6}
    assert native_semantic["cleanupSteps"]["cleanup/read/a"]["versions"]["/updateTime"]["layout"] == {"members": ["nanos", "seconds"]}
    waits = {entry["site"]: entry for entry in receipt["waits"]}
    for site in ["rest/rt2/retry-idle", "rest/rt3/rollback-idle"]:
        assert waits[site]["idleInterval"]["lowerSeconds"] >= 130
    assert waits["rest/rt4/retry-lifetime"]["totalAgeInterval"]["lowerSeconds"] > 270
    assert waits["rest/rt4/retry-lifetime"]["idleInterval"]["upperSeconds"] < 120


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "completion", "source", "unknown", "cleanup", "transport", "sequence", "named-retry", "reused-token", "age", "dispatch"])
def test_p13b_forged_graph_retry_identity_and_clock_proof_are_rejected(mutation):
    receipt, table = p13b_recording()
    changed = copy.deepcopy(receipt)
    rows = {row["site"]: row for row in changed["steps"]}
    if mutation == "missing": changed["steps"].pop()
    if mutation == "duplicate": changed["steps"][-1] = copy.deepcopy(changed["steps"][-2])
    if mutation == "completion": changed["graphComplete"] = False
    if mutation == "source": changed["sourceDigest"] = "0" * 64
    if mutation == "unknown": changed["unknownCommits"] = ["rest/rt1/writer"]
    if mutation == "cleanup": changed["cleanupSteps"].pop()
    if mutation == "transport": rows["rest/rt2/retry-idle"]["transport"] = "grpc"
    if mutation == "sequence": rows["rest/rt1/writer"]["sequence"] = 999
    if mutation == "named-retry": rows["rest/rt2/retry-idle"]["request"]["options"]["readWrite"]["retryTransaction"] = changed["tokens"]["t1"]["value"]
    if mutation == "reused-token": rows["rest/rt2/retry-idle"]["result"]["response"]["transaction"] = changed["tokens"]["t2"]["value"]
    if mutation == "age": changed["waits"][-1]["totalAgeInterval"]["lowerSeconds"] = 260
    if mutation == "dispatch": rows["rest/rt1/first-read"]["timing"]["dispatchMonotonic"] = rows["rest/rt1/writer"]["timing"]["dispatchMonotonic"]
    assert changed != receipt
    synchronize_p13b_observations(changed)
    with pytest.raises(ValueError): tool.recording_semantics(changed, table)


@pytest.mark.parametrize("mutation", ["http", "diagnostic", "version", "commit-time", "retry-code", "cleanup-code"])
def test_p13b_a_semantic_difference_cannot_disappear_from_full_response_comparison(mutation):
    receipt, table = p13b_recording()
    original = tool.recording_semantics(receipt, table)
    changed = copy.deepcopy(receipt)
    rows = {row["site"]: row for row in changed["steps"]}
    if mutation == "http": rows["rest/rt2/retry-idle"]["result"]["http"] = 201
    if mutation == "diagnostic": rows["rest/rt2/retry-idle"]["result"]["details"] = "x" * 120 + " meaningful suffix"
    if mutation == "version":
        before = rows["rest/rt1/first-read"]["result"]["response"]["updateTime"]
        replacement = rows["rest/rt1/read-a"]["result"]["response"]["updateTime"]
        assert before != replacement
        rows["rest/rt1/first-read"]["result"]["response"]["updateTime"] = replacement
    if mutation == "commit-time": rows["rest/rt1/commit"]["result"]["response"].pop("commitTime")
    if mutation == "retry-code": rows["rest/rt4/retry-lifetime"]["result"]["code"] = 3
    if mutation == "cleanup-code": next(row for row in changed["cleanupSteps"] if row["site"] == "cleanup/token/t4")["result"]["code"] = 0
    assert changed != receipt
    synchronize_p13b_observations(changed)
    try:
        actual = tool.recording_semantics(changed, table)
    except ValueError:
        assert mutation in ["version", "retry-code", "cleanup-code"]
    else:
        assert actual != original
        if mutation == "version":
            assert actual["steps"]["rest/rt1/first-read"]["versions"] != original["steps"]["rest/rt1/first-read"]["versions"]


@settings(max_examples=20, deadline=None)
@given(st.sampled_from(["rest/rt1-rollback", "rest/rt1-writer", "rest/rt1-first-read", "rest/rt1-commit", "rest/rt2-retry-idle", "rest/rt3-rollback-idle", "rest/rt3-retry-after-rollback", "rest/rt4-retry-lifetime"]), st.integers(1, 16))
def test_generated_p13b_nonzero_case_codes_are_rejected_or_visible(case_id, code):
    receipt, table = p13b_recording()
    original = tool.recording_semantics(receipt, table)
    row = next(row for row in receipt["steps"] if row["caseId"] == case_id)
    assert row["result"]["code"] == 0
    row["result"]["code"] = code
    synchronize_p13b_observations(receipt)
    try:
        actual = tool.recording_semantics(receipt, table)
    except ValueError:
        return
    assert actual != original


def p13b_shift_timestamps(value, delta):
    """Shift whole timestamps while preserving duration, shape, precision and duplicates."""
    if isinstance(value, dict):
        if set(value) <= {"seconds", "nanos"} and isinstance(value.get("seconds"), str) and re.fullmatch(r"[0-9]{1,12}", value["seconds"]) and type(value.get("nanos", 0)) is int and 0 <= value.get("nanos", 0) <= 999999999:
            return {**value, "seconds": str(int(value["seconds"]) + delta)}
        return {key: p13b_shift_timestamps(item, delta) for key, item in value.items()}
    if isinstance(value, list):
        return [p13b_shift_timestamps(item, delta) for item in value]
    if isinstance(value, str) and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z", value):
        base, dot, fraction = value[:-1].partition(".")
        return (dt.datetime.fromisoformat(base) + dt.timedelta(seconds=delta)).isoformat() + (dot + fraction if dot else "") + "Z"
    return value


def assert_p13b_translation(receipt, translated, table, delta):
    assert tool.projection(translated, table)
    assert translated["steps"][0]["timing"]["dispatchUtc"] != receipt["steps"][0]["timing"]["dispatchUtc"]
    for original, changed in zip(receipt["waits"], translated["waits"], strict=True):
        assert type(changed["seconds"]) is int and changed["seconds"] == original["seconds"]
        for key in ["idleInterval", "totalAgeInterval"]:
            assert changed[key] == original[key]
    for group in ["steps", "cleanupSteps"]:
        assert len(translated[group]) == len(receipt[group])
        for original, changed in zip(receipt[group], translated[group], strict=True):
            for key in ["site", "sequence", "transport", "rpc"]:
                assert changed[key] == original[key]
            for key, value in original["timing"].items():
                if "Monotonic" in key:
                    assert changed["timing"][key] == value
    assert set(translated["tokens"]) == set(receipt["tokens"])
    for role, original in receipt["tokens"].items():
        assert translated["tokens"][role]["value"] == original["value"]
        assert translated["tokens"][role]["state"] == original["state"]
    for key in ["sourceDigest", "corpusDigest", "phaseRequests", "sandboxRequests", "graphComplete", "complete", "openTokens", "unknownStarts", "unknownRollbacks", "unknownCommits"]:
        assert translated[key] == receipt[key]
    assert tool.recording_semantics(translated, table) == tool.recording_semantics(receipt, table)


def test_p13b_literal_one_second_translation_preserves_native_duration_and_completion():
    receipt, table = p13b_recording()
    translated = p13b_shift_timestamps(receipt, 1)
    assert_p13b_translation(receipt, translated, table, 1)
    for key in ["rpc", "phaseRequests", "sandboxRequests", "openTokens", "unknownStarts", "unknownRollbacks", "unknownCommits"]:
        changed = copy.deepcopy(translated)
        if key == "rpc":
            changed["steps"][0][key] = "ForgedRpc"
        elif key == "phaseRequests":
            changed[key]["observation"] += 1
        elif key == "sandboxRequests":
            changed[key] += 1
        else:
            changed[key] = ["forged-resource"]
        assert changed != translated
        with pytest.raises((ValueError, AssertionError)):
            assert_p13b_translation(receipt, changed, table, 1)
        missing = copy.deepcopy(translated)
        if key == "rpc":
            del missing["steps"][0][key]
        else:
            del missing[key]
        with pytest.raises((ValueError, KeyError)):
            assert_p13b_translation(receipt, missing, table, 1)


@settings(max_examples=10, deadline=None)
@given(st.integers(1, 1000000))
def test_p13b_time_translation_keeps_retry_state_and_version_relations(delta):
    receipt, table = p13b_recording()
    assert_p13b_translation(receipt, p13b_shift_timestamps(receipt, delta), table, delta)


@settings(max_examples=30, deadline=None)
@given(st.integers(1, 1000000), st.sampled_from([None, 0, 1, 999999999]), st.sampled_from(["", ".000", ".000001", ".000000001"]))
def test_generated_p13b_timestamp_shapes_keep_precision_members_and_duplicate_equality(delta, nanos, fraction):
    proto = {"seconds": "1790726400"}
    if nanos is not None:
        proto["nanos"] = nanos
    rest = "2026-09-30T00:00:00" + fraction + "Z"
    value = {"seconds": 130, "monotonic": 100.25, "interval": {"lowerSeconds": 130.0, "upperSeconds": 131.0}, "uri": "demo/example", "marker": "owned", "stamps": [proto, rest, copy.deepcopy(proto), rest]}
    changed = p13b_shift_timestamps(value, delta)
    assert changed["seconds"] == 130 and type(changed["seconds"]) is int
    for key in ["monotonic", "interval", "uri", "marker"]:
        assert changed[key] == value[key]
    assert len(changed["stamps"]) == 4
    assert set(changed["stamps"][0]) == set(proto)
    assert changed["stamps"][0]["seconds"] == str(int(proto["seconds"]) + delta)
    if nanos is not None:
        assert changed["stamps"][0]["nanos"] == nanos and type(changed["stamps"][0]["nanos"]) is int
    assert changed["stamps"][0] == changed["stamps"][2]
    assert changed["stamps"][1] == changed["stamps"][3] != rest
    expected = (dt.datetime(2026, 9, 30) + dt.timedelta(seconds=delta)).isoformat() + fraction + "Z"
    assert changed["stamps"][1] == expected
    assert p13b_shift_timestamps(changed, -delta) == value


@pytest.mark.parametrize("value", [{"seconds": 130}, {"seconds": "130", "duration": True}, {"seconds": "130", "nanos": "1"}, {"seconds": "130", "nanos": -1}, {"seconds": "130", "nanos": 1000000000}, {"seconds": "invalid", "nanos": 0}])
def test_p13b_translation_leaves_non_timestamp_seconds_objects_unchanged(value):
    assert p13b_shift_timestamps(value, 1) == value


@pytest.mark.parametrize("mutation", ["unequal-duplicate", "reverse-rank", "duration", "precision", "missing-path"])
def test_p13b_nonuniform_timestamp_and_duration_changes_are_rejected_or_visible(mutation):
    receipt, table = p13b_recording()
    original = tool.recording_semantics(receipt, table)
    rows = {row["site"]: row for row in receipt["steps"]}
    first = rows["rest/rt1/first-read"]["result"]["response"]
    if mutation == "unequal-duplicate":
        before = first["updateTime"]
        first["updateTime"] = p13b_shift_timestamps(before, 1)
        assert before != first["updateTime"]
    if mutation == "reverse-rank":
        before = first["updateTime"]
        first["updateTime"] = rows["rest/rt1/read-a"]["result"]["response"]["updateTime"]
        assert before != first["updateTime"]
    if mutation == "duration":
        before = receipt["waits"][0]["seconds"]
        receipt["waits"][0]["seconds"] += 1
        assert receipt["waits"][0]["seconds"] != before
    if mutation == "precision":
        before = first["updateTime"]
        first["updateTime"] = before.split(".")[0] + "Z"
        assert first["updateTime"] != before
    if mutation == "missing-path":
        assert "updateTime" in first
        del first["updateTime"]
    synchronize_p13b_observations(receipt)
    try:
        actual = tool.recording_semantics(receipt, table)
    except ValueError:
        return
    assert actual != original


@pytest.mark.parametrize("table_name,expected_project", [("fs_txn_table_p02", "fireemu-oracle-sbx"), ("fs_txn_table_p13b", "fireemu-oracle-txn")])
def test_cli_binds_the_validated_table_project_to_the_local_wire(tmp_path, monkeypatch, table_name, expected_project):
    import txn_program_wire as wire
    receipt, _ = toy_recording() if table_name == "fs_txn_table_p02" else p13b_recording()
    production = tmp_path / "production.json"
    production.write_text(json.dumps(receipt))
    output = tmp_path / "compared.json"
    monkeypatch.setenv("SMOKE_TABLE", table_name)
    monkeypatch.setenv("FIRESTORE_EMULATOR_HOST", "127.0.0.1:12345")
    monkeypatch.delenv("COMPARE_RUNTIME_PROOF", raising=False)
    monkeypatch.setattr(wire, "discover_runtime", lambda _node: {})
    calls = []
    monkeypatch.setattr(wire, "NodeWire", lambda *args, **kwargs: calls.append(kwargs) or object())
    class FixtureCollector:
        def __init__(self, *_args, **_kwargs): pass
        def run(self): return copy.deepcopy(receipt)
    monkeypatch.setattr(tool, "Collector", FixtureCollector)
    monkeypatch.setattr(tool.sys, "argv", ["compare", str(production), str(output)])
    tool.main()
    assert len(calls) == 1
    assert calls[0].get("project") == expected_project
    assert calls[0]["target"] == {"kind": "local", "host": "127.0.0.1", "port": 12345}
    assert json.loads(output.read_text())["mismatches"] == 0


@pytest.mark.parametrize("project", ["foreign-project", "fireemu-oracle-txn-extra", "", None, 7])
def test_cli_rejects_an_unapproved_table_project_before_creating_a_wire(tmp_path, monkeypatch, project):
    import types
    import txn_program_wire as wire
    from fs_txn_table_p02 import TABLE
    table = {**TABLE, "project": project}
    production = tmp_path / "freeze.json"
    production.write_text(json.dumps({"projection": {"corpusDigest": "unused"}}))
    output = tmp_path / "compared.json"
    monkeypatch.setenv("SMOKE_TABLE", "fixture_table")
    monkeypatch.setenv("FIRESTORE_EMULATOR_HOST", "127.0.0.1:12345")
    monkeypatch.delenv("COMPARE_RUNTIME_PROOF", raising=False)
    monkeypatch.setattr(tool.importlib, "import_module", lambda _name: types.SimpleNamespace(TABLE=table))
    monkeypatch.setattr(wire, "discover_runtime", lambda _node: {})
    dispatches = []
    monkeypatch.setattr(wire, "NodeWire", lambda *_args, **_kwargs: dispatches.append(True))
    monkeypatch.setattr(tool.sys, "argv", ["compare", str(production), str(output)])
    with pytest.raises(ValueError, match="project"):
        tool.main()
    assert dispatches == [] and not output.exists()


@settings(max_examples=30, deadline=None)
@given(st.sampled_from(["fireemu-oracle-sbx", "fireemu-oracle-txn"]), st.text(alphabet="0123456789abcdef", min_size=32, max_size=32))
def test_generated_table_projects_rebase_only_declared_request_fields(project, nonce):
    import txn_program_wire as wire
    from unittest.mock import patch
    from fs_txn_table_p02 import TABLE
    from txn_program_program import compile_plan
    from txn_program_runner import wire_scope
    plan = compile_plan({**TABLE, "project": project}, nonce, "b" * 32)
    database = plan["database"]
    document = plan["documents"]["a"]
    request = {"database": database, "name": document, "documents": [document], "writes": [{"update": {"name": document, "fields": {}}}], "transaction": "dG9rZW4=", "literal": database}
    original = copy.deepcopy(request)
    specs = []
    with patch.object(wire, "verify_runtime", lambda _runtime: None):
        local = wire.NodeWire({}, wire_scope(TABLE), target={"kind": "local", "host": "127.0.0.1", "port": 12345}, project=plan["project"])
    def intercept(spec, _timeout):
        specs.append(spec)
        raise RuntimeError("offline dispatch interception")
    local._child = intercept
    with patch.object(wire, "verify_runtime", lambda _runtime: None), pytest.raises(RuntimeError, match="offline dispatch interception"):
        local.send("grpc", "GetDocument", request, nonce=nonce, owner_id="b" * 32, bearer="owner")
    spec = specs[0]
    assert spec["projectId"] == "demo-program"
    assert spec["request"]["database"] == "projects/demo-program/databases/(default)"
    expected_document = document.replace(database, "projects/demo-program/databases/(default)", 1)
    assert spec["request"]["name"] == expected_document
    assert spec["request"]["documents"] == [expected_document]
    assert spec["request"]["writes"][0]["update"]["name"] == expected_document
    assert spec["request"]["transaction"] == original["transaction"]
    assert spec["request"]["literal"] == database
    assert request == original
