"""Offline campaign coverage through the existing shared adapter and gate."""

from __future__ import annotations

import copy
import json

import pytest

import batch_adapter
from broad_contract import digest
from shared_cases import (
    campaign_manifest,
    campaign_proposal,
    run_scenario,
    validate_campaign_proposal,
)
from shared_gate import Gate, create


def test_proposal_uses_existing_dispatchable_explain_recipe_and_explicit_exclusions():
    proposal = campaign_proposal()

    assert validate_campaign_proposal(proposal)

    assert proposal["kind"] == "production-campaign-slice-01-v2"
    assert proposal["ownerInputs"] == {
        "owner": None,
        "permissionReference": None,
        "startsAt": None,
        "endsAt": None,
        "nonce": None,
        "currentEnvironment": None,
    }
    accepted = [case for case in proposal["cases"] if case["admission"] == "accepted"]
    outside = [case for case in proposal["cases"] if case["admission"] == "outside"]
    assert len(accepted) == 6
    assert len(outside) == 14
    assert all(case["service"] == "firestore" for case in accepted)
    assert all(case["method"] == "POST" for case in accepted)
    assert all(":run" in case["path"] for case in accepted)
    assert all(
        case["setup"]
        and case["principalProof"]
        and case["namespace"]
        and case["readback"]
        and case["cleanup"]
        and case["budget"]["requestCount"] == 1
        and case["recoveryBudget"]["requestCount"] == 6
        for case in accepted
    )
    assert all(case["body"] for case in accepted)
    assert all(case["reason"] for case in outside)


def test_checked_in_proposal_matches_existing_shared_recipe_contract():
    path = __import__("pathlib").Path(
        __file__
    ).parents[2] / "spec/compatibility/broad-runs/prod-campaign-slice-01.json"
    proposal = json.loads(path.read_bytes())

    assert proposal == campaign_proposal()


@pytest.mark.parametrize("field", ["owner", "permissionReference", "startsAt", "endsAt", "nonce", "currentEnvironment"])
def test_proposal_acceptance_inputs_fail_closed(field):
    proposal = campaign_proposal()
    proposal["ownerInputs"][field] = "supplied"

    with pytest.raises(ValueError, match="acceptance must be unset"):
        validate_campaign_proposal(proposal)


def test_manifest_has_fresh_namespace_concrete_requests_and_reserved_recovery():
    plan = campaign_manifest("a" * 32)
    job = plan["jobs"]["query-explain"]

    assert plan["contract"] == "shared-local-v1"
    assert plan["nonce"] == "a" * 32
    assert len(job["resources"]) == 2
    assert all("a" * 32 in resource for resource in job["resources"])
    assert all(operation["service"] == "firestore" for operation in job["observation"])
    assert any(":runQuery" in operation["path"] for operation in job["observation"])
    assert any(":runAggregationQuery" in operation["path"] for operation in job["observation"])
    assert plan["recoverySeconds"] > 0
    assert plan["costMicrousd"] >= plan["fixedCostMicrousd"]
    assert [item["versionFrom"] for item in job["recovery"] if "versionFrom" in item] == [0, 3]
    assert len(job["stepIds"]) == len(job["observation"])


def test_proposal_binds_fresh_nonce_through_every_plan_path_and_fails_closed_on_drift():
    proposal = campaign_proposal()
    job = proposal["planTemplate"]["jobs"]["query-explain"]

    assert proposal["planTemplate"]["nonce"] == "{freshNonce}"
    assert all("{freshNonce}" in resource for resource in job["resources"])
    assert all(
        "{freshNonce}" in operation["path"]
        for operation in [*job["observation"], *job["recovery"]]
    )

    drifted = copy.deepcopy(proposal)
    drifted["planTemplate"]["jobs"]["query-explain"]["resources"][0] = drifted[
        "planTemplate"
    ]["jobs"]["query-explain"]["resources"][0].replace("{freshNonce}", "0" * 32)
    with pytest.raises(ValueError, match="namespace template drift"):
        validate_campaign_proposal(drifted)


class FixtureBackend:
    def __init__(self):
        self.docs = {}
        self.variant = None

    def __call__(self, url, method, body, headers, **kwargs):
        path = url.split("/v1/", 1)[1].split("?", 1)[0]
        if method == "GET":
            value = copy.deepcopy(self.docs.get(path))
            return (200, value, "application/json") if value else (404, {"error": {"code": 404, "status": "NOT_FOUND"}}, "application/json")
        if method == "PATCH":
            value = {
                "name": path,
                "fields": body["fields"],
                "updateTime": "2026-09-14T00:00:00Z",
            }
            self.docs[path] = value
            return 200, copy.deepcopy(value), "application/json"
        if method == "DELETE":
            self.docs.pop(path, None)
            return 200, {}, "application/json"
        if self.variant in {"unreceived", "truncated"}:
            raise ValueError("bounded transport failed")
        if self.variant == "http-400-error":
            return 400, [{"error": {"code": 400, "status": "INVALID_ARGUMENT"}}], "application/json"
        if self.variant == "http-400-changed-error":
            return 400, [{"error": {"code": 400, "status": "FAILED_PRECONDITION"}}], "application/json"
        if self.variant == "non-json":
            return 200, "html", "text/html"
        if self.variant == "unexpected-success":
            return 200, [{"unexpected": True}], "application/json"
        if self.variant == "changed-error":
            return 200, [{"error": {"status": "FAILED_PRECONDITION"}}], "application/json"
        explain = body.get("explainOptions", {}).get("analyze") is True
        aggregation = "structuredAggregationQuery" in body
        query = body.get("structuredQuery") or body["structuredAggregationQuery"]["structuredQuery"]
        empty = query.get("limit") == 0
        metrics = {"planSummary": {"indexesUsed": ["different"] if self.variant == "changed-metrics" else []}}
        if explain:
            metrics["executionStats"] = {"resultsReturned": "0" if empty else "2"}
        if not explain:
            return 200, [{"explainMetrics": metrics}], "application/json"
        if aggregation:
            return 200, [{
                "result": {"aggregateFields": {"count": {"integerValue": "0" if empty else "2"}}},
                "readTime": "2026-09-14T00:00:00Z",
                "explainMetrics": metrics,
            }], "application/json"
        if empty:
            return 200, [{"readTime": "2026-09-14T00:00:00Z", "explainMetrics": metrics}], "application/json"
        return 200, [
            {"document": {"name": path + "/items/item-a"}, "readTime": "2026-09-14T00:00:00Z"},
            {"document": {"name": path + "/items/item-b"}, "readTime": "2026-09-14T00:00:00Z"},
            {"readTime": "2026-09-14T00:00:00Z", "explainMetrics": metrics},
        ], "application/json"


def run_fixture(tmp_path, monkeypatch, variant=None, *, absent_before_cleanup=False):
    import shared_cases

    plan = campaign_manifest("b" * 32)
    plan["localOrigins"] = {
        "auth": "http://127.0.0.1:18081",
        "firestore": "http://127.0.0.1:18082",
    }
    output = tmp_path / "run"
    create(output / "gate", plan)
    gate = Gate(output / "gate", "query-explain")
    for index in range(plan["coordinatorRequests"]):
        gate.coordinator_call(index, lambda: (200, {}))
    gate.claim()
    adapter = batch_adapter.Adapter(
        batch_adapter.candidate(),
        plan["nonce"],
        output / "worker",
        local_origins={
            "auth": "http://127.0.0.1:18081",
            "firestore": "http://127.0.0.1:18082",
        },
    )
    adapter.shared_gate = gate
    backend = FixtureBackend()
    backend.variant = variant
    monkeypatch.setattr(batch_adapter, "wire", backend)
    monkeypatch.setattr(shared_cases.time, "sleep", lambda _: None)
    def before_cleanup():
        if absent_before_cleanup:
            backend.docs.pop(plan["jobs"]["query-explain"]["resources"][0])

    result = run_scenario(adapter, plan, "query-explain", before_cleanup=before_cleanup)
    return result, json.loads((output / "gate" / "state.json").read_bytes())


def test_existing_adapter_fixture_records_complete_state_and_cleanup(tmp_path, monkeypatch):
    result, state = run_fixture(tmp_path, monkeypatch)

    assert result["recordingComplete"] is True
    assert result["collectionComplete"] is True
    assert result["stateValidation"] is True
    assert result["cleanupComplete"] is True
    assert result["compatibility"] == "not-observed"
    assert result["principalEvidence"]["job"] == "query-explain"
    assert result["principalEvidence"]["nonce"] == "b" * 32
    assert result["principalEvidence"]["planDigest"] == state["planDigest"]
    assert result["principalEvidence"]["localOrigins"] == {
        "auth": "http://127.0.0.1:18081",
        "firestore": "http://127.0.0.1:18082",
    }
    assert [row["id"] for row in result["rows"]] == campaign_manifest("b" * 32)["jobs"]["query-explain"]["stepIds"]
    saved = json.loads((tmp_path / "run" / "worker" / "result.json").read_bytes())
    assert saved["principalEvidence"] == result["principalEvidence"]
    assert "currentDocument.updateTime=" in result["cleanup"][1]["request"]["path"]
    assert "currentDocument.updateTime=" in result["cleanup"][4]["request"]["path"]
    assert state["jobs"]["query-explain"]["absent"] == state["jobs"]["query-explain"]["resources"]


@pytest.mark.parametrize("variant", ["non-json", "unexpected-success", "changed-error"])
def test_existing_adapter_fixture_keeps_collection_and_cleanup_distinct(tmp_path, monkeypatch, variant):
    result, _ = run_fixture(tmp_path, monkeypatch, variant)

    assert result["collectionComplete"] is (variant != "non-json")
    assert result["recordingComplete"] is (variant != "non-json")
    assert result["stateValidation"] is False
    assert result["cleanupComplete"] is True
    assert result["compatibility"] == "not-observed"
    assert bool(result["failure"]) is (variant == "non-json")


def test_each_explain_recipe_has_its_actual_rest_array_shape(tmp_path, monkeypatch):
    result, _ = run_fixture(tmp_path, monkeypatch)

    rows = {row["id"]: row["body"] for row in result["rows"]}
    assert len(rows["explain/query/plan-only"]) == 1
    assert set(rows["explain/query/plan-only"][0]) == {"explainMetrics"}
    assert any("document" in row for row in rows["explain/query/analyze"])
    assert sum("explainMetrics" in row for row in rows["explain/query/analyze"]) == 1
    assert len(rows["explain/query/empty-analyze"]) == 1
    assert "readTime" in rows["explain/query/empty-analyze"][0]
    assert set(rows["explain/aggregation/plan-only"][0]) == {"explainMetrics"}
    assert set(rows["explain/aggregation/analyze"][0]) == {"result", "readTime", "explainMetrics"}
    assert set(rows["explain/aggregation/empty-analyze"][0]) == {"result", "readTime", "explainMetrics"}


@pytest.mark.parametrize("mutation", ["method", "path", "body", "order"])
def test_comparison_rejects_exact_request_or_order_drift(tmp_path, monkeypatch, mutation):
    from shared_production_pair import compare_campaign_rows

    left, _ = run_fixture(tmp_path, monkeypatch)
    right = copy.deepcopy(left)
    if mutation == "method":
        right["rows"][4]["request"]["method"] = "GET"
    elif mutation == "path":
        right["rows"][4]["request"]["path"] += "/wrong"
    elif mutation == "body":
        right["rows"][5]["request"]["body"]["explainOptions"]["analyze"] = False
    else:
        right["rows"][4], right["rows"][5] = right["rows"][5], right["rows"][4]

    result = compare_campaign_rows(left, right, [row["id"] for row in left["rows"]])

    assert result["compatibility"] == "indeterminate"
    assert result["rows"] == []


def test_comparison_rejects_both_sides_same_wrong_request(tmp_path, monkeypatch):
    from shared_production_pair import compare_campaign_rows

    left, _ = run_fixture(tmp_path, monkeypatch)
    right = copy.deepcopy(left)
    for receipt in (left, right):
        receipt["rows"][4]["request"]["path"] += "/wrong"

    result = compare_campaign_rows(left, right, [row["id"] for row in left["rows"]])

    assert result["compatibility"] == "indeterminate"
    assert result["rows"] == []


def test_existing_comparison_compares_real_emitted_rows_and_marks_semantic_mismatch_complete(tmp_path, monkeypatch):
    from shared_production_pair import compare_campaign_rows

    left, _ = run_fixture(tmp_path, monkeypatch)
    right, _ = run_fixture(tmp_path / "right", monkeypatch, "changed-metrics")

    result = compare_campaign_rows(left, right, [row["id"] for row in left["rows"]])

    assert result["recordingComplete"] is True
    assert result["stateValidation"] is True
    assert result["cleanupComplete"] is True
    assert result["compatibility"] == "mismatch"
    assert result["rows"][4]["verdict"] == "mismatch"


def test_comparison_can_record_changed_error_array_as_mismatch(tmp_path, monkeypatch):
    from shared_production_pair import compare_campaign_rows

    left, _ = run_fixture(tmp_path, monkeypatch)
    right, _ = run_fixture(tmp_path / "right", monkeypatch, "changed-error")

    result = compare_campaign_rows(left, right, [row["id"] for row in left["rows"]])

    assert result["collectionComplete"] is True
    assert result["compatibility"] == "mismatch"


def test_existing_comparison_keeps_preflight_drift_non_green():
    from shared_production_pair import compare_campaign_rows

    left = {
        "recordingComplete": True,
        "stateValidation": True,
        "cleanupComplete": True,
        "preflight": {"configurationDigest": "baseline"},
        "rows": [{"id": "x", "status": 200, "body": {}}],
    }
    right = copy.deepcopy(left)
    right["preflight"]["configurationDigest"] = "drifted"

    result = compare_campaign_rows(
        left, right, ["x"], expected_preflight={"configurationDigest": "baseline"}
    )

    assert result["preflightDrift"] is True
    assert result["compatibility"] == "indeterminate"
    assert result["rows"] == []


def test_existing_comparison_rejects_unbound_principal_evidence():
    from shared_production_pair import compare_campaign_rows

    receipt = {
        "recordingComplete": True,
        "stateValidation": True,
        "cleanupComplete": True,
        "principalEvidence": {"job": "query-explain"},
        "rows": [],
    }

    result = compare_campaign_rows(receipt, copy.deepcopy(receipt), [])

    assert result["compatibility"] == "indeterminate"
    assert result["rows"] == []


def test_existing_comparison_rejects_principal_evidence_drift(tmp_path, monkeypatch):
    from shared_production_pair import compare_campaign_rows

    left, _ = run_fixture(tmp_path, monkeypatch)
    right = copy.deepcopy(left)
    right["principalEvidence"]["nonce"] = "different"

    result = compare_campaign_rows(left, right, [row["id"] for row in left["rows"]])

    assert result["compatibility"] == "indeterminate"
    assert result["rows"] == []


@pytest.mark.parametrize("field", ["recordingComplete", "stateValidation", "cleanupComplete"])
def test_existing_comparison_keeps_incomplete_results_non_green(field):
    from shared_production_pair import compare_campaign_rows

    left = {"recordingComplete": True, "stateValidation": True, "cleanupComplete": True, "rows": [{"id": "x", "status": 200, "body": {}}]}
    right = copy.deepcopy(left)
    right[field] = False

    result = compare_campaign_rows(left, right, ["x"])

    assert result["compatibility"] == "indeterminate"
    assert result["rows"] == []


@pytest.mark.parametrize("baseline", [None, "http-400-error"])
def test_comparison_collects_http_400_error_arrays_and_records_mismatch(tmp_path, monkeypatch, baseline):
    from shared_production_pair import compare_campaign_rows

    left, _ = run_fixture(tmp_path / "left", monkeypatch, baseline)
    right, _ = run_fixture(tmp_path / "right", monkeypatch, "http-400-changed-error")

    assert right["rows"][4]["status"] == 400
    assert right["collectionComplete"] is True
    assert right["recordingComplete"] is True
    assert right["stateValidation"] is False
    assert right["cleanupComplete"] is True
    assert right["failure"] is None
    result = compare_campaign_rows(left, right, [row["id"] for row in left["rows"]])
    assert result["collectionComplete"] is True
    assert result["stateValidation"] is False
    assert result["compatibility"] == "mismatch"
    assert result["rows"][4]["verdict"] == "mismatch"


@pytest.mark.parametrize("variant", ["non-json", "truncated", "unreceived"])
def test_comparison_keeps_incomplete_transport_indeterminate(tmp_path, monkeypatch, variant):
    from shared_production_pair import compare_campaign_rows

    left, _ = run_fixture(tmp_path / "left", monkeypatch)
    right, _ = run_fixture(tmp_path / "right", monkeypatch, variant)

    assert right["collectionComplete"] is False
    assert right["recordingComplete"] is False
    assert right["cleanupComplete"] is True
    result = compare_campaign_rows(left, right, [row["id"] for row in left["rows"]])
    assert result["compatibility"] == "indeterminate"
    assert result["rows"] == []


@pytest.mark.parametrize("both_sides", [False, True])
@pytest.mark.parametrize("mutation", ["body", "status", "response-digest", "typed-body"])
def test_comparison_rejects_response_evidence_mutation_before_semantic_match(tmp_path, monkeypatch, both_sides, mutation):
    from shared_production_pair import compare_campaign_rows

    left, _ = run_fixture(tmp_path, monkeypatch)
    right = copy.deepcopy(left)
    if mutation == "typed-body":
        for receipt in (left, right):
            receipt["rows"][4]["body"][0]["explainMetrics"]["planSummary"]["indexesUsed"] = [1]
            receipt["principalEvidence"]["dispatch"]["observation"][4]["responseDigest"] = digest(receipt["rows"][4]["body"])
    expected_ids = [row["id"] for row in left["rows"]]
    assert compare_campaign_rows(left, right, expected_ids)["compatibility"] == "match"
    for receipt in (left, right) if both_sides else (right,):
        if mutation == "body":
            receipt["rows"][4]["body"][0]["explainMetrics"]["planSummary"]["indexesUsed"] = ["altered"]
        elif mutation == "typed-body":
            receipt["rows"][4]["body"][0]["explainMetrics"]["planSummary"]["indexesUsed"] = [True]
        elif mutation == "status":
            receipt["rows"][4]["status"] = 400
        else:
            receipt["principalEvidence"]["dispatch"]["observation"][4]["responseDigest"] = "stale"

    result = compare_campaign_rows(left, right, [row["id"] for row in left["rows"]])

    assert result["compatibility"] == "indeterminate"
    assert result["rows"] == []


@pytest.mark.parametrize("variant, verdict", [(None, "match"), ("changed-metrics", "mismatch")])
def test_comparison_accepts_later_recovery_events_after_skipped_conditional_delete(tmp_path, monkeypatch, variant, verdict):
    from shared_production_pair import compare_campaign_rows

    left, _ = run_fixture(tmp_path / "left", monkeypatch, absent_before_cleanup=True)
    right, state = run_fixture(tmp_path / "right", monkeypatch, variant, absent_before_cleanup=True)

    assert right["collectionComplete"] is True
    assert right["cleanupComplete"] is True
    assert right["cleanup"][0]["status"] == 404
    assert right["cleanup"][1]["status"] is None
    assert right["cleanup"][1]["body"] == {"skipped": "absent-or-unavailable-cleanup-read"}
    assert [event["index"] for event in right["principalEvidence"]["dispatch"]["recovery"]] == [0, 2, 3, 4, 5]
    assert state["skips"] == [{"job": "query-explain", "index": 1, "reason": "absent-or-unavailable-cleanup-read"}]
    result = compare_campaign_rows(left, right, [row["id"] for row in left["rows"]])

    assert result["collectionComplete"] is True
    assert result["cleanupComplete"] is True
    assert result["compatibility"] == verdict
    assert result["rows"][4]["verdict"] == verdict


@pytest.mark.parametrize("mutation", ["missing", "duplicate"])
def test_comparison_requires_unique_recovery_event_after_skipped_delete(tmp_path, monkeypatch, mutation):
    from shared_production_pair import compare_campaign_rows

    left, _ = run_fixture(tmp_path, monkeypatch, absent_before_cleanup=True)
    right = copy.deepcopy(left)
    for receipt in (left, right):
        events = receipt["principalEvidence"]["dispatch"]["recovery"]
        if mutation == "missing":
            events.pop(1)
        else:
            events.append(copy.deepcopy(events[1]))

    result = compare_campaign_rows(left, right, [row["id"] for row in left["rows"]])

    assert result["compatibility"] == "indeterminate"
    assert result["rows"] == []


@pytest.mark.parametrize("mutation", ["privileged", "cost", "principal", "missing-case", "extra-job", "request-body", "budget", "typed-cost"])
def test_proposal_rejects_drift_from_complete_canonical_contract(mutation):
    proposal = campaign_proposal()
    if mutation == "privileged":
        proposal["planTemplate"]["jobs"]["query-explain"]["observation"][4]["privileged"] = False
    elif mutation == "cost":
        proposal["planTemplate"]["costMicrousd"] = 0
    elif mutation == "principal":
        proposal["cases"][0]["principal"] = "arbitrary-principal"
    elif mutation == "missing-case":
        proposal["cases"].pop()
    elif mutation == "extra-job":
        proposal["planTemplate"]["jobs"]["extra"] = copy.deepcopy(proposal["planTemplate"]["jobs"]["query-explain"])
    elif mutation == "request-body":
        proposal["planTemplate"]["jobs"]["query-explain"]["observation"][4]["body"]["explainOptions"]["analyze"] = True
    elif mutation == "typed-cost":
        proposal["planTemplate"]["costMicrousd"] = float(proposal["planTemplate"]["costMicrousd"])
    else:
        proposal["budget"]["totalRequests"] = 0

    with pytest.raises(ValueError, match="closed proposal drift"):
        validate_campaign_proposal(proposal)


@pytest.mark.parametrize("both_sides", [False, True])
@pytest.mark.parametrize("mutation", ["null-final-read", "missing-event", "extra-event", "final-present", "skip-with-version"])
def test_comparison_rejects_incomplete_or_forged_cleanup_evidence(tmp_path, monkeypatch, both_sides, mutation):
    from shared_production_pair import compare_campaign_rows

    left, _ = run_fixture(tmp_path, monkeypatch)
    right = copy.deepcopy(left)
    expected_ids = [row["id"] for row in left["rows"]]
    assert compare_campaign_rows(left, right, expected_ids)["compatibility"] == "match"
    for receipt in (left, right) if both_sides else (right,):
        events = receipt["principalEvidence"]["dispatch"]["recovery"]
        if mutation == "null-final-read":
            receipt["cleanup"][2]["status"] = None
            receipt["cleanup"][2]["body"] = {"missing": "final absence evidence"}
        elif mutation == "missing-event":
            events.pop(2)
        elif mutation == "extra-event":
            extra = copy.deepcopy(events[-1])
            extra["index"] = 6
            events.append(extra)
        elif mutation == "final-present":
            receipt["cleanup"][2]["status"] = 200
            events[2]["status"] = 200
        else:
            receipt["cleanup"][1]["status"] = None
            receipt["cleanup"][1]["body"] = {"skipped": "absent-or-unavailable-cleanup-read"}
            events.pop(1)

    result = compare_campaign_rows(left, right, expected_ids)

    assert result["compatibility"] == "indeterminate"
    assert result["rows"] == []


@pytest.mark.parametrize("mutation", ["missing-status", "wrong-body", "extra-field", "event", "executed-without-version"])
def test_comparison_requires_exact_skip_receipt_without_dispatch_event(tmp_path, monkeypatch, mutation):
    from shared_production_pair import compare_campaign_rows

    left, _ = run_fixture(tmp_path, monkeypatch, absent_before_cleanup=True)
    right = copy.deepcopy(left)
    expected_ids = [row["id"] for row in left["rows"]]
    assert compare_campaign_rows(left, right, expected_ids)["compatibility"] == "match"
    for receipt in (left, right):
        skipped = receipt["cleanup"][1]
        events = receipt["principalEvidence"]["dispatch"]["recovery"]
        if mutation == "missing-status":
            skipped.pop("status")
        elif mutation == "wrong-body":
            skipped["body"] = {"skipped": "arbitrary"}
        elif mutation == "extra-field":
            skipped["failure"] = "unexpected failure"
        else:
            if mutation == "executed-without-version":
                skipped["status"] = 200
            events.insert(1, {
                "index": 1,
                "requestDigest": digest(skipped["request"]),
                "status": skipped["status"],
                "responseDigest": digest(skipped["body"]),
                "completed": True,
            })

    result = compare_campaign_rows(left, right, expected_ids)

    assert result["compatibility"] == "indeterminate"
    assert result["rows"] == []
