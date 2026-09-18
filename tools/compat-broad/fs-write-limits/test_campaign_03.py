"""Offline checks for FS-WRITE-LIMITS-03.

The responder below is an independent model of the limits under test, not a
replay of the compiler's declared expectations: it parses each resource name and
applies the catalog boundaries itself. A test that passes here has agreed with
that model, which is why the real artifact shadow is still required.

Nothing in this module sends a production request or approves a campaign.
"""

from __future__ import annotations

import copy
import json
from urllib.parse import unquote

import pytest
from collector_03 import collect
from comparator_03 import compare_rows
from compiler_03 import (
    CAMPAIGN,
    COLLECTION_ID_MAX,
    DOCUMENT_NAME_MAX,
    SUBCOLLECTION_DEPTH_MAX,
    compile_limits_plan,
    resource_name_bytes,
    subcollection_depth,
)
from expectations_03 import (
    evaluate_rows,
    preflight_count,
    validate_cleanup,
    validate_local_receipt,
    writes_safe,
)
from shared_gate import Gate, create

NOT_FOUND = {"error": {"code": 404, "status": "NOT_FOUND", "message": "absent"}}


def _invalid(message):
    return {"error": {"code": 400, "status": "INVALID_ARGUMENT", "message": message}}


def _path_error(resource):
    """Apply the three request-stage limits this campaign observes."""
    relative = resource.split("/documents/", 1)[1]
    segments = relative.split("/")
    for index, segment in enumerate(segments):
        if index % 2 == 0 and len(segment.encode()) > COLLECTION_ID_MAX:
            return "collection id is too long"
    if subcollection_depth(resource) > SUBCOLLECTION_DEPTH_MAX:
        return "subcollection depth exceeds the maximum"
    if resource_name_bytes(resource) > DOCUMENT_NAME_MAX:
        return "document name is too long"
    return None


def _undecodable(fields):
    for value in (fields or {}).values():
        array = value.get("arrayValue") if isinstance(value, dict) else None
        if isinstance(array, dict) and not isinstance(array.get("values", []), list):
            return True
    return False


class Responder:
    """A minimal owned-namespace Firestore model over the campaign's operations."""

    def __init__(self):
        self.documents: dict[str, dict] = {}
        self.clock = 0
        self.sent: list[tuple[str, str]] = []

    def _version(self):
        self.clock += 1
        return f"2026-09-18T00:00:{self.clock:02d}Z"

    def _create(self, name, fields):
        version = self._version()
        self.documents[name] = {
            "name": name,
            "fields": copy.deepcopy(fields),
            "createTime": version,
            "updateTime": version,
        }
        return version

    def __call__(self, operation, _recovery, _index, _request_index):
        self.sent.append((operation["method"], operation["path"]))
        status, body = self._respond(operation)
        return {"status": status, "body": body, "complete": True, "failure": None}

    def _respond(self, operation):
        path, method = operation["path"], operation["method"]
        if method == "POST":
            return self._batch_write(operation["body"]["writes"])
        resource, _, query = path.removeprefix("/v1/").partition("?")
        if method == "GET":
            document = self.documents.get(resource)
            return (200, copy.deepcopy(document)) if document else (404, NOT_FOUND)
        if method == "DELETE":
            expected = unquote(query.removeprefix("currentDocument.updateTime="))
            document = self.documents.get(resource)
            if document is None or document["updateTime"] != expected:
                return 400, _invalid("precondition failed")
            del self.documents[resource]
            return 200, {}
        error = _path_error(resource)
        if error:
            return 400, _invalid(error)
        if _undecodable(operation["body"]["fields"]):
            return 400, _invalid("cannot decode value")
        if resource in self.documents:
            return 409, _invalid("already exists")
        self._create(resource, operation["body"]["fields"])
        return 200, copy.deepcopy(self.documents[resource])

    def _batch_write(self, writes):
        names = []
        for write in writes:
            update = write.get("update")
            if update is None:
                continue
            if _undecodable(update.get("fields")):
                return 400, _invalid("cannot decode value")
            names.append(update["name"])
        if len(names) != len(set(names)):
            return 400, _invalid("the same document cannot be written more than once")
        statuses, results = [], []
        for write in writes:
            update = write.get("update")
            if update is None:
                statuses.append({"code": 3, "message": "empty write operation"})
                results.append({})
                continue
            error = _path_error(update["name"])
            if error:
                statuses.append({"code": 3, "message": error})
                results.append({})
                continue
            if update["name"] in self.documents:
                statuses.append({"code": 6, "message": "already exists"})
                results.append({})
                continue
            version = self._create(update["name"], update["fields"])
            statuses.append({})
            results.append({"updateTime": version})
        return 200, {"status": statuses, "writeResults": results}


def plan_for(nonce="a", project="demo-test"):
    return compile_limits_plan(project, "(default)", nonce * 32)


def run_campaign(tmp_path, plan, name="run"):
    create(tmp_path / f"gate-{name}", plan["localGatePlan"])
    gate = Gate(tmp_path / f"gate-{name}", "limits")
    gate.claim()
    responder = Responder()
    result = collect(gate, plan, tmp_path / f"collection-{name}", responder)
    return result, responder


def test_campaign_covers_exactly_the_two_declared_residues():
    plan = plan_for()
    assert plan["campaignId"] == CAMPAIGN
    residues = {case["residue"] for case in plan["cases"]}
    assert residues == {"R3", "R4"}
    limits = {
        document["limitId"]
        for document in plan["documents"].values()
        if "limitId" in document
    }
    assert limits == {
        "FS-LIMIT-COLLECTION-ID",
        "FS-LIMIT-SUBCOLLECTION-DEPTH",
        "FS-LIMIT-DOCUMENT-NAME-BYTES",
    }
    # The index-entry limits and the unsupported limits are owner decisions.
    assert not any("INDEX" in limit for limit in limits)


def test_boundary_pairs_are_exact_and_do_not_confound_each_other():
    plan = plan_for()
    documents = plan["documents"]
    accept, refuse = (
        documents["collection-id-accept"],
        documents["collection-id-refuse"],
    )
    ids = [
        max(
            len(segment.encode())
            for index, segment in enumerate(
                d["resource"].split("/documents/", 1)[1].split("/")
            )
            if index % 2 == 0
        )
        for d in (accept, refuse)
    ]
    assert ids == [COLLECTION_ID_MAX, COLLECTION_ID_MAX + 1]
    assert [
        documents["subcollection-depth-accept"]["depth"],
        documents["subcollection-depth-refuse"]["depth"],
    ] == [
        SUBCOLLECTION_DEPTH_MAX,
        SUBCOLLECTION_DEPTH_MAX + 1,
    ]
    assert [
        documents["document-name-accept"]["nameBytes"],
        documents["document-name-refuse"]["nameBytes"],
    ] == [
        DOCUMENT_NAME_MAX,
        DOCUMENT_NAME_MAX + 1,
    ]
    for label in ("collection-id", "subcollection-depth"):
        for side in ("accept", "refuse"):
            assert documents[f"{label}-{side}"]["nameBytes"] <= DOCUMENT_NAME_MAX
    for label in ("collection-id", "document-name"):
        for side in ("accept", "refuse"):
            assert documents[f"{label}-{side}"]["depth"] <= SUBCOLLECTION_DEPTH_MAX


def test_boundary_padding_follows_the_target_project_and_database():
    short = compile_limits_plan("p", "(default)", "a" * 32)
    long = compile_limits_plan("demo-firestore-probe", "(default)", "a" * 32)
    for plan in (short, long):
        assert (
            plan["documents"]["document-name-accept"]["nameBytes"] == DOCUMENT_NAME_MAX
        )
    assert (
        short["documents"]["document-name-accept"]["resource"]
        != long["documents"]["document-name-accept"]["resource"]
    )


def test_plan_is_deterministic_bounded_and_nonce_isolated():
    first = plan_for()
    assert first == plan_for()
    other = plan_for("b")
    assert all("a" * 32 not in json.dumps(request) for request in other["requests"])
    accounting = first["budgetAccounting"]
    assert accounting["observationRequests"] == 35
    assert accounting["recoveryRequests"] == 39
    assert accounting["ownedDocuments"] == 13
    assert accounting["productionReady"] is False
    assert preflight_count(first) == 13
    kinds = [request["kind"] for request in first["requests"]]
    assert kinds[:13] == ["preflight-typed-absence"] * 13
    assert kinds.count("batch-write") == 3
    assert kinds.count("create-only-patch") == 6
    assert kinds.count("cleanup-conditional-delete") == 13


def test_every_batch_write_is_create_only_and_namespace_marked():
    plan = plan_for()
    for request in plan["requests"]:
        if request["kind"] != "batch-write":
            continue
        for write in request["body"]["writes"]:
            if not write:
                continue
            assert write["currentDocument"] == {"exists": False}
            name = write["update"]["name"]
            assert write["update"]["fields"]["_sharedOwner"] == {"referenceValue": name}
            assert name in [d["resource"] for d in plan["documents"].values()]


def test_catalog_drift_is_refused(monkeypatch):
    import compiler_03

    monkeypatch.setattr(compiler_03, "SUBCOLLECTION_DEPTH_MAX", 99)
    with pytest.raises(ValueError, match="catalog drift"):
        compiler_03.compile_limits_plan("demo-test", "(default)", "a" * 32)


@pytest.mark.parametrize("nonce", ["", "A" * 32, "a" * 31])
def test_malformed_nonce_is_refused(nonce):
    with pytest.raises(ValueError):
        compile_limits_plan("demo-test", "(default)", nonce)


def test_unproven_namespace_cannot_authorize_any_mutation():
    plan = plan_for()
    observation = plan["localGatePlan"]["jobs"]["limits"]["observation"]
    assert writes_safe([], plan) is False
    rows = [
        {
            "index": index,
            "status": 404,
            "complete": True,
            "body": NOT_FOUND,
            "request": observation[index],
        }
        for index in range(13)
    ]
    assert writes_safe(rows, plan) is True
    rows[7]["body"] = {"error": {"code": 400, "status": "INVALID_ARGUMENT"}}
    rows[7]["status"] = 400
    assert writes_safe(rows, plan) is False


def test_batch_write_is_gated_by_the_same_predicate_as_patch(tmp_path):
    plan = plan_for("9")
    create(tmp_path / "gate", plan["localGatePlan"])
    gate = Gate(tmp_path / "gate", "limits")
    gate.claim()
    responder = Responder()

    def unproven(operation, recovery, index, request_index):
        if not recovery and operation["method"] == "GET" and index == 5:
            # A live document where the preflight required typed absence.
            return {
                "status": 200,
                "body": {
                    "name": "x",
                    "fields": {},
                    "updateTime": "2026-09-18T00:00:00Z",
                },
                "complete": True,
                "failure": None,
            }
        return responder(operation, recovery, index, request_index)

    result = collect(gate, plan, tmp_path / "collection", unproven)
    assert result["recordingComplete"] is False
    assert not [method for method, _ in responder.sent if method in ("POST", "PATCH")]


def test_expected_local_journal_completes_and_validates(tmp_path):
    plan = plan_for("e")
    result, responder = run_campaign(tmp_path, plan)
    assert result["expectationMismatches"] == []
    assert result["recordingComplete"] is True
    assert result["cleanupComplete"] is True
    assert result["collectionComplete"] is True
    assert responder.documents == {}
    receipt = {
        "productionExecuted": False,
        "recordingComplete": True,
        "stateValidation": True,
        "cleanupComplete": True,
        "completed": True,
        "rows": result["rows"],
        "cleanup": result["cleanup"],
        "resourceAbsence": result["resourceAbsence"],
        "gate": result["gate"],
    }
    assert validate_cleanup(receipt, plan) is True
    assert validate_local_receipt(receipt, plan) is True


def test_suffix_that_does_not_land_is_an_expectation_mismatch(tmp_path):
    plan = plan_for("f")

    class NoSuffix(Responder):
        def _batch_write(self, writes):
            status, body = super()._batch_write(writes)
            if status == 200 and len(writes) == 3 and writes[1] == {}:
                name = writes[2]["update"]["name"]
                self.documents.pop(name, None)
                body["status"][2] = {"code": 3, "message": "not dispatched"}
                body["writeResults"][2] = {}
            return status, body

    create(tmp_path / "gate", plan["localGatePlan"])
    gate = Gate(tmp_path / "gate", "limits")
    gate.claim()
    result = collect(gate, plan, tmp_path / "collection", NoSuffix())
    bases = {problem["basis"] for problem in result["expectationMismatches"]}
    assert "BatchWrite per-item status codes differ from the expectation" in bases
    assert result["cleanupComplete"] is True


def test_whole_request_refusal_of_the_malformed_case_is_a_mismatch(tmp_path):
    plan = plan_for("c")

    class WholeRequest(Responder):
        def _batch_write(self, writes):
            if any(not write for write in writes):
                return 400, _invalid("empty write operation")
            return super()._batch_write(writes)

    create(tmp_path / "gate", plan["localGatePlan"])
    gate = Gate(tmp_path / "gate", "limits")
    gate.claim()
    result = collect(gate, plan, tmp_path / "collection", WholeRequest())
    assert any(
        problem["basis"] == "BatchWrite did not return a per-item response"
        for problem in result["expectationMismatches"]
    )


def test_accepted_boundary_that_is_refused_is_a_mismatch(tmp_path):
    plan = plan_for("d")

    class StrictNames(Responder):
        def _respond(self, operation):
            if operation["method"] == "PATCH":
                resource = operation["path"].split("?", 1)[0].removeprefix("/v1/")
                if resource_name_bytes(resource) >= DOCUMENT_NAME_MAX:
                    return 400, _invalid("document name is too long")
            return super()._respond(operation)

    create(tmp_path / "gate", plan["localGatePlan"])
    gate = Gate(tmp_path / "gate", "limits")
    gate.claim()
    result = collect(gate, plan, tmp_path / "collection", StrictNames())
    assert result["expectationMismatches"]
    assert result["cleanupComplete"] is True


def _journal(plan, tmp_path, name):
    result, _ = run_campaign(tmp_path, plan, name)
    assert result["expectationMismatches"] == []
    return result["rows"]


def test_comparator_matches_a_self_control_and_normalizes_identity(tmp_path):
    left_plan = compile_limits_plan("fireemu-35fe6", "(default)", "1" * 32)
    right_plan = compile_limits_plan("demo-firestore-probe", "(default)", "2" * 32)
    left = _journal(left_plan, tmp_path, "left")
    right = _journal(right_plan, tmp_path, "right")
    same = compare_rows(left_plan, left, left_plan, left)
    assert same["classification"] == "MATCH"
    assert same["acquisitionValidated"] is False
    assert same["promotionReady"] is False
    cross = compare_rows(left_plan, left, right_plan, right)
    assert cross["classification"] == "EXPECTED_NONDETERMINISM"
    assert cross["structuralClassification"] == "MATCH"


def test_comparator_reports_a_continuation_difference_structurally(tmp_path):
    plan = compile_limits_plan("fireemu-35fe6", "(default)", "3" * 32)
    rows = _journal(plan, tmp_path, "base")
    other = copy.deepcopy(rows)
    index = next(
        i
        for i, request in enumerate(plan["requests"])
        if request["kind"] == "batch-write"
    )
    other[index]["status"] = 400
    other[index]["body"] = _invalid("empty write operation")
    result = compare_rows(plan, rows, plan, other)
    assert result["classification"] == "SEMANTIC_MISMATCH"
    assert result["structuralClassification"] == "SEMANTIC_MISMATCH"
    assert result["rows"][index]["structural"] == "SEMANTIC_MISMATCH"


def test_comparator_separates_wording_from_shape(tmp_path):
    plan = compile_limits_plan("fireemu-35fe6", "(default)", "4" * 32)
    rows = _journal(plan, tmp_path, "wording")
    other = copy.deepcopy(rows)
    index = next(
        i
        for i, request in enumerate(plan["requests"])
        if request["kind"] == "batch-write"
        and request["case"] == "batch-duplicate-document"
    )
    other[index]["body"]["error"]["message"] = "a different diagnostic wording"
    result = compare_rows(plan, rows, plan, other)
    assert result["classification"] == "SEMANTIC_MISMATCH"
    assert result["structuralClassification"] == "MATCH"
    assert result["rows"][index]["structural"] == "MATCH"


@pytest.mark.parametrize("mutation", ["complete", "body", "request", "count", "index"])
def test_incomplete_or_unbound_journal_is_indeterminate(tmp_path, mutation):
    plan = compile_limits_plan("fireemu-35fe6", "(default)", "5" * 32)
    rows = _journal(plan, tmp_path, "bound")
    other = copy.deepcopy(rows)
    if mutation == "complete":
        other[0]["complete"] = False
    elif mutation == "body":
        del other[0]["body"]
    elif mutation == "request":
        other[20]["request"]["body"] = {"writes": []}
    elif mutation == "count":
        other.pop()
    else:
        other[0]["index"] = False
    result = compare_rows(plan, rows, plan, other)
    assert result["classification"] == "INDETERMINATE"
    assert result["acquisitionValidated"] is False


def test_evaluate_rows_refuses_a_reordered_journal(tmp_path):
    plan = compile_limits_plan("fireemu-35fe6", "(default)", "6" * 32)
    rows = _journal(plan, tmp_path, "order")
    swapped = copy.deepcopy(rows)
    swapped[0], swapped[1] = swapped[1], swapped[0]
    assert evaluate_rows(swapped, plan)
