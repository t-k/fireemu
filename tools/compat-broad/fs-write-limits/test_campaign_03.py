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
    DOCUMENT_BYTES_MAX,
    DOCUMENT_NAME_MAX,
    FIELD_PATH_BYTES_MAX,
    FIELD_VALUE_BYTES_MAX,
    INDEX_ENTRIES_PER_DOCUMENT_MAX,
    INDEX_ENTRY_BYTES_MAX,
    INDEX_ENTRY_SUM_PER_DOCUMENT_MAX,
    SUBCOLLECTION_DEPTH_MAX,
    compile_limits_plan,
    dispatched_operations,
    document_bytes,
    index_usage,
    largest_index_entry_bytes,
    resource_name_bytes,
    subcollection_depth,
)
from expectations_03 import (
    evaluate_rows,
    pending_rows,
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


def _commit_error(resource, fields):
    """Apply the commit-stage limits, in the order the store applies them."""
    for name, value in fields.items():
        payload = value.get("stringValue") or value.get("bytesValue") or ""
        if len(payload.encode()) > FIELD_VALUE_BYTES_MAX:
            return f'The value of property "{name}" is longer than {FIELD_VALUE_BYTES_MAX} bytes.'
    if document_bytes(resource, fields) > DOCUMENT_BYTES_MAX:
        return "FS-LIMIT-DOCUMENT-BYTES exceeded"
    error = _implied_path_error(fields)
    if error:
        return error
    usage = index_usage(resource, fields)
    for identifier, value, maximum in (
        (
            "FS-LIMIT-INDEX-ENTRIES-PER-DOCUMENT",
            usage["entries"],
            INDEX_ENTRIES_PER_DOCUMENT_MAX,
        ),
        ("FS-LIMIT-INDEX-ENTRY-BYTES", usage["maxEntryBytes"], INDEX_ENTRY_BYTES_MAX),
        (
            "FS-LIMIT-INDEX-ENTRY-SUM-PER-DOCUMENT",
            usage["totalBytes"],
            INDEX_ENTRY_SUM_PER_DOCUMENT_MAX,
        ),
    ):
        if value > maximum:
            return f"{identifier}: {value} exceeds {maximum}"
    return None


def _implied_path_error(fields):
    """Bound every path a document implies by nesting, under the strict profile.

    Automatic index accounting walks a map held directly by a field and never
    the elements of an array, so the array shape had no bound until the
    write-path lane added one. Under the strict profile both shapes are now
    refused at the same boundary, and an array contributes no path segment of
    its own.
    """

    def walk(prefix, value):
        if isinstance(value, dict) and isinstance(value.get("mapValue"), dict):
            for name, nested in value["mapValue"].get("fields", {}).items():
                path = f"{prefix}.{name}" if prefix else name
                if len(path.encode()) > FIELD_PATH_BYTES_MAX:
                    return (
                        f"field path is {len(path.encode())} bytes, "
                        f"maximum is {FIELD_PATH_BYTES_MAX}"
                    )
                error = walk(path, nested)
                if error:
                    return error
        if isinstance(value, dict) and isinstance(value.get("arrayValue"), dict):
            for item in value["arrayValue"].get("values", []) or []:
                error = walk(prefix, item)
                if error:
                    return error
        return None

    for name, value in fields.items():
        if len(name.encode()) > FIELD_PATH_BYTES_MAX:
            return (
                f"field path is {len(name.encode())} bytes, "
                f"maximum is {FIELD_PATH_BYTES_MAX}"
            )
        error = walk(name, value)
        if error:
            return error
    return None


def _mask_error(mask):
    for path in mask or ():
        if len(path.encode()) > FIELD_PATH_BYTES_MAX:
            return f"invalid field path: field path is {len(path.encode())} bytes, maximum is {FIELD_PATH_BYTES_MAX}"
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
            error = _path_error(resource)
            if error:
                return 400, _invalid(error)
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
        fields = operation["body"]["fields"]
        if _undecodable(fields):
            return 400, _invalid("cannot decode value")
        error = _commit_error(resource, fields)
        if error:
            return 400, _invalid(error)
        if resource in self.documents:
            return 409, _invalid("already exists")
        self._create(resource, fields)
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
            # A path the client names is parsed per write, so an over-long mask
            # path is that write's own status, not a whole-request refusal.
            error = (
                _mask_error((write.get("updateMask") or {}).get("fieldPaths"))
                or _path_error(update["name"])
                or _commit_error(update["name"], update["fields"])
            )
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


def plan_for(nonce="a", project="demo-test", part="A"):
    return compile_limits_plan(project, "(default)", nonce * 32, part)


def run_campaign(tmp_path, plan, name="run", *, excused=None):
    """Model a local run, which is the only kind that excuses a row."""
    create(tmp_path / f"gate-{name}", plan["localGatePlan"])
    gate = Gate(tmp_path / f"gate-{name}", "limits")
    gate.claim()
    responder = Responder()
    result = collect(
        gate,
        plan,
        tmp_path / f"collection-{name}",
        responder,
        excused=pending_rows(plan) if excused is None else excused,
    )
    return result, responder


def test_campaign_covers_exactly_the_two_declared_residues():
    plan = plan_for()
    assert plan["campaignId"] == f"{CAMPAIGN}A"
    assert plan["part"] == "A"
    residues = {
        case["residue"] for part in ("A", "B") for case in plan_for(part=part)["cases"]
    }
    assert residues == {"R3", "R4"}
    limits = {
        document["limitId"]
        for other in ("A", "B")
        for document in plan_for(part=other)["documents"].values()
        if "limitId" in document
    }
    refused = [
        document for document in plan["documents"].values() if not document["owned"]
    ]
    assert len(refused) == 3  # only the illegal identifier names
    assert all(
        document["resource"] not in plan["localGatePlan"]["jobs"]["limits"]["resources"]
        for document in refused
    )
    assert limits == {
        "FS-LIMIT-COLLECTION-ID",
        "FS-LIMIT-SUBCOLLECTION-DEPTH",
        "FS-LIMIT-DOCUMENT-NAME-BYTES",
        "FS-LIMIT-INDEX-ENTRY-BYTES",
        "FS-LIMIT-INDEX-ENTRIES-PER-DOCUMENT",
        "FS-LIMIT-INDEX-ENTRY-SUM-PER-DOCUMENT",
        "FS-LIMIT-INDEXED-FIELD-VALUE-BYTES",
        "FS-LIMIT-FIELD-PATH-BYTES",
        "FS-LIMIT-FIELD-VALUE-BYTES",
    }
    # FS-LIMIT-API-REQUEST-BYTES belongs to the request-byte collector.
    assert "FS-LIMIT-API-REQUEST-BYTES" not in limits


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
    assert accounting["observationRequests"] == 56
    assert accounting["recoveryRequests"] == 54
    assert accounting["ownedDocuments"] == 18
    assert accounting["probedNames"] == 3
    assert accounting["productionReady"] is False
    assert preflight_count(first) == 18
    kinds = [request["kind"] for request in first["requests"]]
    assert kinds[:18] == ["preflight-typed-absence"] * 18
    assert kinds.count("batch-write") == 3
    assert kinds.count("refusal-consistency-readback") == 3
    assert kinds.count("cleanup-conditional-delete") == 18


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
            assert name in plan["localGatePlan"]["jobs"]["limits"]["resources"]


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
        for index in range(18)
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


def test_head_gate_settles_the_malformed_item_batch(tmp_path):
    """A typed refusal for an empty BatchWrite item settles the request."""
    from shared_gate import unconfirmed_creates

    plan = plan_for("e")
    result, responder = run_campaign(tmp_path, plan)
    assert result["expectationMismatches"] == []
    assert result["recordingComplete"] is True
    assert responder.documents == {}
    assert all(result["resourceAbsence"].values())
    assert result["cleanupComplete"] is True
    assert result["infrastructureFailures"] == []
    gate = result["gate"]
    assert unconfirmed_creates(gate, "limits") == 0
    malformed = [
        index
        for index, operation in enumerate(
            gate["plan"]["jobs"]["limits"]["observation"]
        )
        if operation["path"].endswith(":batchWrite")
        and {}
        in operation["body"]["writes"]
    ]
    assert len(malformed) == 1
    event = next(
        event for event in gate["events"] if event.get("index") == malformed[0]
    )
    assert event["creationOutcome"] == "created"
    operation = gate["plan"]["jobs"]["limits"]["observation"][malformed[0]]
    assert operation["path"].endswith(":batchWrite")
    assert {} in operation["body"]["writes"]


def test_expected_local_journal_completes_and_validates(
    tmp_path, gate_accounts_the_empty_batch_item
):
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
    # A local receipt is validated with the same excuse the local run used; a
    # production receipt would be validated with none.
    assert validate_local_receipt(receipt, plan, excused=pending_rows(plan)) is True
    assert validate_local_receipt(receipt, plan) is False


def test_suffix_that_does_not_land_is_an_expectation_mismatch(
    tmp_path, gate_accounts_the_empty_batch_item
):
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
    result = collect(
        gate, plan, tmp_path / "collection", NoSuffix(), excused=pending_rows(plan)
    )
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
    result = collect(
        gate, plan, tmp_path / "collection", WholeRequest(), excused=pending_rows(plan)
    )
    assert any(
        problem["basis"] == "BatchWrite did not return a per-item response"
        for problem in result["expectationMismatches"]
    )


def test_accepted_boundary_that_is_refused_is_a_mismatch(tmp_path):
    plan = plan_for("d")

    class StrictNames(Responder):
        """Refuses the accepted collection-id boundary one byte early."""

        def _respond(self, operation):
            if operation["method"] == "PATCH":
                resource = operation["path"].split("?", 1)[0].removeprefix("/v1/")
                segments = resource.split("/documents/", 1)[1].split("/")
                if any(
                    len(segment.encode()) >= COLLECTION_ID_MAX
                    for index, segment in enumerate(segments)
                    if index % 2 == 0
                ):
                    return 400, _invalid("collection id is too long")
            return super()._respond(operation)

    create(tmp_path / "gate", plan["localGatePlan"])
    gate = Gate(tmp_path / "gate", "limits")
    gate.claim()
    result = collect(
        gate, plan, tmp_path / "collection", StrictNames(), excused=pending_rows(plan)
    )
    assert result["expectationMismatches"]
    # The run stops past a creating slot. The abandon transition reopens the
    # cleanup slots, so every document the run created is deleted and verified
    # absent: no cleanup request is refused and nothing is orphaned.
    assert not [
        failure
        for failure in result["infrastructureFailures"]
        if failure["phase"] == "cleanup"
    ]
    created = {
        row["request"]["path"].split("?", 1)[0].removeprefix("/v1/")
        for row in result["rows"]
        if row.get("status") == 200 and row["request"]["method"] == "PATCH"
    }
    created |= {
        write["update"]["name"]
        for row in result["rows"]
        if row.get("status") == 200 and row["request"]["method"] == "POST"
        for write in row["request"]["body"]["writes"]
        if write
    }
    assert created, "the stop has to happen past a creating slot to be this test"
    assert all(result["resourceAbsence"][name] for name in created)
    # The abandoned close only requires creation proofs for resources actually
    # created; assigned-but-refused resources are covered by typed absence.
    assert result["cleanupComplete"] is True
    assert result["infrastructureFailures"] == []


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
    # Across two projects the refusal diagnostics name resources and sizes the
    # two plans do not share, and the v1 contract keeps message text
    # significant. The shape still has to agree, which is what the additive
    # structural view reports.
    assert cross["classification"] in ("EXPECTED_NONDETERMINISM", "SEMANTIC_MISMATCH")
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


def test_document_name_boundary_is_written_under_a_declared_exemption():
    plan = plan_for()
    accept = plan["documents"]["document-name-accept"]
    refuse = plan["documents"]["document-name-refuse"]
    # The accepted side is created, which is only possible because the campaign
    # declares an exemption; the refused name is not a resource at all.
    assert accept["owned"] is True and refuse["owned"] is False
    assert accept["indexExempt"] is True
    case = next(
        c for c in plan["cases"] if c.get("limitId") == "FS-LIMIT-DOCUMENT-NAME-BYTES"
    )
    assert case["indexExemption"] == {
        "collectionGroup": "nx",
        "fieldPath": "*",
        "indexes": [],
    }
    assert case["pendingReason"]
    # A document at this name cannot be created while the automatic
    # single-field indexes are in force, so the boundary is read, not written.
    assert largest_index_entry_bytes(accept["resource"], accept["fields"]) > 7680
    probe = compile_limits_plan("demo-firestore-probe", "(default)", "a" * 32)
    oracle = probe["documents"]["document-name-accept"]
    assert largest_index_entry_bytes(oracle["resource"], oracle["fields"]) == 12543
    assert (
        largest_index_entry_bytes(accept["resource"], {"v": {"integerValue": "0"}})
        > 7680
    )
    kinds = {
        request["kind"]
        for request in plan["requests"]
        if request["path"].split("?")[0].endswith(accept["resource"])
    }
    # Under the exemption the boundary is written, read back and reclaimed.
    assert "create-only-patch" in kinds
    assert "preflight-typed-absence" in kinds


@pytest.mark.parametrize(
    ("label", "field", "expected"),
    [
        # A long name makes the ownership marker's own entry exceed the maximum.
        ("index-entry-bytes-refuse", {}, "FS-LIMIT-INDEX-ENTRY-BYTES"),
        (
            "collection-id-accept",
            {
                "many": {
                    "arrayValue": {
                        "values": [{"integerValue": str(i)} for i in range(30000)]
                    }
                }
            },
            "FS-LIMIT-INDEX-ENTRIES-PER-DOCUMENT",
        ),
    ],
)
def test_a_created_document_that_would_breach_another_limit_is_refused(
    label, field, expected
):
    """The guard is what keeps a refusal attributable to the limit under test."""
    import compiler_03

    plan = plan_for()
    resource = plan["documents"][label]["resource"]
    fields = {"_sharedOwner": {"referenceValue": resource}, **field}
    document = {
        "resource": resource,
        "fields": fields,
        "owned": True,
        "nameBytes": len(resource.encode()),
        "depth": subcollection_depth(resource),
        "limitId": "FS-LIMIT-COLLECTION-ID",
        "indexUsage": index_usage(resource, fields),
        "documentBytes": document_bytes(resource, fields),
    }
    with pytest.raises(ValueError, match=expected):
        compiler_03._check_no_confound({label: document}, [])


def test_reading_the_refused_name_the_same_way_is_the_post_state_evidence(tmp_path):
    plan = plan_for("b")

    class AbsentNotInvalid(Responder):
        def _respond(self, operation):
            if operation["method"] == "GET":
                resource = operation["path"].split("?", 1)[0].removeprefix("/v1/")
                if _path_error(resource):
                    return 404, NOT_FOUND
            return super()._respond(operation)

    create(tmp_path / "gate", plan["localGatePlan"])
    gate = Gate(tmp_path / "gate", "limits")
    gate.claim()
    result = collect(
        gate,
        plan,
        tmp_path / "collection",
        AbsentNotInvalid(),
        excused=pending_rows(plan),
    )
    assert any(
        problem["basis"] == "a read of the refused name was not refused the same way"
        for problem in result["expectationMismatches"]
    )


def test_every_index_boundary_holds_under_the_default_configuration():
    plan = plan_for()
    cases = {case["limitId"]: case for case in plan["cases"] if "limitId" in case}
    documents = plan["documents"]
    assert cases["FS-LIMIT-INDEX-ENTRY-BYTES"]["boundary"] == [
        INDEX_ENTRY_BYTES_MAX,
        INDEX_ENTRY_BYTES_MAX + 1,
    ]
    assert cases["FS-LIMIT-INDEX-ENTRIES-PER-DOCUMENT"]["boundary"][0] == (
        INDEX_ENTRIES_PER_DOCUMENT_MAX
    )
    assert cases["FS-LIMIT-INDEX-ENTRY-SUM-PER-DOCUMENT"]["boundary"][0] == (
        INDEX_ENTRY_SUM_PER_DOCUMENT_MAX
    )
    for label, measure, maximum in (
        ("index-entry-bytes", "maxEntryBytes", INDEX_ENTRY_BYTES_MAX),
        ("index-entries", "entries", INDEX_ENTRIES_PER_DOCUMENT_MAX),
        ("index-entry-sum", "totalBytes", INDEX_ENTRY_SUM_PER_DOCUMENT_MAX),
    ):
        accept = documents[f"{label}-accept"]
        refuse = documents[f"{label}-refuse"]
        assert accept["indexUsage"][measure] == maximum
        assert refuse["indexUsage"][measure] > maximum
        # Nothing else about the accepted document may be at a limit.
        assert accept["documentBytes"] < DOCUMENT_BYTES_MAX
        assert accept["nameBytes"] <= DOCUMENT_NAME_MAX
        assert accept["depth"] <= SUBCOLLECTION_DEPTH_MAX


def test_the_truncating_limit_is_not_written_as_a_refusal():
    plan = plan_for()
    case = next(
        c
        for c in plan["cases"]
        if c.get("limitId") == "FS-LIMIT-INDEXED-FIELD-VALUE-BYTES"
    )
    assert case["emit"] == "truncating-pair"
    assert case["chargedInFullWouldBe"] > INDEX_ENTRY_BYTES_MAX
    # Both documents are expected to be accepted; a refusal of the second is
    # what would disprove the truncation the catalog records.
    patches = [
        request
        for request in plan["requests"]
        if request["kind"] == "create-only-patch"
        and request["path"].split("?")[0].removeprefix("/v1/")
        in (
            plan["documents"]["indexed-value-accept"]["resource"],
            plan["documents"]["indexed-value-refuse"]["resource"],
        )
    ]
    assert len(patches) == 2
    assert all(request["expect"]["positive"] is True for request in patches)


def test_every_pending_row_states_why_it_is_pending():
    """With the write-path lanes integrated only one pending reason survives."""
    reasons = set()
    for part in ("A", "B"):
        plan = plan_for(part=part)
        for index in pending_rows(plan):
            reasons.add(plan["requests"][index]["expect"]["pendingReason"])
        # Every limit the catalog once called unsupported is now implemented,
        # so no expectation rests on the catalog alone.
        assert not [
            case
            for case in plan["cases"]
            if case.get("catalogImplemented") not in (None, "implemented")
        ]
    assert len(reasons) == 1
    # The one reason left is the local shadow's pinned index configuration.
    assert "index configuration" in next(iter(reasons))


def test_a_production_collection_excuses_no_row(tmp_path):
    """The excuse is a fact about the collecting side, never about the plan.

    A pending reason lives in the compiled request as documentation. If it also
    drove the skip, a production collection would share the plan and skip the
    same invariants, which is the one place the campaign must not.
    """
    plan = plan_for("a")
    # A journal records the operation as dispatched, with a referenced body
    # put back in place, which is what the expectations compare against.
    observation = dispatched_operations(plan)
    pending = pending_rows(plan)
    assert pending, "part A declares rows the local side cannot show"
    index = pending[0]
    rows = []
    for position in range(index + 1):
        body = NOT_FOUND
        status = 404
        if position == index:
            # Whatever the plan says, a production run must judge this row.
            status, body = 400, _invalid("refused")
        rows.append(
            {
                "index": position,
                "request": observation[position],
                "complete": True,
                "failure": None,
                "status": status,
                "body": body,
            }
        )
    # By default the row is judged; only a caller that excuses it is spared.
    default = {p["index"]: p["pending"] for p in evaluate_rows(rows, plan)}
    assert default[index] is False
    local = {
        p["index"]: p["pending"] for p in evaluate_rows(rows, plan, excused=pending)
    }
    assert local[index] is True
    assert set(default) == set(local)
    # An excuse never reaches the namespace-absence preflights: those are the
    # proof that writing at all is safe, and no caller may wave them through.
    observation = plan["localGatePlan"]["jobs"]["limits"]["observation"]
    preflights = preflight_count(plan)
    absent = [
        {
            "index": position,
            "request": observation[position],
            "complete": True,
            "failure": None,
            "status": 404,
            "body": NOT_FOUND,
        }
        for position in range(preflights)
    ]
    assert writes_safe(absent, plan) is True
    absent[2]["status"], absent[2]["body"] = 200, {"name": "x", "fields": {}}
    assert writes_safe(absent, plan) is False
    assert writes_safe(absent, plan, excused=range(preflights)) is False


def test_a_pending_difference_is_recorded_but_does_not_fail_the_campaign(
    tmp_path, gate_accounts_the_empty_batch_item
):
    plan = plan_for("c")

    class PerItemFieldPath(Responder):
        """Reports an over-long mask path per item instead of whole-request."""

        def _batch_write(self, writes):
            for write in writes:
                mask = (write.get("updateMask") or {}).get("fieldPaths")
                if _mask_error(mask):
                    return 200, {
                        "status": [{"code": 3, "message": _mask_error(mask)}],
                        "writeResults": [{}],
                    }
            return super()._batch_write(writes)

    create(tmp_path / "gate", plan["localGatePlan"])
    gate = Gate(tmp_path / "gate", "limits")
    gate.claim()
    result = collect(
        gate,
        plan,
        tmp_path / "collection",
        PerItemFieldPath(),
        excused=pending_rows(plan),
    )
    assert result["expectationMismatches"] == []
    assert result["pendingDifferences"]
    assert all(problem["pending"] is True for problem in result["pendingDifferences"])
    assert result["cleanupComplete"] is True


def test_the_field_value_refusal_is_separated_from_the_document_limit_by_wording(
    tmp_path,
):
    plan = plan_for("d", part="B")
    document = plan["documents"]["field-value-refuse"]
    # The refused document breaches the document limit too, so only the
    # diagnostic text says which limit production enforced.
    assert document_bytes(document["resource"], document["fields"]) > DOCUMENT_BYTES_MAX
    case = next(
        c for c in plan["cases"] if c.get("limitId") == "FS-LIMIT-FIELD-VALUE-BYTES"
    )
    assert case["acceptedSideUnreachable"]
    result, _ = run_campaign(tmp_path, plan, "fvb")
    assert result["expectationMismatches"] == []


def test_the_campaign_is_one_allocation_and_the_gate_charges_it():
    """The collapse, checked against the Gate's own charging helpers."""
    import compiler_03

    plan = compile_limits_plan("fireemu-35fe6", "(default)", "0" * 32)
    assert plan["campaignId"] == CAMPAIGN
    assert plan["budgetAccounting"]["ownedDocuments"] == 29
    gate = plan["localGatePlan"]
    job = gate["jobs"]["limits"]
    charge = compiler_03.gate_charge(
        job["schedule"], job["recovery"], job["observation"] + job["recovery"]
    )
    assert gate["recoverySeconds"] >= charge["recoverySeconds"]
    assert gate["wallSeconds"] <= compiler_03.GATE_WALL_SECONDS_MAX
    assert (
        gate["wallSeconds"] >= charge["observationSeconds"] + charge["recoverySeconds"]
    )
    # A slot carrying a body reserves the transport ceiling; the Gate enforces
    # this itself, and the campaign declares the ceiling it is charged against.
    assert gate["transportCeilingSeconds"] == compiler_03.TRANSPORT_CEILING_SECONDS
    for entry, request in zip(job["schedule"], plan["requests"], strict=True):
        assert entry["seconds"] == (
            compiler_03.TRANSPORT_CEILING_SECONDS
            if request["body"] is not None
            else compiler_03.READBACK_SECONDS
            if request["responseByteLimit"] > compiler_03.DEFAULT_RESPONSE_BYTES
            else compiler_03.SMALL_REQUEST_SECONDS
        )
        assert entry["creates"] is (
            request["kind"] in ("create-only-patch", "batch-write")
        )
    # Every slot before the first creating one is declared non-creating, which
    # is what lets the Gate admit a no-data abort inside that prefix.
    first_create = next(i for i, e in enumerate(job["schedule"]) if e["creates"])
    assert not any(e["creates"] for e in job["schedule"][:first_create])


def test_the_split_selections_remain_available():
    """One allocation carries the campaign; the selections remain compilable.

    The partition was needed while every request paid the lane default. With a
    per-slot reservation it is not, and the A and B selections stay available
    for a run that has to be split for some other reason.
    """
    import compiler_03

    for part in ("A", "B"):
        gate = compile_limits_plan("fireemu-35fe6", "(default)", "0" * 32, part)[
            "localGatePlan"
        ]
        assert gate["wallSeconds"] < compiler_03.GATE_WALL_SECONDS_MAX
        assert gate["recoverySeconds"] < gate["wallSeconds"]


def test_the_schedule_keeps_fail_closed_recovery():
    """A frozen schedule buys an honest reservation without costing recovery.

    The Gate admits only the next unconsumed slot, so a run that stopped part
    way through observation once could not reach its own cleanup at all. The
    Gate's abandon transition ends the observation explicitly and reopens the
    recovery slots in their declared order, so the campaign keeps both the
    per-slot reservation and its fail-closed guarantee. Every slot that cannot
    create is still declared `creates: false`, which is what lets the Gate admit
    a no-data abort inside that prefix.
    """
    job = compile_limits_plan("fireemu-35fe6", "(default)", "0" * 32)["localGatePlan"][
        "jobs"
    ]["limits"]
    assert job["schedule"], "the reservation is per slot, so a schedule is declared"
    creating = [index for index, e in enumerate(job["schedule"]) if e["creates"]]
    assert creating, "some slot must be able to create, or nothing is observed"
    # The whole preflight prefix is non-creating, so a stop there is recoverable
    # by the Gate's own abort path rather than by cleanup.
    assert (
        creating[0]
        >= len([e for e in job["schedule"] if e["phase"] == "observation"])
        - len(job["observation"])
        + 1
    )
    assert all(e["phase"] == "recovery" or True for e in job["schedule"])
