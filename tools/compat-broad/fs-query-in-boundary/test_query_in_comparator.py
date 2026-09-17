import copy
import hashlib
import json

from query_in_comparator import compare_evidence, compare_rows
from query_in_compiler import compile_plan


def _bundle(project: str = "demo", nonce: str = "a" * 32) -> dict:
    plan = compile_plan(project, "(default)", nonce)
    rows = []
    for index, operation in enumerate(plan["observation"]):
        if operation["kind"] in {"preflight-typed-absence"}:
            status, body = 404, {"error": {"code": 404, "status": "NOT_FOUND"}}
        elif operation["kind"] in {"create-only-patch", "before-readback", "after-readback"}:
            status, body = 200, {"name": plan["document"], "fields": plan["fixtureFields"], "updateTime": "2026-09-18T00:00:00Z"}
        elif operation["kind"] == "positive-query":
            status, body = 200, {"documents": [plan["expectedPositiveDocument"]]}
        else:
            status, body = 400, {"error": {"status": "INVALID_ARGUMENT"}}
        rows.append(
            {
                "index": index,
                "request": copy.deepcopy(operation),
                "complete": True,
                "failure": None,
                "status": status,
                "body": body,
                "rawSha256": f"{index:064x}",
            }
        )
    cleanup = []
    for index, operation in enumerate(plan["recovery"]):
        cleanup.append(
            {
                "index": index,
                "request": copy.deepcopy(operation),
                "complete": True,
                "failure": None,
                "status": 404 if index != 1 else None,
                "body": None if index == 1 else {"error": {"code": 404, "status": "NOT_FOUND"}},
                "rawSha256": f"{index + 6:064x}",
                **({"skipped": "already-absent"} if index == 1 else {}),
            }
        )
    journal = [*rows, *cleanup]
    raw = {}
    for index, row in enumerate(journal):
        raw_value = row["body"]
        if index == 2:
            raw_value = [{"document": row["body"]["documents"][0]}]
        raw_body = json.dumps(raw_value, sort_keys=True, separators=(",", ":")).encode()
        digest = hashlib.sha256(raw_body).hexdigest()
        row["rawSha256"] = digest
        raw[str(index)] = {
            "projectionVersion": 1,
            "sourceRawSha256": digest,
            "rawBody": raw_body,
            "phase": "observation" if index < 6 else "recovery",
            "index": index if index < 6 else index - 6,
            "status": row["status"],
            "complete": True,
            "byteCount": len(raw_body),
            "contentType": "application/json",
        }
    raw["2"]["documents"] = rows[2]["body"]["documents"]
    return {
        "plan": plan,
        "rows": rows,
        "cleanup": cleanup,
        "ownership": {"created": False, "cleanupComplete": True},
        "raw": raw,
    }


def test_identical_complete_journals_match_without_acquisition_authority():
    left = _bundle()
    right = copy.deepcopy(left)
    result = compare_evidence(left, right)
    assert result["classification"] == "MATCH"
    assert result["acquisitionValidated"] is False
    assert result["promotionReady"] is False


def test_plan_or_operation_drift_is_indeterminate():
    left = _bundle()
    right = _bundle("other")
    right["rows"][2]["request"]["body"]["structuredQuery"]["limit"] = 2
    result = compare_evidence(left, right)
    assert result["classification"] == "INDETERMINATE"
    assert result["errors"]


def test_complete_typed_response_difference_is_semantic_mismatch():
    left = _bundle()
    right = copy.deepcopy(left)
    left["rows"][2]["status"] = 200
    left["rows"][2]["body"] = {"documents": [{"name": left["plan"]["document"], "fields": left["plan"]["fixtureFields"]}]}
    right["rows"][2]["status"] = 200
    right["rows"][2]["body"] = {"documents": []}
    for bundle in (left, right):
        value = bundle["rows"][2]["body"]
        if value.get("documents"):
            value = [{"document": value["documents"][0]}]
        else:
            value = []
        body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        digest = hashlib.sha256(body).hexdigest()
        bundle["rows"][2]["rawSha256"] = digest
        bundle["raw"]["2"].update(rawBody=body, sourceRawSha256=digest, documents=bundle["rows"][2]["body"]["documents"], status=200, byteCount=len(body))
    result = compare_evidence(left, right)
    assert result["classification"] == "SEMANTIC_MISMATCH"


def test_incomplete_receipt_and_unsafe_cleanup_are_indeterminate():
    left = _bundle()
    right = copy.deepcopy(left)
    right["rows"][0]["complete"] = False
    right["cleanup"][0]["ownership"] = False
    result = compare_evidence(left, right)
    assert result["classification"] == "INDETERMINATE"


def test_cleanup_update_time_predicate_is_percent_encoded():
    bundle = _bundle()
    timestamp = "2026-09-18T00:00:00Z"
    bundle["cleanup"][0].update(
        status=200,
        skipped=None,
        body={"name": bundle["plan"]["document"], "fields": bundle["plan"]["fixtureFields"], "updateTime": timestamp},
    )
    bundle["cleanup"][0].pop("skipped")
    bundle["cleanup"][1].pop("skipped")
    bundle["cleanup"][1].update(status=200, body={})
    bundle["cleanup"][1]["request"]["path"] += "?currentDocument.updateTime=2026-09-18T00%3A00%3A00Z"
    raw_body = json.dumps(bundle["cleanup"][0]["body"], sort_keys=True, separators=(",", ":")).encode()
    digest = hashlib.sha256(raw_body).hexdigest()
    bundle["cleanup"][0]["rawSha256"] = digest
    bundle["raw"]["6"].update(status=200, rawBody=raw_body, sourceRawSha256=digest, byteCount=len(raw_body))
    delete_body = b"{}"
    delete_digest = hashlib.sha256(delete_body).hexdigest()
    bundle["cleanup"][1]["rawSha256"] = delete_digest
    bundle["raw"]["7"].update(status=200, rawBody=delete_body, sourceRawSha256=delete_digest, byteCount=len(delete_body))
    assert compare_evidence(bundle, copy.deepcopy(bundle))["classification"] == "MATCH"


def test_fabricated_positive_projection_is_indeterminate():
    bundle = _bundle()
    bundle["raw"]["2"]["documents"] = []
    result = compare_evidence(bundle, bundle)
    assert result["classification"] == "INDETERMINATE"


def test_compare_rows_accepts_explicit_sidecars():
    bundle = _bundle()
    result = compare_rows(
        bundle["plan"], bundle["rows"], bundle["plan"], bundle["rows"],
        production_cleanup=bundle["cleanup"], local_cleanup=bundle["cleanup"],
        production_raw=bundle["raw"], local_raw=bundle["raw"],
    )
    assert result["classification"] == "MATCH"
