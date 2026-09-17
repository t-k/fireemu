import copy
import hashlib
import json

import pytest
from query_in_comparator import (
    compare_evidence,
    compare_rows,
    load_collected_bundle,
)
from query_in_compiler import compile_plan
from query_in_production import RawJournal


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
                "status": 404 if index == 2 else 200,
                "body": (
                    {"name": plan["document"], "fields": plan["fixtureFields"], "updateTime": "2026-09-18T00:00:00Z"}
                    if index == 0
                    else {} if index == 1 else {"error": {"code": 404, "status": "NOT_FOUND"}}
                ),
                "rawSha256": f"{index + 6:064x}",
            }
        )
    cleanup[1]["request"]["path"] += "?currentDocument.updateTime=2026-09-18T00%3A00%3A00Z"
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
    bundle["cleanup"][0].pop("skipped", None)
    bundle["cleanup"][1].pop("skipped", None)
    bundle["cleanup"][1].update(status=200, body={})
    bundle["cleanup"][1]["request"]["path"] = bundle["plan"]["recovery"][1]["path"] + "?currentDocument.updateTime=2026-09-18T00%3A00%3A00Z"
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


def test_comparator_accepts_json_media_type_parameters():
    bundle = _bundle()
    for view in bundle["raw"].values():
        view["contentType"] = "Application/JSON; charset=UTF-8"
    result = compare_evidence(bundle, copy.deepcopy(bundle))
    assert result["classification"] == "MATCH"


def test_positive_query_extra_body_key_is_not_a_contract_match():
    bundle = _bundle()
    bundle["rows"][2]["body"]["extra"] = True
    result = compare_evidence(bundle, copy.deepcopy(bundle))
    assert result["classification"] == "SEMANTIC_MISMATCH"


def test_skipped_cleanup_cannot_have_complete_raw_sidecar_without_status():
    bundle = _bundle()
    bundle["cleanup"][1].update(status=None, body={}, skipped="already-absent")
    bundle["cleanup"][1]["rawSha256"] = hashlib.sha256(b"null").hexdigest()
    bundle["raw"]["7"].update(
        rawBody=b"null",
        sourceRawSha256=hashlib.sha256(b"null").hexdigest(),
        status=None,
        complete=True,
        byteCount=4,
    )
    result = compare_evidence(bundle, copy.deepcopy(bundle))
    assert result["classification"] == "INDETERMINATE"


def test_cleanup_update_time_bytes_are_expected_nondeterminism():
    left = _bundle()
    right = copy.deepcopy(left)
    for candidate, timestamp in (
        (left, "2026-09-18T00:00:00Z"),
        (right, "2026-09-18T01:00:00Z"),
    ):
        plan = candidate["plan"]
        for row_index in (1, 3, 5):
            candidate["rows"][row_index]["body"]["updateTime"] = timestamp
            raw_body = json.dumps(
                candidate["rows"][row_index]["body"], sort_keys=True, separators=(",", ":")
            ).encode()
            candidate["raw"][str(row_index)].update(
                rawBody=raw_body,
                sourceRawSha256=hashlib.sha256(raw_body).hexdigest(),
                byteCount=len(raw_body),
            )
            candidate["rows"][row_index]["rawSha256"] = candidate["raw"][str(row_index)]["sourceRawSha256"]
        candidate["cleanup"][0] = {
            "index": 0,
            "request": copy.deepcopy(plan["recovery"][0]),
            "complete": True,
            "failure": None,
            "status": 200,
            "body": {
                "name": plan["document"],
                "fields": plan["fixtureFields"],
                "updateTime": timestamp,
            },
        }
        candidate["cleanup"][1].pop("skipped", None)
        candidate["cleanup"][1].update(status=200, body={})
        candidate["cleanup"][1]["request"] = copy.deepcopy(plan["recovery"][1])
        candidate["cleanup"][1]["request"]["path"] += (
            "?currentDocument.updateTime=" + timestamp.replace(":", "%3A")
        )
        raw_body = json.dumps(candidate["cleanup"][0]["body"], sort_keys=True, separators=(",", ":")).encode()
        candidate["raw"]["6"].update(
            rawBody=raw_body,
            sourceRawSha256=hashlib.sha256(raw_body).hexdigest(),
            status=200,
            byteCount=len(raw_body),
        )
        candidate["raw"]["7"].update(
            rawBody=b"{}",
            sourceRawSha256=hashlib.sha256(b"{}").hexdigest(),
            status=200,
            byteCount=2,
        )
        candidate["cleanup"][0]["rawSha256"] = candidate["raw"]["6"]["sourceRawSha256"]
        candidate["cleanup"][1]["rawSha256"] = candidate["raw"]["7"]["sourceRawSha256"]
    assert compare_evidence(left, right)["classification"] == "EXPECTED_NONDETERMINISM"


def test_cleanup_timestamp_formatting_and_byte_count_are_expected_nondeterminism():
    left = _bundle()
    right = copy.deepcopy(left)
    for candidate, timestamp, encoded in (
        (left, "2026-09-18T00:00:00Z", "2026-09-18T00:00:00Z"),
        (right, "2026-09-18T00:00:00.000000Z", "2026-09-18T00:00:00.000000Z"),
    ):
        candidate["cleanup"][0].pop("skipped", None)
        candidate["cleanup"][0]["status"] = 200
        candidate["cleanup"][0]["body"] = {
            "name": candidate["plan"]["document"],
            "fields": candidate["plan"]["fixtureFields"],
            "updateTime": timestamp,
        }
        candidate["cleanup"][1].pop("skipped", None)
        candidate["cleanup"][1]["status"] = 200
        candidate["cleanup"][1]["body"] = {}
        candidate["cleanup"][1]["request"]["path"] = candidate["plan"]["recovery"][1]["path"] + "?currentDocument.updateTime=" + encoded.replace(":", "%3A")
        candidate["raw"]["7"].update(status=200, complete=True)
        candidate["rows"][1]["body"]["updateTime"] = timestamp
        candidate["rows"][3]["body"]["updateTime"] = timestamp
        candidate["rows"][5]["body"]["updateTime"] = timestamp
        candidate["cleanup"][0]["body"]["updateTime"] = timestamp
        candidate["cleanup"][1]["request"]["path"] = candidate["cleanup"][1]["request"]["path"].replace(
            "2026-09-18T00%3A00%3A00Z", encoded.replace(":", "%3A")
        )
        for slot in (1, 3, 5, 6):
            body = candidate["rows"][slot]["body"] if slot < 6 else candidate["cleanup"][0]["body"]
            raw_body = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
            candidate["raw"][str(slot)].update(
                rawBody=raw_body,
                sourceRawSha256=hashlib.sha256(raw_body).hexdigest(),
                **({"status": 200, "complete": True} if slot == 6 else {}),
                byteCount=len(raw_body),
            )
            (candidate["rows"][slot] if slot < 6 else candidate["cleanup"][0])["rawSha256"] = candidate["raw"][str(slot)]["sourceRawSha256"]
        candidate["raw"]["7"].update(
            rawBody=b"{}", sourceRawSha256=hashlib.sha256(b"{}").hexdigest(), byteCount=2
        )
        candidate["cleanup"][1]["rawSha256"] = candidate["raw"]["7"]["sourceRawSha256"]
    assert compare_evidence(left, right)["classification"] == "EXPECTED_NONDETERMINISM"


def test_loader_binds_persisted_raw_bytes_and_manifest_slots(tmp_path):
    bundle = _bundle()
    output = tmp_path / "receipt"
    output.mkdir()
    journal = RawJournal(output / "raw")
    for slot in range(9):
        view = bundle["raw"][str(slot)]
        if slot == 7:
            view = {**view, "status": 404, "complete": False}
        binding = journal.add(
            view["phase"],
            view["index"],
            view["status"],
            view["rawBody"],
            complete=view["complete"],
            content_type="application/json; charset=UTF-8",
        )
        row = bundle["rows"][slot] if slot < 6 else bundle["cleanup"][slot - 6]
        row["raw"] = copy.deepcopy(binding)
        row["rawSha256"] = binding["sha256"]
    journal.close()
    persisted = copy.deepcopy(bundle)
    persisted["raw"] = None
    (output / "collection.json").write_text(
        json.dumps(persisted, sort_keys=True, separators=(",", ":"))
    )

    loaded = load_collected_bundle(output)

    assert loaded["raw"]["2"]["rawBody"] == bundle["raw"]["2"]["rawBody"]
    assert loaded["raw"]["2"]["sourceRawSha256"] == bundle["raw"]["2"]["sourceRawSha256"]
    assert loaded["raw"]["2"]["contentType"] == "application/json; charset=UTF-8"


def test_loader_rejects_missing_raw_slot_without_reconstructing_bytes(tmp_path):
    bundle = _bundle()
    output = tmp_path / "receipt"
    output.mkdir()
    journal = RawJournal(output / "raw")
    for slot in range(8):
        view = bundle["raw"][str(slot)]
        if slot == 7:
            view = {**view, "status": 404, "complete": False}
        binding = journal.add(
            view["phase"], view["index"], view["status"], view["rawBody"],
            complete=view["complete"], content_type="application/json",
        )
        row = bundle["rows"][slot] if slot < 6 else bundle["cleanup"][slot - 6]
        row["raw"] = copy.deepcopy(binding)
        row["rawSha256"] = binding["sha256"]
    journal.close()
    bundle["raw"] = None
    (output / "collection.json").write_text(json.dumps(bundle))

    with pytest.raises(ValueError, match="nine raw slots"):
        load_collected_bundle(output)
