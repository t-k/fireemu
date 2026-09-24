"""Offline metrics only: full real compiler; no fireemu or production claims.

Google protobuf serialization cross-checks live in the companion validation
script so this normal suite adds no runtime dependency beyond existing pytest.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import request_bytes_metric_audit as audit
from request_bytes_catalog_samples import compile_catalog_sample_plan
from request_bytes_compiler import (
    CATALOG_MAXIMUM,
    compact_utf8,
    compile_request_bytes_plan,
    validate_request_bytes_plan,
)

DATABASE = "projects/fireemu-35fe6/databases/(default)"
PROJECT = "fireemu-35fe6"
NONCE = "0" * 32  # fabricated input, NEVER a production nonce or live evidence


def _body(text="x"):
    return {"writes": [{"update": {
        "name": DATABASE + "/documents/c/d",
        "fields": {"blob": {"stringValue": text}},
    }, "currentDocument": {"exists": False}}]}


@pytest.fixture(scope="module")
def original_plan():
    return compile_catalog_sample_plan(PROJECT, "(default)", NONCE)


def test_audit_is_anchored_on_the_10_mib_catalog_samples():
    # The strict campaign moved to 11 MiB; this audit stays a 10 MiB study.
    assert audit.AUDIT_LIMIT == CATALOG_MAXIMUM == 10_485_760


@pytest.mark.parametrize("index, expected", [(0, 10484525), (1, 10484526), (2, 10484527)])
def test_real_compiler_raw_boundaries_are_all_below_proto_boundary(original_plan, index, expected):
    probe = original_plan["probes"][index]
    raw = compact_utf8(probe["body"])
    measured = audit.measure_body(raw, DATABASE)
    assert len(raw) == CATALOG_MAXIMUM + index - 1
    assert measured["protobufCommitRequestBytes"] == expected
    assert measured["rawMinusProtobufBytes"] == 1234
    assert measured["protobufExceeds10MiB"] is False
    assert measured["rawExceeds10MiB"] is (index == 2)
    assert measured["protobufDatabaseFieldBytes"] == 44
    assert measured["protobufEmbeddedPreconditionsBytes"] == 4 * 17
    assert measured["documentCount"] == 17
    assert measured["maxDocumentLogicalBytes"] == 655228


@pytest.mark.parametrize("offset, raw_size", [(-1, 10486993), (0, 10486994), (1, 10486995)])
def test_proposed_proto_boundaries_are_exact_and_keep_create_only_shape(original_plan, offset, raw_size):
    probe = original_plan["probes"][offset + 1]
    before = compact_utf8(probe["body"])
    candidate = audit.candidate_at_proto_size(probe["body"], DATABASE, CATALOG_MAXIMUM + offset)
    result = audit.measure_body(candidate, DATABASE)
    assert result["protobufCommitRequestBytes"] == CATALOG_MAXIMUM + offset
    assert len(candidate) == raw_size
    assert result["everyDocumentBelowCampaignMargin"] is True
    assert result["maxDocumentLogicalBytes"] == 656461
    assert compact_utf8(probe["body"]) == before  # immutable original input
    decoded = json.loads(candidate)
    assert [w["update"]["name"] for w in decoded["writes"]] == probe["resources"]
    assert all(w["currentDocument"] == {"exists": False} for w in decoded["writes"])
    assert all(w["update"]["fields"]["_owner"] == {"stringValue": NONCE} for w in decoded["writes"])


def test_two_spaces_cross_raw_threshold_without_changing_decoded_input(original_plan):
    raw = compact_utf8(original_plan["probes"][0]["body"])
    padded = b"  " + raw
    assert json.loads(raw) == json.loads(padded)
    a, b = audit.measure_body(raw, DATABASE), audit.measure_body(padded, DATABASE)
    assert a["protobufCommitRequestBytes"] == b["protobufCommitRequestBytes"] == 10484525
    assert a["rawExceeds10MiB"] is False and b["rawExceeds10MiB"] is True
    assert a["rawBodySha256"] != b["rawBodySha256"]
    assert a["compactRestBodyBytes"] == b["compactRestBodyBytes"]


def test_json_escape_changes_only_wire_representation():
    raw = compact_utf8(_body("x"))
    escaped = raw.replace(b'"stringValue":"x"', b'"stringValue":"\\u0078"')
    assert escaped != raw and json.loads(escaped) == json.loads(raw)
    a, b = audit.measure_body(raw, DATABASE), audit.measure_body(escaped, DATABASE)
    assert a["protobufCommitRequestBytes"] == b["protobufCommitRequestBytes"]
    assert b["rawRestBodyBytes"] - a["rawRestBodyBytes"] == 5


@pytest.mark.parametrize("text", ["", "日本語", "é", "e\u0301", "😀", "\\\"\n\t", "\x00"])
def test_utf8_json_escaping_and_no_normalization(text):
    obj = _body(text)
    raw = compact_utf8(obj)
    escaped = json.dumps(obj, ensure_ascii=True, indent=2).encode()
    a, b = audit.measure_body(raw, DATABASE), audit.measure_body(escaped, DATABASE)
    assert a["protobufCommitRequestBytes"] == b["protobufCommitRequestBytes"]
    assert a["stringValueUtf8Bytes"] == len(text.encode("utf-8"))
    assert a["rawRestBodyBytes"] == len(raw)
    assert b["rawRestBodyBytes"] == len(escaped)


def test_empty_string_oneof_and_false_precondition_count_known_wire_bytes():
    # Database field: tag + len + 42 bytes = 44. Document name = 56 bytes.
    # Empty Value.string_value is 8a 01 00 (3 bytes), not omitted.
    # fields entry: key 0a 04 'blob' + value 12 03 [8a 01 00] = 11 bytes.
    # Document: name 58 + fields(2+11) = 71. Write: update(2+71) + precond 22 02 08 00 = 77.
    # Commit: database 44 + writes(2+77) = 123.
    result = audit.measure_body(compact_utf8(_body("")), DATABASE)
    assert result["protobufCommitRequestBytes"] == 123
    assert result["protobufEmbeddedPreconditionsBytes"] == 4
    assert result["maxDocumentProtobufBytes"] == 71


@pytest.mark.parametrize("n, size", [(0, 1), (127, 1), (128, 2), (16383, 2), (16384, 3), (2097151, 3), (2097152, 4)])
def test_varint_widths(n, size):
    assert audit._varint_bytes(n) == size


def test_string_field_17_has_two_byte_tag():
    assert audit._length_delimited(17, 0) == 3
    assert audit._length_delimited(1, 0) == 2


@pytest.mark.parametrize("mutate", [
    lambda b: b.update(transaction=""),
    lambda b: b.update(database=DATABASE),
    lambda b: b["writes"][0].update(updateMask={}),
    lambda b: b["writes"][0].update(updateTransforms=[]),
    lambda b: b["writes"][0]["update"].update(updateTime="2020-01-01T00:00:00Z"),
    lambda b: b["writes"][0].pop("currentDocument"),
    lambda b: b["writes"][0]["currentDocument"].update(exists=True),
    lambda b: b["writes"][0]["currentDocument"].update(exists=0),
    lambda b: b["writes"][0]["update"]["fields"].update(blob={"integerValue": "1"}),
    lambda b: b["writes"][0]["update"]["fields"].update(blob={"stringValue": 1}),
    lambda b: b["writes"][0]["update"]["fields"].update(blob={"stringValue": "x", "bytesValue": ""}),
    lambda b: b["writes"][0]["update"].update(name="projects/other/databases/(default)/documents/c/d"),
    lambda b: b["writes"].append(copy.deepcopy(b["writes"][0])),
    lambda b: b.update(writes=[]),
    lambda b: b["writes"][0]["update"].update(fields={"": {"stringValue": "x"}}),
])
def test_unsupported_data_is_refused_not_silently_undercounted(mutate):
    body = _body()
    mutate(body)
    with pytest.raises(ValueError):
        audit.measure_body(compact_utf8(body), DATABASE)


@pytest.mark.parametrize("raw", [b"", b"{}", b"null", b"{", b'{"writes":[],"writes":[]}',
                                    b'{"writes":NaN}', b'"\\ud800"', b"\xff"])
def test_bad_json_never_yields_measurement(raw):
    with pytest.raises(ValueError):
        audit.measure_body(raw, DATABASE)


def test_audit_never_mutates_or_resizes_frozen_plan(original_plan):
    before = hashlib.sha256(compact_utf8(original_plan)).hexdigest()
    result = audit.audit_compiled(PROJECT, "(default)", NONCE)
    assert result["originalMetricStatus"] == "observation hypothesis"
    assert result["inputKind"] == "compiler-regeneration-not-production-evidence"
    assert len(result["rows"]) == 3 and len(result["offlineCandidatesNotAuthorized"]) == 4
    assert hashlib.sha256(compact_utf8(original_plan)).hexdigest() == before


def test_saved_file_hash_binds_raw_bytes_before_reserialization(tmp_path):
    raw = b" \n" + compact_utf8(_body())
    path = tmp_path / "body.json"
    path.write_bytes(raw)
    before = path.read_bytes()
    result = audit.measure_saved_file(path, DATABASE, hashlib.sha256(raw).hexdigest())
    assert result["rows"][0]["rawRestBodyBytes"] == len(raw)
    assert result["rows"][0]["compactRestBodyBytes"] == len(raw) - 2
    assert path.read_bytes() == before
    with pytest.raises(ValueError, match="hash-mismatch"):
        audit.measure_saved_file(path, DATABASE, hashlib.sha256(compact_utf8(_body())).hexdigest())


def test_fifo_is_refused_without_waiting_for_writer(tmp_path):
    fifo = tmp_path / "not-a-file"
    os.mkfifo(fifo)
    result = subprocess.run([sys.executable, str(Path(audit.__file__)), "body", "--database-resource", DATABASE,
                             "--body-file", str(fifo), "--sha256", "0" * 64],
                            capture_output=True, text=True, timeout=5, check=False)
    assert result.returncode == 2 and not result.stdout


def test_cli_raw_file_is_read_only_and_never_claims_observation(tmp_path):
    raw = compact_utf8(_body("PRIVATE_VALUE_NOT_TO_REPORT"))
    path = tmp_path / "body.json"
    path.write_bytes(raw)
    args = [sys.executable, str(Path(audit.__file__)), "body", "--database-resource", DATABASE,
            "--body-file", str(path), "--sha256", hashlib.sha256(raw).hexdigest()]
    proc = subprocess.run(args, capture_output=True, text=True, timeout=5, check=False)
    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout)
    assert report["productionExecuted"] is False
    assert report["authorizesNetwork"] is False
    assert report["compatibility"] == "NOT_ASSESSED"
    assert report["backendQuotaMetric"] == "UNVERIFIED"
    assert "PRIVATE_VALUE_NOT_TO_REPORT" not in proc.stdout
    assert path.read_bytes() == raw
    assert sorted(p.name for p in tmp_path.iterdir()) == ["body.json"]


def test_cli_bad_hash_does_not_echo_private_body(tmp_path):
    path = tmp_path / "body.json"
    path.write_bytes(compact_utf8(_body("PRIVATE_VALUE")))
    result = subprocess.run([sys.executable, str(Path(audit.__file__)), "body", "--database-resource", DATABASE,
                             "--body-file", str(path), "--sha256", "0" * 64],
                            capture_output=True, text=True, timeout=5, check=False)
    assert result.returncode == 2 and not result.stdout
    assert "PRIVATE_VALUE" not in result.stderr


def test_body_bound_is_local_and_not_the_claimed_service_limit(monkeypatch):
    raw = compact_utf8(_body())
    monkeypatch.setattr(audit, "MAX_AUDIT_BYTES", len(raw) - 1)
    with pytest.raises(ValueError, match="out-of-audit-scope"):
        audit.measure_body(raw, DATABASE)


def _imported_modules(path):
    import ast
    tree = ast.parse(Path(path).read_text())
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name.split(".")[0] for alias in node.names)
        if isinstance(node, ast.ImportFrom):
            modules.add(node.module.split(".")[0])
    return modules


def test_no_network_client_gate_or_ledger_is_imported():
    assert _imported_modules(audit.__file__) <= {
        "__future__", "argparse", "copy", "hashlib", "json", "os", "re", "stat", "sys",
        "pathlib", "typing", "request_bytes_compiler", "request_bytes_catalog_samples",
    }
    # The catalog sample module only loads the compiler by exact path.
    samples = Path(audit.__file__).with_name("request_bytes_catalog_samples.py")
    assert _imported_modules(samples) <= {"__future__", "importlib", "pathlib", "typing"}
