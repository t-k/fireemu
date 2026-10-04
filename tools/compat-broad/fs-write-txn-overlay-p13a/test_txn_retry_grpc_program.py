"""P09 closes its data graph and leaves reserved cleanup available on stop."""

import importlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))


def program():
    return importlib.import_module("txn_retry_grpc_program")


def test_closed_graph_has_one_owned_document_and_a_48_request_cap():
    p = program()
    value = p.compile_plan("a" * 32, "b" * 32)
    assert len(value["steps"]) == value["caps"]["observation"] == 25
    assert value["caps"] == {"observation": 25, "tokenCleanup": 7, "documentCleanup": 7, "management": 7, "credential": 2}
    assert sum(value["caps"].values()) == p.MAX_REQUESTS == 48
    assert value["document"] == "projects/fireemu-oracle-sbx/databases/(default)/documents/oracle/" + "a" * 32 + "/txn-p09/control"
    assert len({row["id"] for row in value["steps"]}) == 25
    assert {row["rpc"] for row in value["steps"]} == {"BeginTransaction", "GetDocument", "Commit", "Rollback"}
    assert value["iamConfig"] == "none" and value["retries"] == "none"


@pytest.mark.parametrize("nonce,owner", [("x", "b" * 32), ("a" * 32, "../escape"), ("A" * 32, "b" * 32), ("a" * 32 + "/x", "b" * 32)])
def test_identity_cannot_escape_the_closed_owned_path(nonce, owner):
    with pytest.raises(ValueError):
        program().compile_plan(nonce, owner)


def test_next_step_cannot_be_skipped_duplicated_or_replaced():
    p = program()
    value = p.compile_plan("a" * 32, "b" * 32)
    cursor = p.GraphCursor(value)
    with pytest.raises(ValueError):
        cursor.claim("setup/create")
    assert cursor.claim("setup/absence")["rpc"] == "GetDocument"
    with pytest.raises(ValueError):
        cursor.claim("setup/absence")
    assert cursor.claim("setup/create")["rpc"] == "Commit"
    with pytest.raises(ValueError):
        cursor.claim("unknown/foreign")
    for row in value["steps"][2:]:
        cursor.claim(row["id"])
    assert cursor.complete is True
    with pytest.raises(ValueError):
        cursor.claim(value["steps"][-1]["id"])


def test_observation_exhaustion_does_not_spend_cleanup_reserves():
    p = program()
    budget = p.RequestBudget(p.compile_plan("a" * 32, "b" * 32))
    for _ in range(25):
        budget.charge("observation")
    with pytest.raises(ValueError):
        budget.charge("observation")
    for phase, count in (("tokenCleanup", 7), ("documentCleanup", 7), ("management", 7), ("credential", 2)):
        for _ in range(count):
            budget.charge(phase)
        with pytest.raises(ValueError):
            budget.charge(phase)
    assert budget.total == 48
    with pytest.raises(ValueError):
        budget.charge("arbitrary")


def test_case_map_distinguishes_native_bytes_from_rest_base64_decoding():
    p = program()
    value = p.compile_plan("a" * 32, "b" * 32)
    assert set(value["cases"]) == {"grpc/retry-with-committed-previous", "grpc/retry-with-rolled-back-previous", "grpc/retry-with-read-only-previous", "grpc/retry-with-unissued-previous", "grpc/rollback-after-commit", "grpc/rollback-after-rollback"}
    assert not any("malformed" in name for name in value["cases"])
    assert p.UNKNOWN_TOKEN == "AAAAAAAAAAA="
    assert value["sourceDigest"] == p.source_digest()
    assert value["corpusDigest"] == p.corpus_digest()


def test_mutated_request_graph_or_reserve_is_refused():
    p = program()
    for mutate in (lambda v: v["steps"].pop(), lambda v: v["caps"].update({"observation": 26}), lambda v: v.update({"document": "projects/foreign/databases/(default)/documents/other/x"})):
        value = p.compile_plan("a" * 32, "b" * 32)
        mutate(value)
        with pytest.raises(ValueError):
            p.validate_plan(value)


def test_dynamic_requests_keep_owned_markers_and_only_use_issued_token_bindings():
    p = program()
    value = p.compile_plan("a" * 32, "b" * 32)
    rows = {row["id"]: row for row in value["steps"]}
    create = p.request_for_step(value, rows["setup/create"], {})
    write = create["writes"][0]
    assert write["currentDocument"] == {"exists": False}
    assert write["update"]["name"] == value["document"]
    assert write["update"]["fields"]["owner"] == {"stringValue": "b" * 32}
    assert write["update"]["fields"]["nonce"] == {"stringValue": "a" * 32}
    with pytest.raises(ValueError):
        p.request_for_step(value, rows["committed/retry"], {})
    with pytest.raises(ValueError):
        p.request_for_step(value, rows["committed/retry"], {"committed": "not base64!"})
    request = p.request_for_step(value, rows["committed/retry"], {"committed": "AQ=="})
    assert request == {"database": value["database"], "options": {"readWrite": {"retryTransaction": "AQ=="}}}
    assert p.request_for_step(value, rows["read-only/begin"], {})["options"] == {"readOnly": {}}
    assert p.request_for_step(value, rows["unknown/retry"], {})["options"]["readWrite"]["retryTransaction"] == p.UNKNOWN_TOKEN
