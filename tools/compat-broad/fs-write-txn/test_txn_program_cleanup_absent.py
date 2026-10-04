"""A document a refused writer never created is absent, not owed: the recovery's read proves it and nothing is deleted."""

import importlib

import pytest

support = importlib.import_module("txn_program_support_for_tests")
program = importlib.import_module("txn_program_program")
collector_module = importlib.import_module("txn_program_collector")
NONCE, OWNER = "a" * 32, "b" * 32


def ledger():
    plan = program.compile_plan(support.TABLE, NONCE, OWNER)
    return collector_module.Ledger(plan), plan


def read(value, role, code, response=None):
    result = {"code": code, "details": "" if code == 0 else "not found", "response": response, "http": None}
    value._cleanup_read(f"cleanup/read/{role}", role, "grpc", result, code)


def test_an_owed_document_that_the_recovery_reads_as_not_found_is_absent():
    value, _plan = ledger()
    value.docs["a"]["status"] = "possibly-owned"
    read(value, "a", 5)
    assert value.docs["a"]["status"] == "confirmed-absent"
    assert "a" not in value.owed_documents() and value.all_absent() is False   # the other document is still unexamined


def test_a_document_this_recording_acknowledged_that_the_recovery_cannot_read_is_still_an_error():
    value, _plan = ledger()
    value.docs["a"]["status"] = "created"
    with pytest.raises(ValueError, match="not readable"):
        read(value, "a", 5)
    assert value.docs["a"]["status"] == "created"


@pytest.mark.parametrize("code", [3, 10, 14])
def test_a_possibly_owned_document_read_with_any_other_refusal_is_not_settled(code):
    value, _plan = ledger()
    value.docs["a"]["status"] = "possibly-owned"
    with pytest.raises(ValueError, match="not readable"):
        read(value, "a", code)
    assert value.docs["a"]["status"] == "possibly-owned"
