"""Foreign tokens stay within the run's declared resources."""

import fs_txn_table_p16 as p16
import txn_program_cli as cli
from txn_program_program import compile_plan, request_for_step


def test_p16_is_registered_and_resolves_run_prefixed_database_names():
    assert cli.table_for("p16-foreign-tokens") is p16.TABLE
    first = compile_plan(p16.TABLE, "a" * 32, "b" * 32)
    second = compile_plan(p16.TABLE, "c" * 32, "b" * 32)
    assert first["databases"]["named"] == "projects/fireemu-oracle-query/databases/txn-" + "a" * 32
    assert first["databases"]["named"] != second["databases"]["named"]
    assert first["documents"]["m"].startswith("projects/fireemu-oracle-txn/databases/(default)/documents/oracle/" + "a" * 32)


def test_rest_covers_every_foreign_rpc_and_grpc_has_representatives_with_valid_controls():
    plan = compile_plan(p16.TABLE, "a" * 32, "b" * 32)
    for alias, expected in (("named", {"GetDocument", "BatchGetDocuments", "Commit", "Rollback"}), ("foreign", {"GetDocument", "BatchGetDocuments", "Rollback"})):
        cases = [s for s in plan["steps"] if s["role"] == "observation" and s.get("onDatabase") == alias]
        assert {s["rpc"] for s in cases if s["transport"] == "rest"} == expected
        assert any(s["transport"] == "grpc" for s in cases)
        assert len({s["tokenInput"] for s in cases}) == len(cases)
        for step in cases:
            begin = next(s for s in plan["steps"] if s["tokenOutput"] == step["tokenInput"])
            assert "onDatabase" not in begin
            request_for_step(plan, step, {step["tokenInput"]: "dG9rZW4="}, p16.TABLE)
    for transport in ("rest", "grpc"):
        controls = [s for s in plan["steps"] if s["transport"] == transport and s.get("onDatabase") == "named" and s["role"] == "control"]
        assert {s["rpc"] for s in controls} >= {"BeginTransaction", "GetDocument", "BatchGetDocuments", "Commit", "Rollback"}
    assert all(not s["writes"] and s["rpc"] != "Commit" for s in plan["steps"] if s.get("onDatabase") == "foreign")
    assert sum(s["rpc"] == "BeginTransaction" for s in plan["steps"]) == plan["maxTokens"]
