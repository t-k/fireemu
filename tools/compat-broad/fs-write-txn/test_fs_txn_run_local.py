"""The local rehearsal tool's summary: every step's answer in order, the cleanup apart, and what was left unknown."""

import fs_txn_run_local as tool


def row(site, code, details="", transport="rest", rpc="GetDocument"):
    return {"site": site, "transport": transport, "rpc": rpc, "result": {"code": code, "details": details}}


def test_the_summary_keeps_every_step_in_order_and_the_cleanup_apart():
    receipt = {"complete": True, "failureType": None, "steps": [row("a", 0), row("b", 5, "x" * 300, "grpc", "Commit")], "cleanupSteps": [row("cleanup/token/t", 0, "", "rest", "Rollback")],
               "unknownStarts": [], "unknownRollbacks": [], "unknownCommits": [], "waits": [{"site": "b"}]}
    summary = tool.summarize(receipt)
    assert [step["site"] for step in summary["steps"]] == ["a", "b"] and summary["steps"][1] == {"site": "b", "transport": "grpc", "rpc": "Commit", "code": 5, "details": "x" * 100}
    assert summary["cleanup"][0]["rpc"] == "Rollback" and summary["waits"] == [{"site": "b"}] and summary["complete"] is True


def test_a_stopped_recording_reports_its_failure_and_what_it_left_unknown():
    receipt = {"complete": False, "failureType": "ValueError", "steps": [], "cleanupSteps": [], "unknownStarts": ["s"], "unknownRollbacks": ["r"], "unknownCommits": ["c"]}
    summary = tool.summarize(receipt)
    assert (summary["complete"], summary["failure"], summary["unknownStarts"], summary["unknownRollbacks"], summary["unknownCommits"], summary["waits"]) == (False, "ValueError", ["s"], ["r"], ["c"], [])


def test_local_main_passes_the_compiled_declarations_to_node_wire(tmp_path, monkeypatch):
    import sys
    import txn_program_wire as wire_module
    import fs_txn_table_p16 as p16
    scopes = []
    class Recording:
        def __init__(self, plan, table, budget, wire, *args, **kwargs):
            assert wire.scope["databases"] == plan["databases"]
            assert wire.scope["placements"] == p16.TABLE["placements"]
            assert "{nonce}" not in wire.scope["databases"]["named"]
            scopes.append(wire.scope)
        def _observe(self): pass
        def run(self):
            return {"complete": True, "failureType": None, "steps": [], "cleanupSteps": [], "unknownStarts": [], "unknownRollbacks": [], "unknownCommits": []}
    monkeypatch.setattr(tool, "Collector", Recording)
    monkeypatch.setattr(wire_module, "discover_runtime", lambda _: {})
    monkeypatch.setattr(wire_module, "verify_runtime", lambda _: None)
    monkeypatch.setenv("SMOKE_TABLE", "fs_txn_table_p16")
    monkeypatch.setenv("FIRESTORE_EMULATOR_HOST", "127.0.0.1:12345")
    monkeypatch.delenv("COMPARE_CLOCK", raising=False)
    monkeypatch.setattr(sys, "argv", ["fs_txn_run_local.py", str(tmp_path / "summary.json")])
    tool.main()
    assert len(scopes) == 1
