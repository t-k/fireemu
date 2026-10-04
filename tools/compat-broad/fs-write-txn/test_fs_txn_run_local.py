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
