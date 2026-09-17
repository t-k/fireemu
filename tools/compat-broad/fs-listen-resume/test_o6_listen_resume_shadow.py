from o6_listen_resume.manifest import compile_plan
from o6_listen_resume.shadow import run_shadow


def test_shadow_is_offline_and_emits_one_revision_per_document():
    plan = compile_plan("3" * 32)
    receipt = run_shadow(plan)
    assert receipt["productionExecuted"] is False
    assert receipt["sdk"]["firebase"] == "12.18.0"
    assert receipt["transport"]["interruptionObserved"] is True
    assert receipt["transport"]["reconnectObserved"] is True
    assert receipt["cleanup"] == {
        resource["path"]: True for resource in plan["ownedResources"]
    }
    revisions = [
        (event["document"], event["revision"])
        for event in receipt["events"]
        if event["revision"] is not None
    ]
    assert revisions.count((plan["ownedResources"][0]["path"], 0)) == 1
    assert revisions.count((plan["ownedResources"][0]["path"], 1)) == 1
    assert revisions.count((plan["ownedResources"][0]["path"], 2)) == 1
    assert revisions.count((plan["ownedResources"][1]["path"], 0)) == 1


def test_negative_shadow_refuses_stale_compacted_and_reset_tokens():
    plan = compile_plan("4" * 32)
    receipt = run_shadow(plan, scenario="negative")
    errors = [
        (event["tokenCase"], event["errorCode"])
        for event in receipt["events"]
        if event["errorCode"]
    ]
    assert errors == [
        ("stale-token", "FAILED_PRECONDITION"),
        ("compacted-token", "FAILED_PRECONDITION"),
        ("session-reset", "ABORTED"),
    ]
