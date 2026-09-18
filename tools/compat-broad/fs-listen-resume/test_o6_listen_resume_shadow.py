from o6_listen_resume.manifest import compile_plan
from o6_listen_resume.shadow import run_shadow


def test_shadow_is_offline_and_emits_expected_logical_events_only():
    plan = compile_plan("3" * 32)
    receipt = run_shadow(plan)
    assert receipt["status"] == "PREPARATION_ONLY"
    assert receipt["productionExecuted"] is False
    assert receipt["sdk"]["firebase"] == "12.18.0"
    assert "expectedLogicalEvents" in receipt
    assert not {"collector", "transport", "bounds", "cleanup"} & receipt.keys()
    revisions = [
        (event["document"], event["revision"])
        for event in receipt["expectedLogicalEvents"]
        if event["revision"] is not None
    ]
    assert revisions.count((plan["ownedResources"][0]["path"], 0)) == 1
    assert revisions.count((plan["ownedResources"][0]["path"], 1)) == 1
    assert revisions.count((plan["ownedResources"][0]["path"], 2)) == 1
    assert revisions.count((plan["ownedResources"][1]["path"], 0)) == 1


def test_negative_shadow_keeps_unimplemented_token_cases_as_obligations():
    plan = compile_plan("4" * 32)
    receipt = run_shadow(plan, scenario="negative")
    assert receipt["unsupportedObligations"] == plan["unsupportedObligations"]
    assert all(
        event["snapshotType"] != "error" for event in receipt["expectedLogicalEvents"]
    )
