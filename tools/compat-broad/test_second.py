"""Second exploration inputs and safety properties do not invent production answers."""

import copy
import importlib.util


def second():
    assert importlib.util.find_spec("second_cases"), (
        "separately identified second corpus required"
    )
    import second_cases

    return second_cases


def test_second_catalog_separates_shapes_and_preserves_first_manifest():
    from batch_contract import candidate
    from broad_contract import digest

    s = second()
    old = digest(candidate())
    manifest = s.manifest()
    assert manifest["kind"] == "second-broad-local-v1"
    assert manifest["productionApproval"] is None
    assert manifest["productionExecutable"] is False
    cases = manifest["authCases"]
    assert len(cases) == 32 and len({c["id"] for c in cases}) == 32
    assert {"missing", "null", "number", "object", "array", "self", "other"} <= {
        c.get("selector") for c in cases
    }
    assert {
        "displayName-shape",
        "restricted-mix",
        "verification-shape",
        "principal",
        "selector",
        "admin-control",
    } <= {c["dimension"] for c in cases}
    assert all(c["productionExpectation"] is None for c in cases)
    assert len(s.firestore_cases()) == 6
    assert digest(candidate()) == old
    assert digest(manifest) != old


def test_safety_checks_are_not_http_expectations():
    s = second()
    before = {
        "a": {"localId": "a", "displayName": "A", "emailVerified": False},
        "b": {"localId": "b", "displayName": "B", "emailVerified": False},
    }
    after = copy.deepcopy(before)
    after["b"]["displayName"] = "changed"
    case = {"actor": "b", "dimension": "selector"}
    assert all(s.auth_invariants(case, 200, before, after).values())
    assert not all(s.auth_invariants(case, 400, before, after).values())
    assert all(s.auth_invariants(case, 400, before, before).values())
    assert all(s.auth_invariants(case, 200, before, before).values())
    after["a"]["displayName"] = "intrusion"
    assert not all(s.auth_invariants(case, 200, before, after).values())
    assert not all(s.auth_invariants({"actor": "missing"}, 200, before, after).values())
    after = copy.deepcopy(before)
    after["b"]["customAttributes"] = '{"admin":true}'
    assert not all(s.auth_invariants(case, 200, before, after).values())


def test_firestore_refusal_invariant_is_conditional_and_keeps_unknown_outcome():
    s = second()
    assert s.state_invariant(400, {"n": 1}, {"n": 1}) is True
    assert s.state_invariant(400, {"n": 1}, {"n": 2}) is False
    assert s.state_invariant(200, {"n": 1}, {"n": 2}) is None
    for case in s.firestore_cases():
        assert "expect" not in str(case)
        assert [x["id"] for x in case["steps"]][-1] == "after"
        assert any(x["id"] == "before" for x in case["steps"])


def test_no_response_and_missing_steps_are_not_completed_observations():
    s = second()
    program = s.firestore_cases()[0]
    good: dict[str, object] = {
        "status": 200,
        "code": "OK",
        "body": {"fields": {"n": 1}},
    }
    bad_cases: list[dict[str, object] | None] = [
        {"status": 0, "code": "no-response"},
        {"status": 0, "code": "probe-error"},
        None,
    ]
    for bad in bad_cases:
        values = {x["id"]: copy.deepcopy(good) for x in program["steps"]}
        if bad is None:
            values.pop("diagnostic")
        else:
            values["diagnostic"] = bad
        actual = {program["id"]: {"steps": values}}
        rows = s.firestore_rows([program], actual, [], {"programs": []})
        assert (
            next(r for r in rows if r["id"].endswith("#diagnostic"))["status"]
            == "missing"
        )
        assert (
            next(r for r in rows if r["id"].endswith("#state-invariant"))["status"]
            != "pass"
        )
        assert not s.recording_complete([program], actual)
    values = {x["id"]: copy.deepcopy(good) for x in program["steps"]}
    values["diagnostic"] = {"status": 400, "code": "INVALID_ARGUMENT", "body": {}}
    assert s.recording_complete([program], {program["id"]: {"steps": values}})


def test_second_exit_code_keeps_cleanup_and_compatibility_separate():
    s = second()
    good = {
        "status": "completed",
        "recordingComplete": True,
        "ownedProcess": {"stopped": True, "listenersClosed": True},
        "auth": {"completed": True, "failure": None, "unrecovered": []},
        "cases": [{"status": "mismatch", "basis": "historical-production-reference"}],
    }
    assert s.exit_code(good) == 0
    for patch in [
        {"cleanupFailure": "ValueError"},
        {"parentCleanupFailure": "ValueError"},
        {"status": "incomplete"},
        {"recordingComplete": False},
        {"ownedProcess": {"stopped": False, "listenersClosed": True}},
    ]:
        assert s.exit_code({**good, **patch}) == 2
    assert s.exit_code({**good, "cases": [{"status": "fail"}]}) == 1


def test_second_manifest_is_reproducible_and_has_no_inherited_permission():
    import json

    from broad_contract import ROOT

    s = second()
    stored = json.loads(
        (ROOT / "spec/compatibility/broad-second-candidate.json").read_bytes()
    )
    assert stored == s.manifest()
    assert not stored["productionExecutable"] and stored["productionApproval"] is None
