"""The per-commit Txn-04 replay judge: the committed production projection decides a fresh binary's answers in both profiles."""

import copy
import json
import random
import sys
from pathlib import Path

import pytest

sys.path[:0] = [str(Path(__file__).parent), str(Path(__file__).parents[1]), str(Path(__file__).parents[2] / "compat-inventory")]
import txn04_current_replay as replay
import txn_expiry_comparison as comparison
from broad_contract import digest

ROOT = Path(__file__).resolve().parents[3]
RECORD = ROOT / "spec/compatibility/broad-runs/fs-transaction-expiry-retry-04-recorded-comparison-v1.json"
RELEASE_INPUTS = ROOT / "spec/compatibility/broad-runs/fs-transaction-release-replay-inputs-v1.json"


def record():
    return json.loads(RECORD.read_bytes())


def production():
    return replay.expectations(record(), json.loads(RELEASE_INPUTS.read_bytes()))


def local_like_production():
    expected = production()
    return {"projection": copy.deepcopy(expected["projection"]), "postStates": copy.deepcopy(expected["postStates"])}


def strict_as_published():
    """The strict local answers the committed record says strict gives: production's, except the superseded differences."""
    value = record()
    local = local_like_production()
    differences = value["profiles"]["strict"]["results"][0]["supersededDifferences"]
    for key, pair in differences.items():
        if key.endswith(comparison.POST_STATE):
            local["postStates"][key[: -len(comparison.POST_STATE)]] = pair["local"]
        else:
            local["projection"][key] = pair["local"]
    return local


def test_expectations_come_from_the_committed_record_and_agree_with_the_release_inputs():
    expected = production()
    assert len(expected["projection"]) == 13
    assert expected["superseded"] == set(record()["supersededForStrict"]["cases"])
    assert expected["recordingSha256"] == [row["reference"]["sha256"] for row in record()["recordings"]]


def test_expectations_refuse_a_projection_that_no_longer_matches_its_recorded_digest():
    value = record()
    value["cases"][0]["code"] = 99
    with pytest.raises(ValueError, match="projection digest"):
        replay.expectations(value, json.loads(RELEASE_INPUTS.read_bytes()))


def test_expectations_refuse_post_states_that_no_longer_match_their_recorded_digest():
    value = record()
    key = sorted(value["postStates"])[0]
    value["postStates"][key]["role"] = "other"
    with pytest.raises(ValueError, match="post-state digest"):
        replay.expectations(value, json.loads(RELEASE_INPUTS.read_bytes()))


def test_expectations_refuse_release_inputs_that_disagree_with_the_record():
    inputs = json.loads(RELEASE_INPUTS.read_bytes())
    inputs["special"]["e04"]["recordings"][1]["projection"]["projection"].popitem()
    with pytest.raises(ValueError, match="release replay inputs"):
        replay.expectations(record(), inputs)
    inputs = json.loads(RELEASE_INPUTS.read_bytes())
    inputs["special"]["e04"]["recordings"][0]["originSha256"] = "0" * 64
    with pytest.raises(ValueError, match="release replay inputs"):
        replay.expectations(record(), inputs)


def test_emulator_passes_only_when_every_case_and_post_state_equals_production():
    assert replay.judge_profile("emulator", production(), local_like_production()) == []


def test_emulator_fails_on_any_single_changed_case_or_post_state():
    expected = production()
    for case in sorted(expected["projection"]):
        for field in ("code", "status", "message", "rpc", "role"):
            local = local_like_production()
            local["projection"][case][field] = "changed"
            assert replay.judge_profile("emulator", expected, local), (case, field)
    for case in sorted(expected["postStates"]):
        local = local_like_production()
        local["postStates"][case] = {"role": "x", "document": None}
        assert replay.judge_profile("emulator", expected, local), case


def test_a_missing_or_extra_case_fails_both_profiles():
    expected = production()
    for profile in ("strict", "emulator"):
        local = local_like_production()
        local["projection"].pop(sorted(local["projection"])[0])
        assert replay.judge_profile(profile, expected, local)
        local = local_like_production()
        local["projection"]["extra/case"] = {"code": 0}
        assert replay.judge_profile(profile, expected, local)


def test_strict_passes_with_the_published_superseded_differences():
    assert replay.judge_profile("strict", production(), strict_as_published()) == []


def test_strict_fails_when_the_superseded_commit_after_idle_no_longer_differs():
    # publish.py required this difference: strict refuses a 90 s idle commit that production accepted, which is why the cases are superseded.
    local = strict_as_published()
    local["projection"]["idle-expiry/commit-after-idle"] = copy.deepcopy(production()["projection"]["idle-expiry/commit-after-idle"])
    problems = replay.judge_profile("strict", production(), local)
    assert any("commit-after-idle" in p for p in problems)


def test_strict_fails_on_a_difference_outside_the_superseded_cases():
    expected = production()
    for case in sorted(set(expected["projection"]) - expected["superseded"]):
        local = strict_as_published()
        local["projection"][case]["code"] = "changed"
        assert replay.judge_profile("strict", expected, local), case


def test_strict_ignores_any_answer_in_the_superseded_cases_other_than_requiring_the_commit_difference():
    expected = production()
    local = strict_as_published()
    local["projection"]["idle-expiry/rollback-after-idle"] = {"code": 1, "status": "x", "message": "y", "rpc": "z", "role": "w"}
    assert replay.judge_profile("strict", expected, local) == []


def test_an_unknown_profile_is_refused():
    with pytest.raises(ValueError):
        replay.judge_profile("official", production(), local_like_production())


def test_judging_is_independent_of_key_order():
    # property: the verdict depends on the content of the tables, never on their insertion order
    rng = random.Random(0)
    expected = production()
    for _ in range(50):
        for profile, local in (("emulator", local_like_production()), ("strict", strict_as_published())):
            items = list(local["projection"].items())
            rng.shuffle(items)
            states = list(local["postStates"].items())
            rng.shuffle(states)
            assert replay.judge_profile(profile, expected, {"projection": dict(items), "postStates": dict(states)}) == []


def good_acquired(binary_sha="a" * 64, head="b" * 40, inputs_digest="c" * 64, count=500):
    value = record()
    return {
        "complete": False,
        "selfContract": {"classification": comparison.SEMANTIC_MISMATCH},
        "publication": {"failures": []},
        "child": {"exitCode": 0, "signal": None, "stopped": True},
        "sourceDigestBefore": value["sourceDigest"],
        "sourceDigestAfter": value["sourceDigest"],
        "casesDigest": value["casesDigest"],
        "runtime": {"artifactSha256": binary_sha, "childObservedArtifactSha256": binary_sha, "sourceCommit": head, "runtimeInputsDigest": inputs_digest, "runtimeInputCount": count, "runtimeInputsClean": True, "wrongControlTokenStatus": 403, "pythonRuntime": {"pythonVersion": "3.12.13"}, "childPythonRuntime": {"pythonVersion": "3.12.13"}},
        "receipt": {
            "complete": True, "sourceDigest": value["sourceDigest"], "target": "local", "timing": "control-clock",
            "rows": [{"caseId": row["caseId"]} for row in value["cases"]],
            "unrecovered": [], "openTransactions": [], "unconfirmedTransactionStarts": [], "responsibility": [],
            "transactionReleases": [{"released": True}], "cleanup": [{"complete": True, "absent": True}] * 5,
        },
    }


def binding(**overrides):
    value = {"record": record(), "binary_sha": "a" * 64, "head": "b" * 40, "inputs_digest": "c" * 64}
    value.update(overrides)
    return value


def test_a_clean_receipt_bound_to_this_binary_and_head_has_no_problems():
    assert replay.receipt_problems(good_acquired(), **binding()) == []


MUTATIONS = {
    "self-contract match": lambda a: a.update(selfContract={"classification": comparison.MATCH}),
    "self-contract missing": lambda a: a.pop("selfContract"),
    "publication failure": lambda a: a["publication"]["failures"].append("x"),
    "child exit": lambda a: a["child"].update(exitCode=1),
    "child not stopped": lambda a: a["child"].update(stopped=False),
    "source drift": lambda a: a.update(sourceDigestAfter="d" * 64),
    "source differs from record": lambda a: a.update(sourceDigestBefore="d" * 64, sourceDigestAfter="d" * 64),
    "cases digest": lambda a: a.update(casesDigest="d" * 64),
    "binary sha": lambda a: a["runtime"].update(artifactSha256="d" * 64),
    "child observed sha": lambda a: a["runtime"].update(childObservedArtifactSha256="d" * 64),
    "head": lambda a: a["runtime"].update(sourceCommit="d" * 40),
    "inputs digest": lambda a: a["runtime"].update(runtimeInputsDigest="d" * 64),
    "inputs dirty": lambda a: a["runtime"].update(runtimeInputsClean=False),
    "control token": lambda a: a["runtime"].update(wrongControlTokenStatus=200),
    "python runtime": lambda a: a["runtime"].update(pythonRuntime={"pythonVersion": "3.12.12"}),
    "child python": lambda a: a["runtime"].update(childPythonRuntime={"pythonVersion": "3.12.12"}),
    "receipt incomplete": lambda a: a["receipt"].update(complete=False),
    "receipt source": lambda a: a["receipt"].update(sourceDigest="d" * 64),
    "receipt target": lambda a: a["receipt"].update(target="production"),
    "receipt timing": lambda a: a["receipt"].update(timing="wall-clock"),
    "case missing": lambda a: a["receipt"]["rows"].pop(),
    "case duplicated": lambda a: a["receipt"]["rows"].append(dict(a["receipt"]["rows"][0])),
    "unrecovered": lambda a: a["receipt"]["unrecovered"].append("x"),
    "open transaction": lambda a: a["receipt"]["openTransactions"].append("x"),
    "unconfirmed start": lambda a: a["receipt"]["unconfirmedTransactionStarts"].append("x"),
    "responsibility": lambda a: a["receipt"]["responsibility"].append("x"),
    "unreleased": lambda a: a["receipt"]["transactionReleases"].append({"released": False}),
    "cleanup count": lambda a: a["receipt"].update(cleanup=[{"complete": True, "absent": True}] * 4),
    "cleanup present": lambda a: a["receipt"].update(cleanup=[{"complete": True, "absent": True}] * 4 + [{"complete": True, "absent": False}]),
    "no receipt": lambda a: a.update(receipt=None),
}


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_every_receipt_obligation_is_checked(name):
    acquired = good_acquired()
    MUTATIONS[name](acquired)
    assert replay.receipt_problems(acquired, **binding()), name


def test_dependency_info_must_list_the_checkout_and_no_test_only_tree(tmp_path):
    lines = " ".join(str(tmp_path / f"crates/x/src/m{i}.rs") for i in range(101))
    assert replay.dependency_info_problems(f"target/debug/fireemu: {lines}\n", tmp_path) == []
    assert replay.dependency_info_problems("target/debug/fireemu: " + " ".join(str(tmp_path / f"crates/x/src/m{i}.rs") for i in range(5)) + "\n", tmp_path)
    tainted = lines + " " + str(tmp_path / "crates/x/tests/support.rs")
    assert replay.dependency_info_problems(f"target/debug/fireemu: {tainted}\n", tmp_path)


def test_dependency_info_with_exactly_one_hundred_files_is_too_few(tmp_path):
    # build.py required more than 100 listed files; 100 is the near miss
    exactly = " ".join(str(tmp_path / f"crates/x/src/m{i}.rs") for i in range(100))
    assert replay.dependency_info_problems(f"target/debug/fireemu: {exactly}\n", tmp_path)


def release_inputs():
    return json.loads(RELEASE_INPUTS.read_bytes())


def test_expectations_refuse_a_record_with_fewer_cases_even_when_its_digests_agree():
    value = record()
    value["cases"].pop()
    projection = {row["caseId"]: {k: v for k, v in row.items() if k != "caseId"} for row in value["cases"]}
    for row in value["recordings"]:
        row["projectionDigest"] = digest(projection)
    inputs = release_inputs()
    for entry in inputs["special"]["e04"]["recordings"]:
        entry["projection"]["projection"] = projection
    with pytest.raises(ValueError, match="case inventory"):
        replay.expectations(value, inputs)


def test_expectations_refuse_a_record_that_does_not_bind_exactly_two_recordings():
    value = record()
    value["recordings"].append(copy.deepcopy(value["recordings"][0]))
    with pytest.raises(ValueError, match="two recordings"):
        replay.expectations(value, release_inputs())


def test_expectations_refuse_release_post_states_that_disagree_with_the_record():
    inputs = release_inputs()
    states = inputs["special"]["e04"]["recordings"][0]["projection"]["postStates"]
    states.pop(sorted(states)[0])
    with pytest.raises(ValueError, match="release replay inputs"):
        replay.expectations(record(), inputs)


def test_expectations_refuse_a_superseded_case_outside_the_campaign_or_without_commit_after_idle():
    value = record()
    value["supersededForStrict"]["cases"].append("idle-expiry/not-a-case")
    with pytest.raises(ValueError, match="superseded"):
        replay.expectations(value, release_inputs())
    value = record()
    value["supersededForStrict"]["cases"].remove("idle-expiry/commit-after-idle")
    with pytest.raises(ValueError, match="superseded"):
        replay.expectations(value, release_inputs())


def test_strict_fails_when_a_superseded_case_is_missing_from_the_replay():
    # the superseded cases are exempt from equality, not from being answered at all
    local = strict_as_published()
    local["projection"].pop("idle-expiry/rollback-after-idle")
    assert any("case inventory" in p for p in replay.judge_profile("strict", production(), local))
