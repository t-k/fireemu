"""The publisher refuses anything it cannot vouch for: an incomplete or mismatching replay, replays on different artifacts, a replay of another file, recordings that
disagree, and a published record that carries an identity of the run."""

import copy
import hashlib
import json

import pytest

import publish_recorded_comparison as publish

NONCE, OWNER, TOKEN = "a" * 32, "b" * 32, "tok-" + "c" * 20


def recording(n):
    return {"nonce": NONCE, "ownerId": OWNER, "n": n}


def write(tmp_path, n):
    path = tmp_path / f"recording-{n}.json"
    path.write_text(json.dumps(recording(n)))
    return path


def result(path, **overrides):
    value = {
        "metadata": {"commit": "1" * 40, "binary_sha256": "2" * 64, "profile": "strict", "compareToolSha256": "3" * 64, "clock": "real",
                     "productionFileSha256": hashlib.sha256(path.read_bytes()).hexdigest(), "program": "P", "planCorpusDigest": "4" * 64, "productionCorpusDigest": "4" * 64},
        "complete": True, "failure": None, "mismatches": 0,
        "cases": [{"caseId": "c", "production": {"code": 0, "details": ""}, "local": {"code": 0, "details": ""}, "match": True}],
        "reads": [{"site": "r", "production": {"code": 0}, "local": {"code": 0}, "match": True}],
    }
    value.update(overrides)
    return value


def projection(**overrides):
    value = {"program": "P", "packetName": "p", "corpusDigest": "4" * 64, "cases": [{"caseId": "c", "code": 0}], "reads": [], "tokens": {}, "cleanup": {"absent": True}}
    value.update(overrides)
    return value


def build(tmp_path, results=None, projections=None, paths=None):
    paths = paths or [write(tmp_path, 1), write(tmp_path, 2)]
    results = results or [result(path) for path in paths]
    return publish.build(program="P", key="p01", conditions=["FS-TRANSACTION/x"], recordings=paths, results=results,
                         projections=projections or [projection(), projection()], identities=[NONCE, OWNER, TOKEN])


def test_two_complete_matching_replays_on_one_artifact_are_published(tmp_path):
    observations, comparison = build(tmp_path)
    assert comparison["summary"] == {"recordings": 2, "rows": 4, "mismatches": 0}
    assert comparison["artifact"] == {"sourceCommit": "1" * 40, "binarySha256": "2" * 64}
    assert observations["corpora"][0]["agree"] is True
    assert observations["condition"] == ["FS-TRANSACTION/x"]


@pytest.mark.parametrize("override", [{"complete": False}, {"mismatches": 1}, {"mismatches": None}])
def test_an_incomplete_or_mismatching_replay_is_refused(tmp_path, override):
    paths = [write(tmp_path, 1), write(tmp_path, 2)]
    results = [result(paths[0]), result(paths[1], **override)]
    with pytest.raises(ValueError):
        build(tmp_path, results=results, paths=paths)


def test_replays_on_different_artifacts_or_tools_are_refused(tmp_path):
    paths = [write(tmp_path, 1), write(tmp_path, 2)]
    for key, other in (("commit", "9" * 40), ("binary_sha256", "9" * 64), ("compareToolSha256", "9" * 64), ("profile", "emulator")):
        results = [result(paths[0]), result(paths[1])]
        results[1]["metadata"][key] = other
        with pytest.raises(ValueError):
            build(tmp_path, results=results, paths=paths)


def test_a_replay_of_another_production_file_is_refused(tmp_path):
    paths = [write(tmp_path, 1), write(tmp_path, 2)]
    results = [result(paths[0]), result(paths[1])]
    results[1]["metadata"]["productionFileSha256"] = "9" * 64
    with pytest.raises(ValueError):
        build(tmp_path, results=results, paths=paths)


def test_recordings_whose_projections_differ_are_refused(tmp_path):
    with pytest.raises(ValueError):
        build(tmp_path, projections=[projection(), projection(cases=[{"caseId": "c", "code": 10}])])


def test_a_published_record_that_carries_an_identity_of_the_run_is_refused(tmp_path):
    leaky = projection(cases=[{"caseId": "c", "code": 0, "details": f"owner {OWNER}"}])
    with pytest.raises(ValueError):
        build(tmp_path, projections=[leaky, copy.deepcopy(leaky)])


def test_the_replay_clock_is_recorded_and_must_agree(tmp_path):
    paths = [write(tmp_path, 1), write(tmp_path, 2)]
    results = [result(paths[0], metadata={**result(paths[0])["metadata"], "clock": "virtual"}), result(paths[1])]
    with pytest.raises(ValueError):
        build(tmp_path, results=results, paths=paths)
