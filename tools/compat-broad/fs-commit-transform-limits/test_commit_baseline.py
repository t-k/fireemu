"""Provenance for the production baseline digests a Commit permission binds.

Every observation used here is a local fixture. No production request is made
and no credential is read; the fixtures carry no secret field.
"""

import copy
import hashlib
import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "production-admission"))
sys.path.insert(0, str(HERE))

import commit_baseline
from batch_contract import NUMBER, PROJECT
from broad_contract import digest

PROJECT_BODY = {"projectId": PROJECT, "projectNumber": NUMBER}
DATABASE_BODY = {
    "name": f"projects/{PROJECT}/databases/(default)",
    "uid": "fixture-uid",
    "type": "FIRESTORE_NATIVE",
    "databaseEdition": "STANDARD",
    "locationId": "us-central1",
    "etag": "volatile",
    "earliestVersionTime": "2026-09-18T00:00:00Z",
}
AUTH_BODY = {"name": f"projects/{NUMBER}/config", "mfa": {"state": "DISABLED"}}


def observation_file(path, bodies):
    """A recorded production response journal in the shape the lanes write."""
    lines = []
    for route, body in bodies:
        lines.append(
            json.dumps(
                {
                    "service": "metadata",
                    "route": route,
                    "phase": "observation",
                    "response": {
                        "httpStatus": 200,
                        "mediaType": "application/json",
                        "body": body,
                    },
                    "digest": digest(body),
                }
            )
        )
    path.write_text("\n".join(lines) + "\n")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def record_for(tmp_path, *, bodies=None):
    bodies = bodies or [
        (commit_baseline.ROUTES["projectIdentity"], PROJECT_BODY),
        (commit_baseline.ROUTES["database"], DATABASE_BODY),
        (commit_baseline.ROUTES["authConfig"], AUTH_BODY),
    ]
    evidence = tmp_path / "evidence"
    evidence.mkdir(exist_ok=True)
    sha = observation_file(evidence / "responses.jsonl", bodies)
    record = {
        "kind": commit_baseline.RECORD_KIND,
        "observations": [
            {
                "route": route,
                "path": "responses.jsonl",
                "sha256": sha,
                "index": index,
            }
            for index, (route, _body) in enumerate(bodies)
        ],
    }
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps(record))
    return path, evidence


def test_every_baseline_digest_is_derived_from_a_named_observation(tmp_path):
    path, evidence = record_for(tmp_path)
    baseline = commit_baseline.baseline_from_record(path, evidence_root=evidence)
    assert set(baseline) == set(commit_baseline.BASELINE_FIELDS)
    assert baseline["authConfigDigest"] == digest(AUTH_BODY)
    assert baseline["pricingLocation"] == "us-central1"
    assert baseline["projectIdentity"] == {
        "projectId": PROJECT,
        "projectNumber": NUMBER,
    }
    # The volatile response fields never enter the bound projection.
    assert "etag" not in baseline["databaseProjection"]
    assert "earliestVersionTime" not in baseline["databaseProjection"]
    assert baseline["databaseProjectionDigest"] == digest(
        baseline["databaseProjection"]
    )
    assert (
        baseline["provenance"]["authConfig"]["sha256"]
        == json.loads(path.read_text())["observations"][2]["sha256"]
    )


def test_an_observation_file_that_changed_since_it_was_named_is_refused(tmp_path):
    path, evidence = record_for(tmp_path)
    journal = evidence / "responses.jsonl"
    journal.write_text(journal.read_text().replace("DISABLED", "ENABLED"))
    with pytest.raises(ValueError, match="observation"):
        commit_baseline.baseline_from_record(path, evidence_root=evidence)


@pytest.mark.parametrize(
    "damage",
    [
        {"kind": "other-baseline-v1"},
        {"observations": []},
        {"observations": "not-a-list"},
    ],
    ids=["kind", "empty", "malformed"],
)
def test_a_malformed_baseline_record_is_refused(tmp_path, damage):
    path, evidence = record_for(tmp_path)
    record = {**json.loads(path.read_text()), **damage}
    path.write_text(json.dumps(record))
    with pytest.raises(ValueError):
        commit_baseline.baseline_from_record(path, evidence_root=evidence)


def test_every_required_route_must_be_named_exactly_once(tmp_path):
    path, evidence = record_for(tmp_path)
    record = json.loads(path.read_text())
    missing = {**record, "observations": record["observations"][:2]}
    path.write_text(json.dumps(missing))
    with pytest.raises(ValueError, match="route"):
        commit_baseline.baseline_from_record(path, evidence_root=evidence)
    duplicate = {
        **record,
        "observations": [*record["observations"], record["observations"][0]],
    }
    path.write_text(json.dumps(duplicate))
    with pytest.raises(ValueError, match="route"):
        commit_baseline.baseline_from_record(path, evidence_root=evidence)


def test_an_observation_of_another_project_is_refused(tmp_path):
    path, evidence = record_for(
        tmp_path,
        bodies=[
            (
                commit_baseline.ROUTES["projectIdentity"],
                {"projectId": "other-project", "projectNumber": "1"},
            ),
            (commit_baseline.ROUTES["database"], DATABASE_BODY),
            (commit_baseline.ROUTES["authConfig"], AUTH_BODY),
        ],
    )
    with pytest.raises(ValueError, match="project identity"):
        commit_baseline.baseline_from_record(path, evidence_root=evidence)


def test_an_index_naming_another_route_is_refused(tmp_path):
    path, evidence = record_for(tmp_path)
    record = json.loads(path.read_text())
    record["observations"][2]["index"] = 0
    path.write_text(json.dumps(record))
    with pytest.raises(ValueError, match="route"):
        commit_baseline.baseline_from_record(path, evidence_root=evidence)


def test_a_non_success_observation_is_refused(tmp_path):
    path, evidence = record_for(tmp_path)
    journal = evidence / "responses.jsonl"
    lines = [json.loads(line) for line in journal.read_text().splitlines()]
    lines[2]["response"]["httpStatus"] = 403
    journal.write_text("\n".join(json.dumps(line) for line in lines) + "\n")
    record = json.loads(path.read_text())
    sha = hashlib.sha256(journal.read_bytes()).hexdigest()
    for entry in record["observations"]:
        entry["sha256"] = sha
    path.write_text(json.dumps(record))
    with pytest.raises(ValueError, match="observation"):
        commit_baseline.baseline_from_record(path, evidence_root=evidence)


def test_a_path_escaping_the_evidence_root_is_refused(tmp_path):
    path, evidence = record_for(tmp_path)
    record = json.loads(path.read_text())
    for entry in record["observations"]:
        entry["path"] = "../evidence/responses.jsonl"
    path.write_text(json.dumps(record))
    with pytest.raises(ValueError, match="bounded"):
        commit_baseline.baseline_from_record(path, evidence_root=evidence)


def test_validate_refuses_a_permission_whose_baseline_no_observation_produces(tmp_path):
    path, evidence = record_for(tmp_path)
    baseline = commit_baseline.baseline_from_record(path, evidence_root=evidence)
    permission = commit_baseline.permission_baseline(baseline)
    commit_baseline.validate_permission_baseline(permission, baseline)
    for field in ("authConfigDigest", "databaseProjectionDigest", "pricingLocation"):
        damaged = copy.deepcopy(permission)
        damaged[field] = (
            "3eddf9795664048f56b927705e0e36d03e2866289a302f21ac21520c96961c1c"
            if field.endswith("Digest")
            else "europe-west1"
        )
        with pytest.raises(ValueError, match="observation"):
            commit_baseline.validate_permission_baseline(damaged, baseline)
