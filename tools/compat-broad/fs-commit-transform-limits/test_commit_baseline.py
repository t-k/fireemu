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


LIVE_RECEIPT = {
    "kind": "commit-acquisition-receipt-v2",
    "executionKind": "fixed-production-wire",
    "productionExecuted": False,
}


def record_for(tmp_path, *, bodies=None, receipt=None, journal="responses.jsonl"):
    bodies = bodies or [
        (commit_baseline.ROUTES["projectIdentity"], PROJECT_BODY),
        (commit_baseline.ROUTES["database"], DATABASE_BODY),
        (commit_baseline.ROUTES["authConfig"], AUTH_BODY),
    ]
    evidence = tmp_path / "evidence"
    journal_path = evidence / journal
    journal_path.parent.mkdir(parents=True, exist_ok=True)
    sha = observation_file(journal_path, bodies)
    receipt_path = evidence / "receipt.json"
    receipt_path.write_text(json.dumps(LIVE_RECEIPT if receipt is None else receipt))
    receipt_sha = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
    record = {
        "kind": commit_baseline.RECORD_KIND,
        "observations": [
            {
                "route": route,
                "path": journal,
                "sha256": sha,
                "index": index,
                "production": {
                    "path": "receipt.json",
                    "sha256": receipt_sha,
                    "mode": "live",
                },
            }
            for index, (route, _body) in enumerate(bodies)
        ],
    }
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps(record))
    return path, evidence


def derive(path, evidence):
    """Derive with the temporary directory declared as the production log root."""
    return commit_baseline.baseline_from_record(
        path, evidence_root=evidence, production_roots=(Path(evidence).resolve().parts,)
    )


def test_every_baseline_digest_is_derived_from_a_named_observation(tmp_path):
    path, evidence = record_for(tmp_path)
    baseline = derive(path, evidence)
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
        derive(path, evidence)


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
        derive(path, evidence)


def test_every_required_route_must_be_named_exactly_once(tmp_path):
    path, evidence = record_for(tmp_path)
    record = json.loads(path.read_text())
    missing = {**record, "observations": record["observations"][:2]}
    path.write_text(json.dumps(missing))
    with pytest.raises(ValueError, match="route"):
        derive(path, evidence)
    duplicate = {
        **record,
        "observations": [*record["observations"], record["observations"][0]],
    }
    path.write_text(json.dumps(duplicate))
    with pytest.raises(ValueError, match="route"):
        derive(path, evidence)


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
        derive(path, evidence)


def test_an_index_naming_another_route_is_refused(tmp_path):
    path, evidence = record_for(tmp_path)
    record = json.loads(path.read_text())
    record["observations"][2]["index"] = 0
    path.write_text(json.dumps(record))
    with pytest.raises(ValueError, match="route"):
        derive(path, evidence)


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
        derive(path, evidence)


def test_a_path_escaping_the_evidence_root_is_refused(tmp_path):
    path, evidence = record_for(tmp_path)
    record = json.loads(path.read_text())
    for entry in record["observations"]:
        entry["path"] = "../evidence/responses.jsonl"
    path.write_text(json.dumps(record))
    with pytest.raises(ValueError, match="bounded"):
        derive(path, evidence)


@pytest.mark.parametrize(
    "receipt",
    [
        {
            "kind": "commit-acquisition-receipt-v2",
            "executionKind": "injected-transport",
        },
        {"kind": "second45-local-result-v1", "productionExecuted": False},
        {"kind": "commit-acquisition-receipt-v2"},
        {},
    ],
    ids=["injected", "local-result", "no-marker", "empty"],
)
def test_a_journal_without_a_live_production_execution_is_refused(tmp_path, receipt):
    """A replay fixture has the same line shape as a production journal."""
    path, evidence = record_for(tmp_path, receipt=receipt)
    with pytest.raises(ValueError, match="live production"):
        derive(path, evidence)


def test_a_journal_whose_production_evidence_changed_is_refused(tmp_path):
    path, evidence = record_for(tmp_path)
    (evidence / "receipt.json").write_text(
        json.dumps({**LIVE_RECEIPT, "productionExecuted": True})
    )
    with pytest.raises(ValueError, match="production evidence"):
        derive(path, evidence)


@pytest.mark.parametrize(
    "damage",
    [
        {"mode": "replay"},
        {"mode": None},
        {"path": "missing.json"},
    ],
    ids=["replay-mode", "no-mode", "missing-evidence"],
)
def test_a_production_marker_that_does_not_declare_a_live_run_is_refused(
    tmp_path, damage
):
    path, evidence = record_for(tmp_path)
    record = json.loads(path.read_text())
    for entry in record["observations"]:
        entry["production"] = {**entry["production"], **damage}
    path.write_text(json.dumps(record))
    with pytest.raises(ValueError):
        derive(path, evidence)


def test_an_observation_under_a_fixture_directory_is_refused(tmp_path):
    """A recorded replay lives beside the real logs and must never be a baseline."""
    path, evidence = record_for(
        tmp_path, journal="cli-fixtures/fixture/responses.jsonl"
    )
    with pytest.raises(ValueError, match="production log"):
        derive(path, evidence)


def test_an_observation_outside_the_production_log_roots_is_refused(tmp_path):
    path, evidence = record_for(tmp_path)
    with pytest.raises(ValueError, match="production log"):
        commit_baseline.baseline_from_record(
            path,
            evidence_root=evidence,
            production_roots=(("docs.local", "logs"),),
        )


def _evidence_root():
    """Where `docs.local` lives; a linked worktree does not carry its own copy."""
    for candidate in (ROOT, *ROOT.parents):
        if (candidate / "docs.local").is_dir():
            return candidate
    return ROOT


REAL_RUN = _evidence_root() / "docs.local/logs/2026-09-18/commit500-501-o8-run-v10"
REPLAY_FIXTURE = _evidence_root() / "docs.local/logs/2026-09-13/second45-production"
PRODUCTION_AUTH_CONFIG_DIGEST = (
    "7878eb2600c66f48c82ef55fb8c2443ab15689ea7542a77fbda206da06f817c2"
)


def real_record(tmp_path, evidence, journal, receipt, routes):
    sha = hashlib.sha256((evidence / journal).read_bytes()).hexdigest()
    receipt_sha = hashlib.sha256((evidence / receipt).read_bytes()).hexdigest()
    path = tmp_path / "baseline.json"
    path.write_text(
        json.dumps(
            {
                "kind": commit_baseline.RECORD_KIND,
                "observations": [
                    {
                        "route": commit_baseline.ROUTES[key],
                        "path": journal,
                        "sha256": sha,
                        "index": index,
                        "production": {
                            "path": receipt,
                            "sha256": receipt_sha,
                            "mode": "live",
                        },
                    }
                    for key, index in routes.items()
                ],
            }
        )
    )
    return path


@pytest.mark.skipif(
    not (REAL_RUN / "receipt.json").is_file(), reason="the v10 run is host local"
)
def test_the_real_production_journal_yields_the_observed_auth_config_digest(tmp_path):
    """The value 32 permissions use, recomputed from the run that observed it."""
    path = real_record(
        tmp_path,
        REAL_RUN,
        "coordinator/responses.jsonl",
        "receipt.json",
        {"projectIdentity": 0, "database": 1, "authConfig": 2},
    )
    baseline = commit_baseline.baseline_from_record(path, evidence_root=REAL_RUN)
    assert baseline["authConfigDigest"] == PRODUCTION_AUTH_CONFIG_DIGEST
    assert baseline["pricingLocation"] == "us-central1"
    assert baseline["databaseProjectionDigest"] == (
        "31957f98b7ec76e9c2e7a04803772f7270763a8ed62037fbdefa74c2c8f71d33"
    )


@pytest.mark.skipif(
    not (REPLAY_FIXTURE / "cli-fixtures/fixture/responses.jsonl").is_file(),
    reason="the second45 replay fixture is host local",
)
def test_the_replay_fixture_journal_is_refused(tmp_path):
    """Same routes, same project, same line shape, a different digest."""
    journal = "cli-fixtures/fixture/responses.jsonl"
    body = json.loads((REPLAY_FIXTURE / journal).read_text().splitlines()[2])[
        "response"
    ]["body"]
    assert digest(body) != PRODUCTION_AUTH_CONFIG_DIGEST
    path = real_record(
        tmp_path,
        REPLAY_FIXTURE,
        journal,
        "cli-fixtures/fixture/result.json",
        {"projectIdentity": 0, "database": 1, "authConfig": 2},
    )
    with pytest.raises(ValueError, match="production log"):
        commit_baseline.baseline_from_record(path, evidence_root=REPLAY_FIXTURE)


def test_validate_refuses_a_permission_whose_baseline_no_observation_produces(tmp_path):
    path, evidence = record_for(tmp_path)
    baseline = derive(path, evidence)
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
