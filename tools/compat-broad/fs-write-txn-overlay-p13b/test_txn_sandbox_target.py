"""Fixed sandbox routing and owner-bound baseline identity, without a network."""

import copy
import hashlib
import json
import sys
import time
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import txn_expiry_descriptor as campaign
import txn_expiry_plan as plan
import txn_expiry_preflight as preflight
import txn_expiry_remote_transport as remote
from broad_contract import digest
from test_txn_expiry_transport import request

PROJECT = "fireemu-oracle-sbx"
NUMBER = "1" * 12  # Synthetic fixture; never an oracle project number.
NONCE = "b" * 32


def test_default_plan_reference_locks_and_data_route_share_the_sandbox():
    compiled = plan.compile_plan(NONCE, "a" * 32)
    reference = campaign.plan_compiler(NONCE)
    assert compiled["projectId"] == reference["project"] == PROJECT
    assert "projectNumber" not in compiled and "projectNumber" not in reference
    assert plan.compile_plan(NONCE, "a" * 32, project="fireemu-test")["projectId"] == "fireemu-test"
    assert all(PROJECT in lock["key"] for lock in campaign.lock_scopes(reference))
    name = f"projects/{PROJECT}/databases/(default)/documents/oracle/{NONCE}/txn-expiry-04/control"
    assert remote.build(request("GetDocument", projectId=PROJECT, name=name)) == (
        "GET", "/v1/" + name, None
    )
    assert "projectNumber" in plan.OWNER_FIELDS_REQUIRED


@pytest.mark.parametrize("project", ["fireemu-35fe6", "foreign-project"])
def test_old_or_foreign_data_target_is_refused(project):
    name = f"projects/{project}/databases/(default)/documents/oracle/{NONCE}/txn-expiry-04/control"
    with pytest.raises(ValueError, match="fixed production project"):
        remote.build(request("GetDocument", projectId=project, name=name))


def test_actual_management_urls_and_quota_headers_match_the_fixed_data_target(monkeypatch):
    import batch_adapter
    import o8_admission

    sent = []
    monkeypatch.setattr(o8_admission, "authorize_transport", lambda *a, **k: None)

    def wire(url, method, body, headers, **kwargs):
        sent.append((url, method, body, headers))
        return {"http": {"complete": True, "bodyKind": "json", "status": 200}, "body": {}}

    monkeypatch.setattr(batch_adapter, "wire", wire)
    expected = {
        "project": f"https://cloudresourcemanager.googleapis.com/v1/projects/{PROJECT}",
        "database": f"https://firestore.googleapis.com/v1/projects/{PROJECT}/databases/(default)",
        "auth": f"https://identitytoolkit.googleapis.com/admin/v2/projects/{PROJECT}/config",
    }
    for slot, url in expected.items():
        assert preflight.metadata_url(slot) == url
        preflight.management_transport(
            preflight.management_call("observation", slot, "fixture-token", deadline=time.monotonic() + 10),
            capability=object(), binding={}, binding_digest="a" * 64,
        )
        assert sent[-1] == (url, "GET", None, {"Authorization": "Bearer fixture-token", "x-goog-user-project": PROJECT})
    assert campaign.PROJECT == PROJECT


def permission(number=NUMBER):
    return campaign.permission_bindings(
        campaign.plan_compiler(NONCE), "a" * 40, "b" * 64, campaign.source_map(),
        project_number=number,
    )


def test_private_project_number_is_an_explicit_permission_binding():
    bound = permission()
    assert bound["projectNumber"] == NUMBER
    assert bound["project"] == bound["quotaProject"] == PROJECT
    with pytest.raises(ValueError, match="project number"):
        campaign.permission_bindings(campaign.plan_compiler(NONCE), "a" * 40, "b" * 64, campaign.source_map())


@pytest.mark.parametrize("number", [None, True, 123456, "", "0" * 12, "01" * 6, "12345", "1" * 21])
def test_malformed_project_number_is_not_permission(number):
    with pytest.raises(ValueError, match="project number"):
        permission(number)


def baseline_fixture(tmp_path, *, project=PROJECT, number=NUMBER, database_project=PROJECT):
    """Synthetic hash-bound observations, never evidence of a real execution."""
    routes = {
        "projectIdentity": f"cloudresourcemanager.googleapis.com/v1/projects/{project}",
        "database": f"firestore.googleapis.com/v1/projects/{project}/databases/(default)",
        "authConfig": f"identitytoolkit.googleapis.com/admin/v2/projects/{project}/config",
    }
    bodies = {
        "projectIdentity": {"projectId": project, "projectNumber": number},
        "database": {"name": f"projects/{database_project}/databases/(default)", "uid": "fixture", "type": "FIRESTORE_NATIVE", "databaseEdition": "STANDARD", "locationId": "us-central1"},
        "authConfig": {"name": f"projects/{number}/config", "mfa": {"state": "DISABLED"}},
    }
    actions = {"projectIdentity": "project", "database": "database", "authConfig": "auth"}
    folder = tmp_path / "evidence"
    folder.mkdir()
    journal = folder / "journal.jsonl"
    journal.write_text("\n".join(json.dumps({"route": routes[key], "phase": "observation", "response": {"httpStatus": 200, "body": body}}) for key, body in bodies.items()) + "\n")
    receipt = folder / "receipt.json"
    receipt.write_text(json.dumps({"executionKind": "fixed-production-wire", "metadata": [{"id": "observation:" + actions[key], "status": 200, "responseDigest": digest(body)} for key, body in bodies.items()]}))
    marker = {"path": receipt.name, "sha256": hashlib.sha256(receipt.read_bytes()).hexdigest(), "mode": "live"}
    record = folder / "record.json"
    record.write_text(json.dumps({"kind": "commit-production-baseline-v1", "observations": [{"route": route, "path": journal.name, "sha256": hashlib.sha256(journal.read_bytes()).hexdigest(), "index": i, "production": marker} for i, route in enumerate(routes.values())]}))
    return record, folder


def derive(record, root, number=NUMBER):
    return campaign.commit_baseline.baseline_from_record(
        record, evidence_root=root, production_roots=(("evidence",),), project_number=number,
    )


def test_sandbox_baseline_is_bound_to_the_owner_number_and_permission(tmp_path):
    record, root = baseline_fixture(tmp_path)
    baseline = derive(record, root)
    assert baseline["projectIdentity"] == {"projectId": PROJECT, "projectNumber": NUMBER}
    bound = {**permission(), **campaign.commit_baseline.permission_baseline(baseline)}
    campaign.commit_baseline.validate_permission_baseline(bound, baseline)
    foreign = copy.deepcopy(baseline)
    foreign["projectIdentity"]["projectNumber"] = "2" * 12
    with pytest.raises(ValueError, match="identity"):
        campaign.commit_baseline.validate_permission_baseline(bound, foreign)
    with pytest.raises(ValueError, match="identity"):
        derive(record, root, "2" * 12)


@pytest.mark.parametrize("change", [{"project": "fireemu-35fe6"}, {"database_project": "foreign-project"}])
def test_sandbox_baseline_rejects_foreign_routes_and_database_bodies(tmp_path, change):
    record, root = baseline_fixture(tmp_path, **change)
    with pytest.raises(ValueError):
        derive(record, root)


def test_legacy_baseline_wrapper_does_not_implicitly_accept_sandbox_records(tmp_path):
    core = preflight._load("_target_test_legacy_baseline", HERE.parent / "fs-commit-transform-limits/commit_baseline.py")
    record, root = baseline_fixture(tmp_path)
    with pytest.raises(ValueError, match="route"):
        core.baseline_from_record(record, evidence_root=root, production_roots=(("evidence",),))


def test_sandbox_provenance_rejects_legacy_routes():
    legacy = {key: {"route": route.replace(PROJECT, "fireemu-35fe6"), "sha256": "a" * 64} for key, route in campaign.commit_baseline.ROUTES.items()}
    with pytest.raises(ValueError, match="provenance"):
        campaign.commit_baseline.validate_provenance(legacy)


@pytest.mark.parametrize("entrypoint", ["validate_o7_admission", "issue_production_capability"])
def test_missing_number_refuses_before_shared_authority_code(monkeypatch, entrypoint):
    import txn_expiry_admission as admission

    def forbidden(*args, **kwargs):
        pytest.fail("malformed permission reached shared authority code")

    monkeypatch.setattr(admission.o8_admission, entrypoint, forbidden)
    with pytest.raises(ValueError, match="project number"):
        getattr(admission, entrypoint)(permission={})


@pytest.mark.parametrize("damage", ["recovery-phase", "unrelated-run", "injected-run", "changed-journal"])
def test_sandbox_baseline_still_requires_the_bound_observation_run(tmp_path, damage):
    record, root = baseline_fixture(tmp_path)
    value = json.loads(record.read_bytes())
    journal = root / "journal.jsonl"
    receipt = root / "receipt.json"
    if damage in ("recovery-phase", "changed-journal"):
        rows = [json.loads(line) for line in journal.read_text().splitlines()]
        rows[0]["phase"] = "recovery"
        journal.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
        if damage == "recovery-phase":
            for row in value["observations"]:
                row["sha256"] = hashlib.sha256(journal.read_bytes()).hexdigest()
    else:
        saved = json.loads(receipt.read_bytes())
        if damage == "unrelated-run":
            saved["metadata"][0]["responseDigest"] = "0" * 64
        else:
            saved["executionKind"] = "injected-transport"
        receipt.write_text(json.dumps(saved))
        for row in value["observations"]:
            row["production"]["sha256"] = hashlib.sha256(receipt.read_bytes()).hexdigest()
    record.write_text(json.dumps(value))
    with pytest.raises(ValueError):
        derive(record, root)


def test_target_wrapper_and_shared_policy_are_source_bound():
    sources = campaign.source_map()
    for name in (
        "tools/compat-broad/fs-write-txn/txn_expiry_baseline.py",
        "tools/compat-broad/fs-write-txn/txn_expiry_plan.py",
        "tools/compat-broad/fs-commit-transform-limits/commit_baseline.py",
    ):
        assert sources[name] == hashlib.sha256((campaign.ROOT / name).read_bytes()).hexdigest()
