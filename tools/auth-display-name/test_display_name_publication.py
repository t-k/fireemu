"""The publication gate rechecks safe projections rather than trusting passed."""

import copy
import importlib.util
import json
from pathlib import Path

import pytest


def publisher():
    path = Path(__file__).parents[1] / "publish-auth-display-name.py"
    assert path.exists(), "Profile publication gate is required"
    spec = importlib.util.spec_from_file_location("display_name_publication", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_publisher_checks_name_state_and_rejects_secrets():
    p = publisher()
    row = {
        "id": "set-name",
        "httpStatus": 200,
        "nameState": "first",
        "checks": {
            "httpOk": True,
            "nameMatches": True,
            "selectedIdentityUnchanged": True,
        },
        "passed": True,
    }
    p.validate_case(row, "set-name")
    for change in [{"nameState": "second"}, {"idToken": "SECRET"}, {"passed": False}]:
        with pytest.raises(ValueError):
            p.validate_case({**row, **change}, "set-name")


def test_incomplete_private_report_is_never_projected():
    p = publisher()
    with pytest.raises(ValueError):
        p.project(
            {
                "schemaVersion": 2,
                "acceptance": "candidate",
                "target": "local",
                "status": "incomplete",
            },
            "local",
        )


def synthetic_receipt(p):
    # Reuse safe provenance as a fixture, never present this synthesized value as a live observation.
    value = json.loads(
        (p.ROOT / "spec/compatibility/evidence/auth-basic-v2/receipt.json").read_bytes()
    )
    from display_name_contract import CHECKS, NAME_EXPECTED

    value.update(
        scope=p.SCOPE,
        corpus=p.CORPUS,
        probeInputs=p.inputs(),
        sourceReviewSha256=p.digest(json.loads(p.REVIEW.read_bytes())),
        publicationContractSha256=p.publication_contract_sha(),
    )
    for target in ("local", "production"):
        value[target]["cases"] = []
        for name in p.CASES:
            row = {
                "id": name,
                "httpStatus": 400 if name == "invalid-token-update" else 200,
                "checks": {key: True for key in CHECKS[name]},
                "passed": True,
            }
            if name in NAME_EXPECTED:
                row["nameState"] = NAME_EXPECTED[name]
            if name == "signup":
                row["expirySeconds"] = "3600"
            value[target]["cases"].append(row)
    return value


def test_receipt_mutations_cannot_bypass_provenance_or_lifecycle_gates():
    p = publisher()
    value = synthetic_receipt(p)
    p.validate(value)
    mutations = [
        (("acceptance",), "approved"),
        (("scope",), "All Auth"),
        (("corpus", "revision"), 2),
        (("probeInputs",), {}),
        (("sourceReviewSha256",), "0" * 64),
        (("publicationContractSha256",), "0" * 64),
        (("local", "ownedProcess", "exitCode"), 2),
        (("local", "ownedProcess", "listenersClosed"), False),
        (("local", "instance", "parentPid"), 1),
        (("local", "artifact", "sha256"), "0" * 64),
        (("local", "configuration", "fileSha256"), "0" * 64),
        (("local", "cleanup", "uidAbsent"), False),
        (("production", "cleanup", "emailAbsent"), False),
        (("production", "configurationUnchanged"), False),
        (("production", "cases", 2, "nameState"), "SECRET"),
    ]
    for path, invalid in mutations:
        changed = copy.deepcopy(value)
        parent = changed
        for key in path[:-1]:
            parent = parent[key]
        parent[path[-1]] = invalid
        with pytest.raises(ValueError):
            p.validate(changed)


def test_well_formed_mismatch_stays_visible_and_unapproved():
    p = publisher()
    value = synthetic_receipt(p)
    row = value["production"]["cases"][2]
    row.update(nameState="other", passed=False)
    row["checks"]["nameMatches"] = False
    page = p.render(value)
    assert "| set-name | Matched | Mismatch |" in page
    assert "candidate, not approved" in page


def test_committed_name_receipt_and_generated_page_remain_candidate():
    p = publisher()
    value = json.loads(p.BUNDLE.read_bytes())
    assert p.PAGE.read_text() == p.render(value)
    assert value["acceptance"] == "candidate"
    assert all(
        row["passed"]
        for target in ("local", "production")
        for row in value[target]["cases"]
    )
    assert "No human approval is inferred" in p.render(value)
