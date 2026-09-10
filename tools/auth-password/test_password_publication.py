"""Synthetic validator inputs never represent live Firebase execution evidence."""

import copy
import importlib.util
import json
from pathlib import Path

import pytest


def publisher():
    path = Path(__file__).parents[1] / "publish-auth-password.py"
    assert path.exists(), "Password publisher is required"
    spec = importlib.util.spec_from_file_location("password_publication", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def synthetic_receipt(p):
    value = json.loads(
        (p.ROOT / "spec/compatibility/evidence/auth-basic-v2/receipt.json").read_bytes()
    )
    from password_contract import CHECKS, TOKEN_CASES
    from password_recorder import PASSWORD_POLICY

    value.update(
        scope=p.SCOPE,
        corpus=copy.deepcopy(p.CORPUS),
        probeInputs=p.inputs(),
        sourceReviewSha256=p.digest(json.loads(p.REVIEW.read_bytes())),
        publicationContractSha256=p.publication_contract_sha(),
    )
    value["production"]["configuration"].update(
        adminPasswordPolicyAbsent=True, passwordPolicy=copy.deepcopy(PASSWORD_POLICY)
    )
    for target in ("local", "production"):
        value[target]["cases"] = []
        for name in p.CASES:
            row = {
                "id": name,
                "httpStatus": 400 if name == "old-password-rejected" else 200,
                "checks": dict.fromkeys(CHECKS[name], True),
                "passed": True,
            }
            if name in TOKEN_CASES:
                row["expirySeconds"] = "3600"
            value[target]["cases"].append(row)
    return value


def test_receipt_mutations_cannot_bypass_provenance_lifecycle_or_policy():
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
        (("production", "configuration", "adminPasswordPolicyAbsent"), False),
        (("production", "configuration", "passwordPolicy", "schemaVersion"), True),
        (("production", "cases", 2, "expirySeconds"), "1"),
    ]
    for path, invalid in mutations:
        changed = copy.deepcopy(value)
        parent = changed
        for key in path[:-1]:
            parent = parent[key]
        parent[path[-1]] = invalid
        with pytest.raises(ValueError):
            p.validate(changed)


def test_every_case_rejects_secret_fields_and_false_passes():
    p = publisher()
    value = synthetic_receipt(p)
    for row in value["local"]["cases"]:
        for secret in (
            "password",
            "idToken",
            "refreshToken",
            "passwordHash",
            "email",
            "localId",
        ):
            with pytest.raises(ValueError):
                p.validate_case({**row, secret: "SECRET"}, row["id"])
        with pytest.raises(ValueError):
            p.validate_case({**row, "passed": False}, row["id"])


def test_semantic_mismatch_is_visible_but_never_autoapproved():
    p = publisher()
    value = synthetic_receipt(p)
    row = value["production"]["cases"][4]
    row.update(httpStatus=200, passed=False)
    row["checks"] = {"rejected": False, "expectedError": False}
    page = p.render(value)
    assert "| old-password-rejected | Matched | Mismatch |" in page
    assert "candidate, not approved" in page
    assert "No human approval is inferred" in page


def test_incomplete_report_is_rejected():
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


@pytest.mark.parametrize(
    "path,invalid",
    [
        (("schemaVersion",), 2.0),
        (("corpus", "revision"), True),
        (("production", "cleanup", "uidAbsent"), 1),
        (("local", "cleanup", "emailAbsent"), 1),
        (("local", "instance", "wrongTokenStatus"), 403.0),
    ],
)
def test_numeric_substitutes_do_not_satisfy_typed_public_fields(path, invalid):
    p = publisher()
    value = synthetic_receipt(p)
    parent = value
    for key in path[:-1]:
        parent = parent[key]
    parent[path[-1]] = invalid
    with pytest.raises(ValueError):
        p.validate(value)
