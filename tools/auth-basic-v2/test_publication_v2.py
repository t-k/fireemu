import copy
import importlib.util
import json
import sys
from pathlib import Path

import pytest


def publisher():
    path = Path(__file__).parents[1] / "publish-auth-v2.py"
    assert path.exists(), "Revision 2 publication validator is required"
    sys.path.insert(0, str(Path(__file__).parent))
    spec = importlib.util.spec_from_file_location("auth_v2_publication", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_expiry_predicates_are_recomputed_from_the_redacted_value():
    p = publisher()
    checks = {key: True for key in p.CHECKS["signup"]}
    row = {
        "id": "signup",
        "httpStatus": 200,
        "checks": checks,
        "expirySeconds": "3600",
        "passed": True,
    }
    p.validate_case(row, "signup")
    for seconds in ["1", "999999", "SECRET", True, None]:
        with pytest.raises(ValueError):
            p.validate_case({**row, "expirySeconds": seconds}, "signup")
    changed = {**checks, "expiryMatchesOneHour": False}
    p.validate_case(
        {**row, "checks": changed, "expirySeconds": "1", "passed": False}, "signup"
    )


def test_publication_refuses_unexpected_secret_fields():
    p = publisher()
    row = {
        "id": "signup-token-lookup",
        "httpStatus": 200,
        "checks": {"ownedIdentity": True},
        "passed": True,
    }
    p.validate_case(row, "signup-token-lookup")
    for field in ["idToken", "refresh_token", "email", "rawResponse"]:
        with pytest.raises(ValueError):
            p.validate_case({**row, field: "SECRET"}, "signup-token-lookup")


def test_public_receipt_rejects_tampered_provenance_and_cleanup():
    p = publisher()
    assert p.BUNDLE.exists(), (
        "Capture revision 2 before validating its published receipt"
    )
    value = json.loads(p.BUNDLE.read_bytes())
    p.validate(value)
    mutations = [
        (("local", "ownedProcess", "exitCode"), 2),
        (("local", "ownedProcess", "listenersClosed"), False),
        (("local", "instance", "parentPid"), 1),
        (("local", "build", "artifactSha256"), "0" * 64),
        (("local", "configuration", "fileSha256"), "0" * 64),
        (("local", "cleanup", "uidAbsent"), False),
        (("production", "configuration", "improvedEmailPrivacy"), False),
        (("acceptance",), "approved"),
        (("scope",), "All Auth verified"),
        (("sourceReviewSha256",), "0" * 64),
        (("publicationContractSha256",), "0" * 64),
    ]
    for path, invalid in mutations:
        changed = copy.deepcopy(value)
        parent = changed
        for name in path[:-1]:
            parent = parent[name]
        parent[path[-1]] = invalid
        with pytest.raises(ValueError):
            p.validate(changed)
