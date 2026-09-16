import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest


def contract():
    path = Path(__file__).with_name("auth_v2_contract.py")
    assert path.exists(), "Revision 2 contract is missing"
    spec = importlib.util.spec_from_file_location("auth_revision2_contract", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_expiry_shape_and_one_hour_are_distinct_without_secret_retention():
    c = contract()
    for seconds in ["1", "3600", "999999"]:
        value = {
            "expiresIn": seconds,
            "idToken": "SECRET",
            "refreshToken": "SECRET",
            "localId": "uid",
            "email": "email",
        }
        result = c.tokens(value, "uid", "email")
        assert result["expiryIsPositiveInteger"] is True
        assert result["expiryMatchesOneHour"] is (seconds == "3600")
        assert c.expiry_seconds(value) == seconds
        assert "expiryValid" not in result
        assert "SECRET" not in str(result)
    for seconds in [True, None, "SECRET", "0", "01", "1000000"]:
        assert c.expiry_seconds({"expiresIn": seconds}) is None


def test_signup_credentials_have_separate_usage_cases():
    c = contract()
    assert c.CASES[:4] == (
        "signup",
        "signup-token-lookup",
        "signup-token-refresh",
        "signup-refreshed-lookup",
    )
    assert len(c.CASES) == 12


@pytest.mark.skipif(
    os.getenv("AUTH_BASIC_V2_LIVE_LOCAL") != "1", reason="owned process opt-in"
)
def test_owned_revision2_completes_all_cases(tmp_path):
    path = Path(__file__).with_name("auth_v2_owned.py")
    assert path.exists(), "Revision 2 owned launcher is missing"
    result = subprocess.run(
        [sys.executable, str(path), "--output", str(tmp_path / "run")],
        capture_output=True,
        timeout=420,
        check=False,
    )
    assert result.returncode == 0, result.stdout.decode()
    import json

    report = json.loads((tmp_path / "run/local.json").read_bytes())
    assert contract().complete(report)
    assert report["ownedProcess"]["exitCode"] == 0
    assert report["ownedProcess"]["listenersClosed"] is True
    assert all(row["passed"] for row in report["cases"])
    assert [
        row["expirySeconds"] for row in report["cases"] if "expirySeconds" in row
    ] == ["3600"] * 4
