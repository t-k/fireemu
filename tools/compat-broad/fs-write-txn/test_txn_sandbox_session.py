"""The production session composes existing collector and new bounded gates."""

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import txn_sandbox_session as session
from test_txn_sandbox_contract import receipt
from test_txn_sandbox_management import BASELINE


NONCE = "0123456789abcdef0123456789abcdef"
OWNER = "11111111222233334444555566667777"


def test_session_counts_oauth_metadata_data_and_durable_responsibility(tmp_path):
    events = []

    def credential():
        events.append("oauth")
        return "test-access-token"

    class Metadata:
        def __init__(self, token, baseline, budget):
            assert token == "test-access-token" and baseline == BASELINE
            self.budget = budget

        def preflight(self):
            events.append("preflight")
            for _ in range(5):
                self.budget.charge("management")
            return {"database": "digest-a"}

        def postflight(self):
            events.append("postflight")
            for _ in range(2):
                self.budget.charge("management")
            return {"database": "digest-a"}

    def data_wire(token, budget):
        def send(_request):
            budget.charge("data", phase="observation")
            return {"complete": True, "code": 0}

        return send

    class Collector:
        def __init__(self, options, plan, wire, *, responsibility):
            assert options["target"] == "production"
            assert options["timing"] == "wall-clock"
            self.wire = wire
            self.responsibility = responsibility

        def run(self):
            events.append("collector")
            self.responsibility({"event": "dispatch-intent", "inFlight": {"site": "test"}})
            self.wire({})
            answer = receipt(NONCE)
            answer["requestCount"] = 1
            return answer

    result = session.run_once(
        NONCE,
        OWNER,
        tmp_path,
        BASELINE,
        credential_fn=credential,
        metadata_factory=Metadata,
        wire_factory=data_wire,
        collector_factory=Collector,
    )
    assert events == ["oauth", "preflight", "collector", "postflight"]
    assert result["sandboxRequests"] == 9
    assert json.loads((tmp_path / "responsibility.json").read_text())["event"] == "dispatch-intent"
    assert result["preflight"] == {"database": "digest-a"}
    assert result["postflight"] == {"database": "digest-a"}


def test_incomplete_collection_skips_postflight_and_keeps_count(tmp_path):
    class Metadata:
        def __init__(self, token, baseline, budget):
            self.budget = budget

        def preflight(self):
            self.budget.charge("management")
            return {}

        def postflight(self):
            raise AssertionError("postflight must not run after an incomplete collection")

    class Collector:
        def __init__(self, options, plan, wire, *, responsibility):
            pass

        def run(self):
            answer = receipt(NONCE)
            answer["complete"] = False
            answer["unrecovered"] = ["control"]
            return answer

    result = session.run_once(
        NONCE,
        OWNER,
        tmp_path,
        BASELINE,
        credential_fn=lambda: "test-access-token",
        metadata_factory=Metadata,
        wire_factory=lambda token, budget: lambda request: None,
        collector_factory=Collector,
    )
    assert result["complete"] is False
    assert result["sandboxRequests"] == 2
    assert result["postflight"] is None


def test_session_rejects_its_raw_oauth_token_in_collector_receipt(tmp_path):
    class Metadata:
        def __init__(self, token, baseline, budget):
            pass

        def preflight(self):
            return {}

        def postflight(self):
            return {}

    class Collector:
        def __init__(self, options, plan, wire, *, responsibility):
            pass

        def run(self):
            answer = receipt(NONCE)
            answer["rows"][0]["observed"]["message"] = "test-access-token"
            return answer

    with pytest.raises(ValueError, match="credential"):
        session.run_once(
            NONCE, OWNER, tmp_path, BASELINE,
            credential_fn=lambda: "test-access-token",
            metadata_factory=Metadata,
            wire_factory=lambda token, budget: lambda request: None,
            collector_factory=Collector,
        )


@pytest.mark.parametrize("name", [
    "HTTPS_PROXY", "ALL_PROXY", "CLOUDSDK_PROXY_ADDRESS",
    "GOOGLE_APPLICATION_CREDENTIALS", "CLOUDSDK_AUTH_ACCESS_TOKEN_FILE",
    "FIREBASE_TOKEN",
])
def test_ambient_proxy_or_credential_refuses_before_gcloud(monkeypatch, name):
    monkeypatch.setenv(name, "injected")
    monkeypatch.setattr(session.subprocess, "run", lambda *args, **kwargs: pytest.fail("gcloud ran"))
    with pytest.raises(ValueError, match="ambient"):
        session._access_token()


def test_gcloud_gets_only_the_minimum_environment(monkeypatch):
    monkeypatch.setenv("UNRELATED_SECRET", "must-not-travel")
    observed = []

    def run(command, **kwargs):
        observed.append(kwargs["env"])
        return type("Result", (), {"stdout": "test-access-token\n"})()

    monkeypatch.setattr(session.subprocess, "run", run)
    assert session._access_token() == "test-access-token"
    assert "UNRELATED_SECRET" not in observed[0]
    assert observed[0]["HOME"] == os.environ["HOME"]
