"""Finite credential preparation uses synthetic secrets and owned local HTTP only."""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parents[1]))

from broad_contract import digest
from test_stream_bridge import trusted_node_runtime  # noqa: F401

ADC = {
    "type": "authorized_user",
    "client_id": "local-client.apps.googleusercontent.com",
    "client_secret": "synthetic-client-secret",
    "refresh_token": "synthetic-refresh-secret",
}
PRINCIPAL = {
    "clientId": ADC["client_id"],
    "requiredScopes": ["https://www.googleapis.com/auth/cloud-platform"],
}


def prep():
    assert importlib.util.find_spec("credential_prep") is not None, (
        "bounded credential preparation is required"
    )
    return __import__("credential_prep")


def test_frozen_two_post_contract_preserves_inner_budget():
    contract = prep().contract()
    assert [
        (slot["method"], slot["host"], slot["path"]) for slot in contract["slots"]
    ] == [
        ("POST", "oauth2.googleapis.com", "/token"),
        ("POST", "www.googleapis.com", "/oauth2/v1/tokeninfo"),
    ]
    assert contract["outer"] == {
        "requests": 35,
        "seconds": 1200,
        "costMicrousd": 1_303_500,
    }
    assert contract["inner"] == {
        "requests": 33,
        "seconds": 1100,
        "costMicrousd": 1_303_300,
    }
    assert contract["requestSeconds"] == 12


@pytest.mark.parametrize(
    "mutation",
    ["duplicate", "wrong-type", "extra-endpoint", "wrong-digest", "wrong-client"],
)
def test_authorized_user_handoff_is_exact_and_permission_bound(mutation):
    module = prep()
    permission = {"authorizedUserDigest": digest(ADC), "credentialPrincipal": PRINCIPAL}
    value = {
        "kind": "stream-o8-authorized-user-v1",
        "permissionDigest": digest(permission),
        "apiKey": "synthetic-key",
        "adc": dict(ADC),
    }
    if mutation == "duplicate":
        raw = json.dumps(value).replace(
            '"type": "authorized_user"',
            '"type":"service_account","type":"authorized_user"',
        )
        with pytest.raises(ValueError):
            module.decode_json(raw)
        return
    if mutation == "wrong-type":
        value["adc"]["type"] = "service_account"
    elif mutation == "extra-endpoint":
        value["adc"]["token_uri"] = "https://unapproved.invalid/token"
    elif mutation == "wrong-digest":
        value["adc"]["refresh_token"] = "different-secret"
    else:
        permission["credentialPrincipal"] = {
            **PRINCIPAL,
            "clientId": "different-client",
        }
        value["permissionDigest"] = digest(permission)
    with pytest.raises(ValueError):
        module.validate_handoff(value, permission)


def test_authorized_user_digest_covers_exactly_four_canonical_fields():
    permission = {"authorizedUserDigest": digest(ADC), "credentialPrincipal": PRINCIPAL}
    value = {
        "kind": "stream-o8-authorized-user-v1",
        "permissionDigest": digest(permission),
        "apiKey": "synthetic-key",
        "adc": dict(ADC),
    }
    assert prep().validate_handoff(value, permission) == value


@pytest.fixture
def oauth_server():
    import http.server
    import threading
    import time
    from urllib.parse import urlsplit

    state = {"requests": [], "scenario": "success"}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            path = urlsplit(self.path).path
            state["requests"].append(("POST", path))
            if "before_response" in state:
                state["before_response"]()
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            body = (
                {
                    "access_token": "synthetic-access-secret",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                }
                if path == "/token"
                else {
                    "audience": ADC["client_id"],
                    "issued_to": ADC["client_id"],
                    "scope": SCOPE,
                    "expires_in": 3599,
                }
            )
            raw = json.dumps(body).encode()
            if state["scenario"] == "redirect":
                self.send_response(302)
                self.send_header("Location", state["origin"] + "/unexpected")
            else:
                self.send_response(200)
            if state["scenario"] == "oversize":
                raw = b"x" * 16385
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            try:
                if state["scenario"] == "trickle":
                    for byte in raw:
                        self.wfile.write(bytes([byte]))
                        self.wfile.flush()
                        time.sleep(0.1)
                else:
                    self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *_args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    state["origin"] = f"http://127.0.0.1:{server.server_port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()


SCOPE = PRINCIPAL["requiredScopes"][0]


def test_closed_request_builder_has_no_endpoint_or_method_override():
    module = prep()
    assert hasattr(module, "build_request")
    refresh = module.build_request("refresh", ADC)
    assert (refresh["method"], refresh["host"], refresh["path"]) == (
        "POST",
        "oauth2.googleapis.com",
        "/token",
    )
    assert b"grant_type=refresh_token" in refresh["body"]
    info = module.build_request("tokeninfo", "synthetic-access-secret")
    assert info["method"] == "POST" and info["host"] == "www.googleapis.com"
    assert info["path"] == "/oauth2/v1/tokeninfo?access_token=synthetic-access-secret"
    with pytest.raises(ValueError):
        module.build_request("retry", ADC)


@pytest.mark.parametrize("scenario", ["success", "redirect", "oversize", "trickle"])
def test_private_worker_is_bounded_and_never_retries(oauth_server, scenario):
    import time

    module = prep()
    assert hasattr(module, "_private_request")
    oauth_server["scenario"] = scenario
    started = time.monotonic()
    result = module._private_request(
        "refresh",
        ADC,
        fixture_origin=oauth_server["origin"],
        deadline=0.5 if scenario == "trickle" else 3,
    )
    assert time.monotonic() - started < 4
    assert oauth_server["requests"] == [("POST", "/token")]
    assert result["workerReaped"] is True
    if scenario == "success":
        assert result["status"] == 200 and result["body"]["token_type"] == "Bearer"
    else:
        assert result["complete"] is False
        assert "synthetic" not in json.dumps(
            {k: v for k, v in result.items() if k != "body"}
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-client",
        "wrong-client",
        "conflicting-client",
        "scope",
        "short",
        "boolean-expiry",
    ],
)
def test_verified_token_requires_bound_client_scope_and_lifetime(mutation):
    import time

    module = prep()
    assert hasattr(module, "verified_credential")
    body = {"audience": ADC["client_id"], "scope": SCOPE, "expires_in": 3500}
    if mutation == "missing-client":
        body.pop("audience")
    elif mutation == "wrong-client":
        body["audience"] = "different"
    elif mutation == "conflicting-client":
        body["issued_to"] = "different"
    elif mutation == "scope":
        body["scope"] = "unrelated"
    elif mutation == "short":
        body["expires_in"] = 100
    else:
        body["expires_in"] = True
    with pytest.raises(ValueError):
        module.verified_credential(
            "synthetic-access-secret",
            time.monotonic() + 3600,
            body,
            PRINCIPAL,
            time.monotonic(),
        )


def test_verified_token_does_not_require_unknown_email_claims():
    import time

    module = prep()
    assert hasattr(module, "verified_credential")
    credential, facts = module.verified_credential(
        "synthetic-access-secret",
        time.monotonic() + 3500,
        {"issued_to": ADC["client_id"], "scope": SCOPE, "expires_in": 3600},
        PRINCIPAL,
        time.monotonic(),
    )
    assert credential.usable(time.monotonic(), 1102)
    assert credential.expiry < time.monotonic() + 3500
    assert "synthetic-access-secret" not in json.dumps(facts)


def reserved_fixture(tmp_path):
    import time

    import stream_production as production
    from reservations import Ledger

    output = tmp_path / "execution"
    output.mkdir(mode=0o700)
    permission = {
        "kind": "local-stream-shadow-only",
        "credentialMode": prep().MODE,
        "credentialPreparationDigest": digest(prep().contract()),
        "authorizedUserDigest": digest(ADC),
        "credentialPrincipal": PRINCIPAL,
        "apiKeyDigest": digest("synthetic-key"),
        "expiresAt": time.time() + 1800,
    }
    plan = production.prepared_plan(
        "local-credential-prep", "local-owner", digest(permission)
    )
    locks = production.resource_locks(plan)
    budget = {"requests": 35, "accounts": 0, "resources": 3, "costMicrousd": 1_303_500}
    ledger = Ledger.create(tmp_path / "ledger")
    envelope = {
        "permissionDigest": digest(permission),
        "issuedAt": time.time() - 1,
        "expiresAt": permission["expiresAt"],
        "limits": budget,
        "concurrency": 1,
        "scopes": locks,
    }
    claim = {
        "campaignId": plan["nonce"],
        "manifestDigest": digest(plan),
        "nonceDigest": digest(plan["nonce"]),
        "gatePath": str((output / "gate").resolve()),
        "gatePlanDigest": digest(plan),
        "locks": locks,
        "budget": budget,
        "durationSeconds": 1200,
    }
    ticket = ledger.reserve(envelope, claim, plan)
    handoff = {
        "kind": "stream-o8-authorized-user-v1",
        "permissionDigest": digest(permission),
        "apiKey": "synthetic-key",
        "adc": dict(ADC),
    }
    return output, ledger, ticket, permission, plan, handoff


def test_two_spent_slots_require_live_ticket_and_leave_no_secret_artifacts(
    tmp_path, oauth_server
):
    import time

    module = prep()
    assert hasattr(module, "prepare_credentials")
    output, ledger, ticket, permission, plan, handoff = reserved_fixture(tmp_path)

    def check_reservation():
        ledger.validate(ticket, duration=1102)
        assert ledger.bound_claim(ticket)["budget"]["requests"] == 35

    oauth_server["before_response"] = check_reservation
    credential, proof = module.prepare_credentials(
        output,
        ledger,
        ticket,
        permission,
        plan,
        handoff,
        fixture_origin=oauth_server["origin"],
    )
    assert credential.usable(time.monotonic(), 1102)
    assert oauth_server["requests"] == [
        ("POST", "/token"),
        ("POST", "/oauth2/v1/tokeninfo"),
    ]
    assert proof["attempts"] == 2
    artifacts = "".join(p.read_text() for p in output.rglob("*.json"))
    for secret in (
        ADC["client_secret"],
        ADC["refresh_token"],
        "synthetic-access-secret",
        "synthetic-key",
    ):
        assert secret not in artifacts
    with pytest.raises(ValueError):
        module.prepare_credentials(
            output,
            ledger,
            ticket,
            permission,
            plan,
            handoff,
            fixture_origin=oauth_server["origin"],
        )
    assert len(oauth_server["requests"]) == 2
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"


def test_failed_refresh_spends_one_slot_and_never_runs_tokeninfo(
    tmp_path, oauth_server
):
    module = prep()
    assert hasattr(module, "prepare_credentials")
    args = reserved_fixture(tmp_path)
    oauth_server["scenario"] = "redirect"
    with pytest.raises(ValueError):
        module.prepare_credentials(*args, fixture_origin=oauth_server["origin"])
    assert oauth_server["requests"] == [("POST", "/token")]
    assert (args[0] / "credential-preparation/refresh-charge.json").is_file()
    assert not (args[0] / "credential-preparation/tokeninfo-charge.json").exists()


def test_preparation_journal_tampering_cannot_become_final_proof(
    tmp_path, oauth_server
):
    module = prep()
    assert hasattr(module, "prepare_credentials")
    output, ledger, ticket, permission, plan, handoff = reserved_fixture(tmp_path)
    _, proof = module.prepare_credentials(
        output,
        ledger,
        ticket,
        permission,
        plan,
        handoff,
        fixture_origin=oauth_server["origin"],
    )
    path = output / "credential-preparation/tokeninfo-receipt.json"
    record = json.loads(path.read_text())
    record["verified"] = False
    path.write_text(json.dumps(record))
    with pytest.raises(ValueError):
        module.validate_preparation(
            output,
            ledger,
            ticket,
            permission,
            proof,
            {"total": 0, "costMicrousd": 1_300_000},
        )
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"
