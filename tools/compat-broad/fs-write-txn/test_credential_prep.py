"""Finite credential preparation uses synthetic secrets and owned local HTTP only."""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parents[1]))

from broad_contract import digest

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
    assert hasattr(module, "private_request")
    oauth_server["scenario"] = scenario
    started = time.monotonic()
    result = module.private_request(
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
