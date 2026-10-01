"""Finite credential preparation uses synthetic secrets and owned local HTTP only."""

import contextlib
import http.server
import importlib.util
import json
import sys
import threading
import time
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
    from urllib.parse import urlsplit

    state = {"requests": [], "scenario": "success"}
    stop = threading.Event()
    handlers = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            handlers.append(threading.current_thread())
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
            if state["scenario"] == "trickle":
                # Keep both valid JSON bodies slower than the normal worker budget.
                raw += b" " * 256
            if state["scenario"] == "oversize":
                raw = b"x" * 16385
            elif state["scenario"] == "malformed-json":
                raw = b'{"unterminated": tru'
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            try:
                if state["scenario"] == "trickle":
                    for byte in raw:
                        self.wfile.write(bytes([byte]))
                        self.wfile.flush()
                        if stop.wait(0.1):
                            break
                elif state["scenario"] == "truncated":
                    # Declares the full length but only ever writes half the
                    # body, then returns; the handler's default HTTP/1.0
                    # protocol closes the connection right after, matching
                    # the production observation: 200 + Content-Length, then
                    # the connection torn down before the body completes.
                    half = raw[: len(raw) // 2]
                    self.wfile.write(half)
                    self.wfile.flush()
                elif state["scenario"] == "stall":
                    # Declares the full length, writes nothing at all, and
                    # blocks well past any test-side socket timeout so the
                    # client's own read times out instead of hitting EOF.
                    stop.wait(20.0)
                else:
                    self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *_args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    state["origin"] = f"http://127.0.0.1:{server.server_port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield state
    finally:
        stop.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()
        for handler in handlers:
            handler.join(timeout=2)
            assert not handler.is_alive()


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
    # This integration includes interpreter setup; the short body bound is separate.
    started = time.monotonic()
    result = module._private_request(
        "refresh",
        ADC,
        fixture_origin=oauth_server["origin"],
        deadline=module.REQUEST_SECONDS if scenario == "trickle" else 3,
    )
    assert time.monotonic() - started < (module.REQUEST_SECONDS + 2 if scenario == "trickle" else 4)
    assert oauth_server["requests"] == [("POST", "/token")]
    assert result["workerReaped"] is True
    if scenario == "success":
        assert result["status"] == 200 and result["body"]["token_type"] == "Bearer"
    else:
        assert result["complete"] is False
        assert "synthetic" not in json.dumps(
            {k: v for k, v in result.items() if k != "body"}
        )


@pytest.mark.parametrize("scenario", ["success", "redirect", "oversize", "trickle"])
def test_private_worker_tokeninfo_slot_is_bounded_and_never_retries(
    oauth_server, scenario
):
    """The refresh slot above has this coverage; tokeninfo (the slot the
    2026-09-21 production stop actually charged) previously had none at all
    in this bounded-worker parametrization."""
    import time

    module = prep()
    oauth_server["scenario"] = scenario
    # This integration includes interpreter setup; the short body bound is separate.
    started = time.monotonic()
    result = module._private_request(
        "tokeninfo",
        "synthetic-access-secret",
        fixture_origin=oauth_server["origin"],
        deadline=module.REQUEST_SECONDS if scenario == "trickle" else 3,
    )
    assert time.monotonic() - started < (module.REQUEST_SECONDS + 2 if scenario == "trickle" else 4)
    assert oauth_server["requests"] == [("POST", "/oauth2/v1/tokeninfo")]
    assert result["workerReaped"] is True
    if scenario == "success":
        assert (
            result["status"] == 200 and result["body"]["audience"] == ADC["client_id"]
        )
    else:
        assert result["complete"] is False
        assert "synthetic" not in json.dumps(
            {k: v for k, v in result.items() if k != "body"}
        )


@pytest.mark.parametrize(
    "scenario, expected_failure",
    [
        ("truncated", "body-truncated"),
        ("oversize", "body-oversize"),
        ("malformed-json", "json-invalid"),
    ],
)
def test_http_request_failure_taxonomy_carries_diagnostics(
    oauth_server, scenario, expected_failure
):
    """Regression for the 2026-09-21 production stop: a 200 + Content-Length
    response whose connection closes before the declared body arrives used
    to collapse into the same generic 'response-limit'/'transport-or-json'
    failure as an oversize body or a JSON decode error, so operators could
    not tell them apart from the receipt alone."""
    module = prep()
    oauth_server["scenario"] = scenario
    result = module._http_request(
        "tokeninfo", "synthetic-access-secret", fixture_origin=oauth_server["origin"]
    )
    assert result["complete"] is False
    assert result["status"] == 200
    assert result["failure"] == expected_failure
    assert result["elapsedSeconds"] >= 0
    if scenario == "truncated":
        assert result["declaredLength"] is not None
        assert 0 < result["receivedBytes"] < result["declaredLength"]
    assert "synthetic" not in json.dumps(
        {k: v for k, v in result.items() if k != "body"}
    )


def test_http_request_read_timeout_reports_effective_socket_timeout(oauth_server):
    module = prep()
    oauth_server["scenario"] = "stall"
    result = module._http_request(
        "tokeninfo",
        "synthetic-access-secret",
        fixture_origin=oauth_server["origin"],
        timeout=0.3,
    )
    assert result["complete"] is False
    assert result["failure"] == "read-timeout"
    assert result["socketTimeoutSeconds"] == 0.3
    # `elapsedSeconds` is close to but no longer guaranteed to be exactly
    # `>= timeout`: `_http_request` now spends the same absolute deadline
    # across connect, headers and body phases (see PHASE_MARGIN_SECONDS), so
    # the body-phase socket timeout that actually fires is the requested
    # budget minus the earlier phases' (here, negligible) elapsed time and a
    # small per-phase safety margin, not the full requested timeout.
    assert result["elapsedSeconds"] >= 0.3 - module.PHASE_MARGIN_SECONDS - 0.05
    assert result["exceptionClass"]
    assert "synthetic" not in json.dumps(
        {k: v for k, v in result.items() if k != "body"}
    )


def test_http_request_reports_connect_failed_with_exception_class():
    import socket

    module = prep()
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    result = module._http_request(
        "tokeninfo",
        "synthetic-access-secret",
        fixture_origin=f"http://127.0.0.1:{port}",
        timeout=1,
    )
    assert result["complete"] is False
    assert result["status"] is None
    assert result["failure"] == "connect-failed"
    assert result["exceptionClass"] == "ConnectionRefusedError"


def test_bounded_socket_timeout_stays_below_kill_deadline_with_a_floor():
    module = prep()
    # Typical management-slot deadline (~12s, capped by REQUEST_SECONDS):
    # the socket timeout must be strictly below what `_private_request`
    # hands to `worker.communicate(timeout=...)`, with enough margin for
    # interpreter startup and result serialization.
    cleanup_margin = min(0.25, 12.0 / 4)
    bounded = module._bounded_socket_timeout(12.0, cleanup_margin)
    assert bounded < 12.0 - cleanup_margin
    assert bounded == pytest.approx(12.0 - cleanup_margin - 0.5)
    # A very short deadline still gets a usable, non-zero socket timeout.
    assert module._bounded_socket_timeout(0.1, 0.025) == 1.0


def test_tokeninfo_body_stall_is_bounded_without_interpreter_setup(oauth_server):
    """The real HTTP body budget reports its own diagnostic independently of child setup."""
    module = prep()
    oauth_server["scenario"] = "stall"
    budget = module._bounded_socket_timeout(2, .25)
    result = module._http_request(
        "tokeninfo", "synthetic-access-secret", fixture_origin=oauth_server["origin"], timeout=budget,
    )
    observation = {"result": result, "requests": oauth_server["requests"]}
    assert oauth_server["requests"] == [("POST", "/oauth2/v1/tokeninfo")], observation
    assert result["complete"] is False and result["status"] == 200, observation
    assert result["failure"] == "read-timeout" and result["phase"] == "body", observation
    assert result["declaredLength"] > 0 and result["receivedBytes"] == 0, observation
    assert result["socketTimeoutSeconds"] == pytest.approx(budget), observation
    assert budget - module.PHASE_MARGIN_SECONDS - .1 <= result["elapsedSeconds"] < budget + .5, observation
    assert "synthetic" not in json.dumps({key: value for key, value in result.items() if key != "body"})


def test_real_worker_stall_records_its_actual_failure_and_reap(oauth_server, record_property):
    module = prep()
    oauth_server["scenario"] = "stall"
    started = time.monotonic()
    result = module._private_request(
        "tokeninfo", "synthetic-access-secret", fixture_origin=oauth_server["origin"],
        deadline=module.REQUEST_SECONDS,
    )
    observation = {"result": result, "requests": oauth_server["requests"],
                   "callerElapsedSeconds": time.monotonic() - started}
    record_property("workerObservation", json.dumps(observation))
    assert oauth_server["requests"] == [("POST", "/oauth2/v1/tokeninfo")], observation
    assert result["complete"] is False and result["workerReaped"] is True, observation
    assert result["failure"] in {"read-timeout", "deadline"}, observation
    assert observation["callerElapsedSeconds"] < module.REQUEST_SECONDS + 2, observation
    if result["failure"] == "read-timeout":
        assert result["status"] == 200 and result["phase"] == "body", observation
    assert "synthetic" not in json.dumps({key: value for key, value in result.items() if key != "body"})


# --- Owner review a54c5abc8 regression coverage -----------------------------
#
# Adopted from docs.local/reviews/2026-09-21/owner-review-a54c5abc8/
# test_fireemu_credential_review_a54c5ab.py. The owner's fixture drives
# `_http_request`/`_private_request` directly against a raw
# `ThreadingHTTPServer` so it can control header timing and chunked framing
# precisely (the repo's `oauth_server` fixture above cannot delay headers or
# emit incomplete chunked bodies), so it is kept as its own local server
# context manager rather than folded into `oauth_server`.


@contextlib.contextmanager
def _boundary_server(scenario: str):
    state = {"requests": 0, "sentBodyBytes": 0, "scenario": scenario}
    stop = threading.Event()
    handlers = []

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self):
            try:
                self.respond()
            except (BrokenPipeError, ConnectionResetError):
                pass

        def respond(self):
            state["requests"] += 1
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            self.close_connection = True
            if scenario == "delayed_headers_stall":
                stop.wait(0.9)
            self.send_response(200)
            self.send_header("Connection", "close")
            if scenario in ("chunked_truncated", "chunked_success"):
                self.send_header("Transfer-Encoding", "chunked")
            else:
                self.send_header(
                    "Content-Length", "32" if scenario != "success" else "2"
                )
            self.end_headers()
            try:
                if scenario in ("immediate_stall", "delayed_headers_stall"):
                    stop.wait(20.0)
                elif scenario in ("partial_stall", "fixed_truncated"):
                    self.wfile.write(b"0123456789")
                    self.wfile.flush()
                    state["sentBodyBytes"] = 10
                    if scenario == "partial_stall":
                        stop.wait(20.0)
                elif scenario == "chunked_truncated":
                    # A complete ten-byte chunk, followed by EOF before the
                    # required terminal zero chunk.
                    self.wfile.write(b"A\r\n0123456789\r\n")
                    self.wfile.flush()
                    state["sentBodyBytes"] = 10
                elif scenario == "chunked_success":
                    self.wfile.write(b"2\r\n{}\r\n0\r\n\r\n")
                    self.wfile.flush()
                    state["sentBodyBytes"] = 2
                else:
                    self.wfile.write(b"{}")
                    self.wfile.flush()
                    state["sentBodyBytes"] = 2
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *_args):
            pass

    class FixtureServer(http.server.ThreadingHTTPServer):
        def process_request(self, request, client_address):
            handler = threading.Thread(target=self.process_request_thread,
                                       args=(request, client_address), daemon=True)
            handlers.append(handler)
            handler.start()

    httpd = FixtureServer(("127.0.0.1", 0), Handler)
    httpd.daemon_threads = True
    thread = threading.Thread(
        target=httpd.serve_forever, kwargs={"poll_interval": 0.02}
    )
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_port}", state
    finally:
        stop.set()
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()
        for handler in handlers:
            handler.join(timeout=2)
            assert not handler.is_alive()


def _observe(module, scenario: str, *, private: bool, deadline: float = 2.0, timeout: float = .3):
    with _boundary_server(scenario) as (origin, state):
        start = time.monotonic()
        if private:
            result = module._private_request(
                "tokeninfo",
                "synthetic-review-token",
                fixture_origin=origin,
                deadline=deadline,
            )
        else:
            result = module._http_request(
                "tokeninfo",
                "synthetic-review-token",
                fixture_origin=origin,
                timeout=timeout,
            )
        elapsed = time.monotonic() - start
    observation = {
        "scenario": scenario,
        "result": result,
        "fixture": dict(state),
        "callerElapsedSeconds": elapsed,
    }
    assert state["requests"] == 1, observation
    assert "synthetic-review-token" not in json.dumps(result), observation
    return observation


def test_immediate_body_stall_has_a_diagnostic():
    module = prep()
    budget = module._bounded_socket_timeout(2, .25)
    observation = _observe(module, "immediate_stall", private=False, timeout=budget)
    result = observation["result"]
    assert result["complete"] is False
    assert result["failure"] == "read-timeout" and result["phase"] == "body", observation
    assert result["status"] == 200 and result["declaredLength"] == 32, observation
    assert budget - module.PHASE_MARGIN_SECONDS - .1 <= result["elapsedSeconds"] < budget + .5, observation


@pytest.mark.parametrize("deadline", [2.0, 12.0])
def test_header_delay_must_not_consume_the_body_diagnostic_margin(deadline):
    """Earlier header time consumes the same HTTP deadline as body reads (owner review a54c5abc8 item1)."""
    module = prep()
    budget = module._bounded_socket_timeout(deadline, min(.25, deadline / 4))
    observation = _observe(module, "delayed_headers_stall", private=False, timeout=budget)
    result = observation["result"]
    assert result["complete"] is False
    assert result["failure"] == "read-timeout" and result["phase"] == "body", observation
    assert result["status"] == 200 and result["declaredLength"] == 32, observation
    assert result["socketTimeoutSeconds"] == pytest.approx(budget), observation
    assert budget - module.PHASE_MARGIN_SECONDS - .1 <= result["elapsedSeconds"] < budget + .5, observation


def test_partial_body_timeout_retains_received_byte_count():
    """Regression for owner review a54c5abc8 item 2: a mid-body timeout used
    to discard the bytes already read because `receivedBytes` was only ever
    set after a whole `read()` call succeeded."""
    module = prep()
    observation = _observe(module, "partial_stall", private=False)
    result = observation["result"]
    assert result["failure"] == "read-timeout", observation
    assert result["receivedBytes"] == 10, observation


def test_truncated_chunked_body_has_a_truncation_diagnostic():
    """Regression for owner review a54c5abc8 item 2: a chunked disconnect
    before the terminator used to surface as transport-error/IncompleteRead
    with receivedBytes 0 instead of body-truncated with the partial length."""
    module = prep()
    observation = _observe(module, "chunked_truncated", private=False)
    result = observation["result"]
    assert result["complete"] is False
    assert result["failure"] == "body-truncated", observation
    assert result["receivedBytes"] == 10, observation


def test_fixed_length_truncation_positive_control():
    module = prep()
    observation = _observe(module, "fixed_truncated", private=False)
    result = observation["result"]
    assert result["failure"] == "body-truncated", observation
    assert result["receivedBytes"] == 10
    assert result["declaredLength"] == 32


@pytest.mark.parametrize("scenario", ["success", "chunked_success"])
def test_complete_json_positive_controls(scenario):
    module = prep()
    observation = _observe(module, scenario, private=True)
    result = observation["result"]
    assert result["complete"] is True, observation
    assert result["body"] == {}
    assert result["receivedBytes"] == 2
    assert result["workerReaped"] is True


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
        "campaignId": "FS-WRITE-TXN-PRECEDENCE-01",
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


def test_owned_shadow_http_fixture_performs_same_two_slot_protocol(tmp_path):
    import stream_shadow

    assert hasattr(stream_shadow, "SHADOW_ADC")
    output, ledger, ticket, permission, plan, handoff = reserved_fixture(tmp_path)
    # The owned shadow uses exactly these public synthetic fixtures.
    assert stream_shadow.SHADOW_ADC == ADC
    with stream_shadow.metadata_fixture() as (origin, payloads):
        _, proof = prep().prepare_credentials(
            output, ledger, ticket, permission, plan, handoff, fixture_origin=origin
        )
        assert payloads["credentialRequests"] == ["/token", "/oauth2/v1/tokeninfo"]
    combined = prep().validate_preparation(
        output,
        ledger,
        ticket,
        permission,
        proof,
        {"total": 31, "costMicrousd": 1_303_100},
    )
    assert combined == {"requests": 33, "costMicrousd": 1_303_300}


def test_private_worker_uses_isolated_stdlib_interpreter(oauth_server, monkeypatch):
    import subprocess

    original = subprocess.Popen
    calls = []

    def start(argv, **kwargs):
        calls.append((list(argv), dict(kwargs["env"])))
        return original(argv, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", start)
    result = prep()._private_request(
        "refresh",
        ADC,
        fixture_origin=oauth_server["origin"],
        deadline=3,
    )
    assert len(calls) == 1
    assert calls[0][0][1:4] == ["-I", "-S", "-B"]
    assert set(calls[0][1]) == {"PATH", "LANG"}
    assert result["complete"] is True and result["workerReaped"] is True
    assert oauth_server["requests"] == [("POST", "/token")]


def test_trickle_worker_reaches_post_after_separate_interpreter_setup(oauth_server, monkeypatch):
    import subprocess

    processes = []
    launch = subprocess.Popen

    def delayed_launch(*args, **kwargs):
        process = launch(*args, **kwargs)
        processes.append(process)
        time.sleep(1)
        return process

    monkeypatch.setattr(subprocess, "Popen", delayed_launch)
    oauth_server["scenario"] = "trickle"
    try:
        started = time.monotonic()
        result = prep()._private_request(
            "tokeninfo", "synthetic-access-secret",
            fixture_origin=oauth_server["origin"],
        )
        assert time.monotonic() - started < prep().REQUEST_SECONDS + 2
        assert oauth_server["requests"] == [("POST", "/oauth2/v1/tokeninfo")]
        assert result["complete"] is False and result["workerReaped"] is True
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=2)
            for stream in (process.stdin, process.stdout):
                if stream is not None and not stream.closed:
                    stream.close()


@pytest.mark.parametrize("slot", ["refresh", "tokeninfo"])
def test_trickle_body_deadline_reaches_response_without_interpreter_setup(oauth_server, slot):
    oauth_server["scenario"] = "trickle"
    result = prep()._http_request(
        slot, ADC if slot == "refresh" else "synthetic-access-secret",
        oauth_server["origin"], timeout=.5,
    )
    path = "/token" if slot == "refresh" else "/oauth2/v1/tokeninfo"
    assert oauth_server["requests"] == [("POST", path)]
    assert result["complete"] is False
    assert result["status"] == 200 and result["phase"] == "body"
    assert result["failure"] == "read-timeout"
    assert 0 < result["receivedBytes"] < result["declaredLength"]
    assert result["socketTimeoutSeconds"] == .5
    assert result["elapsedSeconds"] < 1.5
    assert "synthetic" not in json.dumps(result)


def _patch_test_thread_clock(monkeypatch, clock):
    owner = threading.current_thread()
    started_threads = []
    original_start = threading.Thread.start
    real_monotonic = time.monotonic

    def start(thread, *args, **kwargs):
        if threading.current_thread() is owner:
            started_threads.append(thread)
        return original_start(thread, *args, **kwargs)

    def monotonic():
        return clock.now if threading.current_thread() is owner else real_monotonic()

    monkeypatch.setattr(time, "monotonic", monotonic)
    monkeypatch.setattr(threading.Thread, "start", start)
    return started_threads


def _assert_no_started_threads(started_threads):
    lingering = [thread for thread in started_threads if thread.is_alive()]
    assert not lingering, [(thread.name, thread.ident) for thread in lingering]


@pytest.mark.parametrize("reaped", [True, False])
@pytest.mark.parametrize("launch_seconds", [0, .6])
def test_short_parent_deadline_kills_once_and_preserves_unconfirmed_reap(
    monkeypatch, reaped, launch_seconds
):
    import subprocess
    from types import SimpleNamespace

    clock = SimpleNamespace(now=0.0)
    initial_threads = _patch_test_thread_clock(monkeypatch, clock)
    owner = threading.current_thread()
    original_launch = subprocess.Popen

    class Worker:
        pid = 123456
        returncode = None

        def __init__(self):
            self.calls = []
            self.kills = 0

        def communicate(self, raw=None, *, timeout):
            self.calls.append((raw, timeout))
            clock.now += timeout
            if len(self.calls) == 1 or not reaped:
                raise subprocess.TimeoutExpired("synthetic-worker", timeout)
            self.returncode = -9
            return b"", b""

        def kill(self):
            self.kills += 1

        def poll(self):
            return self.returncode

    worker = Worker()
    launches = []

    def launch(*args, **kwargs):
        if threading.current_thread() is not owner:
            return original_launch(*args, **kwargs)
        launches.append((args, kwargs))
        clock.now += launch_seconds
        return worker

    monkeypatch.setattr(subprocess, "Popen", launch)
    result = prep()._private_request(
        "tokeninfo", "synthetic-access-secret", deadline=.5,
        fixture_origin="http://127.0.0.1:65535",
    )
    assert len(launches) == 1 and len(worker.calls) == 2
    assert worker.calls[0][1] == pytest.approx(.375 if launch_seconds == 0 else 0)
    assert worker.calls[1][1] == pytest.approx(.125 if launch_seconds == 0 else 0)
    assert worker.calls[0][0] is not None and worker.calls[1][0] is None
    assert result["complete"] is False and result["failure"] == "deadline"
    assert result["workerReaped"] is reaped
    assert worker.kills == (1 if reaped else 2)
    assert ("workerPid" in result) is not reaped
    if not reaped:
        assert result["workerPid"] == worker.pid
    _assert_no_started_threads(initial_threads)


@pytest.mark.parametrize("deadline,socket_budget,parent_budget", [(2, 1.25, 1.75), (12, 11.25, 11.75)])
@pytest.mark.parametrize("complete", [True, False])
def test_parent_accepts_serialized_worker_receipt_with_its_bounded_payload(
    monkeypatch, deadline, socket_budget, parent_budget, complete
):
    import subprocess
    from types import SimpleNamespace

    clock = SimpleNamespace(now=0.0)
    initial_threads = _patch_test_thread_clock(monkeypatch, clock)
    owner = threading.current_thread()
    original_launch = subprocess.Popen
    receipt = {"complete": complete, "status": 200, "receivedBytes": 2 if complete else 0,
               "declaredLength": 2, "phase": "body", "socketTimeoutSeconds": socket_budget,
               "elapsedSeconds": socket_budget}
    if complete:
        receipt["body"] = {}
    else:
        receipt["failure"] = "read-timeout"
    calls = []

    class Worker:
        returncode = None

        def communicate(self, raw, *, timeout):
            payload = json.loads(raw)
            calls.append((payload, timeout))
            assert payload == {"slot": "tokeninfo", "secret": "synthetic-access-secret",
                               "socketTimeoutSeconds": socket_budget,
                               "fixtureOrigin": "http://127.0.0.1:65535"}
            assert timeout == pytest.approx(parent_budget - .1)
            assert socket_budget < timeout
            clock.now += socket_budget
            self.returncode = 0
            return json.dumps(receipt).encode(), b""

        def poll(self):
            return self.returncode

        def kill(self):
            pytest.fail("a serialized receipt within the parent budget must not be killed")

    launches = []

    def launch(*args, **kwargs):
        if threading.current_thread() is not owner:
            return original_launch(*args, **kwargs)
        launches.append((args, kwargs))
        clock.now += .1
        return Worker()

    monkeypatch.setattr(subprocess, "Popen", launch)
    result = prep()._private_request(
        "tokeninfo", "synthetic-access-secret", deadline=deadline,
        fixture_origin="http://127.0.0.1:65535",
    )
    assert len(launches) == len(calls) == 1
    assert result == {**receipt, "workerReaped": True}
    assert "synthetic-access-secret" not in json.dumps(result)
    _assert_no_started_threads(initial_threads)


@pytest.mark.parametrize("scenario", ["tokeninfo-stall", "immediate-body", "delayed-headers"])
def test_body_diagnostic_does_not_depend_on_interpreter_setup(request, monkeypatch, scenario):
    """Exact HTTP diagnostics use the prepared direct path and launch no interpreter."""
    import subprocess

    launch = subprocess.Popen
    launches = []

    def delayed_launch(*args, **kwargs):
        launches.append((args, kwargs))
        # Delay launch after the parent deadline starts, before child stdin and the actual HTTP phase.
        time.sleep(.8)
        return launch(*args, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", delayed_launch)
    if scenario == "tokeninfo-stall":
        test_tokeninfo_body_stall_is_bounded_without_interpreter_setup(
            request.getfixturevalue("oauth_server")
        )
    elif scenario == "immediate-body":
        test_immediate_body_stall_has_a_diagnostic()
    else:
        test_header_delay_must_not_consume_the_body_diagnostic_margin(2.0)
    assert launches == []


@pytest.mark.parametrize("kind", ["deadline", "serialized"])
def test_fake_parent_clock_preserves_a_foreign_threads_real_clock(monkeypatch, kind):
    import subprocess

    release = threading.Event()
    entered = threading.Event()
    observations = []
    real_started = time.monotonic()

    def foreign():
        entered.set()
        release.wait(5)
        try:
            observed_clock = time.monotonic()
            code = subprocess.run(["ps", "-A", "-o", "pid="], capture_output=True, text=True, check=True).returncode
            observations.append({"clock": observed_clock, "returncode": code})
        except BaseException as error:
            observations.append(error)

    thread = threading.Thread(target=foreign, name="foreign-clock-control", daemon=True)
    thread.start()
    assert entered.wait(2)
    try:
        if kind == "deadline":
            test_short_parent_deadline_kills_once_and_preserves_unconfirmed_reap(monkeypatch, True, .6)
        else:
            test_parent_accepts_serialized_worker_receipt_with_its_bounded_payload(
                monkeypatch, 12, 11.25, 11.75, False,
            )
    finally:
        release.set()
        thread.join(timeout=2)
    assert not thread.is_alive()
    assert len(observations) == 1 and isinstance(observations[0], dict), observations
    assert observations[0]["clock"] >= real_started and observations[0]["returncode"] == 0, observations
