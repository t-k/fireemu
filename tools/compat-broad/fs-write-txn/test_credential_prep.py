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
            elif state["scenario"] == "malformed-json":
                raw = b'{"unterminated": tru'
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            try:
                if state["scenario"] == "trickle":
                    for byte in raw:
                        self.wfile.write(bytes([byte]))
                        self.wfile.flush()
                        time.sleep(0.1)
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
                    time.sleep(2.0)
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
    started = time.monotonic()
    result = module._private_request(
        "tokeninfo",
        "synthetic-access-secret",
        fixture_origin=oauth_server["origin"],
        deadline=0.5 if scenario == "trickle" else 3,
    )
    assert time.monotonic() - started < 4
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


def test_private_worker_tokeninfo_stall_times_out_before_kill(oauth_server):
    """The socket-level timeout used to be a hardcoded REQUEST_SECONDS (12s)
    regardless of the deadline handed to `_private_request`, and that
    deadline can never exceed REQUEST_SECONDS -- so the coordinator's own
    SIGKILL always won the race and the worker's graceful, labeled
    read-timeout path was unreachable in production. This proves the fixed
    per-call socket timeout now fires first."""
    module = prep()
    oauth_server["scenario"] = "stall"
    result = module._private_request(
        "tokeninfo",
        "synthetic-access-secret",
        fixture_origin=oauth_server["origin"],
        deadline=2.0,
    )
    assert result["workerReaped"] is True
    assert result["complete"] is False
    assert result["failure"] == "read-timeout"
    expected = module._bounded_socket_timeout(2.0, min(0.25, 2.0 / 4))
    assert result["socketTimeoutSeconds"] == pytest.approx(expected)
    assert result["elapsedSeconds"] < 2.0
    assert "synthetic" not in json.dumps(
        {k: v for k, v in result.items() if k != "body"}
    )


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

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self):
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

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
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


def _observe(module, scenario: str, *, private: bool, deadline: float = 2.0):
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
                timeout=0.3,
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
    observation = _observe(module, "immediate_stall", private=True)
    result = observation["result"]
    assert result["complete"] is False
    assert result["workerReaped"] is True
    assert result["failure"] == "read-timeout", observation
    assert result["status"] == 200


@pytest.mark.parametrize("deadline", [2.0, 12.0])
def test_header_delay_must_not_consume_the_body_diagnostic_margin(deadline):
    """Regression for owner review a54c5abc8 item 1: a fixed per-op socket
    timeout let a 0.9s header delay plus a fresh full-length body timeout
    exceed the coordinator's own kill deadline, so the worker was reaped
    before it could return its own labeled diagnostic. With an absolute
    per-call deadline, time spent waiting on headers comes out of the same
    budget as the body read, so the worker always reports before the kill."""
    module = prep()
    observation = _observe(
        module, "delayed_headers_stall", private=True, deadline=deadline
    )
    result = observation["result"]
    assert result["complete"] is False
    assert result["workerReaped"] is True
    assert result["failure"] == "read-timeout", observation
    assert result["status"] == 200, observation


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
