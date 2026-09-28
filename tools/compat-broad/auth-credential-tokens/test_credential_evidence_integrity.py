"""Strict, non-authenticating credential observations and typed cleanup evidence."""
from __future__ import annotations

import base64
import copy
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import credential_collector as c


def segment(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def jwt(payload=b'{"sub":"owned","iat":1,"exp":3601}', *, header=b'{"alg":"none"}', signature=""):
    return segment(header) + "." + segment(payload) + "." + signature


@pytest.mark.parametrize("payload", [
    b'{"sub":"other","sub":"owned"}',
    b'{"sub":"owned","sub":"owned"}',
    b'{"sub":"other","\\u0073ub":"owned"}',
    b'{"sub":"owned","nested":{"role":1,"role":2}}',
    b'{"sub":"owned","exp":NaN}',
    b'{"sub":"owned","exp":Infinity}',
    b'{"sub":"owned","exp":-Infinity}',
    b'{"sub":"owned","exp":1e9999}',
    '{"sub":"owned"}'.encode("utf-16"),
    '{"sub":"owned"}'.encode("utf-32"),
    b'{"sub":"owned","extra":"\xff"}',
])
def test_ambiguous_payload_gives_neither_shape_nor_subject_equality(payload):
    token = jwt(payload)
    with pytest.raises(ValueError):
        c.claim_shape(token)
    assert c.subjects_match(token, jwt()) is False
    assert c.subjects_match(jwt(), token) is False


@pytest.mark.parametrize("header", [
    b'{"alg":"RS256","alg":"none"}',
    b'{"alg":"none","nested":{"x":0,"x":1}}',
    b'{"alg":true}', b'{}', b'[]',
    '{"alg":"none"}'.encode("utf-16"),
])
def test_header_is_validated_for_subject_comparison_too(header):
    token = jwt(header=header)
    with pytest.raises(ValueError):
        c.claim_shape(token)
    assert c.subjects_match(token, jwt()) is False


@pytest.mark.parametrize("part", [0, 1])
@pytest.mark.parametrize("extra", ["!", "=", " ", "\n", "\t"])
def test_jwt_compact_base64url_does_not_ignore_extra_characters(part, extra):
    pieces = jwt().split(".")
    pieces[part] += extra
    token = ".".join(pieces)
    with pytest.raises(ValueError):
        c.claim_shape(token)
    assert c.subjects_match(token, jwt()) is False


@pytest.mark.parametrize("header,signature", [
    (b'{"alg":"none"}', "c2ln"),
    (b'{"alg":"RS256"}', ""),
    (b'{"alg":"RS256"}', "bad!"),
    (b'{"alg":"RS256"}', "a"),
])
def test_signature_shape_must_agree_with_algorithm_without_claiming_verification(header, signature):
    token = jwt(header=header, signature=signature)
    with pytest.raises(ValueError):
        c.claim_shape(token)
    assert c.subjects_match(token, jwt()) is False


def test_signed_envelope_is_only_described_and_not_cryptographically_authenticated():
    token = jwt(header=b'{"alg":"RS256"}', signature=segment(b'not a real signature'))
    assert c.claim_shape(token)["trustRoot"] == "signed"
    assert c.subjects_match(token, jwt()) is True
    # This positive control deliberately has no valid RSA signature. The helper is
    # observation-only; consumers must not use its result as authentication.


@pytest.mark.parametrize("name", c.TIME_CLAIM_NAMES)
@pytest.mark.parametrize("value", [True, False, 1.5, "10", None, []])
def test_non_integer_time_retains_its_type_but_is_not_a_whole_second(name, value):
    token = jwt(json.dumps({"sub": "owned", name: value}).encode())
    shape = c.claim_shape(token)
    assert name not in shape["times"]
    assert name in shape["claimTypes"]


@pytest.mark.parametrize("value", [0, -1, 1, 2**63])
def test_integer_time_is_preserved_without_inventing_an_expiry_validation(value):
    shape = c.claim_shape(jwt(json.dumps({"sub": "owned", "exp": value}).encode()))
    assert type(shape["times"]["exp"]) is int
    assert shape["times"]["exp"] == value


def test_deep_or_oversized_payload_is_a_bounded_fixed_diagnostic():
    for payload in [b'{"sub":"owned","x":' + b'[' * 2000 + b'0' + b']' * 2000 + b'}',
                    json.dumps({"sub": "owned", "role": "PRIVATE-" * 50000}).encode()]:
        with pytest.raises(ValueError) as exc:
            c.claim_shape(jwt(payload))
        assert "PRIVATE" not in str(exc.value)
        assert exc.value.__suppress_context__ or len(str(exc.value)) < 100
        assert c.subjects_match(jwt(payload), jwt()) is False


def tracker():
    result = c.new_tracker("a" * 32)
    c.track_account(result, "owned", c.owned_email(result, 0))
    return result


@pytest.mark.parametrize("flag", ["false", "true", 0, 1, None, [], {}])
@pytest.mark.parametrize("field", ["uid_absent", "email_absent"])
def test_cleanup_rejects_coercion_before_mutating_the_tracker(flag, field):
    state = tracker()
    before = copy.deepcopy(state)
    flags = {"uid_absent": True, "email_absent": True, field: flag}
    with pytest.raises(ValueError):
        c.mark_deleted(state, "owned", **flags)
    assert state == before
    assert c.cleanup_report(state)["cleanupComplete"] is False


@pytest.mark.parametrize("field", ["uidAbsent", "emailAbsent"])
@pytest.mark.parametrize("value", [1, "false"])
def test_report_rechecks_typed_flags_even_if_caller_mutated_state(field, value):
    state = tracker()
    c.mark_deleted(state, "owned", uid_absent=True, email_absent=True)
    state["accounts"]["owned"][field] = value
    assert c.cleanup_report(state)["remainingAccounts"] == 1
    assert c.cleanup_report(state)["cleanupComplete"] is False


def test_real_boolean_cleanup_and_addressless_accounts_still_complete():
    state = tracker()
    c.mark_deleted(state, "owned", uid_absent=True, email_absent=False)
    assert c.cleanup_report(state)["cleanupComplete"] is False
    c.mark_deleted(state, "owned", uid_absent=True, email_absent=True)
    c.track_account(state, "custom-token-user", None)
    c.mark_deleted(state, "custom-token-user", uid_absent=True, email_absent=False)
    assert c.cleanup_report(state) == {
        "ownedAccounts": 2, "remainingAccounts": 0,
        "addressReadbacks": 1, "cleanupComplete": True,
    }
