"""SECURITY-SENSITIVE: which claims the runner requires of an App Check token (Codex r2 on slice 2b, M2 and M3).

The stock Admin SDK checks `aud` against `projects/<projectId>` only (`firebase_admin/app_check.py`,
`_scoped_project_id` and `_decode_and_verify`), checks the issuer by prefix only (it does not check it at all in
`_decode_and_verify`) and validates `exp` only if the token has one. The replacement service keeps the stock audience
rule as it is, for parity, and adds what the App Check emulator always does: `exp` is required, and the issuer is
exactly `https://firebaseappcheck.googleapis.com/<project number>` with the number agreeing with the `projects/<number>`
audience the emulator puts next to the project ID. It rejects only tokens the emulator never mints.
"""

import json
import time

import pytest
from werkzeug.test import Client

from fireemu_runner import appcheck
from fireemu_runner.manifest import build_manifest
from fireemu_runner.serve import RunnerRouter
from test_appcheck import EMULATOR_KEY, KID, PROJECT, SECRET, call, hooked, token  # noqa: F401  (hooked is a fixture)

ISSUER = "https://firebaseappcheck.googleapis.com/"


def stock_class():
    from firebase_admin import app_check

    return app_check._AppCheckService.__mro__[1]


def stock_accepts(value):
    """Whether the stock SDK's own `_decode_and_verify` accepts `value` for this project."""
    service = object.__new__(stock_class())
    service._scoped_project_id = f"projects/{PROJECT}"
    try:
        service._decode_and_verify(value, EMULATOR_KEY.public_key())
        return True
    except Exception:
        return False


def ours_accepts(value):
    from firebase_admin import app_check

    try:
        app_check.verify_token(value)
        return True
    except Exception:
        return False


NUMBER = "projects/1234567890"
IDENTITY = f"projects/{PROJECT}"


@pytest.mark.parametrize(
    "label, audience",
    [
        ("the project ID only", [IDENTITY]),
        ("the project number only", [NUMBER]),
        ("both, as the emulator mints them", [NUMBER, IDENTITY]),
        ("both, reversed", [IDENTITY, NUMBER]),
        ("neither", ["projects/other-project"]),
        ("no audience", []),
        ("another project's ID with the right number", [NUMBER, "projects/other-project"]),
    ],
)
def test_the_audience_rule_is_the_stock_sdks_for_every_form(hooked, label, audience):  # noqa: F811
    value = token(audience=audience)
    assert ours_accepts(value) == stock_accepts(value), label


def test_the_forms_pin_what_the_stock_sdk_does_so_a_change_in_it_is_noticed(hooked):  # noqa: F811
    assert stock_accepts(token(audience=[IDENTITY])) is True
    assert stock_accepts(token(audience=[NUMBER])) is False
    assert stock_accepts(token(audience=[NUMBER, IDENTITY])) is True


def test_a_token_with_a_number_that_is_not_the_issuers_is_refused_though_the_stock_sdk_accepts_it(hooked):  # noqa: F811
    value = token(audience=["projects/9999999999", IDENTITY])
    assert stock_accepts(value) is True
    assert ours_accepts(value) is False


@pytest.mark.parametrize(
    "label, claims, drop",
    [
        ("no exp", {}, ("exp",)),
        ("a null exp", {"exp": None}, ()),
        ("a string exp", {"exp": "9999999999"}, ()),
        ("no issuer", {}, ("iss",)),
        ("another project's issuer", {"iss": ISSUER + "999"}, ()),
        ("an issuer with a suffix", {"iss": ISSUER + "1234567890/extra"}, ()),
        ("an issuer with a trailing slash", {"iss": ISSUER + "1234567890/"}, ()),
        ("an issuer that is only a prefix of the right one", {"iss": ISSUER + "123456789"}, ()),
        ("an issuer on another host", {"iss": "https://example.com/1234567890"}, ()),
        ("an issuer with a query", {"iss": ISSUER + "1234567890?x=1"}, ()),
        ("an issuer in upper case", {"iss": ISSUER.upper() + "1234567890"}, ()),
        ("an issuer that is not a number", {"iss": ISSUER + "abc"}, ()),
        ("no subject", {}, ("sub",)),
        ("an empty subject", {"sub": ""}, ()),
        ("a numeric subject", {"sub": 5}, ()),
    ],
)
def test_a_correctly_signed_token_with_a_claim_the_emulator_never_mints_is_refused(hooked, label, claims, drop):  # noqa: F811
    assert ours_accepts(token(claims=claims, drop=drop)) is False, label


def test_the_emulators_own_claims_are_accepted(hooked):  # noqa: F811
    assert ours_accepts(token()) is True
    assert ours_accepts(token(audience=[IDENTITY, NUMBER], claims={"jti": "x", "fireemu_epoch": "e" * 32})) is True


@pytest.fixture
def client(discovered, hooked):  # noqa: F811
    return Client(RunnerRouter(discovered, build_manifest(discovered, app_check_verified=True), PROJECT, SECRET))


@pytest.mark.parametrize(
    "label, claims, drop",
    [
        ("no exp", {}, ("exp",)),
        ("another project's issuer", {"iss": ISSUER + "999"}, ()),
        ("an issuer with a suffix", {"iss": ISSUER + "1234567890/more"}, ()),
        ("no issuer", {}, ("iss",)),
    ],
)
def test_an_enforcing_callable_answers_401_to_each_of_them_and_a_plain_one_sees_no_app(client, label, claims, drop):
    bad = token(claims=claims, drop=drop)
    status, body = call(client, "add_enforced", bad)
    assert status == 401 and "result" not in body, label
    status, body = call(client, "add_enforced_off", bad)
    assert status == 200 and body["result"]["app"] is None, label
    status, body = call(client, "add_enforced", token())
    assert status == 200 and body["result"]["app"] == "1:1234567890:web:app"


def refusal(value):
    from firebase_admin import app_check

    with pytest.raises(ValueError) as error:
        app_check.verify_token(value)
    return str(error.value)


def test_the_exact_messages_of_the_claim_checks(hooked):  # noqa: F811
    assert refusal(token(drop=("exp",))) == 'The provided App Check token has no "exp" (expiration) claim.'
    assert refusal(token(claims={"iss": ISSUER + "x"})) == 'The provided App Check token has an incorrect "iss" (issuer) claim.'
    assert ours_accepts(token(drop=("iss",))) is False  # the stock SDK's own issuer check fails first, with an AttributeError
    assert refusal(token(audience=["projects/999", IDENTITY])) == 'The provided App Check token has a project number in "aud" that is not its issuer\'s.'
    assert refusal(token(claims={"sub": ""})) == 'The provided App Check token has no "sub" (app ID) claim.'
    # A missing subject is the stock SDK's to refuse, before the runner's check.
    assert refusal(token(drop=("sub",))) == 'The provided App Check token "sub" (subject) claim "None" must be a non-empty string.'


def test_an_audience_given_as_a_single_string_is_refused_as_the_stock_sdk_refuses_it(hooked):  # noqa: F811
    for audience in (IDENTITY, NUMBER):
        value = token(audience=audience)
        assert stock_accepts(value) is False and ours_accepts(value) is False
