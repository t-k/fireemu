"""Contract tests for custom sign-in identity projection."""
from __future__ import annotations

import base64
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import credential_collector as collector


PROJECT = "demo-custom-identity"
UID = "custom-" + "12" * 16


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _token(**overrides: object) -> str:
    claims: dict[str, object] = {
        "sub": UID,
        "user_id": UID,
        "aud": PROJECT,
        "iss": f"https://securetoken.google.com/{PROJECT}",
        "firebase": {"sign_in_provider": "custom"},
    }
    claims.update(overrides)
    header = _b64(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = _b64(json.dumps(claims, separators=(",", ":")).encode())
    return f"{header}.{payload}."


def _response(*, is_new_user: object = True, **overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "idToken": _token(),
        "refreshToken": "synthetic-refresh-token",
        "isNewUser": is_new_user,
    }
    body.update(overrides)
    return body


class CustomIdentityProjectionTests(unittest.TestCase):
    def test_no_local_id_uses_exact_id_token_subject(self) -> None:
        self.assertEqual(
            collector.custom_signin_response_uid(
                200, _response(), project=PROJECT, requested_uid=UID
            ),
            UID,
        )

    def test_exact_optional_local_id_is_accepted(self) -> None:
        self.assertEqual(
            collector.custom_signin_response_uid(
                200, _response(localId=UID), project=PROJECT, requested_uid=UID
            ),
            UID,
        )

    def test_missing_or_malformed_identity_is_unknown(self) -> None:
        for body in (
            _response(idToken="not-a-token"),
            _response(is_new_user="true"),
            _response(refreshToken=""),
            {"isNewUser": True, "refreshToken": "synthetic-refresh-token"},
        ):
            with self.subTest(body=sorted(body)):
                self.assertIsNone(
                    collector.custom_signin_response_uid(
                        200, body, project=PROJECT, requested_uid=UID
                    )
                )

    def test_conflicting_identity_claims_are_unknown(self) -> None:
        for body in (
            _response(localId="other-uid"),
            _response(idToken=_token(sub="other-uid")),
            _response(idToken=_token(user_id="other-uid")),
            _response(idToken=_token(aud="other-project")),
            _response(idToken=_token(iss="https://securetoken.google.com/other-project")),
            _response(idToken=_token(firebase={"sign_in_provider": "password"})),
            _response(idToken=_token(firebase={"sign_in_provider": "custom", "tenant": "t1"})),
        ):
            with self.subTest(body=sorted(body)):
                self.assertIsNone(
                    collector.custom_signin_response_uid(
                        200, body, project=PROJECT, requested_uid=UID
                    )
                )

    def test_explicit_reuse_remains_identified_but_not_creation(self) -> None:
        self.assertEqual(
            collector.custom_signin_response_uid(
                200, _response(is_new_user=False), project=PROJECT, requested_uid=UID
            ),
            UID,
        )


if __name__ == "__main__":
    unittest.main()
