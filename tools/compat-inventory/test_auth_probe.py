"""Rejection fixtures must never enroll users or send email/SMS."""

from auth_probe import negative_cases


def test_auth_cases_are_rejection_only_with_unique_non_delivery_addresses():
    first, second = negative_cases(), negative_cases()
    assert len(first) == 4
    assert len({case for case, _, _ in first}) == 4
    assert first[0][2]["email"] != second[0][2]["email"]
    for _, path, body in first:
        assert path in {
            "v1/accounts:signInWithPassword",
            "v2/accounts/mfaEnrollment:start",
        }
        if "email" in body:
            assert body["email"].endswith("@example.test")
        assert "phoneNumber" not in body
        assert "oobCode" not in body
        if path.startswith("v2"):
            assert body == {"idToken": "invalid"}
