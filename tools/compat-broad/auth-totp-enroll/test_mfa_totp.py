"""RFC 4226 / RFC 6238 vectors for the locally computed one-time codes."""

from __future__ import annotations

import pytest
from mfa_totp import (
    TotpParameters,
    decode_shared_secret,
    hotp_code,
    step_for,
    totp_code,
)

# RFC 4226 Appendix D and RFC 6238 Appendix B use the ASCII secret "12345678901234567890".
RFC_SECRET_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


def test_shared_secret_decodes_with_and_without_padding() -> None:
    raw = decode_shared_secret(RFC_SECRET_B32)
    assert raw == b"12345678901234567890"
    assert decode_shared_secret(RFC_SECRET_B32.lower()) == raw
    assert decode_shared_secret("gezdgnbv gy3tqojq gezdgnbvgy3tqojq") == raw
    assert decode_shared_secret("MFRGG===") == b"abc"


def test_malformed_shared_secret_is_refused() -> None:
    for bad in ("", "1", "not base32!", "GEZDGNBV1"):
        with pytest.raises(ValueError):
            decode_shared_secret(bad)


def test_rfc4226_hotp_vectors() -> None:
    expected = [
        "755224",
        "287082",
        "359152",
        "969429",
        "338314",
        "254676",
        "287922",
        "162583",
        "399871",
        "520489",
    ]
    for counter, code in enumerate(expected):
        assert hotp_code(b"12345678901234567890", counter, digits=6) == code


def test_rfc6238_totp_vectors_for_hmac_sha1() -> None:
    vectors = {
        59: "94287082",
        1111111109: "07081804",
        1111111111: "14050471",
        1234567890: "89005924",
        2000000000: "69279037",
        20000000000: "65353130",
    }
    parameters = TotpParameters(period_seconds=30, digits=8, algorithm="HMAC_SHA1")
    for instant, code in vectors.items():
        assert totp_code(RFC_SECRET_B32, instant, parameters) == code


def test_step_boundaries_follow_the_declared_period() -> None:
    assert step_for(0, 30) == 0
    assert step_for(29, 30) == 0
    assert step_for(30, 30) == 1
    assert step_for(59, 30) == 1
    with pytest.raises(ValueError):
        step_for(-1, 30)
    with pytest.raises(ValueError):
        step_for(0, 0)


def test_parameters_reject_unsupported_shapes() -> None:
    for kwargs in (
        {"period_seconds": 0},
        {"period_seconds": -30},
        {"digits": 5},
        {"digits": 11},
        {"algorithm": "HMAC_SHA256"},
    ):
        with pytest.raises(ValueError):
            TotpParameters(
                **{
                    "period_seconds": 30,
                    "digits": 6,
                    "algorithm": "HMAC_SHA1",
                    **kwargs,
                }
            )


def test_neighbouring_step_codes_are_available_for_a_window() -> None:
    parameters = TotpParameters(period_seconds=30, digits=6, algorithm="HMAC_SHA1")
    current = totp_code(RFC_SECRET_B32, 1234567890, parameters)
    previous = totp_code(RFC_SECRET_B32, 1234567890 - 30, parameters)
    assert current != previous
    assert len(current) == len(previous) == 6


def test_a_wrong_code_is_derived_without_reusing_a_valid_step() -> None:
    from mfa_totp import wrong_code

    parameters = TotpParameters(period_seconds=30, digits=6, algorithm="HMAC_SHA1")
    instant = 1234567890
    wrong = wrong_code(RFC_SECRET_B32, instant, parameters, window_steps=1)
    accepted = {
        totp_code(RFC_SECRET_B32, instant + offset * 30, parameters)
        for offset in (-1, 0, 1)
    }
    assert wrong not in accepted
    assert len(wrong) == 6 and wrong.isdigit()


def test_module_never_writes_secret_material_to_a_stream(
    capsys: pytest.CaptureFixture[str],
) -> None:
    parameters = TotpParameters(period_seconds=30, digits=6, algorithm="HMAC_SHA1")
    totp_code(RFC_SECRET_B32, 1234567890, parameters)
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == ""
