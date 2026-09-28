"""Locally computed RFC 6238 codes for a TOTP observation campaign.

The shared secret only ever exists in memory and in the caller's private run directory.
Nothing in this module prints, logs, or returns the secret, and callers must keep the
computed codes out of receipts: the comparator redacts them, but redaction after the
fact is not a substitute for never recording them.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import dataclass

SUPPORTED_ALGORITHMS = ("HMAC_SHA1",)
_DIGESTS = {"HMAC_SHA1": hashlib.sha1}


@dataclass(frozen=True)
class TotpParameters:
    """The enrollment parameters the server returns in `totpSessionInfo`."""

    period_seconds: int
    digits: int
    algorithm: str

    def __post_init__(self) -> None:
        if type(self.period_seconds) is not int or self.period_seconds <= 0:
            raise ValueError("periodSec must be a positive integer")
        if type(self.digits) is not int or not 6 <= self.digits <= 10:
            raise ValueError("verificationCodeLength must be between 6 and 10")
        if self.algorithm not in SUPPORTED_ALGORITHMS:
            raise ValueError(f"unsupported hashingAlgorithm: {self.algorithm}")


def decode_shared_secret(shared_secret_key: str) -> bytes:
    """Decode a base32 `sharedSecretKey`, tolerating case, spaces, and missing padding."""
    if not isinstance(shared_secret_key, str):
        raise TypeError("sharedSecretKey must be a string")
    compact = "".join(shared_secret_key.split()).upper()
    if not compact:
        raise ValueError("sharedSecretKey must not be empty")
    body = compact.rstrip("=")
    if not body or any(
        character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for character in body
    ):
        raise ValueError("sharedSecretKey must be RFC 4648 base32")
    padded = body + "=" * (-len(body) % 8)
    try:
        raw = base64.b32decode(padded, casefold=False)
    except (ValueError, TypeError) as error:
        raise ValueError("sharedSecretKey must be RFC 4648 base32") from error
    if not raw:
        raise ValueError("sharedSecretKey decodes to no key material")
    return raw


def step_for(unix_seconds: int, period_seconds: int) -> int:
    """Return the RFC 6238 time step, refusing negative instants and zero periods."""
    if type(unix_seconds) is not int or unix_seconds < 0:
        raise ValueError("unix_seconds must be a non-negative integer")
    if type(period_seconds) is not int or period_seconds <= 0:
        raise ValueError("period_seconds must be a positive integer")
    return unix_seconds // period_seconds


def hotp_code(
    key: bytes, counter: int, digits: int, algorithm: str = "HMAC_SHA1"
) -> str:
    """Return the RFC 4226 HOTP value for one counter."""
    if not isinstance(key, bytes) or not key:
        raise ValueError("key must be non-empty bytes")
    if type(counter) is not int or counter < 0:
        raise ValueError("counter must be a non-negative integer")
    if algorithm not in _DIGESTS:
        raise ValueError(f"unsupported hashingAlgorithm: {algorithm}")
    mac = hmac.new(key, counter.to_bytes(8, "big"), _DIGESTS[algorithm]).digest()
    offset = mac[-1] & 0x0F
    truncated = int.from_bytes(mac[offset : offset + 4], "big") & 0x7FFF_FFFF
    return str(truncated % (10**digits)).zfill(digits)


def totp_code(
    shared_secret_key: str, unix_seconds: int, parameters: TotpParameters
) -> str:
    """Return the code a client would submit at `unix_seconds`."""
    key = decode_shared_secret(shared_secret_key)
    counter = step_for(unix_seconds, parameters.period_seconds)
    return hotp_code(key, counter, parameters.digits, parameters.algorithm)


def wrong_code(
    shared_secret_key: str,
    unix_seconds: int,
    parameters: TotpParameters,
    window_steps: int = 1,
) -> str:
    """Return a code that no step inside the acceptance window can match.

    A campaign needs a deterministic wrong code that cannot accidentally be correct; a
    random six-digit string has a small but real chance of matching a neighbouring step.
    """
    if type(window_steps) is not int or window_steps < 0:
        raise ValueError("window_steps must be a non-negative integer")
    key = decode_shared_secret(shared_secret_key)
    current = step_for(unix_seconds, parameters.period_seconds)
    forbidden = {
        hotp_code(key, step, parameters.digits, parameters.algorithm)
        for step in range(max(0, current - window_steps), current + window_steps + 1)
    }
    modulus = 10**parameters.digits
    candidate = int(next(iter(sorted(forbidden))))
    for increment in range(1, modulus):
        value = str((candidate + increment) % modulus).zfill(parameters.digits)
        if value not in forbidden:
            return value
    raise ValueError("no wrong code exists for the requested digit count")
