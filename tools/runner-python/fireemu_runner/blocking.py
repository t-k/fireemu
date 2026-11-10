"""Auth blocking tokens: run the SDK's production verification with the daemon's public keys.

SECURITY-SENSITIVE. The SDK skips signature and audience checks in the Auth emulator. When the daemon supplies
its public keys, this module confines production verification and certificate responses to the SDK verifier;
without the environment variable the SDK's emulator behavior is unchanged.
"""

import contextvars
import importlib.metadata
import json

ENVIRONMENT_VARIABLE = "FIREEMU_AUTH_BLOCKING_JWKS"
NOTE_VERSION = "0.6.0"


class VerificationUnavailable(Exception):
    pass


def parse_keys(text) -> dict[str, str] | None:
    """Build the certificate mapping consumed by the SDK from the daemon's public JWKS."""
    import jwt
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    try:
        document = json.loads(text)
    except (ValueError, TypeError):
        return None
    entries = document.get("keys") if isinstance(document, dict) else None
    if not isinstance(entries, list) or not entries:
        return None
    keys = {}
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("kty") != "RSA" or not isinstance(entry.get("kid"), str) or not entry["kid"] or not isinstance(entry.get("n"), str) or not isinstance(entry.get("e"), str):
            continue
        try:
            keys[entry["kid"]] = jwt.PyJWK(entry).key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("ascii")
        except Exception:
            continue
    return keys or None


def install_from_environment(environ) -> bool:
    """Install the SDK-only verification hook when the daemon provides usable public keys."""
    if ENVIRONMENT_VARIABLE not in environ:
        return False
    value = environ.pop(ENVIRONMENT_VARIABLE)
    try:
        keys = parse_keys(value)
        if not keys:
            raise VerificationUnavailable("no usable public keys")
        from firebase_admin import _auth_utils
        from firebase_functions.private import token_verifier
        from google.auth.exceptions import TransportError

        stock = token_verifier._JWTVerifier
        if not isinstance(stock, type) or not callable(token_verifier._auth_utils.is_emulated) or not token_verifier._token_gen.ID_TOKEN_CERT_URI:
            raise VerificationUnavailable("unsupported SDK")
        cert_url = token_verifier._token_gen.ID_TOKEN_CERT_URI
        data = json.dumps(keys).encode()
        active = contextvars.ContextVar("fireemu_auth_blocking_verification", default=False)

        class AuthUtilsView:
            def is_emulated(self):
                return False if active.get() else _auth_utils.is_emulated()

            def __getattr__(self, name):
                return getattr(_auth_utils, name)

        class Verifier(stock):
            def verify(self, token, request):
                def certificate_request(url, method="GET", body=None, headers=None, timeout=None, **kwargs):
                    if url != cert_url:
                        raise TransportError("unexpected certificate URL")
                    return type("CertificateResponse", (), {"status": 200, "headers": {}, "data": data})()

                marker = active.set(True)
                try:
                    if isinstance(token, (str, bytes)) and token:
                        _, payload = self._decode_unverified(token.encode() if isinstance(token, str) else token)
                        if not isinstance(payload.get("aud"), str):
                            raise self._invalid_token_error('Firebase Auth Blocking token has an invalid "aud" claim.')
                    return super().verify(token, certificate_request)
                finally:
                    active.reset(marker)

        auth_utils_view = AuthUtilsView()
        token_verifier._JWTVerifier = Verifier
        token_verifier._auth_utils = auth_utils_view
        return True
    except VerificationUnavailable:
        raise
    except Exception as error:
        raise VerificationUnavailable("SDK hook installation failed") from error


def default_note(functions_version) -> str | None:
    if functions_version != NOTE_VERSION:
        return None
    return '[functions] note: firebase-functions (Python) 0.6.0 accepts only a "run.app" audience in an Auth blocking token, while firebase-tools 15.28.2 registers the function\'s cloudfunctions.net address, so in production every Auth blocking function written with it fails with 503 "Error code: 47"; fireemu skips that check by default and runs it, so this function passes here (functions.authBlockingToken: "production", set by productionExact, reproduces the production failure)'


def announce_default_note(stderr):
    try:
        version = importlib.metadata.version("firebase-functions")
    except Exception:
        version = None
    note = default_note(version)
    if note is not None:
        stderr.write(note + "\n")
